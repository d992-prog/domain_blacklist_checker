from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.db.base import utcnow
from app.db.models import AdminAuditLog, CheckJob, ProxyEndpoint, User, WatchlistItem
from app.db.session import get_db
from app.schemas.admin import (
    AdminAuditLogResponse,
    AdminOverviewResponse,
    AdminPasswordUpdateRequest,
    AdminUserCreateRequest,
    AdminUserResponse,
    AdminUserUpdateRequest,
    ProviderSettingsRequest,
    ProviderSettingsResponse,
)
from app.schemas.auth import UserResponse
from app.services.app_settings import get_provider_settings, update_provider_settings
from app.services.audit import add_audit_log
from app.services.security import hash_password

router = APIRouter(prefix="/admin", tags=["admin"])


def _serialize_provider_settings(settings_map: dict[str, str]) -> ProviderSettingsResponse:
    return ProviderSettingsResponse(
        google_safe_browsing_api_key=settings_map.get("google_safe_browsing_api_key"),
        lumen_search_url=settings_map.get("lumen_search_url"),
        virustotal_api_key=settings_map.get("virustotal_api_key"),
        phishtank_app_key=settings_map.get("phishtank_app_key"),
        phishtank_user_agent=settings_map.get("phishtank_user_agent"),
        abuseipdb_api_key=settings_map.get("abuseipdb_api_key"),
        urlhaus_api_url=settings_map.get("urlhaus_api_url"),
        urlhaus_auth_key=settings_map.get("urlhaus_auth_key"),
        talos_api_url=settings_map.get("talos_api_url"),
        webhook_signing_secret=settings_map.get("webhook_signing_secret"),
        configured={
            "google_safe_browsing": bool(settings_map.get("google_safe_browsing_api_key")),
            "lumen": bool(settings_map.get("lumen_search_url")),
            "virustotal": bool(settings_map.get("virustotal_api_key")),
            "phishtank": bool(settings_map.get("phishtank_app_key")),
            "abuseipdb": bool(settings_map.get("abuseipdb_api_key")),
            "urlhaus": bool(settings_map.get("urlhaus_api_url") and settings_map.get("urlhaus_auth_key")),
            "talos": bool(settings_map.get("talos_api_url")),
            "webhook_signing": bool(settings_map.get("webhook_signing_secret")),
        },
    )


@router.get("/overview", response_model=AdminOverviewResponse)
async def overview(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> AdminOverviewResponse:
    del admin
    total_users = int(await db.scalar(select(func.count(User.id))) or 0)
    active_users = int(
        await db.scalar(select(func.count(User.id)).where(User.deleted_at.is_(None), User.status == "approved")) or 0
    )
    total_jobs = int(await db.scalar(select(func.count(CheckJob.id))) or 0)
    total_proxies = int(await db.scalar(select(func.count(ProxyEndpoint.id))) or 0)
    total_watchlist = int(await db.scalar(select(func.count(WatchlistItem.id))) or 0)
    return AdminOverviewResponse(
        total_users=total_users,
        active_users=active_users,
        total_jobs=total_jobs,
        total_proxies=total_proxies,
        total_watchlist=total_watchlist,
    )


@router.get("/users", response_model=list[AdminUserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> list[AdminUserResponse]:
    del admin
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    items: list[AdminUserResponse] = []
    for user in users:
        job_count = int(await db.scalar(select(func.count(CheckJob.id)).where(CheckJob.owner_id == user.id)) or 0)
        proxy_count = int(
            await db.scalar(select(func.count(ProxyEndpoint.id)).where(ProxyEndpoint.owner_id == user.id)) or 0
        )
        watch_count = int(
            await db.scalar(select(func.count(WatchlistItem.id)).where(WatchlistItem.owner_id == user.id)) or 0
        )
        items.append(
            AdminUserResponse(
                id=user.id,
                username=user.username,
                role=user.role,
                status=user.status,
                language=user.language,
                max_domains=user.max_domains,
                access_expires_at=user.access_expires_at,
                status_message=user.status_message,
                last_login_at=user.last_login_at,
                deleted_at=user.deleted_at,
                created_at=user.created_at,
                updated_at=user.updated_at,
                job_count=job_count,
                proxy_count=proxy_count,
                watch_count=watch_count,
            )
        )
    return items


@router.post("/users", response_model=UserResponse)
async def create_user(
    payload: AdminUserCreateRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> UserResponse:
    username = payload.username.strip().lower()
    result = await db.execute(select(User).where(User.username == username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        status=payload.status,
        language=payload.language,
        max_domains=payload.max_domains,
        status_message=payload.status_message,
    )
    db.add(user)
    await add_audit_log(
        db,
        actor_user_id=admin.id,
        target_user_id=None,
        action="user_create",
        details=f"username={username} role={payload.role} status={payload.status}",
    )
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    payload: AdminUserUpdateRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> UserResponse:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.status is not None:
        user.status = payload.status
    if "status_message" in payload.model_fields_set:
        user.status_message = payload.status_message
    if payload.role is not None:
        user.role = payload.role
    if payload.language is not None:
        user.language = payload.language
    if "max_domains" in payload.model_fields_set:
        user.max_domains = payload.max_domains
    if "access_expires_at" in payload.model_fields_set:
        user.access_expires_at = payload.access_expires_at
    user.updated_at = utcnow()
    await add_audit_log(
        db,
        actor_user_id=admin.id,
        target_user_id=user.id,
        action="user_update",
        details=f"role={user.role} status={user.status} max_domains={user.max_domains}",
    )
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.patch("/users/{user_id}/password")
async def update_user_password(
    user_id: int,
    payload: AdminPasswordUpdateRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict[str, str]:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = hash_password(payload.password)
    user.updated_at = utcnow()
    await add_audit_log(
        db,
        actor_user_id=admin.id,
        target_user_id=user.id,
        action="user_password_reset",
        details="Password was reset by administrator.",
    )
    await db.commit()
    return {"detail": "Password updated"}


@router.get("/provider-settings", response_model=ProviderSettingsResponse)
async def get_provider_settings_route(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> ProviderSettingsResponse:
    del admin
    settings_map = await get_provider_settings(db)
    return _serialize_provider_settings(settings_map)


@router.put("/provider-settings", response_model=ProviderSettingsResponse)
async def update_provider_settings_route(
    payload: ProviderSettingsRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> ProviderSettingsResponse:
    settings_map = await update_provider_settings(db, payload.model_dump())
    await add_audit_log(
        db,
        actor_user_id=admin.id,
        target_user_id=None,
        action="provider_settings_update",
        details="Updated provider credentials and integration settings.",
    )
    await db.commit()
    return _serialize_provider_settings(settings_map)


@router.get("/audit-logs", response_model=list[AdminAuditLogResponse])
async def list_audit_logs(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> list[AdminAuditLog]:
    del admin
    result = await db.execute(
        select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc()).limit(min(limit, 500))
    )
    return list(result.scalars().all())
