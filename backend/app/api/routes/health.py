from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin, require_feature_access
from app.core.config import get_settings
from app.db.models import CheckJob, DomainReport, ProxyEndpoint, User, WatchlistItem
from app.db.session import get_db
from app.services.app_settings import get_provider_settings

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/monitoring")
async def monitoring_health(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> dict[str, object]:
    del admin
    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.result_ttl_hours)
    await db.execute(delete(CheckJob).where(CheckJob.created_at < cutoff))
    await db.commit()

    jobs_total = int(await db.scalar(select(func.count(CheckJob.id))) or 0)
    reports_total = int(await db.scalar(select(func.count(DomainReport.id))) or 0)
    running_jobs = int(
        await db.scalar(select(func.count(CheckJob.id)).where(CheckJob.status == "running")) or 0
    )
    queued_jobs = int(
        await db.scalar(select(func.count(CheckJob.id)).where(CheckJob.status == "queued")) or 0
    )
    active_proxies = int(
        await db.scalar(select(func.count(ProxyEndpoint.id)).where(ProxyEndpoint.is_active.is_(True))) or 0
    )
    active_watchlist = int(
        await db.scalar(select(func.count(WatchlistItem.id)).where(WatchlistItem.is_active.is_(True))) or 0
    )
    return {
        "status": "ok",
        "jobs_total": jobs_total,
        "reports_total": reports_total,
        "running_jobs": running_jobs,
        "queued_jobs": queued_jobs,
        "active_proxies": active_proxies,
        "active_watchlist": active_watchlist,
    }


@router.get("/runtime")
async def runtime_summary(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_feature_access),
) -> dict[str, object]:
    settings = get_settings()
    settings_map = await get_provider_settings(db)
    active_proxies = int(
        await db.scalar(
            select(func.count(ProxyEndpoint.id)).where(
                ProxyEndpoint.is_active.is_(True),
                ProxyEndpoint.owner_id == user.id,
            )
        )
        or 0
    )
    active_watchlist = int(
        await db.scalar(
            select(func.count(WatchlistItem.id)).where(
                WatchlistItem.is_active.is_(True),
                WatchlistItem.owner_id == user.id,
            )
        )
        or 0
    )
    return {
        "app_name": settings.app_name,
        "proxy_attempts_per_request": settings.proxy_attempts_per_request,
        "direct_http_fallback": settings.direct_http_fallback,
        "max_parallel_jobs": settings.max_parallel_jobs,
        "check_rate_limit_per_minute": settings.check_rate_limit_per_minute,
        "watch_scheduler_poll_seconds": settings.watch_scheduler_poll_seconds,
        "configured_providers": {
            "google_safe_browsing": bool(settings_map.get("google_safe_browsing_api_key")),
            "lumen": bool(settings_map.get("lumen_search_url")),
            "virustotal": bool(settings_map.get("virustotal_api_key")),
            "phishtank": bool(settings_map.get("phishtank_app_key")),
            "abuseipdb": bool(settings_map.get("abuseipdb_api_key")),
            "urlhaus": bool(settings_map.get("urlhaus_api_url") and settings_map.get("urlhaus_auth_key")),
            "talos": bool(settings_map.get("talos_api_url")),
            "webhook_signing": bool(settings_map.get("webhook_signing_secret")),
        },
        "active_proxies": active_proxies,
        "active_watchlist": active_watchlist,
        "is_admin": user.role in {"owner", "admin"},
    }
