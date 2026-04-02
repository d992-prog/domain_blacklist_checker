from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_feature_access
from app.db.models import ProxyEndpoint, User
from app.db.session import get_db
from app.schemas.proxies import ProxyCreateRequest, ProxyResponse, ProxyUpdateRequest
from app.services.proxy_pool import build_proxy_url, parse_proxy_url

router = APIRouter(prefix="/proxies", tags=["proxies"])


def serialize_proxy(proxy: ProxyEndpoint) -> ProxyResponse:
    display_url = build_proxy_url(proxy)
    if proxy.username:
        masked_user = proxy.username[0] + "***"
        secret = f"{proxy.username}:{proxy.password}@" if proxy.password else f"{proxy.username}@"
        masked_secret = f"{masked_user}:***@" if proxy.password else f"{masked_user}@"
        display_url = display_url.replace(secret, masked_secret, 1)
    return ProxyResponse(
        id=proxy.id,
        scheme=proxy.scheme,
        host=proxy.host,
        port=proxy.port,
        username=(proxy.username[0] + "***") if proxy.username else None,
        password="***" if proxy.password else None,
        is_active=proxy.is_active,
        fail_count=proxy.fail_count,
        success_count=proxy.success_count,
        last_used_at=proxy.last_used_at,
        last_error=proxy.last_error,
        created_at=proxy.created_at,
        updated_at=proxy.updated_at,
        display_url=display_url,
    )


@router.get("", response_model=list[ProxyResponse])
async def list_proxies(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_feature_access),
) -> list[ProxyResponse]:
    result = await db.execute(
        select(ProxyEndpoint)
        .where(ProxyEndpoint.owner_id == user.id)
        .order_by(ProxyEndpoint.created_at.desc())
    )
    return [serialize_proxy(proxy) for proxy in result.scalars().all()]


@router.post("", response_model=ProxyResponse, status_code=status.HTTP_201_CREATED)
async def create_proxy(
    payload: ProxyCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_feature_access),
) -> ProxyResponse:
    try:
        parsed = parse_proxy_url(payload.proxy_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    proxy = ProxyEndpoint(owner_id=user.id, **parsed)
    db.add(proxy)
    await db.commit()
    await db.refresh(proxy)
    return serialize_proxy(proxy)


@router.patch("/{proxy_id}", response_model=ProxyResponse)
async def update_proxy(
    proxy_id: int,
    payload: ProxyUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_feature_access),
) -> ProxyResponse:
    result = await db.execute(
        select(ProxyEndpoint).where(ProxyEndpoint.id == proxy_id, ProxyEndpoint.owner_id == user.id)
    )
    proxy = result.scalar_one_or_none()
    if proxy is None:
        raise HTTPException(status_code=404, detail="Proxy not found")
    proxy.is_active = payload.is_active
    await db.commit()
    await db.refresh(proxy)
    return serialize_proxy(proxy)


@router.delete("/{proxy_id}")
async def delete_proxy(
    proxy_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_feature_access),
) -> dict[str, str]:
    result = await db.execute(
        select(ProxyEndpoint).where(ProxyEndpoint.id == proxy_id, ProxyEndpoint.owner_id == user.id)
    )
    proxy = result.scalar_one_or_none()
    if proxy is None:
        raise HTTPException(status_code=404, detail="Proxy not found")
    await db.delete(proxy)
    await db.commit()
    return {"detail": "Proxy deleted"}
