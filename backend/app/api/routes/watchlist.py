from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.models import User, WatchlistItem
from app.db.session import get_db
from app.schemas.watchlist import WatchlistCreateRequest, WatchlistResponse, WatchlistUpdateRequest
from app.services.domain_utils import normalize_domain

router = APIRouter(prefix="/watchlist", tags=["watchlist"])


def serialize_watchlist(item: WatchlistItem) -> WatchlistResponse:
    return WatchlistResponse(
        id=item.id,
        domain=item.domain,
        interval_hours=item.interval_hours,
        is_active=item.is_active,
        last_checked_at=item.last_checked_at,
        next_check_at=item.next_check_at,
        last_job_id=item.last_job_id,
        last_status=item.last_status,
        last_risk_score=item.last_risk_score,
        created_at=item.created_at,
        updated_at=item.updated_at,
    )


@router.get("", response_model=list[WatchlistResponse])
async def list_watchlist(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[WatchlistResponse]:
    result = await db.execute(
        select(WatchlistItem)
        .where(WatchlistItem.owner_id == user.id)
        .order_by(WatchlistItem.created_at.desc())
    )
    return [serialize_watchlist(item) for item in result.scalars().all()]


@router.post("", response_model=WatchlistResponse, status_code=status.HTTP_201_CREATED)
async def create_watchlist_item(
    payload: WatchlistCreateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> WatchlistResponse:
    domain = normalize_domain(payload.domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    result = await db.execute(
        select(WatchlistItem).where(WatchlistItem.owner_id == user.id, WatchlistItem.domain == domain)
    )
    item = result.scalar_one_or_none()
    if item is not None:
        item.interval_hours = payload.interval_hours
        item.is_active = True
        item.next_check_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(item)
        return serialize_watchlist(item)

    item = WatchlistItem(
        owner_id=user.id,
        domain=domain,
        interval_hours=payload.interval_hours,
        is_active=True,
        next_check_at=datetime.now(timezone.utc),
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return serialize_watchlist(item)


@router.patch("/{watch_id}", response_model=WatchlistResponse)
async def update_watchlist_item(
    watch_id: int,
    payload: WatchlistUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> WatchlistResponse:
    result = await db.execute(
        select(WatchlistItem).where(WatchlistItem.id == watch_id, WatchlistItem.owner_id == user.id)
    )
    item = result.scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    if payload.interval_hours is not None:
        item.interval_hours = payload.interval_hours
        if item.is_active:
            item.next_check_at = datetime.now(timezone.utc) + timedelta(hours=item.interval_hours)
    if payload.is_active is not None:
        item.is_active = payload.is_active
        item.next_check_at = (
            datetime.now(timezone.utc) + timedelta(hours=item.interval_hours)
            if item.is_active
            else None
        )
    await db.commit()
    await db.refresh(item)
    return serialize_watchlist(item)


@router.post("/{watch_id}/run", response_model=WatchlistResponse)
async def run_watchlist_item_now(
    watch_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> WatchlistResponse:
    runner = request.app.state.job_runner
    result = await db.execute(
        select(WatchlistItem).where(WatchlistItem.id == watch_id, WatchlistItem.owner_id == user.id)
    )
    item = result.scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    job = await runner.create_job([item.domain], owner_id=user.id)
    item.last_job_id = job.id
    item.next_check_at = datetime.now(timezone.utc) + timedelta(hours=item.interval_hours)
    await db.commit()
    await db.refresh(item)
    return serialize_watchlist(item)


@router.delete("/{watch_id}")
async def delete_watchlist_item(
    watch_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict[str, str]:
    result = await db.execute(
        select(WatchlistItem).where(WatchlistItem.id == watch_id, WatchlistItem.owner_id == user.id)
    )
    item = result.scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    await db.delete(item)
    await db.commit()
    return {"detail": "Watchlist item deleted"}
