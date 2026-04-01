from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_feature_access
from app.core.config import get_settings
from app.db.models import Domain, Log, User
from app.db.session import get_db
from app.schemas.common import MessageResponse
from app.schemas.domain import (
    DomainBulkCreateRequest,
    DomainCreateRequest,
    DomainImportResponse,
    DomainResponse,
    DomainUpdateRequest,
)
from app.schemas.log import LogResponse
from app.services.domain_parser import normalize_domain, parse_upload
from app.services.logs import add_log
from app.services.masking import mask_domain
from app.services.security import user_has_feature_access

router = APIRouter(prefix="/domains", tags=["domains"])
ALLOWED_SCHEDULER_MODES = {"continuous", "pattern"}


def get_monitoring(request: Request):
    return request.app.state.monitoring


def validate_scheduler_mode(value: str | None) -> str | None:
    if value is None:
        return None
    if value not in ALLOWED_SCHEDULER_MODES:
        raise HTTPException(status_code=400, detail="scheduler_mode must be continuous or pattern")
    return value


def allow_restricted_domain_action(payload: DomainUpdateRequest) -> bool:
    changes = payload.model_dump(exclude_none=True)
    return changes == {"is_active": False}


def serialize_domain(domain: Domain, *, masked: bool) -> DomainResponse:
    return DomainResponse(
        id=domain.id,
        domain=mask_domain(domain.domain) if masked else domain.domain,
        zone=domain.zone,
        status=domain.status,
        is_active=domain.is_active,
        manual_burst=domain.manual_burst,
        scheduler_mode=domain.scheduler_mode,
        check_interval=domain.check_interval,
        burst_check_interval=domain.burst_check_interval,
        confirmation_threshold=domain.confirmation_threshold,
        available_recheck_enabled=domain.available_recheck_enabled,
        available_recheck_interval=domain.available_recheck_interval,
        pattern_slow_interval=domain.pattern_slow_interval,
        pattern_fast_interval=domain.pattern_fast_interval,
        pattern_window_start_minute=domain.pattern_window_start_minute,
        pattern_window_end_minute=domain.pattern_window_end_minute,
        check_mode=domain.check_mode,
        last_check_at=domain.last_check_at,
        last_cycle_started_at=domain.last_cycle_started_at,
        worker_heartbeat_at=domain.worker_heartbeat_at,
        last_success_at=domain.last_success_at,
        available_at=domain.available_at,
        last_seen_owner=domain.last_seen_owner,
        last_seen_rdap_status=domain.last_seen_rdap_status,
        last_owner_change_at=domain.last_owner_change_at,
        available_confirmations=domain.available_confirmations,
        consecutive_failures=domain.consecutive_failures,
        alert_sent_at=domain.alert_sent_at,
        last_error=None if masked else domain.last_error,
        created_at=domain.created_at,
        updated_at=domain.updated_at,
    )


@router.get("", response_model=list[DomainResponse])
async def list_domains(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[DomainResponse]:
    result = await db.execute(
        select(Domain)
        .where(Domain.owner_id == user.id)
        .order_by(Domain.created_at.desc())
    )
    masked = not user_has_feature_access(user) and user.role not in {"owner", "admin"}
    return [serialize_domain(domain, masked=masked) for domain in result.scalars().all()]


@router.post("", response_model=DomainImportResponse, status_code=status.HTTP_201_CREATED)
async def create_domain(
    payload: DomainCreateRequest | DomainBulkCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_feature_access),
) -> DomainImportResponse:
    if isinstance(payload, DomainCreateRequest):
        domain_candidates = [payload.domain]
        check_interval = payload.check_interval
        burst_check_interval = payload.burst_check_interval
    else:
        domain_candidates = payload.domains
        check_interval = payload.check_interval
        burst_check_interval = payload.burst_check_interval

    inserted: list[Domain] = []
    skipped: list[str] = []
    settings = get_settings()
    monitoring = get_monitoring(request)
    scheduler_mode = validate_scheduler_mode(payload.scheduler_mode)
    existing_count = int(
        await db.scalar(select(func.count(Domain.id)).where(Domain.owner_id == user.id)) or 0
    )

    for raw in domain_candidates:
        normalized = normalize_domain(raw)
        if not normalized:
            skipped.append(raw)
            continue

        existing = await db.execute(
            select(Domain).where(Domain.owner_id == user.id, Domain.domain == normalized)
        )
        if existing.scalar_one_or_none():
            skipped.append(normalized)
            continue

        if user.max_domains is not None and existing_count + len(inserted) >= user.max_domains:
            raise HTTPException(
                status_code=403,
                detail=f"Domain limit reached ({user.max_domains})",
            )

        domain = Domain(
            owner_id=user.id,
            domain=normalized,
            zone="fr",
            status="checking",
            is_active=True,
            manual_burst=False,
            scheduler_mode=scheduler_mode or "continuous",
            check_interval=check_interval or settings.normal_check_interval,
            burst_check_interval=burst_check_interval or settings.burst_check_interval,
            confirmation_threshold=payload.confirmation_threshold or settings.available_confirmation_threshold,
            available_recheck_enabled=bool(payload.available_recheck_enabled),
            available_recheck_interval=payload.available_recheck_interval or settings.available_recheck_interval,
            pattern_slow_interval=payload.pattern_slow_interval or settings.pattern_slow_interval,
            pattern_fast_interval=payload.pattern_fast_interval or settings.pattern_fast_interval,
            pattern_window_start_minute=(
                payload.pattern_window_start_minute
                if payload.pattern_window_start_minute is not None
                else settings.pattern_window_start_minute
            ),
            pattern_window_end_minute=(
                payload.pattern_window_end_minute
                if payload.pattern_window_end_minute is not None
                else settings.pattern_window_end_minute
            ),
            check_mode="normal",
            available_confirmations=0,
        )
        db.add(domain)
        inserted.append(domain)

    await db.flush()
    for domain in inserted:
        await add_log(
            db,
            owner_id=user.id,
            domain_id=domain.id,
            event_type="info",
            message=f"Monitoring started for {domain.domain}",
        )
    await db.commit()

    for domain in inserted:
        await monitoring.ensure_domain(domain.id)

    return DomainImportResponse(
        inserted=[serialize_domain(domain, masked=False) for domain in inserted],
        skipped=skipped,
    )


@router.post("/upload", response_model=DomainImportResponse, status_code=status.HTTP_201_CREATED)
async def upload_domains(
    request: Request,
    file: UploadFile = File(...),
    check_interval: float | None = Form(default=None),
    burst_check_interval: float | None = Form(default=None),
    scheduler_mode: str | None = Form(default=None),
    confirmation_threshold: int | None = Form(default=None),
    available_recheck_enabled: bool | None = Form(default=None),
    available_recheck_interval: float | None = Form(default=None),
    pattern_slow_interval: float | None = Form(default=None),
    pattern_fast_interval: float | None = Form(default=None),
    pattern_window_start_minute: int | None = Form(default=None),
    pattern_window_end_minute: int | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_feature_access),
) -> DomainImportResponse:
    settings = get_settings()
    try:
        domains = await parse_upload(file, settings.max_upload_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return await create_domain(
        DomainBulkCreateRequest(
            domains=domains,
            check_interval=check_interval,
            burst_check_interval=burst_check_interval,
            scheduler_mode=scheduler_mode,
            confirmation_threshold=confirmation_threshold,
            available_recheck_enabled=available_recheck_enabled,
            available_recheck_interval=available_recheck_interval,
            pattern_slow_interval=pattern_slow_interval,
            pattern_fast_interval=pattern_fast_interval,
            pattern_window_start_minute=pattern_window_start_minute,
            pattern_window_end_minute=pattern_window_end_minute,
        ),
        request=request,
        db=db,
        user=user,
    )


@router.patch("/{domain_id}", response_model=DomainResponse)
async def update_domain(
    domain_id: int,
    payload: DomainUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> DomainResponse:
    if not user_has_feature_access(user) and user.role not in {"owner", "admin"}:
        if not allow_restricted_domain_action(payload):
            raise HTTPException(
                status_code=403,
                detail=user.status_message or "Account access is restricted",
            )
    domain = await db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Domain not found")

    if payload.is_active is not None:
        domain.is_active = payload.is_active
        if payload.is_active:
            if domain.status in {"available", "captured"}:
                domain.status = domain.status
            else:
                domain.status = "checking"
        else:
            if domain.status == "available":
                domain.check_mode = "available-stop"
            elif domain.status != "captured":
                domain.status = "inactive"
    if payload.manual_burst is not None:
        domain.manual_burst = payload.manual_burst
        domain.check_mode = "burst" if payload.manual_burst else "normal"
    scheduler_mode = validate_scheduler_mode(payload.scheduler_mode)
    if scheduler_mode is not None:
        domain.scheduler_mode = scheduler_mode
    if payload.check_interval is not None:
        domain.check_interval = payload.check_interval
    if payload.burst_check_interval is not None:
        domain.burst_check_interval = payload.burst_check_interval
    if payload.confirmation_threshold is not None:
        domain.confirmation_threshold = payload.confirmation_threshold
    if payload.available_recheck_enabled is not None:
        domain.available_recheck_enabled = payload.available_recheck_enabled
        if payload.available_recheck_enabled and domain.status == "available":
            domain.is_active = True
        if not payload.available_recheck_enabled and domain.status == "available":
            domain.is_active = False
    if payload.available_recheck_interval is not None:
        domain.available_recheck_interval = payload.available_recheck_interval
    if payload.pattern_slow_interval is not None:
        domain.pattern_slow_interval = payload.pattern_slow_interval
    if payload.pattern_fast_interval is not None:
        domain.pattern_fast_interval = payload.pattern_fast_interval
    if payload.pattern_window_start_minute is not None:
        domain.pattern_window_start_minute = payload.pattern_window_start_minute
    if payload.pattern_window_end_minute is not None:
        domain.pattern_window_end_minute = payload.pattern_window_end_minute
    if payload.check_mode is not None:
        domain.check_mode = payload.check_mode

    await db.commit()
    await db.refresh(domain)

    monitoring = get_monitoring(request)
    if domain.is_active:
        await monitoring.ensure_domain(domain.id)
    else:
        detached = await monitoring.stop_domain(domain.id)
        if detached:
            await add_log(
                db,
                owner_id=user.id,
                domain_id=domain.id,
                event_type="error",
                message="Worker did not stop in time and was detached from orchestrator",
            )
            await db.commit()

    return serialize_domain(domain, masked=False)


@router.delete("/{domain_id}", response_model=MessageResponse)
async def delete_domain(
    domain_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> MessageResponse:
    domain = await db.get(Domain, domain_id)
    if domain is None or domain.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Domain not found")
    domain_name = domain.domain

    detached = await get_monitoring(request).stop_domain(domain.id)
    if detached:
        await add_log(
            db,
            owner_id=user.id,
            domain_id=None,
            event_type="error",
            message=f"Worker for {domain_name} did not stop in time before deletion and was detached from orchestrator",
        )
    await db.delete(domain)
    await db.commit()
    return MessageResponse(detail="Domain deleted")


@router.get("/logs", response_model=list[LogResponse])
async def list_logs(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[Log]:
    result = await db.execute(
        select(Log)
        .where(Log.owner_id == user.id)
        .order_by(Log.created_at.desc())
        .limit(min(limit, 500))
    )
    return list(result.scalars().all())
