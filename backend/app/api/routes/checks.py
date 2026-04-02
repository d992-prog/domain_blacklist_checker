from __future__ import annotations

import asyncio
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi import File, UploadFile
from fastapi.responses import Response, StreamingResponse

from app.api.deps import get_current_user, require_feature_access
from app.core.config import get_settings
from app.db.models import User
from app.schemas.checks import (
    CheckRequest,
    HistoryItem,
    JobReportBundle,
    JobResponse,
    JobStatusResponse,
    WebhookRequest,
    WebhookResponse,
)
from app.services.domain_utils import dedupe_domains, normalize_domain
from app.services.exports import build_csv_report, build_pdf_report

router = APIRouter(tags=["checks"])


def get_job_runner(request: Request):
    return request.app.state.job_runner


async def enforce_check_rate_limit(request: Request, key: str) -> None:
    allowed = await request.app.state.check_rate_limiter.allow(key)
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded for check creation")


@router.post("/check", response_model=JobResponse)
async def create_check_job(
    payload: CheckRequest,
    request: Request,
    user: User = Depends(require_feature_access),
) -> JobResponse:
    await enforce_check_rate_limit(request, f"user:{user.id}")
    domains = dedupe_domains(payload.domains)
    if not domains:
        raise HTTPException(status_code=400, detail="No valid domains were provided")
    if len(domains) > get_settings().max_domains_per_job:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {get_settings().max_domains_per_job} domains per job",
        )
    if user.max_domains is not None and len(domains) > user.max_domains:
        raise HTTPException(status_code=400, detail=f"Maximum {user.max_domains} domains allowed for your account")
    runner = get_job_runner(request)
    job = await runner.create_job(domains, owner_id=user.id)
    return JobResponse(job_id=job.id, status=job.status, total_domains=job.total_domains)


@router.post("/check/upload", response_model=JobResponse)
async def create_check_job_from_upload(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_feature_access),
) -> JobResponse:
    await enforce_check_rate_limit(request, f"user:{user.id}")
    content = (await file.read()).decode("utf-8", errors="ignore")
    domains = dedupe_domains(re.split(r"[\s,;]+", content))
    if not domains:
        raise HTTPException(status_code=400, detail="No valid domains were found in the uploaded file")
    if len(domains) > get_settings().max_domains_per_job:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {get_settings().max_domains_per_job} domains per job",
        )
    if user.max_domains is not None and len(domains) > user.max_domains:
        raise HTTPException(status_code=400, detail=f"Maximum {user.max_domains} domains allowed for your account")
    runner = get_job_runner(request)
    job = await runner.create_job(domains, owner_id=user.id)
    return JobResponse(job_id=job.id, status=job.status, total_domains=job.total_domains)


@router.get("/status/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: str,
    request: Request,
    user: User = Depends(get_current_user),
) -> JobStatusResponse:
    runner = get_job_runner(request)
    job, reports = await runner.get_status(job_id, user)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        progress=job.progress,
        total_domains=job.total_domains,
        completed_domains=job.completed_domains,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        last_error=job.last_error,
        reports=reports,
    )


@router.get("/status/{job_id}/stream")
async def stream_job_status(
    job_id: str,
    request: Request,
    user: User = Depends(get_current_user),
):
    runner = get_job_runner(request)

    async def event_stream():
        while True:
            job, reports = await runner.get_status(job_id, user)
            if job is None:
                payload = json.dumps({"detail": "Job not found"})
                yield f"event: error\ndata: {payload}\n\n"
                return

            payload = json.dumps(
                {
                    "job_id": job.id,
                    "status": job.status,
                    "progress": job.progress,
                    "total_domains": job.total_domains,
                    "completed_domains": job.completed_domains,
                    "created_at": job.created_at.isoformat(),
                    "started_at": job.started_at.isoformat() if job.started_at else None,
                    "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                    "last_error": job.last_error,
                    "reports": reports,
                }
            )
            yield f"event: status\ndata: {payload}\n\n"
            if job.status in {"completed", "failed"}:
                return
            await asyncio.sleep(2)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/report/{job_id}", response_model=JobReportBundle)
async def get_job_report(
    job_id: str,
    request: Request,
    format: str = Query(default="json", pattern="^(json|csv|pdf)$"),
    user: User = Depends(get_current_user),
):
    runner = get_job_runner(request)
    bundle = await runner.get_bundle(job_id, user)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Job not found")

    if format == "json":
        return JobReportBundle(**bundle)
    if format == "csv":
        csv_payload = build_csv_report(bundle)
        return Response(
            content=csv_payload,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="report-{job_id}.csv"'},
        )
    pdf_payload = build_pdf_report(bundle)
    return Response(
        content=pdf_payload,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report-{job_id}.pdf"'},
    )


@router.get("/history", response_model=list[HistoryItem])
async def get_history(
    request: Request,
    domain: str | None = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
    user: User = Depends(require_feature_access),
):
    normalized = normalize_domain(domain) if domain else None
    if domain and not normalized:
        raise HTTPException(status_code=400, detail="Invalid domain filter")
    runner = get_job_runner(request)
    return await runner.get_history(user.id, normalized, days)


@router.delete("/history/{report_id}")
async def delete_history_item(
    report_id: int,
    request: Request,
    user: User = Depends(require_feature_access),
) -> dict[str, str]:
    runner = get_job_runner(request)
    deleted = await runner.delete_history_item(user.id, report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="History item not found")
    return {"detail": "History item deleted"}


@router.post("/webhook", response_model=WebhookResponse)
async def create_webhook(
    payload: WebhookRequest,
    request: Request,
    user: User = Depends(require_feature_access),
) -> WebhookResponse:
    runner = get_job_runner(request)
    webhook = await runner.create_webhook(user.id, str(payload.url), payload.events)
    return WebhookResponse(id=webhook.id, url=webhook.url, events=webhook.events, created_at=webhook.created_at)


@router.get("/webhook", response_model=list[WebhookResponse])
async def list_webhooks(
    request: Request,
    user: User = Depends(require_feature_access),
) -> list[WebhookResponse]:
    runner = get_job_runner(request)
    hooks = await runner.list_webhooks(user.id)
    return [
        WebhookResponse(id=hook.id, url=hook.url, events=hook.events, created_at=hook.created_at)
        for hook in hooks
    ]


@router.delete("/webhook/{webhook_id}")
async def delete_webhook(
    webhook_id: int,
    request: Request,
    user: User = Depends(require_feature_access),
) -> dict[str, str]:
    runner = get_job_runner(request)
    deleted = await runner.delete_webhook(user.id, webhook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"detail": "Webhook deleted"}


@router.post("/webhook/{webhook_id}/test")
async def test_webhook(
    webhook_id: int,
    request: Request,
    user: User = Depends(require_feature_access),
) -> dict[str, str]:
    runner = get_job_runner(request)
    sent = await runner.send_test_webhook(user.id, webhook_id)
    if not sent:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"detail": "Test webhook sent"}
