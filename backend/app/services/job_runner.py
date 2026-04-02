from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import httpx
from sqlalchemy import delete, desc, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import CheckJob, DomainReport, User, WatchlistItem, WebhookSubscription
from app.db.session import AsyncSessionLocal
from app.services.app_settings import get_provider_settings
from app.services.checker import DomainChecker


class JobRunner:
    def __init__(self) -> None:
        from app.core.config import get_settings

        self.settings = get_settings()
        self._tasks: dict[str, asyncio.Task] = {}
        self._checker = DomainChecker()
        self._stop = asyncio.Event()
        self._wake = asyncio.Event()
        self._dispatcher_task: asyncio.Task | None = None

    async def create_job(self, domains: list[str], *, owner_id: int | None) -> CheckJob:
        await self.cleanup_old_jobs()
        job = CheckJob(
            id=str(uuid4()),
            owner_id=owner_id,
            status="queued",
            progress=0,
            total_domains=len(domains),
            completed_domains=0,
            requested_domains=domains,
        )
        async with AsyncSessionLocal() as session:
            session.add(job)
            await session.commit()
            await session.refresh(job)
        self._wake.set()
        return job

    async def start(self) -> None:
        if self._dispatcher_task is None or self._dispatcher_task.done():
            self._stop.clear()
            self._dispatcher_task = asyncio.create_task(self._dispatcher_loop(), name="job-dispatcher")

    async def shutdown(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._dispatcher_task is not None:
            self._dispatcher_task.cancel()
        tasks = [task for task in self._tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*(tasks + ([self._dispatcher_task] if self._dispatcher_task else [])), return_exceptions=True)

    async def _dispatcher_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self._dispatch_available_jobs()
                self._wake.clear()
                await asyncio.wait_for(self._wake.wait(), timeout=2)
            except asyncio.TimeoutError:
                continue

    async def _dispatch_available_jobs(self) -> None:
        self._tasks = {job_id: task for job_id, task in self._tasks.items() if not task.done()}
        available_slots = max(self.settings.max_parallel_jobs - len(self._tasks), 0)
        if available_slots <= 0:
            return

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(CheckJob)
                .where(CheckJob.status == "queued")
                .order_by(CheckJob.created_at.asc())
                .limit(available_slots)
            )
            jobs = result.scalars().all()

        for job in jobs:
            if job.id in self._tasks:
                continue
            task = asyncio.create_task(self._run_job(job.id), name=f"check-job-{job.id}")
            self._tasks[job.id] = task

    async def _run_job(self, job_id: str) -> None:
        try:
            async with AsyncSessionLocal() as session:
                job = await session.get(CheckJob, job_id)
                if job is None:
                    return
                requested_domains = list(job.requested_domains)
                owner_id = job.owner_id
                job.status = "running"
                job.started_at = datetime.now(timezone.utc)
                await session.commit()

            semaphore = asyncio.Semaphore(self.settings.domain_concurrency)
            progress_lock = asyncio.Lock()
            progress_state = {"completed": 0, "total": len(requested_domains)}

            async def process_domain(domain: str) -> None:
                async with semaphore:
                    try:
                        report_payload = await self._checker.build_report(domain, owner_id=owner_id)
                    except Exception as exc:
                        report_payload = {
                            "domain": domain,
                            "overall_status": "warning",
                            "risk_score": 0,
                            "blacklists": [],
                            "lumen": {
                                "status": "unknown",
                                "total_notices": 0,
                                "trend": None,
                                "notices": [],
                                "note": f"Check failed: {exc}",
                            },
                            "safe_browsing": {"status": "unknown", "note": "Skipped because the domain check failed."},
                            "email_auth": {
                                "spf": "fail",
                                "dkim": "fail",
                                "dmarc": "fail",
                                "note": "Email authentication lookup was not completed.",
                            },
                            "providers": [],
                            "recommendations": [
                                "Retry the scan and inspect resolver or provider connectivity for this domain."
                            ],
                            "checked_at": datetime.now(timezone.utc).isoformat(),
                        }

                    async with AsyncSessionLocal() as session:
                        session.add(
                            DomainReport(
                                job_id=job_id,
                                owner_id=owner_id,
                                domain=domain,
                                overall_status=report_payload["overall_status"],
                                risk_score=report_payload["risk_score"],
                                payload=report_payload,
                            )
                        )
                        async with progress_lock:
                            progress_state["completed"] += 1
                            completed = progress_state["completed"]
                            progress = round(completed / max(progress_state["total"], 1) * 100)
                        await session.execute(
                            update(CheckJob)
                            .where(CheckJob.id == job_id)
                            .values(completed_domains=completed, progress=progress)
                        )
                        await session.commit()

            await asyncio.gather(*(process_domain(domain) for domain in requested_domains))

            async with AsyncSessionLocal() as session:
                await self._finalize_job(session, job_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            async with AsyncSessionLocal() as session:
                job = await session.get(CheckJob, job_id)
                if job is not None:
                    job.status = "failed"
                    job.last_error = str(exc)
                    job.finished_at = datetime.now(timezone.utc)
                    await session.commit()
                    await self._dispatch_webhooks("job.failed", job.id)
        finally:
            self._tasks.pop(job_id, None)
            self._wake.set()

    async def _finalize_job(self, session: AsyncSession, job_id: str) -> None:
        job = await session.get(CheckJob, job_id)
        if job is None:
            return
        result = await session.execute(
            select(DomainReport).where(DomainReport.job_id == job_id).order_by(DomainReport.domain.asc())
        )
        reports = result.scalars().all()
        listed = sum(1 for report in reports if report.overall_status == "listed")
        warning = sum(1 for report in reports if report.overall_status == "warning")
        average_risk = round(sum(report.risk_score for report in reports) / max(len(reports), 1))
        job.status = "completed"
        job.progress = 100
        job.finished_at = datetime.now(timezone.utc)
        job.summary = {
            "total_domains": len(reports),
            "listed_domains": listed,
            "warning_domains": warning,
            "clean_domains": len(reports) - listed - warning,
            "average_risk_score": average_risk,
        }
        await session.commit()
        for report in reports:
            await session.execute(
                update(WatchlistItem)
                .where(WatchlistItem.owner_id == job.owner_id, WatchlistItem.domain == report.domain)
                .values(
                    last_checked_at=report.checked_at,
                    last_status=report.overall_status,
                    last_risk_score=report.risk_score,
                    last_job_id=job_id,
                )
            )
        await session.commit()
        await self._dispatch_webhooks("job.completed", job_id)

    def _can_access_job(self, job: CheckJob, requester: User) -> bool:
        return requester.role in {"owner", "admin"} or job.owner_id == requester.id

    async def get_status(self, job_id: str, requester: User) -> tuple[CheckJob | None, list[dict[str, Any]]]:
        async with AsyncSessionLocal() as session:
            job = await session.get(CheckJob, job_id)
            if job is None or not self._can_access_job(job, requester):
                return None, []
            result = await session.execute(
                select(DomainReport)
                .where(DomainReport.job_id == job_id)
                .order_by(DomainReport.risk_score.desc(), DomainReport.domain.asc())
            )
            reports = [report.payload for report in result.scalars().all()]
            return job, reports

    async def get_bundle(self, job_id: str, requester: User) -> dict[str, Any] | None:
        job, reports = await self.get_status(job_id, requester)
        if job is None:
            return None
        summary = job.summary or {
            "total_domains": job.total_domains,
            "listed_domains": sum(1 for report in reports if report["overall_status"] == "listed"),
            "warning_domains": sum(1 for report in reports if report["overall_status"] == "warning"),
            "clean_domains": sum(1 for report in reports if report["overall_status"] == "clean"),
            "average_risk_score": round(sum(report["risk_score"] for report in reports) / max(len(reports), 1))
            if reports
            else 0,
        }
        return {"job_id": job.id, "status": job.status, "summary": summary, "reports": reports}

    async def get_history(self, owner_id: int, domain: str | None, days: int) -> list[dict[str, Any]]:
        async with AsyncSessionLocal() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            query = (
                select(DomainReport)
                .where(DomainReport.owner_id == owner_id, DomainReport.checked_at >= cutoff)
                .order_by(desc(DomainReport.checked_at))
                .limit(200)
            )
            if domain:
                query = query.where(DomainReport.domain == domain)
            result = await session.execute(query)
            return [
                {
                    "id": report.id,
                    "job_id": report.job_id,
                    "domain": report.domain,
                    "overall_status": report.overall_status,
                    "risk_score": report.risk_score,
                    "checked_at": report.checked_at,
                }
                for report in result.scalars().all()
            ]

    async def delete_history_item(self, owner_id: int, report_id: int) -> bool:
        async with AsyncSessionLocal() as session:
            report = await session.get(DomainReport, report_id)
            if report is None or report.owner_id != owner_id:
                return False
            job_id = report.job_id
            await session.delete(report)
            await session.commit()

            remaining = await session.execute(select(DomainReport.id).where(DomainReport.job_id == job_id).limit(1))
            if remaining.scalar_one_or_none() is None:
                job = await session.get(CheckJob, job_id)
                if job is not None and job.owner_id == owner_id:
                    await session.delete(job)
                    await session.commit()
            return True

    async def create_webhook(self, owner_id: int, url: str, events: list[str]) -> WebhookSubscription:
        webhook = WebhookSubscription(owner_id=owner_id, url=url, events=events)
        async with AsyncSessionLocal() as session:
            session.add(webhook)
            await session.commit()
            await session.refresh(webhook)
            return webhook

    async def list_webhooks(self, owner_id: int) -> list[WebhookSubscription]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(WebhookSubscription)
                .where(WebhookSubscription.owner_id == owner_id)
                .order_by(WebhookSubscription.created_at.desc())
            )
            return list(result.scalars().all())

    async def delete_webhook(self, owner_id: int, webhook_id: int) -> bool:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(WebhookSubscription).where(
                    WebhookSubscription.id == webhook_id,
                    WebhookSubscription.owner_id == owner_id,
                )
            )
            webhook = result.scalar_one_or_none()
            if webhook is None:
                return False
            await session.delete(webhook)
            await session.commit()
            return True

    async def send_test_webhook(self, owner_id: int, webhook_id: int) -> bool:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(WebhookSubscription).where(
                    WebhookSubscription.id == webhook_id,
                    WebhookSubscription.owner_id == owner_id,
                )
            )
            webhook = result.scalar_one_or_none()
            if webhook is None:
                return False
        payload = {
            "event": "job.test",
            "job_id": "test-job",
            "status": "completed",
            "summary": {
                "total_domains": 1,
                "listed_domains": 0,
                "warning_domains": 1,
                "clean_domains": 0,
                "average_risk_score": 15,
            },
            "reports": [],
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }
        await self._post_webhook(webhook.url, payload)
        return True

    async def cleanup_old_jobs(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.settings.result_ttl_hours)
        async with AsyncSessionLocal() as session:
            await session.execute(delete(CheckJob).where(CheckJob.created_at < cutoff))
            await session.commit()

    async def _dispatch_webhooks(self, event_name: str, job_id: str) -> None:
        async with AsyncSessionLocal() as session:
            job = await session.get(CheckJob, job_id)
            if job is None or job.owner_id is None:
                return
            owner_id = job.owner_id
            settings_map = await get_provider_settings(session)

        async with AsyncSessionLocal() as session:
            owner = await session.get(User, owner_id)
            if owner is None:
                return

        bundle = await self.get_bundle(job_id, owner)
        if bundle is None:
            return

        payload = {
            "event": event_name,
            "job_id": job_id,
            "status": bundle["status"],
            "summary": bundle["summary"],
            "reports": bundle["reports"],
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        secret = settings_map.get("webhook_signing_secret", "")
        signature = ""
        if secret:
            signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(WebhookSubscription).where(WebhookSubscription.owner_id == owner_id)
            )
            hooks = [hook for hook in result.scalars().all() if "*" in hook.events or event_name in hook.events]

        for hook in hooks:
            await self._post_webhook(hook.url, payload, body=body, signature=signature, signing_secret=secret)

    async def _post_webhook(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        body: bytes | None = None,
        signature: str | None = None,
        signing_secret: str | None = None,
    ) -> None:
        encoded = body or json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        signed = signature
        if signed is None and signing_secret:
            signed = hmac.new(signing_secret.encode("utf-8"), encoded, hashlib.sha256).hexdigest()
        headers = {"Content-Type": "application/json"}
        if signed:
            headers["X-Signature-256"] = signed
        try:
            async with httpx.AsyncClient(timeout=self.settings.request_timeout) as client:
                await client.post(url, content=encoded, headers=headers)
        except httpx.HTTPError:
            return
