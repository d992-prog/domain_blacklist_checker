from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.db.base import utcnow
from app.db.models import Domain, Proxy, User
from app.services.app_settings import get_diagnostic_telegram_settings
from app.services.logs import add_log
from app.services.notifier import TelegramNotifier
from app.services.security import user_has_feature_access
from app.worker.checks import CheckOutcome, RdapResult, RdapSignal, dns_check, rdap_check
from app.worker.decision import evaluate_domain
from app.worker.scheduling import resolve_runtime_schedule

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WorkerState:
    task: asyncio.Task[None]
    last_heartbeat: float
    started_at: float
    sleeping_until: float | None = None


class MonitoringOrchestrator:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
        notifier: TelegramNotifier,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self.notifier = notifier
        self._workers: dict[int, WorkerState] = {}
        self._lock = asyncio.Lock()
        self._proxy_revival_task: asyncio.Task[None] | None = None
        self._supervisor_task: asyncio.Task[None] | None = None
        self._stopping = False

    async def bootstrap(self) -> None:
        async with self.session_factory() as session:
            result = await session.execute(select(Domain).where(Domain.is_active.is_(True)))
            domains = result.scalars().all()

        async with self._lock:
            for domain in domains:
                await self._start_worker_locked(domain.id)

        self._proxy_revival_task = asyncio.create_task(self._proxy_revival_loop())
        self._supervisor_task = asyncio.create_task(self._supervisor_loop())

    async def shutdown(self) -> None:
        self._stopping = True
        async with self._lock:
            tasks = [(domain_id, state.task) for domain_id, state in self._workers.items()]
            self._workers.clear()
        for domain_id, task in tasks:
            await self._cancel_worker_task(domain_id, task, reason="shutdown")
        for service_task in (self._proxy_revival_task, self._supervisor_task):
            if service_task:
                service_task.cancel()
                await asyncio.gather(service_task, return_exceptions=True)

    async def ensure_domain(self, domain_id: int) -> None:
        async with self._lock:
            await self._start_worker_locked(domain_id)

    async def stop_domain(self, domain_id: int) -> bool:
        async with self._lock:
            state = self._workers.pop(domain_id, None)
        if state:
            return await self._cancel_worker_task(domain_id, state.task, reason="manual stop")
        return False

    def worker_count(self) -> int:
        return len(self._workers)

    async def _start_worker_locked(self, domain_id: int) -> None:
        existing = self._workers.get(domain_id)
        if existing and not existing.task.done():
            existing.last_heartbeat = asyncio.get_running_loop().time()
            return
        task = asyncio.create_task(self._worker_loop(domain_id))
        now = asyncio.get_running_loop().time()
        self._workers[domain_id] = WorkerState(
            task=task,
            last_heartbeat=now,
            started_at=now,
            sleeping_until=None,
        )

    async def _cancel_worker_task(
        self,
        domain_id: int,
        task: asyncio.Task[None],
        *,
        reason: str,
        timeout: float = 2.0,
    ) -> bool:
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=timeout)
            return False
        except asyncio.CancelledError:
            return False
        except asyncio.TimeoutError:
            logger.error(
                "Worker for domain %s did not stop within %.1fs during %s; detaching task",
                domain_id,
                timeout,
                reason,
            )
            return True
        except Exception:
            logger.exception("Worker for domain %s raised while stopping during %s", domain_id, reason)
            return False

    async def _restart_worker(self, domain_id: int, *, reason: str) -> None:
        existing: WorkerState | None = None
        async with self._lock:
            existing = self._workers.get(domain_id)
        detached = False
        if existing:
            detached = await self._cancel_worker_task(domain_id, existing.task, reason=reason)
        async with self._lock:
            task = asyncio.create_task(self._worker_loop(domain_id))
            now = asyncio.get_running_loop().time()
            self._workers[domain_id] = WorkerState(
                task=task,
                last_heartbeat=now,
                started_at=now,
                sleeping_until=None,
            )

        async with self.session_factory() as session:
            domain = await session.get(Domain, domain_id)
            await add_log(
                session,
                domain_id=domain_id,
                event_type="error",
                message=(
                    f"Worker restarted automatically: {reason}"
                    + ("; previous task did not stop in time" if detached else "")
                ),
            )
            await session.commit()
            await self._send_diagnostic_alert(
                session,
                title="Worker restarted",
                details=(
                    f"domain_id={domain_id}\n"
                    f"domain={domain.domain if domain else 'unknown'}\n"
                    f"reason={reason}\n"
                    f"detached_previous_task={detached}"
                ),
            )

    def _heartbeat(self, domain_id: int) -> None:
        state = self._workers.get(domain_id)
        if state:
            state.last_heartbeat = asyncio.get_running_loop().time()
            state.sleeping_until = None

    def _mark_sleep(self, domain_id: int, interval: float) -> None:
        state = self._workers.get(domain_id)
        if state:
            state.sleeping_until = asyncio.get_running_loop().time() + max(0.0, interval)

    async def _worker_loop(self, domain_id: int) -> None:
        logger.info("Worker started for domain %s", domain_id)
        try:
            while not self._stopping:
                self._heartbeat(domain_id)
                interval = await self._run_cycle(domain_id)
                if not await self._should_continue(domain_id):
                    break
                self._heartbeat(domain_id)
                self._mark_sleep(domain_id, interval)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            logger.info("Worker cancelled for domain %s", domain_id)
            raise
        except Exception:
            logger.exception("Worker crashed for domain %s; restarting", domain_id)
            if not self._stopping:
                await asyncio.sleep(1)
                await self._restart_worker(domain_id, reason="uncaught exception")
        finally:
            async with self._lock:
                current = self._workers.get(domain_id)
                if current and current.task is asyncio.current_task():
                    self._workers.pop(domain_id, None)

    async def _should_continue(self, domain_id: int) -> bool:
        async with self.session_factory() as session:
            domain = await session.get(Domain, domain_id)
            return bool(domain and domain.is_active)

    async def _run_cycle(self, domain_id: int) -> float:
        async with self.session_factory() as session:
            domain = await session.get(Domain, domain_id)
            if domain is None:
                return self.settings.normal_check_interval

            if not domain.is_active:
                inactive_time = utcnow()
                if domain.status != "available":
                    domain.status = "inactive"
                domain.check_mode = "available-stop" if domain.status == "available" else "normal"
                domain.updated_at = inactive_time
                domain.worker_heartbeat_at = inactive_time
                await session.commit()
                return max(domain.check_interval, self.settings.normal_check_interval)

            owner = await session.get(User, domain.owner_id) if domain.owner_id else None
            if owner is None or not user_has_feature_access(owner):
                paused_at = utcnow()
                domain.status = "inactive"
                domain.worker_heartbeat_at = paused_at
                domain.updated_at = paused_at
                domain.last_error = owner.status_message if owner else "Domain owner missing"
                runtime = resolve_runtime_schedule(domain, "normal", paused_at)
                domain.check_mode = runtime.mode
                await session.commit()
                return runtime.interval

            cycle_started_at = utcnow()
            domain.last_cycle_started_at = cycle_started_at
            domain.worker_heartbeat_at = cycle_started_at
            domain.updated_at = cycle_started_at
            await session.commit()

        try:
            async with asyncio.timeout(self.settings.worker_cycle_timeout_seconds):
                dns_signal, rdap_direct = await asyncio.gather(
                    dns_check(domain.domain, self.settings),
                    rdap_check(domain.domain, self.settings),
                )
        except TimeoutError:
            return await self._mark_cycle_failure(domain_id, "Cycle timed out")
        except Exception as exc:
            return await self._mark_cycle_failure(domain_id, f"Cycle failed: {exc}")

        async with self.session_factory() as session:
            domain = await session.get(Domain, domain_id)
            if domain is None:
                return self.settings.normal_check_interval
            owner = await session.get(User, domain.owner_id) if domain.owner_id else None

            rdap_proxy: RdapResult | None = None
            if rdap_direct.signal == RdapSignal.ERROR:
                rdap_proxy = await self._run_proxy_fallback(session, domain.domain, domain.owner_id)

            outcome = CheckOutcome(
                dns=dns_signal,
                rdap_direct=rdap_direct,
                rdap_proxy=rdap_proxy,
            )
            decision = evaluate_domain(
                domain,
                dns_signal=outcome.dns,
                rdap_signal=outcome.effective_rdap.signal,
                confirmation_threshold=domain.confirmation_threshold,
            )

            checked_at = utcnow()
            runtime = resolve_runtime_schedule(domain, decision.check_mode, checked_at)
            rdap_result = outcome.effective_rdap
            previous_owner = domain.last_seen_owner
            previous_status = domain.last_seen_rdap_status
            previous_error = domain.last_error

            snapshot_log = self._build_snapshot_log(domain.domain, previous_owner, previous_status, rdap_result)
            if snapshot_log:
                await add_log(
                    session,
                    owner_id=domain.owner_id,
                    domain_id=domain.id,
                    event_type="info",
                    message=snapshot_log,
                )

            domain.status = decision.status
            domain.check_mode = runtime.mode
            domain.available_confirmations = decision.confirmations
            domain.last_check_at = checked_at
            domain.worker_heartbeat_at = checked_at
            domain.last_error = decision.last_error
            domain.updated_at = checked_at
            domain.consecutive_failures = 0
            domain.last_success_at = checked_at
            domain.last_seen_owner = rdap_result.owner
            domain.last_seen_rdap_status = rdap_result.registration_status

            if previous_owner != rdap_result.owner:
                domain.last_owner_change_at = checked_at

            should_alert = decision.should_alert and domain.alert_sent_at is None
            if should_alert:
                domain.alert_sent_at = checked_at
                domain.available_at = checked_at
            available_reference = domain.available_at or checked_at
            within_capture_watch = (
                decision.status == "available"
                and (checked_at - available_reference).total_seconds() < self.settings.available_capture_watch_seconds
            )

            if decision.status == "captured":
                domain.is_active = False
            elif decision.status == "available" and not domain.available_recheck_enabled and not within_capture_watch:
                domain.is_active = False

            if decision.should_log:
                await add_log(
                    session,
                    owner_id=domain.owner_id,
                    domain_id=domain.id,
                    event_type=decision.log_type,
                    message=decision.log_message,
                )
            elif decision.last_error and decision.last_error != previous_error:
                await add_log(
                    session,
                    owner_id=domain.owner_id,
                    domain_id=domain.id,
                    event_type="error" if decision.status == "error" else "info",
                    message=decision.log_message,
                )

            await session.commit()
            domain_name = domain.domain
            alert_time = domain.alert_sent_at
            owner_token = owner.telegram_token if owner else ""
            owner_chat_id = owner.telegram_chat_id if owner else ""

        if should_alert and alert_time is not None and owner_token and owner_chat_id:
            await self.notifier.send_domain_available(
                domain_name,
                alert_time,
                token=owner_token,
                chat_id=owner_chat_id,
            )

        return runtime.interval

    async def _mark_cycle_failure(self, domain_id: int, message: str) -> float:
        async with self.session_factory() as session:
            domain = await session.get(Domain, domain_id)
            if domain is None:
                return self.settings.normal_check_interval

            failed_at = utcnow()
            domain.status = "error"
            domain.worker_heartbeat_at = failed_at
            domain.updated_at = failed_at
            domain.last_error = message
            domain.consecutive_failures += 1

            runtime = resolve_runtime_schedule(domain, "normal", failed_at)
            domain.check_mode = runtime.mode

            should_log = domain.consecutive_failures in {1, 3, 5}
            if should_log:
                await add_log(
                    session,
                    owner_id=domain.owner_id,
                    domain_id=domain.id,
                    event_type="error",
                    message=f"{message} (consecutive_failures={domain.consecutive_failures})",
                )

            await session.commit()
            if domain.consecutive_failures in {3, 5, 10}:
                await self._send_diagnostic_alert(
                    session,
                    title="Repeated worker failures",
                    details=(
                        f"domain={domain.domain}\n"
                        f"consecutive_failures={domain.consecutive_failures}\n"
                        f"message={message}"
                    ),
                )
            return runtime.interval

    async def _run_proxy_fallback(
        self,
        session: AsyncSession,
        domain_name: str,
        owner_id: int | None,
    ) -> RdapResult:
        proxies = await self._pick_candidate_proxies(session, owner_id)
        if not proxies:
            return RdapResult(signal=RdapSignal.ERROR)

        for proxy in proxies:
            proxy.last_used = utcnow()
            result = await rdap_check(domain_name, self.settings, proxy=proxy)
            if result.signal == RdapSignal.ERROR:
                proxy.fail_count += 1
                if proxy.fail_count > self.settings.proxy_fail_threshold:
                    proxy.status = "dead"
                await add_log(
                    session,
                    owner_id=owner_id,
                    domain_id=None,
                    event_type="error",
                    message=f"Proxy {proxy.host}:{proxy.port} failed for {domain_name}",
                )
                continue

            proxy.fail_count = 0
            proxy.status = "active"
            await session.flush()
            return result

        await session.flush()
        return RdapResult(signal=RdapSignal.ERROR)

    async def _pick_candidate_proxies(
        self,
        session: AsyncSession,
        owner_id: int | None,
    ) -> list[Proxy]:
        result = await session.execute(
            select(Proxy)
            .where(Proxy.status == "active", Proxy.owner_id == owner_id)
            .order_by(Proxy.fail_count.asc(), Proxy.last_used.asc().nullsfirst(), Proxy.id.asc())
            .limit(max(1, self.settings.max_proxy_attempts_per_cycle))
        )
        return list(result.scalars().all())

    def _build_snapshot_log(
        self,
        domain_name: str,
        previous_owner: str | None,
        previous_status: str | None,
        rdap_result: RdapResult,
    ) -> str | None:
        if rdap_result.signal != RdapSignal.FOUND:
            return None
        owner_changed = previous_owner != rdap_result.owner
        status_changed = previous_status != rdap_result.registration_status
        if not owner_changed and not status_changed:
            return None
        parts: list[str] = []
        if owner_changed:
            parts.append(f"owner {previous_owner or 'unknown'} -> {rdap_result.owner or 'unknown'}")
        if status_changed:
            parts.append(
                "RDAP status "
                f"{previous_status or 'unknown'} -> {rdap_result.registration_status or 'unknown'}"
            )
        return f"Registration snapshot changed for {domain_name}: " + "; ".join(parts)

    async def _send_diagnostic_alert(
        self,
        session: AsyncSession,
        *,
        title: str,
        details: str,
    ) -> None:
        token, chat_id = await get_diagnostic_telegram_settings(session)
        if not token or not chat_id:
            return
        await self.notifier.send_diagnostic(
            title,
            details,
            token=token,
            chat_id=chat_id,
        )

    async def _proxy_revival_loop(self) -> None:
        try:
            while not self._stopping:
                await asyncio.sleep(self.settings.dead_proxy_retry_seconds)
                async with self.session_factory() as session:
                    await session.execute(
                        update(Proxy)
                        .where(Proxy.status == "dead")
                        .values(status="active", fail_count=0)
                    )
                    await session.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Proxy revival loop failed")

    async def _supervisor_loop(self) -> None:
        try:
            while not self._stopping:
                await asyncio.sleep(self.settings.worker_supervisor_interval_seconds)
                now = asyncio.get_running_loop().time()

                async with self.session_factory() as session:
                    result = await session.execute(select(Domain.id).where(Domain.is_active.is_(True)))
                    active_domain_ids = {item[0] for item in result.all()}

                async with self._lock:
                    tracked_ids = set(self._workers.keys())

                missing_ids = active_domain_ids - tracked_ids
                for domain_id in missing_ids:
                    async with self._lock:
                        await self._start_worker_locked(domain_id)

                for domain_id in active_domain_ids:
                    state = self._workers.get(domain_id)
                    if state is None:
                        continue
                    if state.task.done():
                        await self._restart_worker(domain_id, reason="task finished unexpectedly")
                        continue
                    if state.sleeping_until is not None and now <= state.sleeping_until + 5:
                        continue
                    if now - state.last_heartbeat > self.settings.worker_stall_threshold_seconds:
                        await self._restart_worker(domain_id, reason="heartbeat stalled")
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Worker supervisor loop failed")
