from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.db.models import CheckJob, WatchlistItem
from app.db.session import AsyncSessionLocal


class WatchScheduler:
    def __init__(self, job_runner, poll_seconds: int = 60) -> None:
        self.job_runner = job_runner
        self.poll_seconds = poll_seconds
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="watch-scheduler")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception:
                pass
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_seconds)
            except asyncio.TimeoutError:
                continue

    async def _tick(self) -> None:
        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(WatchlistItem).where(
                    WatchlistItem.is_active.is_(True),
                    (WatchlistItem.next_check_at.is_(None)) | (WatchlistItem.next_check_at <= now),
                )
            )
            items = result.scalars().all()

        for item in items:
            async with AsyncSessionLocal() as session:
                current = await session.get(WatchlistItem, item.id)
                if current is None or not current.is_active:
                    continue
                if current.last_job_id:
                    last_job = await session.get(CheckJob, current.last_job_id)
                    if last_job is not None and last_job.status in {"queued", "running"}:
                        continue
            job = await self.job_runner.create_job([item.domain], owner_id=item.owner_id)
            async with AsyncSessionLocal() as session:
                current = await session.get(WatchlistItem, item.id)
                if current is None or not current.is_active:
                    continue
                current.last_job_id = job.id
                current.next_check_at = now + timedelta(hours=current.interval_hours)
                await session.commit()
