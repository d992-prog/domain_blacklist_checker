from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api import api_router
from app.core.config import get_settings
from app.db.migrations import run_startup_migrations
from app.db.session import AsyncSessionLocal, engine
from app.services.bootstrap import ensure_owner_account
from app.services.job_runner import JobRunner
from app.services.rate_limiter import SlidingWindowRateLimiter
from app.services.watch_scheduler import WatchScheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await run_startup_migrations(engine)
    await ensure_owner_account(AsyncSessionLocal, settings)

    app.state.job_runner = JobRunner()
    await app.state.job_runner.start()
    app.state.watch_scheduler = WatchScheduler(
        app.state.job_runner,
        poll_seconds=settings.watch_scheduler_poll_seconds,
    )
    await app.state.watch_scheduler.start()
    app.state.check_rate_limiter = SlidingWindowRateLimiter(settings.check_rate_limit_per_minute)
    try:
        yield
    finally:
        await app.state.watch_scheduler.stop()
        await app.state.job_runner.shutdown()
        await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=settings.cors_origin_list != ["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router, prefix=settings.api_prefix)

    if settings.frontend_dist_dir.exists():
        app.mount("/", StaticFiles(directory=settings.frontend_dist_dir, html=True), name="frontend")

    return app


app = create_app()
