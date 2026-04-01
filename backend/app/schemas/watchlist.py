from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class WatchlistCreateRequest(BaseModel):
    domain: str
    interval_hours: int = Field(default=24, ge=1, le=168)


class WatchlistUpdateRequest(BaseModel):
    interval_hours: int | None = Field(default=None, ge=1, le=168)
    is_active: bool | None = None


class WatchlistResponse(BaseModel):
    id: int
    domain: str
    interval_hours: int
    is_active: bool
    last_checked_at: datetime | None = None
    next_check_at: datetime | None = None
    last_job_id: str | None = None
    last_status: str | None = None
    last_risk_score: int | None = None
    created_at: datetime
    updated_at: datetime
