from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ProxyCreateRequest(BaseModel):
    proxy_url: str


class ProxyUpdateRequest(BaseModel):
    is_active: bool


class ProxyResponse(BaseModel):
    id: int
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None
    is_active: bool
    fail_count: int
    success_count: int
    last_used_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime
    display_url: str
