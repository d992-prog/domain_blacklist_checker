from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AdminUserUpdateRequest(BaseModel):
    status: str | None = None
    status_message: str | None = None
    role: str | None = None
    language: str | None = None
    max_domains: int | None = Field(default=None, ge=1)
    access_expires_at: datetime | None = None


class AdminUserResponse(BaseModel):
    id: int
    username: str
    role: str
    status: str
    language: str
    max_domains: int | None
    access_expires_at: datetime | None
    status_message: str | None
    last_login_at: datetime | None
    deleted_at: datetime | None
    created_at: datetime
    updated_at: datetime
    job_count: int
    proxy_count: int
    watch_count: int


class ProviderSettingsRequest(BaseModel):
    google_safe_browsing_api_key: str | None = None
    lumen_search_url: str | None = None
    virustotal_api_key: str | None = None
    phishtank_app_key: str | None = None
    phishtank_user_agent: str | None = None
    abuseipdb_api_key: str | None = None
    urlhaus_api_url: str | None = None
    urlhaus_auth_key: str | None = None
    talos_api_url: str | None = None
    webhook_signing_secret: str | None = None


class ProviderSettingsResponse(BaseModel):
    google_safe_browsing_api_key: str | None
    lumen_search_url: str | None
    virustotal_api_key: str | None
    phishtank_app_key: str | None
    phishtank_user_agent: str | None
    abuseipdb_api_key: str | None
    urlhaus_api_url: str | None
    urlhaus_auth_key: str | None
    talos_api_url: str | None
    webhook_signing_secret: str | None
    configured: dict[str, bool]


class AdminOverviewResponse(BaseModel):
    total_users: int
    active_users: int
    total_jobs: int
    total_proxies: int
    total_watchlist: int


class AdminAuditLogResponse(BaseModel):
    id: int
    actor_user_id: int | None
    target_user_id: int | None
    action: str
    details: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
