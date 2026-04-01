from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Domain Blacklist Checker"
    api_prefix: str = "/api"
    db_url: str = Field(
        default="sqlite+aiosqlite:///./domain_blacklist_checker.db",
        alias="DB_URL",
    )
    cors_origins: str = Field(default="*", alias="CORS_ORIGINS")
    request_timeout: float = Field(default=12.0, alias="REQUEST_TIMEOUT")
    dns_timeout_seconds: float = Field(default=3.0, alias="DNS_TIMEOUT_SECONDS")
    dns_fallback_nameservers: str = Field(default="", alias="DNS_FALLBACK_NAMESERVERS")
    max_domains_per_job: int = Field(default=10_000, alias="MAX_DOMAINS_PER_JOB")
    domain_concurrency: int = Field(default=12, alias="DOMAIN_CONCURRENCY")
    blacklist_concurrency: int = Field(default=32, alias="BLACKLIST_CONCURRENCY")
    max_parallel_jobs: int = Field(default=2, alias="MAX_PARALLEL_JOBS")
    check_rate_limit_per_minute: int = Field(default=50, alias="CHECK_RATE_LIMIT_PER_MINUTE")
    proxy_attempts_per_request: int = Field(default=3, alias="PROXY_ATTEMPTS_PER_REQUEST")
    direct_http_fallback: bool = Field(default=True, alias="DIRECT_HTTP_FALLBACK")
    result_ttl_hours: int = Field(default=24, alias="RESULT_TTL_HOURS")
    provider_cache_seconds: int = Field(default=900, alias="PROVIDER_CACHE_SECONDS")
    watch_scheduler_poll_seconds: int = Field(default=60, alias="WATCH_SCHEDULER_POLL_SECONDS")
    owner_login: str = Field(default="", alias="OWNER_LOGIN")
    owner_password: str = Field(default="", alias="OWNER_PASSWORD")
    default_pending_message: str = Field(
        default="Account access is limited until an administrator reviews it.",
        alias="DEFAULT_PENDING_MESSAGE",
    )
    login_rate_limit_attempts: int = Field(default=5, alias="LOGIN_RATE_LIMIT_ATTEMPTS")
    login_lock_minutes: int = Field(default=10, alias="LOGIN_LOCK_MINUTES")
    session_cookie_secure: bool = Field(default=False, alias="SESSION_COOKIE_SECURE")
    google_safe_browsing_api_key: str = Field(default="", alias="GOOGLE_SAFE_BROWSING_API_KEY")
    lumen_search_url: str = Field(default="", alias="LUMEN_SEARCH_URL")
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
    phishtank_app_key: str = Field(default="", alias="PHISHTANK_APP_KEY")
    phishtank_user_agent: str = Field(
        default="domain-blacklist-checker/1.0",
        alias="PHISHTANK_USER_AGENT",
    )
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    urlhaus_api_url: str = Field(default="https://urlhaus-api.abuse.ch/v1/host/", alias="URLHAUS_API_URL")
    urlhaus_auth_key: str = Field(default="", alias="URLHAUS_AUTH_KEY")
    talos_api_url: str = Field(default="", alias="TALOS_API_URL")
    webhook_signing_secret: str = Field(default="", alias="WEBHOOK_SIGNING_SECRET")
    frontend_dist_dir_override: str = Field(default="", alias="FRONTEND_DIST_DIR")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @property
    def cors_origin_list(self) -> list[str]:
        if self.cors_origins.strip() == "*":
            return ["*"]
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def dns_fallback_nameserver_list(self) -> list[str]:
        return [item.strip() for item in self.dns_fallback_nameservers.split(",") if item.strip()]

    @property
    def frontend_dist_dir(self) -> Path:
        if self.frontend_dist_dir_override:
            return Path(self.frontend_dist_dir_override)
        return Path(__file__).resolve().parents[3] / "frontend" / "dist"


@lru_cache
def get_settings() -> Settings:
    return Settings()
