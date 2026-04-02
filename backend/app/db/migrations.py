from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.db.base import Base


def _ensure_column(sync_conn, table_name: str, column_name: str, statement: str) -> None:
    inspector = inspect(sync_conn)
    tables = inspector.get_table_names()
    if table_name not in tables:
        return
    columns = {column["name"] for column in inspector.get_columns(table_name)}
    if column_name in columns:
        return
    sync_conn.execute(text(statement))


def _ensure_index(sync_conn, statement: str) -> None:
    sync_conn.execute(text(statement))


def _migrate(sync_conn) -> None:
    Base.metadata.create_all(sync_conn)

    _ensure_column(sync_conn, "users", "role", "ALTER TABLE users ADD COLUMN role VARCHAR(24) DEFAULT 'user'")
    _ensure_column(sync_conn, "users", "status", "ALTER TABLE users ADD COLUMN status VARCHAR(24) DEFAULT 'approved'")
    _ensure_column(sync_conn, "users", "language", "ALTER TABLE users ADD COLUMN language VARCHAR(8) DEFAULT 'ru'")
    _ensure_column(sync_conn, "users", "max_domains", "ALTER TABLE users ADD COLUMN max_domains INTEGER")
    _ensure_column(sync_conn, "users", "access_expires_at", "ALTER TABLE users ADD COLUMN access_expires_at DATETIME")
    _ensure_column(sync_conn, "users", "status_message", "ALTER TABLE users ADD COLUMN status_message TEXT")
    _ensure_column(sync_conn, "users", "last_login_at", "ALTER TABLE users ADD COLUMN last_login_at DATETIME")
    _ensure_column(sync_conn, "users", "deleted_at", "ALTER TABLE users ADD COLUMN deleted_at DATETIME")
    _ensure_column(
        sync_conn,
        "users",
        "login_failed_attempts",
        "ALTER TABLE users ADD COLUMN login_failed_attempts INTEGER DEFAULT 0",
    )
    _ensure_column(sync_conn, "users", "login_locked_until", "ALTER TABLE users ADD COLUMN login_locked_until DATETIME")
    _ensure_column(sync_conn, "users", "created_at", "ALTER TABLE users ADD COLUMN created_at DATETIME")
    _ensure_column(sync_conn, "users", "updated_at", "ALTER TABLE users ADD COLUMN updated_at DATETIME")

    _ensure_column(
        sync_conn,
        "user_sessions",
        "remember_me",
        "ALTER TABLE user_sessions ADD COLUMN remember_me BOOLEAN DEFAULT 0",
    )
    _ensure_column(sync_conn, "user_sessions", "expires_at", "ALTER TABLE user_sessions ADD COLUMN expires_at DATETIME")
    _ensure_column(sync_conn, "user_sessions", "last_used_at", "ALTER TABLE user_sessions ADD COLUMN last_used_at DATETIME")
    _ensure_column(sync_conn, "user_sessions", "revoked_at", "ALTER TABLE user_sessions ADD COLUMN revoked_at DATETIME")
    _ensure_column(sync_conn, "user_sessions", "created_at", "ALTER TABLE user_sessions ADD COLUMN created_at DATETIME")

    _ensure_column(sync_conn, "check_jobs", "owner_id", "ALTER TABLE check_jobs ADD COLUMN owner_id INTEGER")
    _ensure_column(sync_conn, "check_jobs", "summary", "ALTER TABLE check_jobs ADD COLUMN summary JSON")
    _ensure_column(sync_conn, "check_jobs", "last_error", "ALTER TABLE check_jobs ADD COLUMN last_error TEXT")
    _ensure_column(sync_conn, "domain_reports", "owner_id", "ALTER TABLE domain_reports ADD COLUMN owner_id INTEGER")
    _ensure_column(
        sync_conn,
        "webhook_subscriptions",
        "owner_id",
        "ALTER TABLE webhook_subscriptions ADD COLUMN owner_id INTEGER",
    )
    _ensure_column(sync_conn, "proxy_endpoints", "owner_id", "ALTER TABLE proxy_endpoints ADD COLUMN owner_id INTEGER")
    _ensure_column(sync_conn, "watchlist_items", "owner_id", "ALTER TABLE watchlist_items ADD COLUMN owner_id INTEGER")
    _ensure_column(sync_conn, "watchlist_items", "last_job_id", "ALTER TABLE watchlist_items ADD COLUMN last_job_id VARCHAR(36)")
    _ensure_column(sync_conn, "watchlist_items", "last_status", "ALTER TABLE watchlist_items ADD COLUMN last_status VARCHAR(24)")
    _ensure_column(sync_conn, "watchlist_items", "last_risk_score", "ALTER TABLE watchlist_items ADD COLUMN last_risk_score INTEGER")

    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_check_jobs_owner_id ON check_jobs(owner_id)")
    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_domain_reports_owner_id ON domain_reports(owner_id)")
    _ensure_index(
        sync_conn,
        "CREATE INDEX IF NOT EXISTS ix_webhook_subscriptions_owner_id ON webhook_subscriptions(owner_id)",
    )
    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_proxy_endpoints_owner_id ON proxy_endpoints(owner_id)")
    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_watchlist_items_owner_id ON watchlist_items(owner_id)")
    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_users_role ON users(role)")
    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_users_status ON users(status)")
    _ensure_index(
        sync_conn,
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_watchlist_owner_domain ON watchlist_items(owner_id, domain)",
    )


async def run_startup_migrations(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(_migrate)
