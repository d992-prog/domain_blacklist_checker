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

    _ensure_column(sync_conn, "check_jobs", "owner_id", "ALTER TABLE check_jobs ADD COLUMN owner_id INTEGER")
    _ensure_column(sync_conn, "domain_reports", "owner_id", "ALTER TABLE domain_reports ADD COLUMN owner_id INTEGER")
    _ensure_column(
        sync_conn,
        "webhook_subscriptions",
        "owner_id",
        "ALTER TABLE webhook_subscriptions ADD COLUMN owner_id INTEGER",
    )
    _ensure_column(sync_conn, "proxy_endpoints", "owner_id", "ALTER TABLE proxy_endpoints ADD COLUMN owner_id INTEGER")
    _ensure_column(sync_conn, "watchlist_items", "owner_id", "ALTER TABLE watchlist_items ADD COLUMN owner_id INTEGER")

    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_check_jobs_owner_id ON check_jobs(owner_id)")
    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_domain_reports_owner_id ON domain_reports(owner_id)")
    _ensure_index(
        sync_conn,
        "CREATE INDEX IF NOT EXISTS ix_webhook_subscriptions_owner_id ON webhook_subscriptions(owner_id)",
    )
    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_proxy_endpoints_owner_id ON proxy_endpoints(owner_id)")
    _ensure_index(sync_conn, "CREATE INDEX IF NOT EXISTS ix_watchlist_items_owner_id ON watchlist_items(owner_id)")
    _ensure_index(
        sync_conn,
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_watchlist_owner_domain ON watchlist_items(owner_id, domain)",
    )


async def run_startup_migrations(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(_migrate)
