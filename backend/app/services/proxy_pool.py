from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import select

from app.db.models import ProxyEndpoint
from app.db.session import AsyncSessionLocal

SUPPORTED_PROXY_SCHEMES = {"http", "https", "socks5", "socks5h"}


def parse_proxy_url(proxy_url: str) -> dict[str, str | int | None]:
    parsed = urlparse(proxy_url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED_PROXY_SCHEMES:
        raise ValueError("Supported proxy schemes: http, https, socks5, socks5h")
    if not parsed.hostname or not parsed.port:
        raise ValueError("Proxy must include host and port")

    return {
        "scheme": scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "username": parsed.username,
        "password": parsed.password,
    }


def build_proxy_url(proxy: ProxyEndpoint) -> str:
    credentials = ""
    if proxy.username:
        credentials = proxy.username
        if proxy.password:
            credentials += f":{proxy.password}"
        credentials += "@"
    return f"{proxy.scheme}://{credentials}{proxy.host}:{proxy.port}"


@dataclass(frozen=True)
class ProxyLease:
    id: int
    url: str


class ProxyPool:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._cursor = 0

    async def acquire_candidates(self, owner_id: int | None, limit: int = 3) -> list[ProxyLease]:
        async with self._lock:
            async with AsyncSessionLocal() as session:
                query = select(ProxyEndpoint).where(ProxyEndpoint.is_active.is_(True))
                if owner_id is not None:
                    query = query.where(ProxyEndpoint.owner_id == owner_id)
                result = await session.execute(query.order_by(ProxyEndpoint.fail_count.asc(), ProxyEndpoint.id.asc()))
                proxies = result.scalars().all()
            if not proxies:
                return []
            ordered = proxies[self._cursor :] + proxies[: self._cursor]
            self._cursor = (self._cursor + 1) % len(proxies)
            return [ProxyLease(id=proxy.id, url=build_proxy_url(proxy)) for proxy in ordered[:limit]]

    async def mark_success(self, proxy_id: int) -> None:
        async with AsyncSessionLocal() as session:
            proxy = await session.get(ProxyEndpoint, proxy_id)
            if proxy is None:
                return
            proxy.success_count += 1
            proxy.last_used_at = datetime.now(timezone.utc)
            proxy.last_error = None
            await session.commit()

    async def mark_failure(self, proxy_id: int, error: str) -> None:
        async with AsyncSessionLocal() as session:
            proxy = await session.get(ProxyEndpoint, proxy_id)
            if proxy is None:
                return
            proxy.fail_count += 1
            proxy.last_used_at = datetime.now(timezone.utc)
            proxy.last_error = error[:1000]
            await session.commit()
