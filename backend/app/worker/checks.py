from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum

import dns.asyncresolver
import dns.resolver
import httpx

from app.core.config import Settings
from app.db.models import Proxy
from app.services.proxy_utils import build_proxy_url

logger = logging.getLogger(__name__)


class DnsSignal(StrEnum):
    NXDOMAIN = "NXDOMAIN"
    EXISTS = "EXISTS"
    ERROR = "ERROR"


class RdapSignal(StrEnum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"


@dataclass(slots=True)
class RdapResult:
    signal: RdapSignal
    owner: str | None = None
    registration_status: str | None = None


@dataclass(slots=True)
class CheckOutcome:
    dns: DnsSignal
    rdap_direct: RdapResult
    rdap_proxy: RdapResult | None

    @property
    def effective_rdap(self) -> RdapResult:
        if self.rdap_direct.signal == RdapSignal.ERROR and self.rdap_proxy is not None:
            return self.rdap_proxy
        return self.rdap_direct


async def dns_check(domain: str, settings: Settings) -> DnsSignal:
    errors: list[str] = []
    resolver_pool: list[tuple[str, dns.asyncresolver.Resolver]] = []

    system_resolver = dns.asyncresolver.Resolver()
    system_resolver.timeout = settings.dns_timeout_seconds
    system_resolver.lifetime = settings.dns_timeout_seconds
    resolver_pool.append(("system", system_resolver))

    fallback_nameservers = settings.dns_fallback_nameserver_list
    if fallback_nameservers:
        fallback_resolver = dns.asyncresolver.Resolver(configure=False)
        fallback_resolver.nameservers = fallback_nameservers
        fallback_resolver.timeout = settings.dns_timeout_seconds
        fallback_resolver.lifetime = settings.dns_timeout_seconds
        resolver_pool.append(("fallback", fallback_resolver))

    for resolver_name, resolver in resolver_pool:
        for record_type in ("NS", "SOA"):
            try:
                await resolver.resolve(domain, record_type, lifetime=settings.dns_timeout_seconds)
                return DnsSignal.EXISTS
            except dns.resolver.NXDOMAIN:
                return DnsSignal.NXDOMAIN
            except dns.resolver.NoAnswer:
                return DnsSignal.EXISTS
            except Exception as exc:
                errors.append(f"{resolver_name}:{record_type}:{type(exc).__name__}:{exc}")

    logger.warning("DNS check failed for %s: %s", domain, " | ".join(errors))
    return DnsSignal.ERROR


async def rdap_check(
    domain: str,
    settings: Settings,
    proxy: Proxy | None = None,
) -> RdapResult:
    target = f"{settings.rdap_base_url.rstrip('/')}/{domain}"
    client_kwargs: dict[str, object] = {
        "timeout": settings.rdap_timeout_seconds,
        "follow_redirects": True,
    }
    if proxy is not None:
        client_kwargs["proxy"] = build_proxy_url(proxy)

    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            response = await client.get(target)
        if response.status_code == 404:
            return RdapResult(signal=RdapSignal.NOT_FOUND)
        if 200 <= response.status_code < 300:
            payload = response.json()
            return RdapResult(
                signal=RdapSignal.FOUND,
                owner=_extract_owner(payload),
                registration_status=_extract_registration_status(payload),
            )
        logger.warning("Unexpected RDAP status for %s: %s", domain, response.status_code)
        return RdapResult(signal=RdapSignal.ERROR)
    except Exception:
        logger.exception("RDAP check failed for %s", domain)
        return RdapResult(signal=RdapSignal.ERROR)


def _extract_owner(payload: dict) -> str | None:
    entities = payload.get("entities") or []
    priority_roles = {"registrant", "holder", "administrative"}
    fallback: list[str] = []
    for entity in entities:
        label = _entity_label(entity)
        if not label:
            continue
        roles = set(entity.get("roles") or [])
        if roles & priority_roles:
            return label
        fallback.append(label)
    if fallback:
        return fallback[0]
    return payload.get("ldhName")


def _entity_label(entity: dict) -> str | None:
    handle = entity.get("handle")
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            key = item[0]
            value = item[3]
            if key in {"fn", "org"}:
                if isinstance(value, list) and value:
                    return str(value[0])
                if value:
                    return str(value)
    return handle


def _extract_registration_status(payload: dict) -> str | None:
    statuses = payload.get("status") or []
    if not statuses:
        return None
    return ", ".join(str(item) for item in statuses)
