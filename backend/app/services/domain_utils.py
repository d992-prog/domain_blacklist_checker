from __future__ import annotations

import re
from ipaddress import ip_address


DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(value: str) -> str | None:
    raw = value.strip().lower()
    if not raw:
        return None
    if raw.startswith(("http://", "https://")):
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    raw = raw.strip(".")
    if not raw or "@" in raw:
        return None
    try:
        ip_address(raw)
        return None
    except ValueError:
        pass
    return raw if DOMAIN_RE.match(raw) else None


def dedupe_domains(values: list[str]) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values:
        domain = normalize_domain(value)
        if domain and domain not in seen:
            seen.add(domain)
            normalized.append(domain)
    return normalized
