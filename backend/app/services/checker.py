from __future__ import annotations

import asyncio
import ipaddress
import time
from datetime import datetime, timezone
from typing import Any

import dns.asyncresolver
import dns.exception
import httpx

from app.core.config import get_settings
from app.db.session import AsyncSessionLocal
from app.services.app_settings import get_provider_settings
from app.services.catalog import DNSBL_SOURCES, BlacklistSource
from app.services.proxy_pool import ProxyLease, ProxyPool


class DomainChecker:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.lifetime = self.settings.dns_timeout_seconds
        self.proxy_pool = ProxyPool()
        self._provider_cache: dict[str, tuple[float, Any]] = {}
        if self.settings.dns_fallback_nameserver_list:
            self.resolver.nameservers = self.settings.dns_fallback_nameserver_list

    async def build_report(self, domain: str, *, owner_id: int | None) -> dict[str, Any]:
        provider_settings = await self._load_provider_settings()
        ip_addresses = await self._resolve_ips(domain)
        blacklists = await self._check_blacklists(domain, ip_addresses)
        email_auth = await self._check_email_auth(domain)
        safe_browsing = await self._check_safe_browsing(domain, owner_id=owner_id, settings_map=provider_settings)
        lumen = await self._check_lumen(domain, owner_id=owner_id, settings_map=provider_settings)
        providers = await self._check_optional_providers(
            domain,
            ip_addresses,
            owner_id=owner_id,
            settings_map=provider_settings,
        )
        risk_score = self._calculate_risk_score(blacklists, safe_browsing, lumen, providers, email_auth)
        overall_status = self._overall_status(risk_score, blacklists, safe_browsing, providers)
        return {
            "domain": domain,
            "overall_status": overall_status,
            "risk_score": risk_score,
            "blacklists": blacklists,
            "lumen": lumen,
            "safe_browsing": safe_browsing,
            "email_auth": email_auth,
            "providers": providers,
            "recommendations": self._recommendations(blacklists, safe_browsing, lumen, providers, email_auth),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _load_provider_settings(self) -> dict[str, str]:
        async with AsyncSessionLocal() as session:
            return await get_provider_settings(session)

    async def _resolve_ips(self, domain: str) -> list[str]:
        ips: set[str] = set()
        for record_type in ("A", "AAAA"):
            try:
                answers = await self.resolver.resolve(domain, record_type)
                ips.update(answer.to_text() for answer in answers)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
        return sorted(ips)

    async def _check_blacklists(self, domain: str, ip_addresses: list[str]) -> list[dict[str, Any]]:
        semaphore = asyncio.Semaphore(self.settings.blacklist_concurrency)

        async def evaluate(source: BlacklistSource) -> dict[str, Any]:
            async with semaphore:
                listed, reason = await self._lookup_source(source, domain, ip_addresses)
                return {
                    "source": source.name,
                    "listed": listed,
                    "reason": reason,
                    "listed_since": None,
                    "category": source.category,
                    "severity": "critical" if source.weight >= 15 else "high" if source.weight >= 5 else "medium",
                }

        return await asyncio.gather(*(evaluate(source) for source in DNSBL_SOURCES))

    async def _lookup_source(
        self,
        source: BlacklistSource,
        domain: str,
        ip_addresses: list[str],
    ) -> tuple[bool, str | None]:
        targets: list[str] = []
        if source.lookup == "ip":
            for ip_value in ip_addresses:
                try:
                    address = ipaddress.ip_address(ip_value)
                except ValueError:
                    continue
                if address.version == 4:
                    targets.append(".".join(reversed(ip_value.split("."))) + f".{source.zone}")
            if not targets:
                return False, "Domain has no resolved IPv4 address for IP-based DNSBL lookup"
        else:
            targets.append(f"{domain}.{source.zone}")

        for target in targets:
            try:
                answers = await self.resolver.resolve(target, "A")
                codes = ", ".join(answer.to_text() for answer in answers)
                return True, f"DNSBL response: {codes}"
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.resolver.NoNameservers:
                return False, "Blacklist source did not answer"
            except dns.exception.Timeout:
                return False, "Blacklist lookup timed out"
        return False, None

    async def _check_email_auth(self, domain: str) -> dict[str, Any]:
        spf = await self._check_txt_pattern(domain, "v=spf1", treat_missing_as="none")
        dmarc = await self._check_dmarc(domain)
        dkim = await self._check_dkim(domain)
        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "note": "DKIM is inferred via common selectors and may require manual confirmation.",
        }

    async def _check_txt_pattern(self, name: str, token: str, *, treat_missing_as: str) -> str:
        try:
            answers = await self.resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return treat_missing_as
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return "fail"
        values = ["".join(part.decode() for part in answer.strings) for answer in answers]
        if any(token.lower() in value.lower() for value in values):
            return "pass"
        return "fail"

    async def _check_dmarc(self, domain: str) -> str:
        try:
            answers = await self.resolver.resolve(f"_dmarc.{domain}", "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return "none"
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return "fail"
        values = ["".join(part.decode() for part in answer.strings) for answer in answers]
        if any("v=dmarc1" in value.lower() and "p=" in value.lower() for value in values):
            return "pass"
        return "fail"

    async def _check_dkim(self, domain: str) -> str:
        selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "smtp"]
        for selector in selectors:
            try:
                answers = await self.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except (dns.resolver.NoNameservers, dns.exception.Timeout):
                return "fail"
            values = ["".join(part.decode() for part in answer.strings) for answer in answers]
            if any("v=dkim1" in value.lower() for value in values):
                return "pass"
            return "fail"
        return "none"

    async def _check_safe_browsing(
        self,
        domain: str,
        *,
        owner_id: int | None,
        settings_map: dict[str, str],
    ) -> dict[str, Any]:
        api_key = settings_map.get("google_safe_browsing_api_key", "")
        if not api_key:
            return {"status": "unknown", "note": "API key is not configured"}

        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "domain-blacklist-checker", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"http://{domain}/"}, {"url": f"https://{domain}/"}],
            },
        }
        try:
            response = await self._http_request("POST", url, owner_id=owner_id, json=payload)
        except httpx.HTTPError as exc:
            return {"status": "unknown", "note": f"Safe Browsing request failed: {exc}"}
        data = response.json()
        matches = data.get("matches", [])
        if not matches:
            return {"status": "safe", "note": None}
        threat = matches[0].get("threatType", "")
        mapping = {
            "MALWARE": "malware",
            "SOCIAL_ENGINEERING": "phishing",
            "UNWANTED_SOFTWARE": "unwanted",
            "POTENTIALLY_HARMFUL_APPLICATION": "unwanted",
        }
        return {"status": mapping.get(threat, "unknown"), "note": threat or "Threat match detected"}

    async def _check_lumen(
        self,
        domain: str,
        *,
        owner_id: int | None,
        settings_map: dict[str, str],
    ) -> dict[str, Any]:
        search_url = settings_map.get("lumen_search_url", "")
        if not search_url:
            return {
                "status": "unknown",
                "total_notices": 0,
                "trend": None,
                "notices": [],
                "note": "Lumen search URL is not configured",
            }
        try:
            response = await self._http_request("GET", search_url, owner_id=owner_id, params={"domain": domain})
        except httpx.HTTPError as exc:
            return {
                "status": "unknown",
                "total_notices": 0,
                "trend": None,
                "notices": [],
                "note": f"Lumen request failed: {exc}",
            }
        payload = response.json()
        notices = payload.get("notices", [])
        parsed_notices = [
            {
                "title": item.get("title") or "Notice",
                "notice_type": item.get("notice_type") or "Other",
                "sender": item.get("sender"),
                "date": item.get("date"),
                "description": item.get("description"),
            }
            for item in notices
        ]
        return {
            "status": "ok",
            "total_notices": int(payload.get("total_notices", len(parsed_notices))),
            "trend": payload.get("trend"),
            "notices": parsed_notices,
            "note": payload.get("note"),
        }

    async def _http_request(self, method: str, url: str, *, owner_id: int | None, **kwargs: Any) -> httpx.Response:
        candidates = await self.proxy_pool.acquire_candidates(owner_id, self.settings.proxy_attempts_per_request)
        last_error: httpx.HTTPError | None = None

        for lease in candidates:
            try:
                response = await self._send_http_request(method, url, proxy=lease, **kwargs)
                await self.proxy_pool.mark_success(lease.id)
                return response
            except httpx.HTTPError as exc:
                last_error = exc
                await self.proxy_pool.mark_failure(lease.id, str(exc))

        if self.settings.direct_http_fallback:
            try:
                return await self._send_http_request(method, url, proxy=None, **kwargs)
            except httpx.HTTPError as exc:
                if last_error is not None:
                    raise last_error
                raise exc
        if last_error is not None:
            raise last_error
        return await self._send_http_request(method, url, proxy=None, **kwargs)

    async def _send_http_request(
        self,
        method: str,
        url: str,
        proxy: ProxyLease | None,
        **kwargs: Any,
    ) -> httpx.Response:
        client_kwargs: dict[str, Any] = {"timeout": self.settings.request_timeout}
        if proxy is not None:
            client_kwargs["proxy"] = proxy.url
        async with httpx.AsyncClient(**client_kwargs) as client:
            response = await client.request(method, url, **kwargs)
            response.raise_for_status()
            return response

    async def _check_optional_providers(
        self,
        domain: str,
        ip_addresses: list[str],
        *,
        owner_id: int | None,
        settings_map: dict[str, str],
    ) -> list[dict[str, Any]]:
        provider_tasks = [
            ("VirusTotal", self._check_virustotal(domain, owner_id=owner_id, settings_map=settings_map)),
            ("PhishTank", self._check_phishtank(domain, owner_id=owner_id, settings_map=settings_map)),
            ("AbuseIPDB", self._check_abuseipdb(ip_addresses, owner_id=owner_id, settings_map=settings_map)),
            ("URLhaus", self._check_urlhaus(domain, owner_id=owner_id, settings_map=settings_map)),
            ("Cisco Talos", self._check_talos(domain, owner_id=owner_id, settings_map=settings_map)),
        ]
        results = await asyncio.gather(*(task for _, task in provider_tasks), return_exceptions=True)
        providers: list[dict[str, Any]] = []
        for (name, _), result in zip(provider_tasks, results, strict=False):
            if isinstance(result, Exception):
                providers.append(self._provider_unknown(name, f"Provider check failed: {result}"))
            else:
                providers.append(result)
        return providers

    async def _check_virustotal(self, domain: str, *, owner_id: int | None, settings_map: dict[str, str]) -> dict[str, Any]:
        api_key = settings_map.get("virustotal_api_key", "")
        if not api_key:
            return self._provider_unknown("VirusTotal", "API key is not configured")

        cache_key = f"virustotal:{domain}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            response = await self._http_request(
                "GET",
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                owner_id=owner_id,
                headers={"x-apikey": api_key},
            )
        except httpx.HTTPError as exc:
            result = self._provider_unknown("VirusTotal", f"Request failed: {exc}")
            self._cache_set(cache_key, result)
            return result

        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        reputation = attributes.get("reputation", 0)
        listed = malicious > 0 or suspicious > 0 or reputation < 0
        result = {
            "name": "VirusTotal",
            "status": "listed" if listed else "clean",
            "listed": listed,
            "note": (
                f"malicious={malicious}, suspicious={suspicious}, harmless={harmless}, reputation={reputation}"
                if listed or malicious or suspicious or reputation
                else "No malicious consensus returned by VirusTotal."
            ),
        }
        self._cache_set(cache_key, result)
        return result

    async def _check_phishtank(self, domain: str, *, owner_id: int | None, settings_map: dict[str, str]) -> dict[str, Any]:
        cache_key = f"phishtank:{domain}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        payload = {
            "url": f"http://{domain}/",
            "format": "json",
            "app_key": settings_map.get("phishtank_app_key", ""),
        }
        headers = {
            "User-Agent": settings_map.get("phishtank_user_agent", self.settings.phishtank_user_agent),
            "Accept": "application/json",
        }
        try:
            response = await self._http_request(
                "POST",
                "https://checkurl.phishtank.com/checkurl/",
                owner_id=owner_id,
                data=payload,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            result = self._provider_unknown("PhishTank", f"Request failed: {exc}")
            self._cache_set(cache_key, result)
            return result

        results = response.json().get("results", {})
        listed = bool(results.get("in_database")) and bool(results.get("valid"))
        phish_id = results.get("phish_id")
        result = {
            "name": "PhishTank",
            "status": "listed" if listed else "clean",
            "listed": listed,
            "note": f"Matched phishing record id={phish_id}" if listed and phish_id else "No active phishing match returned.",
        }
        self._cache_set(cache_key, result)
        return result

    async def _check_abuseipdb(
        self,
        ip_addresses: list[str],
        *,
        owner_id: int | None,
        settings_map: dict[str, str],
    ) -> dict[str, Any]:
        api_key = settings_map.get("abuseipdb_api_key", "")
        if not api_key:
            return self._provider_unknown("AbuseIPDB", "API key is not configured")
        if not ip_addresses:
            return self._provider_unknown("AbuseIPDB", "No resolved IP addresses available")

        worst_confidence = 0
        worst_note: str | None = None
        for ip_value in ip_addresses[:3]:
            cache_key = f"abuseipdb:{ip_value}"
            cached = self._cache_get(cache_key)
            if cached is not None:
                confidence = int(cached.get("_confidence", 0))
                if confidence > worst_confidence:
                    worst_confidence = confidence
                    worst_note = cached.get("note")
                continue
            try:
                response = await self._http_request(
                    "GET",
                    "https://api.abuseipdb.com/api/v2/check",
                    owner_id=owner_id,
                    params={"ipAddress": ip_value, "maxAgeInDays": "90"},
                    headers={"Accept": "application/json", "Key": api_key},
                )
            except httpx.HTTPError as exc:
                return self._provider_unknown("AbuseIPDB", f"Request failed: {exc}")
            data = response.json().get("data", {})
            confidence = int(data.get("abuseConfidenceScore", 0))
            reports = int(data.get("totalReports", 0))
            listed = confidence >= 50 or reports >= 5
            result = {
                "name": "AbuseIPDB",
                "status": "listed" if listed else "clean",
                "listed": listed,
                "note": f"{ip_value}: confidence={confidence}, reports={reports}",
                "_confidence": confidence,
            }
            self._cache_set(cache_key, result)
            if confidence > worst_confidence:
                worst_confidence = confidence
                worst_note = result["note"]
        return {
            "name": "AbuseIPDB",
            "status": "listed" if worst_confidence >= 50 else "clean",
            "listed": worst_confidence >= 50,
            "note": worst_note or f"Checked {ip_addresses[0]}",
        }

    async def _check_urlhaus(self, domain: str, *, owner_id: int | None, settings_map: dict[str, str]) -> dict[str, Any]:
        api_url = settings_map.get("urlhaus_api_url", "")
        auth_key = settings_map.get("urlhaus_auth_key", "")
        if not api_url or not auth_key:
            return self._provider_unknown("URLhaus", "API endpoint or auth key is not configured")

        cache_key = f"urlhaus:{domain}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            response = await self._http_request(
                "POST",
                api_url,
                owner_id=owner_id,
                data={"host": domain},
                headers={"Auth-Key": auth_key},
            )
        except httpx.HTTPError as exc:
            result = self._provider_unknown("URLhaus", f"Request failed: {exc}")
            self._cache_set(cache_key, result)
            return result

        payload = response.json()
        urls = payload.get("urls", []) or []
        listed = payload.get("query_status") == "ok" and bool(urls)
        result = {
            "name": "URLhaus",
            "status": "listed" if listed else "clean",
            "listed": listed,
            "note": f"Matched {len(urls)} malicious URL records." if listed else payload.get("query_status", "No URLhaus hits."),
        }
        self._cache_set(cache_key, result)
        return result

    async def _check_talos(self, domain: str, *, owner_id: int | None, settings_map: dict[str, str]) -> dict[str, Any]:
        del owner_id, settings_map
        return self._provider_unknown(
            "Cisco Talos",
            f"No supported public API is configured for automated lookups; use manual Talos review for {domain}.",
        )

    def _provider_unknown(self, name: str, note: str) -> dict[str, Any]:
        return {"name": name, "status": "unknown", "listed": None, "note": note}

    def _cache_get(self, key: str) -> Any | None:
        cached = self._provider_cache.get(key)
        if not cached:
            return None
        expires_at, value = cached
        if expires_at <= time.time():
            self._provider_cache.pop(key, None)
            return None
        return value

    def _cache_set(self, key: str, value: Any) -> None:
        self._provider_cache[key] = (time.time() + self.settings.provider_cache_seconds, value)

    def _calculate_risk_score(
        self,
        blacklists: list[dict[str, Any]],
        safe_browsing: dict[str, Any],
        lumen: dict[str, Any],
        providers: list[dict[str, Any]],
        email_auth: dict[str, Any],
    ) -> int:
        source_weight = {source.name: source.weight for source in DNSBL_SOURCES}
        score = 0
        for item in blacklists:
            if item["listed"]:
                score += source_weight.get(item["source"], 3)
        if safe_browsing["status"] in {"malware", "phishing", "unwanted"}:
            score += 25
        score += min(int(lumen["total_notices"]) * 2, 20)
        for provider in providers:
            if provider.get("listed"):
                score += 20
        if email_auth["spf"] == "none":
            score += 5
        if email_auth["dkim"] == "none":
            score += 5
        if email_auth["dmarc"] == "none":
            score += 5
        return min(score, 100)

    def _overall_status(
        self,
        risk_score: int,
        blacklists: list[dict[str, Any]],
        safe_browsing: dict[str, Any],
        providers: list[dict[str, Any]],
    ) -> str:
        if any(item["listed"] for item in blacklists) or safe_browsing["status"] in {"malware", "phishing", "unwanted"}:
            return "listed"
        if any(provider.get("listed") for provider in providers) or risk_score > 0:
            return "warning"
        return "clean"

    def _recommendations(
        self,
        blacklists: list[dict[str, Any]],
        safe_browsing: dict[str, Any],
        lumen: dict[str, Any],
        providers: list[dict[str, Any]],
        email_auth: dict[str, Any],
    ) -> list[str]:
        recommendations: list[str] = []
        if any(item["listed"] for item in blacklists):
            recommendations.append(
                "Review the listed IP/domain, remove the root cause, and submit delisting requests for the affected blacklists."
            )
        if safe_browsing["status"] in {"malware", "phishing", "unwanted"}:
            recommendations.append(
                "Run a malware and phishing audit immediately before requesting Google Safe Browsing re-review."
            )
        if lumen["total_notices"] > 0:
            recommendations.append(
                "Review recent legal notices in Lumen, confirm legitimacy, and remove or dispute the flagged content."
            )
        if any(provider.get("listed") for provider in providers):
            recommendations.append(
                "Correlate third-party reputation findings with server logs and abuse mailbox history."
            )
        for key in ("spf", "dkim", "dmarc"):
            if email_auth[key] == "none":
                recommendations.append(f"Publish a valid {key.upper()} record to improve deliverability and trust.")
        if not recommendations:
            recommendations.append("No critical findings detected. Keep monitoring and export the report for baseline tracking.")
        return recommendations
