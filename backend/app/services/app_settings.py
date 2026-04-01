from __future__ import annotations

from collections.abc import Mapping

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import AppSetting

PROVIDER_SETTING_KEYS = {
    "google_safe_browsing_api_key": "google_safe_browsing_api_key",
    "lumen_search_url": "lumen_search_url",
    "virustotal_api_key": "virustotal_api_key",
    "phishtank_app_key": "phishtank_app_key",
    "phishtank_user_agent": "phishtank_user_agent",
    "abuseipdb_api_key": "abuseipdb_api_key",
    "urlhaus_api_url": "urlhaus_api_url",
    "urlhaus_auth_key": "urlhaus_auth_key",
    "talos_api_url": "talos_api_url",
    "webhook_signing_secret": "webhook_signing_secret",
}


async def get_app_setting(session: AsyncSession, key: str) -> str | None:
    result = await session.execute(select(AppSetting).where(AppSetting.key == key))
    setting = result.scalar_one_or_none()
    return setting.value if setting else None


async def set_app_setting(session: AsyncSession, key: str, value: str | None) -> AppSetting:
    result = await session.execute(select(AppSetting).where(AppSetting.key == key))
    setting = result.scalar_one_or_none()
    if setting is None:
        setting = AppSetting(key=key, value=value)
        session.add(setting)
    else:
        setting.value = value
    await session.flush()
    return setting


async def get_settings_map(session: AsyncSession, keys: list[str]) -> dict[str, str | None]:
    result = await session.execute(select(AppSetting).where(AppSetting.key.in_(keys)))
    stored = {item.key: item.value for item in result.scalars().all()}
    return {key: stored.get(key) for key in keys}


async def get_provider_settings(session: AsyncSession) -> dict[str, str]:
    settings = get_settings()
    stored = await get_settings_map(session, list(PROVIDER_SETTING_KEYS.values()))
    return {
        "google_safe_browsing_api_key": stored.get("google_safe_browsing_api_key") or settings.google_safe_browsing_api_key,
        "lumen_search_url": stored.get("lumen_search_url") or settings.lumen_search_url,
        "virustotal_api_key": stored.get("virustotal_api_key") or settings.virustotal_api_key,
        "phishtank_app_key": stored.get("phishtank_app_key") or settings.phishtank_app_key,
        "phishtank_user_agent": stored.get("phishtank_user_agent") or settings.phishtank_user_agent,
        "abuseipdb_api_key": stored.get("abuseipdb_api_key") or settings.abuseipdb_api_key,
        "urlhaus_api_url": stored.get("urlhaus_api_url") or settings.urlhaus_api_url,
        "urlhaus_auth_key": stored.get("urlhaus_auth_key") or settings.urlhaus_auth_key,
        "talos_api_url": stored.get("talos_api_url") or settings.talos_api_url,
        "webhook_signing_secret": stored.get("webhook_signing_secret") or settings.webhook_signing_secret,
    }


async def update_provider_settings(session: AsyncSession, values: Mapping[str, str | None]) -> dict[str, str]:
    for key, value in values.items():
        if key in PROVIDER_SETTING_KEYS:
            await set_app_setting(session, PROVIDER_SETTING_KEYS[key], value or None)
    await session.commit()
    return await get_provider_settings(session)
