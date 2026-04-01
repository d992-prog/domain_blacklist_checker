from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.db.models import Domain


@dataclass(slots=True)
class RuntimeSchedule:
    mode: str
    interval: float


def _pattern_window_bounds(domain: Domain) -> tuple[int, int]:
    start = max(0, min(59, domain.pattern_window_start_minute))
    end = max(0, min(59, domain.pattern_window_end_minute))
    return start, end


def _pattern_window_active(minute: int, start: int, end: int) -> bool:
    if start <= end:
        return start <= minute <= end
    return minute >= start or minute <= end


def _pattern_spread(domain: Domain) -> float:
    return (((domain.id or 1) * 37) % 11 - 5) / 20


def _pattern_slow_interval(domain: Domain) -> float:
    slow_interval = max(1.0, domain.pattern_slow_interval)
    return max(1.0, slow_interval * (1 + _pattern_spread(domain)))


def _seconds_until_window_start(now: datetime, start_minute: int) -> float:
    current_seconds = (now.minute * 60) + now.second + (now.microsecond / 1_000_000)
    start_seconds = start_minute * 60
    remaining = start_seconds - current_seconds
    if remaining <= 0:
        remaining += 3600
    return max(0.1, remaining)


def expected_runtime_interval(domain: Domain) -> float:
    if domain.check_mode in {"capture-watch", "pattern-fast"}:
        return max(0.1, domain.pattern_fast_interval)
    if domain.check_mode == "pattern-slow":
        return _pattern_slow_interval(domain)
    if domain.check_mode in {"available-watch", "available-stop"}:
        return max(10.0, domain.available_recheck_interval)
    return max(0.1, domain.check_interval)


def resolve_runtime_schedule(domain: Domain, base_mode: str, now: datetime) -> RuntimeSchedule:
    if domain.available_at is not None:
        seconds_since_available = (now - domain.available_at).total_seconds()
        if seconds_since_available <= 15 and base_mode in {"available-watch", "available-stop"}:
            return RuntimeSchedule(mode="capture-watch", interval=max(0.1, domain.pattern_fast_interval))

    if base_mode == "available-watch":
        return RuntimeSchedule(
            mode="available-watch",
            interval=max(10.0, domain.available_recheck_interval),
        )

    if base_mode == "available-stop":
        return RuntimeSchedule(
            mode="available-stop",
            interval=max(10.0, domain.available_recheck_interval),
        )

    if domain.scheduler_mode == "pattern":
        start, end = _pattern_window_bounds(domain)
        if _pattern_window_active(now.minute, start, end):
            return RuntimeSchedule(
                mode="pattern-fast",
                interval=max(0.1, domain.pattern_fast_interval),
            )
        slow_interval = _pattern_slow_interval(domain)
        window_wakeup_interval = _seconds_until_window_start(now, start)
        return RuntimeSchedule(
            mode="pattern-slow",
            interval=min(slow_interval, window_wakeup_interval),
        )

    return RuntimeSchedule(mode="normal", interval=max(0.1, domain.check_interval))
