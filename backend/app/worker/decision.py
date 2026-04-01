from __future__ import annotations

from dataclasses import dataclass

from app.db.models import Domain
from app.worker.checks import DnsSignal, RdapSignal


@dataclass(slots=True)
class DecisionResult:
    status: str
    check_mode: str
    confirmations: int
    last_error: str | None
    should_alert: bool
    should_log: bool
    log_type: str
    log_message: str


def evaluate_domain(
    domain: Domain,
    *,
    dns_signal: DnsSignal,
    rdap_signal: RdapSignal,
    confirmation_threshold: int,
) -> DecisionResult:
    possible_available = dns_signal == DnsSignal.NXDOMAIN and rdap_signal == RdapSignal.NOT_FOUND
    normal_mode = "normal"

    if domain.status == "available":
        if possible_available:
            return DecisionResult(
                status="available",
                check_mode="available-watch" if domain.available_recheck_enabled else "available-stop",
                confirmations=max(domain.available_confirmations, confirmation_threshold),
                last_error=None,
                should_alert=False,
                should_log=False,
                log_type="info",
                log_message="Domain remains available",
            )
        if dns_signal == DnsSignal.EXISTS and rdap_signal == RdapSignal.FOUND:
            return DecisionResult(
                status="captured",
                check_mode="captured",
                confirmations=0,
                last_error=None,
                should_alert=False,
                should_log=True,
                log_type="info",
                log_message="Domain is no longer available and appears captured again",
            )
        if dns_signal == DnsSignal.ERROR or rdap_signal == RdapSignal.ERROR:
            return DecisionResult(
                status="available",
                check_mode="available-watch" if domain.available_recheck_enabled else "available-stop",
                confirmations=max(domain.available_confirmations, confirmation_threshold),
                last_error="Temporary check failure while observing available domain",
                should_alert=False,
                should_log=False,
                log_type="info",
                log_message="Temporary check failure while observing available domain",
            )
        return DecisionResult(
            status="available",
            check_mode="available-watch" if domain.available_recheck_enabled else "available-stop",
            confirmations=max(domain.available_confirmations, confirmation_threshold),
            last_error=None,
            should_alert=False,
            should_log=False,
            log_type="info",
            log_message="Availability state preserved while waiting for next signal",
        )

    if possible_available:
        confirmations = domain.available_confirmations + 1
        if confirmations >= confirmation_threshold:
            return DecisionResult(
                status="available",
                check_mode="available-watch" if domain.available_recheck_enabled else "available-stop",
                confirmations=confirmations,
                last_error=None,
                should_alert=True,
                should_log=True,
                log_type="available",
                log_message=(
                    f"Confirmed available after {confirmations} checks "
                    f"(DNS={dns_signal}, RDAP={rdap_signal})"
                ),
            )
        return DecisionResult(
            status="checking",
            check_mode=normal_mode,
            confirmations=confirmations,
            last_error=None,
            should_alert=False,
            should_log=confirmations == 1,
            log_type="info",
            log_message=f"Possible availability detected (DNS={dns_signal}, RDAP={rdap_signal})",
        )

    if dns_signal == DnsSignal.ERROR and rdap_signal == RdapSignal.ERROR:
        return DecisionResult(
            status="error",
            check_mode=normal_mode,
            confirmations=0,
            last_error="DNS and RDAP checks failed",
            should_alert=False,
            should_log=True,
            log_type="error",
            log_message="DNS and RDAP checks failed in the same cycle",
        )

    if rdap_signal == RdapSignal.ERROR:
        return DecisionResult(
            status="checking",
            check_mode=normal_mode,
            confirmations=0,
            last_error="Temporary RDAP failure",
            should_alert=False,
            should_log=False,
            log_type="info",
            log_message="RDAP check failed",
        )

    if dns_signal == DnsSignal.ERROR:
        return DecisionResult(
            status="checking",
            check_mode=normal_mode,
            confirmations=0,
            last_error="DNS check failed",
            should_alert=False,
            should_log=False,
            log_type="info",
            log_message="DNS check failed",
        )

    return DecisionResult(
        status="checking",
        check_mode=normal_mode,
        confirmations=0,
        last_error=None,
        should_alert=False,
        should_log=False,
        log_type="info",
        log_message=f"Domain still registered (DNS={dns_signal}, RDAP={rdap_signal})",
    )
