"""Compute the overall security score, risk rating, and executive summary."""
from __future__ import annotations

from scanner.models import (
    RiskRating,
    Scan,
    Severity,
    SEVERITY_WEIGHT,
)


def _risk_from_score(score: int, counts: dict) -> str:
    if counts.get(Severity.CRITICAL, 0) > 0 or score < 40:
        return RiskRating.CRITICAL
    if counts.get(Severity.HIGH, 0) > 0 or score < 60:
        return RiskRating.HIGH
    if counts.get(Severity.MEDIUM, 0) > 0 or score < 80:
        return RiskRating.MEDIUM
    if counts.get(Severity.LOW, 0) > 0 or score < 95:
        return RiskRating.LOW
    return RiskRating.MINIMAL


def _build_summary(scan: Scan, counts: dict) -> str:
    total = sum(counts.values())
    parts = [
        f"The automated assessment of {scan.target_url} discovered {total} "
        f"finding(s) across {scan.total_urls_discovered} URL(s), issuing "
        f"{scan.total_requests} request(s)."
    ]
    sev_bits = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO):
        n = counts.get(sev, 0)
        if n:
            sev_bits.append(f"{n} {dict(Severity.choices)[sev].lower()}")
    if sev_bits:
        parts.append("Severity breakdown: " + ", ".join(sev_bits) + ".")

    crit = counts.get(Severity.CRITICAL, 0)
    high = counts.get(Severity.HIGH, 0)
    if crit:
        parts.append(
            f"{crit} critical issue(s) require immediate remediation as they "
            "may permit full compromise (e.g. injection or exposed secrets).")
    elif high:
        parts.append(
            f"{high} high-severity issue(s) should be prioritised for "
            "remediation.")
    else:
        parts.append("No critical or high-severity issues were confirmed; "
                     "remaining items are hardening opportunities.")

    parts.append(
        f"Overall security score: {scan.security_score}/100 "
        f"({dict(RiskRating.choices)[scan.risk_rating]} risk). "
        f"Scan duration: {scan.duration_display}.")
    return " ".join(parts)


def finalize(scan: Scan) -> None:
    """Populate score, rating and executive summary from stored findings."""
    counts = scan.severity_counts()
    penalty = 0
    for sev, n in counts.items():
        try:
            penalty += SEVERITY_WEIGHT[Severity(sev)] * n
        except (ValueError, KeyError):
            continue
    score = max(0, 100 - min(penalty, 100))
    scan.security_score = score
    scan.risk_rating = _risk_from_score(score, {Severity(k): v
                                                for k, v in counts.items()})
    scan.executive_summary = _build_summary(scan, {Severity(k): v
                                                  for k, v in counts.items()})
    scan.save(update_fields=["security_score", "risk_rating",
                             "executive_summary"])
