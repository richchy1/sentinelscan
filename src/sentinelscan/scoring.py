"""Deterministic severity-to-points scoring.

This is a simple, documented model. It is NOT CVSS. The same findings always give the
same scores, order and rating: there is no randomness and no clock.
"""

from collections.abc import Iterable
from dataclasses import replace

from sentinelscan.models import Finding, RiskSummary, Severity

POINTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 30,
    Severity.HIGH: 60,
    Severity.CRITICAL: 90,
}
MAX_SCORE = 100


def points_for(severity: Severity) -> int:
    return POINTS[severity]


def score_finding(finding: Finding) -> Finding:
    """A copy of ``finding`` with its score filled in from its severity."""
    return replace(finding, score=points_for(finding.severity))


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Severity descending, then id, then port (None last)."""
    return sorted(
        findings,
        key=lambda f: (-int(f.severity), f.id, f.port if f.port is not None else 1 << 20),
    )


def summarize(findings: Iterable[Finding]) -> RiskSummary:
    """Counts per severity, the capped aggregate score, and an overall rating."""
    items = list(findings)
    counts = {severity.label: 0 for severity in sorted(Severity, reverse=True)}
    unique: dict[tuple[str, int | None], int] = {}
    for finding in items:
        counts[finding.severity.label] += 1
        unique[(finding.id, finding.port)] = points_for(finding.severity)
    aggregate = min(MAX_SCORE, sum(unique.values()))

    highest = max((f.severity for f in items), default=None)
    highest_label = highest.label if highest is not None else "NONE"
    rating = highest_label if highest is not None and highest > Severity.INFO else "NONE"
    return RiskSummary(
        counts_by_severity=counts,
        highest_severity=highest_label,
        aggregate_score=aggregate,
        rating=rating,
    )
