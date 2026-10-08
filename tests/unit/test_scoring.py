from sentinelscan.models import Category, Finding, Severity
from sentinelscan.scoring import POINTS, points_for, score_finding, sort_findings, summarize


def f(fid: str, sev: Severity, port: int | None = 80) -> Finding:
    return Finding(fid, "t", sev, Category.HTTP, "d", "e", "r", "host", port)


def test_points_table_is_complete_and_documented_values() -> None:
    assert {s: points_for(s) for s in Severity} == {
        Severity.INFO: 0, Severity.LOW: 10, Severity.MEDIUM: 30,
        Severity.HIGH: 60, Severity.CRITICAL: 90,
    }
    assert set(POINTS) == set(Severity)


def test_score_finding_fills_score_without_mutating() -> None:
    original = f("A", Severity.HIGH)
    scored = score_finding(original)
    assert scored.score == 60
    assert original.score is None


def test_sort_order_severity_then_id_then_port() -> None:
    items = [
        f("B", Severity.LOW), f("A", Severity.LOW, 443), f("A", Severity.LOW, 80),
        f("Z", Severity.HIGH), f("N", Severity.LOW, None),
    ]
    order = [(x.severity.label, x.id, x.port) for x in sort_findings(items)]
    assert order == [
        ("HIGH", "Z", 80), ("LOW", "A", 80), ("LOW", "A", 443), ("LOW", "B", 80),
        ("LOW", "N", None),
    ]


def test_aggregate_is_capped_at_100() -> None:
    items = [f("X", Severity.HIGH, 1), f("Y", Severity.HIGH, 2)]
    assert summarize(items).aggregate_score == 100


def test_same_id_and_port_counts_once() -> None:
    items = [f("A", Severity.MEDIUM, 80), f("A", Severity.MEDIUM, 80), f("A", Severity.MEDIUM, 81)]
    assert summarize(items).aggregate_score == 60


def test_rating_is_highest_severity_or_none() -> None:
    assert summarize([]).rating == "NONE"
    assert summarize([f("A", Severity.INFO)]).rating == "NONE"
    assert summarize([f("A", Severity.INFO)]).highest_severity == "INFO"
    mixed = summarize([f("A", Severity.LOW), f("B", Severity.HIGH, 2)])
    assert (mixed.rating, mixed.highest_severity) == ("HIGH", "HIGH")
    assert mixed.counts_by_severity["LOW"] == 1


def test_scoring_is_deterministic() -> None:
    items = [f("A", Severity.LOW), f("B", Severity.MEDIUM, 2), f("C", Severity.INFO, None)]
    assert summarize(items) == summarize(list(reversed(items)))
    assert sort_findings(items) == sort_findings(list(reversed(items)))


def test_severity_parse() -> None:
    assert Severity.parse(" High ") is Severity.HIGH
    try:
        Severity.parse("bogus")
    except ValueError as exc:
        assert "choose from" in str(exc)
    else:
        raise AssertionError("expected ValueError")
