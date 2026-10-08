import json
import os
from pathlib import Path

import pytest

from sentinelscan.models import (
    Category,
    Confidence,
    Finding,
    PortResult,
    PortState,
    ReportMetadata,
    ScanResult,
    ServiceResult,
    Severity,
    Target,
)
from sentinelscan.reporter import (
    ReportWriteError,
    check_output_path,
    to_html,
    to_json,
    to_terminal,
    write_report,
)
from sentinelscan.scoring import score_finding, summarize

EVIL = "<script>alert(1)</script>"


def make_result(
    findings: list[Finding] | None = None,
    *,
    open_port: bool = True,
    status: str = "completed",
    errors: tuple[str, ...] = (),
    banner: str = "SSH-2.0-test",
) -> ScanResult:
    scored = [score_finding(f) for f in findings or []]
    meta = ReportMetadata(
        "SentinelScan", "0.1.0", "1.0", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", 1.0,
        {"timeout_s": 1.0}, "3.14", "test",
    )
    ports = (PortResult(22, PortState.OPEN, 1.0), PortResult(23, PortState.CLOSED, 1.0))
    services = (ServiceResult(22, "ssh", Confidence.CONFIRMED, evidence=banner),)
    return ScanResult(
        metadata=meta,
        target=Target("host", "host", (22, 23), ("127.0.0.1",), "127.0.0.1"),
        status=status,
        ports=ports if open_port else (PortResult(23, PortState.CLOSED),),
        services=services if open_port else (),
        findings=tuple(scored),
        stage_errors=errors,
        summary=summarize(scored),
        observations={"http": [], "tls": []},
    )


def finding(evidence: str = "e") -> Finding:
    return Finding(
        "SS-T-001", f"title {evidence}", Severity.MEDIUM, Category.HTTP,
        "why it matters", evidence, "how to fix", "host", 22,
    )


def test_json_round_trips_and_keeps_evidence_and_remediation() -> None:
    data = json.loads(to_json(make_result([finding("proof")])))
    assert data["metadata"]["schema_version"] == "1.0"
    assert data["findings"][0]["evidence"] == "proof"
    assert data["findings"][0]["remediation"] == "how to fix"
    assert data["findings"][0]["severity"] == "MEDIUM"
    assert data["port_counts"] == {"open": 1, "closed": 1, "filtered": 0, "error": 0}
    assert [p["port"] for p in data["ports"]] == [22]  # only open ports listed


def test_json_is_stable() -> None:
    result = make_result([finding()])
    assert to_json(result) == to_json(result)


def test_html_escapes_untrusted_text() -> None:
    result = make_result([finding(EVIL)], banner=EVIL, errors=(EVIL,))
    page = to_html(result)
    assert EVIL not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_html_is_self_contained() -> None:
    page = to_html(make_result([finding()]))
    assert "http://" not in page and "https://" not in page
    assert "<script" not in page and "<link" not in page and "@import" not in page


def test_empty_scan_renders_in_every_format() -> None:
    result = make_result(open_port=False)
    assert "no open ports" in to_terminal(result)
    assert "No open ports" in to_html(result)
    assert json.loads(to_json(result))["ports"] == []


def test_failed_scan_is_reportable() -> None:
    result = make_result(open_port=False, status="failed", errors=("resolve: cannot resolve",))
    assert "status: failed" in to_terminal(result)
    assert "cannot resolve" in to_html(result)
    assert json.loads(to_json(result))["status"] == "failed"


def test_terminal_color_only_when_requested() -> None:
    result = make_result([finding()])
    assert "\033[" not in to_terminal(result, color=False)
    assert "\033[" in to_terminal(result, color=True)


def test_terminal_shows_why_and_fix_for_real_findings() -> None:
    text = to_terminal(make_result([finding()]))
    assert "why it matters" in text and "how to fix" in text


def test_output_path_existing_file_needs_force(tmp_path: Path) -> None:
    target = tmp_path / "r.json"
    target.write_text("old")
    with pytest.raises(ReportWriteError, match="--force") as exc:
        check_output_path(target, force=False)
    assert exc.value.exit_code == 2
    check_output_path(target, force=True)


def test_output_path_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(ReportWriteError, match="does not exist") as exc:
        check_output_path(tmp_path / "nope" / "r.json", force=False)
    assert exc.value.exit_code == 3


def test_output_path_is_directory(tmp_path: Path) -> None:
    with pytest.raises(ReportWriteError, match="directory"):
        check_output_path(tmp_path, force=True)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_output_path_unwritable_directory(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        with pytest.raises(ReportWriteError, match="cannot write") as exc:
            check_output_path(locked / "r.json", force=False)
        assert exc.value.exit_code == 3
    finally:
        locked.chmod(0o700)


def test_write_report_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "r.txt"
    write_report(path, "hello")
    assert path.read_text() == "hello"
