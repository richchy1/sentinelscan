import json
import socket
from pathlib import Path

import pytest
from servers import INSECURE_HEADERS, HttpFixture

from sentinelscan import scanner
from sentinelscan.cli import main


def scan_args(port: int, *extra: str) -> list[str]:
    return ["127.0.0.1", "-p", str(port), "-t", "0.5", *extra]


def test_json_scan_from_one_command(capsys: pytest.CaptureFixture[str]) -> None:
    with HttpFixture(headers=INSECURE_HEADERS) as srv:
        code = main(scan_args(srv.port, "-f", "json"))
    out = capsys.readouterr().out
    data = json.loads(out)
    assert code == 0
    assert data["status"] == "completed"
    assert data["port_counts"]["open"] == 1
    assert any(f["id"] == "SS-HTTP-012" for f in data["findings"])


def test_terminal_scan_prints_report(capsys: pytest.CaptureFixture[str]) -> None:
    with HttpFixture(headers=INSECURE_HEADERS) as srv:
        assert main(scan_args(srv.port)) == 0
    out = capsys.readouterr().out
    assert "FINDINGS" in out and "SS-HTTP-004" in out and "\033[" not in out


def test_invalid_port_list_is_a_one_line_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["127.0.0.1", "-p", "80,abc"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and "Traceback" not in err and err.count("\n") == 1


BAD_OPTIONS = [
    ["-t", "0"], ["-t", "99"], ["-c", "0"], ["-c", "300"], ["-f", "pdf"], ["--fail-on", "x"],
]


@pytest.mark.parametrize("bad", BAD_OPTIONS)
def test_invalid_options_exit_2(bad: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["127.0.0.1", *bad])
    assert exc.value.code == 2


def test_missing_target_exits_2() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_fail_on_threshold(capsys: pytest.CaptureFixture[str]) -> None:
    with HttpFixture(headers=INSECURE_HEADERS) as srv:
        assert main(scan_args(srv.port, "--fail-on", "medium")) == 1
        assert main(scan_args(srv.port, "--fail-on", "high")) == 0
    capsys.readouterr()


def test_output_file_and_overwrite_protection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "report.html"
    with HttpFixture(headers=INSECURE_HEADERS) as srv:
        assert main(scan_args(srv.port, "-f", "html", "-o", str(out))) == 0
        assert "<!doctype html>" in out.read_text()
        assert main(scan_args(srv.port, "-f", "html", "-o", str(out))) == 2
        assert main(scan_args(srv.port, "-f", "html", "-o", str(out), "--force")) == 0
    assert "already exists" in capsys.readouterr().err


def test_bad_output_directory_fails_before_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("scan must not start")

    monkeypatch.setattr("sentinelscan.cli.run_scan", forbidden)
    assert main(["127.0.0.1", "-o", str(tmp_path / "missing" / "r.json")]) == 3
    assert "does not exist" in capsys.readouterr().err


def test_dns_failure_exits_3_with_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*_a: object, **_k: object) -> None:
        raise socket.gaierror(8, "nodename nor servname provided")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert main(["no-such-host.example", "-f", "json"]) == 3
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "failed"
    assert "cannot resolve" in captured.err and "Traceback" not in captured.err


def test_public_target_needs_authorized_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scanner, "resolve_host", lambda _h: ("8.8.8.8",))
    assert main(["example.test"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_verbose_progress_goes_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    with HttpFixture() as srv:
        assert main(scan_args(srv.port, "-v", "-f", "json")) == 0
    captured = capsys.readouterr()
    assert "[*] scanning" in captured.err
    json.loads(captured.out)  # stdout stays clean, valid JSON
