import socket
from pathlib import Path

import pytest
from certs import make_server_cert
from servers import INSECURE_HEADERS, HttpFixture, banner_server, tls_context

from sentinelscan import scanner
from sentinelscan.models import Confidence
from sentinelscan.scanner import AuthorizationError, ScanConfig, run_scan


def cfg(*ports: int, **kwargs: object) -> ScanConfig:
    return ScanConfig(ports=tuple(ports), timeout=0.5, **kwargs)  # type: ignore[arg-type]


def finding_keys(result: object) -> list[tuple[str, int | None]]:
    return [(f.id, f.port) for f in result.findings]  # type: ignore[attr-defined]


def test_insecure_http_server_end_to_end() -> None:
    with HttpFixture(headers=INSECURE_HEADERS) as srv:
        result = run_scan("127.0.0.1", cfg(srv.port))
    assert result.status == "completed"
    assert [s.name for s in result.services] == ["http"]
    assert result.services[0].confidence is Confidence.CONFIRMED
    ids = {f.id for f in result.findings}
    assert {"SS-NET-001", "SS-HTTP-004", "SS-HTTP-010", "SS-HTTP-012"} <= ids
    assert result.summary.rating == "MEDIUM"
    assert all(f.score is not None for f in result.findings)
    assert len(result.observations["http"]) == 1  # type: ignore[arg-type]


def test_same_inputs_give_same_findings_and_order() -> None:
    with HttpFixture(headers=INSECURE_HEADERS) as srv:
        first = run_scan("127.0.0.1", cfg(srv.port))
        second = run_scan("127.0.0.1", cfg(srv.port))
    assert finding_keys(first) == finding_keys(second)
    assert first.summary == second.summary


def test_closed_port_gives_no_findings() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    result = run_scan("127.0.0.1", cfg(port))
    assert result.status == "completed"
    assert result.findings == () and result.summary.rating == "NONE"
    assert result.port_counts()["closed"] == 1


def test_non_http_service_gets_only_network_finding() -> None:
    with banner_server(b"SSH-2.0-OpenSSH_9.6\r\n") as srv:
        result = run_scan("127.0.0.1", cfg(srv.port))
    assert [f.id for f in result.findings] == ["SS-NET-001"]
    assert result.services[0].name == "ssh"


def test_https_and_http_together(tmp_path: Path) -> None:
    files = make_server_cert(tmp_path, names=("localhost",))
    with (
        HttpFixture() as plain,
        HttpFixture(context=tls_context(files.cert, files.key)) as secure,
    ):
        result = run_scan(
            "127.0.0.1",
            cfg(plain.port, secure.port, cafile=str(files.ca), server_name="localhost"),
        )
    by_port: dict[int | None, set[str]] = {}
    for f in result.findings:
        by_port.setdefault(f.port, set()).add(f.id)
    assert "SS-HTTP-001" in by_port[plain.port]  # HTTP does not redirect although HTTPS exists
    assert "SS-HTTP-002" in by_port[secure.port]  # no HSTS on the HTTPS server
    assert "SS-TLS-007" in by_port[secure.port]
    assert not {"SS-TLS-001", "SS-TLS-004", "SS-TLS-005"} & by_port[secure.port]
    assert len(result.observations["tls"]) == 1  # type: ignore[arg-type]


def test_untrusted_certificate_reported_without_cafile(tmp_path: Path) -> None:
    files = make_server_cert(tmp_path, names=("localhost",))
    with HttpFixture(context=tls_context(files.cert, files.key)) as srv:
        result = run_scan("127.0.0.1", cfg(srv.port, server_name="localhost"))
    assert "SS-TLS-005" in {f.id for f in result.findings}


def test_dns_failure_is_a_failed_but_reportable_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_a: object, **_k: object) -> None:
        raise socket.gaierror(8, "nodename nor servname provided")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    result = run_scan("no-such-host.example", cfg(80))
    assert result.status == "failed"
    assert any("cannot resolve" in e for e in result.stage_errors)
    assert result.ports == () and result.target.address is None


def test_public_address_requires_authorization(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "resolve_host", lambda _h: ("8.8.8.8",))

    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("must not connect before authorization")

    monkeypatch.setattr(scanner, "scan_ports", forbidden)
    with pytest.raises(AuthorizationError, match="--authorized"):
        run_scan("example.test", cfg(80))


def test_authorized_public_address_proceeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "resolve_host", lambda _h: ("8.8.8.8",))
    monkeypatch.setattr(scanner, "scan_ports", lambda *_a, **_k: ())
    result = run_scan("example.test", cfg(80, authorized=True))
    assert result.status == "completed"


@pytest.mark.parametrize(
    ("address", "public"),
    [("127.0.0.1", False), ("10.1.2.3", False), ("192.168.0.9", False), ("::1", False),
     ("169.254.1.1", False), ("8.8.8.8", True), ("1.1.1.1", True)],
)
def test_is_public_address(address: str, public: bool) -> None:
    assert scanner.is_public_address(address) is public
