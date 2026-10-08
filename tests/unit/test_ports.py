import socket

import pytest

from sentinelscan.models import PortState
from sentinelscan.ports import (
    COMMON_PORTS,
    PortSpecError,
    ResolveError,
    parse_ports,
    resolve_host,
    scan_port,
    scan_ports,
)


def test_single_ports_sorted_and_deduplicated() -> None:
    assert parse_ports("443,22,80,22") == (22, 80, 443)


def test_range_and_list_combined() -> None:
    assert parse_ports("8000-8003,80") == (80, 8000, 8001, 8002, 8003)


def test_common_keyword() -> None:
    assert parse_ports(" Common ") == COMMON_PORTS


def test_common_ports_are_sorted_and_unique() -> None:
    assert list(COMMON_PORTS) == sorted(set(COMMON_PORTS))


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "abc", "0", "65536", "-5", "80,,22", "9-3", "1-2-3", "²", "80;22"],
)
def test_malformed_specs_raise(bad: str) -> None:
    with pytest.raises(PortSpecError):
        parse_ports(bad)


def test_too_many_ports_raises() -> None:
    with pytest.raises(PortSpecError, match="too many"):
        parse_ports("1-65535")


def test_custom_limit_allows_larger_scan() -> None:
    assert len(parse_ports("1-2000", max_ports=5000)) == 2000


def _free_port() -> int:
    """A port number that nothing is listening on right now."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_scan_port_open() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        result = scan_port("127.0.0.1", port, timeout=1.0)
    assert result.state is PortState.OPEN
    assert result.port == port
    assert result.latency_ms is not None


def test_scan_port_closed() -> None:
    result = scan_port("127.0.0.1", _free_port(), timeout=1.0)
    assert result.state is PortState.CLOSED


def _raise_timeout(*args: object, **kwargs: object) -> None:
    raise TimeoutError("timed out")


def _raise_unreachable(*args: object, **kwargs: object) -> None:
    raise OSError(65, "No route to host")


def test_scan_port_timeout_is_filtered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "create_connection", _raise_timeout)
    result = scan_port("192.0.2.1", 80, timeout=0.1)
    assert result.state is PortState.FILTERED
    assert result.latency_ms is None


def test_scan_port_other_oserror_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "create_connection", _raise_unreachable)
    result = scan_port("192.0.2.1", 80, timeout=0.1)
    assert result.state is PortState.ERROR
    assert result.error is not None
    assert "No route to host" in result.error

def test_resolve_ip_literal() -> None:
    assert resolve_host("127.0.0.1") == ("127.0.0.1",)


def test_resolve_localhost_returns_addresses() -> None:
    assert len(resolve_host("localhost")) >= 1


def test_resolve_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise socket.gaierror(8, "nodename nor servname provided")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(ResolveError, match="cannot resolve"):
        resolve_host("no-such-host.example")


def test_resolve_empty_raises() -> None:
    with pytest.raises(ResolveError):
        resolve_host("  ")


def test_resolve_puts_ipv4_first(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(*args: object, **kwargs: object) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert resolve_host("example.test") == ("127.0.0.1", "::1")


def test_scan_ports_sorted_with_correct_states() -> None:
    closed_port = _free_port()
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        open_port = server.getsockname()[1]
        results = scan_ports("127.0.0.1", [open_port, closed_port], timeout=1.0, workers=4)
    assert [r.port for r in results] == sorted([open_port, closed_port])
    states = {r.port: r.state for r in results}
    assert states[open_port] is PortState.OPEN
    assert states[closed_port] is PortState.CLOSED


def test_scan_ports_is_deterministic() -> None:
    ports = [_free_port() for _ in range(3)]
    first = scan_ports("127.0.0.1", ports, timeout=1.0)
    second = scan_ports("127.0.0.1", ports, timeout=1.0)
    assert [(r.port, r.state) for r in first] == [(r.port, r.state) for r in second]


@pytest.mark.parametrize("workers", [0, 257])
def test_scan_ports_rejects_bad_workers(workers: int) -> None:
    with pytest.raises(ValueError, match="workers"):
        scan_ports("127.0.0.1", [80], workers=workers)


@pytest.mark.parametrize("timeout", [0.0, 0.05, 31.0])
def test_scan_ports_rejects_bad_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        scan_ports("127.0.0.1", [80], timeout=timeout)
