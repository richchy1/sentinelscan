from pathlib import Path

from certs import make_server_cert
from servers import HttpFixture, tls_context, tls_server

from sentinelscan.checks import check_tls
from sentinelscan.http import fetch
from sentinelscan.models import Severity
from sentinelscan.services import identify_service
from sentinelscan.tls import inspect_tls


def run(port: int, **kwargs: object):  # type: ignore[no-untyped-def]
    obs = inspect_tls("127.0.0.1", port, timeout=2.0, **kwargs)  # type: ignore[arg-type]
    return obs, {f.id: f for f in check_tls(obs, target="localhost")}


def test_valid_certificate_is_verified(tmp_path: Path) -> None:
    files = make_server_cert(tmp_path, names=("localhost",))
    with tls_server(files.cert, files.key) as srv:
        obs, found = run(srv.port, server_name="localhost", cafile=str(files.ca))
    assert obs.handshake_ok and obs.verified
    assert obs.version in ("TLSv1.2", "TLSv1.3")
    assert obs.cert is not None and "localhost" in obs.cert.san
    assert obs.days_to_expiry is not None and 85 <= obs.days_to_expiry <= 90
    assert set(found) == {"SS-TLS-007"}


def test_expired_certificate_detected(tmp_path: Path) -> None:
    files = make_server_cert(tmp_path, names=("localhost",), expired=True)
    with tls_server(files.cert, files.key) as srv:
        obs, found = run(srv.port, server_name="localhost", cafile=str(files.ca))
    assert not obs.verified
    assert "SS-TLS-001" in found
    assert found["SS-TLS-001"].severity is Severity.HIGH
    assert obs.days_to_expiry is not None and obs.days_to_expiry < 0


def test_hostname_mismatch_detected(tmp_path: Path) -> None:
    files = make_server_cert(tmp_path, names=("other.test",))
    with tls_server(files.cert, files.key) as srv:
        obs, found = run(srv.port, server_name="localhost", cafile=str(files.ca))
    assert "SS-TLS-004" in found
    assert obs.cert is not None and obs.cert.san == ("other.test",)


def test_self_signed_is_untrusted_with_details_from_cryptography(tmp_path: Path) -> None:
    files = make_server_cert(tmp_path, names=("localhost",), self_signed=True)
    with tls_server(files.cert, files.key) as srv:
        obs, found = run(srv.port, server_name="localhost")
    assert "SS-TLS-005" in found
    assert obs.cert is not None  # decoded via the optional cryptography package
    assert "localhost" in obs.cert.subject


def test_expiring_soon_detected(tmp_path: Path) -> None:
    files = make_server_cert(tmp_path, names=("localhost",), days_valid=7)
    with tls_server(files.cert, files.key) as srv:
        _obs, found = run(srv.port, server_name="localhost", cafile=str(files.ca))
    assert "SS-TLS-002" in found


def test_ip_literal_certificate(tmp_path: Path) -> None:
    files = make_server_cert(tmp_path, names=("127.0.0.1",))
    with tls_server(files.cert, files.key) as srv:
        obs, found = run(srv.port, server_name="127.0.0.1", cafile=str(files.ca))
    assert obs.verified
    assert set(found) == {"SS-TLS-007"}


def test_connection_refused_is_a_failed_observation() -> None:
    obs = inspect_tls("127.0.0.1", 1, server_name="localhost", timeout=0.5)
    assert not obs.handshake_ok
    assert obs.error


def test_non_tls_server_is_a_failed_handshake() -> None:
    with HttpFixture() as srv:
        obs = inspect_tls("127.0.0.1", srv.port, server_name="localhost", timeout=1.0)
    assert not obs.handshake_ok
    assert obs.error


def test_service_id_and_https_fetch_against_tls_server(tmp_path: Path) -> None:
    files = make_server_cert(tmp_path, names=("localhost",))
    with HttpFixture(context=tls_context(files.cert, files.key)) as srv:
        service = identify_service("127.0.0.1", srv.port, timeout=1.0)
        hops = fetch("127.0.0.1", srv.port, use_tls=True, host="localhost", timeout=2.0)
    assert service.name == "https" and service.is_tls and service.is_http
    assert hops[0].status == 200 and hops[0].scheme == "https"
