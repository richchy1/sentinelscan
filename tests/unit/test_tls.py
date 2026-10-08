import sys
from datetime import datetime, timedelta, timezone

import pytest

from sentinelscan.checks import check_tls
from sentinelscan.models import Severity
from sentinelscan.tls import (
    CertInfo,
    TlsObservation,
    days_until_expiry,
    parse_cert_dict,
    parse_der,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def cert(days: int) -> CertInfo:
    return CertInfo("CN=t", "CN=ca", ("t",), NOW - timedelta(days=30), NOW + timedelta(days=days))


def observe(**kwargs: object) -> TlsObservation:
    defaults: dict[str, object] = {"port": 443, "handshake_ok": True, "verified": True}
    defaults.update(kwargs)
    return TlsObservation(**defaults)  # type: ignore[arg-type]


def ids(obs: TlsObservation) -> set[str]:
    return {f.id for f in check_tls(obs, target="t")}


def test_days_until_expiry_uses_injected_clock() -> None:
    assert days_until_expiry(NOW + timedelta(days=10, hours=5), NOW) == 10
    assert days_until_expiry(NOW + timedelta(hours=5), NOW) == 0
    assert days_until_expiry(NOW - timedelta(hours=5), NOW) == -1


def test_parse_cert_dict() -> None:
    raw = {
        "subject": ((("commonName", "example.test"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "subjectAltName": (("DNS", "example.test"), ("IP Address", "127.0.0.1")),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
    }
    info = parse_cert_dict(raw)
    assert info.subject == "commonName=example.test"
    assert info.issuer == "organizationName=Test CA"
    assert info.san == ("example.test", "127.0.0.1")
    assert info.not_after == datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_healthy_tls13_only_informational() -> None:
    obs = observe(version="TLSv1.3", cipher="X", cert=cert(90), days_to_expiry=90)
    found = check_tls(obs, target="t")
    assert [f.id for f in found] == ["SS-TLS-007"]
    assert found[0].severity is Severity.INFO


def test_expired_certificate() -> None:
    assert "SS-TLS-001" in ids(observe(version="TLSv1.3", cert=cert(-5), days_to_expiry=-5))


def test_expired_detected_from_verify_code_without_cert_details() -> None:
    obs = observe(version="TLSv1.3", verified=False, verify_code=10, verify_message="expired")
    assert "SS-TLS-001" in ids(obs)
    assert "SS-TLS-005" not in ids(obs)


def test_expiring_soon_thresholds() -> None:
    assert "SS-TLS-002" in ids(observe(cert=cert(10), days_to_expiry=10))
    soon = ids(observe(cert=cert(20), days_to_expiry=20))
    assert "SS-TLS-003" in soon and "SS-TLS-002" not in soon
    assert not {"SS-TLS-002", "SS-TLS-003"} & ids(observe(cert=cert(90), days_to_expiry=90))


def test_hostname_mismatch() -> None:
    obs = observe(verified=False, verify_code=62, verify_message="Hostname mismatch", cert=cert(90))
    found = ids(obs)
    assert "SS-TLS-004" in found
    assert "SS-TLS-005" not in found


def test_untrusted_certificate() -> None:
    obs = observe(verified=False, verify_code=18, verify_message="self-signed certificate")
    assert "SS-TLS-005" in ids(obs)


def test_legacy_protocol_is_high() -> None:
    found = check_tls(observe(version="TLSv1.1", cipher="X"), target="t")
    assert found[0].id == "SS-TLS-006"
    assert found[0].severity is Severity.HIGH


def test_failed_handshake_produces_no_finding() -> None:
    assert check_tls(TlsObservation(443, False, error="boom"), target="t") == []


def test_tls_findings_are_complete() -> None:
    obs = observe(
        version="TLSv1.1", verified=False, verify_code=18, verify_message="x", cert=cert(-1)
    )
    for f in check_tls(obs, target="t"):
        assert f.description and f.evidence and f.remediation


def test_parse_der_without_cryptography_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "cryptography", None)  # makes `import cryptography` fail
    assert parse_der(b"not a certificate") is None
