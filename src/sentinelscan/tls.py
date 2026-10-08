"""TLS handshake and certificate observation.

Observes what a normal, modern handshake negotiates. It does not try to downgrade the
connection, probe which legacy protocols a server supports, or enumerate ciphers.
"""

import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sentinelscan.sanitize import sanitize


@dataclass(frozen=True, slots=True)
class CertInfo:
    subject: str
    issuer: str
    san: tuple[str, ...]
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True, slots=True)
class TlsObservation:
    port: int
    handshake_ok: bool
    server_name: str | None = None
    version: str | None = None
    cipher: str | None = None
    verified: bool = False
    verify_code: int | None = None
    verify_message: str | None = None
    cert: CertInfo | None = None
    days_to_expiry: int | None = None
    cert_details_note: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        cert = self.cert
        return {
            "port": self.port,
            "handshake_ok": self.handshake_ok,
            "server_name": self.server_name,
            "version": self.version,
            "cipher": self.cipher,
            "verified": self.verified,
            "verify_code": self.verify_code,
            "verify_message": self.verify_message,
            "certificate": None
            if cert is None
            else {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "san": list(cert.san),
                "not_before": cert.not_before.isoformat(),
                "not_after": cert.not_after.isoformat(),
            },
            "days_to_expiry": self.days_to_expiry,
            "cert_details_note": self.cert_details_note,
            "error": self.error,
        }


def days_until_expiry(not_after: datetime, now: datetime) -> int:
    """Whole days until expiry, rounded down. Negative means already expired.

    ``now`` is a parameter so tests never depend on the real clock.
    """
    return (not_after - now).days


def _flatten_name(name: Any) -> str:
    """Turn ssl's nested subject/issuer tuples into 'commonName=x, organizationName=y'."""
    parts = [f"{key}={value}" for rdn in name for key, value in rdn]
    return sanitize(", ".join(parts))


def _cert_time(text: str) -> datetime:
    """Parse ssl's 'Jun  1 00:00:00 2025 GMT' format into an aware UTC datetime."""
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(text), timezone.utc)


def parse_cert_dict(cert: Mapping[str, Any]) -> CertInfo:
    """Convert ``SSLSocket.getpeercert()`` output into a CertInfo."""
    san = tuple(sanitize(value) for _kind, value in cert.get("subjectAltName", ()))
    return CertInfo(
        subject=_flatten_name(cert.get("subject", ())),
        issuer=_flatten_name(cert.get("issuer", ())),
        san=san,
        not_before=_cert_time(cert["notBefore"]),
        not_after=_cert_time(cert["notAfter"]),
    )


def parse_der(der: bytes) -> CertInfo | None:
    """Decode a DER certificate with the optional ``cryptography`` package.

    The standard library cannot decode a certificate that failed verification, so this is
    the only way to show issuer and dates for self-signed or untrusted certificates.
    Returns None when ``cryptography`` is not installed.
    """
    try:
        from cryptography import x509
    except ImportError:
        return None
    certificate = x509.load_der_x509_certificate(der)
    san: list[str] = []
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = [str(v) for v in extension.value.get_values_for_type(x509.DNSName)]
        san += [str(v) for v in extension.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    return CertInfo(
        subject=sanitize(certificate.subject.rfc4514_string()),
        issuer=sanitize(certificate.issuer.rfc4514_string()),
        san=tuple(sanitize(v) for v in san),
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
    )


def _cipher_name(tls: ssl.SSLSocket) -> str | None:
    cipher = tls.cipher()
    return cipher[0] if cipher else None


def _inspect_unverified(
    address: str, port: int, server_name: str | None, timeout: float
) -> tuple[str | None, str | None, bytes | None]:
    """Second handshake with verification off, only to read version, cipher and the cert."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((address, port), timeout=timeout)
    except OSError:
        return None, None, None
    try:
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            return tls.version(), _cipher_name(tls), tls.getpeercert(binary_form=True)
    except OSError:
        return None, None, None
    finally:
        raw.close()


def inspect_tls(
    address: str,
    port: int,
    *,
    server_name: str | None,
    timeout: float = 3.0,
    cafile: str | None = None,
    now: datetime | None = None,
) -> TlsObservation:
    """Handshake with verification ON and record what happened."""
    now = now or datetime.now(timezone.utc)
    context = ssl.create_default_context(cafile=cafile)
    try:
        raw = socket.create_connection((address, port), timeout=timeout)
    except OSError as exc:
        return TlsObservation(
            port, False, server_name, error=sanitize(f"{type(exc).__name__}: {exc}")
        )
    try:
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            version, cipher = tls.version(), _cipher_name(tls)
            peer = tls.getpeercert()
            cert = parse_cert_dict(peer) if peer else None
        return TlsObservation(
            port,
            True,
            server_name,
            version=version,
            cipher=cipher,
            verified=True,
            cert=cert,
            days_to_expiry=days_until_expiry(cert.not_after, now) if cert else None,
        )
    except ssl.SSLCertVerificationError as exc:
        version, cipher, der = _inspect_unverified(address, port, server_name, timeout)
        cert = parse_der(der) if der else None
        note = None
        if cert is None:
            note = (
                "certificate details unavailable: install the optional 'cryptography' "
                "package or pass --cafile to read untrusted certificates"
            )
        return TlsObservation(
            port,
            True,
            server_name,
            version=version,
            cipher=cipher,
            verified=False,
            verify_code=exc.verify_code,
            verify_message=sanitize(exc.verify_message or str(exc)),
            cert=cert,
            days_to_expiry=days_until_expiry(cert.not_after, now) if cert else None,
            cert_details_note=note,
        )
    except OSError as exc:  # includes ssl.SSLError
        return TlsObservation(
            port, False, server_name, error=sanitize(f"{type(exc).__name__}: {exc}")
        )
    finally:
        raw.close()
