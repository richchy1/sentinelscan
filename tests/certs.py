"""Generate throw-away certificates for TLS tests (needs the dev dependency cryptography)."""

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class CertFiles:
    cert: Path
    key: Path
    ca: Path | None


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _builder(
    subject: x509.Name,
    issuer: x509.Name,
    key: ec.EllipticCurvePrivateKey,
    not_before: datetime,
    not_after: datetime,
) -> x509.CertificateBuilder:
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
    )


def make_ca(directory: Path) -> tuple[Path, x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = _name("SentinelScan Test CA")
    cert = (
        _builder(name, name, key, now - timedelta(days=1), now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            True,
        )
        .sign(key, hashes.SHA256())
    )
    return _write(directory / "ca.pem", _pem(cert)), cert, key


def make_server_cert(
    directory: Path,
    *,
    names: tuple[str, ...] = ("localhost",),
    days_valid: int = 90,
    expired: bool = False,
    self_signed: bool = False,
) -> CertFiles:
    """A certificate for ``names``. CA-signed by default; set ``self_signed`` to skip the CA."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    if expired:
        not_before, not_after = now - timedelta(days=60), now - timedelta(days=10)
    else:
        not_before, not_after = now - timedelta(days=1), now + timedelta(days=days_valid)

    subject = _name(names[0])
    san: list[x509.GeneralName] = []
    for n in names:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            san.append(x509.DNSName(n))

    ca_path: Path | None = None
    if self_signed:
        issuer, signing_key, aki = subject, key, None
    else:
        ca_path, ca_cert, ca_key = make_ca(directory)
        issuer, signing_key = ca_cert.subject, ca_key
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())

    builder = (
        _builder(subject, issuer, key, not_before, not_after)
        .add_extension(x509.SubjectAlternativeName(san), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            True,
        )
    )
    if aki is not None:
        builder = builder.add_extension(aki, False)
    cert = builder.sign(signing_key, hashes.SHA256())
    return CertFiles(
        cert=_write(directory / "server.pem", _pem(cert)),
        key=_write(directory / "server.key", _key_pem(key)),
        ca=ca_path,
    )
