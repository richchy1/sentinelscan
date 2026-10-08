"""Evidence-based service identification.

A port number is never evidence by itself: ``CONFIRMED`` is only returned when
protocol evidence was seen on the wire.
"""

import re
import socket
import ssl

from sentinelscan import __version__
from sentinelscan.models import Confidence, ServiceResult
from sentinelscan.sanitize import sanitize

BANNER_WAIT = 0.5  # seconds to wait for a server-first banner
READ_LIMIT = 4096

# Ports that are *commonly* used by a service. Only ever used for a PROBABLE guess,
# and never for web ports (those are actively probed instead).
_PORT_HINTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    110: "pop3",
    143: "imap",
    445: "smb",
    465: "smtps",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    9200: "elasticsearch",
    27017: "mongodb",
}

_SERVER_HEADER = re.compile(rb"\r\nserver:[ \t]*([^\r\n]*)", re.IGNORECASE)
_MYSQL_VERSION = re.compile(rb"\d+\.\d+")


def port_hint(port: int) -> str | None:
    """The service a port is commonly used for, or None (never evidence by itself)."""
    return _PORT_HINTS.get(port)


def _classify_banner(port: int, banner: bytes) -> ServiceResult | None:
    """Recognise a server-first banner. Returns None if it is not recognised."""
    evidence = sanitize(banner)
    upper = banner[:200].upper()

    def result(name: str, confidence: Confidence = Confidence.CONFIRMED) -> ServiceResult:
        return ServiceResult(port, name, confidence, evidence=evidence)

    if banner.startswith(b"SSH-"):
        return result("ssh")
    if banner.startswith(b"HTTP/"):
        return ServiceResult(port, "http", Confidence.CONFIRMED, evidence=evidence, is_http=True)
    if banner.startswith(b"RFB "):
        return result("vnc")
    if banner.startswith(b"220"):
        if b"SMTP" in upper:
            return result("smtp")
        if b"FTP" in upper:
            return result("ftp")
        return None
    if banner.startswith(b"+OK"):
        return result("pop3")
    if banner.startswith(b"* OK"):
        return result("imap")
    if len(banner) > 6 and banner[4] == 10 and _MYSQL_VERSION.match(banner[5:]):
        return ServiceResult(
            port,
            "mysql",
            Confidence.PROBABLE,
            evidence=evidence,
            guess_basis="greeting packet resembles a MySQL handshake",
        )
    return None


def _http_request(host: str) -> bytes:
    safe_host = re.sub(r"[^\w.\-:\[\]]", "", host) or "localhost"
    return (
        f"HEAD / HTTP/1.1\r\nHost: {safe_host}\r\n"
        f"User-Agent: SentinelScan/{__version__}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def _exchange(sock: socket.socket | ssl.SSLSocket, host: str, timeout: float) -> bytes:
    """Send one HEAD request and read whatever comes back (possibly nothing)."""
    sock.settimeout(timeout)
    try:
        sock.sendall(_http_request(host))
        return sock.recv(READ_LIMIT)
    except OSError:
        return b""


def _read_banner(address: str, port: int, timeout: float) -> bytes | None:
    """Wait briefly for a server-first banner. None means we could not connect."""
    try:
        sock = socket.create_connection((address, port), timeout=timeout)
    except OSError:
        return None
    with sock:
        sock.settimeout(min(timeout, BANNER_WAIT))
        try:
            return sock.recv(READ_LIMIT)
        except OSError:
            return b""


def _probe_tls(address: str, port: int, host: str, timeout: float) -> tuple[bool, bytes]:
    """Try a TLS handshake (verification off: identification only) then an HTTP request."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((address, port), timeout=timeout)
    except OSError:
        return False, b""
    try:
        with context.wrap_socket(raw, server_hostname=None) as tls:
            return True, _exchange(tls, host, timeout)
    except OSError:  # includes ssl.SSLError
        return False, b""
    finally:
        raw.close()


def _probe_http(address: str, port: int, host: str, timeout: float) -> bytes:
    try:
        sock = socket.create_connection((address, port), timeout=timeout)
    except OSError:
        return b""
    with sock:
        return _exchange(sock, host, timeout)


def _http_evidence(response: bytes) -> str:
    status_line = response.split(b"\r\n", 1)[0]
    server = _SERVER_HEADER.search(response)
    text = sanitize(status_line)
    if server:
        text += f"; Server: {sanitize(server.group(1))}"
    return sanitize(text)


def identify_service(
    address: str,
    port: int,
    timeout: float = 1.0,
    server_name: str | None = None,
) -> ServiceResult:
    """Identify the service on an open port using safe, read-only probes."""
    host = server_name or address

    # 1. Passive read: SSH, SMTP, FTP, POP3, IMAP speak first.
    banner = _read_banner(address, port, timeout)
    if banner is None:
        return ServiceResult(port, None, Confidence.UNKNOWN, evidence="could not connect")
    if banner:
        recognised = _classify_banner(port, banner)
        if recognised:
            return recognised
        return ServiceResult(
            port,
            None,
            Confidence.UNKNOWN,
            evidence=sanitize(banner),
            guess_basis="server sent an unrecognised banner",
        )

    # 2. TLS handshake, then HTTP inside it.
    tls_ok, tls_response = _probe_tls(address, port, host, timeout)
    if tls_ok:
        if tls_response.startswith(b"HTTP/"):
            return ServiceResult(
                port,
                "https",
                Confidence.CONFIRMED,
                evidence=_http_evidence(tls_response),
                is_http=True,
                is_tls=True,
            )
        return ServiceResult(
            port,
            "tls",
            Confidence.CONFIRMED,
            evidence="TLS handshake completed; no HTTP response",
            is_tls=True,
        )

    # 3. Plain HTTP.
    response = _probe_http(address, port, host, timeout)
    if response.startswith(b"HTTP/"):
        return ServiceResult(
            port, "http", Confidence.CONFIRMED, evidence=_http_evidence(response), is_http=True
        )

    # 4. Nothing recognised: a guess from the port number, clearly labelled, or UNKNOWN.
    hint = port_hint(port)
    if hint:
        return ServiceResult(
            port,
            hint,
            Confidence.PROBABLE,
            evidence="no banner and no response to TLS or HTTP probes",
            guess_basis=f"port {port} is commonly used for {hint}",
        )
    return ServiceResult(
        port,
        None,
        Confidence.UNKNOWN,
        evidence="no banner and no response to TLS or HTTP probes",
    )
