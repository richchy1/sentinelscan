"""Port spec parsing and TCP connect scanning."""

import socket
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor

from sentinelscan.models import PortResult, PortState

MAX_PORTS = 1024
DEFAULT_TIMEOUT = 1.0
MIN_TIMEOUT = 0.1
MAX_TIMEOUT = 30.0
DEFAULT_WORKERS = 50
MAX_WORKERS = 256

# Ports that commonly run services worth looking at (sorted).
COMMON_PORTS: tuple[int, ...] = (
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    80,  # HTTP
    110,  # POP3
    143,  # IMAP
    443,  # HTTPS
    445,  # SMB
    465,  # SMTPS
    587,  # SMTP submission
    993,  # IMAPS
    995,  # POP3S
    3000,  # dev web servers
    3306,  # MySQL
    3389,  # RDP
    5000,  # dev web servers / AirPlay on macOS
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # dev web servers
    8080,  # alternate HTTP
    8443,  # alternate HTTPS
    9200,  # Elasticsearch
    27017,  # MongoDB
)


class PortSpecError(ValueError):
    """Raised when a port specification is malformed."""


def _parse_port(text: str) -> int:
    """Turn one piece of text like '443' into a valid port number."""
    text = text.strip()
    # isascii() matters: str.isdigit() also accepts characters like '²'.
    if not (text.isascii() and text.isdigit()):
        raise PortSpecError(f"not a valid port number: {text!r}")
    value = int(text)
    if not 1 <= value <= 65535:
        raise PortSpecError(f"port out of range 1-65535: {value}")
    return value


def parse_ports(spec: str, max_ports: int = MAX_PORTS) -> tuple[int, ...]:
    """Parse '22,80,8000-8100' or 'common' into a sorted tuple of unique ports."""
    spec = spec.strip().lower()
    if not spec:
        raise PortSpecError("port list is empty")
    if spec == "common":
        return COMMON_PORTS

    ports: set[int] = set()
    for part in spec.split(","):
        if not part.strip():
            raise PortSpecError("empty entry in port list")
        if "-" in part:
            start_text, _, end_text = part.partition("-")
            start = _parse_port(start_text)
            end = _parse_port(end_text)
            if start > end:
                raise PortSpecError(f"range start is greater than end: {part.strip()!r}")
            if end - start + 1 > max_ports:
                raise PortSpecError(f"too many ports (limit {max_ports})")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(part))
        if len(ports) > max_ports:
            raise PortSpecError(f"too many ports (limit {max_ports})")
    return tuple(sorted(ports))


def scan_port(address: str, port: int, timeout: float = 1.0) -> PortResult:
    """TCP connect to one port and classify the outcome."""
    started = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            pass
    except ConnectionRefusedError:
        return PortResult(port, PortState.CLOSED, latency_ms=_elapsed_ms(started))
    except TimeoutError:
        return PortResult(port, PortState.FILTERED)
    except OSError as exc:
        return PortResult(port, PortState.ERROR, error=f"{type(exc).__name__}: {exc}")
    return PortResult(port, PortState.OPEN, latency_ms=_elapsed_ms(started))


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)

class ResolveError(Exception):
    """Raised when a hostname cannot be resolved."""


def resolve_host(host: str) -> tuple[str, ...]:
    """Resolve a hostname or IP literal once; IPv4 first, then sorted."""
    host = host.strip()
    if not host:
        raise ResolveError("target is empty")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        reason = exc.strerror if isinstance(exc, socket.gaierror) and exc.strerror else exc
        raise ResolveError(f"cannot resolve {host!r}: {reason}") from exc
    addresses = {str(info[4][0]) for info in infos}
    return tuple(sorted(addresses, key=lambda addr: (":" in addr, addr)))


def scan_ports(
    address: str,
    ports: Sequence[int],
    timeout: float = DEFAULT_TIMEOUT,
    workers: int = DEFAULT_WORKERS,
) -> tuple[PortResult, ...]:
    """Scan many ports in parallel; results are always sorted by port."""
    if not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds")
    if not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"workers must be between 1 and {MAX_WORKERS}")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda port: scan_port(address, port, timeout), ports))
    return tuple(sorted(results, key=lambda result: result.port))
