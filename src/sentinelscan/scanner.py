"""Orchestrates the scan pipeline.

TARGET -> validate/resolve -> TCP discovery -> service ID -> HTTP analysis
       -> TLS analysis -> checks -> findings -> scoring -> result
"""

import ipaddress
import platform
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

from sentinelscan import __version__
from sentinelscan.checks import check_http, check_network, check_tls
from sentinelscan.http import HttpObservation, fetch
from sentinelscan.models import (
    Finding,
    PortResult,
    PortState,
    ReportMetadata,
    ScanResult,
    ServiceResult,
    Target,
)
from sentinelscan.ports import (
    DEFAULT_TIMEOUT,
    DEFAULT_WORKERS,
    ResolveError,
    resolve_host,
    scan_ports,
)
from sentinelscan.scoring import score_finding, sort_findings, summarize
from sentinelscan.services import identify_service
from sentinelscan.tls import TlsObservation, inspect_tls

SCHEMA_VERSION = "1.0"
Progress = Callable[[str], None]


class AuthorizationError(Exception):
    """Raised when a public address is scanned without the --authorized flag."""


@dataclass(frozen=True)
class ScanConfig:
    ports: tuple[int, ...]
    timeout: float = DEFAULT_TIMEOUT
    workers: int = DEFAULT_WORKERS
    follow_redirects: bool = False
    max_redirects: int = 5
    cafile: str | None = None
    server_name: str | None = None
    authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "ports": f"{len(self.ports)} ports",
            "timeout_s": self.timeout,
            "concurrency": self.workers,
            "follow_redirects": self.follow_redirects,
            "max_redirects": self.max_redirects,
            "cafile": self.cafile,
            "server_name": self.server_name,
        }


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def is_public_address(address: str) -> bool:
    """True for addresses outside loopback, private, link-local and other reserved ranges."""
    return ipaddress.ip_address(address).is_global


def _utc_iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_scan(
    target: str,
    config: ScanConfig,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    progress: Progress | None = None,
) -> ScanResult:
    """Run every stage in order. Expected network errors are recorded, never raised.

    Raises AuthorizationError (before any connection) for public addresses when the
    scan was not marked ``authorized``.
    """
    say = progress or (lambda _message: None)
    started_at, started = now(), time.perf_counter()
    host = target.strip()
    stage_errors: list[str] = []

    say(f"resolving {host}")
    try:
        addresses = resolve_host(host)
    except ResolveError as exc:
        stage_errors.append(f"resolve: {exc}")
        return _finish(
            Target(target, host, config.ports, is_ip_literal=is_ip_literal(host)),
            config, started_at, started, now(), "failed", (), (), [], stage_errors, {},
        )
    address = addresses[0]
    if not config.authorized and any(is_public_address(a) for a in addresses):
        raise AuthorizationError(
            f"{host} resolves to a public address ({address}). Scan only systems you own or "
            "are explicitly authorised to test, then re-run with --authorized."
        )
    scan_target = Target(
        target, host, config.ports, addresses, address, is_ip_literal=is_ip_literal(host)
    )
    server_name = config.server_name or host

    say(f"scanning {len(config.ports)} ports on {address}")
    port_results = scan_ports(address, config.ports, config.timeout, config.workers)
    open_ports = [p.port for p in port_results if p.state is PortState.OPEN]
    for p in port_results:
        if p.state is PortState.ERROR:
            stage_errors.append(f"port {p.port}: {p.error}")

    say(f"identifying services on {len(open_ports)} open ports")
    services = _identify_all(address, open_ports, config, server_name)
    service_by_port = {s.port: s for s in services}

    https_available = any(s.is_http and s.is_tls for s in services)
    findings: list[Finding] = []
    observations: dict[str, object] = {"http": [], "tls": []}
    http_list: list[dict[str, object]] = []
    tls_list: list[dict[str, object]] = []

    for port in open_ports:
        findings += check_network(port, service_by_port.get(port), host)

    for port in open_ports:
        service = service_by_port[port]
        if service.is_http:
            say(f"HTTP analysis on port {port}")
            hops = fetch(
                address,
                port,
                use_tls=service.is_tls,
                host=server_name,
                timeout=max(config.timeout, 2.0),
                follow_redirects=config.follow_redirects,
                max_redirects=config.max_redirects,
            )
            http_list.extend(h.to_dict() for h in hops)
            stage_errors += _http_errors(hops)
            findings += check_http(hops, target=host, port=port, https_available=https_available)
        if service.is_tls:
            say(f"TLS analysis on port {port}")
            tls_obs = inspect_tls(
                address,
                port,
                server_name=server_name,
                timeout=max(config.timeout, 2.0),
                cafile=config.cafile,
                now=now(),
            )
            tls_list.append(tls_obs.to_dict())
            stage_errors += _tls_errors(tls_obs)
            findings += check_tls(tls_obs, target=host)

    observations["http"], observations["tls"] = http_list, tls_list
    return _finish(
        scan_target, config, started_at, started, now(), "completed",
        port_results, services, findings, stage_errors, observations,
    )


def _identify_all(
    address: str, ports: Sequence[int], config: ScanConfig, server_name: str
) -> tuple[ServiceResult, ...]:
    if not ports:
        return ()
    workers = min(config.workers, len(ports))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(
            lambda port: identify_service(address, port, config.timeout, server_name), ports
        )
        return tuple(sorted(results, key=lambda s: s.port))


def _http_errors(hops: Sequence[HttpObservation]) -> list[str]:
    return [f"http {h.url}: {h.error}" for h in hops if h.error]


def _tls_errors(obs: TlsObservation) -> list[str]:
    return [f"tls port {obs.port}: {obs.error}"] if obs.error else []


def _finish(
    target: Target,
    config: ScanConfig,
    started_at: datetime,
    started: float,
    finished_at: datetime,
    status: str,
    ports: Sequence[PortResult],
    services: Sequence[ServiceResult],
    findings: Sequence[Finding],
    stage_errors: Sequence[str],
    observations: dict[str, object],
) -> ScanResult:
    scored = sort_findings(score_finding(f) for f in findings)
    metadata = ReportMetadata(
        tool_name="SentinelScan",
        tool_version=__version__,
        schema_version=SCHEMA_VERSION,
        started_at_utc=_utc_iso(started_at),
        finished_at_utc=_utc_iso(finished_at),
        duration_s=round(time.perf_counter() - started, 2),
        scan_config=config.to_dict(),
        python_version=platform.python_version(),
        platform=platform.platform(),
    )
    return ScanResult(
        metadata=metadata,
        target=target,
        status=status,
        ports=tuple(sorted(ports, key=lambda p: p.port)),
        services=tuple(services),
        findings=tuple(scored),
        stage_errors=tuple(stage_errors),
        summary=summarize(scored),
        observations=observations,
    )
