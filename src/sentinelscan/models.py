"""Data models: frozen dataclasses and enums. No I/O."""

from dataclasses import dataclass
from enum import Enum, IntEnum


class PortState(str, Enum):
    """What we observed when connecting to a port."""

    OPEN = "open"  # connection succeeded
    CLOSED = "closed"  # connection actively refused
    FILTERED = "filtered"  # no answer before the timeout
    ERROR = "error"  # something else went wrong (e.g. network unreachable)


class Severity(IntEnum):
    """Ordered severity: INFO < LOW < MEDIUM < HIGH < CRITICAL."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError:
            names = ", ".join(member.name.lower() for member in cls)
            raise ValueError(f"unknown severity {text!r} (choose from: {names})") from None


class Confidence(str, Enum):
    """How sure we are about a service identification."""

    CONFIRMED = "confirmed"  # protocol evidence seen on the wire
    PROBABLE = "probable"  # weak evidence plus port context (a guess)
    UNKNOWN = "unknown"  # no usable evidence


class Category(str, Enum):
    NETWORK = "network"
    SERVICE = "service"
    HTTP = "http"
    TLS = "tls"
    SCAN = "scan"


@dataclass(frozen=True, slots=True)
class PortResult:
    """Outcome of scanning one port."""

    port: int
    state: PortState
    latency_ms: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Plain dict for JSON output."""
        return {
            "port": self.port,
            "state": self.state.value,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class ServiceResult:
    """What is listening on an open port, and how sure we are."""

    port: int
    name: str | None
    confidence: Confidence
    evidence: str = ""
    guess_basis: str | None = None
    is_http: bool = False
    is_tls: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "port": self.port,
            "name": self.name,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "guess_basis": self.guess_basis,
            "is_http": self.is_http,
            "is_tls": self.is_tls,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """One observation worth reporting: what was seen, why it matters, how to fix it."""

    id: str
    title: str
    severity: Severity
    category: Category
    description: str
    evidence: str
    remediation: str
    target: str
    port: int | None = None
    score: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "target": self.target,
            "port": self.port,
            "score": self.score,
        }


@dataclass(frozen=True, slots=True)
class Target:
    raw: str
    host: str
    port_spec: tuple[int, ...]
    addresses: tuple[str, ...] = ()
    address: str | None = None  # the address actually scanned
    is_ip_literal: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "raw": self.raw,
            "host": self.host,
            "address": self.address,
            "addresses": list(self.addresses),
            "is_ip_literal": self.is_ip_literal,
            "ports_requested": len(self.port_spec),
        }


@dataclass(frozen=True, slots=True)
class RiskSummary:
    counts_by_severity: dict[str, int]
    highest_severity: str
    aggregate_score: int
    rating: str

    def to_dict(self) -> dict[str, object]:
        return {
            "counts_by_severity": dict(self.counts_by_severity),
            "highest_severity": self.highest_severity,
            "aggregate_score": self.aggregate_score,
            "rating": self.rating,
        }


@dataclass(frozen=True, slots=True)
class ReportMetadata:
    tool_name: str
    tool_version: str
    schema_version: str
    started_at_utc: str
    finished_at_utc: str
    duration_s: float
    scan_config: dict[str, object]
    python_version: str
    platform: str

    def to_dict(self) -> dict[str, object]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "schema_version": self.schema_version,
            "started_at_utc": self.started_at_utc,
            "finished_at_utc": self.finished_at_utc,
            "duration_s": self.duration_s,
            "scan_config": dict(self.scan_config),
            "python_version": self.python_version,
            "platform": self.platform,
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Everything a scan produced; the single input to every report format."""

    metadata: ReportMetadata
    target: Target
    status: str  # "completed" or "failed"
    ports: tuple[PortResult, ...]
    services: tuple[ServiceResult, ...]
    findings: tuple[Finding, ...]
    stage_errors: tuple[str, ...]
    summary: RiskSummary
    observations: dict[str, object]

    def port_counts(self) -> dict[str, int]:
        counts = {state.value: 0 for state in PortState}
        for result in self.ports:
            counts[result.state.value] += 1
        return counts

    def open_ports(self) -> tuple[PortResult, ...]:
        return tuple(p for p in self.ports if p.state is PortState.OPEN)

    def to_dict(self) -> dict[str, object]:
        return {
            "metadata": self.metadata.to_dict(),
            "target": self.target.to_dict(),
            "status": self.status,
            "summary": self.summary.to_dict(),
            "port_counts": self.port_counts(),
            "ports": [p.to_dict() for p in self.open_ports()],
            "services": [s.to_dict() for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
            "observations": self.observations,
            "stage_errors": list(self.stage_errors),
        }
