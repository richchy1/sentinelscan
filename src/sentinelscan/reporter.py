"""Terminal, JSON and HTML report rendering.

Banners and headers come from the scanned target and are untrusted, so every dynamic
value in the HTML report goes through ``html.escape``.
"""

import html
import json
import os
from collections.abc import Callable
from pathlib import Path
from string import Template
from typing import TextIO

from sentinelscan.models import Finding, ScanResult, Severity

FORMATS = ("terminal", "json", "html")

_ANSI = {
    "INFO": "\033[36m",
    "LOW": "\033[34m",
    "MEDIUM": "\033[33m",
    "HIGH": "\033[31m",
    "CRITICAL": "\033[1;31m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RESET": "\033[0m",
}


class ReportWriteError(Exception):
    """Raised for output-file problems. ``exit_code`` is 2 for bad input, 3 for runtime."""

    def __init__(self, message: str, exit_code: int = 3) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def should_color(stream: TextIO) -> bool:
    """Color only on a real terminal and when NO_COLOR is not set."""
    return stream.isatty() and "NO_COLOR" not in os.environ


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"


def to_terminal(result: ScanResult, color: bool = False) -> str:
    def paint(text: str, key: str) -> str:
        return f"{_ANSI[key]}{text}{_ANSI['RESET']}" if color else text

    meta, target = result.metadata, result.target
    lines = [
        paint(f"{meta.tool_name} {meta.tool_version}", "BOLD")
        + f" - scan of {target.host}"
        + (f" ({target.address})" if target.address else ""),
        f"started {meta.started_at_utc}  duration {meta.duration_s}s  status: {result.status}",
        "",
    ]

    counts = result.port_counts()
    lines.append(
        paint("PORTS", "BOLD")
        + f"  {counts['open']} open, {counts['closed']} closed, "
        f"{counts['filtered']} filtered, {counts['error']} error"
    )
    services = {s.port: s for s in result.services}
    if result.open_ports():
        lines.append(f"  {'PORT':<7}{'SERVICE':<16}{'CONFIDENCE':<12}EVIDENCE")
        for port in result.open_ports():
            service = services.get(port.port)
            name = (service.name if service and service.name else "unknown") if service else "-"
            confidence = service.confidence.value if service else "-"
            evidence = service.evidence if service else ""
            if service and service.guess_basis:
                evidence = f"[guess: {service.guess_basis}] {evidence}".strip()
            lines.append(f"  {port.port:<7}{name:<16}{confidence:<12}{evidence}")
    else:
        lines.append("  no open ports found")
    lines.append("")

    lines.append(paint(f"FINDINGS ({len(result.findings)})", "BOLD"))
    if not result.findings:
        lines.append("  none")
    for finding in result.findings:
        label = paint(f"[{finding.severity.label}]", finding.severity.label)
        where = f"port {finding.port}" if finding.port is not None else "host"
        lines.append(f"  {label} {finding.id} {finding.title} ({where}, score {finding.score})")
        lines.append(f"      evidence: {finding.evidence}")
        if finding.severity > Severity.INFO:
            lines.append(f"      why:      {finding.description}")
            lines.append(f"      fix:      {finding.remediation}")
    lines.append("")

    summary = result.summary
    counted = ", ".join(f"{n} {k}" for k, n in summary.counts_by_severity.items() if n)
    lines.append(
        paint("SUMMARY", "BOLD")
        + f"  rating {summary.rating}, score {summary.aggregate_score}/100"
        + (f"  ({counted})" if counted else "")
    )
    if result.stage_errors:
        lines.append("")
        lines.append(paint("NOTES / STAGE ERRORS", "DIM"))
        lines.extend(f"  - {error}" for error in result.stage_errors)
    return "\n".join(lines) + "\n"


_HTML_PAGE = Template(
    """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelScan report - $host</title>
<style>
:root { --bg:#fff; --fg:#1a1d21; --muted:#5d6670; --line:#d9dde2; --card:#f6f7f9;
  --info:#0b7a99; --low:#2860b8; --medium:#a86a00; --high:#c0322c; --critical:#8e1b3d; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#14171a; --fg:#e8eaed; --muted:#9aa3ad; --line:#2d333a; --card:#1c2024;
    --info:#4fc3e0; --low:#7aa7f0; --medium:#e0a33a; --high:#f0746e; --critical:#f06b92; } }
body { margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:960px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:1.5rem; margin:0 0 4px; } h2 { font-size:1.1rem; margin:32px 0 8px; }
.muted { color:var(--muted); font-size:.9rem; }
.summary { display:flex; gap:12px; flex-wrap:wrap; margin:16px 0; }
.stat { background:var(--card); border:1px solid var(--line); border-radius:8px;
  padding:10px 14px; min-width:110px; }
.stat b { display:block; font-size:1.4rem; }
table { width:100%; border-collapse:collapse; font-size:.9rem; display:block; overflow-x:auto; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line);
  vertical-align:top; }
.finding { background:var(--card); border:1px solid var(--line); border-left-width:5px;
  border-radius:8px; padding:10px 14px; margin:10px 0; }
.finding h3 { margin:0 0 4px; font-size:1rem; }
.finding p { margin:4px 0; } code { font:13px ui-monospace,Menlo,monospace; word-break:break-word; }
.sev { font-weight:700; font-size:.8rem; letter-spacing:.04em; }
.INFO { border-left-color:var(--info); } .INFO .sev { color:var(--info); }
.LOW { border-left-color:var(--low); } .LOW .sev { color:var(--low); }
.MEDIUM { border-left-color:var(--medium); } .MEDIUM .sev { color:var(--medium); }
.HIGH { border-left-color:var(--high); } .HIGH .sev { color:var(--high); }
.CRITICAL { border-left-color:var(--critical); } .CRITICAL .sev { color:var(--critical); }
</style>
</head>
<body><main>
$body
</main></body>
</html>
"""
)


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _finding_html(finding: Finding) -> str:
    where = f"port {finding.port}" if finding.port is not None else "host"
    return (
        f'<div class="finding {_e(finding.severity.label)}">'
        f'<h3><span class="sev">{_e(finding.severity.label)}</span> '
        f"{_e(finding.id)} - {_e(finding.title)}</h3>"
        f'<p class="muted">{_e(where)} - score {_e(finding.score)}</p>'
        f"<p><b>Evidence:</b> <code>{_e(finding.evidence)}</code></p>"
        f"<p><b>Why it matters:</b> {_e(finding.description)}</p>"
        f"<p><b>Fix:</b> {_e(finding.remediation)}</p></div>"
    )


def to_html(result: ScanResult) -> str:
    meta, target, summary = result.metadata, result.target, result.summary
    counts = result.port_counts()
    services = {s.port: s for s in result.services}

    rows = []
    for port in result.open_ports():
        service = services.get(port.port)
        evidence = service.evidence if service else ""
        if service and service.guess_basis:
            evidence = f"[guess: {service.guess_basis}] {evidence}"
        rows.append(
            f"<tr><td>{port.port}</td><td>{_e(service.name if service else None) or 'unknown'}"
            f"</td><td>{_e(service.confidence.value if service else '-')}</td>"
            f"<td><code>{_e(evidence)}</code></td></tr>"
        )
    ports_html = (
        "<table><thead><tr><th>Port</th><th>Service</th><th>Confidence</th><th>Evidence</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        if rows
        else '<p class="muted">No open ports found.</p>'
    )

    stats = "".join(
        f'<div class="stat"><span class="muted">{_e(label)}</span><b>{_e(value)}</b></div>'
        for label, value in (
            ("Rating", summary.rating),
            ("Score", f"{summary.aggregate_score}/100"),
            ("Open ports", counts["open"]),
            ("Findings", len(result.findings)),
        )
    )
    findings_html = "".join(_finding_html(f) for f in result.findings) or (
        '<p class="muted">No findings.</p>'
    )
    errors_html = ""
    if result.stage_errors:
        items = "".join(f"<li><code>{_e(err)}</code></li>" for err in result.stage_errors)
        errors_html = f"<h2>Notes and stage errors</h2><ul>{items}</ul>"

    body = (
        f"<h1>SentinelScan report</h1>"
        f'<p class="muted">Target {_e(target.host)}'
        f"{' (' + _e(target.address) + ')' if target.address else ''} - "
        f"status {_e(result.status)} - started {_e(meta.started_at_utc)} - "
        f"duration {_e(meta.duration_s)}s - {_e(meta.tool_name)} {_e(meta.tool_version)}</p>"
        f'<div class="summary">{stats}</div>'
        f"<h2>Open ports</h2>"
        f'<p class="muted">{counts["open"]} open, {counts["closed"]} closed, '
        f'{counts["filtered"]} filtered, {counts["error"]} error</p>{ports_html}'
        f"<h2>Findings</h2>{findings_html}{errors_html}"
        '<p class="muted">Scores are a simple documented model, not CVSS. '
        "A scan is a point-in-time observation.</p>"
    )
    return _HTML_PAGE.substitute(host=_e(target.host), body=body)


RENDERERS: dict[str, Callable[[ScanResult], str]] = {
    "json": to_json,
    "html": to_html,
}


def render(result: ScanResult, fmt: str, *, color: bool = False) -> str:
    if fmt == "terminal":
        return to_terminal(result, color)
    return RENDERERS[fmt](result)


def check_output_path(path: Path, *, force: bool) -> None:
    """Fail fast, before scanning, if the report cannot be written."""
    if path.is_dir():
        raise ReportWriteError(f"output path is a directory: {path}", 2)
    if path.exists() and not force:
        raise ReportWriteError(f"{path} already exists (use --force to overwrite)", 2)
    parent = path.parent if str(path.parent) else Path(".")
    if not parent.is_dir():
        raise ReportWriteError(f"directory does not exist: {parent}", 3)
    if not os.access(parent, os.W_OK):
        raise ReportWriteError(f"cannot write to directory: {parent}", 3)


def write_report(path: Path, text: str) -> None:
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ReportWriteError(f"cannot write {path}: {exc.strerror or exc}", 3) from exc
