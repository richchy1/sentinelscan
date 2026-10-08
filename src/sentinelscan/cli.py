"""SentinelScan command-line interface. Parses arguments and calls the scanner."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from sentinelscan import __version__
from sentinelscan.models import ScanResult, Severity
from sentinelscan.ports import (
    DEFAULT_TIMEOUT,
    DEFAULT_WORKERS,
    MAX_TIMEOUT,
    MAX_WORKERS,
    MIN_TIMEOUT,
    PortSpecError,
    parse_ports,
)
from sentinelscan.reporter import (
    FORMATS,
    ReportWriteError,
    check_output_path,
    render,
    should_color,
    write_report,
)
from sentinelscan.scanner import AuthorizationError, ScanConfig, run_scan

EXIT_OK = 0
EXIT_FINDINGS = 1  # only with --fail-on
EXIT_USAGE = 2
EXIT_RUNTIME = 3

EPILOG = """\
Only scan systems you own or are explicitly authorised to test.
exit codes: 0 scan completed, 1 finding at/above --fail-on, 2 usage or input error,
3 runtime failure (e.g. DNS failure, unwritable output).
"""


def _timeout(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not MIN_TIMEOUT <= value <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(f"must be between {MIN_TIMEOUT} and {MAX_TIMEOUT}")
    return value


def _workers(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if not 1 <= value <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_WORKERS}")
    return value


def _redirects(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {text!r}") from None
    if not 0 <= value <= 5:
        raise argparse.ArgumentTypeError("must be between 0 and 5")
    return value


def _severity(text: str) -> Severity:
    try:
        return Severity.parse(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelscan",
        description="Scan a host you are authorised to test: open TCP ports, services, "
        "HTTP security headers and TLS certificates.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", metavar="TARGET", help="hostname or IP address to scan")
    parser.add_argument(
        "-p", "--ports", default="common",
        help="ports: '22,80,8000-8100' or 'common' (default: common; max 1024 ports)",
    )
    parser.add_argument(
        "-t", "--timeout", type=_timeout, default=DEFAULT_TIMEOUT, metavar="SECONDS",
        help=f"per-connection timeout, {MIN_TIMEOUT}-{MAX_TIMEOUT} (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-c", "--concurrency", type=_workers, default=DEFAULT_WORKERS, metavar="N",
        help=f"parallel connections, 1-{MAX_WORKERS} (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "-f", "--format", choices=FORMATS, default="terminal",
        help="report format (default: terminal)",
    )
    parser.add_argument("-o", "--output", type=Path, metavar="FILE", help="write report to FILE")
    parser.add_argument("--force", action="store_true", help="overwrite an existing --output file")
    parser.add_argument(
        "--follow-redirects", action="store_true",
        help="follow same-host HTTP redirects (never leaves the target host)",
    )
    parser.add_argument(
        "--max-redirects", type=_redirects, default=5, metavar="N",
        help="maximum redirects to follow, 0-5 (default: 5)",
    )
    parser.add_argument(
        "--cafile", metavar="FILE", help="trust this CA file when checking TLS certificates"
    )
    parser.add_argument(
        "--server-name", metavar="NAME",
        help="name for TLS SNI, certificate checks and the HTTP Host header",
    )
    parser.add_argument(
        "--authorized", action="store_true",
        help="confirm you are authorised to scan a public address",
    )
    parser.add_argument(
        "--fail-on", type=_severity, metavar="SEVERITY",
        help="exit 1 if any finding is at or above SEVERITY (info, low, medium, high, critical)",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true", help="show progress on stderr")
    verbosity.add_argument("-q", "--quiet", action="store_true", help="print only the report")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _exit_code(result: ScanResult, fail_on: Severity | None) -> int:
    if result.status != "completed":
        return EXIT_RUNTIME
    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return the process exit code."""
    args = build_parser().parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except PortSpecError as exc:
        _error(str(exc))
        return EXIT_USAGE

    if args.output is not None:
        try:
            check_output_path(args.output, force=args.force)
        except ReportWriteError as exc:
            _error(str(exc))
            return exc.exit_code

    config = ScanConfig(
        ports=ports,
        timeout=args.timeout,
        workers=args.concurrency,
        follow_redirects=args.follow_redirects,
        max_redirects=args.max_redirects,
        cafile=args.cafile,
        server_name=args.server_name,
        authorized=args.authorized,
    )
    progress = (lambda message: print(f"[*] {message}", file=sys.stderr)) if args.verbose else None
    try:
        result = run_scan(args.target, config, progress=progress)
    except AuthorizationError as exc:
        _error(str(exc))
        return EXIT_USAGE

    if args.output is not None:
        try:
            write_report(args.output, render(result, args.format, color=False))
        except ReportWriteError as exc:
            _error(str(exc))
            return exc.exit_code
        if not args.quiet:
            print(f"report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(render(result, args.format, color=should_color(sys.stdout)))

    for stage_error in result.stage_errors if result.status != "completed" else ():
        _error(stage_error)
    return _exit_code(result, args.fail_on)


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())


if __name__ == "__main__":
    run()
