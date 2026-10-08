# Architecture

## Pipeline

```text
TARGET -> validate/resolve -> TCP discovery -> service ID -> HTTP analysis
       -> TLS analysis -> checks -> findings -> scoring -> report
```

`scanner.run_scan()` runs these stages in order. Expected network failures (refused, timeout,
bad HTTP, failed handshake) are recorded in `stage_errors` and never crash the scan. A DNS failure
produces a result with `status: "failed"` that can still be reported.

## Modules

| Module | Responsibility | Depends on |
|---|---|---|
| `models.py` | Frozen dataclasses and enums. No I/O. Every model has `to_dict()` for JSON. | stdlib |
| `sanitize.py` | Strips control characters from untrusted text and caps its length. | stdlib |
| `ports.py` | Parse port specs, resolve the host once, TCP connect scan with a bounded thread pool. | `models` |
| `services.py` | Identify the service on an open port with safe probes; `confirmed`/`probable`/`unknown`. | `models`, `sanitize` |
| `http.py` | `GET /` with `http.client`; records headers (every `Set-Cookie` separately, values redacted). Observes only. | `sanitize` |
| `tls.py` | Handshake with verification on; records version, cipher, certificate, verification result. | `sanitize` |
| `checks.py` | Pure functions: observations -> `Finding`s. | `models`, `http`, `tls` |
| `scoring.py` | Severity -> points table, ordering, aggregate score and rating. | `models` |
| `scanner.py` | Orchestrator and authorization guard. | all of the above |
| `reporter.py` | Terminal, JSON and self-contained HTML; safe output-file handling. | `models` |
| `cli.py` | `argparse`, input validation, exit codes. No scanning logic. | `scanner`, `reporter` |

## Key decisions

- **Observe vs judge.** `http.py` and `tls.py` only record facts. All rules live in `checks.py` as
  pure functions, so each rule is unit-tested with a hand-built observation and no sockets.
- **Standard library only.** `http.client` is used instead of `requests` because it exposes every
  `Set-Cookie` header separately, never follows redirects on its own, and lets us control TLS exactly.
- **Threads, not asyncio.** A `ThreadPoolExecutor` (default 50 workers, hard cap 256) is simple and
  needs no extra test dependencies. Each worker mostly waits on the network.
- **Determinism.** Results are sorted by port, findings by (severity desc, id, port), and scoring has
  no randomness or clock. The same observations always give the same findings.
- **Evidence over assumption.** A port number alone is never evidence. Port 5000 is not "UPnP"; it is
  whatever it answers (on macOS often AirPlay, reported as HTTP with its `Server` header).
- **Injected clock.** Certificate expiry maths takes `now` as a parameter, so tests do not depend on
  the real date.

## Data flow of a finding

`HttpObservation`/`TlsObservation` -> `check_*()` -> `Finding(id, title, severity, category,
description, evidence, remediation, target, port)` -> `scoring.score_finding()` fills `score` ->
`ScanResult` -> reporter. Finding IDs are stable (for example `SS-HTTP-004`) so reports can be
compared over time.
