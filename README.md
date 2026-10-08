# SentinelScan

A small, dependency-free command-line tool that scans a host **you are authorised to test** and reports open TCP ports, what is actually running on them, weak HTTP security headers and cookies, and TLS certificate problems, with evidence and a fix for every finding.

> **Responsible use.** Only scan systems you own or have explicit written permission to test. Scanning
> systems without permission may be illegal. SentinelScan only observes: it contains no exploits, no
> brute-forcing, no payloads and no destructive code. Public addresses are refused unless you pass
> `--authorized`.

## How it works

```text
TARGET -> validate/resolve -> TCP connect scan -> service identification
       -> HTTP analysis -> TLS analysis -> checks -> findings -> scoring -> report

 cli.py  --->  scanner.py  --->  ports.py      (find open ports)
 (args,        (orchestrates,    services.py   (what is listening, with confidence)
  exit          never crashes    http.py       (observe headers/cookies)  \
  codes)        on expected      tls.py        (observe cert/protocol)     > observe only
                network errors)  checks.py     (judge observations -> findings)   judge only
                      |          scoring.py    (severity -> points, rating)
                      v
                 reporter.py  --->  terminal | JSON | self-contained HTML
```

The key design choice is the split between **observing** (`http.py`, `tls.py`) and **judging**
(`checks.py`). Every rule is a pure function that can be tested with a hand-built observation and no
sockets.

## Install

Python 3.10 or newer. The scanner itself needs **no third-party packages**.

```bash
git clone https://github.com/richchy1/sentinelscan.git
cd sentinelscan
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
sentinelscan --help
```

Optional: `pip install -e ".[tls-detail]"` adds the `cryptography` package so the report can show
issuer and dates for self-signed or untrusted certificates (the standard library cannot decode them).
Developers: `pip install -e ".[dev]"`.

## Try it in 30 seconds (everything stays on your machine)

```bash
# terminal 1: an intentionally insecure server, bound to 127.0.0.1 only
python examples/demo_server.py

# terminal 2: scan it
sentinelscan 127.0.0.1 -p 8080
```

Real output from that scan (trimmed; the full reports are in [`examples/`](examples/)):

```text
SentinelScan 0.1.0 - scan of 127.0.0.1 (127.0.0.1)
started 2026-10-08T14:40:54Z  duration 0.51s  status: completed

PORTS  1 open, 0 closed, 0 filtered, 0 error
  PORT   SERVICE         CONFIDENCE  EVIDENCE
  8080   http            confirmed   HTTP/1.0 200 OK; Server: Apache/2.4.49

FINDINGS (8)
  [MEDIUM] SS-HTTP-004 Missing Content-Security-Policy (port 8080, score 30)
      evidence: Content-Security-Policy header not present
      why:      A CSP limits where scripts and other content can load from, which reduces the impact of cross-site scripting.
      fix:      Define a Content-Security-Policy, starting with default-src 'self'.
  ... 7 more findings ...

SUMMARY  rating MEDIUM, score 80/100  (1 MEDIUM, 5 LOW, 2 INFO)
```

More examples:

```bash
sentinelscan localhost -p 22,80,443,8000-8100         # ports and ranges
sentinelscan 127.0.0.1 -f json -o report.json         # machine-readable
sentinelscan 127.0.0.1 -f html -o report.html         # self-contained web page
sentinelscan 127.0.0.1 --fail-on medium               # exit 1 if a finding >= medium (CI use)
sentinelscan lab.internal --cafile lab-ca.pem --server-name lab.internal
```

See [docs/usage.md](docs/usage.md) for every option and exit code.

## What it checks

| Area | Checks |
|---|---|
| Network | open ports (informational) |
| Services | banner, TLS and HTTP evidence; every result is `confirmed`, `probable` (a labelled guess) or `unknown` |
| HTTP | HTTP to HTTPS redirect, HSTS (missing/weak), CSP (missing/weak), `X-Content-Type-Options`, clickjacking protection, `Referrer-Policy`, cookie `Secure`/`HttpOnly`/`SameSite`, server version disclosure, off-host redirects |
| TLS | expired / expiring (14 and 30 days), hostname mismatch, untrusted or self-signed chain, TLS 1.0/1.1, negotiated version |

Scoring is a simple documented table (INFO 0, LOW 10, MEDIUM 30, HIGH 60, CRITICAL 90, total capped at
100). **It is not CVSS.** No check emits CRITICAL, because without exploit or CVE data it cannot be justified.

## Tests

```bash
pip install -e ".[dev]"
pytest              # 176 tests
pytest -m unit      # 127 offline tests
pytest -m integration  # 49 tests against localhost fixture servers
ruff check . && mypy src
```

No test touches the internet. Integration tests start real servers on `127.0.0.1` (plain HTTP, HTTPS
with generated valid, expired, wrong-hostname and self-signed certificates, fake SSH banners, silent
sockets). See [docs/testing.md](docs/testing.md). Tested locally on Python 3.14; CI runs 3.10 to 3.14.

## Limitations

- TCP connect scan only: no UDP, no SYN/stealth scanning. It is visible in the target's logs.
- Results are a point-in-time observation, not a vulnerability assessment. A clean report does not
  mean a host is secure.
- Only the protocol version a normal modern handshake negotiates is reported. It does not probe
  whether a server still *supports* TLS 1.0/1.1 or enumerate ciphers.
- For certificates that fail verification, details need `--cafile` or the optional `cryptography` package.
- Only `GET /` is analysed per HTTP port; authenticated or deep application testing is out of scope.
- IPv6 targets work but are not specifically tested. Only the first resolved address is scanned.
- Service identification is best-effort. `unknown` is a valid answer.

## Project layout

```text
src/sentinelscan/   cli, scanner, ports, services, http, tls, checks, scoring, reporter, models, sanitize
tests/unit/         offline tests          tests/integration/   localhost fixture-server tests
docs/               architecture, usage, testing, security model
examples/           demo_server.py, sample_report.json, sample_report.html
```

## License

MIT, see [LICENSE](LICENSE).
