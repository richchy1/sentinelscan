# Testing

```bash
pip install -e ".[dev]"      # pytest, ruff, mypy, cryptography
pytest                       # everything (176 tests, about 18 seconds)
pytest -m unit               # 127 offline tests, about 2 seconds
pytest -m integration        # 49 tests against localhost servers
ruff check .
mypy src
```

Tests are marked `unit` or `integration` automatically by their folder (`tests/conftest.py`).
**No test touches the internet.** Everything uses `127.0.0.1`, fakes, or injected values.

## Layers

| Layer | What it covers | How |
|---|---|---|
| `tests/unit/test_ports.py` | port-spec parsing and bounds, open/closed/filtered/error states, DNS errors, ordering, determinism, argument limits | pure functions, ephemeral listeners, `monkeypatch` for timeouts and DNS |
| `tests/unit/test_services.py` | banner recognition, "never confirmed without wire evidence", port 5000 is never guessed as UPnP | fake servers |
| `tests/unit/test_checks_http.py` | every HTTP rule, case-insensitive headers, multiple cookies, cookie value redaction, redirect safety | hand-built `HttpObservation`s |
| `tests/unit/test_tls.py` | expiry maths with an injected clock, certificate parsing, every TLS rule | hand-built `TlsObservation`s |
| `tests/unit/test_scoring.py` | every severity path, aggregate cap, de-duplication, ordering, determinism | pure |
| `tests/unit/test_reporter.py` | JSON round trip, HTML escaping of hostile text, no external URLs, empty and failed scans, output-path errors | `tmp_path` |
| `tests/integration/test_http_fixtures.py` | insecure and secure real `http.server` fixtures give exactly the expected finding IDs; redirects are bounded and same-host only | local servers |
| `tests/integration/test_tls_local.py` | valid, expired, wrong-hostname, self-signed, expiring-soon and IP certificates | local TLS servers with generated certificates |
| `tests/integration/test_scanner_end_to_end.py` | full pipeline, HTTP+HTTPS together, DNS failure, authorization guard | fixtures |
| `tests/integration/test_cli.py` | `main([...])` end to end, exit codes, `--fail-on`, `--force`, no tracebacks | fixtures, `capsys` |

## Fixtures

- `tests/servers.py`: `TcpServer`, `banner_server`, `silent_server`, `HttpFixture` (plain or TLS, with
  fixed response headers), `INSECURE_HEADERS`, `SECURE_HEADERS`.
- `tests/certs.py`: generates throw-away certificates with `cryptography` at test time, so no private
  key is ever committed (`*.pem`, `*.key`, `*.crt` are git-ignored).

## Notes

- Timeout and DNS failures are simulated with `monkeypatch`, because real ones depend on the network
  and would make tests flaky.
- Python's `HTTPServer` calls `socket.getfqdn()` when it binds, which can take many seconds on some
  networks. The test servers and `examples/demo_server.py` skip that call.
- Any bug found in future gets a named regression test.
