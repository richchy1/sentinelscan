# Usage

```text
sentinelscan TARGET [-p PORTS] [-t SECONDS] [-c N] [-f {terminal,json,html}] [-o FILE] [--force]
                    [--follow-redirects] [--max-redirects N] [--cafile FILE] [--server-name NAME]
                    [--authorized] [--fail-on SEVERITY] [-v | -q] [--version] [-h]
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `TARGET` | required | Hostname or IP address. |
| `-p`, `--ports` | `common` | Ports: `22,80,443`, ranges `8000-8100`, or `common` (26 well-known ports). Max 1024 ports; 1-65535. |
| `-t`, `--timeout` | `1.0` | Per-connection timeout in seconds, 0.1-30. |
| `-c`, `--concurrency` | `50` | Parallel connections, 1-256. |
| `-f`, `--format` | `terminal` | `terminal`, `json` or `html`. |
| `-o`, `--output` | stdout | Write the report to a file. The path is checked **before** scanning. |
| `--force` | off | Overwrite an existing `--output` file. |
| `--follow-redirects` | off | Follow HTTP redirects, same host only. |
| `--max-redirects` | `5` | Redirect limit, 0-5. |
| `--cafile` | system CAs | Trust this CA file for TLS checks (for private/lab CAs). |
| `--server-name` | target | Name for TLS SNI, certificate checks and the HTTP `Host` header. |
| `--authorized` | off | Required to scan public addresses. |
| `--fail-on` | off | Exit 1 if any finding is at or above `info`, `low`, `medium`, `high`, `critical`. |
| `-v` / `-q` | | Progress on stderr / print only the report. |

## Examples

```bash
sentinelscan 127.0.0.1                                  # common ports, terminal report
sentinelscan localhost -p 22,80,443,8000-8100
sentinelscan 127.0.0.1 -p 8080 -f json -o report.json
sentinelscan 127.0.0.1 -p 8080 -f html -o report.html --force
sentinelscan 127.0.0.1 -p 8443 --cafile ca.pem --server-name localhost
sentinelscan 10.0.0.5 --fail-on high                    # use in CI
sentinelscan scanme.example --authorized                # public address: you must confirm
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed (and no finding reached `--fail-on`). |
| 1 | A finding at or above `--fail-on`. |
| 2 | Usage or input error: bad port list, bad option, output file exists without `--force`, public target without `--authorized`. |
| 3 | Runtime failure: DNS failure, unwritable output directory. |

Expected problems print one line starting with `error:` and never a traceback.

## Reading a report

Each finding has an `id`, a `severity`, **evidence** (what was actually observed), **why it matters**
and **how to fix it**. Open ports and identified services are `INFO` observations, not
vulnerabilities. A service marked `probable` is a labelled guess (the report says what it is based
on); `unknown` means there was no usable evidence.
