# Security model

SentinelScan is a defensive tool for systems you own or are authorised to test.

## What it will never do

No exploitation, brute-forcing, credential guessing, payload delivery, persistence, protocol
downgrade attempts, cipher enumeration or denial-of-service behaviour. It sends: TCP connects,
a passive banner read, a TLS handshake, `HEAD /` (service identification) and `GET /` (HTTP analysis).

## Authorization guard

Loopback, private and link-local addresses (`127.0.0.0/8`, `10/8`, `192.168/16`, `169.254/16`, `::1`,
and so on) are scanned directly. If **any** address a hostname resolves to is public, the scan stops
**before a single connection is made** with an error telling you to re-run with `--authorized`. This is
a safeguard against typos, not a legal protection: you remain responsible for having permission.

## Bounded work

| Limit | Value |
|---|---|
| Ports per scan | 1024 (checked before a range is expanded) |
| Concurrent connections | default 50, max 256 |
| Connect timeout | 0.1-30 s |
| HTTP response body read | 64 KB |
| Redirects | off by default; max 5; same host only |
| Evidence length | 500 characters |

## Untrusted input

Everything a target sends (banners, headers, certificate fields, error text) is untrusted.

- Control characters are stripped and length is capped before anything is stored (`sanitize.py`).
- The HTML report escapes every dynamic value with `html.escape`, uses no JavaScript and makes no
  external requests; a test feeds `<script>` into a banner, a finding and a stage error.
- Cookie **values** are redacted at capture time. Only names and flags are kept.
- Redirects are never followed off the scanned host, so a malicious server cannot steer the scanner
  elsewhere.
- Certificates are not verified during HTTP fetching or service identification (those stages only
  observe); verification is the TLS stage's job and is always on there.

## Scoring

Deterministic and documented, not CVSS: INFO 0, LOW 10, MEDIUM 30, HIGH 60, CRITICAL 90. A finding's
score comes from its severity; the scan score is the sum of unique (finding id, port) pairs capped at
100; the rating is the highest severity present, or `NONE` when only INFO findings exist. No check emits
`CRITICAL`, because the tool has no exploit or CVE data to justify it.

## Reports and files

The output path is validated before scanning. An existing file is never overwritten without
`--force`. File-system errors give a one-line message and exit code 2 or 3.
