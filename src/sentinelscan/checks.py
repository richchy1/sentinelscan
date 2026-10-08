"""Pure functions turning observations into findings.

Nothing here does I/O. Every rule can be tested with a hand-built observation.
"""

import re
from collections.abc import Sequence

from sentinelscan.http import Cookie, HttpObservation
from sentinelscan.models import Category, Finding, ServiceResult, Severity
from sentinelscan.tls import TlsObservation

HSTS_MIN_AGE = 15_552_000  # 180 days
_VERSIONED_PRODUCT = re.compile(r"[A-Za-z][\w.\-]*/\d+(?:\.\d+)*")
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)


def _finding(
    fid: str,
    title: str,
    severity: Severity,
    category: Category,
    description: str,
    evidence: str,
    remediation: str,
    target: str,
    port: int | None,
) -> Finding:
    return Finding(
        id=fid,
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=evidence,
        remediation=remediation,
        target=target,
        port=port,
    )


def _csp_directives(csp: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for part in csp.split(";"):
        name, _, value = part.strip().partition(" ")
        if name:
            directives.setdefault(name.lower(), value.strip())
    return directives


def _names(cookies: Sequence[Cookie]) -> str:
    return ", ".join(sorted({c.name for c in cookies}))


def check_network(port: int, service: ServiceResult | None, target: str) -> list[Finding]:
    """An open port is an observation, not a vulnerability."""
    if service is None or service.name is None:
        detail = "service not identified"
    else:
        detail = f"{service.name} ({service.confidence.value})"
    evidence = f"port {port} accepted a TCP connection; {detail}"
    return [
        _finding(
            "SS-NET-001",
            "Open TCP port",
            Severity.INFO,
            Category.NETWORK,
            "A TCP port accepted a connection. Open ports are the attack surface of a host; "
            "each one should be there on purpose.",
            evidence,
            "Close or firewall ports that are not needed. Keep a list of expected open ports.",
            target,
            port,
        )
    ]


def _location_note(obs: HttpObservation) -> str:
    return f" with Location {obs.redirect_location}" if obs.redirect_location else ""


def _redirects_to_https(obs: HttpObservation) -> bool:
    return obs.is_redirect and (obs.redirect_location or "").lower().startswith("https://")


def check_http(
    hops: Sequence[HttpObservation],
    *,
    target: str,
    port: int,
    https_available: bool,
) -> list[Finding]:
    """Judge a chain of HTTP observations (first hop = what the port answered)."""
    findings: list[Finding] = []
    observed = [h for h in hops if h.status is not None]

    if not observed:
        error = hops[-1].error if hops else "no response"
        findings.append(
            _finding(
                "SS-HTTP-014",
                "HTTP request failed",
                Severity.INFO,
                Category.HTTP,
                "The port looked like HTTP but no valid HTTP response was received, so no "
                "web checks could run. This is not a vulnerability.",
                f"error: {error}",
                "Check that the service speaks HTTP on this port and is reachable.",
                target,
                port,
            )
        )
        return findings

    first, last = observed[0], observed[-1]

    if first.scheme == "http" and https_available:
        if not _redirects_to_https(first) and (first.status or 0) < 400:
            findings.append(
                _finding(
                    "SS-HTTP-001",
                    "HTTP does not redirect to HTTPS",
                    Severity.MEDIUM,
                    Category.HTTP,
                    "HTTPS is available on this host but plain HTTP is served without "
                    "redirecting to it, so users can end up on an unencrypted connection.",
                    f"GET {first.url} returned {first.status}" + _location_note(first),
                    "Redirect all HTTP requests to HTTPS (301) and enable HSTS.",
                    target,
                    first.port,
                )
            )

    if first.redirect_same_host is False and first.redirect_location:
        findings.append(
            _finding(
                "SS-HTTP-013",
                "Redirect to a different host",
                Severity.INFO,
                Category.HTTP,
                "The service redirects to another host. SentinelScan does not follow "
                "redirects off the scanned target.",
                f"Location: {first.redirect_location}",
                "Confirm the redirect target is expected, and scan it separately if needed.",
                target,
                first.port,
            )
        )

    findings.extend(_server_disclosure(last, target))
    if not last.is_redirect:
        findings.extend(_header_policy(last, target))
    findings.extend(_cookie_checks(observed, target))
    return findings


def _server_disclosure(obs: HttpObservation, target: str) -> list[Finding]:
    leaked = [
        f"{name}: {value}"
        for name in ("Server", "X-Powered-By")
        for value in obs.header_values(name)
        if _VERSIONED_PRODUCT.search(value)
    ]
    if not leaked:
        return []
    return [
        _finding(
            "SS-HTTP-012",
            "Server software and version disclosed",
            Severity.LOW,
            Category.HTTP,
            "Response headers reveal exact software versions. This helps an attacker pick "
            "known exploits for that version.",
            "; ".join(leaked),
            "Remove version numbers from the Server and X-Powered-By headers.",
            target,
            obs.port,
        )
    ]


def _header_policy(obs: HttpObservation, target: str) -> list[Finding]:
    port = obs.port
    findings: list[Finding] = []

    def add(fid: str, title: str, sev: Severity, desc: str, evidence: str, fix: str) -> None:
        findings.append(_finding(fid, title, sev, Category.HTTP, desc, evidence, fix, target, port))

    # HSTS is ignored by browsers on plain HTTP, so only judge it on HTTPS.
    if obs.scheme == "https":
        hsts = obs.header("Strict-Transport-Security")
        if hsts is None:
            add(
                "SS-HTTP-002",
                "Missing HSTS header",
                Severity.LOW,
                "Without Strict-Transport-Security, browsers may use plain HTTP on first "
                "visit and are open to downgrade attacks.",
                "Strict-Transport-Security header not present",
                "Send Strict-Transport-Security: max-age=31536000; includeSubDomains",
            )
        else:
            match = _MAX_AGE.search(hsts)
            age = int(match.group(1)) if match else 0
            if age < HSTS_MIN_AGE:
                add(
                    "SS-HTTP-003",
                    "Weak HSTS max-age",
                    Severity.LOW,
                    f"HSTS max-age is shorter than {HSTS_MIN_AGE} seconds (180 days), so "
                    "protection expires quickly.",
                    f"Strict-Transport-Security: {hsts}",
                    "Use max-age of at least 15552000, ideally 31536000.",
                )

    csp = obs.header("Content-Security-Policy")
    if csp is None:
        add(
            "SS-HTTP-004",
            "Missing Content-Security-Policy",
            Severity.MEDIUM,
            "A CSP limits where scripts and other content can load from, which reduces the "
            "impact of cross-site scripting.",
            "Content-Security-Policy header not present",
            "Define a Content-Security-Policy, starting with default-src 'self'.",
        )
    else:
        directives = _csp_directives(csp)
        script_policy = directives.get("script-src", directives.get("default-src", ""))
        unsafe = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in script_policy]
        if unsafe:
            add(
                "SS-HTTP-005",
                "Weak Content-Security-Policy",
                Severity.LOW,
                "The script policy allows unsafe-inline or unsafe-eval, which largely "
                "defeats CSP protection against script injection.",
                f"Content-Security-Policy: {csp}",
                "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes instead.",
            )

    nosniff = obs.header("X-Content-Type-Options")
    if nosniff is None or nosniff.strip().lower() != "nosniff":
        add(
            "SS-HTTP-006",
            "X-Content-Type-Options not set to nosniff",
            Severity.LOW,
            "Browsers may guess a response's content type and run it as something "
            "dangerous (MIME sniffing).",
            f"X-Content-Type-Options: {nosniff}" if nosniff else "header not present",
            "Send X-Content-Type-Options: nosniff",
        )

    frame_ancestors = "frame-ancestors" in _csp_directives(csp or "")
    if obs.header("X-Frame-Options") is None and not frame_ancestors:
        add(
            "SS-HTTP-007",
            "No clickjacking protection",
            Severity.LOW,
            "The page can be embedded in a frame on another site, which enables "
            "clickjacking attacks.",
            "neither X-Frame-Options nor CSP frame-ancestors present",
            "Send X-Frame-Options: DENY or a CSP with frame-ancestors 'none'.",
        )

    if obs.header("Referrer-Policy") is None:
        add(
            "SS-HTTP-008",
            "Missing Referrer-Policy",
            Severity.INFO,
            "Without a Referrer-Policy, browsers may send full URLs to other sites.",
            "Referrer-Policy header not present",
            "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        )
    return findings


def _cookie_checks(observed: Sequence[HttpObservation], target: str) -> list[Finding]:
    """One finding per rule, listing every offending cookie by name (never by value)."""
    missing_secure: list[Cookie] = []
    missing_httponly: list[Cookie] = []
    bad_samesite: list[Cookie] = []
    seen: set[str] = set()
    port = observed[-1].port
    for obs in observed:
        for cookie in obs.cookies:
            if cookie.name in seen:
                continue
            seen.add(cookie.name)
            if obs.scheme == "https" and not cookie.secure:
                missing_secure.append(cookie)
            if not cookie.http_only:
                missing_httponly.append(cookie)
            samesite = (cookie.same_site or "").lower()
            if not samesite or (samesite == "none" and not cookie.secure):
                bad_samesite.append(cookie)

    findings: list[Finding] = []
    if missing_secure:
        findings.append(
            _finding(
                "SS-HTTP-009",
                "Cookie missing Secure flag",
                Severity.MEDIUM,
                Category.HTTP,
                "Cookies without Secure can be sent over plain HTTP, where anyone on the "
                "network can read them.",
                f"cookies: {_names(missing_secure)}",
                "Add the Secure attribute to every cookie set over HTTPS.",
                target,
                port,
            )
        )
    if missing_httponly:
        findings.append(
            _finding(
                "SS-HTTP-010",
                "Cookie missing HttpOnly flag",
                Severity.LOW,
                Category.HTTP,
                "Cookies without HttpOnly can be read by JavaScript, so an injected script "
                "can steal them.",
                f"cookies: {_names(missing_httponly)}",
                "Add HttpOnly to cookies that JavaScript does not need to read.",
                target,
                port,
            )
        )
    if bad_samesite:
        findings.append(
            _finding(
                "SS-HTTP-011",
                "Cookie missing or weak SameSite",
                Severity.LOW,
                Category.HTTP,
                "Cookies without SameSite (or with SameSite=None but no Secure) are sent on "
                "cross-site requests, which enables CSRF.",
                f"cookies: {_names(bad_samesite)}",
                "Set SameSite=Lax or Strict; SameSite=None requires the Secure attribute.",
                target,
                port,
            )
        )
    return findings


# OpenSSL verification error codes we give specific findings for.
_VERIFY_EXPIRED = 10
_VERIFY_HOSTNAME = {62, 64}  # hostname mismatch, IP address mismatch
_LEGACY_TLS = {"TLSv1", "TLSv1.1"}


def check_tls(obs: TlsObservation, *, target: str) -> list[Finding]:
    """Judge a TLS observation. A failed handshake is a stage error, not a finding."""
    if not obs.handshake_ok:
        return []
    findings: list[Finding] = []
    port = obs.port

    def add(fid: str, title: str, sev: Severity, desc: str, evidence: str, fix: str) -> None:
        findings.append(_finding(fid, title, sev, Category.TLS, desc, evidence, fix, target, port))

    days = obs.days_to_expiry
    expired = (days is not None and days < 0) or obs.verify_code == _VERIFY_EXPIRED
    not_after = obs.cert.not_after.date().isoformat() if obs.cert else "unknown date"
    if expired:
        add(
            "SS-TLS-001",
            "Certificate expired",
            Severity.HIGH,
            "The certificate is past its expiry date. Browsers show a full-page warning "
            "and clients that skip validation cannot trust the server's identity.",
            f"notAfter {not_after}; {obs.verify_message or 'expired'}",
            "Renew and deploy a new certificate; automate renewal (for example ACME).",
        )
    elif days is not None and days <= 14:
        add(
            "SS-TLS-002",
            "Certificate expires within 14 days",
            Severity.MEDIUM,
            "The certificate will expire very soon and the service will break for users "
            "if it is not renewed.",
            f"expires in {days} day(s) on {not_after}",
            "Renew the certificate now and automate renewal.",
        )
    elif days is not None and days <= 30:
        add(
            "SS-TLS-003",
            "Certificate expires within 30 days",
            Severity.LOW,
            "The certificate is approaching expiry.",
            f"expires in {days} day(s) on {not_after}",
            "Schedule renewal and confirm automatic renewal works.",
        )

    if obs.verify_code in _VERIFY_HOSTNAME:
        add(
            "SS-TLS-004",
            "Certificate hostname mismatch",
            Severity.HIGH,
            "The certificate is not valid for the name used to connect, so clients cannot "
            "be sure they reached the right server.",
            f"{obs.verify_message}; connected as {obs.server_name or 'IP address'}; "
            f"certificate names: {', '.join(obs.cert.san) if obs.cert else 'unavailable'}",
            "Issue a certificate that lists this hostname in its Subject Alternative Names.",
        )
    elif not obs.verified and obs.verify_code != _VERIFY_EXPIRED:
        add(
            "SS-TLS-005",
            "Certificate not trusted",
            Severity.MEDIUM,
            "The certificate chain could not be verified (self-signed or unknown issuer). "
            "This is expected for lab certificates but not on a public service.",
            obs.verify_message or "verification failed",
            "Use a certificate from a trusted CA, or pass --cafile for your private CA.",
        )

    if obs.version in _LEGACY_TLS:
        add(
            "SS-TLS-006",
            f"Deprecated protocol negotiated ({obs.version})",
            Severity.HIGH,
            "TLS 1.0 and 1.1 are deprecated (RFC 8996) and have known weaknesses.",
            f"negotiated {obs.version} with cipher {obs.cipher}",
            "Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.",
        )
    elif obs.version in ("TLSv1.2", "TLSv1.3"):
        add(
            "SS-TLS-007",
            f"Negotiated {obs.version}",
            Severity.INFO,
            "Observation only: this is the protocol a modern client negotiated.",
            f"negotiated {obs.version} with cipher {obs.cipher}",
            "No action needed. Prefer TLS 1.3 where possible.",
        )
    return findings
