import pytest

from sentinelscan.checks import check_http, check_network
from sentinelscan.http import HttpObservation, parse_set_cookie, redact_cookie, resolve_redirect
from sentinelscan.models import Confidence, ServiceResult, Severity

SECURE = (
    ("Strict-Transport-Security", "max-age=31536000"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
)


def obs(
    headers: tuple[tuple[str, str], ...] = (),
    *,
    scheme: str = "https",
    status: int = 200,
    port: int = 443,
    **kwargs: object,
) -> HttpObservation:
    return HttpObservation(
        url=f"{scheme}://t:{port}/", scheme=scheme, port=port, status=status, headers=headers,
        **kwargs,  # type: ignore[arg-type]
    )


def ids(findings: list) -> set[str]:  # type: ignore[type-arg]
    return {f.id for f in findings}


def run(o: HttpObservation, https_available: bool = True) -> set[str]:
    return ids(check_http([o], target="t", port=o.port, https_available=https_available))


def test_fully_secure_response_has_no_findings() -> None:
    assert run(obs(SECURE)) == set()


def test_header_names_are_case_insensitive() -> None:
    lower = tuple((k.lower(), v) for k, v in SECURE)
    assert run(obs(lower)) == set()


def test_all_missing_headers_on_https() -> None:
    assert run(obs()) == {"SS-HTTP-002", "SS-HTTP-004", "SS-HTTP-006", "SS-HTTP-007", "SS-HTTP-008"}


def test_hsts_is_ignored_on_plain_http() -> None:
    found = run(obs(scheme="http", port=80), https_available=False)
    assert "SS-HTTP-002" not in found
    assert "SS-HTTP-003" not in found


@pytest.mark.parametrize(
    ("value", "weak"),
    [("max-age=100", True), ("max-age=15552000", False), ("includeSubDomains", True)],
)
def test_hsts_strength(value: str, weak: bool) -> None:
    headers = tuple(h for h in SECURE if h[0] != "Strict-Transport-Security")
    found = run(obs(headers + (("Strict-Transport-Security", value),)))
    assert ("SS-HTTP-003" in found) is weak


def test_weak_csp_flagged() -> None:
    headers = tuple(h for h in SECURE if h[0] != "Content-Security-Policy")
    csp = ("Content-Security-Policy", "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
    assert "SS-HTTP-005" in run(obs(headers + (csp,)))


def test_x_frame_options_satisfies_clickjacking_rule() -> None:
    headers = (
        ("Content-Security-Policy", "default-src 'self'"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Strict-Transport-Security", "max-age=31536000"),
    )
    assert "SS-HTTP-007" not in run(obs(headers))


def test_nosniff_wrong_value_flagged() -> None:
    headers = tuple(h for h in SECURE if h[0] != "X-Content-Type-Options")
    assert "SS-HTTP-006" in run(obs(headers + (("X-Content-Type-Options", "sniff"),)))


def test_multiple_cookies_are_checked_individually() -> None:
    headers = SECURE + (
        ("Set-Cookie", "a=<redacted>; Secure; HttpOnly; SameSite=Lax"),
        ("Set-Cookie", "b=<redacted>; Path=/"),
    )
    findings = check_http([obs(headers)], target="t", port=443, https_available=True)
    by_id = {f.id: f for f in findings}
    assert {"SS-HTTP-009", "SS-HTTP-010", "SS-HTTP-011"} <= by_id.keys()
    assert "b" in by_id["SS-HTTP-009"].evidence
    assert "a" not in by_id["SS-HTTP-009"].evidence.replace("cookies:", "")


def test_samesite_none_without_secure_flagged() -> None:
    headers = SECURE + (("Set-Cookie", "c=<redacted>; HttpOnly; SameSite=None"),)
    assert "SS-HTTP-011" in run(obs(headers))


def test_secure_flag_not_required_on_plain_http() -> None:
    headers = (("Set-Cookie", "c=<redacted>; HttpOnly; SameSite=Lax"),)
    assert "SS-HTTP-009" not in run(obs(headers, scheme="http", port=80), https_available=False)


@pytest.mark.parametrize(
    ("value", "disclosed"),
    [("Apache/2.4.49 (Unix)", True), ("nginx", False), ("nginx/1.25.3", True), ("Express", False)],
)
def test_server_version_disclosure(value: str, disclosed: bool) -> None:
    found = run(obs(SECURE + (("Server", value),)))
    assert ("SS-HTTP-012" in found) is disclosed


def test_x_powered_by_disclosure() -> None:
    assert "SS-HTTP-012" in run(obs(SECURE + (("X-Powered-By", "PHP/8.1.0"),)))


def test_http_without_redirect_flagged_when_https_exists() -> None:
    plain = obs(scheme="http", port=80)
    assert "SS-HTTP-001" in run(plain, https_available=True)
    assert "SS-HTTP-001" not in run(plain, https_available=False)


def test_redirect_to_https_is_fine() -> None:
    redirect = obs(
        scheme="http", port=80, status=301,
        redirect_location="https://t/", redirect_same_host=True,
    )
    assert "SS-HTTP-001" not in run(redirect)


def test_redirect_to_other_host_is_informational() -> None:
    redirect = obs(
        scheme="http", port=80, status=302,
        redirect_location="https://elsewhere.example/", redirect_same_host=False,
    )
    assert "SS-HTTP-013" in run(redirect)


def test_failed_request_gives_info_finding() -> None:
    failed = HttpObservation("http://t/", "http", 80, error="not a valid HTTP response")
    findings = check_http([failed], target="t", port=80, https_available=False)
    assert [f.id for f in findings] == ["SS-HTTP-014"]
    assert findings[0].severity is Severity.INFO


def test_every_finding_has_description_evidence_and_remediation() -> None:
    worst = obs(
        (("Server", "Apache/2.4.49"), ("Set-Cookie", "s=<redacted>")),
    )
    plain = obs(scheme="http", port=80)
    findings = check_http([worst], target="t", port=443, https_available=True)
    findings += check_http([plain], target="t", port=80, https_available=True)
    findings += check_network(80, ServiceResult(80, "http", Confidence.CONFIRMED), "t")
    assert findings
    for f in findings:
        assert f.description and f.evidence and f.remediation and f.title


def test_checks_are_deterministic() -> None:
    o = obs((("Server", "Apache/2.4.49"),))
    a = check_http([o], target="t", port=443, https_available=True)
    b = check_http([o], target="t", port=443, https_available=True)
    assert a == b


def test_parse_set_cookie_flags() -> None:
    c = parse_set_cookie("id=abc; Path=/; Secure; HttpOnly; SameSite=Strict")
    assert (c.name, c.secure, c.http_only, c.same_site) == ("id", True, True, "Strict")
    bare = parse_set_cookie("x=1")
    assert (bare.secure, bare.http_only, bare.same_site) == (False, False, None)


def test_cookie_values_are_redacted() -> None:
    assert redact_cookie("sid=SECRETVALUE; Path=/; Secure") == "sid=<redacted>; Path=/; Secure"


@pytest.mark.parametrize(
    ("location", "same"),
    [
        ("/login", True),
        ("https://t/x", True),
        ("https://T:8443/x", True),
        ("https://evil.example/", False),
        ("ftp://t/", False),
    ],
)
def test_resolve_redirect_same_host(location: str, same: bool) -> None:
    assert resolve_redirect("http://t/", location, "t")[1] is same
