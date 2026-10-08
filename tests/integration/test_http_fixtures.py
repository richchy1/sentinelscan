from servers import INSECURE_HEADERS, SECURE_HEADERS, HttpFixture

from sentinelscan.checks import check_http
from sentinelscan.http import fetch


def finding_ids(port: int, *, https_available: bool = False) -> set[str]:
    hops = fetch("127.0.0.1", port, use_tls=False, host="127.0.0.1", timeout=2.0)
    findings = check_http(hops, target="127.0.0.1", port=port, https_available=https_available)
    return {f.id for f in findings}


def test_insecure_server_produces_expected_findings() -> None:
    with HttpFixture(headers=INSECURE_HEADERS) as srv:
        found = finding_ids(srv.port)
    assert found == {
        "SS-HTTP-004",
        "SS-HTTP-006",
        "SS-HTTP-007",
        "SS-HTTP-008",
        "SS-HTTP-010",
        "SS-HTTP-011",
        "SS-HTTP-012",
    }


def test_secure_headers_on_plain_http_produce_no_findings() -> None:
    headers = tuple(h for h in SECURE_HEADERS if h[0] != "Set-Cookie") + (
        ("Set-Cookie", "sid=xyz; Path=/; Secure; HttpOnly; SameSite=Strict"),
    )
    with HttpFixture(headers=headers) as srv:
        assert finding_ids(srv.port) == set()


def test_all_set_cookie_headers_are_seen_and_values_redacted() -> None:
    with HttpFixture(headers=INSECURE_HEADERS) as srv:
        (hop,) = fetch("127.0.0.1", srv.port, use_tls=False, host="127.0.0.1", timeout=2.0)
    assert [c.name for c in hop.cookies] == ["sessionid", "theme"]
    assert "abc123" not in str(hop.to_dict())


def test_missing_https_redirect_flagged_only_when_https_exists() -> None:
    with HttpFixture() as srv:
        assert "SS-HTTP-001" in finding_ids(srv.port, https_available=True)
        assert "SS-HTTP-001" not in finding_ids(srv.port, https_available=False)


def test_redirect_not_followed_by_default() -> None:
    headers = (("Location", "/next"),)
    with HttpFixture(headers=headers, status=302) as srv:
        hops = fetch("127.0.0.1", srv.port, use_tls=False, host="127.0.0.1", timeout=2.0)
    assert len(hops) == 1
    assert hops[0].status == 302
    assert hops[0].redirect_same_host is True


def test_same_host_redirect_followed_when_enabled_and_bounded() -> None:
    headers = (("Location", "/loop"),)
    with HttpFixture(headers=headers, status=302) as srv:
        hops = fetch(
            "127.0.0.1", srv.port, use_tls=False, host="127.0.0.1", timeout=2.0,
            follow_redirects=True, max_redirects=3,
        )
    assert len(hops) == 4  # first request + 3 redirects, then it stops


def test_off_host_redirect_is_never_followed() -> None:
    headers = (("Location", "http://other.example/"),)
    with HttpFixture(headers=headers, status=301) as srv:
        hops = fetch(
            "127.0.0.1", srv.port, use_tls=False, host="127.0.0.1", timeout=2.0,
            follow_redirects=True,
        )
    assert len(hops) == 1
    assert hops[0].redirect_same_host is False


def test_non_http_response_is_recorded_not_raised() -> None:
    from servers import banner_server

    with banner_server(b"SSH-2.0-OpenSSH_9.6\r\n") as srv:
        (hop,) = fetch("127.0.0.1", srv.port, use_tls=False, host="127.0.0.1", timeout=1.0)
    assert hop.status is None
    assert hop.error is not None
