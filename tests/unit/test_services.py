import pytest
from servers import HttpFixture, banner_server, silent_server

from sentinelscan.models import Confidence
from sentinelscan.sanitize import sanitize
from sentinelscan.services import _classify_banner, identify_service, port_hint

T = 0.4


def test_ssh_banner_is_confirmed() -> None:
    with banner_server(b"SSH-2.0-OpenSSH_9.6\r\n") as srv:
        result = identify_service("127.0.0.1", srv.port, timeout=T)
    assert result.name == "ssh"
    assert result.confidence is Confidence.CONFIRMED
    assert "OpenSSH_9.6" in result.evidence


def test_http_server_is_confirmed_and_server_header_captured() -> None:
    with HttpFixture(headers=(("Server", "AirTunes/860.7.1"),), status=403) as srv:
        result = identify_service("127.0.0.1", srv.port, timeout=1.0)
    assert result.name == "http"
    assert result.confidence is Confidence.CONFIRMED
    assert result.is_http and not result.is_tls
    assert "AirTunes" in result.evidence
    assert result.name != "upnp"


def test_silent_socket_on_unhinted_port_is_unknown() -> None:
    with silent_server() as srv:
        result = identify_service("127.0.0.1", srv.port, timeout=T)
    assert result.name is None
    assert result.confidence is Confidence.UNKNOWN


def test_unrecognised_banner_is_unknown_with_evidence() -> None:
    with banner_server(b"hello there\r\n") as srv:
        result = identify_service("127.0.0.1", srv.port, timeout=T)
    assert result.confidence is Confidence.UNKNOWN
    assert result.name is None
    assert result.evidence == "hello there"


@pytest.mark.parametrize(
    ("banner", "name"),
    [
        (b"220 mail.example ESMTP Postfix\r\n", "smtp"),
        (b"220 (vsFTPd 3.0.5) FTP ready\r\n", "ftp"),
        (b"+OK POP3 ready\r\n", "pop3"),
        (b"* OK IMAP4rev1 ready\r\n", "imap"),
        (b"RFB 003.008\n", "vnc"),
    ],
)
def test_banner_classification(banner: bytes, name: str) -> None:
    result = _classify_banner(1234, banner)
    assert result is not None
    assert result.name == name
    assert result.confidence is Confidence.CONFIRMED


def test_ambiguous_220_is_not_guessed() -> None:
    assert _classify_banner(1234, b"220 something\r\n") is None


def test_mysql_greeting_is_only_probable() -> None:
    greeting = b"\x4a\x00\x00\x00\x0a8.0.36\x00" + b"\x00" * 20
    result = _classify_banner(3306, greeting)
    assert result is not None
    assert result.name == "mysql"
    assert result.confidence is Confidence.PROBABLE
    assert result.guess_basis


def test_port_5000_is_never_labelled_from_the_port_number() -> None:
    assert port_hint(5000) is None


def test_port_hint_is_available_for_database_ports() -> None:
    assert port_hint(5432) == "postgresql"


def test_connection_failure_is_unknown() -> None:
    result = identify_service("127.0.0.1", 1, timeout=0.3)
    assert result.confidence is Confidence.UNKNOWN
    assert result.evidence == "could not connect"


def test_sanitize_strips_control_characters_and_truncates() -> None:
    assert sanitize(b"a\x00b\x1b[31mc\r\nd") == "a b [31mc d"
    assert len(sanitize("x" * 2000)) == 500
