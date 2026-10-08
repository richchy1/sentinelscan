"""HTTP observation (observes only, judges nothing).

Uses ``http.client`` so every ``Set-Cookie`` header is seen separately and redirects
are never followed automatically. Certificates are NOT verified here; certificate
problems are the TLS stage's job.
"""

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from sentinelscan import __version__
from sentinelscan.sanitize import sanitize

MAX_BODY = 64 * 1024
USER_AGENT = f"SentinelScan/{__version__}"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True, slots=True)
class Cookie:
    """A cookie's name and flags. The value is never kept."""

    name: str
    secure: bool
    http_only: bool
    same_site: str | None


@dataclass(frozen=True, slots=True)
class HttpObservation:
    url: str
    scheme: str
    port: int
    status: int | None = None
    reason: str | None = None
    headers: tuple[tuple[str, str], ...] = ()
    redirect_location: str | None = None
    redirect_same_host: bool | None = None
    error: str | None = None

    def header_values(self, name: str) -> list[str]:
        """All values of a header (names are case-insensitive)."""
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    def header(self, name: str) -> str | None:
        values = self.header_values(name)
        return values[0] if values else None

    @property
    def cookies(self) -> tuple[Cookie, ...]:
        return tuple(parse_set_cookie(v) for v in self.header_values("Set-Cookie"))

    @property
    def is_redirect(self) -> bool:
        return self.status in REDIRECT_STATUSES

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "scheme": self.scheme,
            "port": self.port,
            "status": self.status,
            "reason": self.reason,
            "headers": [[k, v] for k, v in self.headers],
            "cookies": [
                {
                    "name": c.name,
                    "secure": c.secure,
                    "http_only": c.http_only,
                    "same_site": c.same_site,
                }
                for c in self.cookies
            ],
            "redirect_location": self.redirect_location,
            "redirect_same_host": self.redirect_same_host,
            "error": self.error,
        }


def parse_set_cookie(value: str) -> Cookie:
    """Parse one Set-Cookie header value into name and flags."""
    first, *attributes = [part.strip() for part in value.split(";")]
    name = first.partition("=")[0].strip()
    flags = {a.partition("=")[0].strip().lower(): a.partition("=")[2].strip() for a in attributes}
    return Cookie(
        name=name,
        secure="secure" in flags,
        http_only="httponly" in flags,
        same_site=flags.get("samesite"),
    )


def redact_cookie(value: str) -> str:
    """Replace a cookie's value with <redacted>, keeping the name and attributes."""
    first, sep, rest = value.partition(";")
    name = first.partition("=")[0].strip()
    return f"{name}=<redacted>{sep}{rest}"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def resolve_redirect(base_url: str, location: str, host: str) -> tuple[str, bool]:
    """Absolute redirect URL and whether it stays on the original host."""
    absolute = urljoin(base_url, location)
    parts = urlsplit(absolute)
    same = parts.scheme in ("http", "https") and (parts.hostname or "").lower() == host.lower()
    return absolute, same


def _open(
    address: str, port: int, scheme: str, host: str, timeout: float
) -> http.client.HTTPConnection:
    raw = socket.create_connection((address, port), timeout=timeout)
    sock: socket.socket = raw
    if scheme == "https":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            sock = context.wrap_socket(raw, server_hostname=None if _is_ip(host) else host)
        except OSError:
            raw.close()
            raise
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.sock = sock
    return conn


def _request_once(
    address: str, port: int, scheme: str, host: str, path: str, timeout: float
) -> HttpObservation:
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    url = f"{scheme}://{netloc}{path}"
    try:
        conn = _open(address, port, scheme, host, timeout)
    except OSError as exc:
        return HttpObservation(url, scheme, port, error=sanitize(f"{type(exc).__name__}: {exc}"))
    try:
        conn.request(
            "GET",
            path,
            headers={"Host": netloc, "User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        response = conn.getresponse()
        headers = tuple(
            (sanitize(k), redact_cookie(v) if k.lower() == "set-cookie" else sanitize(v))
            for k, v in response.getheaders()
        )
        status, reason = response.status, sanitize(response.reason or "")
        try:
            response.read(MAX_BODY)
        except (OSError, http.client.HTTPException):
            pass  # headers are what we need; a truncated body is fine
    except (OSError, http.client.HTTPException) as exc:
        message = f"not a valid HTTP response ({type(exc).__name__}: {exc})"
        return HttpObservation(url, scheme, port, error=sanitize(message))
    finally:
        conn.close()

    location = next((v for k, v in headers if k.lower() == "location"), None)
    redirect_url: str | None = None
    same_host: bool | None = None
    if status in REDIRECT_STATUSES and location:
        redirect_url, same_host = resolve_redirect(url, location, host)
    return HttpObservation(
        url=url,
        scheme=scheme,
        port=port,
        status=status,
        reason=reason,
        headers=headers,
        redirect_location=redirect_url,
        redirect_same_host=same_host,
    )


def fetch(
    address: str,
    port: int,
    *,
    use_tls: bool,
    host: str,
    timeout: float = 3.0,
    follow_redirects: bool = False,
    max_redirects: int = 5,
) -> tuple[HttpObservation, ...]:
    """GET / and (optionally) follow same-host redirects. Returns every hop in order."""
    scheme = "https" if use_tls else "http"
    path = "/"
    hops: list[HttpObservation] = []
    for _ in range(max_redirects + 1):
        observation = _request_once(address, port, scheme, host, path, timeout)
        hops.append(observation)
        if (
            not follow_redirects
            or observation.redirect_location is None
            or observation.redirect_same_host is not True
        ):
            break
        target = urlsplit(observation.redirect_location)
        scheme = target.scheme
        port = target.port or (443 if scheme == "https" else 80)
        path = (target.path or "/") + (f"?{target.query}" if target.query else "")
    return tuple(hops)
