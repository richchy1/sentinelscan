"""Tiny localhost servers used as test fixtures. Nothing here touches the internet."""

import http.server
import socket
import socketserver
import ssl
import threading
from collections.abc import Callable
from pathlib import Path
from types import TracebackType


class TcpServer:
    """Accepts connections on 127.0.0.1 and hands each one to ``handler`` in a thread."""

    def __init__(self, handler: Callable[[socket.socket], None]) -> None:
        self._handler = handler
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port: int = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._conns: list[socket.socket] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self._conns.append(conn)
            threading.Thread(target=self._run, args=(conn,), daemon=True).start()

    def _run(self, conn: socket.socket) -> None:
        try:
            self._handler(conn)
        except (OSError, ssl.SSLError):
            pass

    def __enter__(self) -> "TcpServer":
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._sock.close()
        for conn in self._conns:
            try:
                conn.close()
            except OSError:
                pass


def banner_server(banner: bytes) -> TcpServer:
    """Sends ``banner`` first, then closes (like SSH/SMTP)."""

    def handler(conn: socket.socket) -> None:
        conn.sendall(banner)
        conn.close()

    return TcpServer(handler)


def silent_server() -> TcpServer:
    """Accepts and then says nothing, ignoring everything it receives."""

    def handler(conn: socket.socket) -> None:
        conn.settimeout(5)
        try:
            while conn.recv(1024):
                pass
        except OSError:
            pass

    return TcpServer(handler)


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    response_headers: tuple[tuple[str, str], ...] = ()
    status: int = 200
    server_version = ""
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        return

    def _respond(self) -> None:
        body = b"ok"
        # send_response_only: no automatic Server/Date headers, so tests control every header.
        self.send_response_only(self.status)
        for name, value in self.response_headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        self._respond()

    def do_HEAD(self) -> None:
        self._respond()


class _FastHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def handle_error(self, request: object, client_address: object) -> None:
        # Scanners close connections abruptly; that is expected here, not worth a traceback.
        return

    def server_bind(self) -> None:
        # HTTPServer.server_bind calls socket.getfqdn(), a slow reverse-DNS lookup on some
        # networks. Skip it: tests only need the bound socket.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]


class HttpFixture:
    """A real ``http.server`` on 127.0.0.1 (optionally with TLS) with fixed response headers."""

    def __init__(
        self,
        headers: tuple[tuple[str, str], ...] = (),
        status: int = 200,
        context: ssl.SSLContext | None = None,
    ) -> None:
        handler = type("H", (_Handler,), {"response_headers": headers, "status": status})
        self._server = _FastHTTPServer(("127.0.0.1", 0), handler)
        if context is not None:
            self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "HttpFixture":
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._server.shutdown()
        self._server.server_close()


INSECURE_HEADERS: tuple[tuple[str, str], ...] = (
    ("Server", "Apache/2.4.49 (Unix)"),
    ("X-Powered-By", "PHP/8.1.0"),
    ("Set-Cookie", "sessionid=abc123; Path=/"),
    ("Set-Cookie", "theme=dark; SameSite=None"),
)

SECURE_HEADERS: tuple[tuple[str, str], ...] = (
    ("Server", "nginx"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Set-Cookie", "sid=xyz; Path=/; Secure; HttpOnly; SameSite=Strict"),
)


def tls_context(cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    return context


def tls_server(cert: Path, key: Path) -> TcpServer:
    """Completes a TLS handshake, then closes."""
    context = tls_context(cert, key)

    def handler(conn: socket.socket) -> None:
        with context.wrap_socket(conn, server_side=True):
            pass

    return TcpServer(handler)
