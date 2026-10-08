"""An intentionally insecure web server for trying SentinelScan on your own machine.

It binds to 127.0.0.1 only, so nothing outside your computer can reach it.
It sends no security headers, sets weak cookies and discloses a software version.

    python examples/demo_server.py          # listens on 127.0.0.1:8080
    python examples/demo_server.py 9000     # or pick a port
"""

import socketserver
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class InsecureHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"  # deliberately discloses a version
    sys_version = ""

    def do_HEAD(self) -> None:
        self._respond(send_body=False)

    def do_GET(self) -> None:
        self._respond(send_body=True)

    def _respond(self, *, send_body: bool) -> None:
        body = b"SentinelScan demo server (intentionally insecure)\n"
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/8.1.0")
        self.send_header("Set-Cookie", "sessionid=demo; Path=/")
        self.send_header("Set-Cookie", "theme=dark; SameSite=None")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write(f"demo-server: {format % args}\n")


class FastServer(HTTPServer):
    def server_bind(self) -> None:
        # HTTPServer.server_bind calls socket.getfqdn(), a reverse-DNS lookup that can take
        # many seconds on some networks. This server only needs the bound socket.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = FastServer(("127.0.0.1", port), InsecureHandler)
    print(f"Demo server on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
