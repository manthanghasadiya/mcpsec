"""Out-of-band (OOB) HTTP Collector for SSRF confirmation."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import threading
import time
from typing import Any


class _OOBHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for capturing out-of-band SSRF interactions."""

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default stderr request logging
        pass

    def _record_and_respond(self) -> None:
        raw_path = self.path.lstrip("/")
        token = raw_path.split("?")[0].split("/")[0]
        hit = {
            "token": token,
            "source_ip": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "timestamp": time.time(),
            "headers": dict(self.headers),
        }
        if hasattr(self.server, "collector"):
            self.server.collector._record_hit(token, hit)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b"OK")

    def do_GET(self) -> None:
        self._record_and_respond()

    def do_POST(self) -> None:
        self._record_and_respond()

    def do_HEAD(self) -> None:
        self._record_and_respond()

    def do_PUT(self) -> None:
        self._record_and_respond()

    def do_DELETE(self) -> None:
        self._record_and_respond()

    def do_OPTIONS(self) -> None:
        self._record_and_respond()

    def do_PATCH(self) -> None:
        self._record_and_respond()


class OOBCollector:
    """Built-in HTTP out-of-band interaction collector for SSRF detection."""

    def __init__(
        self,
        bind_host: str = "127.0.0.1",
        port: int = 0,
        advertise_host: str | None = None,
    ) -> None:
        if advertise_host and advertise_host not in ("127.0.0.1", "localhost"):
            self.bind_host = "0.0.0.0"
            self.advertise_host = advertise_host
        else:
            self.bind_host = bind_host
            self.advertise_host = advertise_host or bind_host

        self.port = port
        self.server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._hits: dict[str, dict[str, Any]] = {}

    def _record_hit(self, token: str, hit: dict[str, Any]) -> None:
        with self._lock:
            self._hits[token] = hit

    def start(self) -> None:
        """Start the background HTTP server."""
        if self.server is not None:
            return
        self.server = ThreadingHTTPServer(
            (self.bind_host, self.port), _OOBHTTPRequestHandler
        )
        self.server.daemon_threads = True
        self.server.collector = self  # type: ignore[attr-defined]
        self.port = self.server.server_port
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Shut down the background HTTP server cleanly."""
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def new_probe(self) -> tuple[str, str]:
        """Mint a new unique token and corresponding OOB URL.

        Returns:
            (token, url)
        """
        if self.server is None:
            self.start()
        token = secrets.token_hex(8)
        url = f"http://{self.advertise_host}:{self.port}/{token}"
        return token, url

    def received(self, token: str, settle: float = 2.0) -> dict[str, Any] | None:
        """Return the recorded hit for the token, polling up to settle seconds.

        Args:
            token: The probe token to check for.
            settle: Seconds to wait for inbound hit.

        Returns:
            Hit dict or None if not received within settle window.
        """
        deadline = time.monotonic() + settle
        while True:
            with self._lock:
                if token in self._hits:
                    return self._hits[token]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.05, remaining))
        return None

    def __enter__(self) -> OOBCollector:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
