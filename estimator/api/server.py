"""The Estimator Web App's HTTP host.

A small threaded HTTP server that AI-Prowler starts in its own process (one
daemon thread per connection). It only moves bytes: requests go to
router.route(); /estimator-api/events is streamed here as server-sent events.

    from estimator.api import server
    server.start()                 # http://127.0.0.1:8770/estimator/
    server.url(); server.stop()

Run on its own for development or a quick look:
    python -m estimator.api.server [--port 8770] [--network]

Where it listens (design spec "Hosting and access"):
- Personal mode: 127.0.0.1 only, unless office-network access is turned on
  (ESTIMATOR_WEB_NETWORK=1 or --network) - then all addresses, login required
  for anyone not on this PC.
- Server mode: all addresses; everyone signs in.
Port: ESTIMATOR_WEB_PORT, default 8770 (AI-Prowler itself uses 8000).
"""
from __future__ import annotations

import argparse
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from estimator.api import auth, live, router

log = logging.getLogger("estimator.api.server")

DEFAULT_PORT = 8770
SSE_POLL_SECONDS = 1.0
SSE_PING_SECONDS = 15.0
SSE_MAX_SECONDS = 30 * 60          # the browser reconnects by itself (with Last-Event-ID)
MAX_REQUEST_BYTES = 2 * 1024 * 1024

_server: ThreadingHTTPServer | None = None
_thread: threading.Thread | None = None
_lock = threading.Lock()


def default_port() -> int:
    try:
        return int(os.environ.get("ESTIMATOR_WEB_PORT", "") or DEFAULT_PORT)
    except ValueError:
        return DEFAULT_PORT


def default_bind() -> str:
    if auth.mode() == "server" or os.environ.get("ESTIMATOR_WEB_NETWORK", "").strip() in ("1", "true", "yes", "on"):
        return "0.0.0.0"
    return "127.0.0.1"


class _Handler(BaseHTTPRequestHandler):
    server_version = "AI-Prowler-Estimator"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    open_db = None                 # tests can point this at their own database opener

    def log_message(self, fmt, *args):  # keep request lines out of stderr
        log.debug("%s - %s", self.address_string(), fmt % args)

    def _headers_dict(self) -> dict:
        return {k: v for k, v in self.headers.items()}

    def _handle(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0:
            self.close_connection = True
            self._send(router._fail(400, "invalid_input", "bad Content-Length"))
            return
        if router.is_upload(self.command, self.path):
            # Plan files (up to 300 MB) are streamed to disk by the router after the login, role and size
            # checks, never read into memory here. A refused upload leaves its body unread, so the
            # connection is closed afterwards instead of being reused.
            self.close_connection = True
            req = router.Request(self.command, self.path, self._headers_dict(), b"", self.client_address[0],
                                 stream=self.rfile, length=length)
            self._send(router.route(req, self.open_db))
            return
        if length > MAX_REQUEST_BYTES:
            self.close_connection = True
            self._send(router._fail(413, "too_large", "the request is too large"))
            return
        body = self.rfile.read(length) if length else b""
        req = router.Request(self.command, self.path, self._headers_dict(), body, self.client_address[0])
        if req.path == router.API + "/events" and req.method == "GET":
            self._stream_events(req)
            return
        self._send(router.route(req, self.open_db))

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

    def _send(self, resp: router.Response):
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.content_type)
        self.send_header("Content-Length", str(len(resp.body)))
        for k, v in resp.headers.items():
            self.send_header(k, v)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(resp.body)

    def _stream_events(self, req: router.Request):
        caller = auth.resolve(req.headers, req.client_ip)
        if caller is None:
            self._send(router._fail(401, "login_required", "sign in to use the Estimator"))
            return
        opener = self.open_db or router._open_db
        conn = opener()
        try:
            last = req.headers.get("Last-Event-ID") or req.headers.get("last-event-id") or req.query.get("since")
            cursor = live.parse_cursor(last)
            if cursor is None:
                cursor = live.latest_cursor(conn, caller.ctx)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(b"retry: 3000\n" + live.sse_comment(f"cursor {cursor}"))
            self.wfile.flush()
            start = last_ping = time.monotonic()
            while not getattr(self.server, "stopping", False):
                batch = live.updates(conn, caller.ctx, cursor)
                for ev in batch["events"]:
                    self.wfile.write(live.sse_message(ev))
                if batch["events"]:
                    cursor = batch["cursor"]
                    self.wfile.flush()
                now = time.monotonic()
                if now - last_ping >= SSE_PING_SECONDS:
                    self.wfile.write(live.sse_comment())
                    self.wfile.flush()
                    last_ping = now
                if now - start >= SSE_MAX_SECONDS:
                    break
                if not batch["more"]:
                    time.sleep(SSE_POLL_SECONDS)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass                                  # the browser went away
        finally:
            conn.close()


class EstimatorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False               # never share the port with another program on Windows
    stopping = False


def start(port: int | None = None, host: str | None = None) -> str:
    """Start the web app in a background thread (idempotent). Returns its local URL."""
    global _server, _thread
    with _lock:
        if _server is not None:
            return url()
        srv = EstimatorHTTPServer((host or default_bind(), default_port() if port is None else port), _Handler)
        _server = srv
        _thread = threading.Thread(target=srv.serve_forever, name="estimator-web", daemon=True)
        _thread.start()
        log.info("Estimator web app at %s", url())
        return url()


def stop() -> None:
    global _server, _thread
    with _lock:
        srv, _server = _server, None
        th, _thread = _thread, None
    if srv is not None:
        srv.stopping = True
        srv.shutdown()
        srv.server_close()
    if th is not None:
        th.join(timeout=5)


def running() -> bool:
    return _server is not None


def port() -> int | None:
    return _server.server_address[1] if _server else None


def url() -> str:
    p = port()
    return f"http://localhost:{p}{router.APP}/" if p else ""


def start_with_ai_prowler() -> str:
    """Called from ai_prowler_mcp.py. Never raises: the Estimator must not stop AI-Prowler starting.
    ESTIMATOR_WEB=off turns the web app off; a busy port is logged, not fatal."""
    if os.environ.get("ESTIMATOR_WEB", "").strip().lower() in ("off", "0", "false", "no"):
        return ""
    try:
        return start()
    except OSError as e:
        log.warning("Estimator web app not started (port %s busy?): %s", default_port(), e)
    except Exception as e:  # noqa: BLE001
        log.warning("Estimator web app not started: %s", e)
    return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the AI-Prowler Estimator web app on its own.")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--network", action="store_true", help="listen on the office network (login required off this PC)")
    ap.add_argument("--server-mode", action="store_true", help="Server mode: everyone signs in")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    if a.server_mode:
        auth.configure(mode="server")
    u = start(a.port, "0.0.0.0" if (a.network or a.server_mode) else None)
    print(f"Estimator web app: {u}   (Ctrl+C to stop)", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
