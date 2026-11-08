"""The Estimator web app inside AI-Prowler's own server on port 8000 (Coder 2, Sprint 3).

AI-Prowler's port-8000 server (uvicorn, ASGI) is what Remote Access (the Cloudflare tunnel) and the Jobs app
reach. Its routers call handle() for /estimator, /estimator/... and /estimator-api/..., the same way they
call the Service Desk for /desk. Everything goes through router.route(), so the rules (sign-in, same-PC,
CSRF header, roles, hidden margins) are exactly the same as on the Estimator's own port 8770:

- Through the tunnel a request carries Cloudflare headers, so it is never "same PC": the person signs in, or
  uses the Jobs app's own token (auth.set_app_token_resolver, plugged in by AI-Prowler).
- Plan uploads are streamed from the ASGI receive channel to disk in a worker thread (up to 300 MB).
- /estimator-api/events (live updates) is streamed here as server-sent events.
- router.route() runs in a worker thread, never on the event loop (SQLite and file work would stall uvicorn).
"""
from __future__ import annotations

import asyncio
import logging
import time

from estimator.api import auth, live, router, server

log = logging.getLogger("estimator.api.asgi_bridge")

RECEIVE_TIMEOUT_SECONDS = 120


def is_path(path: str) -> bool:
    return path == router.APP or path.startswith(router.APP + "/") or path == router.API or \
        path.startswith(router.API + "/")


def turned_on() -> bool:
    """The Estimator's switch (Setup AI-Prowler). No entry means on, like AI-Prowler's other features."""
    try:
        from estimator.ui.model import is_on
        return bool(is_on())
    except Exception:  # noqa: BLE001 - if the switch can't be read, behave like AI-Prowler: on
        return True


def _headers(scope) -> dict:
    out: dict[str, str] = {}
    for k, v in scope.get("headers", []):
        name = k.decode("latin-1")
        value = v.decode("latin-1")
        # Repeated headers (rare) are joined; cookies with "; " as browsers do.
        if name in out:
            out[name] = out[name] + ("; " if name.lower() == "cookie" else ", ") + value
        else:
            out[name] = value
    return out


def _request(scope, body: bytes = b"", stream=None, length: int = 0) -> router.Request:
    headers = _headers(scope)
    qs = scope.get("query_string", b"").decode("latin-1")
    path = scope.get("path", "") + ("?" + qs if qs else "")
    client = scope.get("client") or ("", 0)
    proto = auth._h(headers, "x-forwarded-proto").lower()
    secure = scope.get("scheme") == "https" or proto == "https"
    return router.Request(scope.get("method", "GET"), path, headers, body, str(client[0] or ""), secure,
                          stream=stream, length=length)


async def _send(send, resp: router.Response) -> None:
    hdrs = [[b"content-type", resp.content_type.encode("latin-1")],
            [b"content-length", str(len(resp.body)).encode()]]
    hdrs += [[k.lower().encode("latin-1"), str(v).encode("latin-1")] for k, v in resp.headers.items()]
    await send({"type": "http.response.start", "status": resp.status, "headers": hdrs})
    await send({"type": "http.response.body", "body": resp.body, "more_body": False})


class ReceiveReader:
    """A blocking .read(n) over an ASGI receive channel, for router code running in a worker thread."""

    def __init__(self, receive, loop: asyncio.AbstractEventLoop):
        self._receive, self._loop = receive, loop
        self._buf = bytearray()
        self._done = False

    def read(self, n: int = -1) -> bytes:
        while not self._done and (n < 0 or len(self._buf) < n):
            fut = asyncio.run_coroutine_threadsafe(self._receive(), self._loop)
            msg = fut.result(timeout=RECEIVE_TIMEOUT_SECONDS)
            if msg.get("type") == "http.disconnect":
                self._done = True
                break
            self._buf += msg.get("body", b"") or b""
            if not msg.get("more_body", False):
                self._done = True
        if n < 0:
            n = len(self._buf)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


async def _read_all(receive, limit: int) -> bytes | None:
    """The whole body, or None when it is over `limit` (the rest is left unread)."""
    chunks, size = [], 0
    while True:
        msg = await receive()
        if msg.get("type") == "http.disconnect":
            break
        part = msg.get("body", b"") or b""
        size += len(part)
        if size > limit:
            return None
        chunks.append(part)
        if not msg.get("more_body", False):
            break
    return b"".join(chunks)


async def handle(scope, receive, send, open_db=None) -> None:
    """Serve one /estimator or /estimator-api request on AI-Prowler's own server."""
    loop = asyncio.get_running_loop()
    path, method = scope.get("path", ""), scope.get("method", "GET").upper()
    if not turned_on():
        if path.startswith(router.API):
            resp = router._fail(404, "estimator_off", "the Estimator is turned off on this AI-Prowler")
        else:
            resp = router.Response(404, "text/plain; charset=utf-8",
                                   b"The Estimator is turned off on this AI-Prowler.", dict(router.SECURITY_HEADERS))
        await _send(send, resp)
        return
    try:
        length = int(auth._h(_headers(scope), "content-length") or 0)
    except ValueError:
        await _send(send, router._fail(400, "invalid_input", "bad Content-Length"))
        return

    if method == "GET" and path == router.API + "/events":
        await _events(scope, receive, send, open_db)
        return

    if router.is_upload(method, path):
        req = _request(scope, stream=ReceiveReader(receive, loop), length=length)
        resp = await loop.run_in_executor(None, lambda: router.route(req, open_db))
        await _send(send, resp)
        return

    body = await _read_all(receive, server.MAX_REQUEST_BYTES)
    if body is None:
        await _send(send, router._fail(413, "too_large", "the request is too large"))
        return
    req = _request(scope, body=body)
    resp = await loop.run_in_executor(None, lambda: router.route(req, open_db))
    await _send(send, resp)


async def _events(scope, receive, send, open_db) -> None:
    """Server-sent events, same messages as server.py's stream (pointers only, the caller's company only)."""
    loop = asyncio.get_running_loop()
    req = _request(scope)
    caller = auth.resolve(req.headers, req.client_ip)
    if caller is None:
        await _send(send, router._fail(401, "login_required", "sign in to use the Estimator"))
        return
    opener = open_db or router._open_db

    def poll(cursor):
        conn = opener()                      # SQLite connections stay on the thread that uses them
        try:
            if cursor is None:
                return {"cursor": live.latest_cursor(conn, caller.ctx), "events": [], "more": False}
            return live.updates(conn, caller.ctx, cursor)
        finally:
            conn.close()

    last = req.headers.get("Last-Event-ID") or auth._h(req.headers, "last-event-id") or req.query.get("since")
    cursor = live.parse_cursor(last)
    if cursor is None:
        cursor = (await loop.run_in_executor(None, poll, None))["cursor"]

    gone = asyncio.Event()

    async def watch_disconnect():
        while True:
            msg = await receive()
            if msg.get("type") == "http.disconnect":
                gone.set()
                return

    watcher = asyncio.ensure_future(watch_disconnect())
    await send({"type": "http.response.start", "status": 200,
                "headers": [[b"content-type", b"text/event-stream; charset=utf-8"], [b"cache-control", b"no-store"],
                            [b"x-accel-buffering", b"no"]]})
    try:
        await send({"type": "http.response.body", "body": b"retry: 3000\n" + live.sse_comment(f"cursor {cursor}"),
                    "more_body": True})
        start = last_ping = time.monotonic()
        while not gone.is_set():
            batch = await loop.run_in_executor(None, poll, cursor)
            if batch["events"]:
                await send({"type": "http.response.body", "more_body": True,
                            "body": b"".join(live.sse_message(e) for e in batch["events"])})
                cursor = batch["cursor"]
            now = time.monotonic()
            if now - last_ping >= server.SSE_PING_SECONDS:
                await send({"type": "http.response.body", "body": live.sse_comment(), "more_body": True})
                last_ping = now
            if now - start >= server.SSE_MAX_SECONDS:
                break
            if not batch["more"]:
                try:
                    await asyncio.wait_for(gone.wait(), timeout=server.SSE_POLL_SECONDS)
                except asyncio.TimeoutError:
                    pass
    except (ConnectionError, OSError, RuntimeError):
        pass                                 # the browser went away mid-write
    finally:
        watcher.cancel()
        if not gone.is_set():
            try:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
            except Exception:  # noqa: BLE001
                pass
