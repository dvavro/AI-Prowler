"""The real HTTP host: sockets, cookies, the SSE stream, start/stop, and starting with AI-Prowler."""
import http.client
import json
import socket
import threading
import time

import pytest

from estimator.api import auth, live, server


@pytest.fixture
def web(monkeypatch):
    monkeypatch.setattr(server, "SSE_POLL_SECONDS", 0.05)
    monkeypatch.setattr(server, "SSE_PING_SECONDS", 0.2)
    server.stop()
    server.start(port=0, host="127.0.0.1")       # any free port
    yield server.port()
    server.stop()


def _req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": f"localhost:{port}", **(headers or {})}
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        h.setdefault("Content-Type", "application/json")
        h.setdefault("X-Estimator-Request", "1")
    c.request(method, path, data, h)
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read())
    c.close()
    return out


def test_same_pc_round_trip_over_http(web):
    st, h, body = _req(web, "GET", "/estimator-api/me")
    assert st == 200 and json.loads(body)["me"]["role"] == "owner"
    assert h["Cache-Control"] == "no-store" and h["X-Content-Type-Options"] == "nosniff"
    st, _, body = _req(web, "POST", "/estimator-api/estimates", {"title": "Over HTTP"})
    assert st == 201 and json.loads(body)["title"] == "Over HTTP"
    st, h, body = _req(web, "GET", "/estimator/")
    assert st == 200 and b"AI-Prowler Estimator" in body


def test_login_cookie_round_trip(web, monkeypatch):
    auth.configure(mode="server", verifier=lambda u, p: {"user_id": u, "role": "estimator"} if p == "pw" else None)
    assert _req(web, "GET", "/estimator-api/me")[0] == 401
    st, h, _ = _req(web, "POST", "/estimator-api/auth/login", {"username": "maria", "password": "pw"})
    cookie = h["Set-Cookie"].split(";")[0]
    st, _, body = _req(web, "GET", "/estimator-api/me", headers={"Cookie": cookie})
    assert st == 200 and json.loads(body)["me"]["user_id"] == "maria"


def test_oversized_request_refused(web):
    c = http.client.HTTPConnection("127.0.0.1", web, timeout=10)
    c.putrequest("POST", "/estimator-api/estimates")
    c.putheader("Host", "localhost")
    c.putheader("Content-Length", str(server.MAX_REQUEST_BYTES + 1))
    c.endheaders()
    assert c.getresponse().status == 413
    c.close()


def _open_stream(port, headers=None):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
    s.sendall(f"GET /estimator-api/events HTTP/1.1\r\nHost: localhost:{port}\r\n{extra}\r\n".encode())
    return s


def _read_until(s, needle: bytes, seconds=8) -> bytes:
    buf, end = b"", time.time() + seconds
    while needle not in buf and time.time() < end:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def test_sse_pushes_changes_made_anywhere(web, db):
    """A change made through the service layer (as chat or an agent would) reaches an open page."""
    from estimator.context import RequestContext
    from estimator.estimating import service
    s = _open_stream(web)
    try:
        head = _read_until(s, b": cursor")
        assert b"200 OK" in head and b"text/event-stream" in head and b"retry: 3000" in head
        service.create_estimate(db, RequestContext(agent="agent:director"), "Pushed live")
        got = _read_until(s, b"event: change")
        assert b"event: change" in got and b'"actor":"agent:director"' in got
        assert b": ping" in _read_until(s, b": ping")             # keep-alive
    finally:
        s.close()


def test_sse_resumes_from_last_event_id(web, db, ctx_for):
    from estimator.estimating import service
    service.create_estimate(db, ctx_for(), "Before")
    first = live.updates(db, ctx_for(), 0)["events"][0]["id"]
    service.create_estimate(db, ctx_for(), "Missed while offline")
    s = _open_stream(web, {"Last-Event-ID": str(first)})
    try:
        got = _read_until(s, b"event: change")
        assert f"id: {first + 1}".encode() in got
    finally:
        s.close()


def test_sse_needs_login_off_this_pc(web):
    auth.configure(mode="server")
    s = _open_stream(web)
    try:
        assert b"401" in _read_until(s, b"login_required")
    finally:
        s.close()


def test_sse_streams_stop_when_the_server_stops(monkeypatch):
    monkeypatch.setattr(server, "SSE_POLL_SECONDS", 0.05)
    server.start(port=0, host="127.0.0.1")
    s = _open_stream(server.port())
    _read_until(s, b": cursor")
    t = threading.Thread(target=server.stop)
    t.start()
    t.join(timeout=10)
    s.close()
    assert not t.is_alive() and not server.running()


def test_start_is_idempotent_and_stop_frees_the_port():
    u1 = server.start(port=0, host="127.0.0.1")
    p = server.port()
    assert server.start(port=0, host="127.0.0.1") == u1 == f"http://localhost:{p}/estimator/"
    server.stop()
    assert not server.running() and server.url() == ""
    with socket.socket() as probe:                           # port is free again
        probe.bind(("127.0.0.1", p))


def test_binds_to_this_pc_only_in_personal_mode(monkeypatch):
    monkeypatch.delenv("ESTIMATOR_WEB_NETWORK", raising=False)
    assert server.default_bind() == "127.0.0.1"
    monkeypatch.setenv("ESTIMATOR_WEB_NETWORK", "1")
    assert server.default_bind() == "0.0.0.0"
    monkeypatch.delenv("ESTIMATOR_WEB_NETWORK")
    auth.configure(mode="server")
    assert server.default_bind() == "0.0.0.0"


def test_port_setting(monkeypatch):
    monkeypatch.delenv("ESTIMATOR_WEB_PORT", raising=False)
    assert server.default_port() == 8770
    monkeypatch.setenv("ESTIMATOR_WEB_PORT", "9123")
    assert server.default_port() == 9123
    monkeypatch.setenv("ESTIMATOR_WEB_PORT", "junk")
    assert server.default_port() == 8770


def test_starting_with_ai_prowler_never_raises(monkeypatch):
    monkeypatch.setenv("ESTIMATOR_WEB", "off")
    assert server.start_with_ai_prowler() == "" and not server.running()
    monkeypatch.delenv("ESTIMATOR_WEB")
    with socket.socket() as busy:                            # another program holds the port
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        monkeypatch.setenv("ESTIMATOR_WEB_PORT", str(busy.getsockname()[1]))
        monkeypatch.setattr(server, "default_bind", lambda: "127.0.0.1")
        assert server.start_with_ai_prowler() == ""
    assert not server.running()
