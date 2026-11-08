"""Coder 2 Sprint 3: the Estimator served by AI-Prowler's own port-8000 server (asgi_bridge), signed in with the
Jobs app's token, and the Jobs app's Estimates tab. The bridge is driven exactly like uvicorn drives it."""
import asyncio
import json
from pathlib import Path

import pytest

from estimator.api import asgi_bridge, auth, prowler_link, staging

ROOT = Path(__file__).resolve().parents[3]
PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
TUNNEL = [(b"host", b"jobs.example.com"), (b"cf-connecting-ip", b"203.0.113.9"), (b"x-forwarded-proto", b"https")]
LOCAL = [(b"host", b"localhost:8000")]
GOOD = "jobs-token-123"


@pytest.fixture(autouse=True)
def clean():
    staging.reset()
    yield
    staging.reset()


@pytest.fixture
def owner_token():
    auth.set_app_token_resolver(prowler_link.personal_app_token_resolver(lambda t: t == GOOD, lambda: "Dana"))


def scope(method, path, headers=(), client="127.0.0.1"):
    p, _, q = path.partition("?")
    return {"type": "http", "method": method, "path": p, "query_string": q.encode(), "headers": list(headers),
            "client": (client, 50000), "scheme": "http"}


def run(method, path, headers=(), body=b"", chunks=None, client="127.0.0.1"):
    """One request through the bridge. Returns (status, headers dict, body bytes)."""
    parts = chunks if chunks is not None else [body]
    msgs = [{"type": "http.request", "body": c, "more_body": i < len(parts) - 1} for i, c in enumerate(parts)]
    hdrs = list(headers)
    if method != "GET":
        hdrs.append((b"content-length", str(sum(len(c) for c in parts)).encode()))
    out = {"status": None, "headers": {}, "body": b""}

    async def receive():
        return msgs.pop(0) if msgs else {"type": "http.disconnect"}

    async def send(m):
        if m["type"] == "http.response.start":
            out["status"] = m["status"]
            out["headers"] = {k.decode().lower(): v.decode() for k, v in m["headers"]}
        else:
            out["body"] += m.get("body", b"")

    asyncio.run(asyncio.wait_for(asyncio_bridge(scope(method, path, hdrs, client), receive, send), 30))
    return out["status"], out["headers"], out["body"]


async def asyncio_bridge(sc, receive, send):
    await asgi_bridge.handle(sc, receive, send)


def bearer(tok=GOOD):
    return [(b"authorization", f"Bearer {tok}".encode())]


def write():
    return [(b"x-estimator-request", b"1")]


# ---------------------------------------------------------------- serving through port 8000

def test_paths():
    for p in ("/estimator", "/estimator/", "/estimator/app.js", "/estimator-api/health"):
        assert asgi_bridge.is_path(p)
    for p in ("/jobs/", "/desk-api/x", "/estimators", "/"):
        assert not asgi_bridge.is_path(p)


def test_page_and_health_through_port_8000():
    st, h, body = run("GET", "/estimator/", LOCAL)
    assert st == 200 and b"AI-Prowler Estimator" in body
    assert h["x-frame-options"] == "SAMEORIGIN" and "frame-ancestors 'self'" in h["content-security-policy"]
    st, _, body = run("GET", "/estimator-api/health", TUNNEL)
    assert st == 200 and json.loads(body)["ok"] is True


def test_same_pc_on_port_8000_opens_without_login():
    st, _, body = run("GET", "/estimator-api/me", LOCAL)
    assert st == 200 and json.loads(body)["me"]["signed_in_by"] == "same_pc"


def test_through_the_tunnel_you_must_sign_in(owner_token):
    st, _, _ = run("GET", "/estimator-api/me", TUNNEL)            # loopback address, but tunnel headers
    assert st == 401


def test_jobs_app_token_signs_the_owner_in(owner_token):
    st, _, body = run("GET", "/estimator-api/me", TUNNEL + bearer())
    me = json.loads(body)["me"]
    assert st == 200 and me["role"] == "owner" and me["name"] == "Dana" and me["signed_in_by"] == "app_token"
    assert me["can_sign_out"] is False                             # signing out is the Jobs app's job
    st, _, _ = run("GET", "/estimator-api/me", TUNNEL + bearer("wrong"))
    assert st == 401


def test_writes_through_the_bridge_still_need_the_app_header(owner_token):
    body = json.dumps({"title": "From the phone"}).encode()
    st, _, _ = run("POST", "/estimator-api/estimates", TUNNEL + bearer(), body)
    assert st == 403
    st, _, out = run("POST", "/estimator-api/estimates", TUNNEL + bearer() + write(), body)
    assert st == 201 and json.loads(out)["title"] == "From the phone"


def test_quick_estimate_from_the_phone(owner_token):
    body = json.dumps({"module_id": "pressure_washing", "answers": {"driveway_sqft": 800}}).encode()
    st, _, out = run("POST", "/estimator-api/quick", TUNNEL + bearer() + write(), body)
    assert st == 201 and json.loads(out)["totals"]["total_cents"] > 0


def test_plan_upload_streams_through_the_bridge(owner_token):
    st, _, out = run("POST", "/estimator-api/estimates", LOCAL + write(), json.dumps({"title": "Plans"}).encode())
    eid = json.loads(out)["id"]
    chunks = [PDF[:10], PDF[10:40], PDF[40:]]                      # arrives in pieces, like a real upload
    st, _, out = run("POST", f"/estimator-api/estimates/{eid}/plans/stage?name=phone.pdf",
                     TUNNEL + bearer() + write(), chunks=chunks)
    s = json.loads(out)
    assert st == 200 and s["needs_confirmation"] and "phone.pdf" in s["question"]
    st, _, out = run("POST", f"/estimator-api/estimates/{eid}/plans/attach", TUNNEL + bearer() + write(),
                     json.dumps({"stage_id": s["stage_id"]}).encode())
    assert st == 201 and json.loads(out)["revision"] == 1


def test_too_large_json_is_refused():
    big = b"{" + b" " * (3 * 1024 * 1024) + b"}"
    st, _, _ = run("POST", "/estimator-api/estimates", LOCAL + write(), big)
    assert st == 413


def test_turned_off_estimator_answers_404(monkeypatch):
    monkeypatch.setattr(asgi_bridge, "turned_on", lambda: False)
    assert run("GET", "/estimator-api/health", LOCAL)[0] == 404
    st, _, body = run("GET", "/estimator/", LOCAL)
    assert st == 404 and b"turned off" in body


def test_live_updates_stream_through_the_bridge(owner_token, ctx_for):
    from estimator.database import open_database
    from estimator.estimating import service
    out = {"status": None, "body": b""}

    def change_from_chat():                     # its own connection: SQLite connections stay on one thread
        conn = open_database()
        try:
            service.create_estimate(conn, ctx_for("owner", "owner", "default", "personal"), "From chat")
        finally:
            conn.close()

    async def go():
        q: asyncio.Queue = asyncio.Queue()

        async def receive():
            return await q.get()

        async def send(m):
            if m["type"] == "http.response.start":
                out["status"] = m["status"]
            else:
                out["body"] += m.get("body", b"")
                if b"event: change" in out["body"]:
                    await q.put({"type": "http.disconnect"})

        task = asyncio.ensure_future(asgi_bridge.handle(scope("GET", "/estimator-api/events", TUNNEL + bearer()),
                                                        receive, send))
        await asyncio.sleep(0.3)
        await asyncio.get_running_loop().run_in_executor(None, change_from_chat)
        await asyncio.wait_for(task, 15)

    asyncio.run(go())
    assert out["status"] == 200 and b"event: change" in out["body"] and b"retry:" in out["body"]


def test_live_updates_need_sign_in_through_the_tunnel():
    st, _, _ = run("GET", "/estimator-api/events", TUNNEL)
    assert st == 401


# ---------------------------------------------------------------- the app-token check itself

def test_broken_or_odd_resolvers_let_nobody_in():
    def boom(_t):
        raise RuntimeError("token store locked")
    for fn in (boom, lambda t: {"user_id": "x", "role": "admin"}, lambda t: {"role": "owner"}, lambda t: None):
        auth.set_app_token_resolver(fn)
        assert auth.resolve({"Authorization": "Bearer abc", "Host": "x.example.com"}, "10.0.0.1") is None


def test_app_token_is_only_read_from_the_authorization_header(owner_token):
    # Never from a cookie: a cookie is sent by the browser on its own, a header isn't (CSRF).
    assert auth.resolve({"Cookie": f"est_session={GOOD}", "Host": "x.example.com"}, "10.0.0.1") is None
    assert auth.resolve({"Authorization": f"Bearer {GOOD}", "Host": "x.example.com"}, "10.0.0.1").how == "app_token"


def test_server_app_token_resolver_maps_roles_and_respects_expiry():
    users = {"company_id": "acme", "users": {"raw-cal": {"name": "Cal Crew", "role": "field_crew"},
                                             "raw-out": {"name": "Nora", "role": "manager", "estimator_role": "none"}}}
    sessions = {"acc-cal": "raw-cal", "acc-out": "raw-out"}

    def resolve_user(data, tok):
        e = data["users"].get(tok)
        return {**e, "id": e["name"].lower().replace(" ", "-")} if e else None

    r = prowler_link.server_app_token_resolver(sessions.get, lambda: users, resolve_user)
    assert r("acc-cal") == {"user_id": "cal-crew", "role": "field", "name": "Cal Crew", "company_id": "acme"}
    assert r("acc-out") is None                                    # opted out of the Estimator
    assert r("expired-or-unknown") is None
    assert r("") is None


def test_web_off_still_sets_up_sign_in_for_port_8000(monkeypatch):
    monkeypatch.setattr(prowler_link, "should_start", lambda _h: (False, "ESTIMATOR_WEB=off"))
    started = []
    from estimator.api import server
    monkeypatch.setattr(server, "start_with_ai_prowler", lambda: started.append(1) or "u")
    assert prowler_link.start_from_ai_prowler(is_http_server=True, server_mode=True,
                                              load_users=lambda: {}, resolve_user=lambda d, t: None) == ""
    assert auth.mode() == "server" and auth._settings.verifier is not None and not started


# ---------------------------------------------------------------- wiring in AI-Prowler and the Jobs app

def test_both_ai_prowler_routers_serve_the_estimator_before_service_desk():
    text = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    for marker in ("# ── Service Desk app + API, server mode", "# ── Service Desk app + API, personal mode"):
        i = text.index(marker)
        assert "if _est_bridge_path(path):" in text[i - 600:i], marker
    assert text.count("await _est_bridge(scope, receive, send)") == 2
    assert "personal_app_token_resolver(" in text and "server_app_token_resolver(" in text
    assert "def _est_bridge_path(" in text and "def _est_connect_app_tokens(" in text


def test_jobs_app_has_the_estimates_tab():
    html = (ROOT / "jobs" / "index.html").read_text(encoding="utf-8")
    assert 'id="navEstimates"' in html and 'id="screen-estimates"' in html and 'id="estimatesFrame"' in html
    assert "estimatesInit();" in html and "/estimator-api/health" in html
    assert "'/estimator/?embed=1#/quick'" in html
    nav = html.split('<nav class="bottomnav">')[1].split("</nav>")[0]
    assert "navEstimates" in nav and 'style="display:none"' in nav.split('id="navEstimates"')[1][:200]


def test_estimator_page_uses_the_jobs_sign_in():
    js = (ROOT / "estimator" / "ui" / "web" / "app.js").read_text(encoding="utf-8")
    assert 'localStorage.getItem("ap_auth")' in js and '"Bearer " + APP_TOKEN' in js
    assert 'APP_TOKEN = "";' in js                                 # a stale token is dropped on 401
    assert "window.EventSource && !APP_TOKEN" in js                # EventSource can't send the header
