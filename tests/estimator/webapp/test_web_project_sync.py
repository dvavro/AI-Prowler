"""POST /estimator-api/sync/receive: a project sent over the internet from a PC (project_sync.send_over_internet).
Streamed like plan files, signed-in users only, and the PC-side client end to end through the router."""
import io
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from estimator import project_sync
from estimator.api import router, staging
from estimator.context import personal_context
from estimator.database import open_database
from estimator.estimating import service

API = "/estimator-api"


@pytest.fixture(autouse=True)
def fresh_staging():
    staging.reset()
    yield
    staging.reset()


def _bundle(estimator_sandbox):
    conn = open_database()
    try:
        eid = service.create_estimate(conn, personal_context(), "Smith house", address="12 Oak St")["id"]
        return project_sync.build_bundle(conn, personal_context(), eid)
    finally:
        conn.close()


def _post(data: bytes, headers, query=""):
    h = {"Host": "acme.example.com", "X-Estimator-Request": "1", **headers}
    return router.route(router.Request("POST", f"{API}/sync/receive{query}", h, b"", "10.0.0.8",
                                       stream=io.BytesIO(data), length=len(data)))


def test_receive_route_is_streamed():
    assert router.is_upload("POST", f"{API}/sync/receive")
    assert router.is_upload("POST", f"{API}/sync/receive?replace=1")
    assert not router.is_upload("GET", f"{API}/sync/receive")


def test_signed_in_estimator_can_send_a_project(estimator_sandbox, session_for):
    data = Path(_bundle(estimator_sandbox)["path"]).read_bytes()
    r = _post(data, session_for("estimator", company="acme"))
    assert r.status == 200, r.body
    out = r.json()
    assert out["mode"] == "new" and out["title"] == "Smith house"
    r2 = _post(data, session_for("estimator", company="acme"))
    assert r2.json()["mode"] == "replaced" and r2.json()["estimate_id"] == out["estimate_id"]
    listed = router.route(router.Request("GET", f"{API}/sync/received",
                                         {"Host": "acme.example.com", **session_for("owner", company="acme")}, b"",
                                         "10.0.0.8"))
    assert listed.json()["count"] == 1
    assert staging.count() == 0                                         # the uploaded file doesn't linger


def test_refusals(estimator_sandbox, session_for):
    data = Path(_bundle(estimator_sandbox)["path"]).read_bytes()
    assert _post(data, {}).status == 401                                # not signed in
    assert _post(data, session_for("field", company="acme")).status == 403
    h = {"Host": "acme.example.com", **session_for("estimator", company="acme")}     # no anti-CSRF header
    assert router.route(router.Request("POST", f"{API}/sync/receive", h, b"", "10.0.0.8", stream=io.BytesIO(data),
                                       length=len(data))).status == 403
    r = router.route(router.Request("POST", f"{API}/sync/receive",
                                    {"Host": "acme.example.com", "X-Estimator-Request": "1",
                                     **session_for("estimator", company="acme")}, b"", "10.0.0.8",
                                    stream=io.BytesIO(data[:100]), length=len(data)))
    assert r.status == 400 and r.json()["error"] == "upload_incomplete"
    assert _post(b"not a zip", session_for("estimator", company="acme")).status == 400
    assert staging.count() == 0


def test_pc_client_signs_in_and_sends(estimator_sandbox, session_for, monkeypatch):
    """send_over_internet's HTTP goes straight into the router (no network)."""
    headers_seen = []

    def fake_http(url, *, data=None, headers=None, method="POST", timeout=60):
        parts = urlsplit(url)
        assert parts.scheme == "https" and parts.netloc == "acme.example.com"
        body = data.read() if hasattr(data, "read") else (data or b"")
        h = {"Host": parts.netloc, **(headers or {})}
        headers_seen.append(h)
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        if parts.path.endswith("/sync/receive"):
            resp = router.route(router.Request(method, path, h, b"", "10.0.0.8", stream=io.BytesIO(body),
                                               length=len(body)))
        else:
            resp = router.route(router.Request(method, path, h, body, "10.0.0.8"))
        return resp.status, resp.json()

    monkeypatch.setattr(project_sync, "_http", fake_http)
    monkeypatch.setattr("estimator.api.auth.login",
                        lambda u, p, ip: (session_for("estimator", company="acme")["Authorization"][7:], None))
    monkeypatch.setattr(router, "_me", lambda caller: {})
    token = project_sync.sign_in("acme.example.com", "dana", "pw")
    conn = open_database()
    try:
        eid = service.create_estimate(conn, personal_context(), "Garage slab")["id"]
        out = project_sync.send_over_internet(conn, personal_context(), eid, "https://acme.example.com/jobs/", token)
    finally:
        conn.close()
    assert out["via"] == "internet" and out["server"]["mode"] == "new"
    assert headers_seen[-1]["Authorization"] == f"Bearer {token}" and headers_seen[-1]["X-Estimator-Request"] == "1"
    assert not list((estimator_sandbox / "exports" / "to_server").glob("*.zip"))   # the local copy is removed


def test_too_big_for_the_internet(estimator_sandbox, monkeypatch):
    monkeypatch.setattr(project_sync, "INTERNET_MAX_BYTES", 10)
    monkeypatch.setattr(project_sync, "_http", lambda *a, **k: pytest.fail("must not upload"))
    conn = open_database()
    try:
        eid = service.create_estimate(conn, personal_context(), "Big plans")["id"]
        with pytest.raises(project_sync.InvalidInput, match="office network"):
            project_sync.send_over_internet(conn, personal_context(), eid, "https://acme.example.com", "tok")
    finally:
        conn.close()
