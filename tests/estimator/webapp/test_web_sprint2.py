"""Coder 2 Sprint 2: project page, plan uploads from the browser (staged, checked, then attached), and the
quick estimate screen. Every call goes through the same service functions as the MCP tools."""
import http.client
import io
import json
import time

import pytest

from estimator.api import router, server, staging

PDF = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
API = "/estimator-api"


@pytest.fixture(autouse=True)
def fresh_staging():
    staging.reset()
    yield
    staging.reset()


def _create(call, title="Job", **kw):
    r = call("POST", f"{API}/estimates", {"title": title, **kw})
    assert r.status == 201, r.body
    return r.json()


def _stage(call, eid, data=PDF, name="plans.pdf", headers=None, supersedes=None, write_header=True):
    path = f"{API}/estimates/{eid}/plans/stage?name={name}" + (f"&supersedes={supersedes}" if supersedes else "")
    return call("POST", path, headers=headers, raw=data, write_header=write_header)


class Untouchable(io.RawIOBase):
    """A request body that must never be read (refusals happen before reading 300 MB)."""
    def read(self, *a):
        raise AssertionError("the body was read before the request was refused")


def _streamed(eid, length, stream, headers=None, name="plans.pdf"):
    h = {"Host": "localhost:8770", "X-Estimator-Request": "1", **(headers or {})}
    return router.route(router.Request("POST", f"{API}/estimates/{eid}/plans/stage?name={name}", h, b"", "127.0.0.1",
                                       stream=stream, length=length))


# ---------------------------------------------------------------- project page

def test_project_page_shows_trades_plans_and_rights(call):
    e = _create(call, "Smith house", address="12 Oak St", due_date="2026-12-01")
    r = call("POST", f"{API}/quick", {"estimate_id": e["id"], "rev": e["rev"], "module_id": "pressure_washing",
                                       "answers": {"driveway_sqft": 1000}})
    assert r.status == 200
    p = call("GET", f"{API}/estimates/{e['id']}/project").json()
    assert p["estimate"]["address"] == "12 Oak St" and p["estimate"]["due_date"] == "2026-12-01"
    assert [t["module_id"] for t in p["status"]["trades"]] == ["pressure_washing"]
    assert p["status"]["trades"][0]["subtotal_cents"] > 0 and p["status"]["estimate"]["total_cents"] > 0
    assert p["plan_sets"] == [] and p["can_upload"] and p["can_quick"] and p["editable"]


def test_project_page_for_field_hides_costs_and_upload(call, session_for):
    e = _create(call)
    call("POST", f"{API}/quick", {"estimate_id": e["id"], "rev": e["rev"], "module_id": "pressure_washing",
                                  "answers": {"driveway_sqft": 1000}})
    p = call("GET", f"{API}/estimates/{e['id']}/project", headers=session_for("field")).json()
    assert p["can_upload"] is False and p["can_quick"] is True
    text = json.dumps(p["estimate"])
    assert "unit_cost_cents" not in text and "margin" not in text
    assert p["estimate"]["totals"].get("total_cents")              # field still sees the total


def test_project_page_other_company_is_not_found(call, session_for):
    e = _create(call)
    r = call("GET", f"{API}/estimates/{e['id']}/project", headers=session_for("owner", company="other-co"))
    assert r.status == 404


# ---------------------------------------------------------------- plan uploads: stage, confirm, attach

def test_upload_is_checked_then_waits_for_attach(call):
    e = _create(call)
    r = _stage(call, e["id"], name="Smith plans.pdf")
    assert r.status == 200, r.body
    s = r.json()
    assert s["needs_confirmation"] is True and "Smith plans.pdf" in s["question"]
    assert s["details"]["file_type"] == "pdf" and s["details"]["revision"] == 1
    assert "confirm=true" not in s["question"]
    # nothing attached yet
    assert call("GET", f"{API}/estimates/{e['id']}/plans").json()["plan_sets"] == []
    a = call("POST", f"{API}/estimates/{e['id']}/plans/attach", {"stage_id": s["stage_id"]})
    assert a.status == 201, a.body
    out = a.json()
    assert out["plan_set_id"] and out["status"] == "uploaded"
    plans = call("GET", f"{API}/estimates/{e['id']}/plans").json()
    assert [p["file"] for p in plans["plan_sets"]] == ["Smith plans.pdf"]
    assert "installed" in plans["engine"] or plans["engine"]       # tells the page whether the engine is there
    assert not (staging.root() / s["stage_id"]).exists()           # staged copy removed after attaching
    assert staging.count() == 0


def test_attached_file_is_the_one_uploaded(call, db):
    e = _create(call)
    s = _stage(call, e["id"]).json()
    pid = call("POST", f"{API}/estimates/{e['id']}/plans/attach", {"stage_id": s["stage_id"]}).json()["plan_set_id"]
    from pathlib import Path
    row = db.execute("SELECT file_path, file_size FROM plan_sets WHERE id = ?", (pid,)).fetchone()
    assert Path(row["file_path"]).read_bytes() == PDF and row["file_size"] == len(PDF)
    assert "estimate_" in row["file_path"] and "web_uploads" not in row["file_path"]


def test_upload_event_reaches_live_updates(call):
    e = _create(call)
    cur = call("GET", f"{API}/updates").json()["cursor"]
    s = _stage(call, e["id"]).json()
    call("POST", f"{API}/estimates/{e['id']}/plans/attach", {"stage_id": s["stage_id"]})
    evs = call("GET", f"{API}/updates?since={cur}").json()["events"]
    assert any(ev["action"] == "plan_uploaded" and ev["estimate_id"] == e["id"] for ev in evs)


def test_revised_set_becomes_revision_2(call):
    e = _create(call)
    first = call("POST", f"{API}/estimates/{e['id']}/plans/attach",
                 {"stage_id": _stage(call, e["id"]).json()["stage_id"]}).json()["plan_set_id"]
    s = _stage(call, e["id"], data=PDF + b"% rev B\n", name="rev B.pdf", supersedes=first).json()
    assert s["details"]["revision"] == 2 and f"plan set {first}" in s["question"]
    a = call("POST", f"{API}/estimates/{e['id']}/plans/attach",
             {"stage_id": s["stage_id"], "supersedes_plan_set_id": first}).json()
    assert a["revision"] == 2


def test_cancel_removes_the_staged_file(call):
    e = _create(call)
    s = _stage(call, e["id"]).json()
    assert (staging.root() / s["stage_id"]).is_dir()
    r = call("DELETE", f"{API}/estimates/{e['id']}/plans/stage/{s['stage_id']}")
    assert r.status == 200 and r.json()["cancelled"]
    assert not (staging.root() / s["stage_id"]).exists()
    a = call("POST", f"{API}/estimates/{e['id']}/plans/attach", {"stage_id": s["stage_id"]})
    assert a.status == 404                                          # can't attach after cancelling
    assert call("GET", f"{API}/estimates/{e['id']}/plans").json()["plan_sets"] == []


@pytest.mark.parametrize("data, name, code, words", [
    (b"MZ\x90\x00 this is a program", "plans.pdf", 400, "doesn't look like a real PDF"),
    (b"%PDF-1.7\n/Encrypt 5 0 R\n%%EOF", "locked.pdf", 400, "password-protected"),
    (PDF, "notes.docx", 400, "can't be used"),
    (PDF, "noextension", 400, "can't be used"),
    (b"", "empty.pdf", 400, "empty"),
    (b"\xff\xd8\xff\xe0 jpeg", "photo.png", 400, "doesn't look like a real PNG"),
])
def test_bad_files_are_refused_and_nothing_is_kept(call, data, name, code, words):
    e = _create(call)
    r = _stage(call, e["id"], data=data, name=name)
    assert r.status == code and words in r.json()["message"], r.body
    assert staging.count() == 0
    root = staging.root()
    assert not root.exists() or not any(root.iterdir())
    assert call("GET", f"{API}/estimates/{e['id']}/plans").json()["plan_sets"] == []


def test_same_file_twice_is_refused(call):
    e = _create(call)
    call("POST", f"{API}/estimates/{e['id']}/plans/attach", {"stage_id": _stage(call, e["id"]).json()["stage_id"]})
    r = _stage(call, e["id"], name="copy.pdf")
    assert r.status == 400 and "already on this estimate" in r.json()["message"]
    assert staging.count() == 0


def test_file_names_are_made_safe(call):
    e = _create(call)
    s = _stage(call, e["id"], name="..%2F..%2Fevil<script>.pdf").json()
    assert "<" not in s["details"]["file"] and "/" not in s["details"]["file"] and ".." not in s["details"]["file"]
    assert s["details"]["file"].endswith(".pdf")


def test_refusals_happen_before_reading_the_body(call, session_for):
    e = _create(call)
    # too big, wrong role, wrong company, bad type, not signed in: none of them read the body
    assert _streamed(e["id"], 300 * 1024 * 1024 + 1, Untouchable()).status == 413
    assert _streamed(e["id"], 10, Untouchable(), headers=session_for("field")).status == 403
    assert _streamed(e["id"], 10, Untouchable(), headers=session_for("reviewer")).status == 403
    assert _streamed(e["id"], 10, Untouchable(), headers=session_for("owner", company="other-co")).status == 404
    assert _streamed(e["id"], 10, Untouchable(), name="x.exe").status == 400
    assert _streamed(9999, 10, Untouchable()).status == 404
    h = {"Host": "localhost:8770"}                                   # CSRF header missing
    assert router.route(router.Request("POST", f"{API}/estimates/{e['id']}/plans/stage?name=a.pdf", h, b"",
                                       "127.0.0.1", stream=Untouchable(), length=10)).status == 403
    remote = {"Host": "estimator.example.com", "X-Estimator-Request": "1"}      # another PC, not signed in
    assert router.route(router.Request("POST", f"{API}/estimates/{e['id']}/plans/stage?name=a.pdf", remote, b"",
                                       "10.0.0.8", stream=Untouchable(), length=10)).status == 401
    assert staging.count() == 0


def test_cut_off_upload_is_refused(call):
    e = _create(call)
    r = _streamed(e["id"], len(PDF) + 100, io.BytesIO(PDF))       # browser said more bytes than arrived
    assert r.status == 400 and r.json()["error"] == "upload_incomplete"
    assert staging.count() == 0


def test_office_can_upload(call, session_for):
    e = _create(call)
    h = session_for("office")
    s = _stage(call, e["id"], headers=h).json()
    assert call("POST", f"{API}/estimates/{e['id']}/plans/attach", {"stage_id": s["stage_id"]}, headers=h).status == 201


def test_only_the_uploader_can_attach_or_cancel(call, session_for):
    e = _create(call)
    s = _stage(call, e["id"], headers=session_for("estimator", user="maria")).json()
    other = session_for("estimator", user="tom")
    assert call("POST", f"{API}/estimates/{e['id']}/plans/attach", {"stage_id": s["stage_id"]},
                headers=other).status == 404
    assert call("DELETE", f"{API}/estimates/{e['id']}/plans/stage/{s['stage_id']}", headers=other).status == 404
    e2 = _create(call, "Other job")
    assert call("POST", f"{API}/estimates/{e2['id']}/plans/attach", {"stage_id": s["stage_id"]},
                headers=session_for("estimator", user="maria")).status == 404      # wrong estimate


def test_stages_expire(call, monkeypatch):
    e = _create(call)
    s = _stage(call, e["id"]).json()
    later = time.time() + staging.STAGE_TTL_SECONDS + 5
    monkeypatch.setattr(staging, "_clock", lambda: later)
    assert call("POST", f"{API}/estimates/{e['id']}/plans/attach", {"stage_id": s["stage_id"]}).status == 404
    staging.sweep()
    assert staging.count() == 0


def test_leftover_folders_are_swept_only_when_old():
    import os
    staging.root().mkdir(parents=True, exist_ok=True)
    old, fresh = staging.root() / "left_from_restart", staging.root() / "just_now"
    old.mkdir()
    fresh.mkdir()
    now = time.time()
    os.utime(old, (now - staging.STAGE_TTL_SECONDS - 60,) * 2)
    assert staging.sweep(now) == 1
    assert not old.exists() and fresh.exists()


def test_safe_name():
    assert staging.safe_name("C:\\Users\\x\\My Plans (rev 2).PDF") == "My Plans (rev 2).pdf"
    assert staging.safe_name("../../etc/passwd") == "passwd"
    assert staging.safe_name("") == "plans"
    assert staging.safe_name("a<b>|c.dxf") == "a_b_c.dxf"


# ---------------------------------------------------------------- streaming over real HTTP

@pytest.fixture
def web():
    server.stop()
    server.start(port=0, host="127.0.0.1")
    yield server.port()
    server.stop()


def test_big_upload_streams_over_http(web):
    """Bigger than the 2 MB JSON limit, so it only works because the host streams it to disk."""
    c = http.client.HTTPConnection("127.0.0.1", web, timeout=30)
    h = {"Host": f"localhost:{web}", "Content-Type": "application/json", "X-Estimator-Request": "1"}
    c.request("POST", f"{API}/estimates", json.dumps({"title": "Big plans"}).encode(), h)
    eid = json.loads(c.getresponse().read())["id"]
    c.close()
    big = PDF + b"%" + b"x" * (server.MAX_REQUEST_BYTES + 1024) + b"\n%%EOF\n"
    c = http.client.HTTPConnection("127.0.0.1", web, timeout=30)
    c.request("POST", f"{API}/estimates/{eid}/plans/stage?name=big.pdf", big,
              {"Host": f"localhost:{web}", "X-Estimator-Request": "1", "Content-Type": "application/octet-stream"})
    r = c.getresponse()
    body = json.loads(r.read())
    assert r.status == 200 and body["needs_confirmation"], body
    assert r.getheader("Connection") == "close"
    c.close()
    assert (staging.root() / body["stage_id"]).is_dir()


def test_refused_upload_over_http_closes_the_connection(web):
    c = http.client.HTTPConnection("127.0.0.1", web, timeout=10)
    c.putrequest("POST", f"{API}/estimates/1/plans/stage?name=a.exe")
    c.putheader("Host", f"localhost:{web}")
    c.putheader("X-Estimator-Request", "1")
    c.putheader("Content-Length", str(50 * 1024 * 1024))
    c.endheaders()                                   # body never sent: the server must answer without waiting
    r = c.getresponse()
    assert r.status in (400, 404) and r.getheader("Connection") == "close"
    c.close()


# ---------------------------------------------------------------- quick estimate

def test_modules_for_the_quick_screen(call):
    mods = call("GET", f"{API}/modules?path=quick").json()["modules"]
    ids = [m["id"] for m in mods]
    assert "pressure_washing" in ids and "house_cleaning" in ids
    assert all(m["path"] in ("quick_estimate", "both") for m in mods)
    cats = [m["category"] for m in mods]
    assert cats == sorted(cats, key=lambda c: c != "service")       # services first
    everything = call("GET", f"{API}/modules").json()["modules"]
    assert len(everything) >= len(mods)


def test_questions_for_a_service(call):
    q = call("GET", f"{API}/modules/pressure_washing/questions").json()
    assert q["module"]["id"] == "pressure_washing"
    assert any(x["id"] == "driveway_sqft" for x in q["questions"])
    assert call("GET", f"{API}/modules/unicorn_grooming/questions").status == 404


def test_quick_estimate_creates_and_prices_a_project(call):
    r = call("POST", f"{API}/quick", {"module_id": "pressure_washing", "answers": {"driveway_sqft": 1000},
                                       "address": "5 Beach Rd"})
    assert r.status == 201, r.body
    e = r.json()
    assert e["created"] is True and e["title"].endswith("– 5 Beach Rd")       # "<service name> – <address>"
    assert e["totals"]["total_cents"] > 0 and e["sections"][0]["module_id"] == "pressure_washing"
    assert e["warnings"] and "sample" in e["warnings"][0].lower()
    listing = call("GET", f"{API}/estimates").json()["estimates"]
    assert [x["id"] for x in listing] == [e["id"]]


def test_quick_estimate_on_an_existing_project_needs_rev(call):
    e = _create(call)
    r = call("POST", f"{API}/quick", {"estimate_id": e["id"], "module_id": "pressure_washing",
                                       "answers": {"driveway_sqft": 500}})
    assert r.status == 400 and "rev" in r.json()["message"]
    r = call("POST", f"{API}/quick", {"estimate_id": e["id"], "rev": e["rev"], "module_id": "pressure_washing",
                                       "answers": {"driveway_sqft": 500}})
    assert r.status == 200 and r.json()["created"] is False
    stale = call("POST", f"{API}/quick", {"estimate_id": e["id"], "rev": e["rev"], "module_id": "pressure_washing",
                                           "answers": {"driveway_sqft": 600}})
    assert stale.status == 409                                       # someone (or chat) changed it since


def test_bad_answers_never_leave_an_empty_project(call):
    for body, words in (
        ({"module_id": "house_cleaning", "answers": {}}, "please answer"),
        ({"module_id": "pressure_washing", "answers": {"driveway": 100}}, "unknown questions"),
        ({"module_id": "pressure_washing", "answers": "lots"}, "answers must be"),
        ({"module_id": "", "answers": {}}, "pick a service"),
    ):
        r = call("POST", f"{API}/quick", body)
        assert r.status == 400 and words in r.json()["message"], (body, r.body)
    assert call("POST", f"{API}/quick", {"module_id": "unicorn_grooming", "answers": {}}).status == 404
    assert call("GET", f"{API}/estimates").json()["estimates"] == []


def test_quick_roles(call, session_for):
    body = {"module_id": "pressure_washing", "answers": {"driveway_sqft": 400}}
    for role in ("office", "field", "estimator"):
        assert call("POST", f"{API}/quick", body, headers=session_for(role)).status == 201, role
    r = call("POST", f"{API}/quick", body, headers=session_for("reviewer"))
    assert r.status == 403
    field = call("POST", f"{API}/quick", body, headers=session_for("field")).json()
    assert "unit_cost_cents" not in json.dumps(field) and field["totals"]["total_cents"] > 0


def test_quick_estimate_needs_the_app_header(call):
    r = call("POST", f"{API}/quick", {"module_id": "pressure_washing", "answers": {"driveway_sqft": 1}},
             write_header=False)
    assert r.status == 403 and r.json()["error"] == "csrf"


# ---------------------------------------------------------------- dashboard additions

def test_dashboard_lists_reviews_waiting_and_my_work(call, db, ctx_for):
    from estimator.estimating import service
    e = _create(call, "Needs review")
    db.execute("UPDATE estimates SET status = 'in_review' WHERE id = ?", (e["id"],))
    db.commit()
    d = call("GET", f"{API}/dashboard").json()
    assert [x["id"] for x in d["attention"]] == [e["id"]]
    assert d["my_work"] is not None and "summary" in d["my_work"]
    assert d["can_quick"] is True
    assert service.QUICK_ROLES  # same list the button uses


def test_web_page_has_the_sprint2_pages():
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for needle in ("/plans/stage", "/plans/attach", "/quick", "/project", "XMLHttpRequest"):
        assert needle in js
    assert "innerHTML" not in js                                     # text only, never parsed as HTML
