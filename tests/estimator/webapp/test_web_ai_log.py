"""The AI Log through the API: list, detail, the sent images, and who can see it.

No LLM calls here - the rows are seeded straight into the table (the unit
tests prove the takeoff and the queue write them). The UI markers at the end
pin the page, the Agents link and the Blueprint Review links in place.
"""
import json
from pathlib import Path

import pytest

from estimator import config
from estimator.agents import ai_log, providers
from estimator.api import nav
from estimator.context import personal_context

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"
CTX = personal_context()


class _FakeProvider:
    """Costs $2 / $10 per 1M tokens, like Sonnet. The API never calls the LLM."""

    def ready(self, provider):
        return True, ""

    def model_for(self, provider):
        return "claude-sonnet-5-5"

    def ask(self, *a, **kw):
        raise AssertionError("the API must not call the LLM")

    def ask_vision(self, *a, **kw):
        raise AssertionError("the API must not call the LLM")

    def cost(self, model, usage):
        return round((usage["input"] * 2 + usage["output"] * 10) / 1_000_000, 5)


@pytest.fixture
def fake():
    f = _FakeProvider()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


def _png(path, w=400, h=300):
    from PIL import Image
    Image.new("RGB", (w, h), "white").save(path, "PNG")
    return path


def _seed(db, **over):
    vals = {"provider": "claude_api", "model": "claude-sonnet-5-5", "role": "llm_takeoff",
            "purpose": "LLM takeoff: read the slab dimensions",
            "system_prompt": "You read plans.", "user_prompt": "Read this slab.",
            "response_text": '{"slab_width_ft": "45\'-7\\""}',
            "parsed": {"slab_width_ft": "45'-7\""}, "auto_run_id": 5, "estimate_id": 2}
    vals.update(over)
    return ai_log.record(db, CTX, **vals)


# ------------------------------------------------------------------ list


def test_list_empty(call):
    r = call("GET", f"{API}/ai-log")
    assert r.status == 200, r.json()
    assert r.json() == {"ok": True, "entries": [], "total": 0, "limit": 50, "offset": 0}


def test_list_newest_first_and_paginated(call, db):
    ids = [_seed(db, purpose=f"call {i}") for i in range(3)]
    r = call("GET", f"{API}/ai-log").json()
    assert r["total"] == 3 and [e["id"] for e in r["entries"]] == ids[::-1]
    assert [e["purpose"] for e in r["entries"]] == ["call 2", "call 1", "call 0"]
    page = call("GET", f"{API}/ai-log?limit=2").json()
    assert len(page["entries"]) == 2 and page["total"] == 3 and page["limit"] == 2
    page2 = call("GET", f"{API}/ai-log?limit=2&offset=2").json()
    assert [e["id"] for e in page2["entries"]] == [ids[0]] and page2["offset"] == 2
    # The list carries no prompts or replies - the detail call has those.
    assert not {"system_prompt", "user_prompt", "response_text", "parsed", "images"} & set(r["entries"][0])


def test_list_filters_by_run_role_and_estimate(call, db):
    _seed(db, auto_run_id=5, role="llm_takeoff", estimate_id=2)
    _seed(db, auto_run_id=5, role="llm_takeoff", estimate_id=2)
    _seed(db, auto_run_id=6, role="reviewer", task_id=9, estimate_id=3, purpose="Reviewer agent, task 9")
    assert call("GET", f"{API}/ai-log?auto_run_id=5").json()["total"] == 2
    assert call("GET", f"{API}/ai-log?auto_run_id=6").json()["total"] == 1
    got = call("GET", f"{API}/ai-log?role=reviewer").json()
    assert got["total"] == 1 and got["entries"][0]["purpose"] == "Reviewer agent, task 9"
    assert call("GET", f"{API}/ai-log?task_id=9").json()["total"] == 1
    assert call("GET", f"{API}/ai-log?estimate_id=3").json()["total"] == 1
    assert call("GET", f"{API}/ai-log?auto_run_id=999").json()["total"] == 0


def test_list_cost_comes_through(call, db, fake):
    eid = _seed(db, usage={"input": 3000, "output": 200})
    e = call("GET", f"{API}/ai-log").json()["entries"][0]
    assert e["id"] == eid and e["cost_micros"] == 8000 and e["cost_cents"] == 0.8


# ------------------------------------------------------------------ detail


def test_detail_has_the_whole_call_but_not_the_file_path(call, db):
    png = _png(config.data_dir() / "sent.png")
    eid = _seed(db, images=[{"ai_send_log_id": 7, "sheet_id": 3, "sheet_no": "S-1",
                             "kind": "full_sheet", "file_path": str(png),
                             "width_px": 400, "height_px": 300}])
    r = call("GET", f"{API}/ai-log/{eid}")
    assert r.status == 200, r.json()
    e = r.json()["entry"]
    assert e["system_prompt"] == "You read plans." and e["user_prompt"] == "Read this slab."
    assert e["response_text"] == '{"slab_width_ft": "45\'-7\\""}'
    assert e["parsed"] == {"slab_width_ft": "45'-7\""}
    assert e["image_count"] == 1 and e["images"][0]["image_url"] == f"/ai-log/{eid}/image/0"
    assert e["images"][0]["sheet_no"] == "S-1" and e["images"][0]["ai_send_log_id"] == 7
    assert "file_path" not in json.dumps(e)                     # the browser never sees the path


def test_detail_missing_is_404(call):
    assert call("GET", f"{API}/ai-log/999").status == 404
    assert call("GET", f"{API}/ai-log/abc").status == 404


def test_detail_other_company_is_404(call, db, session_for):
    eid = _seed(db)
    assert call("GET", f"{API}/ai-log/{eid}", headers=session_for("owner", company="acme")).status == 404
    assert call("GET", f"{API}/ai-log", headers=session_for("owner", company="acme")).json()["total"] == 0


# ------------------------------------------------------------------ the sent images


def test_image_serves_the_sent_picture(call, db):
    png = _png(config.data_dir() / "sent.png")
    eid = _seed(db, images=[{"ai_send_log_id": 7, "sheet_id": 3, "sheet_no": "S-1",
                             "kind": "full_sheet", "file_path": str(png),
                             "width_px": 400, "height_px": 300}])
    r = call("GET", f"{API}/ai-log/{eid}/image/0")
    assert r.status == 200 and r.content_type == "image/png"
    assert r.body == png.read_bytes()
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_image_errors_are_404(call, db, tmp_path):
    eid = _seed(db)                                             # no images on this entry
    assert call("GET", f"{API}/ai-log/{eid}/image/0").status == 404
    outside = _png(tmp_path / "outside.png")
    eid2 = _seed(db, images=[{"file_path": str(outside), "sheet_id": 1}])
    assert call("GET", f"{API}/ai-log/{eid2}/image/0").status == 404   # outside the data folder
    assert call("GET", f"{API}/ai-log/999/image/0").status == 404
    assert call("GET", f"{API}/ai-log/{eid}/image/x").status == 404


# ------------------------------------------------------------------ who can see it


def test_only_owner_and_estimators_can_read(call, db, session_for):
    eid = _seed(db)
    for role in ("reviewer", "office", "field"):
        h = session_for(role)
        assert call("GET", f"{API}/ai-log", headers=h).status == 403, role
        assert call("GET", f"{API}/ai-log/{eid}", headers=h).status == 403, role
        assert call("GET", f"{API}/ai-log/{eid}/image/0", headers=h).status == 403, role
    assert call("GET", f"{API}/ai-log", headers=session_for("estimator")).status == 200
    assert call("GET", f"{API}/ai-log/{eid}", headers=session_for("estimator")).status == 200


# ------------------------------------------------------------------ the page and its links


def test_nav_has_the_ai_log_page():
    mine = [p for p in nav.PAGES if p["id"] == "ai_log"]
    assert len(mine) == 1 and mine[0]["from"] == "agents" and mine[0]["label"] == "AI Log"


def test_ui_markers():
    verify = (WEB / "verify.js").read_text(encoding="utf-8")
    assert "PAGES.ai_log = renderAiLog" in verify
    assert "agents-ai-log-link" in verify and 'href: "#/agents/ai-log"' in verify
    assert "ai-log-empty" in verify and "aiLogDetail" in verify
    app = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'parts[1] === "ai-log"' in app
    review = (WEB / "review.js").read_text(encoding="utf-8")
    assert "bp-auto-ai-log" in review and "bp-detail-ai-log" in review
    assert '#/agents/ai-log?auto_run_id=" + AUTO.runId' in review
    assert '#/agents/ai-log?auto_run_id=" + c.auto_run_id' in review
    css = (WEB / "app.css").read_text(encoding="utf-8")
    assert ".ai-log-text" in css and ".ai-log-img" in css
