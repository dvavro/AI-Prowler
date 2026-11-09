"""Coder 2 Sprint 11: the Reviews screen (check symbol detections: thumbnails, approve, take out, relabel, add, find
similar), the Symbol Library screen and the Agents screen (Agent Manager settings and takeoff runs)."""
import sys
from pathlib import Path

import pytest

from estimator.api import nav
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf  # noqa: E402
from test_plan_engine_sprint10 import legend, plan, shape  # noqa: E402

API = "/estimator-api"
WEB = Path(__file__).resolve().parents[3] / "estimator" / "ui" / "web"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def plans(db, tmp_path, call):
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("flag", None, "SPECIAL DEVICE")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + shape("flag", 12, 8) + \
        shape("flag", 14, 8, 30)
    ps = store.upload(db, ctx, est["id"], str(make_pdf(tmp_path / "power.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    dets = call("GET", f"{API}/plan-sets/{ps}/symbols").json()["detections"]
    return {"plan_set_id": ps, "estimate_id": est["id"], "sheet_id": dets[0]["sheet_id"],
            "recept": [d["id"] for d in dets if d["item_type"] == "duplex_receptacle"],
            "flag": [d["id"] for d in dets if d["item_type"] is None]}


def _by_type(call, ps):
    return {t["item_type"]: t for t in call("GET", f"{API}/plan-sets/{ps}/symbols").json()["counts"]["by_type"]}


# ---------------------------------------------------------------- Reviews                         C2S11-W01..W05

def test_reviews_lists_plan_sets_to_check(call, plans, session_for):                # C2S11-W01
    r = call("GET", f"{API}/symbol-reviews").json()
    p = r["plan_sets"][0]
    assert (p["plan_set_id"], p["estimate_title"], p["found"], p["proposed"], p["needs_review"]) == \
        (plans["plan_set_id"], "Smith house", 5, 5, 2)
    assert r["can_review"] is True and "relabel" in r["actions"]
    f = call("GET", f"{API}/symbol-reviews", headers=session_for("field")).json()
    assert f["count"] == 1 and f["can_review"] is False                            # field staff look, don't decide
    assert call("GET", f"{API}/symbol-reviews", headers=session_for("office")).status == 403
    assert call("GET", f"{API}/symbol-reviews", headers=session_for("owner", company="acme")).json()["count"] == 0


def test_approve_and_take_out_ask_first(call, plans):                               # C2S11-W02
    ps, r = plans["plan_set_id"], plans["recept"]
    ask = call("POST", f"{API}/symbol-detections/review", {"detection_ids": r[:2], "action": "approve"}).json()
    assert ask["needs_confirmation"] is True and "Approve 2" in ask["question"] and "confirm" not in ask["question"]
    assert _by_type(call, ps)["duplex_receptacle"]["approved"] == 0                # nothing changed yet
    done = call("POST", f"{API}/symbol-detections/review", {"detection_ids": r[:2], "action": "approve", "confirm": True})
    assert done.status == 200 and done.json()["changed"] == 2
    call("POST", f"{API}/symbol-detections/review", {"detection_ids": [r[2]], "action": "reject", "confirm": True})
    t = _by_type(call, ps)["duplex_receptacle"]
    assert (t["count"], t["approved"], t["rejected"]) == (2, 2, 1)
    d = next(x for x in call("GET", f"{API}/plan-sets/{ps}/symbols").json()["detections"] if x["id"] == r[2])
    assert d["status"] == "rejected" and d["original"]["status"] == "proposed"


def test_relabel_add_and_find_similar(call, plans):                                 # C2S11-W03
    ps = plans["plan_set_id"]
    out = call("POST", f"{API}/symbol-detections/review", {"detection_ids": plans["flag"][:1], "action": "relabel",
                                                         "item_type": "floor_box", "apply_to_matches": True,
                                                         "confirm": True}).json()
    assert out["changed"] == 2 and _by_type(call, ps)["floor_box"]["count"] == 2
    add = call("POST", f"{API}/symbol-detections/review", {"action": "add", "sheet_id": plans["sheet_id"],
                                                         "point": [16, 5], "item_type": "duplex_receptacle",
                                                         "confirm": True}).json()
    assert add["detection_id"] and _by_type(call, ps)["duplex_receptacle"]["count"] == 4
    ask = call("POST", f"{API}/symbol-detections/similar", {"detection_id": plans["recept"][0]}).json()
    assert ask["needs_confirmation"] is True and ask["found"] == 0               # all three were found already


def test_review_refusals(call, plans, session_for):                                 # C2S11-W04
    url = f"{API}/symbol-detections/review"
    for role in ("field", "office"):
        assert call("POST", url, {"detection_ids": plans["recept"], "action": "approve", "confirm": True},
                    headers=session_for(role)).status == 403
    assert call("POST", url, {"detection_ids": plans["recept"], "action": "approve", "confirm": True},
                headers=session_for("reviewer")).status == 200
    assert call("POST", url, {"detection_ids": "1,2", "action": "approve"}).status == 400
    assert call("POST", url, {"detection_ids": [True], "action": "approve"}).status == 400
    assert call("POST", url, {"detection_ids": plans["recept"], "action": "explode"}).status == 400
    assert call("POST", url, {"action": "add", "sheet_id": plans["sheet_id"], "point": [1], "item_type": "x"}).status == 400
    assert call("POST", url, {"detection_ids": [999999], "action": "approve", "confirm": True}).status == 404
    assert call("POST", url, {"detection_ids": plans["recept"], "action": "approve", "confirm": True},
                headers=session_for("owner", company="acme")).status == 404
    assert call("POST", f"{API}/symbol-detections/similar", {"box": [1, 2]}).status == 400


def test_thumbnail(call, plans, session_for):                                       # C2S11-W05
    r = call("GET", f"{API}/symbol-detections/{plans['recept'][0]}/crop.png")
    assert r.status == 200 and r.content_type == "image/png" and r.body[:8] == b"\x89PNG\r\n\x1a\n"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert call("GET", f"{API}/symbol-detections/{plans['recept'][0]}/crop.png", headers=session_for("field")).status == 200
    assert call("GET", f"{API}/symbol-detections/{plans['recept'][0]}/crop.png", headers=session_for("office")).status == 403
    assert call("GET", f"{API}/symbol-detections/999999/crop.png").status == 404


# ---------------------------------------------------------------- Symbol Library                  C2S11-W06..W07

def test_symbol_library_list_define_export_import(call, plans, session_for):        # C2S11-W06
    r = call("GET", f"{API}/symbol-library").json()
    assert [lb["level"] for lb in r["libraries"]] == ["company", "standard"] and r["can_define"] is True
    assert "electrical" in r["trades"]
    ask = call("POST", f"{API}/symbol-library/define", {"item_type": "floor_box", "trade": "electrical", "code": "FB",
                                                      "from_detection_ids": plans["flag"]}).json()
    assert ask["needs_confirmation"] is True
    d = call("POST", f"{API}/symbol-library/define", {"item_type": "floor_box", "trade": "electrical", "code": "FB",
                                                    "from_detection_ids": plans["flag"], "confirm": True}).json()["definition"]
    assert d["examples"] == 2 and d["version"] == 1
    lib = call("GET", f"{API}/symbol-library?level=company&trade=electrical").json()["libraries"][0]
    assert lib["by_trade"]["electrical"][0]["item_type"] == "floor_box"
    exp = call("GET", f"{API}/symbol-library/export")
    assert exp.status == 200 and "attachment" in exp.headers["Content-Disposition"]
    data = exp.json()
    assert data["format"] == "ai-prowler-symbol-library"
    acme = session_for("owner", company="acme")
    assert call("POST", f"{API}/symbol-library/import", {"data": data}, headers=acme).json()["needs_confirmation"] is True
    assert call("POST", f"{API}/symbol-library/import", {"data": data, "confirm": True}, headers=acme).json()["imported"] == 1
    assert call("POST", f"{API}/symbol-library/import", {"data": "nope"}).status == 400


def test_symbol_library_roles(call, session_for):                                    # C2S11-W07
    rv = call("GET", f"{API}/symbol-library", headers=session_for("reviewer"))
    assert rv.status == 200
    for role in ("field", "office"):
        assert call("GET", f"{API}/symbol-library", headers=session_for(role)).status == 403
    assert call("POST", f"{API}/symbol-library/define", {"item_type": ""}).status == 400
    assert call("POST", f"{API}/symbol-library/define", {"item_type": "Floor Box!!", "confirm": True}).status == 400


# ---------------------------------------------------------------- Agents                          C2S11-W08..W09

def test_agent_manager_settings_ask_first(call, session_for):                       # C2S11-W08
    r = call("GET", f"{API}/agents").json()
    framing = next(a for a in r["agents"] if a["module_id"] == "framing")
    assert framing["enabled"] is True and r["can_configure"] is True and r["runs"] == []
    ask = call("POST", f"{API}/agents/framing", {"changes": {"confidence_threshold": 90}}).json()
    assert ask["needs_confirmation"] is True and ask["would_change"] == {"confidence_threshold": 90}
    assert call("GET", f"{API}/agents").json()["agents"][[a["module_id"] for a in r["agents"]].index("framing")][
        "confidence_threshold"] == 85
    done = call("POST", f"{API}/agents/framing", {"changes": {"confidence_threshold": 90}, "confirm": True}).json()
    assert done["config"]["confidence_threshold"] == 90 and done["changed"] == {"confidence_threshold": 90}
    est = call("GET", f"{API}/agents", headers=session_for("estimator")).json()
    assert est["can_configure"] is False and est["can_start"] is True
    assert call("POST", f"{API}/agents/framing", {"changes": {"enabled": False}, "confirm": True},
                headers=session_for("estimator")).status == 403
    for role in ("reviewer", "field", "office"):
        assert call("GET", f"{API}/agents", headers=session_for(role)).status == 403
    assert call("POST", f"{API}/agents/framing", {"changes": {"colour": "red"}}).status == 400
    assert call("POST", f"{API}/agents/spaceship", {"changes": {"enabled": False}}).status == 404


def test_takeoff_runs_start_status_retry(call, db):                                 # C2S11-W09
    est = service.create_estimate(db, personal_context(), "Jones house")
    ask = call("POST", f"{API}/runs", {"estimate_id": est["id"], "trades": ["framing", "drywall"]}).json()
    assert ask["needs_confirmation"] is True and "Jones house" in ask["question"]
    run = call("POST", f"{API}/runs", {"estimate_id": est["id"], "trades": ["framing", "drywall"], "confirm": True}).json()
    rid = run["run"]["id"]
    states = {t["module_id"]: t["state"] for t in run["tasks"]}
    assert states == {"framing": "running", "drywall": "queued"}
    listed = call("GET", f"{API}/agents").json()["runs"]
    assert listed[0]["id"] == rid and listed[0]["estimate_title"] == "Jones house" and len(listed[0]["tasks"]) == 2
    st = call("GET", f"{API}/runs/{rid}").json()
    assert st["run"]["id"] == rid and "drywall" in {t["module_id"] for t in st["tasks"]}
    t = st["tasks"][0]["task_id"]
    assert call("POST", f"{API}/runner-tasks/{t}/retry", {}).json()["needs_confirmation"] is True
    assert call("POST", f"{API}/runner-tasks/{t}/retry", {"confirm": True}).status == 400   # running: nothing to retry
    assert call("POST", f"{API}/runs", {"estimate_id": est["id"], "trades": "framing"}).status == 400
    assert call("GET", f"{API}/runs/999999").status == 404


# ---------------------------------------------------------------- the page                        C2S11-W10

def test_screens_are_ready_and_the_page_is_wired():                                  # C2S11-W10
    ready = {s["id"] for s in nav.SCREENS if s["status"] == "ready"}
    assert {"reviews", "symbol_library", "agents"} <= ready
    assert any(p["id"] == "symbol_review" for p in nav.PAGES)
    js = (WEB / "verify.js").read_text(encoding="utf-8")
    for name in ("SCREENS.reviews =", "SCREENS.symbol_library =", "SCREENS.agents =", "PAGES.symbol_review ="):
        assert name in js
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert html.index("review.js") < html.index("verify.js")                       # verify.js uses review.js's pct()
    assert 'style="' not in js and ".style." not in js                             # CSP: no inline styles
