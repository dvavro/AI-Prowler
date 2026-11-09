"""Coder 2 Sprint 10: symbols found from the legend on the plan set page (symbol_detections_list), and the Jobs board
for all lanes (each plans job's progress: plans, symbols, takeoff, runner, reviews)."""
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from estimator.api import router
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf  # noqa: E402
from test_plan_engine_sprint10 import legend, plan, shape  # noqa: E402

API = "/estimator-api"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def plan_set(db, tmp_path, call):
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Smith house")
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("recept", "GFI", "DUPLEX RECEPTACLE, GFCI"),
                     ("flag", None, "SPECIAL DEVICE")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + shape("flag", 12, 8)
    pdf = make_pdf(tmp_path / "power.pdf", [plan(lt + [(7.15, 4.95, 7, "GFI")], lines)])
    ps = store.upload(db, ctx, est["id"], str(pdf), confirm=True)["plan_set_id"]
    assert call("POST", f"{API}/plan-sets/{ps}/process", {"confirm": True}).status == 200
    return {"plan_set_id": ps, "estimate_id": est["id"]}


def test_symbols_with_counts_and_filters(call, plan_set):                           # C2S10-W01
    ps = plan_set["plan_set_id"]
    r = call("GET", f"{API}/plan-sets/{ps}/symbols").json()
    assert r["count"] == 4 and r["can_edit"] is True
    by = {t["item_type"]: t for t in r["counts"]["by_type"]}
    assert by["duplex_receptacle"]["count"] == 2 and by["duplex_receptacle_gfci"]["count"] == 1
    assert by[None]["needs_review"] == 1 and r["counts"]["by_sheet"][0]["sheet_no"] == "E-101"
    d = r["detections"][0]
    assert {"point", "scores", "confidence", "status", "definition_from", "method"} <= set(d)
    assert call("GET", f"{API}/plan-sets/{ps}/symbols?type=duplex_receptacle").json()["count"] == 2
    assert call("GET", f"{API}/plan-sets/{ps}/symbols?review=1").json()["count"] == 1
    assert call("GET", f"{API}/plan-sets/{ps}/symbols?status=approved").json()["count"] == 0
    assert call("GET", f"{API}/plan-sets/{ps}/symbols?limit=1").json()["returned"] == 1
    assert call("GET", f"{API}/plan-sets/{ps}/symbols?status=nope").status == 400


def test_symbols_sit_in_their_trades_layer_in_blueprint_review(call, plan_set, db):  # C2S10-W09
    sheet = store.sheets(db, personal_context(), plan_set["plan_set_id"])["sheets"][0]
    r = call("GET", f"{API}/sheets/{sheet['id']}/objects?kind=symbol").json()
    groups = {o["group"] for o in r["objects"]}
    assert groups == {"electrical"}                      # the legend is an ELECTRICAL LEGEND
    assert {o["symbol"]["item_type"] for o in r["objects"]} == {"duplex_receptacle", "duplex_receptacle_gfci", None}
    assert any(lg["id"] == "electrical" and lg["count"] == 4 for lg in r["layers"])


def test_legends_show_how_many_of_each_were_found(call, plan_set):                  # C2S10-W02
    r = call("GET", f"{API}/plan-sets/{plan_set['plan_set_id']}/legends").json()
    found = {e["description"]: e["found"] for e in r["symbol_dictionary"]}
    assert found == {"DUPLEX RECEPTACLE": 2, "DUPLEX RECEPTACLE, GFCI": 1, "SPECIAL DEVICE": 1}


def test_symbols_roles_and_errors(call, plan_set, session_for):                     # C2S10-W03
    ps = plan_set["plan_set_id"]
    for role in ("reviewer", "field"):
        got = call("GET", f"{API}/plan-sets/{ps}/symbols", headers=session_for(role)).json()
        assert got["count"] == 4 and got["can_edit"] is False
    assert call("GET", f"{API}/plan-sets/{ps}/symbols", headers=session_for("office")).status == 403
    assert call("GET", f"{API}/plan-sets/{ps}/symbols", headers=session_for("owner", company="acme")).status == 404
    assert call("GET", f"{API}/plan-sets/999/symbols").status == 404


def _job(db, estimate_id, lane, stage, waiting_on="user"):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return db.execute("INSERT INTO director_jobs (company_id, estimate_id, lane, stage, state, waiting_on, request_text,"
                      " created_at, updated_at) VALUES ('default', ?, ?, ?, 'waiting_on_user', ?, ?, ?, ?)",
                      (estimate_id, lane, stage, waiting_on, f"{lane} job", now, now)).lastrowid


def test_jobs_board_shows_each_plans_jobs_progress(call, plan_set, db):             # C2S10-W04
    ctx = personal_context()
    eid = plan_set["estimate_id"]
    sheet = store.sheets(db, ctx, plan_set["plan_set_id"])["sheets"][0]
    sym = store.objects(db, ctx, sheet_id=sheet["id"], kind="symbol")["objects"]
    jid = _job(db, eid, "full_takeoff", "takeoff")
    other = service.create_estimate(db, ctx, "Fence")
    _job(db, other["id"], "quick_quote", "approve", waiting_on="customer")
    db.commit()
    b = call("GET", f"{API}/jobs").json()
    assert b["summary"]["by_lane"] == {"full_takeoff": 1, "quick_quote": 1}
    assert b["summary"]["waiting"] == {"you": 1, "customer": 1, "others": 0}
    assert b["links"] == {"plans": True, "takeoffs": True, "estimates": True}
    row = next(r for r in b["by_lane"]["full_takeoff"] if r["id"] == jid)
    p = row["progress"]
    assert p["plans"]["plan_sets"] == 1 and p["plans"]["processed"] == 1 and p["plans"]["sheets"] == 1
    assert p["symbols"] == {"found": len(sym), "to_check": 1, "approved": 0}
    assert p["step"] == {"number": 3, "of": 8, "label": "Run the trade takeoffs", "next": "Price approved quantities"}
    quick = b["by_lane"]["quick_quote"][0]
    assert "plans" not in quick["progress"] and quick["progress"]["step"]["label"]


def test_jobs_board_counts_measurements_and_runner_tasks(call, plan_set, db):      # C2S10-W05
    eid = plan_set["estimate_id"]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for status, sug in (("approved", None), ("approved", "12"), ("proposed", None)):
        db.execute("INSERT INTO measurements (company_id, estimate_id, kind, qty, unit, method, status, suggested_qty,"
                   " proposed_by, created_at, updated_at) VALUES ('default', ?, 'count', '1', 'ea', 'manual', ?, ?, 'owner', ?, ?)",
                   (eid, status, sug, now, now))
    run = db.execute("INSERT INTO runs (company_id, estimate_id, state, started_by, created_at, updated_at)"
                     " VALUES ('default', ?, 'running', 'owner', ?, ?)", (eid, now, now)).lastrowid
    for i, (mod, state) in enumerate((("electrical", "completed"), ("plumbing", "needs_review"), ("hvac", "queued"))):
        db.execute("INSERT INTO takeoff_tasks (company_id, run_id, estimate_id, module_id, position, state, updated_at)"
                   " VALUES ('default', ?, ?, ?, ?, ?, ?)", (run, eid, mod, i, state, now))
    _job(db, eid, "full_takeoff", "review")
    db.commit()
    p = call("GET", f"{API}/jobs").json()["by_lane"]["full_takeoff"][0]["progress"]
    assert p["takeoff"] == {"approved": 2, "proposed": 1, "rejected": 0, "suggested": 1}
    assert p["runner"]["trades"] == 3 and p["runner"]["completed"] == 1 and p["runner"]["needs_review"] == 1


def test_board_links_follow_the_role(call, plan_set, db, session_for):              # C2S10-W06
    _job(db, plan_set["estimate_id"], "full_takeoff", "read_plans")
    db.commit()
    field = call("GET", f"{API}/jobs", headers=session_for("field")).json()
    assert field["links"]["takeoffs"] is False and field["links"]["plans"] is True


def test_symbols_guide_names_what_is_on_the_page():                                  # C2S10-W08
    from estimator.ui import help as guides
    g = guides.get_guide("count_symbols_from_the_legend")
    assert g["screen"] == "plans" and g["steps"] >= 5
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for label in ("📖 Read the plans…", "Symbols found from the legend", "to check", "needs a person", "Found", "Legends"):
        assert label in js and label in g["text"], label


def test_pages_have_the_sprint10_parts():                                           # C2S10-W07
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for needle in ("/symbols", "symbolCounts", "Symbols found from the legend", "jobProgress", "jobs-summary",
                   "waiting on you", "#/takeoffs/", "need a scale", "trade(s) done"):
        assert needle in js, needle
    assert "innerHTML" not in js and "setAttribute(\"style\"" not in js
