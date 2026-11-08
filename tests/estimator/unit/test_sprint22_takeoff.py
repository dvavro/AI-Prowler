"""Sprint 22 (Coder 1 part of planned Sprint 6, Phase 2): measurements, the approval lock and the takeoff_* tools
(S22-..). A roof plan is saved through the drawing model (as the plan engine would), then measured, approved,
suggested, re-scaled, re-read and handed to the Estimate Runner.
"""
import json
from decimal import Decimal

import pytest

from estimator.context import RequestContext, personal_context
from estimator.drawing_model import store
from estimator.errors import ConfirmationRequired, InvalidInput, NotEditable, NotFound, PermissionDenied
from estimator.estimating import service, validate
from estimator.mcp_tools import est_tools as t
from estimator.runner import runner
from estimator.takeoff import measurements as m

CTX = personal_context()
AGENT = RequestContext(role="estimator", agent="agent:takeoff")
FIELD = RequestContext(user_id="fred", role="field")
REVIEWER = RequestContext(user_id="rita", role="reviewer")
OTHER = RequestContext(company_id="other-co", user_id="zed", role="owner")


def j(text):
    return json.loads(text)


def ROOF():
    poly = lambda x0, x1: {"type": "polygon", "points": [[x0, 0], [x1, 0], [x1, 4], [x0, 4]]}
    return {"sheets": [{
        "page_no": 1, "sheet_no": "A-301", "title": "ROOF PLAN", "discipline": "roof", "units": "paper_in",
        "viewports": [{"key": "roof", "label": "ROOF PLAN", "scale_note": "1/8\" = 1'-0\""},       # 1 in = 8 ft
                      {"key": "detail", "label": "DETAIL"}],                                       # no scale
        "objects": [
            {"viewport": "roof", "kind": "polygon", "label": "MAIN ROOF", "geometry": poly(0, 5), "source": "vector",
             "confidence": 0.95, "layer": "A-ROOF"},                                 # 40 x 32 ft = 1280 sq ft
            {"viewport": "roof", "kind": "polygon", "label": "GARAGE ROOF", "geometry": poly(5, 7.5),
             "source": "vector", "confidence": 0.8, "layer": "A-ROOF"},             # 20 x 32 ft = 640 sq ft
            {"viewport": "roof", "kind": "line", "label": "EAVE", "source": "vector", "confidence": 0.9,
             "geometry": {"type": "line", "points": [[0, 0], [5, 0]]}},              # 40 ft
            {"viewport": "roof", "kind": "line", "label": "RIDGE", "source": "vector",
             "geometry": {"type": "line", "points": [[0, 2], [2.5, 2]]}},            # 20 ft
            {"viewport": "roof", "kind": "symbol", "label": "VENT", "source": "vector",
             "geometry": {"type": "point", "points": [[1, 1]]}},
            {"viewport": "roof", "kind": "symbol", "label": "VENT", "source": "vector",
             "geometry": {"type": "point", "points": [[2, 1]]}},
            {"viewport": "detail", "kind": "polygon", "label": "CRICKET", "geometry": poly(0, 1), "source": "vector"},
        ]}]}


@pytest.fixture
def roof(db, tmp_path):
    est = service.create_estimate(db, CTX, "Miller roof")
    pdf = tmp_path / "roof.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%%EOF\n")
    ps = store.upload(db, CTX, est["id"], str(pdf), confirm=True)["plan_set_id"]
    store.save_results(db, CTX, ps, ROOF(), "fake")
    objs = {}
    for o in store.objects(db, CTX, plan_set_id=ps)["objects"]:
        objs.setdefault(o["label"], []).append(o["id"])
    return {"est": est["id"], "ps": ps, "o": objs}


def _approved(db, roof, ids, feeds="roof_area_sqft"):
    out = m.propose(db, CTX, roof["est"], "roofing", ids, feeds=feeds, confirm=True)
    mid = out["proposed"][0]["id"]
    m.confirm_measurements(db, CTX, [mid], confirm=True)
    return mid


# ---------------------------------------------------------------- proposing

def test_propose_from_drawing_objects(db, roof):  # S22-P01
    ids = roof["o"]["MAIN ROOF"] + roof["o"]["GARAGE ROOF"]
    with pytest.raises(ConfirmationRequired) as ask:
        m.propose(db, AGENT, roof["est"], "roofing", ids, feeds="roof_area_sqft")
    assert ask.value.details["total"] == "1920.00" and ask.value.details["unit"] == "sqft"
    out = m.propose(db, AGENT, roof["est"], "roofing", ids, feeds="roof_area_sqft", label="whole roof", confirm=True)
    p = out["proposed"][0]
    assert p["qty"] == "1920.00" and p["kind"] == "area" and p["status"] == "proposed" and not p["locked"]
    assert p["method"] == "vector" and p["confidence"] == "0.8" and p["proposed_by"] == "agent:takeoff"
    assert sorted(p["source_object_ids"]) == sorted(ids)
    eave = m.propose(db, CTX, roof["est"], "roofing", roof["o"]["EAVE"], feeds="edges_lf", confirm=True)
    assert eave["proposed"][0]["qty"] == "40.00" and eave["proposed"][0]["unit"] == "lf"
    vents = m.propose(db, CTX, roof["est"], "roofing", roof["o"]["VENT"], kind="count", confirm=True)
    assert vents["proposed"][0]["qty"] == "2.00" and vents["proposed"][0]["unit"] == "ea"
    each = m.propose(db, CTX, roof["est"], "roofing", ids, feeds="roof_area_sqft", one_per_object=True, confirm=True)
    assert sorted(x["qty"] for x in each["proposed"]) == ["1280.00", "640.00"]
    perim = m.propose(db, CTX, roof["est"], "roofing", roof["o"]["MAIN ROOF"], kind="perimeter", confirm=True)
    assert perim["proposed"][0]["qty"] == "144.00"                                  # 2 x (40 + 32)


def test_propose_refusals(db, roof):  # S22-P02
    main = roof["o"]["MAIN ROOF"]
    with pytest.raises(InvalidInput) as unscaled:
        m.propose(db, CTX, roof["est"], "roofing", roof["o"]["CRICKET"], confirm=True)
    assert "plan_set_scale" in unscaled.value.message
    with pytest.raises(InvalidInput):
        m.propose(db, CTX, roof["est"], "roofing", main, feeds="no_such_question", confirm=True)
    with pytest.raises(InvalidInput):                                               # a length can't fill an area
        m.propose(db, CTX, roof["est"], "roofing", roof["o"]["EAVE"], feeds="roof_area_sqft", confirm=True)
    with pytest.raises(InvalidInput):
        m.propose(db, CTX, roof["est"], "roofing", main, feeds="pitch", confirm=True)     # not a number question
    with pytest.raises(InvalidInput):
        m.propose(db, CTX, roof["est"], "teleporting", main, confirm=True)
    with pytest.raises(InvalidInput):
        m.propose(db, CTX, roof["est"], "roofing", main + roof["o"]["EAVE"], confirm=True)    # mixed shapes
    with pytest.raises(PermissionDenied):
        m.propose(db, FIELD, roof["est"], "roofing", main, confirm=True)
    with pytest.raises(NotFound):
        m.propose(db, CTX, roof["est"], "roofing", [999999], confirm=True)
    with pytest.raises(Exception):
        m.propose(db, OTHER, roof["est"], "roofing", main, confirm=True)
    assert db.execute("SELECT COUNT(*) FROM measurements").fetchone()[0] == 0


# ---------------------------------------------------------------- approving and the lock

def test_only_a_person_approves(db, roof):  # S22-C01
    out = m.propose(db, AGENT, roof["est"], "roofing", roof["o"]["MAIN ROOF"] + roof["o"]["GARAGE ROOF"],
                    feeds="roof_area_sqft", one_per_object=True, confirm=True)
    ids = [p["id"] for p in out["proposed"]]
    with pytest.raises(PermissionDenied):
        m.confirm_measurements(db, AGENT, ids, confirm=True)
    with pytest.raises(PermissionDenied):
        m.confirm_measurements(db, FIELD, ids, confirm=True)
    with pytest.raises(ConfirmationRequired):
        m.confirm_measurements(db, REVIEWER, ids)
    bulk = m.confirm_measurements(db, REVIEWER, estimate_id=roof["est"], module_id="roofing", above_confidence="0.9",
                                  confirm=True)
    assert len(bulk["done"]) == 1                                                   # only the 0.95 one
    row = m._load(db, CTX, bulk["done"][0])
    assert row["status"] == "approved" and row["locked"] and row["approved_by"] == "rita"
    rest = m.confirm_measurements(db, CTX, ids, confirm=True)
    assert rest["skipped"] == bulk["done"] and len(rest["done"]) == 1
    with pytest.raises(InvalidInput):
        m.confirm_measurements(db, CTX, ids, confirm=True)                          # nothing left to approve


def test_approved_is_locked_against_agents(db, roof):  # S22-C02
    mid = _approved(db, roof, roof["o"]["MAIN ROOF"])
    with pytest.raises(NotEditable) as locked:
        m.edit(db, AGENT, mid, qty="1300", confirm=True)
    assert "takeoff_suggest_change" in locked.value.message
    with pytest.raises(NotEditable):
        m.reject(db, AGENT, mid, "wrong", confirm=True)
    with pytest.raises(InvalidInput):
        m.suggest_change(db, AGENT, mid, "1300", "", confirm=True)                 # needs a reason
    m.suggest_change(db, AGENT, mid, "1300", "overhang missed", confirm=True)
    row = m._load(db, CTX, mid)
    assert row["qty"] == "1280.00" and row["suggested_qty"] == "1300.00"            # never overwritten
    with pytest.raises(PermissionDenied):
        m.confirm_measurements(db, AGENT, [mid], accept_suggestion=True, confirm=True)
    m.confirm_measurements(db, CTX, [mid], accept_suggestion=True, confirm=True)
    row = m._load(db, CTX, mid)
    assert row["qty"] == "1300.00" and row["suggested_qty"] is None and row["locked"]
    out = m.edit(db, CTX, mid, qty="1290", confirm=True)                            # a person may correct it
    assert out["measurement"]["qty"] == "1290.00" and out["measurement"]["locked"]
    m.reject(db, CTX, mid, "double counted", confirm=True)
    row = m._load(db, CTX, mid)
    assert row["status"] == "rejected" and row["reject_reason"] == "double counted"
    with pytest.raises(NotEditable):
        m.edit(db, CTX, mid, qty="1", confirm=True)
    proposed = m.propose(db, CTX, roof["est"], "roofing", roof["o"]["EAVE"], feeds="edges_lf", confirm=True)
    with pytest.raises(InvalidInput):
        m.suggest_change(db, CTX, proposed["proposed"][0]["id"], "41", "x", confirm=True)   # not approved yet


def test_manual_measurements(db, roof):  # S22-M01
    typed = m.manual(db, CTX, roof["est"], "roofing", feeds="ridge_lf", qty="22.5", unit="lf", approve=True,
                     confirm=True)["measurement"]
    assert typed["qty"] == "22.50" and typed["status"] == "approved" and typed["method"] == "typed"
    vp = store.viewports(db, CTX, store.sheets(db, CTX, roof["ps"])["sheets"][0]["id"])["viewports"]
    roof_vp = next(v["id"] for v in vp if v["label"] == "ROOF PLAN")
    detail_vp = next(v["id"] for v in vp if v["label"] == "DETAIL")
    drawn = m.manual(db, CTX, roof["est"], "roofing", feeds="roof_area_sqft", viewport_id=roof_vp,
                     geometry={"type": "polygon", "points": [[0, 0], [1, 0], [1, 1], [0, 1]]}, confirm=True)
    assert drawn["measurement"]["qty"] == "64.00" and drawn["measurement"]["method"] == "manual"   # 8 x 8 ft
    assert drawn["measurement"]["status"] == "proposed"
    with pytest.raises(InvalidInput):
        m.manual(db, CTX, roof["est"], "roofing", viewport_id=detail_vp,
                 geometry={"type": "polygon", "points": [[0, 0], [1, 0], [1, 1]]}, confirm=True)
    with pytest.raises(InvalidInput):
        m.manual(db, CTX, roof["est"], "roofing", feeds="edges_lf", qty="10", unit="sqft", confirm=True)
    with pytest.raises(InvalidInput):
        m.manual(db, CTX, roof["est"], "roofing", feeds="edges_lf", qty="-3", unit="lf", confirm=True)
    with pytest.raises(InvalidInput):
        m.manual(db, CTX, roof["est"], "roofing", qty="3", confirm=True)                 # no unit
    with pytest.raises(PermissionDenied):
        m.manual(db, AGENT, roof["est"], "roofing", feeds="ridge_lf", qty="5", unit="lf", approve=True, confirm=True)


# ---------------------------------------------------------------- reading and pricing

def test_list_and_approved_answers(db, roof):  # S22-L01
    _approved(db, roof, roof["o"]["MAIN ROOF"])
    _approved(db, roof, roof["o"]["GARAGE ROOF"])
    _approved(db, roof, roof["o"]["EAVE"], feeds="edges_lf")
    low = m.propose(db, AGENT, roof["est"], "roofing", roof["o"]["RIDGE"], feeds="ridge_lf", confidence="0.4",
                    confirm=True)["proposed"][0]["id"]
    high = m.propose(db, AGENT, roof["est"], "roofing", roof["o"]["VENT"], kind="count", confidence="0.7",
                     confirm=True)["proposed"][0]["id"]
    out = m.list_measurements(db, CTX, roof["est"])
    assert out["counts"] == {"proposed": 2, "approved": 3, "rejected": 0}
    assert out["review_queue"] == [low, high]
    assert out["approved_answers"] == {"roofing": {"roof_area_sqft": 1920.0, "edges_lf": 40.0}}
    assert m.list_measurements(db, CTX, roof["est"], status="proposed")["count"] == 2
    with pytest.raises(InvalidInput):
        m.list_measurements(db, CTX, roof["est"], status="maybe")


def test_runner_takes_approved_measurements(db, roof):  # S22-R01
    run = runner.start_run(db, CTX, roof["est"], ["roofing"])
    task = run["tasks"][0]["task_id"]
    with pytest.raises(InvalidInput):
        runner.submit_takeoff(db, CTX, task, from_measurements=True)               # nothing approved yet
    _approved(db, roof, roof["o"]["MAIN ROOF"] + roof["o"]["GARAGE ROOF"])
    _approved(db, roof, roof["o"]["EAVE"], feeds="edges_lf")
    m.propose(db, CTX, roof["est"], "roofing", roof["o"]["RIDGE"], feeds="ridge_lf", confirm=True)   # not approved
    out = runner.submit_takeoff(db, CTX, task, {"pitch": "6/12", "material": "architectural"},
                                from_measurements=True, confidence=90)
    t_row = runner._load_task(db, CTX, task)
    assert t_row["proposed"]["roof_area_sqft"] == 1920.0 and t_row["proposed"]["edges_lf"] == 40.0
    assert "ridge_lf" not in t_row["proposed"]                                      # proposed ones aren't priced
    assert out["ok"]


def test_scale_change_updates_or_suggests(db, roof):  # S22-S01
    approved = _approved(db, roof, roof["o"]["MAIN ROOF"])
    proposed = m.propose(db, CTX, roof["est"], "roofing", roof["o"]["GARAGE ROOF"], feeds="roof_area_sqft",
                         confirm=True)["proposed"][0]["id"]
    sheet = store.sheets(db, CTX, roof["ps"])["sheets"][0]["id"]
    roof_vp = next(v["id"] for v in store.viewports(db, CTX, sheet)["viewports"] if v["label"] == "ROOF PLAN")
    out = store.set_scale(db, CTX, roof_vp, scale_note="1/4\" = 1'-0\"", confirm=True)   # 1 in = 4 ft now
    assert out["measurements"] == {"updated": 1, "suggested": 1, "flagged": 0}
    assert m._load(db, CTX, proposed)["qty"] == "160.00"                            # 10 x 16 ft
    a = m._load(db, CTX, approved)
    assert a["qty"] == "1280.00" and a["suggested_qty"] == "320.00" and "scale" in a["suggested_reason"]
    out = store.set_scale(db, CTX, roof_vp, scale_note="NTS", confirm=True)
    assert out["measurements"]["flagged"] == 2 and m._load(db, CTX, approved)["needs_remeasure"]


def test_reread_plans_never_loses_approved(db, roof):  # S22-S02
    approved = _approved(db, roof, roof["o"]["MAIN ROOF"])
    proposed = m.propose(db, CTX, roof["est"], "roofing", roof["o"]["EAVE"], feeds="edges_lf",
                         confirm=True)["proposed"][0]["id"]
    out = store.save_results(db, CTX, roof["ps"], ROOF(), "fake")
    assert out["measurements"] == {"rejected": 1, "flagged": 1}
    a, p = m._load(db, CTX, approved), m._load(db, CTX, proposed)
    assert a["status"] == "approved" and a["qty"] == "1280.00" and a["needs_remeasure"]
    assert p["status"] == "rejected" and "read again" in p["reject_reason"]
    d = m.detail(db, CTX, approved)
    assert d["calc"]["sheets"][0]["sheet_no"] == "A-301"   # where it came from is kept
    assert m.list_measurements(db, CTX, roof["est"])["needs_remeasure"] == [approved]


def test_detail_and_validate(db, roof):  # S22-D01
    mid = _approved(db, roof, roof["o"]["MAIN ROOF"])
    m.suggest_change(db, AGENT, mid, "1300", "overhang", confirm=True)
    m.propose(db, CTX, roof["est"], "roofing", roof["o"]["EAVE"], feeds="edges_lf", confirm=True)
    d = m.detail(db, CTX, mid)
    assert d["viewport"]["scale_ratio"] == "96" and d["sheet"]["sheet_no"] == "A-301"
    assert d["source_objects"][0]["real_units"]["area_sqft"] == "1280.00"
    assert [h["action"] for h in d["history"]] == ["measurement_proposed", "measurement_approved",
                                                   "measurement_change_suggested"]
    codes = {f["code"] for f in validate.validate(db, CTX, roof["est"])["findings"]}
    assert {"measurements_waiting", "measurements_suggested"} <= codes


def test_takeoff_tools(db, roof):  # S22-T01
    ids = roof["o"]["MAIN ROOF"] + roof["o"]["GARAGE ROOF"]
    assert j(t.takeoff_propose(roof["est"], "roofing", ids, feeds="roof_area_sqft"))["error"] == "needs_confirmation"
    mid = j(t.takeoff_propose(roof["est"], "roofing", ",".join(map(str, ids)), feeds="roof_area_sqft",
                              confirm=True))["proposed"][0]["id"]
    assert j(t.takeoff_confirm(str(mid), confirm=True))["done"] == [mid]
    assert j(t.takeoff_list(roof["est"]))["approved_answers"]["roofing"]["roof_area_sqft"] == 1920.0
    assert j(t.takeoff_suggest_change(mid, "1950", "valley", confirm=True))["measurement"]["suggested_qty"] == \
        "1950.00"
    assert j(t.takeoff_detail(mid))["measurement"]["id"] == mid
    typed = j(t.takeoff_manual(roof["est"], "roofing", feeds="ridge_lf", qty="20", unit="lf", confirm=True))
    tid = typed["measurement"]["id"]
    assert j(t.takeoff_edit(tid, qty="21", confirm=True))["measurement"]["qty"] == "21.00"
    assert j(t.takeoff_delete(tid, "duplicate", confirm=True))["measurement"]["status"] == "rejected"
    run = runner.start_run(db, CTX, roof["est"], ["roofing"])
    out = j(t.runner_submit_takeoff(run["tasks"][0]["task_id"], '{"pitch": "6/12", "material": "architectural"}',
                                    from_measurements=True))
    assert out.get("ok") is not False, out
    bad = {"takeoff_propose": (999, "roofing", "1"), "takeoff_manual": (999, "roofing"), "takeoff_list": (999,),
           "takeoff_confirm": (), "takeoff_edit": (999,), "takeoff_delete": (999,), "takeoff_detail": (999,),
           "takeoff_suggest_change": (999, "1", "x")}
    for name, args in bad.items():
        res = j(getattr(t, name)(*args))
        assert res["ok"] is False and res["error"] and res["message"], (name, res)
