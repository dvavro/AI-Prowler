"""Coder 1 Sprint 25: plan quantities into takeoffs and the Runner, symbol counts into takeoff_propose, the design
firm on plan sets, and the Estimates screen's assemblies and line edits (est_get_assemblies, est_apply_assembly,
est_update_line_item, est_add_trade, est_remove_trade)."""
import json
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from estimator.context import RequestContext, personal_context
from estimator.drawing_model import engine, store
from estimator.errors import ConfirmationRequired, InvalidInput, NotFound, PermissionDenied, StaleRevision
from estimator.estimating import assemblies, quick, service
from estimator.runner import runner
from estimator.takeoff import from_plans
from estimator.takeoff import measurements as takeoffs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plan_engine"))
from pdfmaker import make_pdf, title_block  # noqa: E402

CTX = personal_context()
FIELD = RequestContext(user_id="fred", role="field")
REVIEWER = RequestContext(user_id="rita", role="reviewer")
QUARTER = 'SCALE: 1/4" = 1\'-0"'


def rect(x0, y0, x1, y1):
    return [(x0, y0, x1, y0), (x1, y0, x1, y1), (x1, y1, x0, y1), (x0, y1, x0, y0)]


# David's Sprint 12 test house: LIVING 10 x 12 ft and BEDROOM 9.5 x 12 ft at 1/4" = 1'-0", 2 doors and a window.
HOUSE = rect(5, 5, 10.25, 8.25) + rect(5.125, 5.125, 7.625, 8.125) + rect(7.75, 5.125, 10.125, 8.125)
NAMES = [(5.8, 6.5, 10, "LIVING"), (8.3, 6.5, 10, "BEDROOM")]
SCHEDULES = [(20, 2.0, 12, "DOOR SCHEDULE"), (20, 2.5, 8, "MARK"), (21.5, 2.5, 8, "SIZE"), (23, 2.5, 8, "TYPE"),
             (20, 2.8, 8, "D1"), (21.5, 2.8, 8, "3070"), (23, 2.8, 8, "A"),
             (20, 3.1, 8, "D2"), (21.5, 3.1, 8, "2868"), (23, 3.1, 8, "B"),
             (20, 5.0, 12, "WINDOW SCHEDULE"), (20, 5.5, 8, "MARK"), (21.5, 5.5, 8, "WIDTH"), (23, 5.5, 8, "HEIGHT"),
             (20, 5.8, 8, "W1"), (21.5, 5.8, 8, '4\'-0"'), (23, 5.8, 8, '3\'-0"')]
TAGS = [(6.2, 7.95, 9, "D1"), (7.6, 7.0, 9, "D2"), (9.85, 6.0, 9, "W1")]


def page():
    t = title_block("A-101", "FIRST FLOOR PLAN") + [(4, 21, 14, "FLOOR PLAN"), (4, 21.35, 9, QUARTER)]
    return {"w": 36, "h": 24, "texts": t + NAMES + SCHEDULES + TAGS, "lines": HOUSE}


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def house(db, tmp_path):
    pytest.importorskip("shapely")
    est = service.create_estimate(db, CTX, "Smith house")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "house.pdf", [page()])), confirm=True,
                      design_firm="Hart Architects")["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    return {"estimate_id": est["id"], "plan_set_id": ps, "tmp": tmp_path}


def plain_estimate(db, title="Hand job"):
    return service.create_estimate(db, CTX, title)["id"]


def plan_set_row(db, estimate_id, tmp_path, name="e.pdf", **kw):
    return store.upload(db, CTX, estimate_id, str(make_pdf(tmp_path / name, [page()])), confirm=True, **kw)


def add_symbols(db, ps_id, rows):
    """rows: (item_type, trade, status, count). Straight into symbol_detections, like the engine leaves them."""
    sheet = db.execute("SELECT id FROM sheets WHERE plan_set_id = ? ORDER BY id LIMIT 1", (ps_id,)).fetchone()["id"]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with service.transaction(db):
        for it, tr, st, n in rows:
            for _ in range(n):
                db.execute("INSERT INTO symbol_detections (company_id, plan_set_id, sheet_id, item_type, trade,"
                           " location_json, method, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                           (CTX.company_id, ps_id, sheet, it, tr, '{"x": 1, "y": 1}', "vector", st, now))


def meas(db, eid, module_id):
    return {m["feeds"]: m for m in takeoffs.list_measurements(db, CTX, eid, module_id)["measurements"]}


def rev(db, eid):
    return service.get_estimate(db, CTX, eid)["rev"]


# ---------------------------------------------------------------- measurements from the plans      S25-P01..P04

def test_plan_answers_become_proposed_measurements(db, house):                     # S25-P01
    eid = house["estimate_id"]
    with pytest.raises(ConfirmationRequired) as ask:
        from_plans.propose(db, CTX, eid, "flooring")
    d = ask.value.details
    assert "area_sqft" in str(d["measurements"]) and d["counts"]["new"] == 2
    assert "Floor area: 234.00 sqft" in ask.value.message
    out = from_plans.propose(db, CTX, eid, "flooring", confirm=True)
    assert out["counts"]["new"] == 2 and out["source"] == "wall-and-room model"
    m = meas(db, eid, "flooring")
    assert m["area_sqft"]["qty"] == "234.00" and m["area_sqft"]["status"] == "proposed"
    assert m["area_sqft"]["kind"] == "area" and m["baseboard_lf"]["kind"] == "length"
    row = db.execute("SELECT calc_json, method, proposed_by FROM measurements WHERE id = ?",
                     (m["area_sqft"]["id"],)).fetchone()
    calc = json.loads(row["calc_json"])
    assert calc["from"] == "plans" and calc["how"] == "room floor areas" and calc["plan_set_ids"] == [house["plan_set_id"]]
    assert row["method"] == "vector"
    assert takeoffs.approved_answers(db, CTX, eid, "flooring") == {}            # proposed: never priced
    again = from_plans.propose(db, CTX, eid, "flooring")                        # same numbers: nothing to ask
    assert again["counts"]["unchanged"] == 2 and again["measurements"] == []
    # Coder 2 Sprint 14's plan trades go the same way: counts from the schedules, choices returned, not measured
    wd = from_plans.propose(db, CTX, eid, "windows_doors", confirm=True)
    assert {m["feeds"]: m["qty"] for m in wd["measurements"]} == {"windows_small": "1.00", "exterior_doors": "1.00",
                                                                  "interior_doors": "1.00"}
    sd = from_plans.propose(db, CTX, eid, "siding", confirm=True)
    assert sd["choices"] == {"stories": "one", "walls": "simple"} and "wall_sqft" in meas(db, eid, "siding")


def test_re_running_updates_proposed_and_suggests_on_approved(db, house):           # S25-P02
    eid = house["estimate_id"]
    from_plans.propose(db, CTX, eid, "painting", confirm=True)
    m = meas(db, eid, "painting")
    first = m["wall_sqft"]["qty"]
    out = from_plans.propose(db, CTX, eid, "painting", height_ft=9, confirm=True)
    # wall faces and (Coder 2 Sprint 14) the outside walls both scale with the height; ceilings, doors and trim don't
    assert out["counts"]["update"] == 2 and out["counts"]["unchanged"] == 3
    m = meas(db, eid, "painting")
    assert m["wall_sqft"]["status"] == "proposed" and m["wall_sqft"]["qty"] != first
    assert len(meas(db, eid, "painting")) == 5                                  # still one per question
    takeoffs.confirm_measurements(db, CTX, [m["wall_sqft"]["id"]], confirm=True)
    nine = m["wall_sqft"]["qty"]
    out = from_plans.propose(db, CTX, eid, "painting", height_ft=10, confirm=True)
    assert out["counts"]["suggest"] == 1 and out["counts"]["update"] == 1      # the approved one vs the proposed one
    w = meas(db, eid, "painting")["wall_sqft"]
    assert w["status"] == "approved" and w["qty"] == nine and w["suggested_qty"] not in (None, nine)
    assert "the plans now give" in w["suggested_reason"]
    out = from_plans.propose(db, CTX, eid, "painting", height_ft=10)            # same suggestion again: nothing to do
    assert out["counts"]["same_suggestion"] == 1 and out["measurements"] == []
    takeoffs.reject(db, CTX, m["ceiling_sqft"]["id"], "measured by hand", confirm=True)
    out = from_plans.propose(db, CTX, eid, "painting", height_ft=10)
    assert out["counts"]["rejected_before"] == 1
    events = [r["action"] for r in db.execute("SELECT action FROM estimate_events WHERE estimate_id = ?", (eid,))]
    assert {"measurement_proposed", "measurement_updated", "measurement_change_suggested"} <= set(events)


def test_symbol_counts_into_measurements(db, house):                               # S25-P03
    eid, ps = house["estimate_id"], house["plan_set_id"]
    add_symbols(db, ps, [("duplex_receptacle", "electrical", "approved", 2), ("duplex_receptacle", "electrical",
                                                                              "proposed", 1),
                         ("switch", "electrical", "rejected", 1), ("water_closet", "plumbing", "approved", 1),
                         ("water_heater", "plumbing", "approved", 1)])
    out = from_plans.propose(db, CTX, eid, "electrical", confirm=True)
    assert out["source"] == "symbols counted on the plans" and any("still to check" in n for n in out["notes"])
    e = meas(db, eid, "electrical")
    assert set(e) == {"outlets"} and e["outlets"]["qty"] == "2.00" and e["outlets"]["kind"] == "count"
    calc = json.loads(db.execute("SELECT calc_json FROM measurements WHERE id = ?",
                                 (e["outlets"]["id"],)).fetchone()[0])
    assert len(calc["symbol_detection_ids"]) == 2 and calc["include_proposed_symbols"] is False
    out = from_plans.propose(db, CTX, eid, "electrical", include_proposed=True, confirm=True)
    assert out["counts"]["update"] == 1 and meas(db, eid, "electrical")["outlets"]["qty"] == "3.00"
    p = from_plans.propose(db, CTX, eid, "plumbing", confirm=True)
    assert p["choices"] == {"water_heater": "tank"} and set(meas(db, eid, "plumbing")) == {"toilets"}


def test_refusals(db, house, tmp_path):                                            # S25-P04
    eid = house["estimate_id"]
    with pytest.raises(PermissionDenied):
        from_plans.propose(db, FIELD, eid, "flooring")
    with pytest.raises(InvalidInput):
        from_plans.propose(db, CTX, eid, "roofing")                              # the plans don't answer roofing
    with pytest.raises(InvalidInput):
        from_plans.propose(db, CTX, eid, "electrical")                           # no approved symbols yet
    other = plain_estimate(db)
    with pytest.raises(InvalidInput):
        from_plans.propose(db, CTX, other, "flooring", plan_set_id=house["plan_set_id"])
    from estimator.mcp_tools import est_tools as t
    bad = json.loads(t.takeoff_propose(eid, "flooring", object_ids="[1]", from_plans=True))
    assert bad["error"] == "invalid_input"
    asks = json.loads(t.takeoff_propose(eid, "flooring", from_plans=True))
    assert asks["error"] == "needs_confirmation" and asks["counts"]["new"] == 2


# ---------------------------------------------------------------- the Runner                       S25-R01..R02

def test_runner_takes_trades_from_the_plans(db, house):                            # S25-R01
    eid = house["estimate_id"]
    run = runner.start_run(db, CTX, eid, ["flooring", "electrical", "roofing"])
    tasks = {t["module_id"]: t for t in run["tasks"]}
    assert "from_plans=true" in tasks["flooring"]["next"] and "from_plans" not in tasks["roofing"]["next"]
    with pytest.raises(InvalidInput) as e:                                       # flooring needs its material too
        runner.submit_takeoff(db, CTX, tasks["flooring"]["task_id"], from_plans=True)
    assert "material" in e.value.message
    out = runner.submit_takeoff(db, CTX, tasks["flooring"]["task_id"], {"material": "lvp"}, from_plans=True)
    assert out["task"]["state"] == "needs_review" and out["task"]["proposed"]["area_sqft"] == 234.0
    assert out["task"]["proposed"]["material"] == "lvp" and "from the plans" in out["task"]["note"]
    with pytest.raises(InvalidInput):
        runner.submit_takeoff(db, CTX, tasks["roofing"]["task_id"], from_plans=True)
    # approved measurements win over the plans' numbers; answers given win over both
    takeoffs.manual(db, CTX, eid, "flooring", feeds="area_sqft", qty="240", unit="sqft", approve=True, confirm=True)
    out = runner.submit_takeoff(db, CTX, tasks["flooring"]["task_id"], {"material": "tile"}, from_plans=True,
                                from_measurements=True)
    assert out["task"]["proposed"]["area_sqft"] == 240.0 and out["task"]["proposed"]["baseboard_lf"] > 0
    out = runner.submit_takeoff(db, CTX, tasks["flooring"]["task_id"], {"material": "tile", "area_sqft": 250},
                                from_plans=True, from_measurements=True)
    assert out["task"]["proposed"]["area_sqft"] == 250


def test_unchecked_symbols_never_auto_advance(db, house):                          # S25-R02
    from estimator.agent_manager.configs import update_config
    eid, ps = house["estimate_id"], house["plan_set_id"]
    add_symbols(db, ps, [("duplex_receptacle", "electrical", "approved", 4),
                         ("duplex_receptacle", "electrical", "proposed", 2)])
    from estimator.modules import get_registry
    update_config(db, CTX, "electrical", {"auto_advance": True, "confidence_threshold": 80}, confirm=True,
                  registry=get_registry())
    task = runner.start_run(db, CTX, eid, ["electrical"])["tasks"][0]
    out = runner.submit_takeoff(db, CTX, task["task_id"], from_plans=True, confidence=95)
    assert out["task"]["state"] == "needs_review" and not out.get("auto_approved")
    assert any("still to check" in n for n in out["plan_notes"])
    assert out["task"]["proposed"]["outlets"] == 4
    db.execute("UPDATE symbol_detections SET status = 'approved' WHERE plan_set_id = ?", (ps,))
    db.commit()
    out = runner.submit_takeoff(db, CTX, task["task_id"], from_plans=True, confidence=95)
    assert out.get("auto_approved") and out["task"]["state"] == "completed" and out["task"]["answers"]["outlets"] == 6


# ---------------------------------------------------------------- design firm                      S25-F01

def test_design_firm_on_plan_sets(db, house, tmp_path):                            # S25-F01
    eid, ps = house["estimate_id"], house["plan_set_id"]
    assert store.load_plan_set(db, CTX, ps)["design_firm"] == "Hart Architects"
    rev2 = store.upload(db, CTX, eid, str(make_pdf(tmp_path / "rev2.pdf", [page(), page()])),
                        supersedes_plan_set_id=ps, confirm=True)
    row = store.load_plan_set(db, CTX, rev2["plan_set_id"])
    assert (row["design_firm"], row["design_firm_source"]) == ("Hart Architects", f"plan set {ps}")
    other = plain_estimate(db, "Jones")
    third = plan_set_row(db, other, tmp_path, "jones.pdf")["plan_set_id"]
    assert store.load_plan_set(db, CTX, third)["design_firm"] is None
    with pytest.raises(ConfirmationRequired) as ask:
        store.set_design_firm(db, CTX, third, "  hart   ARCHITECTS ")
    assert ask.value.details["design_firm"] == "Hart Architects"                 # the spelling already on file
    assert ask.value.details["same_firm_plan_sets"] == 2
    store.set_design_firm(db, CTX, third, "hart architects", confirm=True)
    firms = store.design_firms(db, CTX)
    assert firms["firms"][0]["name"] == "Hart Architects" and firms["firms"][0]["plan_sets"] == 3
    assert firms["firms"][0]["estimates"] == 2 and firms["plan_sets_without_firm"] == 0
    assert store.set_design_firm(db, CTX, third, "Hart Architects")["changed"] is False
    store.set_design_firm(db, CTX, third, None, confirm=True)
    assert store.design_firms(db, CTX)["plan_sets_without_firm"] == 1
    with pytest.raises(PermissionDenied):
        store.set_design_firm(db, FIELD, third, "X", confirm=True)
    with pytest.raises(InvalidInput):
        store.set_design_firm(db, CTX, third, "x" * 121, confirm=True)
    with pytest.raises(NotFound):
        store.set_design_firm(db, CTX, 99999, "X", confirm=True)
    ev = db.execute("SELECT after_json FROM estimate_events WHERE action = 'plan_design_firm_set'").fetchall()
    assert len(ev) == 2


# ---------------------------------------------------------------- assemblies                       S25-A01..A03

def test_get_assemblies():                                                          # S25-A01
    a = assemblies.get_assemblies("flooring")
    from estimator.modules import get_registry
    mod = get_registry().get("flooring")
    assert a["assembly_id"] == f"flooring@{mod.version}" and len(a["components"]) == len(mod.lines)
    inputs = {i["id"]: i for i in a["inputs"]}
    assert inputs["area_sqft"]["measured"] and not inputs["material"]["measured"]
    assert [o["id"] for o in a["options"]] == ["good", "better", "best"] and a["plans_answer_it"] is True
    assert assemblies.get_assemblies("pressure_washing")["plans_answer_it"] is False
    with pytest.raises(InvalidInput):
        assemblies.get_assemblies("nope")


def approved_flooring(db, eid, area="500", base="120", approve_base=True):
    a = takeoffs.manual(db, CTX, eid, "flooring", feeds="area_sqft", qty=area, unit="sqft", approve=True,
                        confirm=True)["measurement"]
    b = takeoffs.manual(db, CTX, eid, "flooring", feeds="baseboard_lf", qty=base, unit="lf", approve=approve_base,
                        confirm=True)["measurement"]
    return a, b


def test_apply_assembly_from_measurements(db):                                      # S25-A02
    eid = plain_estimate(db)
    a, b = approved_flooring(db, eid, approve_base=False)
    with pytest.raises(ConfirmationRequired) as ask:
        assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring", params={"material": "lvp"})
    d = ask.value.details
    assert d["answers"]["area_sqft"] == 500.0 and d["sources"]["area_sqft"] == {"from": "measured",
                                                                               "measurement_ids": [a["id"]]}
    assert d["sources"]["material"] == {"from": "typed"} and d["sources"]["baseboard_lf"] == {"from": "default"}
    assert d["waiting"] == {"baseboard_lf": 1} and "waiting for approval" in ask.value.message
    assert {ln["rule"] for ln in d["lines"]} == {"lvp", "install_plank"}
    out = assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring", params={"material": "lvp"}, confirm=True)
    sec = next(s for s in out["sections"] if s["module_id"] == "flooring")
    assert len(sec["lines"]) == 2 and all(ln["assembly_use_id"] == out["assembly_use_id"] for ln in sec["lines"])
    assert sec["answers"]["area_sqft"] == 500.0 and out["totals"]["total_cents"] > 0
    uses = assemblies.assembly_uses(db, CTX, eid)
    assert len(uses) == 1 and uses[0]["measurement_ids"] == [a["id"]] and uses[0]["assembly_id"].startswith("flooring@")
    # again with the "best" option: the material comes from the option, the area is still measured, kept answers stay
    takeoffs.confirm_measurements(db, CTX, [b["id"]], confirm=True)
    out = assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring", option="best", confirm=True)
    sec = next(s for s in out["sections"] if s["module_id"] == "flooring")
    assert sec["answers"]["material"] == "hardwood" and sec["answers"]["baseboard_lf"] == 120.0
    assert out["sources"]["material"] == {"from": "option best"}
    # typed over a measured answer is allowed, and says so
    out = assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring", params={"area_sqft": 450}, confirm=True)
    assert out["sources"]["area_sqft"]["from"] == "typed" and out["sources"]["area_sqft"]["over_measured"] == 500.0
    assert out["sources"]["material"]["from"].startswith("kept")
    # only the measurements you pick
    c = takeoffs.manual(db, CTX, eid, "flooring", feeds="area_sqft", qty="100", unit="sqft", approve=True,
                        confirm=True)["measurement"]
    out = assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring", measurement_ids=[c["id"]], confirm=True)
    assert next(s for s in out["sections"] if s["module_id"] == "flooring")["answers"]["area_sqft"] == 100.0
    out = assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring", confirm=True)
    assert next(s for s in out["sections"] if s["module_id"] == "flooring")["answers"]["area_sqft"] == 600.0


def test_apply_assembly_refusals(db):                                              # S25-A03
    eid = plain_estimate(db)
    a, b = approved_flooring(db, eid, approve_base=False)
    r = rev(db, eid)
    with pytest.raises(InvalidInput):
        assemblies.apply_assembly(db, CTX, eid, r, "flooring", params={"colour": "red"})
    with pytest.raises(InvalidInput):
        assemblies.apply_assembly(db, CTX, eid, r, "flooring", option="platinum")
    with pytest.raises(InvalidInput) as e:
        assemblies.apply_assembly(db, CTX, eid, r, "flooring", params={"material": "lvp"}, measurement_ids=[b["id"]])
    assert "aren't approved" in e.value.message
    with pytest.raises(InvalidInput):
        assemblies.apply_assembly(db, CTX, eid, r, "flooring", params={"material": "lvp"}, measurement_ids=[99999])
    with pytest.raises(InvalidInput) as e:                                       # material is required
        assemblies.apply_assembly(db, CTX, eid, r, "flooring")
    assert "material" in e.value.message
    with pytest.raises(InvalidInput):                                            # nothing measured or typed
        assemblies.apply_assembly(db, CTX, plain_estimate(db), 1, "electrical", confirm=True)
    with pytest.raises(PermissionDenied):
        assemblies.apply_assembly(db, FIELD, eid, r, "flooring", params={"material": "lvp"})
    with pytest.raises(StaleRevision):
        assemblies.apply_assembly(db, CTX, eid, r - 1, "flooring", params={"material": "lvp"})
    with pytest.raises(InvalidInput):
        assemblies.apply_assembly(db, CTX, eid, r, "flooring", use_measurements=False, measurement_ids=[a["id"]])


# ---------------------------------------------------------------- line edits                       S25-L01..L03

def priced(db):
    eid = plain_estimate(db)
    approved_flooring(db, eid)
    assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring", params={"material": "lvp"}, confirm=True)
    lines = {ln["calc"]["rule"]: ln for s in service.get_estimate(db, CTX, eid)["sections"] for ln in s["lines"]}
    return eid, lines


def test_override_a_priced_line(db):                                               # S25-L01
    eid, lines = priced(db)
    lvp = lines["lvp"]
    before = service.get_estimate(db, CTX, eid)["totals"]["total_cents"]
    with pytest.raises(InvalidInput) as e:
        assemblies.update_line_item(db, CTX, eid, rev(db, eid), lvp["id"], unit_cost_cents=lvp["unit_cost_cents"] + 50)
    assert "reason" in e.value.message
    with pytest.raises(ConfirmationRequired) as ask:
        assemblies.update_line_item(db, CTX, eid, rev(db, eid), lvp["id"], unit_cost_cents=lvp["unit_cost_cents"] + 50,
                                    reason="supplier quote")
    assert ask.value.details["override"] is True and "override of the flooring assembly" in ask.value.message
    out = assemblies.update_line_item(db, CTX, eid, rev(db, eid), lvp["id"], unit_cost_cents=lvp["unit_cost_cents"] + 50,
                                      quantity="520", reason="supplier quote", confirm=True)
    line = next(ln for s in out["sections"] for ln in s["lines"] if ln["id"] == lvp["id"])
    assert line["unit_cost_cents"] == lvp["unit_cost_cents"] + 50 and Decimal(line["quantity"]) == 520
    assert line["override"]["reason"] == "supplier quote" and line["override"]["by"] == CTX.actor
    assert line["override"]["changed"]["unit_cost_cents"]["from"] == lvp["unit_cost_cents"]
    assert out["totals"]["total_cents"] > before
    ev = db.execute("SELECT before_json, after_json FROM estimate_events WHERE action = 'line_overridden'").fetchone()
    assert json.loads(ev["after_json"])["reason"] == "supplier quote"
    # re-applying keeps the cost change, drops the quantity change, and says so
    with pytest.raises(ConfirmationRequired) as ask:
        assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring")
    assert len(ask.value.details["overrides_kept"]) == 1 and len(ask.value.details["overrides_dropped"]) == 1
    out = assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring", confirm=True)
    new = next(ln for s in out["sections"] for ln in s["lines"] if ln["calc"]["rule"] == "lvp")
    assert new["unit_cost_cents"] == lvp["unit_cost_cents"] + 50 and Decimal(new["quantity"]) == 500
    assert new["override"]["reason"] == "supplier quote" and out["overrides_kept"][0]["changed"] == ["unit_cost_cents"]
    # put it back
    out = assemblies.update_line_item(db, CTX, eid, rev(db, eid), new["id"], revert=True, confirm=True)
    back = next(ln for s in out["sections"] for ln in s["lines"] if ln["id"] == new["id"])
    assert back["unit_cost_cents"] == lvp["unit_cost_cents"] and back["override"] is None
    with pytest.raises(InvalidInput):
        assemblies.update_line_item(db, CTX, eid, rev(db, eid), new["id"], revert=True, confirm=True)
    # re-applying without keep_overrides drops everything
    assemblies.update_line_item(db, CTX, eid, rev(db, eid), new["id"], waste_pct="0.2", reason="odd room",
                                confirm=True)
    out = assemblies.apply_assembly(db, CTX, eid, rev(db, eid), "flooring", keep_overrides=False, confirm=True)
    assert out["overrides_kept"] == [] and len(out["overrides_dropped"]) == 1


def test_hand_lines_remove_and_refusals(db):                                       # S25-L02
    eid, lines = priced(db)
    service.add_line_item(db, CTX, eid, rev(db, eid), kind="other", description="Dumpster", quantity="1", unit="ea",
                          unit_cost_cents=45000)
    hand = next(ln for s in service.get_estimate(db, CTX, eid)["sections"] if s["module_id"] == "custom"
                for ln in s["lines"])
    out = assemblies.update_line_item(db, CTX, eid, rev(db, eid), hand["id"], unit_cost_cents=50000, confirm=True)
    assert any(ln["unit_cost_cents"] == 50000 for s in out["sections"] for ln in s["lines"])   # no reason needed
    with pytest.raises(ConfirmationRequired):
        assemblies.update_line_item(db, CTX, eid, rev(db, eid), hand["id"], remove=True)
    out = assemblies.update_line_item(db, CTX, eid, rev(db, eid), hand["id"], remove=True, confirm=True)
    assert out["removed_line_id"] == hand["id"]
    with pytest.raises(InvalidInput):                                            # a priced line needs a reason
        assemblies.update_line_item(db, CTX, eid, rev(db, eid), lines["lvp"]["id"], remove=True, confirm=True)
    r = rev(db, eid)
    with pytest.raises(InvalidInput):
        assemblies.update_line_item(db, CTX, eid, r, lines["lvp"]["id"], remove=True, revert=True, reason="x")
    with pytest.raises(InvalidInput):
        assemblies.update_line_item(db, CTX, eid, r, lines["lvp"]["id"], quantity="-1", reason="x")
    with pytest.raises(InvalidInput):
        assemblies.update_line_item(db, CTX, eid, r, lines["lvp"]["id"], waste_pct="2", reason="x")
    with pytest.raises(InvalidInput):                                            # nothing changes
        assemblies.update_line_item(db, CTX, eid, r, lines["lvp"]["id"], quantity=lines["lvp"]["quantity"],
                                    reason="x")
    with pytest.raises(PermissionDenied):
        assemblies.update_line_item(db, REVIEWER, eid, r, lines["lvp"]["id"], quantity="1", reason="x")
    with pytest.raises(StaleRevision):
        assemblies.update_line_item(db, CTX, eid, r - 1, lines["lvp"]["id"], quantity="1", reason="x")
    other = plain_estimate(db, "Other")
    with pytest.raises(NotFound):
        assemblies.update_line_item(db, CTX, other, rev(db, other), lines["lvp"]["id"], quantity="1", reason="x")


def test_overrides_and_other_pricing_paths(db):                                     # S25-L03
    eid, lines = priced(db)
    assemblies.update_line_item(db, CTX, eid, rev(db, eid), lines["lvp"]["id"], unit_cost_cents=999,
                                reason="special order", confirm=True)
    out = quick.answer(db, CTX, eid, "flooring", {"area_sqft": 300, "material": "lvp"}, rev(db, eid))
    assert any("hand change" in w for w in out["warnings"])                      # re-pricing says what it replaced
    eid2, lines2 = priced(db)
    assemblies.update_line_item(db, CTX, eid2, rev(db, eid2), lines2["lvp"]["id"], description="LVP, Coretec",
                                reason="customer's pick", confirm=True)
    service.set_status(db, CTX, eid2, rev(db, eid2), "approved")
    new = service.create_revision(db, CTX, eid2, "customer asked for more")
    copied = [ln for s in service.get_estimate(db, CTX, new["id"])["sections"] for ln in s["lines"]
              if ln["description"] == "LVP, Coretec"]
    assert copied and copied[0]["override"]["reason"] == "customer's pick"      # the hand change goes with it


# ---------------------------------------------------------------- tools                            S25-T01

def test_tools(db, house):                                                          # S25-T01
    from estimator.mcp_tools import est_tools as t
    j = json.loads
    eid = plain_estimate(db, "Tools")
    r = rev(db, eid)
    out = j(t.est_add_trade(eid, r, "Flooring"))
    assert any(s["module_id"] == "flooring" for s in out["sections"])
    assert j(t.est_add_trade(eid, out["rev"], "flooring"))["error"] == "invalid_input"     # already there
    ask = j(t.est_remove_trade(eid, out["rev"], "flooring"))
    assert ask["error"] == "needs_confirmation" and ask["lines"] == 0
    gone = j(t.est_remove_trade(eid, out["rev"], "flooring", confirm=True))
    assert not any(s["module_id"] == "flooring" for s in gone["sections"])
    assert j(t.est_remove_trade(eid, gone["rev"], "flooring", confirm=True))["error"] == "invalid_input"
    assert j(t.est_get_assemblies("flooring"))["module_id"] == "flooring"
    assert j(t.est_get_assemblies("nope"))["error"] == "invalid_input"
    approved_flooring(db, eid)
    asked = j(t.est_apply_assembly(eid, rev(db, eid), "flooring", params='{"material": "tile"}'))
    assert asked["error"] == "needs_confirmation"
    done = j(t.est_apply_assembly(eid, rev(db, eid), "flooring", params={"material": "tile"}, confirm=True))
    line = done["sections"][0]["lines"][0]
    assert j(t.est_update_line_item(eid, done["rev"], line["id"], quantity="1"))["error"] == "invalid_input"
    upd = j(t.est_update_line_item(eid, done["rev"], line["id"], quantity="1", reason="test", confirm=True))
    assert Decimal(upd["changed"]["quantity"]) == 1
    assert j(t.est_apply_assembly(eid, upd["rev"], "flooring", params="not json"))["error"] == "invalid_input"
    firms = j(t.plan_set_design_firm())
    assert firms["firms"][0]["name"] == "Hart Architects"
    assert j(t.plan_set_design_firm(house["plan_set_id"]))["error"] == "invalid_input"
    assert j(t.plan_set_design_firm(house["plan_set_id"], clear=True))["error"] == "needs_confirmation"
    task = runner.start_run(db, CTX, house["estimate_id"], ["flooring"])["tasks"][0]
    sub = j(t.runner_submit_takeoff(task["task_id"], answers={"material": "lvp"}, from_plans=True))
    assert sub["task"]["proposed"]["area_sqft"] == 234.0
    names = {fn.__name__ for fn in t.TOOLS}
    assert {"est_update_line_item", "est_get_assemblies", "est_apply_assembly", "est_add_trade", "est_remove_trade",
            "plan_set_design_firm"} <= names
