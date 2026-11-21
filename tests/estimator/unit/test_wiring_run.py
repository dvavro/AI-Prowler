"""The Wiring run on the Measure screen (2026-11-19, David): the project's floor plan + panel drawing go in, one proposed
cable measurement per size comes out, the routes are placed on the plan sheet, and approved cable prices the estimate
in place of the 'average run per device' wire guess. Small drawings built here with ezdxf - never the live plans."""
import json

import pytest

ezdxf = pytest.importorskip("ezdxf")
from estimator.context import personal_context  # noqa: E402
from estimator.drawing_model import engine, store  # noqa: E402
from estimator.errors import InvalidInput  # noqa: E402
from estimator.estimating import quick, service  # noqa: E402
from estimator.modules.registry import ModuleRegistry  # noqa: E402
from estimator.takeoff import measurements as ms  # noqa: E402
from estimator.takeoff import wiring_run  # noqa: E402
from test_wiring import _panel, _plan  # noqa: E402

CTX = personal_context()
REG = ModuleRegistry().load()
# 2026-11-20 (David: the quote had no range receptacle and too many breakers): the run proposes the cable sizes - the
# range's 10/2 from the schedule priced as 10/3 (it needs a neutral) - plus the branch-circuit and range-receptacle counts.
CABLE = {"wire_14_2_ft", "wire_12_2_ft", "wire_12_3_ft", "wire_10_3_ft"}
COUNTS = {"branch_circuits", "range_receptacles"}
ALL = CABLE | COUNTS


def _job(db, tmp_path, panel=True):
    est = service.create_estimate(db, CTX, "Wired house")
    service.add_trade(db, CTX, est["id"], "electrical", est.get("rev", 1))
    files = [_plan(tmp_path)] + ([_panel(tmp_path)] if panel else [])
    for f in files:
        ps = store.upload(db, CTX, est["id"], f, confirm=True)["plan_set_id"]
        engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return est


def test_sources_tell_plan_from_panel(db, tmp_path):                                     # WRR-01
    est = _job(db, tmp_path)
    src = wiring_run.sources(db, CTX, est["id"])
    assert src["plan"]["name"] == "plan.dxf" and src["panel"]["name"] == "panel.dxf"
    assert src["plan"]["sheet_id"]


def test_no_panel_drawing_lays_the_circuits_out(db, tmp_path):                           # WRR-02
    """2026-11-21 (David: "Add the fall back"): no panel drawing is no longer a refusal - the circuits are laid out from
    the floor plan, and the run says so."""
    est = _job(db, tmp_path, panel=False)
    assert wiring_run.sources(db, CTX, est["id"])["panel"] is None
    steps = []
    out = wiring_run.run(db, CTX, est["id"], on_step=steps.append)
    assert out["circuits_from"] == "laid_out"
    assert any("no panel schedule" in s for s in steps)
    rows = {m["feeds"] for m in ms.list_measurements(db, CTX, est["id"], "electrical")["measurements"]
            if m["proposed_by"] == wiring_run.PROPOSED_BY}
    assert {"wire_14_2_ft", "wire_12_2_ft", "branch_circuits", "range_receptacles"} <= rows


def test_bad_settings_are_refused(db, tmp_path):                                         # WRR-03
    est = _job(db, tmp_path)
    with pytest.raises(InvalidInput, match="ceiling ft"):
        wiring_run.run(db, CTX, est["id"], {"ceiling_ft": 40})
    with pytest.raises(InvalidInput, match="route"):
        wiring_run.run(db, CTX, est["id"], {"route": {"0": "floor"}})


def test_run_proposes_cable_and_places_routes(db, tmp_path):                             # WRR-04
    est = _job(db, tmp_path)
    r = wiring_run.run(db, CTX, est["id"], {"route": {"1": "ceiling"}})
    assert r["unassigned"] == [] and wiring_run.dxf_path(est["id"]).is_file()
    assert wiring_run.latest(CTX, est["id"])["ran_at"] == r["ran_at"]
    rows = {m["feeds"]: m for m in ms.list_measurements(db, CTX, est["id"], "electrical")["measurements"]
            if m["proposed_by"] == wiring_run.PROPOSED_BY}
    assert set(rows) == ALL
    assert rows["range_receptacles"]["kind"] == "count" and float(rows["range_receptacles"]["qty"]) == 1
    branch = [c for c in r["circuits"] if c["amps"] < 30 and c["devices"]]
    assert float(rows["branch_circuits"]["qty"]) == len(branch) and rows["branch_circuits"]["unit"] == "ea"
    bom = {b["cable"].split()[0]: b for b in r["bom"]}
    m = rows["wire_12_2_ft"]
    assert m["status"] == "proposed" and m["unit"] == "lf" and float(m["qty"]) == bom["12/2"]["measured_ft"]
    calc = db.execute("SELECT calc_json FROM measurements WHERE id = ?", (m["id"],)).fetchone()["calc_json"]
    assert json.loads(calc)["circuits"] == ["C-1", "C-2", "C-3", "C-4"]
    # The routes land on the plan sheet: the panel's home run starts at the panel symbol the plan reader found.
    sym = db.execute("SELECT geometry_json FROM drawing_objects WHERE sheet_id = ? AND kind = 'symbol'"
                     " AND UPPER(block_name) LIKE '%PANEL%'", (r["sources"]["plan"]["sheet_id"],)).fetchone()
    px, py = json.loads(sym["geometry_json"])["points"][0]
    c1 = next(c for c in r["overlay"]["circuits"] if c["id"] == "C-1")
    assert c1["lines"][0][0] == pytest.approx([px, py], abs=0.01)
    assert len(c1["devices"]) == 2
    # Rerunning replaces the proposals instead of piling them up.
    wiring_run.run(db, CTX, est["id"])
    again = [m for m in ms.list_measurements(db, CTX, est["id"], "electrical")["measurements"]
             if m["proposed_by"] == wiring_run.PROPOSED_BY]
    assert len(again) == len(ALL)


def test_marks_on_the_plan_and_the_audit_says_where_they_come_from(db, tmp_path):        # WRR-09
    """2026-11-20 (David: "3 of these items don't have symbols, can they be added to the drawing"; the audit said "The
    AI counted" for them): the overlay carries the wiring run's marks in sheet coordinates, and the audit says the
    wiring run found them (no AI), that the drawing has no symbol for them, and ticks them."""
    from estimator.takeoff import audit
    est = _job(db, tmp_path)
    r = wiring_run.run(db, CTX, est["id"])
    marks = {a["feeds"]: a for a in r["overlay"]["added"]}
    assert set(marks) == {"range_receptacles", "branch_circuits"}
    rng = next(c for c in r["overlay"]["circuits"] if c["id"] == "RANGE")
    assert marks["range_receptacles"]["at"] == rng["devices"][0] and marks["range_receptacles"]["circuits"] == ["RANGE"]
    c1 = next(c for c in r["overlay"]["circuits"] if c["id"] == "C-1")
    assert marks["branch_circuits"]["at"] == pytest.approx(c1["lines"][0][0], abs=0.01)    # at the panel
    found = {f["feeds"]: f for f in audit.audit(db, CTX, est["id"])["findings"] if f["kind"] == "waiting"}
    assert set(found) == ALL and all(f["selected"] and "AI" not in f["detail"] for f in found.values())
    assert "wiring run found 1 ea" in found["range_receptacles"]["detail"]
    assert "no symbol" in found["range_receptacles"]["detail"]
    assert "wiring run routed" in found["wire_12_2_ft"]["detail"]


def test_moving_a_device_to_another_circuit(db, tmp_path):                              # WRR-05
    est = _job(db, tmp_path)
    r = wiring_run.run(db, CTX, est["id"], overrides={"OUTLET@12.0,0.5": "C-2"})
    c = {x["id"]: x for x in r["circuits"]}
    assert c["C-1"]["devices"] == 1 and c["C-2"]["devices"] == 3
    assert r["overrides"] == {"OUTLET@12.0,0.5": "C-2"}


def test_approved_cable_prices_the_estimate(db, tmp_path):                               # WRR-06
    est = _job(db, tmp_path)
    r = wiring_run.run(db, CTX, est["id"])
    ms.confirm_measurements(db, CTX, r["measurement_ids"], confirm=True)
    answers = ms.approved_answers(db, CTX, est["id"], "electrical", REG)["electrical"]
    assert answers["wire_12_2_ft"] == pytest.approx(next(b["measured_ft"] for b in r["bom"]
                                                         if b["cable"].startswith("12/2")), abs=0.01)
    def rules_for(a):
        e = service.create_estimate(db, CTX, "priced")
        e = quick.answer(db, CTX, e["id"], "electrical", a, e["rev"], REG)
        return {ln["calc"]["rule"] for s in e["sections"] for ln in s["lines"]}
    rules = rules_for({"outlets": 10, "switches": 4, **answers})
    assert {"cable_12_2", "cable_14_2", "cable_12_3", "cable_10_3", "range_receptacles"} <= rules
    assert not rules & {"wire", "wire_220", "wire_15a", "heavy_wire"}                  # the average-run guess steps aside
    # With no measured cable the average-run guess is back.
    rules = rules_for({"outlets": 10, "switches": 4})
    assert "wire" in rules and not any(x.startswith("cable_") for x in rules)


def test_ai_auto_run_routes_the_wiring(db, tmp_path):                                    # WRR-08
    """2026-11-19 (David): AI Auto Run on Electrical routes the wiring after the device count - keeping the last Wiring
    run's settings and device moves - and says why when it can't."""
    from estimator.agents.llm_takeoff_runner import run_wiring_stage
    est = _job(db, tmp_path)
    wiring_run.run(db, CTX, est["id"], {"route": {"0": "walls"}}, {"OUTLET@12.0,0.5": "C-2"})
    steps = []
    w = run_wiring_stage(db, CTX, est["id"], on_step=steps.append)
    # 2026-11-21: each wiring stage is said as it starts, for AI Auto Run's waiting message.
    assert w["ran"] is True and steps[0] == "routing the wiring" and len(w["measurement_ids"]) == len(ALL)
    assert [s.split(":")[0] for s in steps[1:]] == ["wiring"] * 3
    assert "reading the panel schedule" in steps[1] and "6 circuits routed" in steps[2] and "cable lengths" in steps[3]
    assert w["circuits"] == 6 and "ft of 12/2" in w["summary"]
    last = wiring_run.latest(CTX, est["id"])
    assert last["settings"]["route"] == {"0": "walls"} and last["overrides"] == {"OUTLET@12.0,0.5": "C-2"}
    (tmp_path / "bare").mkdir()
    bare = _job(db, tmp_path / "bare", panel=False)                                     # no panel drawing
    w = run_wiring_stage(db, CTX, bare["id"])                    # 2026-11-21: the circuits are laid out instead
    assert w["ran"] is True and w["circuits_from"] == "laid_out" and "laid out" in w["summary"]


def test_rerun_keeps_approved_cable_by_default(db, tmp_path):                            # WRR-07a
    """2026-11-19 (David): keeping approved items saves review time - the approved cable sizes stay and aren't
    proposed again; a size not approved yet is replaced."""
    est = _job(db, tmp_path)
    first = wiring_run.run(db, CTX, est["id"])
    m12 = next(i for i in first["measurement_ids"] if db.execute(
        "SELECT feeds FROM measurements WHERE id = ?", (i,)).fetchone()[0] == "wire_12_2_ft")
    ms.confirm_measurements(db, CTX, [m12], confirm=True)
    again = wiring_run.run(db, CTX, est["id"], {"route": {"0": "walls"}})
    rows = {r["feeds"]: dict(r) for r in db.execute(
        "SELECT * FROM measurements WHERE estimate_id = ? AND proposed_by = ?", (est["id"], wiring_run.PROPOSED_BY))}
    assert len(rows) == len(ALL) and rows["wire_12_2_ft"]["id"] == m12 and rows["wire_12_2_ft"]["status"] == "approved"
    assert sorted(again["measurement_ids"]) == sorted(r["id"] for f, r in rows.items() if f != "wire_12_2_ft")
    assert again["keep_approved"] is True


def test_rerun_with_other_routing_suggests_the_new_lengths(db, tmp_path):               # WRR-07d
    """2026-11-21 (David: "I reran the run wiring with different defaults and I don't see any changes to approve"):
    everything approved, then a rerun with other routing - each approved item the new run measures differently keeps
    its approved value, with the new one suggested; accepting it prices the new length."""
    est = _job(db, tmp_path)
    first = wiring_run.run(db, CTX, est["id"], {"foundation": "basement", "outlets_via": "above"})
    ms.confirm_measurements(db, CTX, first["measurement_ids"], confirm=True)
    again = wiring_run.run(db, CTX, est["id"], {"foundation": "crawlspace", "outlets_via": "walls", "ceiling_ft": 10})
    assert again["measurement_ids"] == [] and again["suggested_ids"]                       # nothing new; changes waiting
    rows = {r["feeds"]: dict(r) for r in db.execute(
        "SELECT * FROM measurements WHERE estimate_id = ? AND proposed_by = ?", (est["id"], wiring_run.PROPOSED_BY))}
    m = rows["wire_12_2_ft"]
    new12 = next(b["measured_ft"] for b in again["bom"] if b["cable"].startswith("12/2"))
    old12 = next(b["measured_ft"] for b in first["bom"] if b["cable"].startswith("12/2"))
    assert new12 != old12 and m["status"] == "approved" and float(m["qty"]) == pytest.approx(old12, abs=0.01)
    assert float(m["suggested_qty"]) == pytest.approx(new12, abs=0.05) and m["id"] in again["suggested_ids"]
    assert "crawlspace" in m["suggested_reason"]
    assert rows["branch_circuits"]["suggested_qty"] is None                                # the same count: nothing
    # The same rerun again: the same suggestion, not a second one.
    third = wiring_run.run(db, CTX, est["id"], {"foundation": "crawlspace", "outlets_via": "walls", "ceiling_ft": 10})
    assert sorted(third["suggested_ids"]) == sorted(again["suggested_ids"])
    ms.confirm_measurements(db, CTX, again["suggested_ids"], confirm=True, accept_suggestion=True)
    assert float(ms.approved_answers(db, CTX, est["id"], "electrical", REG)["electrical"]["wire_12_2_ft"]) == \
        pytest.approx(new12, abs=0.05)


def test_rerun_from_scratch(db, tmp_path):                                               # WRR-07b
    """2026-11-19 (David): with "Keep approved items" off, the earlier wiring measurements go, approved ones too; only
    the new set is left."""
    est = _job(db, tmp_path)
    first = wiring_run.run(db, CTX, est["id"])
    ms.confirm_measurements(db, CTX, first["measurement_ids"], confirm=True)
    again = wiring_run.run(db, CTX, est["id"], {"route": {"0": "walls"}},               # a longer way round downstairs
                           keep_approved=False)
    rows = [dict(r) for r in db.execute("SELECT * FROM measurements WHERE estimate_id = ? AND proposed_by = ?",
                                        (est["id"], wiring_run.PROPOSED_BY))]
    assert sorted(r["id"] for r in rows) == sorted(again["measurement_ids"])            # only the new set
    assert len(rows) == len(ALL) and all(r["status"] == "proposed" for r in rows)
    assert "electrical" not in ms.approved_answers(db, CTX, est["id"], "electrical", REG)  # nothing approved yet
    m = next(r for r in rows if r["feeds"] == "wire_12_2_ft")
    new = next(b["measured_ft"] for b in again["bom"] if b["cable"].startswith("12/2"))
    assert float(m["qty"]) == pytest.approx(new, abs=0.01)
    gone = db.execute("SELECT COUNT(*) FROM estimate_events WHERE estimate_id = ? AND action = 'measurement_deleted'",
                      (est["id"],)).fetchone()[0]
    assert gone == len(ALL)                                                              # the history says so


def test_rerun_after_the_plans_were_read_again_proposes_the_cable_again(db, tmp_path):   # WRR-07c
    """2026-11-20 (David: the audit said to rerun the wiring): approved cable whose sheet went when the plans were read
    again isn't "already approved" for the plans as they read now - the rerun proposes every size again, the old cable
    stays priced until the new length is approved, and the audit then offers that (ticked) in one click."""
    from estimator.takeoff import audit
    est = _job(db, tmp_path)
    first = wiring_run.run(db, CTX, est["id"])
    ms.confirm_measurements(db, CTX, first["measurement_ids"], confirm=True)
    db.execute("UPDATE measurements SET sheet_id = NULL, viewport_id = NULL WHERE estimate_id = ?", (est["id"],))
    db.commit()                                                                          # as after a re-read
    before = {f["id"]: f for f in audit.audit(db, CTX, est["id"])["findings"]}
    reruns = [f for f in before.values() if f["kind"] == "rerun"]
    assert len(reruns) == len(ALL) and all(f["rerun"] == "wiring" and "Run wiring now" in f["advice"]
                                    and "don't need AI Auto Run" in f["advice"] for f in reruns)
    again = wiring_run.run(db, CTX, est["id"])                                           # keep approved: on
    assert len(again["measurement_ids"]) == len(ALL)                                     # every size proposed again
    old = db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND status = 'approved'"
                     " AND sheet_id IS NULL", (est["id"],)).fetchone()[0]
    assert old == len(ALL)                                                               # still priced meanwhile
    found = audit.audit(db, CTX, est["id"])["findings"]
    rep = [f for f in found if f["kind"] == "replace_old"]
    assert len(rep) == len(ALL) and all(f["selected"] for f in rep)
    assert all(("wiring run routed" if f["feeds"].startswith("wire_") else "wiring run found") in f["detail"] for f in rep)
    audit.apply(db, CTX, est["id"], [f["id"] for f in rep], confirm=True)
    left = db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND status = 'approved'"
                      " AND sheet_id IS NOT NULL", (est["id"],)).fetchone()[0]
    assert left == len(ALL) and not any(f["kind"] in ("rerun", "replace_old", "double_counted")
                                 for f in audit.audit(db, CTX, est["id"])["findings"])
