"""Surface conduit in the wiring takeoff (2026-11-23, David: "Did or should the wiring calculate plastic or metal pipe and
elbows since this job is a metal shed and I want to mount the conduit on top of the steel ... include a basic expansion
coefficient of the material used for conduit so the structure will last").

The thermal expansion numbers are the code's: PVC 3.38e-5 in/in/F (NEC Table 352.44: 4.06 in per 100 ft at 100 F, an
expansion fitting at 1/4 in), steel EMT 6.5e-6 (NEC 300.7(B): 0.2 x PVC)."""
import math
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("ezdxf")
from estimator.takeoff import conduit as cd  # noqa: E402
from estimator.takeoff import wiring  # noqa: E402
from test_ai_design import SHED, shed_design  # noqa: E402


def S(**kw):
    return wiring.settings_with_defaults(kw)


def test_the_code_table_numbers():                                                       # CO-01
    # NEC Table 352.44: 100 ft of PVC over a 100 F change moves 4.06 in
    assert cd.movement_in("pvc", 100, 100, "wood") == pytest.approx(4.056, abs=0.01)
    # steel is 0.2 x PVC (NEC 300.7(B) informational note): about 0.78 in - against wood framing, less what the wood moves
    assert cd.MATERIALS["emt"]["alpha"] / cd.MATERIALS["pvc"]["alpha"] == pytest.approx(0.192, abs=0.01)
    assert cd.movement_in("emt", 100, 100, "wood") == pytest.approx((6.5e-6 - 2.5e-6) * 1200 * 100)
    # EMT strapped to a steel building moves with it: nothing to take up
    assert cd.movement_in("emt", 100, 100, "steel") == pytest.approx(0.0)
    # an expansion fitting at 1/4 in or more; each takes up its travel (PVC couplings 6 in)
    assert cd.expansion_fittings(0.24, "pvc", 0.25) == 0
    assert cd.expansion_fittings(0.25, "pvc", 0.25) == 1
    assert cd.expansion_fittings(6.5, "pvc", 0.25) == 2


def test_fill_sizes_the_conduit():                                                       # CO-02
    assert cd.conductors("12/2") == (12, 3) and cd.conductors("10/3") == (10, 4)
    assert cd.trade_size("emt", {12: 9}) == ("1/2", False)                               # Annex C Table C.1: 9 #12
    assert cd.trade_size("emt", {12: 10}) == ("3/4", False)
    assert cd.trade_size("pvc", {12: 9}) == ("3/4", False)                               # Table C.10: 8 #12 in 1/2
    assert cd.trade_size("emt", {12: 6, 10: 3})[0] == "3/4"                               # mixed: by fill fraction
    assert cd.trade_size("emt", {6: 12}) == ("1", True)                                  # over-full even at 1 in


def test_one_run_counts_its_fittings():                                                  # CO-03
    s = S(method="pvc", temp_swing_indoor_f=90)
    r = cd.run("pvc", [1.5, 30.0, 0.0, 7.0], 2, {12: 3}, False, s, "C-1: outlet to outlet")
    assert r["length_ft"] == 38.5 and r["size"] == "1/2" and r["bends"] == 2
    assert r["couplings"] == 2 + 0                                                       # 30 ft: two joints; 7 ft: none
    # straps within 3 ft of each box, then every 3 ft for 1/2 in PVC (NEC 352.30)
    assert r["straps"] == 2 + math.ceil(24 / 3) + math.ceil(1 / 3)
    leg = next(e for e in r["expansion"] if e["leg_ft"] == 30.0)
    assert leg["movement_in"] == pytest.approx(3.38e-5 * 360 * 90, abs=0.01) and leg["fittings"] == 1
    assert r["expansion_fittings"] == 2                                                  # the 7 ft leg moves 0.26 in too


def _shed_takeoff(**settings):
    tmp = Path(tempfile.mkdtemp())
    plan, panel = tmp / "plan.dxf", tmp / "panel.dxf"
    from estimator.design import draw_electrical
    draw_electrical.draw_plan(SHED, shed_design(), str(plan), "TEST")
    draw_electrical.draw_panel(shed_design(), str(panel), "TEST")
    return wiring.takeoff(str(plan), str(panel), settings)


def test_nm_cable_is_unchanged_by_default():                                            # CO-04
    r = _shed_takeoff()
    assert "conduit" not in r and all(b["cable"].endswith(("NM-B", "NM-B (or SER)")) for b in r["bom"])
    assert not wiring.routing_summary(r["settings"]).startswith("NM-B")


def test_a_metal_shed_in_emt_on_steel():                                                 # CO-05
    r = _shed_takeoff(method="emt", structure="steel", temp_swing_indoor_f=90)
    c = r["conduit"]
    items = {i["feeds"]: i["qty"] for i in c["items"]}
    # THHN instead of NM-B cable: each circuit's conductors plus a ground
    cables = {b["cable"]: b for b in r["bom"]}
    assert set(cables) == {"12 AWG THHN", "10 AWG THHN"} and cables["12 AWG THHN"]["feeds"] == "thhn_12_ft"
    # EMT inside, PVC only on the short stubs out through the wall to the weatherproof boxes (an LB each)
    assert items["emt_050_ft"] > 300 and items["pvc_050_ft"] < 60
    assert items["conduit_bodies"] >= sum(1 for d in shed_design()["devices"]
                                          if d["type"] in ("outlet_wp", "light_exterior")) - 2
    assert items["emt_elbows"] > 0 and items["emt_connectors"] > 0 and items["emt_straps"] > items["emt_connectors"]
    # EMT on the steel building needs no expansion fittings; one box per device inside and outside - except the
    # weatherproof GFCI kits, which come with their own box (2026-11-23: not counted twice)
    assert "emt_expansion" not in items
    devs = shed_design()["devices"]
    n_kit = sum(1 for d in devs if d["type"] == "outlet_wp")
    n_ext = sum(1 for d in devs if d["type"] == "light_exterior")
    assert items.get("wp_boxes", 0) == n_ext and items["surface_boxes"] == len(devs) - n_kit - n_ext
    # home runs leave the panel together
    assert any(x["what"].startswith("home run ") for x in c["run_list"])
    assert "EMT conduit on the surface (outside: PVC), on a steel building" in wiring.routing_summary(r["settings"])


def test_pvc_everywhere_needs_expansion_couplings():                                    # CO-06
    hot = _shed_takeoff(method="pvc", structure="steel", temp_swing_indoor_f=90)["conduit"]
    mild = _shed_takeoff(method="pvc", structure="steel", temp_swing_indoor_f=20)["conduit"]
    assert hot["expansion_fittings"] > mild["expansion_fittings"] > 0
    worst = hot["expansion"][0]
    assert worst["fittings"] >= 1 and worst["movement_in"] == pytest.approx(
        3.38e-5 * worst["leg_ft"] * 12 * worst["swing_f"], abs=0.01)
    # the threshold is a setting: a looser one counts fewer
    loose = _shed_takeoff(method="pvc", structure="steel", temp_swing_indoor_f=90, expansion_threshold_in=1.0)["conduit"]
    assert loose["expansion_fittings"] < hot["expansion_fittings"]


def test_a_floor_can_be_wired_another_way():                                            # CO-07
    s = S(method="nm", method_by_floor={0: "emt"})
    assert wiring.method_for(0, s) == "emt" and wiring.method_for(1, s) == "nm"
    r = _shed_takeoff(method="nm", method_by_floor={"0": "emt"})
    assert r["conduit"]["methods"] == {"0": "emt"}


def test_each_conduit_run_has_a_path_to_draw():                                         # CO-09
    """2026-11-23 (David: "Cant see a visual of the conduit, so how can I review it?"): every run carries where it goes
    and the circuits in it, so the Measure screen can draw it."""
    r = _shed_takeoff(method="emt", structure="steel")
    runs = r["conduit"]["run_list"]
    assert runs and all(x["path"] and x["circuits"] for x in runs)
    assert all(len(p) == 2 for x in runs for p in x["path"])
    homes = [x for x in runs if x["home_run"]]
    assert homes and any(len(x["circuits"]) > 1 for x in homes)                         # shared home runs
    stubs = [x for x in runs if x["what"].endswith("(outside, through the wall)")]
    assert stubs and all(x["pull_points"] >= 1 and x["outdoor"] for x in stubs)          # the LB


def _wired_job(db, tmp_path):
    from estimator.context import personal_context
    from estimator.drawing_model import engine, store
    from estimator.estimating import service
    from test_wiring import _panel, _plan
    ctx = personal_context()
    est = service.create_estimate(db, ctx, "Wired then conduit")
    service.add_trade(db, ctx, est["id"], "electrical", est.get("rev", 1))
    for f in (_plan(tmp_path), _panel(tmp_path)):
        ps = store.upload(db, ctx, est["id"], f, confirm=True)["plan_set_id"]
        engine.start(db, ctx, ps, confirm=True)
    db.commit()
    return ctx, est["id"]


def test_switching_to_conduit_hands_the_cable_over(db, tmp_path):                      # CO-10
    """2026-11-23 (David: "What is the 6, 10, 12 AWG THHN wiring when we already have a cable lengths?"): the NM cable was
    approved, then the wiring was run again in conduit with "keep approved" on. The THHN replaces the cable: approving it
    takes the cable off, so the wire is priced once - and the overlay has the conduit to draw."""
    import json
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import wiring_run
    ctx, eid = _wired_job(db, tmp_path)
    first = wiring_run.run(db, ctx, eid)
    ms.confirm_measurements(db, ctx, first["measurement_ids"], confirm=True)
    cable = {r["feeds"]: r["id"] for r in db.execute(
        "SELECT feeds, id FROM measurements WHERE estimate_id = ? AND feeds LIKE 'wire_%' AND status = 'approved'", (eid,))}
    assert "wire_12_2_ft" in cable
    second = wiring_run.run(db, ctx, eid, {"method": "emt"}, keep_approved=True)
    assert second["overlay"]["conduit"] and all(len(r["line"]) >= 2 for r in second["overlay"]["conduit"])
    assert {12} <= {g for r in second["overlay"]["conduit"] for g in r["awg"]}
    rows = {r["feeds"]: dict(r) for r in db.execute(
        "SELECT * FROM measurements WHERE estimate_id = ? AND status = 'proposed' AND feeds LIKE 'thhn_%'", (eid,))}
    thhn12 = rows["thhn_12_ft"]
    calc = json.loads(thhn12["calc_json"])
    assert cable["wire_12_2_ft"] in calc["replaces"] and "wiring method changed" in calc["how"]
    replaced = {i for r in rows.values() for i in json.loads(r["calc_json"]).get("replaces", [])}
    assert replaced == set(cable.values())                                               # every old cable size
    # no "change to 0" left waiting on the old cable
    assert not db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND feeds LIKE 'wire_%'"
                          " AND suggested_qty IS NOT NULL", (eid,)).fetchone()[0]
    with pytest.raises(Exception) as asked:
        ms.confirm_measurements(db, ctx, [thhn12["id"]])
    assert "the wiring method changed" in str(asked.value)
    out = ms.confirm_measurements(db, ctx, [r["id"] for r in rows.values()], confirm=True)
    assert set(out["replaced"]) == set(cable.values())
    left = db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND feeds LIKE 'wire_%'"
                      " AND status = 'approved'", (eid,)).fetchone()[0]
    assert left == 0
    why = db.execute("SELECT reject_reason FROM measurements WHERE id = ?", (cable["wire_12_2_ft"],)).fetchone()[0]
    assert "the wiring method changed" in why


def test_update_from_plans_clears_the_cable_conduit_replaced(db, tmp_path):             # CO-11
    """2026-11-23 (David: "why is it counting wire twice?"): NM cable priced on the estimate, then the wiring run again
    in EMT from scratch (the old cable measurements go). Update from the plans must take the cable off the estimate,
    not leave it priced as if typed in, beside the THHN."""
    from estimator.api import links
    from estimator.estimating import quick, service
    from estimator.modules.registry import ModuleRegistry
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import wiring_run
    reg = ModuleRegistry().load()
    ctx, eid = _wired_job(db, tmp_path)
    first = wiring_run.run(db, ctx, eid)
    ms.confirm_measurements(db, ctx, first["measurement_ids"], confirm=True)
    est = service.get_estimate(db, ctx, eid)
    answers, _ = links.answers_from_measurements(db, ctx, est, "electrical", reg)
    quick.answer(db, ctx, eid, "electrical", answers, est["rev"], reg)
    est = service.get_estimate(db, ctx, eid)
    sec = next(s for s in est["sections"] if s["module_id"] == "electrical")
    assert float(sec["answers"]["wire_12_2_ft"]) > 0
    second = wiring_run.run(db, ctx, eid, {"method": "emt"}, keep_approved=False)
    ms.confirm_measurements(db, ctx, second["measurement_ids"], confirm=True)
    answers, changes = links.answers_from_measurements(db, ctx, est, "electrical", reg)
    assert answers["wire_12_2_ft"] == 0 and changes["wire_12_2_ft"]["to"] == 0
    assert float(answers["thhn_12_ft"]) > 0 and float(answers["emt_050_ft"]) > 0
    out = quick.answer(db, ctx, eid, "electrical", answers, est["rev"], reg)
    lines = {ln["description"] for s in out["sections"] for ln in s["lines"]}
    assert not any(d.startswith("Cable ") and "NM-B" in d for d in lines)
    assert any(d.startswith("THHN 12 AWG") for d in lines)


def test_the_electrical_trade_prices_conduit(db):                                        # CO-08
    from estimator.context import personal_context
    from estimator.estimating import quick, service
    from estimator.modules.registry import ModuleRegistry
    reg = ModuleRegistry().load()
    mod = reg.get("electrical")
    keys = {ln.price_key for ln in mod.lines}
    for k in ("el_emt_050_lf", "el_pvc_expansion_ea", "el_emt_expansion_ea", "el_thhn_12_lf", "el_surface_box_ea",
              "el_conduit_body_ea"):
        assert k in keys and k in mod.sample_prices
    ctx = personal_context()
    e = service.create_estimate(db, ctx, "Metal shed, surface EMT")
    answers = {"outlets": 10, "lights": 20, "thhn_12_ft": 2200, "emt_050_ft": 420, "pvc_050_ft": 32, "emt_elbows": 25,
               "emt_couplings": 18, "emt_connectors": 82, "emt_straps": 124, "pvc_expansion": 1, "conduit_bodies": 10,
               "surface_boxes": 38, "wp_boxes": 8, "appliance_circuits": 2}
    out = quick.answer(db, ctx, e["id"], "electrical", answers, e["rev"], reg)
    lines = {ln["description"]: ln for s in out["sections"] for ln in s["lines"]}
    emt = lines["1/2 in EMT conduit (measured)"]
    assert float(emt["quantity"]) == 420                       # the measured feet; the 10% waste is applied when priced
    assert float(emt.get("waste_pct", emt.get("waste", 0.10)) or 0) in (0.10, 10)
    assert "PVC expansion couplings (thermal movement, NEC 352.44)" in lines
    assert "Run conduit on the surface and pull the wire" in lines
    assert "Surface boxes, 4 in square with raised covers" in lines
    # measured THHN and surface boxes: the per-device wire and the wall boxes step aside (not priced twice)
    assert "Branch circuit wire (12/2)" not in lines
    assert not any(d.startswith(("Plastic electrical boxes", "Metal electrical boxes")) for d in lines)
    # 2026-11-23 (David: "make the fixes so no double counting"): the lights hang on the surface boxes - no fixture
    # boxes as well
    assert not any(d.startswith("Light fixture boxes") for d in lines)
    # ...and the dedicated circuits are in the conduit labor, not run again
    assert "Run dedicated circuits" not in lines
