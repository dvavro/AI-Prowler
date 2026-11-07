"""Sprint 12 (re-ordered from Sprint 14): HVAC, windows and doors, siding, insulation (S12-..)."""
import pytest

from estimator.context import personal_context
from estimator.director import engine
from estimator.director.settings import update_settings
from estimator.director.triage import triage
from estimator.estimating import quick, scenarios, service
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
NEW = {"hvac", "windows_doors", "siding", "insulation"}


def _lines(db, module, answers):
    e = service.create_estimate(db, CTX, module)
    e = quick.answer(db, CTX, e["id"], module, answers, e["rev"], REG)
    return e, {ln["calc"]["rule"]: ln for ln in e["sections"][0]["lines"]}


def test_expansion_trades_load():  # S12-M01
    mods = {m.id: m for m in REG.list()}
    assert NEW <= set(mods) and not REG.errors and len([m for m in mods.values() if m.category == "construction"]) >= 12
    assert all(mods[m].notes for m in NEW)
    assert [s["id"] for s in mods["siding"].scenarios] == ["good", "better", "best"]
    assert [s["id"] for s in mods["windows_doors"].scenarios] == ["good", "better"]
    assert [s["id"] for s in mods["insulation"].scenarios] == ["good", "better", "best"]


@pytest.mark.parametrize("text, module", [
    ("replace the ac unit", "hvac"), ("new heat pump", "hvac"), ("install a mini split in the garage", "hvac"),
    ("furnace replacement", "hvac"), ("replace the windows", "windows_doors"), ("new front door", "windows_doors"),
    ("install a garage door", "windows_doors"), ("sliding door replacement", "windows_doors"),
    ("restucco the house", "siding"), ("new vinyl siding", "siding"), ("replace the fascia and soffit", "siding"),
    ("blow insulation in the attic", "insulation"), ("spray foam the garage", "insulation"),
])
def test_triage_expansion_trades(text, module):  # S12-T01
    r = triage(text, REG)
    assert (r.lane, r.module_id) == ("standard_estimate", module), r.as_dict()


@pytest.mark.parametrize("text, module", [("clean the windows", "window_cleaning"),
                                          ("pressure wash the stucco", "pressure_washing")])
def test_services_not_taken_by_trades(text, module):  # S12-T02
    assert triage(text, REG).module_id == module


def test_hvac_sizing_rule_and_override(db):  # S12-H01
    _, ln = _lines(db, "hvac", {"system": "heat_pump", "conditioned_sqft": 1800, "sqft_per_ton": 400})
    assert ln["heat_pump_equipment"]["quantity"] == "4.5"              # 1,800 / 400 = 4.5 tons
    _, ln = _lines(db, "hvac", {"system": "heat_pump", "conditioned_sqft": 600})
    assert ln["heat_pump_equipment"]["quantity"] == "1.5"              # never under 1.5 tons
    _, ln = _lines(db, "hvac", {"system": "heat_pump", "conditioned_sqft": 1800, "tons": 3})
    assert ln["heat_pump_equipment"]["quantity"] == "3"
    _, ln = _lines(db, "hvac", {"system": "mini_split", "conditioned_sqft": 900})
    assert ln["mini_split_heads"]["quantity"] == "3" and ln["install_labor"]["quantity"] == "24"
    assert "trunk" not in ln and "registers" not in ln                 # ductless


def test_hvac_needs_a_size(db):  # S12-H02
    r = engine.start(db, CTX, "new heat pump", answers={"system": "heat_pump"}, registry=REG)
    assert r["job"]["stage"] == "collect_job" and r["next_step"]["at_least_one"]


def test_siding_squares_never_negative(db):  # S12-S01
    _, ln = _lines(db, "siding", {"wall_sqft": 100, "openings": 20, "material": "vinyl"})
    assert "vinyl" not in ln and ln["j_channel"]["quantity"] == "320"           # zero-quantity lines are dropped


def test_trade_options(db):  # S12-O01
    e, _ = _lines(db, "siding", {"wall_sqft": 2000, "openings": 12, "material": "fiber_cement", "eave_lf": 160})
    opts = {o["id"]: o for o in scenarios.price_options(db, CTX, e["id"], registry=REG)["options"]}
    assert opts["better"]["current"] and opts["good"]["total_cents"] < opts["better"]["total_cents"] < opts["best"]["total_cents"]
    e, _ = _lines(db, "insulation", {"attic_sqft": 1500})
    opts = {o["id"]: o for o in scenarios.price_options(db, CTX, e["id"], registry=REG)["options"]}
    assert opts["better"]["total_cents"] == 232500 and opts["good"]["total_cents"] < 232500 < opts["best"]["total_cents"]


def test_energy_upgrade_three_trades(db):  # S12-D01
    update_settings(db, CTX, {"review_required_over_cents": 10_000_000})
    r = engine.start(db, CTX, "replace the ac unit", answers={"system": "heat_pump", "conditioned_sqft": 1800},
                     registry=REG)
    r = engine.add_trade(db, CTX, r["job"]["id"], "insulation", {"attic_sqft": 1800, "attic_r": "49"}, registry=REG)
    r = engine.add_trade(db, CTX, r["job"]["id"], "windows_doors", {"windows_small": 8, "windows_large": 2},
                         registry=REG)
    est = service.get_estimate(db, CTX, r["estimate"]["id"])
    assert [s["module_id"] for s in est["sections"]] == ["hvac", "insulation", "windows_doors"]
    assert r["job"]["stage"] == "approve" and "good/better/best" in r["next_step"]["say"]
    r = engine.next_step(db, CTX, r["job"]["id"], scenarios=True, scenario_module="windows_doors", registry=REG)
    assert {o["id"] for o in r["scenarios"]} == {"good", "better"}
