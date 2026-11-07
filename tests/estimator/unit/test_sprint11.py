"""Sprint 11 (re-ordered from Sprint 13): plumbing and electrical, finishing the 8 core trades (S11-..)."""
import pytest

from estimator.context import personal_context
from estimator.director import engine
from estimator.director.triage import triage
from estimator.estimating import quick, service
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
CORE = {"concrete", "framing", "roofing", "flooring", "drywall", "painting", "plumbing", "electrical"}


def _price(db, module, answers):
    e = service.create_estimate(db, CTX, module)
    return quick.answer(db, CTX, e["id"], module, answers, e["rev"], REG)


def test_all_eight_core_trades_load():  # S11-M01
    assert CORE <= {m.id for m in REG.list() if m.category == "construction"} and not REG.errors
    assert "water_heater" in REG.get("plumbing").required_any and "panel" in REG.get("electrical").required_any
    assert REG.get("plumbing").notes and REG.get("electrical").notes


@pytest.mark.parametrize("text, module", [
    ("replace a toilet", "plumbing"), ("install a tankless water heater", "plumbing"),
    ("plumbing for a new bathroom", "plumbing"), ("repipe the house", "plumbing"), ("install a gas line", "plumbing"),
    ("install a ceiling fan", "electrical"), ("add 6 outlets in the garage", "electrical"),
    ("panel upgrade to 200 amp", "electrical"), ("install an ev charger", "electrical"),
    ("install recessed lights", "electrical"), ("install lights in the kitchen", "electrical"),
])
def test_triage_plumbing_electrical(text, module):  # S11-T01
    r = triage(text, REG)
    assert (r.lane, r.module_id) == ("standard_estimate", module), r.as_dict()


def test_none_choice_is_not_an_answer(db):  # S11-D01
    r = engine.start(db, CTX, "plumbing work", answers={"water_heater": "none"}, registry=REG)
    assert r["job"]["stage"] == "collect_job" and r["next_step"]["at_least_one"]
    r = engine.next_step(db, CTX, r["job"]["id"], answers={"water_heater": "tank"}, registry=REG)
    # $1,100 heater + 4 hr x $85 + $250 permit
    assert r["estimate"]["total_cents"] == 110000 + 34000 + 25000


def test_panel_only_job(db):  # S11-D02
    r = engine.start(db, CTX, "panel upgrade to 200 amp", answers={"panel": "upgrade"}, registry=REG)
    assert r["estimate"]["total_cents"] == 370000 and r["job"]["stage"] == "review"


def test_old_work_costs_more_labor(db):  # S11-P01
    new = _price(db, "electrical", {"outlets": 10, "permit": False})
    old = _price(db, "electrical", {"outlets": 10, "work": "remodel", "permit": False})
    labor = {e["calc"]["rule"]: e["total_cents"] for e in new["sections"][0]["lines"]}["device_labor"]
    labor_old = {e["calc"]["rule"]: e["total_cents"] for e in old["sections"][0]["lines"]}["device_labor"]
    assert labor == 45000 and labor_old == 72000                      # 5 hr vs 8 hr at $90


def test_replace_work_needs_no_pipe(db):  # S11-P02
    e = _price(db, "plumbing", {"work": "replace", "toilets": 1, "permit": False})
    rules = {ln["calc"]["rule"] for ln in e["sections"][0]["lines"]}
    assert rules == {"removal", "trim"} and e["totals"]["total_cents"] == 25000   # minimum


def test_bathroom_remodel_five_trades(db):  # S11-D03
    r = engine.start(db, CTX, "plumbing for a new bathroom", answers={"toilets": 1, "sinks": 1, "showers": 1},
                     registry=REG)
    jid = r["job"]["id"]
    for module, answers in [("electrical", {"work": "remodel", "outlets": 2, "gfci": 2, "lights": 3, "fans": 1}),
                            ("drywall", {"wall_lf": 30, "board": "moisture"}),
                            ("painting", {"wall_sqft": 200, "ceiling_sqft": 60}),
                            ("flooring", {"area_sqft": 60, "material": "tile"})]:
        r = engine.add_trade(db, CTX, jid, module, answers, registry=REG)
    est = service.get_estimate(db, CTX, r["estimate"]["id"])
    assert [s["module_id"] for s in est["sections"]] == ["plumbing", "electrical", "drywall", "painting", "flooring"]
    assert r["estimate"]["total_cents"] == sum(s["subtotal_cents"] for s in est["sections"])
    assert r["job"]["stage"] == "review"
    notes = " ".join(f["message"] for f in r["next_step"]["findings"])
    assert "permit and inspection" in notes and "fire-rated" in notes
