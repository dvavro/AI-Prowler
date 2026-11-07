"""Sprint 13 (re-ordered from Sprint 15): fencing, landscaping, demolition; all 15 planned trades (S13-..)."""
import pytest

from estimator.context import personal_context
from estimator.director import engine
from estimator.director.triage import TRADE_WORDS, triage
from estimator.estimating import quick, scenarios, service
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
NEW = {"fencing", "landscaping", "demolition"}


def _lines(db, module, answers):
    e = service.create_estimate(db, CTX, module)
    e = quick.answer(db, CTX, e["id"], module, answers, e["rev"], REG)
    return e, {ln["calc"]["rule"]: ln for ln in e["sections"][0]["lines"]}


def test_every_planned_trade_has_a_module():  # S13-M01
    mods = {m.id: m for m in REG.list()}
    construction = {m for m in mods if mods[m].category == "construction"}
    assert NEW <= construction and not REG.errors
    assert set(TRADE_WORDS) == construction and len(construction) == 15
    assert all(mods[m].notes for m in NEW)
    assert [s["id"] for s in mods["fencing"].scenarios] == ["good", "better", "best"]


@pytest.mark.parametrize("text, module", [
    ("install a new fence along the back yard", "fencing"), ("build a 6 ft block wall", "fencing"),
    ("replace the fence and add a gate", "fencing"), ("chain link around the lot", "fencing"),
    ("desert landscaping for the front yard", "landscaping"), ("install artificial turf in the back", "landscaping"),
    ("put in a drip system and plant trees", "landscaping"), ("paver patio out back", "landscaping"),
    ("lay sod in the back yard", "landscaping"),
    ("demo the kitchen", "demolition"), ("gut the master bathroom", "demolition"),
    ("knock out a wall between the kitchen and living room", "demolition"),
    ("tear down the old shed", "demolition"), ("break out the old concrete patio", "demolition"),
])
def test_triage_new_trades(text, module):  # S13-T01
    r = triage(text, REG)
    assert (r.lane, r.module_id) == ("standard_estimate", module), r.as_dict()


@pytest.mark.parametrize("text, module", [
    ("mow my lawn every two weeks", "landscaping_maintenance"), ("landscaping maintenance monthly", "landscaping_maintenance"),
    ("pressure wash the fence", "pressure_washing"), ("haul away junk from the garage", "junk_removal"),
])
def test_services_not_taken_by_new_trades(text, module):  # S13-T02
    assert triage(text, REG).module_id == module


def test_fence_posts_and_height(db):  # S13-F01
    _, ln = _lines(db, "fencing", {"length_lf": 100, "material": "vinyl", "height": "8"})
    assert ln["posts"]["quantity"] == "14"                          # ceil(100 / 8) + 1
    assert ln["install"]["quantity"] == "26.6667" or ln["install"]["quantity"].startswith("26.6")
    _, ln = _lines(db, "fencing", {"length_lf": 100, "material": "block"})
    assert "posts" not in ln and "install" not in ln and ln["blocks"]["quantity"] == "675"


def test_fence_options(db):  # S13-O01
    e, _ = _lines(db, "fencing", {"length_lf": 120, "material": "wood"})
    opts = {o["id"]: o for o in scenarios.price_options(db, CTX, e["id"], registry=REG)["options"]}
    assert opts["good"]["current"] and opts["good"]["total_cents"] < opts["better"]["total_cents"] < opts["best"]["total_cents"]


def test_landscaping_needs_something(db):  # S13-L01
    r = engine.start(db, CTX, "desert landscaping for the front yard", registry=REG)
    assert r["job"]["module_id"] == "landscaping" and r["next_step"]["at_least_one"]
    r = engine.next_step(db, CTX, r["job"]["id"], answers={"clear_sqft": 500}, registry=REG)
    assert r["next_step"].get("at_least_one")                       # clearing alone isn't a landscape job


def test_demolition_dumpsters(db):  # S13-D01
    _, ln = _lines(db, "demolition", {"walls_lf": 10})
    assert ln["dumpsters"]["quantity"] == "1" and "protection" in ln
    _, ln = _lines(db, "demolition", {"concrete_sqft": 600, "protection": True})
    assert "dumpsters" not in ln and "protection" not in ln            # concrete goes by the ton, outside work


def test_remodel_demo_first(db):  # S13-D02
    r = engine.start(db, CTX, "gut the master bathroom", answers={"interior_sqft": 80, "level": "gut", "fixtures": 3},
                     registry=REG)
    r = engine.add_trade(db, CTX, r["job"]["id"], "plumbing", {"toilets": 1, "sinks": 1, "showers": 1}, registry=REG)
    est = service.get_estimate(db, CTX, r["estimate"]["id"])
    assert [s["module_id"] for s in est["sections"]] == ["demolition", "plumbing"]
    assert r["estimate"]["total_cents"] == sum(s["subtotal_cents"] for s in est["sections"])
    assert r["job"]["stage"] == "review"
    notes = " ".join(f["message"] for f in r["next_step"]["findings"])
    assert "asbestos" in notes and "bearing wall" in notes
