"""Sprint 10 (re-ordered from Sprint 12/13): framing, drywall and painting from measurements (S10-..)."""
import pytest

from estimator.context import personal_context
from estimator.director import engine
from estimator.director.settings import update_settings
from estimator.director.triage import triage
from estimator.estimating import quick, scenarios, service
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()


def test_new_trades_load():  # S10-M01
    mods = {m.id: m for m in REG.list() if m.category == "construction"}
    assert {"framing", "drywall", "painting"} <= set(mods) and not REG.errors
    assert mods["framing"].required_any == ("wall_lf", "floor_sqft", "trusses")
    assert [s["id"] for s in mods["drywall"].scenarios] == ["good", "better", "best"]
    assert [s["id"] for s in mods["painting"].scenarios] == ["good", "better", "best"]
    assert all(mods[m].notes for m in ("framing", "drywall", "painting"))


@pytest.mark.parametrize("text, module", [
    ("frame a new interior wall", "framing"),
    ("build 3 interior walls in the garage", "framing"),
    ("hang drywall in the garage", "drywall"),
    ("sheetrock the basement", "drywall"),
    ("tape and mud the new walls", "drywall"),
    ("paint the living room", "painting"),
    ("repaint the outside of the house", "painting"),
    ("paint the trim and doors", "painting"),
])
def test_triage_new_trades(text, module):  # S10-T01
    r = triage(text, REG)
    assert (r.lane, r.module_id) == ("standard_estimate", module), r.as_dict()


@pytest.mark.parametrize("text", ["carpet cleaning", "clean the carpets in 3 rooms"])
def test_carpet_cleaning_is_a_service(text):  # S10-T02
    r = triage(text, REG)
    assert (r.lane, r.module_id) == ("quick_quote", "generic_service")


def test_framing_asks_for_something_to_frame(db):  # S10-D01
    r = engine.start(db, CTX, "frame some walls", registry=REG)
    assert r["job"]["module_id"] == "framing" and r["next_step"]["at_least_one"]
    assert set(r["job"]["open_questions"]) == {"wall_lf", "floor_sqft", "trusses"}
    r = engine.next_step(db, CTX, r["job"]["id"], answers={"wall_lf": 100}, registry=REG)
    assert r["estimate"]["total_cents"] == 159624 and r["job"]["stage"] == "review"


def test_room_addition_framing_drywall_paint(db):  # S10-D02
    r = engine.start(db, CTX, "frame a room addition", answers={"wall_lf": 60, "exterior": True, "openings": 3},
                     registry=REG)
    r = engine.add_trade(db, CTX, r["job"]["id"], "drywall", {"wall_lf": 60, "ceiling_sqft": 225, "openings_sqft": 50},
                         registry=REG)
    r = engine.add_trade(db, CTX, r["job"]["id"], "painting", {"wall_sqft": 430, "ceiling_sqft": 225, "primer": True},
                         registry=REG)
    est = service.get_estimate(db, CTX, r["estimate"]["id"])
    assert [s["module_id"] for s in est["sections"]] == ["framing", "drywall", "painting"]
    assert r["estimate"]["total_cents"] == sum(s["subtotal_cents"] for s in est["sections"])
    assert r["job"]["stage"] == "review"
    notes = " ".join(f["message"] for f in r["next_step"]["findings"])
    assert "header sizes" in notes and "fire-rated" in notes and "Hot weather" in notes


def test_drywall_finish_options(db):  # S10-O01
    e = service.create_estimate(db, CTX, "drywall")
    e = quick.answer(db, CTX, e["id"], "drywall", {"wall_lf": 120, "ceiling_sqft": 400, "openings_sqft": 100}, e["rev"],
                     REG)
    opts = {o["id"]: o for o in scenarios.price_options(db, CTX, e["id"], registry=REG)["options"]}
    assert opts["better"]["current"] and opts["better"]["total_cents"] == 234280
    # level 3 is $0.15/sq ft less, level 5 is $0.30/sq ft more, over 1,260 sq ft
    assert opts["good"]["difference_cents"] == -18900 and opts["best"]["difference_cents"] == 37800


def test_painting_options(db):  # S10-O02
    update_settings(db, CTX, {"review_required_over_cents": 10_000_000})
    r = engine.start(db, CTX, "paint the living room", answers={"wall_sqft": 1200, "ceiling_sqft": 400}, registry=REG)
    r = engine.next_step(db, CTX, r["job"]["id"], scenarios=True, registry=REG)
    totals = {o["id"]: o["total_cents"] for o in r["scenarios"]}
    assert totals["good"] < totals["better"] == 247600 < totals["best"]
    r = engine.next_step(db, CTX, r["job"]["id"], choose_scenario="best", registry=REG)
    assert r["job"]["answers"]["grade"] == "premium" and r["estimate"]["total_cents"] == totals["best"]
