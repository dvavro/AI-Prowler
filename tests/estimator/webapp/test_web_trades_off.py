"""2026-11-17 (David): the Trades switch in AI-Prowler's 🏗 Estimator tab is the master setting. A trade that's off
isn't quoted: it's hidden from the trade pickers, the Price Book and the symbol screens, can't be added to an estimate,
and the Director leaves it out - while an estimate that already has it keeps working. (C2-TO..)"""
import json

import pytest

from estimator import agent_manager
from estimator.context import RequestContext, personal_context
from estimator.director import engine
from estimator.errors import InvalidInput, PermissionDenied
from estimator.estimating import quick, service
from estimator.mcp_tools import est_tools as t
from estimator.modules.registry import ModuleRegistry
from estimator.symbols import library

API = "/estimator-api"
CTX = personal_context()
REG = ModuleRegistry().load()
SLAB = {"area_sqft": 400}


def _switch(db, module_id, on):
    agent_manager.update_config(db, CTX, module_id, {"enabled": on}, confirm=True, registry=REG)
    db.commit()


def test_off_trade_is_hidden_from_pickers_and_price_book(call, db):          # C2-TO01
    _switch(db, "concrete", False)
    mods = call("GET", f"{API}/modules").json()["modules"]
    assert "concrete" not in {m["id"] for m in mods} and "framing" in {m["id"] for m in mods}
    every = {m["id"]: m for m in call("GET", f"{API}/modules?all=1").json()["modules"]}
    assert every["concrete"]["off"] is True and every["framing"]["off"] is False
    assert "concrete" not in {m["id"] for m in call("GET", f"{API}/modules?path=quick").json()["modules"]}
    book = call("GET", f"{API}/price-book").json()
    assert not [p for p in book["prices"] if p.get("module_id") == "concrete"] and book["trades_off"] == ["concrete"]
    assert any(p.get("module_id") == "framing" for p in book["prices"])
    listed = json.loads(t.est_list_modules())
    assert "concrete" not in {m["id"] for m in listed["modules"]} and listed["switched_off"] == ["concrete"]
    _switch(db, "concrete", True)                                             # back on: offered again
    assert "concrete" in {m["id"] for m in call("GET", f"{API}/modules").json()["modules"]}
    assert any(p.get("module_id") == "concrete" for p in call("GET", f"{API}/price-book").json()["prices"])


def test_off_trade_cannot_be_added_but_existing_estimates_keep_working(db):  # C2-TO02
    had = service.create_estimate(db, CTX, "Already has concrete")
    had = quick.answer(db, CTX, had["id"], "concrete", SLAB, had["rev"], REG)
    _switch(db, "concrete", False)
    again = quick.answer(db, CTX, had["id"], "concrete", {**SLAB, "area_sqft": 500}, had["rev"], REG)   # Edit answers
    assert again["totals"]["total_cents"] > had["totals"]["total_cents"]
    new = service.create_estimate(db, CTX, "New job")
    with pytest.raises(InvalidInput, match="switched off"):
        quick.answer(db, CTX, new["id"], "concrete", SLAB, new["rev"], REG)
    with pytest.raises(InvalidInput, match="switched off"):
        service.add_trade(db, CTX, new["id"], "concrete", new["rev"], REG)
    with pytest.raises(InvalidInput, match="switched off"):
        engine.set_project_trades(db, CTX, new["id"], ["concrete", "framing"], registry=REG)
    out = engine.set_project_trades(db, CTX, had["id"], ["concrete", "framing"], registry=REG)   # it has concrete
    assert "concrete" in engine.planned_trades(db, CTX, had["id"])
    assert out["job"]


def test_director_leaves_an_off_trade_out(db):                                # C2-TO03
    _switch(db, "concrete", False)
    r = engine.start(db, CTX, "pour a 20 x 20 concrete slab", registry=REG)
    assert r["job"]["module_id"] is None and "switched off" in r["next_step"]["say"]
    assert "concrete" not in r["next_step"]["ask"]
    with pytest.raises(InvalidInput, match="switched off"):
        engine.start(db, CTX, "a slab", module_id="concrete", registry=REG)
    with pytest.raises(InvalidInput, match="switched off"):
        engine.intake(db, CTX, "a slab", module_id="concrete", registry=REG)


def test_services_switch_off_too(call, db):                                   # C2-TO05 (services can be limited)
    agent_manager.set_offered(db, CTX, "pressure_washing", False, REG)
    db.commit()
    assert "pressure_washing" not in {m["id"] for m in call("GET", f"{API}/modules?path=quick").json()["modules"]}
    assert not [p for p in call("GET", f"{API}/price-book").json()["prices"] if p.get("module_id") == "pressure_washing"]
    new = service.create_estimate(db, CTX, "Driveway")
    with pytest.raises(InvalidInput, match="switched off"):
        quick.answer(db, CTX, new["id"], "pressure_washing", {"driveway_sqft": 800}, new["rev"], REG)
    r = engine.start(db, CTX, "pressure wash my driveway", registry=REG)
    assert r["job"]["lane"] is None and "switched off" in r["next_step"]["say"]
    assert "pressure_washing" not in r["next_step"]["ask"]
    assert engine.start(db, CTX, "clean my windows", registry=REG)["job"]["module_id"] == "window_cleaning"
    with pytest.raises(PermissionDenied, match="only the owner"):
        agent_manager.set_offered(db, RequestContext(user_id="o", role="office"), "window_cleaning", False, REG)
    agent_manager.set_offered(db, CTX, "pressure_washing", True, REG)
    db.commit()
    assert "pressure_washing" in {m["id"] for m in call("GET", f"{API}/modules?path=quick").json()["modules"]}


def test_off_trade_symbols_are_hidden(db):                                    # C2-TO04
    assert "electrical" in library.list_library(db, CTX)["trades"]
    _switch(db, "electrical", False)
    got = library.list_library(db, CTX)
    assert "electrical" not in got["trades"]
    assert all(d["trade"] != "electrical" for lib in got["libraries"] for defs in lib["by_trade"].values() for d in defs)
    _switch(db, "hvac", False)
    assert "mechanical" not in library.list_library(db, CTX)["trades"]        # HVAC's plan symbols are "mechanical"
