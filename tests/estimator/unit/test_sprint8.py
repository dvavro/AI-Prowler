"""Sprint 8: good/better/best options, multi-trade jobs, bid by trade, playbook changes, site visits (S8-..)."""
import json

import pytest

from estimator.bids import service as bids
from estimator.context import RequestContext, personal_context
from estimator.director import engine, overrides
from estimator.director.settings import update_settings
from estimator.errors import ConfirmationRequired, InvalidInput, NotEditable, NotFound, PermissionDenied
from estimator.estimating import quick, scenarios, service, setup
from estimator.modules.registry import ManifestError, ModuleRegistry, load_module

CTX = personal_context()
REG = ModuleRegistry().load()
ESTIMATOR = RequestContext(role="estimator", user_id="ed", mode="server")
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}


def _start(db, text, ctx=CTX, **kw):
    return engine.start(db, ctx, text, registry=REG, **kw)


def _next(db, r, ctx=CTX, **kw):
    return engine.next_step(db, ctx, r["job"]["id"], registry=REG, **kw)


def _roof_estimate(db):
    e = service.create_estimate(db, CTX, "roof")
    return quick.answer(db, CTX, e["id"], "roofing", ROOF, e["rev"], REG)


# ---------------------------------------------------------------- options

def test_built_in_options_load():  # S8-O01
    assert [s["id"] for s in REG.get("roofing").scenarios] == ["good", "better", "best"]
    assert {"roofing", "flooring", "concrete", "window_cleaning", "pressure_washing"} <= {
        m.id for m in REG.list() if m.scenarios}


def test_bad_options_in_manifest_rejected(tmp_path):  # S8-O02
    import shutil
    dst = tmp_path / "construction" / "roofing"
    shutil.copytree(REG.get("roofing").folder, dst)
    mf = dst / "manifest.yaml"
    text = mf.read_text(encoding="utf-8")
    mf.write_text(text.replace("answers: {material: metal}", "answers: {material: gold}"), encoding="utf-8")
    with pytest.raises(ManifestError, match="not a choice"):
        load_module(dst)
    mf.write_text(text.replace("answers: {material: metal}", "answers: {colour: red}"), encoding="utf-8")
    with pytest.raises(ManifestError, match="unknown question"):
        load_module(dst)


def test_price_roofing_options_without_changing_estimate(db):  # S8-O03
    e = _roof_estimate(db)
    out = scenarios.price_options(db, CTX, e["id"], registry=REG)
    opts = {o["id"]: o for o in out["options"]}
    assert opts["better"]["current"] and opts["better"]["total_cents"] == 781710
    # 3-tab: 21.66 sq x 1.10 x $95 instead of $125 = $714.78 less
    assert opts["good"]["total_cents"] == 781710 - 71478 and opts["good"]["difference_cents"] == -71478
    assert opts["best"]["total_cents"] > opts["better"]["total_cents"]
    assert service.get_estimate(db, CTX, e["id"])["totals"]["total_cents"] == 781710      # unchanged
    assert len(scenarios.list_options(db, CTX, e["id"])) == 3


def test_choose_option(db):  # S8-O04
    e = _roof_estimate(db)
    best = {o["id"]: o for o in scenarios.price_options(db, CTX, e["id"], registry=REG)["options"]}["best"]
    out = scenarios.choose_option(db, CTX, e["id"], "best", e["rev"], registry=REG)
    assert out["totals"]["total_cents"] == best["total_cents"] and out["chosen_option"]["answers"] == {"material": "metal"}
    chosen = [o["id"] for o in scenarios.list_options(db, CTX, e["id"]) if o["chosen"]]
    assert chosen == ["best"]
    with pytest.raises(NotFound, match="price the options first"):
        scenarios.choose_option(db, CTX, e["id"], "platinum", out["rev"], registry=REG)


def test_custom_options(db):  # S8-O05
    e = service.create_estimate(db, CTX, "clean")
    e = quick.answer(db, CTX, e["id"], "house_cleaning", {"bedrooms": 3, "bathrooms": 2, "sqft": 1800}, e["rev"], REG)
    with pytest.raises(InvalidInput, match="has good/better/best options"):
        scenarios.price_options(db, CTX, e["id"], registry=REG)
    out = scenarios.price_options(db, CTX, e["id"], options=[
        {"id": "standard", "label": "Standard clean", "answers": {"condition": "1"}},
        {"id": "deep", "label": "Deep clean", "answers": {"condition": "5"}}], registry=REG)
    assert out["options"][0]["total_cents"] < out["options"][1]["total_cents"]
    with pytest.raises(InvalidInput, match="no questions"):
        scenarios.price_options(db, CTX, e["id"], options=[{"id": "a", "answers": {"x": 1}},
                                                           {"id": "b", "answers": {"x": 2}}], registry=REG)
    with pytest.raises(InvalidInput, match="2 to 4"):
        scenarios.price_options(db, CTX, e["id"], options=[{"id": "a", "answers": {"condition": "1"}}], registry=REG)


def test_options_on_the_bid(db):  # S8-O06
    e = _roof_estimate(db)
    scenarios.price_options(db, CTX, e["id"], registry=REG)
    service.set_status(db, CTX, e["id"], e["rev"], "approved")
    b = bids.generate(db, CTX, e["id"], customer={"name": "Smith"}, registry=REG)
    html = open(b["html_path"], encoding="utf-8").read()
    assert "<h2>Options</h2>" in html and "Best: standing seam metal" in html and "(quoted above)" in html
    text = bids.preview(db, CTX, b["id"])["text"]
    assert "Options (total job price):" in text and "Good: 3-tab shingles: $7,102.32" in text


def test_director_options_and_choice(db):  # S8-O07
    update_settings(db, CTX, {"review_required_over_cents": 10_000_000})
    r = _start(db, "replace the roof", answers=ROOF)
    assert r["job"]["stage"] == "approve" and "good/better/best" in r["next_step"]["say"]
    r = _next(db, r, scenarios=True)
    assert len(r["scenarios"]) == 3 and any("Roofing options" in n for n in r["notes"])
    r = _next(db, r, choose_scenario="good")
    assert r["job"]["answers"]["material"] == "three_tab" and r["estimate"]["total_cents"] == 710232
    assert r["job"]["stage"] == "approve"
    r = _next(db, r, approve=True, confirm_sample_prices=True)
    with pytest.raises(NotEditable, match="revise=true"):
        _next(db, r, choose_scenario="best")


# ---------------------------------------------------------------- several trades on one job

def test_add_service_to_quick_quote(db):  # S8-M01
    r = _start(db, "pressure wash my driveway", answers={"driveway_sqft": 1500, "condition": "light"})
    r = engine.add_trade(db, CTX, r["job"]["id"], "window_cleaning", registry=REG)
    assert r["next_step"]["module_id"] == "window_cleaning" and "Window Cleaning part" in r["next_step"]["say"]
    assert r["job"]["open_questions"] == ["window_cleaning.windows"]
    r = engine.add_trade(db, CTX, r["job"]["id"], "window_cleaning", {"windows": 20}, registry=REG)
    est = service.get_estimate(db, CTX, r["estimate"]["id"])
    assert [s["module_id"] for s in est["sections"]] == ["pressure_washing", "window_cleaning"]
    # 1,500 x $0.15 = $225 driveway + 20 windows x $6 = $120
    assert r["estimate"]["total_cents"] == 34500 and r["job"]["lane"] == "quick_quote"
    assert r["job"]["trades"] == {"window_cleaning": {"windows": 20}}


def test_add_construction_trade_makes_standard_estimate(db):  # S8-M02
    r = _start(db, "pressure wash my driveway", answers={"driveway_sqft": 1500})
    r = engine.add_trade(db, CTX, r["job"]["id"], "concrete", {"area_sqft": 200, "remove_existing": True}, registry=REG)
    assert r["job"]["lane"] == "standard_estimate" and r["job"]["stage"] == "review"
    assert "standard estimate" in r["notes"][0]


def test_remove_trade_and_rules(db):  # S8-M03
    r = _start(db, "replace the roof", answers=ROOF)
    with pytest.raises(InvalidInput, match="main trade"):
        engine.add_trade(db, CTX, r["job"]["id"], "roofing", registry=REG)
    r = engine.add_trade(db, CTX, r["job"]["id"], "flooring", {"area_sqft": 500, "material": "lvp"}, registry=REG)
    assert r["estimate"]["total_cents"] == 781710 + 247125
    r = engine.add_trade(db, CTX, r["job"]["id"], "flooring", remove=True, registry=REG)
    assert r["estimate"]["total_cents"] == 781710 and r["job"]["trades"] == {}
    with pytest.raises(NotFound):
        engine.add_trade(db, CTX, r["job"]["id"], "flooring", remove=True, registry=REG)
    r = _next(db, r, reviewed=True, approve=True, confirm_sample_prices=True)
    with pytest.raises(NotEditable, match="revision"):
        engine.add_trade(db, CTX, r["job"]["id"], "flooring", {"area_sqft": 100, "material": "lvp"}, registry=REG)


def test_bid_by_trade_totals(db):  # S8-M04
    r = _start(db, "replace the roof", answers=ROOF)
    r = engine.add_trade(db, CTX, r["job"]["id"], "flooring", {"area_sqft": 500, "material": "lvp"}, registry=REG)
    r = _next(db, r, reviewed=True, approve=True, confirm_sample_prices=True)
    with pytest.raises(InvalidInput, match="price_detail"):
        bids.generate(db, CTX, r["estimate"]["id"], price_detail="fancy", registry=REG)
    setup.setup_step(db, CTX, "bid_template", {"price_detail": "trade_totals"})
    b = bids.generate(db, CTX, r["estimate"]["id"], registry=REG)
    html = open(b["html_path"], encoding="utf-8").read()
    assert "<b>Roofing</b>" in html and "$7,817.10" in html and "$2,471.25" in html and "$1,191.30" not in html
    text = bids.preview(db, CTX, b["id"])["text"]
    assert "Roofing: $7,817.10" in text and "Flooring: $2,471.25" in text and "TOTAL: $10,288.35" in text
    lines = bids.generate(db, CTX, r["estimate"]["id"], price_detail="lines", registry=REG)
    assert "$1,191.30" in open(lines["html_path"], encoding="utf-8").read()   # tear-off line shown when itemised


# ---------------------------------------------------------------- playbook changes

def test_playbook_review_limit_override(db):  # S8-P01
    overrides.update_overrides(db, CTX, "standard_estimate", {"review_required_over_cents": 1_000_000}, registry=REG)
    assert overrides.effective_settings(db, "default", "standard_estimate")["review_required_over_cents"] == 1_000_000
    assert overrides.effective_settings(db, "default", "quick_quote")["review_required_over_cents"] == 50000
    r = _start(db, "replace the roof", answers=ROOF)
    assert r["job"]["stage"] == "approve"                   # $7,817 is under the company's $10,000 limit


def test_required_checklist(db):  # S8-P02
    overrides.update_overrides(db, CTX, "standard_estimate",
                               {"checklist": {"roofing": ["Site photo taken"], "*": ["Customer name confirmed"]}},
                               registry=REG)
    r = _start(db, "replace the roof", answers=ROOF)
    r = _next(db, r, reviewed=True, approve=True, confirm_sample_prices=True)
    assert r["estimate"]["status"] == "in_review" and any("checklist" in n for n in r["notes"])
    assert r["next_step"]["checklist"] == ["Customer name confirmed", "Site photo taken"]
    assert "Site photo taken" in r["next_step"]["say"]
    r = _next(db, r, approve=True, confirm_sample_prices=True, checklist_done=True)
    assert r["estimate"]["status"] == "approved"
    step = [s for s in engine.status(db, CTX, r["job"]["id"])["steps"] if s["stage"] == "approve"][-1]
    assert step["state"] == "done"
    flooring = _start(db, "new lvp floors", answers={"area_sqft": 100, "material": "lvp"})
    assert flooring["next_step"]["checklist"] == ["Customer name confirmed"]


def test_playbook_update_rules(db):  # S8-P03
    with pytest.raises(PermissionDenied):
        overrides.update_overrides(db, ESTIMATOR, "standard_estimate", {"checklist": {"*": ["x"]}}, registry=REG)
    with pytest.raises(InvalidInput, match="can't change"):
        overrides.update_overrides(db, CTX, "standard_estimate", {"quick_send_limit_cents": 5}, registry=REG)
    with pytest.raises(InvalidInput, match="module id"):
        overrides.update_overrides(db, CTX, "standard_estimate", {"checklist": {"bakery": ["x"]}}, registry=REG)
    with pytest.raises(NotFound):
        overrides.update_overrides(db, CTX, "moon", {}, registry=REG)
    out = overrides.update_overrides(db, CTX, "quick_quote", {"quick_send_limit_cents": 25000,
                                                              "checklist": {"*": ["Photo"]}}, registry=REG)
    assert out["overrides"] == {"quick_send_limit_cents": 25000, "checklist": {"*": ["Photo"]}}
    out = overrides.update_overrides(db, CTX, "quick_quote", {"checklist": {"*": None}}, registry=REG)
    assert out["overrides"] == {"quick_send_limit_cents": 25000}
    assert overrides.update_overrides(db, CTX, "quick_quote", {}, reset=True, registry=REG)["overrides"] == {}
    ev = db.execute("SELECT COUNT(*) FROM estimate_events WHERE action = 'playbook_changed'").fetchone()[0]
    assert ev == 3


# ---------------------------------------------------------------- site visits

def test_site_visit_booking(db, fake_host):  # S8-V01
    r = _start(db, "replace the roof", customer={"name": "Pat Smith", "address": "12 Oak St", "city": "Chandler"})
    with pytest.raises(InvalidInput, match="turned off"):
        engine.book_site_visit(db, CTX, r["job"]["id"], "2026-11-12", registry=REG)
    update_settings(db, CTX, {"calendar_booking_enabled": True})
    with pytest.raises(ConfirmationRequired, match="Pat Smith at 12 Oak St on Thursday, November 12 at 09:00"):
        engine.book_site_visit(db, CTX, r["job"]["id"], "2026-11-12", start_time="09:00", registry=REG)
    out = engine.book_site_visit(db, CTX, r["job"]["id"], "2026-11-12", start_time="09:00", end_time="10:00",
                                 confirm=True, registry=REG)
    assert out["visit_job_id"] == "JOB-0001" and out["customer_id"] == "CUST-0001"
    job = fake_host.named("create_job")[0]["updates"]
    assert job["Service Type"] == "Site visit (estimate: Roofing)" and job["Service Date"] == "2026-11-12"
    assert job["Start Time"] == "09:00" and job["Job Status"] == "Scheduled"
    st = engine.status(db, CTX, r["job"]["id"])
    assert any(s["stage"] == "site_visit" for s in st["steps"])
    engine.book_site_visit(db, CTX, r["job"]["id"], "2026-11-19", confirm=True, registry=REG)
    assert len(fake_host.named("create_customer")) == 1          # customer reused the second time


@pytest.mark.parametrize("kw, msg", [({"date": "next tuesday"}, "YYYY-MM-DD"),
                                     ({"date": "2026-11-12", "start_time": "9am"}, "HH:MM")])
def test_site_visit_bad_input(db, kw, msg):  # S8-V02
    update_settings(db, CTX, {"calendar_booking_enabled": True})
    r = _start(db, "replace the roof", customer={"name": "Pat"})
    with pytest.raises(InvalidInput, match=msg):
        engine.book_site_visit(db, CTX, r["job"]["id"], registry=REG, **kw)
    r2 = _start(db, "replace the roof")
    with pytest.raises(InvalidInput, match="who is the customer"):
        engine.book_site_visit(db, CTX, r2["job"]["id"], "2026-11-12", registry=REG)


def test_customer_picks_option_after_quote_sent(db, fake_host):  # S8-O08
    update_settings(db, CTX, {"review_required_over_cents": 10_000_000})
    r = _start(db, "replace the roof", answers=ROOF, customer={"email": "pat@example.com"})
    r = _next(db, r, scenarios=True)
    r = _next(db, r, approve=True, confirm_sample_prices=True, send=True, confirm=True)
    assert r["job"]["stage"] == "follow_up"
    r = _next(db, r, revise=True, change_summary="customer chose metal", choose_scenario="best")
    assert r["job"]["answers"]["material"] == "metal" and r["estimate"]["status"] == "draft"
    assert r["estimate"]["total_cents"] > 781710 and r["job"]["stage"] == "approve"
