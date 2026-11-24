"""🔄 Update from the plans (2026-11-23, David: "When I hit update from the plan, a popup asking for yes but it closes
before I press anything? Its a bug."). Asking for the yes posted to the server, which told the Director panel the
project changed - it looked again and redrew itself, wiping its own Yes/Cancel box. The question changes nothing, so it
doesn't count as a change, and the panel never redraws over a question waiting for an answer.

    browser_upload.bat tests\\estimator\\browser\\test_browser_update_from_plans.py
"""
from estimator.context import personal_context
from estimator.estimating import quick, service
from estimator.takeoff import measurements as ms

CTX = personal_context()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}


def _approved_then_remeasured(db):
    e = service.create_estimate(db, CTX, "Roof")
    e = quick.answer(db, CTX, e["id"], "roofing", ROOF, e["rev"])
    service.set_status(db, CTX, e["id"], service.get_estimate(db, CTX, e["id"])["rev"], "approved")
    ms.manual(db, CTX, e["id"], "roofing", feeds="roof_area_sqft", qty="2400", unit="sqft", approve=True, confirm=True)
    db.commit()
    return e["id"]


def test_the_directors_yes_box_stays_until_answered(page, db):
    eid = _approved_then_remeasured(db)
    page.goto(page.base + f"#/estimates/{eid}")
    page.wait_for_selector("#director-plans-update")
    page.click("#director-plans-update")
    page.wait_for_selector("#director-update-confirm-box")
    page.wait_for_timeout(3500)                          # the panel used to look again ~1.2 s later and wipe it
    assert page.locator("#director-update-confirm-box").is_visible()
    page.click("#director-update-confirm")
    page.wait_for_function("() => !document.querySelector('#director-update-confirm-box')", timeout=15000)
    page.wait_for_timeout(500)
    est = service.get_estimate(db, CTX, eid)
    assert est["status"] == "draft"
    sec = next(s for s in est["sections"] if s["module_id"] == "roofing")
    assert float(sec["answers"]["roof_area_sqft"]) == 2400


def test_the_estimates_own_button_asks_and_waits_too(page, db):
    eid = _approved_then_remeasured(db)
    page.goto(page.base + f"#/estimates/{eid}")
    page.wait_for_selector("#estimate-update-plans")
    page.click("#estimate-update-plans")
    page.wait_for_selector("#update-plans-confirm-box")
    page.wait_for_timeout(3500)
    assert page.locator("#update-plans-confirm-box").is_visible()
    page.click("#update-plans-cancel")
    assert "nothing changed" in page.inner_text("#update-plans-ask")
