"""WIZ-01..WIZ-07 — the Getting-started wizard (🧙 on the Jobs screen).

Its steps ARE the app's typical day (customer -> quote -> job -> route ->
clock in/out -> photos/text -> invoice -> receipt), so this is also the map for
the typical-day flow test. Step titles are read from the running app
(WIZ_STEPS), so editing the wizard doesn't make these tests stale.
"""
import pytest
from playwright.sync_api import expect

from app_wizard import Wizard

DAY_FLOW = ["Add a customer", "Record a quote", "Add a job", "Build the route",
            "Clock in & out", "Add photos", "Invoice", "Send the receipt"]


@pytest.fixture
def wiz(app, page):
    app.goto("jobs")
    return Wizard(page, app.log)


def test_WIZ_01_opens_from_the_jobs_screen_at_step_1(wiz):
    steps = wiz.expected_steps()
    wiz.open()
    wiz.expect_at(0, len(steps), steps[0]["title"])
    assert wiz.has_button("Next") and wiz.has_button("Skip for now")
    assert not wiz.has_button("Back"), "step 1 must not offer Back"


def test_WIZ_02_next_walks_every_step_then_done_closes(wiz):
    steps = wiz.expected_steps()
    wiz.open()
    for i, s in enumerate(steps):
        wiz.expect_at(i, len(steps), s["title"])
        if s["voice"]:
            expect(wiz.body.locator(".wiz-voice")).to_contain_text("Try saying")
        assert wiz.has_button("Back") == (i > 0), f"step {i + 1}: Back shown={wiz.has_button('Back')}"
        last = i == len(steps) - 1
        if last:
            assert wiz.has_button("Done") and not wiz.has_button("Next")
            assert not wiz.has_button("Skip for now"), "Skip should be hidden on the last step"
            wiz.done()
        else:
            wiz.next()
    wiz.expect_closed()


def test_WIZ_03_back_returns_to_the_previous_step(wiz):
    steps = wiz.expected_steps()
    wiz.open()
    wiz.next()
    wiz.next()
    wiz.expect_at(2, len(steps), steps[2]["title"])
    wiz.back()
    wiz.expect_at(1, len(steps), steps[1]["title"])


def test_WIZ_04_skip_closes_and_reopening_starts_over(wiz):
    steps = wiz.expected_steps()
    wiz.open()
    wiz.next()
    wiz.next()
    wiz.skip()
    wiz.expect_closed()
    wiz.open()
    wiz.expect_at(0, len(steps), steps[0]["title"])


def test_WIZ_05_tapping_outside_closes_it(wiz):
    wiz.open()
    wiz.click_outside()
    wiz.expect_closed()


def test_WIZ_06_first_step_lays_out_the_typical_day(wiz):
    wiz.open()
    items = [t.strip() for t in wiz.body.locator(".wiz-list li").all_inner_texts()]
    assert items == DAY_FLOW, f"the wizard's day plan changed: {items}"


def test_WIZ_07_every_place_the_wizard_sends_you_exists(app, page):
    """The wizard tells users to use the Customers tab, the Quotes tab, the
    Pricing list, the Route tab, the Job Board and the 📖 Commands tab. A new
    user who can't find one of them is stuck — check each exists."""
    visible = app.visible_screens()
    missing = []
    for screen in ("route", "board", "jobs"):
        if screen not in visible:
            missing.append(f"'{screen}' screen in the bottom bar")
    if "sheet" not in visible:
        missing.append("Database screen (holds the Customers / Quotes / Pricing tabs)")
    else:
        app.goto("sheet")
        page.wait_for_timeout(800)
        tabs = " | ".join(t.strip() for t in page.locator("#sheetTabs").locator("button, a, [onclick]")
                          .all_inner_texts())
        for needed in ("Customers", "Quotes", "Pricing", "Commands"):
            if needed.lower() not in tabs.lower():
                missing.append(f"'{needed}' tab on the Database screen (tabs found: {tabs or 'none'})")
    app.goto("jobs")
    if not page.locator("#screen-jobs").get_by_text("Add", exact=False).first.is_visible():
        missing.append("'+ Add' button on the Jobs screen")
    assert not missing, "The wizard sends users to places that aren't there:\n  " + "\n  ".join(missing)
