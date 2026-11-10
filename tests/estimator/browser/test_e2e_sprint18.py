"""Coder 2 Sprint 18 E2E GUI tests (Playwright, human mode): guided tours, help panel, empty states.

    run_tests_estimator.bat browser -k E2E_S18 [--human]

See tests/estimator/E2E_GUI_TEST_PLAN.md.
"""
import pytest

from browser_helpers import type_in
from e2e_helpers import CTX, dismiss_tour, nav_ids, sign_in_as, sign_in_many
from estimator.drawing_model import engine, store
from estimator.estimating import service
from estimator import practice
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape

CTX_ = CTX


@pytest.fixture
def power_job(db, tmp_path):
    """A read plan set with symbols, for the practice tour's plan steps."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("flag", None, "SPECIAL DEVICE")])
    lines = (ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90)
             + shape("flag", 12, 8) + shape("flag", 14, 8, 30))
    est = service.create_estimate(db, CTX, "Smith house")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "power.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps}


@pytest.fixture
def practice_with_plans(db, tmp_path, power_job):
    """The practice project, with the power plan set seeded onto it."""
    made = practice.create(db, CTX)
    pid = made["estimate_id"]
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5)
    ps = store.upload(db, CTX, pid, str(make_pdf(tmp_path / "practice.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return pid


def tour_title(page):
    return page.inner_text("#tour-title")


def tour_next(page):
    page.click("#tour-next")


def wait_tour(page):
    page.wait_for_selector("#tour-pop:visible", timeout=10000)


# ------------------------------------------------------------------ M1: autostart once

def test_E2E_S18_M1_tour_autostart_once(page):
    page.goto(page.base + "#/dashboard")
    wait_tour(page)
    assert tour_title(page) == "Start a quote in two minutes"
    assert "Step 1 of 5" in page.inner_text("#tour-count")
    # Skip: reopening the dashboard never auto-starts it again.
    page.click("#tour-skip")
    page.wait_for_selector("#tour-pop", state="hidden")
    page.goto(page.base + "#/projects")
    wait_tour(page)  # a different screen's tour does start (first open)
    assert tour_title(page) == "Name the project"
    # X closes without saving: reopening that screen starts its tour again.
    page.click("#tour-x")
    page.wait_for_selector("#tour-pop", state="hidden")
    page.goto(page.base + "#/dashboard")
    page.wait_for_timeout(800)
    assert page.locator("#tour-pop:visible").count() == 0  # dashboard was skipped
    page.goto(page.base + "#/projects")
    wait_tour(page)
    assert tour_title(page) == "Name the project"
    # Finish it this time: Back works, and the last step says Finish.
    tour_next(page)
    assert page.locator("#tour-back:not([disabled])").count() == 1
    page.click("#tour-back")
    assert tour_title(page) == "Name the project"
    for _ in range(3):
        tour_next(page)
    assert page.inner_text("#tour-next") == "Finish"
    tour_next(page)
    page.wait_for_selector("#tour-pop", state="hidden")
    page.goto(page.base + "#/dashboard")
    page.wait_for_timeout(500)
    page.goto(page.base + "#/projects")
    page.wait_for_timeout(800)
    assert page.locator("#tour-pop:visible").count() == 0


# ------------------------------------------------------------------ M2: popup positioning

def test_E2E_S18_M2_tour_popup_positioning(page):
    page.set_viewport_size({"width": 900, "height": 600})
    page.goto(page.base + "#/dashboard")
    wait_tour(page)
    vw, vh = 900, 600
    for step in range(5):
        box = page.locator("#tour-pop").bounding_box()
        assert box is not None
        assert box["x"] >= 0 and box["y"] >= 0, box
        assert box["x"] + box["width"] <= vw + 1, box
        assert box["y"] + box["height"] <= vh + 1, box
        if step < 4:
            tour_next(page)
            page.wait_for_function(f"() => document.querySelector('#tour-count').textContent.includes('Step {step + 2} of')")
    # A step near the bottom flips above its control instead of running off the page:
    # replay the dashboard tour in a short viewport and walk to the last step.
    page.click("#tour-skip")
    page.set_viewport_size({"width": 900, "height": 320})
    page.goto(page.base + "#/dashboard")
    page.wait_for_selector("#dash-quick")
    page.click("#help-link")
    page.wait_for_selector("#help-panel:visible")
    page.locator("#help-panel-replay button", has_text="Replay the Dashboard tour").click()
    wait_tour(page)
    for _ in range(4):
        tour_next(page)
        page.wait_for_timeout(300)
    box = page.locator("#tour-pop").bounding_box()
    assert box is not None
    assert box["x"] >= 0 and box["y"] >= 0 and box["x"] + box["width"] <= 901, box
    assert box["y"] + box["height"] <= 321, box  # flipped above, not off the bottom
    # A step with no control is centred in view (the practice tour with no practice project yet).
    page.click("#tour-skip")
    page.click("#help-link")
    page.wait_for_selector("#help-panel:visible")
    page.locator("#help-panel-replay button", has_text="Practice project tour").click()
    wait_tour(page)
    box = page.locator("#tour-pop").bounding_box()
    vw = page.evaluate("window.innerWidth")
    assert abs((box["x"] + box["width"] / 2) - vw / 2) < 30, box  # centred
    assert box["y"] + box["height"] <= 321, box


# ------------------------------------------------------------------ M3: practice tour

def test_E2E_S18_M3_practice_tour_no_stuck(page, practice_with_plans):
    page.goto(page.base + "#/dashboard")
    wait_tour(page)
    page.click("#tour-skip")
    page.click("#help-link")
    page.wait_for_selector("#help-panel:visible")
    page.locator("#help-panel-replay button", has_text="Practice project tour").click()
    wait_tour(page)
    assert "Practice: Garcia house" in page.inner_text("#tour-body") or "practice project" in page.inner_text("#tour-body").lower()
    seen = []
    for _ in range(12):
        try:
            page.wait_for_selector("#tour-pop:visible", timeout=5000)
        except Exception:
            break
        seen.append(tour_title(page))
        tour_next(page)
        page.wait_for_timeout(400)
    assert page.locator("#tour-pop:visible").count() == 0, seen  # finished, never stuck
    assert "Start on the practice project" in seen
    assert len(seen) >= 4, seen  # it walked, not skipped wholesale


# ------------------------------------------------------------------ M4: help panel

def test_E2E_S18_M4_help_panel_search_escape(page):
    page.goto(page.base + "#/dashboard")
    page.wait_for_selector("#dash-quick")
    dismiss_tour(page)
    page.click("#help-link")
    page.wait_for_selector("#help-panel:visible")
    assert "Help" in page.inner_text("#help-panel-title")
    # The panel lists only this screen's guides, and the filter matches title/id:
    # the dashboard has one guide, "Use the dashboard", so search for that
    # ("quote" lives on the quick screen's guide and can never match here).
    type_in(page, "#help-panel-find", "dashboard")
    page.wait_for_function("() => document.querySelectorAll('#help-panel-list li a').length >= 1")
    assert page.locator("#help-panel-list li a").count() >= 1
    type_in(page, "#help-panel-find", "zzz-no-such-guide")
    page.wait_for_function("() => document.querySelector('#help-panel-list').textContent.includes('Nothing matches')")
    page.keyboard.press("Escape")
    page.wait_for_selector("#help-panel", state="hidden")
    # The panel's link lands on the full Help screen.
    page.click("#help-link")
    page.wait_for_selector("#help-panel:visible")
    page.click("#help-panel-all")
    page.wait_for_url("**#/help*")
    page.wait_for_selector("#help-find")
    assert "Guides for the Dashboard screen" in page.inner_text("main") or "Dashboard" in page.inner_text("main")
    # A hash change closes the panel. The Help screen itself renders no "?"
    # button (renderHelp has no helpLink), so open the panel from the
    # dashboard, which does, then leave for Projects.
    page.goto(page.base + "#/dashboard")
    page.wait_for_selector("#dash-quick")
    dismiss_tour(page)  # the Help tour autostarted on #/help; its pop-up survives the route
    page.click("#help-link")
    page.wait_for_selector("#help-panel:visible")
    page.goto(page.base + "#/projects")
    page.wait_for_selector("#filter-status")
    assert page.locator("#help-panel:visible").count() == 0


# ------------------------------------------------------------------ M5: help screen replay + states

def test_E2E_S18_M5_help_replay_states(page):
    page.goto(page.base + "#/dashboard")
    wait_tour(page)
    page.click("#tour-skip")  # dashboard -> skipped
    page.goto(page.base + "#/projects")
    wait_tour(page)
    for _ in range(3):
        tour_next(page)
    assert page.inner_text("#tour-next") == "Finish"
    tour_next(page)  # projects -> completed
    page.wait_for_selector("#tour-pop", state="hidden")
    page.goto(page.base + "#/help")
    page.wait_for_selector("#help-tours")
    # Landing on #/help autostarts the Help tour; dismiss it first, or the
    # Replay click below no-ops (startTour returns while tourCurrent is set).
    page.wait_for_timeout(800)
    if page.locator("#tour-pop:visible").count():
        page.click("#tour-x")
        page.wait_for_selector("#tour-pop", state="hidden")
    tours = page.inner_text("#help-tours")
    assert "Dashboard" in tours and "skipped" in tours
    assert "Projects" in tours and "done" in tours
    # Replay the Help tour itself: its steps are on this screen, so the pop-up shows.
    page.locator("#help-tours li", has_text="Help").locator("button", has_text="Replay").click()
    wait_tour(page)
    assert tour_title(page) == "Search the guides"
    page.click("#tour-x")
    page.wait_for_selector("#tour-pop", state="hidden")


# ------------------------------------------------------------------ M6: mobile tour

def test_E2E_S18_M6_mobile_tour_reviews(phone, power_job):
    phone.goto(phone.base + "?embed=1#/m/reviews?kind=symbol")
    phone.wait_for_selector("#mrev-card")
    wait_tour(phone)
    assert tour_title(phone) == "What to check"
    assert phone.url.endswith("#/m/reviews") or "#/m/reviews" in phone.url
    for want in ("One item at a time", "Approve or take out", "Not sure? Skip it"):
        tour_next(phone)
        phone.wait_for_function(f"() => document.querySelector('#tour-title').textContent === '{want}'")
    assert phone.inner_text("#tour-next") == "Finish"
    tour_next(phone)
    phone.wait_for_selector("#tour-pop", state="hidden")
    # The phone buttons are real: swiping still works after the tour closes.
    first = phone.get_attribute("#mrev-card", "data-id")
    b = phone.locator("#mrev-card").bounding_box()
    y = b["y"] + b["height"] / 2
    phone.mouse.move(b["x"] + b["width"] - 20, y)
    phone.mouse.down()
    for step in range(1, 9):
        phone.mouse.move(b["x"] + b["width"] - 20 - step * 30, y)
    phone.mouse.up()
    phone.wait_for_selector("#mrev-confirm-box")
    assert "out of the count" in phone.inner_text("#mrev-confirm-box")


# ------------------------------------------------------------------ M7: empty states

def test_E2E_S18_M7_empty_states_links(page, db):
    page.goto(page.base + "#/projects")
    page.wait_for_selector("#new-project")
    dismiss_tour(page)
    assert "No projects yet" in page.inner_text("main")
    page.goto(page.base + "#/estimates")
    page.wait_for_selector("#estimates-empty")
    dismiss_tour(page)
    assert "No estimates" in page.inner_text("#estimates-empty")
    page.click("#estimates-empty a")
    page.wait_for_url("**#/projects")
    page.goto(page.base + "#/agents")
    page.wait_for_selector("#agents-list, #agents-empty")
    dismiss_tour(page)
    # A fresh company already has one agent per construction trade
    # (list_configs builds one per registry trade), so the Agents screen
    # shows the list, not the empty state; the empty-state wording itself
    # is covered statically by test_web_sprint18 W20.
    assert page.locator("#agents-list").count() == 1
    assert page.locator("#agents-list tr[data-module=roofing]").count() == 1
    page.goto(page.base + "#/jobs")
    page.wait_for_selector("#jobs-empty")
    dismiss_tour(page)
    assert "No jobs yet" in page.inner_text("#jobs-empty")
    page.click("#jobs-quick")
    page.wait_for_url("**#/quick")
    # A project with no plans: the empty state says what to do next, with the upload control.
    est = service.create_estimate(db, CTX, "Empty house")
    db.commit()
    page.goto(page.base + f"#/projects/{est['id']}")
    page.wait_for_selector("#plan-upload")
    assert "No trades priced yet" in page.inner_text("main")
    page.goto(page.base + "#/plans")
    page.wait_for_selector("#plans-empty")
    assert "No plans yet" in page.inner_text("#plans-empty")


# ------------------------------------------------------------------ M8: per-user progress + role gates

def test_E2E_S18_M8_tour_per_user_progress(browser, site):
    problems = []
    ctx1 = browser.new_context(viewport={"width": 1400, "height": 950})
    ctx2 = browser.new_context(viewport={"width": 1400, "height": 950})
    p1 = ctx1.new_page()
    p2 = ctx2.new_page()
    for pg in (p1, p2):
        pg.set_default_timeout(15000)
        pg.on("pageerror", lambda e: problems.append(str(e)))
        pg.base = site
    try:
        with sign_in_many([(p2, "estimator")]):
            p1.goto(p1.base + "#/dashboard")
            p1.wait_for_selector("#tour-pop:visible", timeout=10000)
            p1.click("#tour-skip")
            p1.wait_for_selector("#tour-pop", state="hidden")
            # The estimator has not skipped it: their first open still auto-starts.
            p2.goto(p2.base + "#/dashboard")
            p2.wait_for_selector("#tour-pop:visible", timeout=10000)
            assert p2.inner_text("#tour-title") == "Start a quote in two minutes"
            p2.click("#tour-skip")
            p2.wait_for_selector("#tour-pop", state="hidden")
            # "?" opens the panel on a screen each role can open.
            p2.goto(p2.base + "#/agents")
            p2.wait_for_selector("#agents-list, #agents-empty")
            p2.wait_for_timeout(400)
            if p2.locator("#tour-pop:visible").count():
                p2.click("#tour-skip")
            p2.click("#help-link")
            p2.wait_for_selector("#help-panel:visible")
            assert "Agents" in p2.inner_text("#help-panel-title")
            p1.goto(p1.base + "#/dashboard")
            p1.wait_for_timeout(800)
            assert p1.locator("#tour-pop:visible").count() == 0
            p2.goto(p2.base + "#/dashboard")
            p2.wait_for_timeout(800)
            assert p2.locator("#tour-pop:visible").count() == 0
    finally:
        ctx1.close()
        ctx2.close()
    assert not problems, problems
