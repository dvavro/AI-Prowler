"""Coder 2 Sprint 11 browser tests (Tester 2): checking symbols in Reviews, adding a missed one and finding more like it,
Blueprint Review's Symbols tab and ?symbol= links, the Symbol Library and Agents screens.

    run_tests_estimator.bat browser [--human]
"""
import pytest

from browser_helpers import HUMAN, answer_yes, type_in
from e2e_helpers import dismiss_tour
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service
from estimator.runner import runner
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape

CTX = personal_context()


@pytest.fixture
def job(db, tmp_path):
    """A plan with a legend (receptacle, special device); 3 receptacles, 2 special devices, and 3 triangles that aren't
    in the legend (the engine misses them)."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("flag", None, "SPECIAL DEVICE")])
    lines = (ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90)
             + shape("flag", 12, 8) + shape("flag", 14, 8, 30)
             + shape("tri", 5, 10) + shape("tri", 8, 10, 90) + shape("tri", 11, 10, 200))
    est = service.create_estimate(db, CTX, "Smith house")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "power.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps, "sheet_id": store.sheets(db, CTX, ps)["sheets"][0]["id"]}


def tile_count(page, item_type):
    return int(page.inner_text(f"#symrev-types [data-type={item_type}] .num"))


def wait_cards(page, n):
    page.wait_for_function(f"() => document.querySelectorAll('#symrev-grid .sym-card').length === {n}")


def click_on_sheet(page, x, y):
    """Click the plan at sheet inches (x, y), holding Alt so the click isn't snapped to a corner."""
    cx, cy = page.evaluate("([x, y]) => { const v = RV.viewer, r = v.box.getBoundingClientRect();"
                           " return [r.left + v.tx + x * v.z, r.top + v.ty + y * v.z]; }", [x, y])
    page.keyboard.down("Alt")
    page.mouse.click(cx, cy)
    page.keyboard.up("Alt")


# ------------------------------------------------------------------ Reviews                        C2S11-B01

def test_check_symbols_approve_and_relabel(page, job):                             # C2S11-B01
    page.goto(page.base + "#/reviews")
    page.wait_for_selector("#reviews-list")
    assert "Smith house" in page.inner_text("#reviews-list tbody tr")
    page.click("#reviews-list tbody tr")
    wait_cards(page, 5)
    page.wait_for_function("() => [...document.querySelectorAll('#symrev-grid img.sym-thumb')]"
                           ".every(i => i.complete && i.naturalWidth > 0)")
    # Approve two of the three receptacles.
    page.click("#symrev-types [data-type=duplex_receptacle]")
    wait_cards(page, 3)
    cards = page.locator("#symrev-grid .sym-card")
    cards.nth(0).click()
    cards.nth(1).click()
    assert page.inner_text("#symrev-count") == "3 matches, 2 selected"
    dismiss_tour(page)  # the symbol-review tour autostarts on first open; its pop-up covers Approve
    page.click("#symrev-approve")
    answer_yes(page, "symrev")
    page.wait_for_function("() => document.querySelectorAll('#symrev-grid .sym-card[data-status=approved]').length === 2")
    # The unknown special devices: one is relabelled with every identical match.
    page.click("#symrev-types [data-type=unknown]")
    wait_cards(page, 2)
    page.locator("#symrev-grid .sym-card").nth(0).click()
    page.click("#symrev-relabel")
    type_in(page, "#symrev-relabel-type", "floor box")
    page.check("#symrev-relabel-all")
    page.click("#symrev-relabel-go")
    answer_yes(page, "symrev")
    page.wait_for_selector("#symrev-types [data-type=floor_box]")
    assert tile_count(page, "floor_box") == 2
    assert page.locator("#symrev-types [data-type=unknown]").count() == 0
    page.click("#symrev-types [data-type=floor_box]")
    wait_cards(page, 2)
    assert "was unidentified symbol" in page.inner_text("#symrev-grid .sym-card >> nth=0")     # the first result is kept


# ------------------------------------------------------------------ add a missed one, find more     C2S11-B02

def test_add_a_missed_symbol_on_the_plan_then_find_similar(page, job):             # C2S11-B02
    page.goto(page.base + f"#/takeoffs/{job['estimate_id']}")
    page.wait_for_selector("#bp-viewer img.bp-tile", state="attached")
    page.click("#bp-tools [data-tool=symbol]")
    click_on_sheet(page, 5, 10)                          # the first triangle
    page.wait_for_selector("#bp-symbol-form")
    type_in(page, "#bp-symbol-type", "thermostat")
    page.click("#bp-symbol-add")
    answer_yes(page, "bp-sym")
    page.click("#bp-tab-symbols")
    page.wait_for_selector("#bp-symbol-types [data-symbol-type=thermostat]")
    # In Reviews, find the other two.
    page.goto(page.base + f"#/reviews/{job['plan_set_id']}?type=thermostat")
    wait_cards(page, 1)
    card = page.locator("#symrev-grid .sym-card")
    assert card.get_attribute("data-status") == "approved" and "added by a person" in card.inner_text()
    card.click()
    page.click("#symrev-similar")
    page.wait_for_selector("#symrev-confirm-box")
    assert "Found 2 more" in page.inner_text("#symrev-confirm-box")
    answer_yes(page, "symrev")
    wait_cards(page, 3)
    assert tile_count(page, "thermostat") == 3
    assert page.locator("#symrev-grid .sym-card[data-status=proposed]").count() == 2    # the found ones are to check


# ------------------------------------------------------------------ Blueprint Review               C2S11-B03..B04

def test_open_on_the_plan_highlights_that_symbol(page, job):                       # C2S11-B03
    page.goto(page.base + f"#/reviews/{job['plan_set_id']}?type=duplex_receptacle")
    wait_cards(page, 3)
    first = page.locator("#symrev-grid .sym-card").nth(0)
    det = first.get_attribute("data-id")
    first.locator("a", has_text="open on the plan").click()
    page.wait_for_url(f"**#/takeoffs/{job['estimate_id']}?*symbol={det}*")
    page.wait_for_selector(f"#bp-symbol-detail[data-detection='{det}']")
    assert page.get_attribute("#bp-tab-symbols", "class").split().count("active") == 1
    assert page.locator("#bp-viewer [data-oid].sel").count() == 1
    assert "1 of 1" in page.inner_text("#bp-symbol-where")


def test_symbols_tab_highlights_a_type_and_steps_through(page, job):               # C2S11-B04
    page.goto(page.base + f"#/takeoffs/{job['estimate_id']}")
    page.wait_for_selector("#bp-viewer img.bp-tile", state="attached")
    page.click("#bp-tab-symbols")
    row = page.locator("#bp-symbol-types [data-symbol-type=duplex_receptacle]")
    assert "3 found" in row.inner_text() and "3 to check" in row.inner_text()
    row.click()
    assert page.inner_text("#bp-symbol-where") == "3 highlighted"
    assert page.locator("#bp-viewer [data-oid].sel").count() == 3
    page.click("#bp-symbol-next")
    assert page.inner_text("#bp-symbol-where") == "1 of 3"
    assert page.locator("#bp-viewer [data-oid].sel").count() == 1
    for _ in range(3):
        page.click("#bp-symbol-next")
    assert page.inner_text("#bp-symbol-where") == "1 of 3"                        # round again
    page.click("#bp-symbol-prev")
    assert page.inner_text("#bp-symbol-where") == "3 of 3"
    assert page.get_attribute("#bp-symbol-review", "href").endswith(f"#/reviews/{job['plan_set_id']}?type=duplex_receptacle")


# ------------------------------------------------------------------ Symbol Library, Agents         C2S11-B05..B06

def test_symbol_library_learns_and_defines(page, job, db):                         # C2S11-B05
    from estimator.symbols import review
    flags = [d["id"] for d in db.execute("SELECT id FROM symbol_detections WHERE item_type IS NULL")]
    review.review(db, CTX, flags[:1], "relabel", item_type="floor_box", apply_to_matches=True, confirm=True)
    db.commit()
    page.goto(page.base + "#/symbol_library")
    page.wait_for_selector("#symlib-company tr[data-type=floor_box]")
    assert "Your company's symbols" in page.inner_text("#symlib-company h3")
    assert page.locator("#symlib-standard tr[data-type]").count() >= 37
    page.click("#symlib-new")
    type_in(page, "#symlib-type", "data outlet")
    type_in(page, "#symlib-desc", "Data outlet, Cat 6")
    type_in(page, "#symlib-code", "D")
    page.click("#symlib-save")
    answer_yes(page, "symlib")
    page.wait_for_selector("#symlib-company tr[data-type=data_outlet]")
    assert page.get_attribute("#symlib-export", "href").endswith("/symbol-library/export")


def test_agents_settings_and_runs(page, db):                                        # C2S11-B06
    est = service.create_estimate(db, CTX, "Jones house")
    runner.start_run(db, CTX, est["id"], ["framing", "drywall"])
    db.commit()
    page.goto(page.base + "#/agents")
    num = "#agents-list tr[data-module=framing] input[type=number]"
    page.wait_for_selector(num)
    type_in(page, num, "90")
    page.click("#agents-list [data-save=framing]")
    answer_yes(page, "agents")
    page.wait_for_function(f"() => document.querySelector('{num}') && document.querySelector('{num}').value === '90'")
    page.click("#runs-list details summary")
    page.wait_for_selector("#runs-list tr[data-task]")
    states = page.inner_text("#runs-list .run-tasks")
    assert "framing" in states.lower() and "drywall" in states.lower() and "queued" in states.lower()
    if HUMAN:
        page.wait_for_timeout(1500)                       # a moment to look before the browser closes
