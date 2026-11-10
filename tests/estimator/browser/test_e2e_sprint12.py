"""Coder 2 Sprint 12 E2E GUI tests (Playwright, human mode): ceiling height, approved-symbol counts, tankless water
heater, drywall vs painting arithmetic — all on the Plan quantities page and Reviews.

    run_tests_estimator.bat browser -k E2E_S12 [--human]

Builds on the existing Sprint 12 browser tests (test_browser_sprint12.py: B07/B08) and extends the assertions to the
full M-check wording. See tests/estimator/E2E_GUI_TEST_PLAN.md. M1/M2/M3/M7 stay MANUAL (real-plan accuracy / live AI).
"""
import pytest

from browser_helpers import answer_yes, type_in
from e2e_helpers import CTX, dismiss_tour
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape
from test_plan_engine_sprint12 import HOUSE, NAMES, SCHEDULES, TAGS, page as sheet

CTX_ = CTX


@pytest.fixture
def house(db, tmp_path):
    """Two rooms (LIVING 120 sq ft, BEDROOM 114 sq ft) with 6" walls, an entry door, a bedroom door and a window.
    Same seed as test_browser_sprint12.py: perimeters 44 / 43 ft, openings 38.8 / 29.8 sq ft, height 8 ft."""
    est = service.create_estimate(db, CTX, "Smith house")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "house.pdf", [sheet(NAMES + SCHEDULES + TAGS, HOUSE)])),
                      confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps}


@pytest.fixture
def elec(db, tmp_path):
    """3 duplex receptacles, a water closet, a tankless water heater (legend) and a smoke detector.
    Same seed as test_plan_engine_sprint12.py C2S12-L03: approving 2 receptacles leaves 1 still to check;
    approving the rest gives plumbing toilets 1 and water_heater tankless."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("tri", None, "WATER CLOSET"),
                     ("flag", None, "TANKLESS WATER HEATER"), ("quad", None, "SMOKE DETECTOR")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + shape("tri", 12, 5) + \
        shape("flag", 14, 5) + shape("quad", 16, 5)
    est = service.create_estimate(db, CTX, "Bath remodel")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "e.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps}


def cell(page, trade, question):
    return page.inner_text(f"#qty-trade-{trade} [data-q={question}] td.num")


def num(text):
    return float(text.replace(",", "").strip())


def room_wall_sqft(page, name):
    row = page.locator("#qty-rooms tbody tr", has_text=name)
    return row.locator("td").nth(5).inner_text()


def open_quantities(page, est_id, query=""):
    page.goto(page.base + f"#/quantities/{est_id}" + query)
    page.wait_for_selector("#qty-trades")
    dismiss_tour(page)


def open_reviews(page, plan_set_id):
    page.goto(page.base + f"#/reviews/{plan_set_id}")
    page.wait_for_selector("#symrev-grid")
    dismiss_tour(page)


def wait_cards(page, n):
    page.wait_for_function(f"() => document.querySelectorAll('#symrev-grid .sym-card').length === {n}")


# ------------------------------------------------------------------ M4: ceiling height 9 ft

def test_E2E_S12_M4_ceiling_height_recalc(page, house):
    open_quantities(page, house["estimate_id"])
    page.wait_for_selector("#qty-rooms")
    # Baseline at 8 ft: rooms' wall areas are perimeter x 8 less openings.
    assert room_wall_sqft(page, "LIVING") == "313.2"      # 44 x 8 - 38.8
    assert room_wall_sqft(page, "BEDROOM") == "314.2"     # 43 x 8 - 29.8
    assert cell(page, "painting", "wall_sqft") == "627.4"
    assert cell(page, "framing", "wall_height") == "8"
    assert cell(page, "drywall", "wall_height") == "8"
    # Change the ceiling height to 9 ft.
    type_in(page, "#qty-height", "9")
    page.click("#qty-apply")
    page.wait_for_function("() => location.hash.includes('height=9')")
    page.wait_for_function("() => { const c = document.querySelector('#qty-trade-framing [data-q=wall_height] td.num');"
                           " return c && c.textContent === '9'; }")
    # Drywall and painting wall areas go up by perimeter x 1 ft (44 + 43 = 87 sq ft in all).
    assert room_wall_sqft(page, "LIVING") == "357.2"      # 44 x 9 - 38.8
    assert room_wall_sqft(page, "BEDROOM") == "357.2"     # 43 x 9 - 29.8
    assert cell(page, "painting", "wall_sqft") == "714.4"
    assert cell(page, "drywall", "wall_height") == "9"
    assert cell(page, "framing", "wall_height") == "9"   # framing says "9"
    assert cell(page, "drywall", "wall_lf") == "87"      # the lengths didn't move, only the height
    assert "9 ft" in page.inner_text("#qty-rooms tbody tr >> nth=0")


# ------------------------------------------------------------------ M5: approved counts after reload

def test_E2E_S12_M5_approved_counts_after_reload(page, elec):
    open_reviews(page, elec["plan_set_id"])
    wait_cards(page, 6)
    # Approve two of the three outlets in Reviews.
    page.click("#symrev-types [data-type=duplex_receptacle]")
    wait_cards(page, 3)
    cards = page.locator("#symrev-grid .sym-card")
    cards.nth(0).click()
    cards.nth(1).click()
    assert page.inner_text("#symrev-count") == "3 matches, 2 selected"
    page.click("#symrev-approve")
    answer_yes(page, "symrev")
    page.wait_for_function("() => document.querySelectorAll('#symrev-grid .sym-card[data-status=approved]').length === 2")
    # Reload: the approvals stuck.
    page.goto(page.base + f"#/reviews/{elec['plan_set_id']}")
    page.wait_for_selector("#symrev-grid")
    wait_cards(page, 6)
    page.click("#symrev-types [data-type=duplex_receptacle]")
    wait_cards(page, 3)
    assert page.locator("#symrev-grid .sym-card[data-status=approved]").count() == 2
    # Plan quantities: electrical outlets = the approved count, the rest still to check.
    open_quantities(page, elec["estimate_id"])
    assert cell(page, "electrical", "outlets") == "2"
    assert "1 still to check" in page.inner_text("#qty-trade-electrical")
    assert "approve them in Reviews" not in page.inner_text("#qty-trade-electrical")
    # Tick the box to count symbols still to check: all three count now.
    page.check("#qty-proposed")
    page.click("#qty-apply")
    page.wait_for_function("() => location.hash.includes('proposed=1')")
    page.wait_for_function("() => { const c = document.querySelector('#qty-trade-electrical [data-q=outlets] td.num');"
                           " return c && c.textContent === '3'; }")
    assert cell(page, "electrical", "outlets") == "3"


# ------------------------------------------------------------------ M6: tankless water heater

def test_E2E_S12_M6_tankless_water_heater(page, elec):
    open_reviews(page, elec["plan_set_id"])
    wait_cards(page, 6)
    # The tankless water heater is in the legend: its card names it.
    assert "tankless" in page.inner_text("#symrev-grid").lower()
    assert page.locator("#symrev-types [data-type=tankless_water_heater]").count() == 1
    # Approve everything (the heater, the water closet, the outlets, the smoke detector).
    page.click("#symrev-all")
    assert page.inner_text("#symrev-count") == "6 matches, 6 selected"
    page.click("#symrev-approve")
    answer_yes(page, "symrev")
    page.wait_for_function("() => document.querySelectorAll('#symrev-grid .sym-card[data-status=approved]').length === 6")
    # Plumbing: the water heater is tankless once it's approved.
    open_quantities(page, elec["estimate_id"])
    assert cell(page, "plumbing", "water_heater") == "tankless"
    assert cell(page, "plumbing", "toilets") == "1"
    assert cell(page, "electrical", "outlets") == "3"


# ------------------------------------------------------------------ M8: drywall vs painting arithmetic

def test_E2E_S12_M8_drywall_painting_arithmetic(page, house):
    open_quantities(page, house["estimate_id"])
    page.wait_for_selector("#qty-rooms")
    # Drywall hangs what painting paints: wall_lf x height + ceiling - openings = painting wall + ceiling.
    dry_wall = num(cell(page, "drywall", "wall_lf")) * num(cell(page, "drywall", "wall_height"))
    dry_total = dry_wall + num(cell(page, "drywall", "ceiling_sqft")) - num(cell(page, "drywall", "openings_sqft"))
    paint_total = num(cell(page, "painting", "wall_sqft")) + num(cell(page, "painting", "ceiling_sqft"))
    assert abs(dry_total - paint_total) < 0.1, (dry_total, paint_total)
    # The numbers behind it, from the same model.
    assert cell(page, "drywall", "wall_lf") == "87"          # both faces of the partition: the rooms' perimeters
    assert cell(page, "drywall", "ceiling_sqft") == "234"
    assert cell(page, "drywall", "openings_sqft") == "68.6"  # doors and windows, once for each room they open into
    assert cell(page, "painting", "wall_sqft") == "627.4"
    assert cell(page, "painting", "ceiling_sqft") == "234"
    assert cell(page, "flooring", "area_sqft") == "234"      # drywall's ceiling is flooring's floor
    assert cell(page, "framing", "wall_height") == "8"
