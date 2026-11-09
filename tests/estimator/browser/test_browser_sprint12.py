"""Coder 2 Sprint 12 browser tests (Tester 2): the Plan quantities page - from Blueprint Review to the rooms, doors
and windows, and each trade's answers from the one wall-and-room model; changing the ceiling height.

    run_tests_estimator.bat browser [--human]
"""
import pytest

from browser_helpers import type_in
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service
from pdfmaker import make_pdf
from test_plan_engine_sprint12 import HOUSE, NAMES, SCHEDULES, TAGS, page as sheet

CTX = personal_context()


@pytest.fixture
def house(db, tmp_path):
    """Two rooms (LIVING 120 sq ft, BEDROOM 114 sq ft) with 6" walls, an entry door, a bedroom door and a window."""
    est = service.create_estimate(db, CTX, "Smith house")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "house.pdf", [sheet(NAMES + SCHEDULES + TAGS, HOUSE)])),
                      confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return est["id"]


def cell(page, trade, question):
    return page.inner_text(f"#qty-trade-{trade} [data-q={question}] td.num")


def test_plan_quantities_from_blueprint_review(page, house):                    # C2S12-B07
    page.goto(page.base + f"#/takeoffs/{house}")
    page.click("#bp-quantities")
    page.wait_for_selector("#qty-rooms")
    assert page.locator("#qty-rooms tbody tr").count() == 2
    assert "LIVING" in page.inner_text("#qty-rooms") and "BEDROOM" in page.inner_text("#qty-rooms")
    assert page.locator("#qty-openings tbody tr").count() == 3
    assert "2 room(s), 234 sq ft" in page.inner_text("#qty-summary")
    # Every trade from the same model: drywall's ceiling is flooring's floor.
    assert cell(page, "drywall", "ceiling_sqft") == cell(page, "flooring", "area_sqft") == "234"
    assert cell(page, "framing", "wall_height") == "8"
    assert "approve them in Reviews" in page.inner_text("#qty-trade-electrical")
    # A 10 ft ceiling where the plans don't say.
    type_in(page, "#qty-height", "10")
    page.click("#qty-apply")
    page.wait_for_function("() => location.hash.includes('height=10')")
    page.wait_for_function("() => { const c = document.querySelector('#qty-trade-framing [data-q=wall_height] td.num');"
                           " return c && c.textContent === '10'; }")
    assert "10 ft" in page.inner_text("#qty-rooms tbody tr")


def test_a_project_without_plans_says_so(page, db):                              # C2S12-B08
    est = service.create_estimate(db, CTX, "No plans yet")
    db.commit()
    page.goto(page.base + f"#/quantities/{est['id']}")
    page.wait_for_selector("#qty-empty")
    assert "Read the plans" in page.inner_text("#qty-empty")
    assert page.locator("#qty-trades .card").count() == 7
