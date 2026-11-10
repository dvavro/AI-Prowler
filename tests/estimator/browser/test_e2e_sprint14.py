"""Coder 2 Sprint 14 E2E GUI tests (Playwright, human mode): elevations, door/window schedule linking, HVAC library.

    run_tests_estimator.bat browser -k E2E_S14 [--human]

M7: a mechanical plan with a legend - diffusers, returns and thermostats counted
    after approval in Reviews; mini-split heads set the system.
M8: a plan with a garage - the HVAC area leaves the garage out and says so.
M1-M6 stay manual (real-plan accuracy). See tests/estimator/E2E_GUI_TEST_PLAN.md.
"""
import pytest

from browser_helpers import answer_yes
from e2e_helpers import CTX, dismiss_tour
from estimator.drawing_model import engine, store
from estimator.estimating import service
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape
from test_plan_engine_sprint12 import HOUSE, NAMES, page as sheet


@pytest.fixture
def hvac(db, tmp_path):
    """A mechanical plan (3 supply diffusers, 1 return grille, 1 thermostat,
    2 mini-split heads) plus the two-room floor plan (LIVING 120 + BEDROOM 114
    = 234 sq ft). Same seed as test_plan_engine_sprint14.py C2S14-H03."""
    lt, ll = legend([("recept", None, "SUPPLY DIFFUSER"), ("tri", None, "RETURN AIR GRILLE"),
                     ("flag", None, "THERMOSTAT"), ("quad", None, "DUCTLESS MINI-SPLIT INDOOR UNIT")])
    lines = ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90) + shape("tri", 12, 5) + \
        shape("flag", 14, 5) + shape("quad", 16, 5) + shape("quad", 18, 5)
    est = service.create_estimate(db, CTX, "HVAC job")
    ps = store.upload(db, CTX, est["id"],
                      str(make_pdf(tmp_path / "m.pdf", [plan(lt, lines), sheet(NAMES, HOUSE, sheet_no="A-101")])),
                      confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps}


@pytest.fixture
def garage(db, tmp_path):
    """The two-room floor plan with the rooms named LIVING and GARAGE (120 + 114
    sq ft). Same seed as test_plan_engine_sprint14.py C2S14-H04."""
    names = [(5.8, 6.5, 10, "LIVING"), (8.3, 6.5, 10, "GARAGE")]
    est = service.create_estimate(db, CTX, "Garage job")
    ps = store.upload(db, CTX, est["id"],
                      str(make_pdf(tmp_path / "house.pdf", [sheet(names, HOUSE)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps}


def cell(page, trade, question):
    """One trade answer's number on the Plan quantities page (test_browser_sprint12.py pattern)."""
    return page.inner_text(f"#qty-trade-{trade} [data-q={question}] td.num")


def open_quantities(page, estimate_id):
    page.goto(page.base + f"#/quantities/{estimate_id}")
    page.wait_for_selector("#qty-summary")
    dismiss_tour(page)


# ------------------------------------------------------------------ M7: HVAC counts after approval

def test_E2E_S14_M7_hvac_counts_after_approval(page, hvac):
    eid, ps = hvac["estimate_id"], hvac["plan_set_id"]
    # Before approval the HVAC card has the rooms' area but no symbol counts.
    open_quantities(page, eid)
    assert cell(page, "hvac", "conditioned_sqft") == "234"
    assert page.locator("#qty-trade-hvac [data-q=registers]").count() == 0
    # Approve all seven symbols in Reviews.
    page.goto(page.base + f"#/reviews/{ps}")
    page.wait_for_selector("#symrev-grid")
    dismiss_tour(page)
    page.wait_for_function("() => document.querySelectorAll('#symrev-grid .sym-card').length === 7")
    page.click("#symrev-all")
    page.click("#symrev-approve")
    answer_yes(page, "symrev")
    page.wait_for_function("() => document.body.innerText.includes('7 symbols approved')")
    page.wait_for_function("() => document.querySelectorAll('#symrev-grid .sym-card.approved').length === 7")
    # Now the HVAC card counts them, and the mini-split heads set the system.
    open_quantities(page, eid)
    assert cell(page, "hvac", "conditioned_sqft") == "234"
    assert cell(page, "hvac", "registers") == "3"
    assert cell(page, "hvac", "returns") == "1"
    assert cell(page, "hvac", "thermostats") == "1"
    assert cell(page, "hvac", "zones") == "2"
    assert cell(page, "hvac", "system") == "mini_split"


# ------------------------------------------------------------------ M8: garage excluded from HVAC

def test_E2E_S14_M8_garage_excluded_from_hvac(page, garage):
    eid = garage["estimate_id"]
    open_quantities(page, eid)
    assert cell(page, "hvac", "conditioned_sqft") == "120"
    assert "114 sq ft of garages" in page.inner_text("#qty-trade-hvac")
    rooms = page.inner_text("#qty-rooms")
    assert "LIVING" in rooms and "GARAGE" in rooms
    assert "2 room(s), 234 sq ft" in page.inner_text("#qty-summary")
