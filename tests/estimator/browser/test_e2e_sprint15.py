"""Coder 2 Sprint 15 E2E GUI tests (Playwright, human mode): site & landscape reading, measurement, zones.

    run_tests_estimator.bat browser -k E2E_S15 [--human]

M7 (phone fixture): a yard-only project - the Site and landscape section, no
    "no rooms found" box, all quantities visible.
M8: read a yard plan, then read it again - the quantities are the same, not doubled.
M1-M6 stay manual (real-plan accuracy / live AI). See tests/estimator/E2E_GUI_TEST_PLAN.md.
"""
import pytest

from e2e_helpers import CTX, dismiss_tour
from estimator.estimating import service
from pdfmaker import make_pdf
from test_plan_engine_sprint15 import read, yard


def upload_plan(page, estimate_id, path):
    """Upload a plan on the project page; return the new plan set id."""
    page.goto(page.base + f"#/projects/{estimate_id}")
    page.wait_for_selector("#plan-file")
    dismiss_tour(page)
    page.set_input_files("#plan-file", path)
    page.click("#plan-upload")
    page.wait_for_selector("#plan-confirm")
    page.click("#plan-attach")
    page.wait_for_selector("#plans tbody tr")
    return int(page.locator("#plans tbody tr").first.locator("td").first.inner_text())


def read_plan_set(page, plan_set_id, timeout=120000):
    """Read the plan set on its page (handles the ask-first confirm)."""
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    page.goto(page.base + f"#/plan-sets/{plan_set_id}")
    page.wait_for_selector("#plan-read")
    dismiss_tour(page)
    page.click("#plan-read")
    try:
        page.wait_for_selector("#plan-confirm", timeout=5000)
        page.click("#plan-confirm")
    except PlaywrightTimeoutError:
        pass
    page.wait_for_function("() => document.querySelector('#plan-say') && "
                           "document.querySelector('#plan-say').innerText.startsWith('Read:')", timeout=timeout)


def cell(page, trade, question):
    """One trade answer's number on the Plan quantities page (test_browser_sprint12.py pattern)."""
    return page.inner_text(f"#qty-trade-{trade} [data-q={question}] td.num")


@pytest.fixture
def yard_est(db, tmp_path):
    """A yard plan already read by the real engine (test_plan_engine_sprint15.read)."""
    eid, ps = read(db, tmp_path, [yard()])
    db.commit()
    return {"estimate_id": eid, "plan_set_id": ps}


def assert_site_quantities(page, eid):
    """The site & landscape section for a yard-only project (Sprint 15 engine numbers)."""
    page.goto(page.base + f"#/quantities/{eid}")
    page.wait_for_selector("#qty-summary")
    dismiss_tour(page)
    assert page.locator("#qty-site-only").count() == 1
    assert "site and landscape plans" in page.inner_text("#qty-site-only")
    assert "Site and landscape" in page.inner_text("main")
    assert page.locator("#qty-empty").count() == 0
    zones = page.inner_text("#qty-zones")
    assert "Sod / lawn" in zones and "5,632" in zones
    assert "Rock / gravel" in zones and "512" in zones
    assert "Pavers" in zones and "256" in zones
    fences = page.inner_text("#qty-fences")
    assert "wood" in fences and "114 lf" in fences
    assert "Gates: 1 walk, 1 drive" in page.inner_text("#qty-gates")
    assert cell(page, "fencing", "length_lf") == "114"
    assert cell(page, "landscaping", "sod_sqft") == "5,632"


# ------------------------------------------------------------------ M7: phone; yard-only project sections

def test_E2E_S15_M7_phone_yard_project_sections(phone, yard_est):
    assert_site_quantities(phone, yard_est["estimate_id"])


# ------------------------------------------------------------------ M8: re-read adds nothing

def test_E2E_S15_M8_reread_adds_zones(page, db, tmp_path):
    est = service.create_estimate(db, CTX, "Yard job")
    db.commit()
    ps = upload_plan(page, est["id"], str(make_pdf(tmp_path / "yard.pdf", [yard()])))
    read_plan_set(page, ps)
    assert_site_quantities(page, est["id"])
    read_plan_set(page, ps)
    assert_site_quantities(page, est["id"])
