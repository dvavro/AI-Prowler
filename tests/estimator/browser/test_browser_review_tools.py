"""Blueprint Review tools: Pan keeps an unfinished line, and Rotate turns the sheet.

    run_tests_estimator.bat browser -k review_tools [--human]

RV-B01: drawing a length, switching to Pan, and switching back must not lose
the line - setTool used to clear RV.draft on every tool switch, so a line
drawn but not yet finished vanished the moment Jamie panned to look around.
RV-B02: the Rotate button turns the sheet 90 degrees clockwise, keeps whatever
is in the middle of the screen in the middle, and clicks still land on the
same part of the plan (toSheet undoes the rotation).
"""
import pytest

from e2e_helpers import dismiss_tour
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


def open_takeoffs(page, house):
    page.goto(page.base + f"#/takeoffs/{house}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.wait_for_function("() => typeof RV !== 'undefined' && RV.viewer")


def viewer_box(page):
    return page.evaluate("() => { const r = RV.viewer.box.getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; }")


def test_pan_keeps_unfinished_length(page, house):                                  # RV-B01
    open_takeoffs(page, house)
    page.click("#bp-tools [data-tool=length]")
    x, y, w, h = viewer_box(page)
    page.mouse.click(x + w * 0.4, y + h * 0.4)
    page.wait_for_timeout(700)          # two quick clicks would double-click and finish the line
    page.mouse.click(x + w * 0.4 + 120, y + h * 0.4 + 40)
    page.wait_for_selector("#bp-draft")
    page.click("#bp-tools [data-tool=pan]")
    # The unfinished line is still there, and the readout still offers Finish.
    assert page.locator("#bp-draft").count() == 1
    assert page.locator("#bp-readout").count() == 1
    assert "is kept" in page.inner_text("#bp-tool-help")
    # Back on Length, finish it and save it as a length.
    page.click("#bp-tools [data-tool=length]")
    page.click("#bp-finish")
    page.wait_for_selector("#bp-save-box")
    page.click("#bp-save")
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    try:
        page.wait_for_selector("#bp-save-yes", timeout=5000)
        page.click("#bp-save-yes")
    except PlaywrightTimeoutError:
        pass
    page.wait_for_function("() => document.querySelector('#bp-measurements').children.length > 0")


def test_rotate_keeps_the_middle_still(page, house):                                # RV-B02
    open_takeoffs(page, house)

    def centre():
        return page.evaluate("() => { const v = RV.viewer; const r = v.box.getBoundingClientRect();"
                             " return v.toSheet(r.left + r.width / 2, r.top + r.height / 2); }")
    before = centre()
    page.click("#bp-rotate")
    page.wait_for_function("() => RV.viewer.rot === 90")
    assert "rotate(90deg)" in page.evaluate("() => RV.viewer.stage.style.transform")
    after = centre()
    assert abs(before[0] - after[0]) < 0.5 and abs(before[1] - after[1]) < 0.5
    page.click("#bp-rotate")
    page.click("#bp-rotate")
    page.click("#bp-rotate")
    page.wait_for_function("() => RV.viewer.rot === 0")
