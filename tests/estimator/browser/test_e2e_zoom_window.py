"""Zoom Window tool E2E GUI tests (Playwright, human mode).

    run_tests_estimator.bat browser -k zoom_window [--human]

The Blueprint Review (takeoffs) Zoom window tool: drag a box to zoom into it,
click to zoom in one step. Follows the takeoffs-screen pattern in
test_e2e_sprint11.py (same plan fixture, RV.viewer in page.evaluate).
"""
import pytest

from e2e_helpers import CTX, dismiss_tour
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape

CTX_ = CTX


@pytest.fixture
def job(db, tmp_path):
    """A plan with a legend (receptacle, special device); same seed as
    test_e2e_sprint11.py, so the takeoffs screen loads with a processed plan."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE"), ("flag", None, "SPECIAL DEVICE")])
    lines = (ll + shape("recept", 5, 5) + shape("recept", 7, 5) + shape("recept", 9, 5, 90)
             + shape("flag", 12, 8) + shape("flag", 14, 8, 30)
             + shape("tri", 5, 10) + shape("tri", 8, 10, 90) + shape("tri", 11, 10, 200))
    est = service.create_estimate(db, CTX, "Smith house")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "power.pdf", [plan(lt, lines)])), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return {"estimate_id": est["id"], "plan_set_id": ps, "sheet_id": store.sheets(db, CTX, ps)["sheets"][0]["id"]}


def open_takeoffs(page, job):
    page.goto(page.base + f"#/takeoffs/{job['estimate_id']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)


def viewer_box(page):
    return page.evaluate("() => { const r = RV.viewer.box.getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; }")


def test_zoom_window_drag_zooms_to_box(page, job):
    open_takeoffs(page, job)
    z0 = page.evaluate("() => RV.viewer.z")
    page.click("#bp-tools [data-tool=zoomwin]")
    x, y, w, h = viewer_box(page)
    x0, y0 = x + w * 0.3, y + h * 0.3
    x1, y1 = x + w * 0.7, y + h * 0.7
    page.mouse.move(x0, y0)
    page.mouse.down()
    page.mouse.move(x1, y1, steps=10)
    assert page.locator("#bp-zoombox").count() == 1
    page.mouse.up()
    z1 = page.evaluate("() => RV.viewer.z")
    assert z1 > z0 * 1.5
    assert page.locator("#bp-zoombox").count() == 0


def test_zoom_window_click_zooms_in_one_step(page, job):
    open_takeoffs(page, job)
    z0 = page.evaluate("() => RV.viewer.z")
    page.click("#bp-tools [data-tool=zoomwin]")
    x, y, w, h = viewer_box(page)
    page.mouse.click(x + w / 2, y + h / 2)
    z1 = page.evaluate("() => RV.viewer.z")
    assert abs(z1 / z0 - 1.5) < 0.01


def test_zoom_window_repeat_drag_no_text_select(page, db):
    """Two Zoom Window drags in a row must both zoom, and no label text may
    get selected. Uses the real designscad 25x25 DWG (not the Smith fixture:
    the Smith drag path selects no text, so it cannot catch this bug). A drag
    across the ENTRY label used to select its text; the next drag then started
    a native drag of the selected text (dragstart on svg.bp-overlay), the
    browser fired pointercancel, pointerup never ran, and the zoom never
    happened. user-select: none on .bp-viewer plus a dragstart preventDefault
    stop the native drag; the pointercancel handler now also cleans up
    (start / zoom box) instead of only dropping the pointer id.
    Skips when the ODA File Converter is not installed (DWG cannot be read).
    """
    from pathlib import Path as _Path
    import pytest as _pytest
    if not list(_Path("C:/Program Files/ODA").glob("ODAFileConverter*/ODAFileConverter.exe")):
        _pytest.skip("ODA File Converter not installed")
    dwg = _Path(__file__).parent / "fixtures" / "designscad_25x25_2bhk.dwg"
    est = service.create_estimate(db, CTX, "DWG repeat drag")
    ps = store.upload(db, CTX, est["id"], str(dwg), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    db.commit()
    page.goto(page.base + f"#/takeoffs/{est['id']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.evaluate("() => RV.viewer.zoomToBox([109620, 109408, 110026, 110667])")
    page.click("#bp-tools [data-tool=zoomwin]")
    x, y, w, h = viewer_box(page)
    z0 = page.evaluate("() => RV.viewer.z")
    page.mouse.move(x + w * 0.3, y + h * 0.3)
    page.mouse.down()
    page.mouse.move(x + w * 0.7, y + h * 0.7, steps=10)
    page.mouse.up()
    z1 = page.evaluate("() => RV.viewer.z")
    assert z1 > z0 * 1.5
    assert page.evaluate("() => window.getSelection().toString()") == ""
    # Second drag, same tool, must zoom again (this is the one that used to
    # be cancelled by the native drag of the label text).
    page.click("#bp-tools [data-tool=zoomwin]")
    page.mouse.move(x + w * 0.25, y + h * 0.25)
    page.mouse.down()
    page.mouse.move(x + w * 0.75, y + h * 0.75, steps=10)
    page.mouse.up()
    z2 = page.evaluate("() => RV.viewer.z")
    assert z2 > z1
    assert page.evaluate("() => window.getSelection().toString()") == ""
