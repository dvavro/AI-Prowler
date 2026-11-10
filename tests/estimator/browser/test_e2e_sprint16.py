"""Coder 2 Sprint 16 E2E GUI tests (Playwright, human mode): scanned plans, scale calibration, blueprints, DWG warning.

    run_tests_estimator.bat browser -k E2E_S16 [--human]

M2: a scanned plan read by the engine assumes 150 DPI and overstates the size;
    calibrating on a known dimension fixes it, and the objects are re-measured.
M4: a white-on-blue scan is read inverted; the sheet image is dark-on-light.
M6: with no DWG converter installed, uploading a DWG warns on upload and fails
    with guidance on read (ESTIMATOR_DWG_CONVERTER=off).
M8: a scanned plan read twice keeps its scan notes and quantities; no duplication.
M1/M3/M5/M7 stay manual (real-scan accuracy / physical photo / live AI /
environment mutation). See tests/estimator/E2E_GUI_TEST_PLAN.md.

The scan fixture is Smith Residence A-101 as a 200 dpi raster
(tests/estimator/browser/fixtures/smith_residence_A101_scan.png), which has no
DPI metadata, so the engine assumes 150 DPI and the sheet is 48 x 32 in. Before
calibration the model total is about 1,214 sq ft (2 rooms); the 40 ft dimension
line on the sheet is at PNG pixels x 800-2800, y 2500 (7200 x 4800 px), which
calibrates 1 inch = 36 inches and re-measures the rooms to about 683 sq ft.
"""
import re
from pathlib import Path

import pytest

from browser_helpers import type_in
from e2e_helpers import CTX, dismiss_tour
from estimator.estimating import service
from estimator.ui.model import tool_status

SCAN = Path(__file__).parent / "fixtures" / "smith_residence_A101_scan.png"


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


def _sqft(summary):
    m = re.search(r"([\d,]+(?:\.\d+)?) sq ft", summary)
    assert m, summary
    return float(m.group(1).replace(",", ""))


def assert_scan_quantities(page, eid):
    """A scanned plan's quantities: the scan note, 2 rooms, 16 walls."""
    page.goto(page.base + f"#/quantities/{eid}")
    page.wait_for_selector("#qty-summary")
    dismiss_tour(page)
    assert page.locator("#qty-needs-review").count() == 1
    assert "read from scanned or photographed plans" in page.inner_text("main")
    summary = page.inner_text("#qty-summary")
    assert "2 room(s)" in summary
    return summary


def assert_scan_sheet(page, ps):
    """The sheet page for the scanned plan: 16 walls, 2 rooms."""
    page.goto(page.base + f"#/plan-sets/{ps}")
    page.wait_for_selector("#plan-say")
    dismiss_tour(page)
    page.locator("#sheets tbody tr").first.click()
    page.wait_for_selector("#sheet-image")
    page.wait_for_selector("#sheet-found")
    found = page.inner_text("#sheet-found")
    assert "16 walls" in found and "2 rooms" in found


# ------------------------------------------------------------------ M2: scan calibration

def test_E2E_S16_M2_scan_calibration(page, db, tmp_path):
    est = service.create_estimate(db, CTX, "Scan job")
    db.commit()
    ps = upload_plan(page, est["id"], str(SCAN))
    read_plan_set(page, ps)
    # Before calibration the assumed 150 DPI overstates the rooms (~1,214 sq ft).
    assert 1150 <= _sqft(assert_scan_quantities(page, est["id"])) <= 1300
    # The sheet's viewport shows the assumed scale: 1/4" = 1'-0", 1" = 48".
    assert_scan_sheet(page, ps)
    viewports = page.inner_text("#viewports")
    assert "48" in viewports
    page.click("[data-calibrate]")
    # The 40'-0" dimension line is at PNG pixels x 800-2800, y 2500 (7200 x 4800 px).
    box = page.locator("#sheet-image").bounding_box()
    assert box is not None
    page.mouse.click(box["x"] + box["width"] * 800 / 7200, box["y"] + box["height"] * 2500 / 4800)
    page.mouse.click(box["x"] + box["width"] * 2800 / 7200, box["y"] + box["height"] * 2500 / 4800)
    page.wait_for_selector("#cal-box")
    type_in(page, "#cal-distance", "40'-0\"")
    page.click("#cal-set")
    page.wait_for_selector("#cal-confirm-box")
    page.click("#cal-confirm-box button.primary")
    page.wait_for_function("() => document.body.innerText.match(/Calibrated: 1\u2033 = 3[56]/) && "
                           "document.body.innerText.includes('18 object(s) re-measured')")
    page.wait_for_function("() => document.querySelector('#viewports').innerText.includes('calibration')")
    # After calibration the rooms measure to about 683 sq ft, and still two rooms.
    total = _sqft(assert_scan_quantities(page, est["id"]))
    assert 670 <= total <= 695
    rooms = page.inner_text("#qty-rooms")
    assert "LIVING" in rooms and "KITCHEN" in rooms


# ------------------------------------------------------------------ M4: blueprint inversion

def test_E2E_S16_M4_blueprint_inversion(page, db, tmp_path):
    Image = pytest.importorskip("PIL.Image")
    ImageOps = pytest.importorskip("PIL.ImageOps")
    inverted = tmp_path / "blueprint.png"
    ImageOps.invert(Image.open(SCAN).convert("RGB")).save(inverted, dpi=(200, 200))
    est = service.create_estimate(db, CTX, "Blueprint job")
    db.commit()
    ps = upload_plan(page, est["id"], str(inverted))
    read_plan_set(page, ps)
    # The scan was read inverted: 8 walls and 2 rooms were found.
    page.goto(page.base + f"#/plan-sets/{ps}")
    page.wait_for_selector("#plan-say")
    dismiss_tour(page)
    page.locator("#sheets tbody tr").first.click()
    page.wait_for_selector("#sheet-image")
    page.wait_for_function("() => { const i = document.querySelector('#sheet-image'); return i.naturalWidth > 0; }")
    page.wait_for_selector("#sheet-found")
    found = page.inner_text("#sheet-found")
    assert "8 walls" in found and "2 rooms" in found
    # The sheet image shown is dark-on-light, not white-on-blue.
    mean = page.evaluate("""() => {
        const img = document.querySelector('#sheet-image');
        const c = document.createElement('canvas');
        c.width = 720; c.height = 480;
        const ctx = c.getContext('2d');
        ctx.drawImage(img, 0, 0, 720, 480);
        const d = ctx.getImageData(0, 0, 720, 480).data;
        let sum = 0;
        for (let i = 0; i < d.length; i += 4) sum += d[i];
        return sum / (d.length / 4);
    }""")
    assert mean > 200, mean
    # The quantities carry the scan warning, as on any scanned plan.
    assert_scan_quantities(page, est["id"])


# ------------------------------------------------------------------ M6: DWG without a converter warns

def test_E2E_S16_M6_dwg_without_converter_warns(page, db, tmp_path, monkeypatch):
    monkeypatch.setenv("ESTIMATOR_DWG_CONVERTER", "off")
    dwg = next(r for r in tool_status() if r["tool"].startswith("DWG converter"))
    assert dwg["ok"] is False and dwg["detail"].startswith("Not installed")
    dwg_file = tmp_path / "house.dwg"
    dwg_file.write_bytes(b"AC1032" + b"\x00" * 64)
    est = service.create_estimate(db, CTX, "DWG job")
    db.commit()
    page.goto(page.base + f"#/projects/{est['id']}")
    page.wait_for_selector("#plan-file")
    dismiss_tour(page)
    page.set_input_files("#plan-file", str(dwg_file))
    page.click("#plan-upload")
    page.wait_for_selector("#plan-confirm")
    message = page.inner_text("#plan-message")
    assert "DWG needs a DWG-to-DXF converter" in message and "ODA File Converter" in message
    page.click("#plan-attach")
    page.wait_for_selector("#plans tbody tr")
    ps = int(page.locator("#plans tbody tr").first.locator("td").first.inner_text())
    page.goto(page.base + f"#/plan-sets/{ps}")
    page.wait_for_selector("#plan-read")
    dismiss_tour(page)
    page.click("#plan-read")
    page.wait_for_selector("#plan-confirm", timeout=5000)
    page.click("#plan-confirm")
    # Reading fails with the guidance, shown on the plan-set page.
    page.wait_for_function("() => { const m = document.querySelector('#plan-message'); return m && "
                           "m.innerText.includes('ODA File Converter') && "
                           "m.innerText.includes('save the drawing as DXF'); }", timeout=120000)
    # A real reload shows the failed read stuck: "Reading failed" with the
    # guidance, and no sheets. (mark_failed persists - the estimator DB
    # connection is autocommit - so a failed read is visible on reload, not
    # just once in #plan-message. Note: goto to the same hash is a no-op -
    # the hash is already #/plan-sets/{ps} - so this must be page.reload().)
    page.reload()
    page.wait_for_selector("#plan-say")
    say = page.inner_text("#plan-say")
    assert "Reading failed" in say and "ODA File Converter" in say
    assert page.locator("#sheets").count() == 0


# ------------------------------------------------------------------ M8: re-read keeps scan notes

def test_E2E_S16_M8_reread_scan_notes(page, db, tmp_path):
    est = service.create_estimate(db, CTX, "Scan job")
    db.commit()
    ps = upload_plan(page, est["id"], str(SCAN))
    read_plan_set(page, ps)
    first = assert_scan_quantities(page, est["id"])
    assert_scan_sheet(page, ps)
    read_plan_set(page, ps)
    second = assert_scan_quantities(page, est["id"])
    assert second == first
    assert_scan_sheet(page, ps)
