"""E2E (Playwright, human mode): Blueprint Review follows the sheet switches, and AI Auto Run lists its results
(2026-11-15, David).

David switched three sheets off for Concrete and kept the foundation sheet on, then opened Blueprint Review: it
showed every sheet as if on, said "No trade on this project needs a measurement yet" (Concrete was picked for the
project but not priced), and the auto-run button couldn't run. Now:
  * the sheet list marks the switched-off sheets and opens on one that is on;
  * a trade picked for the project shows in "What to measure" before it is priced;
  * 🤖 AI Auto Run lists what it measured and the concrete volume it adds up to.
The run itself is not started here (no real AI): POST /auto-run is answered with a finished run made in the test,
and the page reads that run from the real server.
"""
import json

import pytest

from e2e_helpers import CTX, dismiss_tour
from estimator.api import autorun_api
from estimator.director import engine as director
from estimator.drawing_model import engine, store
from estimator.estimating import service
from estimator.takeoff import footer_section, sheet_trades
from pdfmaker import make_pdf
from test_plan_engine_sprint10 import legend, plan, shape

NOW = "2026-11-15T12:00:00+00:00"


@pytest.fixture
def shed(db, tmp_path):
    """A two-page plan set: page 1 switched off for Concrete, page 2 on; Concrete picked, not priced."""
    lt, ll = legend([("recept", None, "DUPLEX RECEPTACLE")])
    pages = [plan(lt, ll + shape("recept", 5, 5)), plan(lt, ll + shape("recept", 9, 9))]
    est = service.create_estimate(db, CTX, "NSB Shed slab")
    ps = store.upload(db, CTX, est["id"], str(make_pdf(tmp_path / "shed.pdf", pages)), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    director.set_project_trades(db, CTX, est["id"], ["concrete"])
    sheets = store.sheets(db, CTX, ps)["sheets"]
    off, on = sheets[0]["id"], sheets[1]["id"]
    sheet_trades.set_active(db, CTX, off, "concrete", False)
    db.commit()
    return {"est": est["id"], "off": off, "on": on}


def _finished_run(db, seed):
    """A finished AI run on the sheet that is on: slab and footer, the footer size read off the plan."""
    vp = db.execute("SELECT id FROM viewports WHERE sheet_id = ? ORDER BY id LIMIT 1", (seed["on"],)).fetchone()[0]
    run = autorun_api.create_run(db, CTX, seed["est"], seed["on"], vp, "concrete",
                                 [{"id": "llm", "source": "llm", "label": "45'-7\" x 46'-7\" (read by the AI)"}])
    # The footer detail as on David's sheet: 3-1/2" + 6-1/2" + 12" outside face, 4" slab, 12" wide (2026-11-15) -
    # 18" below the slab; the AI's check agreed with the reading.
    read = {"detail_found": True, "outside_face": ['3-1/2"', '6-1/2"', '12"'], "slab_thickness": '4"',
            "footer_width": '12"'}
    check = {"overall": "agrees", "checks": [{"item": "outside_face", "agrees": True},
                                             {"item": "slab_thickness", "agrees": True},
                                             {"item": "footer_width", "agrees": True}]}
    calc = json.dumps({"source": "llm", "auto_run_id": run, "candidate_id": "llm", "footer_size": "12x20",
                       "perimeter_lf": "184.33", "footer_section": footer_section.from_read(read, "12x20"),
                       "footer_read": read, "footer_check": check, "slab_width": "45'-7\"",
                       "slab_length": "46'-7\"", "area_read": "2123.42"})
    ids = []
    for feeds, kind, label, qty, unit in (("area_sqft", "area", "Slab (AI)", "2123.42", "sqft"),
                                          ("footing_lf", "length", "Footer (AI)", "180.33", "lf"),
                                          ("footing_section_sqft", "area", "Footer cross-section (AI)", "1.5000",
                                           "sqft/lf")):
        ids.append(db.execute(
            "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label,"
            " qty, unit, source_object_ids, calc_json, method, status, locked, proposed_by, created_at, updated_at)"
            " VALUES ('default', ?, 'concrete', ?, ?, ?, ?, ?, ?, ?, '[]', ?, 'ai', 'proposed', 0, 'llm-takeoff', ?, ?)",
            (seed["est"], feeds, seed["on"], vp, kind, label, qty, unit, calc, NOW, NOW)).lastrowid)
    autorun_api.update_run(db, run, step="reading the plan with the AI", measurement_ids=ids)
    db.commit()
    return run


def test_E2E_review_opens_on_a_sheet_that_is_on_and_marks_the_off_ones(page, shed):
    page.goto(page.base + f"#/takeoffs/{shed['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    assert page.eval_on_selector("#review-sheet", "s => +s.value") == shed["on"]
    off_label = page.inner_text(f"#review-sheet option[value='{shed['off']}']")
    on_label = page.inner_text(f"#review-sheet option[value='{shed['on']}']")
    assert "switched off" in off_label and off_label.startswith("⛔")
    assert on_label.startswith("✅") and "switched off" not in on_label
    # Concrete was picked for the project (not priced yet): the guide asks for its measurements.
    guide = page.inner_text("#bp-guide")
    assert "No trade on this project needs a measurement yet" not in guide and "Concrete" in guide
    # The button is AI Auto Run, and it can run.
    btn = page.locator("#bp-auto-run")
    assert "AI Auto Run" in btn.inner_text() and btn.is_enabled()
    # Open the switched-off sheet: it says AI Auto Run skips it, and the button still runs (the sheets that are on).
    page.select_option("#review-sheet", str(shed["off"]))
    page.wait_for_selector("#bp-auto-off")
    assert "skips it" in page.inner_text("#bp-auto-off")
    assert page.locator("#bp-auto-run").is_enabled()


def test_E2E_ai_auto_run_lists_its_measurements_and_the_concrete_volume(page, db, shed):
    sent, made = [], []

    def fake_start(route):
        if route.request.method != "POST":
            route.continue_()
            return
        sent.append(json.loads(route.request.post_data or "{}"))
        made.append(_finished_run(db, shed))           # the run "starts" when the button is clicked
        route.fulfill(status=200, content_type="application/json", body=json.dumps({"ok": True, "run_id": made[0],
                                                                                     "status": "running"}))
    page.route("**/estimator-api/auto-run", fake_start)
    page.goto(page.base + f"#/takeoffs/{shed['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.select_option("#review-sheet", str(shed["off"]))          # start it from a switched-off sheet
    page.wait_for_selector("#bp-auto-off")
    page.click("#bp-auto-run")
    # While it works: a "please wait" banner with a spinner and the steps, and the button can't be clicked again.
    page.wait_for_selector(".bp-running #bp-auto-steps")
    assert "please wait" in page.inner_text("#bp-auto-status")
    btn = page.locator("#bp-auto-run")
    assert btn.is_disabled() and "working" in btn.inner_text()
    page.wait_for_function("() => document.querySelector('#bp-auto-steps li.now') && "
                           "document.querySelector('#bp-auto-steps li.now').innerText.includes('AI to read')")
    # The open sheet was off, so no sheet was sent: the server picks the one that is on, and the page moves there.
    assert sent and sent[0].get("sheet_id") is None and sent[0]["module_id"] == "concrete"
    assert page.eval_on_selector("#review-sheet", "s => +s.value") == shed["on"]
    autorun_api.update_run(db, made[0], status="done", step="done")
    db.commit()
    page.wait_for_selector("#bp-auto-results", timeout=20000)
    assert page.locator(".bp-running").count() == 0 and btn.is_enabled() and "working" not in btn.inner_text()
    box = page.inner_text("#bp-auto-results")
    assert "AI Auto Run measurements" in box
    assert "Slab (AI)" in box and "Footer (AI)" in box
    vol = page.inner_text("#bp-auto-volume")
    assert "Concrete volume: 36.24 cu yd" in vol
    # Every step's formula, to check by hand - the footer is only the part below the slab (2026-11-15).
    row = lambda s: page.inner_text(f"#bp-auto-formulas tr[data-step='{s}']")
    assert "22 in - 4 in slab" in row("Footer depth below the slab") and "18 in" in row("Footer depth below the slab")
    assert "12 in x 18 in" in row("Footer cross-section") and "216 sq in" in row("Footer cross-section")
    assert "184.33 lf - 4 x 12 in ÷ 12" in row("Footer length (middle line)") and "180.33 lf" in row("Footer length (middle line)")
    footer = row("Footer concrete")
    assert "180.33 lf x 216 sq in ÷ 144 ÷ 27" in footer and "10.02 cu yd" in footer
    assert "2,123.42 sq ft x 4 in ÷ 12 ÷ 27" in row("Slab concrete")
    assert "26.22 + 10.02" in row("Total concrete")
    assert "38.05 cu yd" in row("Order with waste")
    # The AI checked its footer reading against the plan, and every value agreed.
    assert "every value agrees (3 checked)" in page.inner_text("#bp-footer-check")
    assert "AI Auto Run finished: 3 proposed measurement(s)" in page.inner_text("#bp-auto-status")
    # Correct the section by hand: add the 4 x 2 in ledge notch. It asks first, then works the footer out again.
    page.click("#bp-footer-edit summary")
    assert page.input_value("#bp-footer-outside_in") == "22"
    page.fill("#bp-footer-ledge_w_in", "4")
    page.fill("#bp-footer-ledge_d_in", "2")
    page.click("#bp-footer-save")
    page.wait_for_selector("#bp-footer-question")
    assert "208 sq in" in page.inner_text("#bp-footer-question") and "9.65 cu yd" in page.inner_text("#bp-footer-question")
    page.click("#bp-footer-yes")
    page.wait_for_function("() => document.querySelector('#bp-auto-volume') && "
                           "document.querySelector('#bp-auto-volume').innerText.includes('35.87')", timeout=20000)
    assert "(4 in x 2 in ledge)" in row("Footer cross-section") and "208 sq in" in row("Footer cross-section")
    calc = json.loads(db.execute("SELECT calc_json FROM measurements WHERE feeds = 'footing_section_sqft'").fetchone()[0])
    assert calc["footer_section"]["ledge_w_in"] == 4 and calc["footer_section"]["from"]["ledge_w_in"] == "entered by a person"
    # Reloading the page keeps the results (the latest run on the sheet is loaded again).
    page.reload()
    page.wait_for_selector("#bp-auto-formulas tr[data-step='Footer concrete']", timeout=20000)
    assert "35.87 cu yd" in page.inner_text("#bp-auto-volume")       # the corrected footer stays


# ------------------------------------------------------------------ 2026-11-16: formulas on the drawing, drawn areas

def _drawn_plan(db, seed):
    """The sheet that is on gets David's plan: only the slab's bottom and right edges drawn, at a calibrated scale, and
    a footer detail beside it with its own scale (12 real in per paper in)."""
    W, H = (float(v) for v in db.execute("SELECT width, height FROM sheets WHERE id = ?", (seed["on"],)).fetchone())
    vp = db.execute("SELECT id FROM viewports WHERE sheet_id = ? ORDER BY id LIMIT 1", (seed["on"],)).fetchone()[0]
    ratio = 559 / (0.6 * H)
    x0, y0, w, h = 0.05 * W, 0.1 * H, 547 / ratio, 559 / ratio
    db.execute("UPDATE viewports SET scale_ratio = ?, is_nts = 0, bbox_json = ? WHERE id = ?",
               (str(ratio), json.dumps([0, 0, 0.62 * W, H]), vp))
    for a, b in (([x0, y0 + h], [x0 + w, y0 + h]), ([x0 + w, y0], [x0 + w, y0 + h])):
        db.execute("INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json, source)"
                   " VALUES ('default', ?, ?, 'wall', ?, 'vector')", (seed["on"], vp, json.dumps({"type": "line", "points": [a, b]})))
    box = [0.65 * W, 0.1 * H, 0.95 * W, 0.6 * H]
    detail = db.execute("INSERT INTO viewports (company_id, sheet_id, label, bbox_json, scale_ratio, is_nts)"
                        " VALUES ('default', ?, '12\"X20\" MONO. FOOTER', ?, '12', 0)", (seed["on"], json.dumps(box))).lastrowid
    db.commit()
    return {"corner": [round(x0 + w, 4), round(y0 + h, 4)], "detail": detail, "box": box}


def _screen(page, x, y):
    """Where a point of the sheet is on the screen (the viewer isn't rotated). The drawing is scrolled into the window
    first, as a person would before clicking on it."""
    page.eval_on_selector("#bp-viewer", "v => { const r = v.getBoundingClientRect();"
                          " if (r.top < 0 || r.bottom > window.innerHeight) v.scrollIntoView({block: 'start'}); }")
    return page.evaluate("([x, y]) => { const v = RV.viewer, r = v.box.getBoundingClientRect();"
                         " return [r.left + v.tx + x * v.z, r.top + v.ty + y * v.z]; }", [x, y])


def test_E2E_click_a_formula_to_see_it_and_draw_an_area_to_add(page, db, shed):
    plan = _drawn_plan(db, shed)
    run = _finished_run(db, shed)
    autorun_api.update_run(db, run, status="done", step="done")
    db.commit()
    page.goto(page.base + f"#/takeoffs/{shed['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.wait_for_selector("#bp-auto-formulas tr.bp-step-link[data-step='Slab area']", timeout=20000)
    assert "placed on the plan's own lines" in page.inner_text("#bp-slab-fit")
    # Click "Slab area": the drawing outlines the slab in red, its corner on the plan's drawn edges.
    page.click("#bp-auto-formulas tr[data-step='Slab area']")
    page.wait_for_selector("#bp-hl polygon.bp-hl")
    assert "on" in page.get_attribute("#bp-auto-formulas tr[data-step='Slab area']", "class")
    corners = page.get_attribute("#bp-hl polygon.bp-hl", "points").split()
    assert f"{plan['corner'][0]},{plan['corner'][1]}" in corners
    # "Footer concrete": the footer band inside the slab (outer ring and inner ring); click again to clear it.
    page.click("#bp-auto-formulas tr[data-step='Footer concrete']")
    page.wait_for_function("() => { const p = document.querySelector('#bp-hl polygon.bp-hl');"
                           " return p && p.getAttribute('points').split(' ').length === 10; }")
    page.click("#bp-auto-formulas tr[data-step='Footer concrete']")
    page.wait_for_selector("#bp-hl", state="detached")
    # "Footer cross-section": the footer detail's frame.
    page.click("#bp-auto-formulas tr[data-step='Footer cross-section']")
    page.wait_for_selector("#bp-hl polyline.bp-hl")
    # Add the sloped edge: click its three corners on the detail (Alt: exactly where clicked, no snapping), Finish.
    page.click("#bp-adjust-footer-add")
    assert "footer detail" in page.inner_text("#bp-tool-help")
    bx, by = plan["box"][0] + 0.5, plan["box"][1] + 0.5
    page.keyboard.down("Alt")
    for x, y in ((bx, by), (bx + 1, by), (bx, by + 1)):              # half a square paper inch = 72 sq in at 12:1
        page.mouse.click(*_screen(page, x, y))
    page.keyboard.up("Alt")
    readout = page.inner_text("#bp-readout-text")
    assert "sq in" in readout
    assert 66 <= float(readout.split("≈")[1].split("sq in")[0].replace(",", "")) <= 78
    page.click("#bp-finish")
    page.fill("#bp-adjust-label", "sloped edge")
    page.click("#bp-adjust-save")
    page.wait_for_selector("#bp-adjust-question")
    assert "(sloped edge) to the footer cross-section" in page.inner_text("#bp-adjust-question")
    page.click("#bp-adjust-yes")
    page.wait_for_selector("#bp-adjust-list tr[data-area='a1']", timeout=20000)
    assert "sloped edge" in page.inner_text("#bp-adjust-list")
    assert "sq in (sloped edge)" in page.inner_text("#bp-auto-formulas tr[data-step='Footer cross-section']")
    assert "36.24" not in page.inner_text("#bp-auto-volume")           # the footer grew, so the total did too
    calc = json.loads(db.execute("SELECT calc_json FROM measurements WHERE feeds = 'footing_section_sqft'").fetchone()[0])
    added = calc["footer_section"]["adjust"][0]
    assert added["label"] == "sloped edge" and 66 <= float(added["sqin"]) <= 78
    # The drawn area shows on the drawing too (green: added), from its row.
    page.click("#bp-adjust-list button[data-show='a1']")
    page.wait_for_selector("#bp-hl polygon.bp-hl.plus")


def test_E2E_calibrate_the_detail_then_see_the_sections_parts_on_it(page, db, shed):
    """David calibrated nothing (the automatic calibrator gave up on his NTS detail); the page walks him through it,
    then one click on the footer's bottom outside corner draws the parts the cross-section is worked out from."""
    plan = _drawn_plan(db, shed)
    db.execute("UPDATE viewports SET scale_ratio = NULL, is_nts = 1, calibration_json = ? WHERE id = ?",
               (json.dumps({"status": "manual_required", "reason": "the written dimensions don't agree on one scale"}),
                plan["detail"]))
    run = _finished_run(db, shed)
    autorun_api.update_run(db, run, status="done", step="done")
    db.commit()
    page.goto(page.base + f"#/takeoffs/{shed['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.wait_for_selector("#bp-detail-noscale", timeout=20000)
    assert "don't agree on one scale" in page.inner_text("#bp-detail-noscale")
    # 📏 Calibrate the footer detail: click both ends of a 12" dimension (1 paper inch here), type 12".
    page.click("#bp-detail-calibrate")
    assert "12\" dimension" in page.inner_text("#bp-tool-help")
    x0, y0 = plan["box"][0] + 0.5, plan["box"][3] - 0.5
    page.keyboard.down("Alt")
    page.mouse.click(*_screen(page, x0, y0))
    page.mouse.click(*_screen(page, x0 + 1, y0))
    page.keyboard.up("Alt")
    page.fill("#bp-cal-distance", "12\"")
    page.click("#bp-cal-set")
    page.wait_for_selector("#bp-cal-yes")
    page.click("#bp-cal-yes")
    # The results come back with the detail scaled: the section can now be placed.
    page.wait_for_selector("#bp-section-place-btn", timeout=20000)
    scale = float(db.execute("SELECT scale_ratio FROM viewports WHERE id = ?", (plan["detail"],)).fetchone()[0])
    assert 11 <= scale <= 13
    # 📍 One click on the footer's bottom outside corner: the parts are drawn on the detail, to its scale.
    key = page.inner_text("#bp-hl-key")                                   # what the colours mean (yellow = taken away)
    assert "already in the slab" in key and "taken away" in key
    assert "255, 212, 59" in page.eval_on_selector("#bp-hl-key .k-minus", "e => getComputedStyle(e, '::before').backgroundColor")
    page.click("#bp-section-place-btn")
    assert "bottom outside corner" in page.inner_text("#bp-tool-help")
    page.keyboard.down("Alt")
    page.mouse.click(*_screen(page, x0, y0))
    page.keyboard.up("Alt")
    page.wait_for_selector("#bp-hl polygon[data-part='below']", timeout=20000)
    labels = " ".join(page.eval_on_selector_all("#bp-hl text", "ts => ts.map(t => t.textContent)"))
    assert "12 x 18 = 216 sq in" in labels and "in the slab (4 in)" in labels
    assert page.locator("#bp-hl polygon[data-part='slab'].inslab").count() == 1
    assert "on" in page.get_attribute("#bp-auto-formulas tr[data-step='Footer cross-section']", "class")
    pts = page.get_attribute("#bp-hl polygon[data-part='below']", "points").split()
    bx, by = (float(v) for v in pts[0].split(","))
    assert abs(bx - x0) < 0.05 and abs(by - y0) < 0.05                    # it starts at the corner clicked
    rx = float(pts[1].split(",")[0])
    assert abs((rx - bx) * scale - 12) < 0.5                              # 12 in wide, to the detail's scale
    calc = json.loads(db.execute("SELECT calc_json FROM measurements WHERE feeds = 'footing_lf'").fetchone()[0])
    assert calc["footer_section"]["anchor"]["viewport_id"] == plan["detail"]
    # ⇄ flips which way the inside is.
    page.click("#bp-section-flip")
    page.wait_for_function("(bx) => { const p = document.querySelector(\"#bp-hl polygon[data-part='below']\");"
                           " return p && parseFloat(p.getAttribute('points').split(' ')[1]) < bx; }", arg=bx)
