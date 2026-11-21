"""Measure screen, "To measure" tab, Electrical: the ⚡ Wiring run (2026-11-19, David) — run it with its settings, see the
cable totals and the routes on the plan, approve the cable, move a device to another circuit, download the DXF.

    browser_upload.bat tests\\estimator\\browser\\test_browser_wiring.py
"""
import sys
from pathlib import Path

import pytest

pytest.importorskip("ezdxf")
from estimator.context import personal_context  # noqa: E402
from estimator.drawing_model import engine, store  # noqa: E402
from estimator.estimating import service  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from test_wiring import _panel, _plan  # noqa: E402

CTX = personal_context()


@pytest.fixture
def job(db, tmp_path):
    est = service.create_estimate(db, CTX, "Wired house")
    service.add_trade(db, CTX, est["id"], "electrical", est.get("rev", 1))
    for f in (_plan(tmp_path), _panel(tmp_path)):                 # the floor plan first: the screen opens on it
        ps = store.upload(db, CTX, est["id"], f, confirm=True)["plan_set_id"]
        engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return est["id"]


def open_wiring(page, estimate_id):
    page.goto(page.base + f"#/takeoffs/{estimate_id}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    page.click("#bp-tab-guide")
    page.wait_for_selector("#bp-wiring-run")


def test_run_show_approve_move_download(page, job, tmp_path):
    open_wiring(page, job)
    # The cable rows aren't "click along it" Length rows: they point at the Wiring stage (2026-11-19, David).
    row = page.locator("#bp-pane-guide li[data-feeds=wire_12_2_ft]")
    assert "⚡ Wiring" in row.inner_text() and "click along" not in row.inner_text()
    row.click()                                                                            # goes to the card
    src = page.inner_text("#bp-wiring-sources")
    assert "plan.dxf" in src and "panel.dxf" in src
    # 2026-11-21 (David: "can we have the user decide/set wire running options before the run wiring"): the button
    # opens the wiring options first - a basement house by default, outlets through the studs.
    page.click("#bp-wiring-run")
    page.wait_for_selector("#bp-wiring-options", state="visible")
    assert page.input_value("#bp-wire-foundation") == "basement" and page.input_value("#bp-wire-outlets_via") == "walls"
    assert page.is_checked("#bp-wire-panel_in_basement")
    # Each drop-down says what the picked choice does to the routing (2026-11-21, David: "It needs to be clearer").
    assert "basement ceiling" in page.inner_text("#bp-wire-foundation-help")
    assert "drilled in the studs" in page.inner_text("#bp-wire-outlets_via-help")
    page.select_option("#bp-wire-outlets_via", "above")
    assert "The most cable" in page.inner_text("#bp-wire-outlets_via-help")
    page.select_option("#bp-wire-outlets_via", "walls")
    # A slab: the panel-in-the-basement option goes, and outlets can't be fed from below (nothing in the slab).
    page.select_option("#bp-wire-foundation", "slab")
    assert "No cable ever goes in the concrete" in page.inner_text("#bp-wire-foundation-help")
    assert page.locator("#bp-wire-panel_in_basement").count() == 0
    assert page.locator("#bp-wire-outlets_via option[value=below]").is_disabled()
    page.select_option("#bp-wire-foundation", "basement")
    page.fill("#bp-wire-ceiling_ft", "8.5")
    page.click("#bp-wiring-options-run")
    page.wait_for_selector("#bp-wiring-bom")
    assert page.locator("#bp-wiring-options").count() == 0
    cables = page.locator("#bp-wiring-bom td:first-child").all_inner_texts()
    assert set(cables) == {"10/3 NM-B", "12/2 NM-B", "12/3 NM-B", "14/2 NM-B"}         # the range: 10/3 (a neutral)
    assert "basement" in page.inner_text("#bp-wiring-routing") and "8.5 ft ceilings" in page.inner_text("#bp-wiring-routing")
    page.click("#bp-wiring-run")                                                           # the settings stay
    page.wait_for_selector("#bp-wiring-options", state="visible")
    assert page.input_value("#bp-wire-ceiling_ft") == "8.5"
    page.click("#bp-wiring-options-close")

    # The routes are on the plan, one group per circuit; picking a circuit fades the others.
    assert page.locator("#bp-wiring-routes .bp-wire-c").count() == 6
    page.click("#bp-wiring-circuits tr[data-circuit='C-1']")
    assert "picked" in page.get_attribute("#bp-wiring-routes", "class")
    assert page.locator("#bp-wiring-routes .bp-wire-c.on").get_attribute("data-circuit") == "C-1"
    page.uncheck("#bp-wiring-show")
    assert page.locator("#bp-wiring-routes").count() == 0
    page.check("#bp-wiring-show")

    # Approve the cable (the screen asks first).
    state = page.inner_text("#bp-wiring-state")
    assert "waiting for approval" in state and "6 wiring measurements" in state           # 4 cable sizes + 2 counts
    assert "breaker and range/dryer receptacle counts" in state
    assert "Approve the cable and counts" in page.inner_text("#bp-wiring-approve-btn")
    page.click("#bp-wiring-approve-btn")
    page.click("#bp-wiring-approve-yes")
    page.wait_for_selector("#bp-wiring-state:has-text('Cable approved')")

    # Move the C-1 outlet at (12, 0.5) to the kitchen circuit and run again: C-1 drops to 1 device.
    page.wait_for_selector("#bp-wiring-devices")                                          # C-1 is still picked
    page.select_option("#bp-wiring-devices select[data-device='OUTLET@12.0,0.5']", "C-2")
    # "Keep approved items" (beside AI Auto Run, on by default) unticked: this rerun starts the cable over.
    assert page.is_checked("#bp-auto-keep")
    page.uncheck("#bp-auto-keep")
    page.click("#bp-wiring-rerun")
    page.wait_for_selector("#bp-wiring-circuits tr[data-circuit='C-1'] td:nth-child(3):text-is('1')")
    # A rerun starts from scratch (2026-11-19, David): the approved cable went, the new cable waits for approval.
    page.wait_for_selector("#bp-wiring-approve-btn")
    assert page.locator("#bp-wiring-clear-moves").count() == 1

    with page.expect_download() as dl:
        page.click("#bp-wiring-dxf")
    out = tmp_path / "got.dxf"
    dl.value.save_as(out)
    assert dl.value.suggested_filename == f"estimate_{job}_wiring.dxf" and b"E-WIRE-SCHEDULE" in out.read_bytes()
    # 2026-11-20 (David): the wiring schematic - the panel and every circuit's conductors - its own download
    assert "conductors" in page.get_attribute("#bp-wiring-schematic", "title")
    with page.expect_download() as dl2:
        page.click("#bp-wiring-schematic")
    out2 = tmp_path / "schematic.dxf"
    dl2.value.save_as(out2)
    assert dl2.value.suggested_filename == f"estimate_{job}_schematic.dxf" and b"WIRING SCHEMATIC" in out2.read_bytes()


def test_audit_runs_the_wiring_again_without_ai_auto_run(page, db, job):
    """2026-11-20 (David: "how do I just run the wiring estimate? is it the same as AI Auto Run? the hover says nothing
    about wiring"): the AI Auto Run hover says it routes the wiring too, and the audit's "needs a run done again" item
    for old cable has its own ⚡ Run wiring now button - the new cable then waits, ticked, for one-click approval."""
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import wiring_run
    first = wiring_run.run(db, CTX, job)
    ms.confirm_measurements(db, CTX, first["measurement_ids"], confirm=True)
    db.execute("UPDATE measurements SET sheet_id = NULL, viewport_id = NULL WHERE estimate_id = ?", (job,))
    db.commit()                                                                          # as after a re-read
    page.goto(page.base + f"#/takeoffs/{job}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    assert "route the wiring" in (page.get_attribute("#bp-auto-run", "data-runs") or "")
    page.click("#bp-audit-open")
    page.wait_for_selector("#bp-audit-list")
    assert "Needs a run done again" in page.inner_text("#bp-audit")
    assert "don't need AI Auto Run" in page.inner_text("#bp-audit")
    page.locator(".bp-audit-run-wiring").first.click()
    page.wait_for_selector("#bp-audit .bp-audit-item.replace_old", timeout=30000)
    text = page.inner_text("#bp-audit")
    assert "a new length is waiting" in text and "Needs a run done again" not in text
    assert "a new count is waiting" in text and "The wiring run found" in text           # the circuit/receptacle counts
    assert page.inner_text("#bp-audit-apply").startswith("✓ Apply 6 fix")               # ticked: one click
    page.click("#bp-audit-apply")
    page.wait_for_selector("#bp-audit-done, #bp-audit-summary:has-text('Nothing to clean up')", timeout=20000)
    old = db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND status = 'approved'"
                     " AND sheet_id IS NULL", (job,)).fetchone()[0]
    new = db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND status = 'approved'"
                     " AND sheet_id IS NOT NULL", (job,)).fetchone()[0]
    assert old == 0 and new == 6                                                         # priced once, from the new plans


def test_run_wiring_from_the_toolbar(page, db, job):
    """2026-11-20 (David: "I don't see the run wiring"): ⚡ Run wiring sits beside AI Auto Run on the toolbar - just the
    wiring, no AI - and proposes the cable sizes."""
    page.goto(page.base + f"#/takeoffs/{job}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    btn = page.locator("#bp-run-wiring")
    btn.hover()                                                   # 2026-11-21: a hover card says what it needs
    page.wait_for_selector("#bp-run-wiring-help", state="visible")
    assert "no AI tokens" in page.inner_text("#bp-run-wiring-help")
    assert "No panel schedule?" in page.inner_text("#bp-run-wiring-help")
    btn.click()                                                   # 2026-11-21: the wiring options first
    page.wait_for_selector("#bp-wiring-options", state="visible")
    page.click("#bp-wiring-options-run")
    page.wait_for_function("() => { const b = document.querySelector('#bp-run-wiring');"
                           " return b && !b.disabled && !b.textContent.includes('Routing'); }", timeout=30000)
    n = db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND proposed_by = 'wiring-takeoff'"
                   " AND status = 'proposed'", (job,)).fetchone()[0]
    assert n == 6                                                   # 4 cable sizes + the branch-circuit and receptacle counts
    # 2026-11-21 (David: "after hitting run wiring and selecting each wiring estimate, I expected the wiring color code
    # to popup and highlight the wire routing ... nothing shows up in the cad window"): the routes and the colour key
    # are on the plan right after the run...
    page.wait_for_selector("#bp-wiring-routes .bp-wire-c", state="attached")
    assert page.locator("#bp-wiring-routes .bp-wire-c").count() == 6
    page.wait_for_selector("#bp-wiring-key", state="visible")
    # ...and clicking a cable measurement in the list lights up the circuits that cable is, the rest faded.
    mids = {r[0]: r[1] for r in db.execute("SELECT feeds, id FROM measurements WHERE estimate_id = ? AND proposed_by ="
                                           " 'wiring-takeoff' AND status = 'proposed'", (job,))}
    page.click("#bp-tab-list")
    page.click(f"#bp-rows li[data-mid='{mids['wire_10_3_ft']}']")
    page.wait_for_selector(".bp-wiring-key-head:has-text('10/3 cable')")           # the range's 10/2, priced as 10/3
    assert [e.get_attribute("data-circuit") for e in page.locator("#bp-wiring-routes .bp-wire-c.on").all()] == ["RANGE"]
    assert "picked" in page.get_attribute("#bp-wiring-routes", "class")
    page.click(f"#bp-rows li[data-mid='{mids['wire_12_2_ft']}']")
    page.wait_for_selector(".bp-wiring-key-head:has-text('12/2 cable')")
    on = {e.get_attribute("data-circuit") for e in page.locator("#bp-wiring-routes .bp-wire-c.on").all()}
    assert on == {"C-1", "C-2", "C-3", "C-4"}
    page.click(f"#bp-rows li[data-mid='{mids['wire_12_2_ft']}']", position={"x": 30, "y": 12})   # closed: all again
    page.wait_for_selector(".bp-wiring-key-head:has-text('Wiring — 6 circuits')")
    assert page.locator("#bp-wiring-routes .bp-wire-c").count() == 6


def test_rerun_with_other_options_offers_the_new_lengths(page, db, job):
    """2026-11-21 (David: "I reran the run wiring with different defaults and I don't see any changes to approve"):
    with everything approved and "Keep approved items" on, a rerun with other routing shows the changed lengths to
    accept - one click puts them on the estimate."""
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import wiring_run
    first = wiring_run.run(db, CTX, job, {"outlets_via": "above"})
    ms.confirm_measurements(db, CTX, first["measurement_ids"], confirm=True)
    db.commit()
    open_wiring(page, job)
    assert page.is_checked("#bp-auto-keep")
    page.click("#bp-wiring-run")
    page.wait_for_selector("#bp-wiring-options", state="visible")
    page.select_option("#bp-wire-outlets_via", "walls")
    page.select_option("#bp-wire-foundation", "crawlspace")
    page.click("#bp-wiring-options-run")
    page.wait_for_selector("#bp-wiring-accept-btn", timeout=30000)
    assert "accept the new values" in page.inner_text("#bp-wiring-state")
    page.click("#bp-wiring-accept-btn")
    page.click("#bp-wiring-accept-yes")
    page.wait_for_selector("#bp-wiring-state:has-text('Cable approved')", timeout=20000)
    left = db.execute("SELECT COUNT(*) FROM measurements WHERE estimate_id = ? AND suggested_qty IS NOT NULL",
                      (job,)).fetchone()[0]
    assert left == 0


def test_audit_show_on_drawing_for_cable_shows_the_routes(page, db, job):
    """2026-11-20 (David: "show on drawing for the wiring shows nothing, and a black popup happens behind the audit
    window"): cable has no symbols - the wiring routes show, the circuits of that size standing out - and the message
    shows beside the audit window, readable, not under it."""
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import wiring_run
    first = wiring_run.run(db, CTX, job)
    ms.confirm_measurements(db, CTX, first["measurement_ids"], confirm=True)
    db.execute("UPDATE measurements SET sheet_id = NULL, viewport_id = NULL WHERE estimate_id = ?", (job,))
    db.commit()
    wiring_run.run(db, CTX, job)                                  # the new cable waits: "a new length is waiting"
    page.goto(page.base + f"#/takeoffs/{job}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    page.click("#bp-audit-open")
    page.wait_for_selector("#bp-audit .bp-audit-item.replace_old")
    item = page.locator("#bp-audit .bp-audit-item.replace_old", has_text="Cable 12/2").first
    item.locator(".bp-audit-show").click()
    page.wait_for_selector("#bp-wiring-routes.picked .bp-wire-c.on", state="attached")
    on = page.locator("#bp-wiring-routes .bp-wire-c.on").count()
    assert 1 <= on < page.locator("#bp-wiring-routes .bp-wire-c").count()
    page.wait_for_selector("#toast:not([hidden])")
    assert "wired in 12/2" in page.inner_text("#toast")
    t, a = page.locator("#toast").bounding_box(), page.locator("#bp-audit").bounding_box()
    assert t["x"] + t["width"] <= a["x"] + 1                      # beside the audit window, not under it
    assert page.evaluate("() => { const t = document.getElementById('toast').getBoundingClientRect();"
                         " return document.elementFromPoint(t.x + 5, t.y + 5).closest('#toast') !== null; }")


def test_marks_for_what_the_drawing_has_no_symbol_for(page, db, job):
    """2026-11-20 (David: "3 of these items don't have symbols, can they be added to the drawing by you"): the wiring
    run marks the range receptacle at the range and the branch breakers at the panel; the audit says the wiring run
    found them (not "the AI counted"), and its Show on drawing lights up the mark and the circuits behind it."""
    from estimator.takeoff import wiring_run
    wiring_run.run(db, CTX, job)
    page.goto(page.base + f"#/takeoffs/{job}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    page.click("#bp-audit-open")
    item = page.locator("#bp-audit .bp-audit-item.waiting", has_text="Range receptacles")
    item.wait_for()
    text = item.inner_text()
    assert "wiring run found 1 ea" in text and "no symbol" in text and "The AI counted" not in text
    assert item.locator("input[type=checkbox]").is_checked()                              # ticked, like its cable
    item.locator(".bp-audit-show").click()
    mark = page.locator("#bp-wiring-routes .bp-wire-added[data-added=range_receptacle]")
    mark.wait_for(state="attached")
    assert "on" in mark.get_attribute("class")
    assert "RANGE RECEPTACLE 14-50R" in mark.locator("text.bp-wire-added-label").text_content()
    on = page.locator("#bp-wiring-routes .bp-wire-c.on")
    assert on.count() == 1 and on.get_attribute("data-circuit") == "RANGE"
    assert "Range receptacle" in page.inner_text("#bp-wiring-key")
    page.wait_for_selector("#toast:not([hidden])")
    assert "marked by the wiring run" in page.inner_text("#toast")
    # The breakers: the mark at the panel; the branch circuits behind it lit, the 30 A ones faded.
    page.locator("#bp-audit .bp-audit-item.waiting", has_text="Branch circuits").locator(".bp-audit-show").click()
    page.wait_for_selector("#bp-wiring-routes .bp-wire-added.on[data-added=branch_breakers]", state="attached")
    lit = page.locator("#bp-wiring-routes .bp-wire-c.on").evaluate_all("els => els.map(e => e.dataset.circuit)")
    assert "RANGE" not in lit and "C-1" in lit
    # Show all circuits: every mark back at full strength.
    page.click("#bp-wiring-key-all")
    assert page.locator("#bp-wiring-routes .bp-wire-added.off").count() == 0


def test_audit_show_goes_to_the_floor_plan_and_lights_the_wiring(page, db, job):
    """2026-11-20 (David: "the click should switch to the sheet or plan that needs review and will light up the
    wiring"): from the panel drawing - and for old cable from before a re-read too - Show on drawing goes to the floor
    plan, lights up the circuits of that size and zooms to them, beside the audit window, not under it."""
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import wiring_run
    first = wiring_run.run(db, CTX, job)
    plan_sheet = first["sources"]["plan"]["sheet_id"]
    ms.confirm_measurements(db, CTX, first["measurement_ids"], confirm=True)
    db.execute("UPDATE measurements SET sheet_id = NULL, viewport_id = NULL WHERE estimate_id = ?", (job,))
    db.commit()                                                   # old cable: "needs a run done again", no sheet
    panel_sheet = db.execute("SELECT s.id FROM sheets s JOIN plan_sets p ON p.id = s.plan_set_id"
                             " WHERE p.estimate_id = ? AND s.id != ?", (job, plan_sheet)).fetchone()[0]
    page.goto(page.base + f"#/takeoffs/{job}")
    page.wait_for_selector("#bp-viewer [data-oid]", state="attached")
    page.select_option("#review-sheet", str(panel_sheet))        # the person is on the panel drawing
    page.wait_for_function(f"() => document.querySelector('#review-sheet').value === '{panel_sheet}'")
    page.click("#bp-audit-open")
    page.wait_for_selector("#bp-audit .bp-audit-item.rerun")
    item = page.locator("#bp-audit .bp-audit-item.rerun", has_text="Cable 12/2").first
    item.locator(".bp-audit-show").click()                       # old cable has a Show link too
    page.wait_for_selector("#bp-wiring-routes.picked .bp-wire-c.on", state="attached")
    assert page.input_value("#review-sheet") == str(plan_sheet)  # went to the floor plan by itself
    lit = page.locator("#bp-wiring-routes .bp-wire-c.on").first.bounding_box()
    viewer, audit_box = page.locator("#bp-viewer").bounding_box(), page.locator("#bp-audit").bounding_box()
    cx = lit["x"] + lit["width"] / 2
    assert viewer["x"] <= cx <= viewer["x"] + viewer["width"]     # zoomed to it, in the drawing
    assert cx < audit_box["x"]                                    # and not under the audit window
    assert "lit up" in page.inner_text("#toast")


def test_wiring_colour_key_hover_and_click(page, db, job):
    """2026-11-20 (David: "no color code saying red is one circuit, yellow another ... hovering a wire always says room
    AC 30A ... I can't see what wire size it is, what breaker it's on and what it powers"): a colour key on the drawing,
    each wire says its circuit on hover, and a click on a key row or a wire shows only that circuit."""
    from estimator.takeoff import wiring_run
    wiring_run.run(db, CTX, job)
    open_wiring(page, job)
    page.check("#bp-wiring-show")
    page.wait_for_selector("#bp-wiring-key")
    rows = page.locator("#bp-wiring-key .bp-wiring-key-row")
    assert rows.count() == 6                                                  # one per circuit
    colours = page.eval_on_selector_all("#bp-wiring-key .bp-wire-swatch", "s => s.map(x => x.style.backgroundColor)")
    assert len(set(colours)) == 6                                             # each its own colour
    first = page.inner_text("#bp-wiring-key .bp-wiring-key-row >> nth=0")
    assert "C-1" in first and "12/2" in first and "20A" in first
    hover = page.eval_on_selector("#bp-wiring-routes [data-circuit='C-1'] > title", "t => t.textContent")
    assert "C-1" in hover and "20 A" in hover and "12/2 cable" in hover and "device" in hover
    # Hovering a wire reaches the wire (its wide hit line), not the room under it.
    assert page.locator("#bp-wiring-routes .bp-wire-hit").count() > 0
    page.locator("#bp-wiring-key .bp-wiring-key-row[data-circuit='C-2']").click()
    page.wait_for_selector("#bp-wiring-routes.picked [data-circuit='C-2'].on", state="attached")
    assert "Circuit C-2" in page.inner_text("#bp-wiring-key")
    page.click("#bp-wiring-key-all")
    page.wait_for_function("() => !document.querySelector('#bp-wiring-routes.picked')")
    # A click on a wire on the drawing picks its circuit.
    page.eval_on_selector("#bp-wiring-routes [data-circuit='C-3'] .bp-wire-hit",
                          "h => h.dispatchEvent(new MouseEvent('click', {bubbles: true}))")
    page.click("#bp-wiring-key-hide")
    page.wait_for_selector("#bp-wiring-key", state="detached")


@pytest.fixture
def drawn_job(db, tmp_path):
    from test_wiring import _plan_with_circuits
    est = service.create_estimate(db, CTX, "Wired house with circuit lines")
    service.add_trade(db, CTX, est["id"], "electrical", est.get("rev", 1))
    for f in (_plan_with_circuits(tmp_path), _panel(tmp_path)):
        ps = store.upload(db, CTX, est["id"], f, confirm=True)["plan_set_id"]
        engine.start(db, CTX, ps, confirm=True)
    db.commit()
    return est["id"]


def test_wiring_checked_against_the_drawn_circuits(page, db, drawn_job):
    """2026-11-20 (David): the designer's circuit lines get their own layer (hide them, keep the devices), and the
    wiring run is checked against them - each difference with a one-click "Move to C-2"."""
    open_wiring(page, drawn_job)
    page.click("#bp-tab-layers")
    page.wait_for_selector("#bp-pane-layers tr[data-group='circuits']")
    assert "Circuit lines" in page.inner_text("#bp-pane-layers tr[data-group='circuits']")
    assert page.locator("#bp-viewer [data-group='circuits'] [data-oid]").count() > 0
    page.click("#bp-tab-guide")
    page.click("#bp-wiring-run")
    page.click("#bp-wiring-options-run")                          # 2026-11-21: the wiring options box first
    page.wait_for_selector("#bp-wiring-check")
    assert "2 of 3 circuit(s) agree — 1 to check" in page.inner_text("#bp-wiring-check")
    row = page.locator("#bp-wiring-check-list li").first
    assert "drawing: C-2" in row.inner_text() and "wiring run: C-1" in row.inner_text()
    assert "On the drawing but not in the panel schedule: C-9" in page.inner_text("#bp-wiring")
    row.locator(".bp-wiring-check-move").click()
    page.wait_for_function("() => (document.querySelector('#bp-wiring-check') || {}).textContent"
                           " && document.querySelector('#bp-wiring-check').textContent.includes('3 of 3')", timeout=30000)
    assert page.locator("#bp-wiring-check-list").count() == 0
