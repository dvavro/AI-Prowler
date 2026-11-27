"""E2E (Playwright, headless): the takeoff-page UX rework (2026-11-18, David).

David's first live electrical auto-run (estimate 9, the house wiring DXF) showed the toolbar
far from the drawing, count rows that didn't highlight, a Count tool he wants gone, a
measurements table duplicated above the drawing, and a tab bar truncating "Measure steps".
Now:
  * the toolbar sits immediately above the drawing (the sheet picker stays up top);
  * the steps tab reads "AI Count steps" for an electrical run, "Measure steps" otherwise;
  * the Count tool is gone from the toolbar and the guide - AI Auto Measure/Count is the only way to count;
  * the above-drawing measurements table is gone, but the status line, Re-run and AI Log stay;
  * the Device counts table's Count column is editable by hand (ask-first, like every change),
    and a zero row creates its measurement when a number is typed in;
  * clicking a count row highlights the symbols it counted on the drawing.
Seeded with finished runs the same way test_e2e_ai_auto_run.py does (no real AI).
"""
from e2e_helpers import dismiss_tour
from estimator.api import autorun_api
from test_e2e_ai_auto_run import _finished_electrical_run, _finished_run, ehouse, shed  # noqa: F401

# ehouse/shed are fixtures from the auto-run tests, reused here (pytest picks up imported fixtures).


def _open_electrical(page, db, seed):
    """A finished electrical run, open on the electrical sheet with the counts table showing."""
    run = _finished_electrical_run(db, seed)
    autorun_api.update_run(db, run, status="done", step="done")
    db.commit()
    page.goto(page.base + f"#/takeoffs/{seed['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.select_option("#review-sheet", str(seed["elec"]))
    page.wait_for_selector("#bp-tab-steps", timeout=20000)
    page.click("#bp-tab-steps")
    page.wait_for_selector("#bp-auto-count-table", timeout=20000)


def test_E2E_toolbar_sits_with_the_drawing_and_sheet_picker_stays_up_top(page, shed):
    page.goto(page.base + f"#/takeoffs/{shed['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    # The toolbar is the element immediately before the drawing + side panel split.
    assert page.evaluate("() => document.querySelector('.bp-split').previousElementSibling.id") == "bp-tools"
    # The sheet picker stays in the top bar, with the toolbar gone from it.
    assert page.locator(".bp-bar #review-sheet").count() == 1
    assert page.locator(".bp-bar #bp-tools").count() == 0
    # No Count tool anywhere on the page (2026-11-18: AI Auto Measure/Count counts now).
    assert page.locator('[data-tool="count"]').count() == 0


def test_E2E_steps_tab_reads_ai_count_steps_for_an_electrical_run(page, db, ehouse):
    run = _finished_electrical_run(db, ehouse)
    autorun_api.update_run(db, run, status="done", step="done")
    db.commit()
    page.goto(page.base + f"#/takeoffs/{ehouse['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.select_option("#review-sheet", str(ehouse["elec"]))
    page.wait_for_function("() => document.querySelector('#bp-tab-steps') && "
                           "document.querySelector('#bp-tab-steps').innerText === 'AI Count steps'",
                           timeout=20000)


def test_E2E_steps_tab_reads_takeoff_steps_for_a_concrete_run(page, db, shed):
    run = _finished_run(db, shed)
    autorun_api.update_run(db, run, status="done", step="done")
    db.commit()
    page.goto(page.base + f"#/takeoffs/{shed['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.wait_for_function("() => document.querySelector('#bp-tab-steps') && "
                           "document.querySelector('#bp-tab-steps').innerText === 'Measure steps'",
                           timeout=20000)


def test_E2E_no_count_button_in_the_guide_either(page, db, ehouse):
    run = _finished_electrical_run(db, ehouse)
    autorun_api.update_run(db, run, status="done", step="done")
    db.commit()
    page.goto(page.base + f"#/takeoffs/{ehouse['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.select_option("#review-sheet", str(ehouse["elec"]))
    page.wait_for_selector("#bp-tab-steps", timeout=20000)
    page.click("#bp-tab-guide")
    guide = page.inner_text("#bp-guide")
    assert "✚ Count" not in guide
    # The count rows point at AI Auto Measure/Count instead of offering a Count tool, and keep their badges.
    assert "🤖 AI Auto Measure/Count" in guide
    assert "to review — 12 ea" in guide
    assert page.locator('[data-tool="count"]').count() == 0


def test_E2E_no_above_drawing_table_but_status_rerun_and_ai_log_remain(page, db, ehouse):
    run = _finished_electrical_run(db, ehouse)
    autorun_api.update_run(db, run, status="done", step="done")
    db.commit()
    page.goto(page.base + f"#/takeoffs/{ehouse['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    page.select_option("#review-sheet", str(ehouse["elec"]))
    page.wait_for_function("() => document.querySelector('#bp-auto-status') && "
                           "document.querySelector('#bp-auto-status').innerText.includes('finished: 4 proposed')",
                           timeout=20000)
    assert page.locator("#bp-auto-results").count() == 0
    assert "AI Auto Measure/Count finished: 4 proposed measurement(s)" in page.inner_text("#bp-auto-status")
    assert page.locator("#bp-auto-rerun").count() == 1
    assert page.locator("a[href*='#/agents/ai-log']").count() >= 1


def test_E2E_correct_a_count_by_hand_and_create_one_from_a_zero_row(page, db, ehouse):
    _open_electrical(page, db, ehouse)
    outlets = "#bp-auto-count-table tr[data-feeds='outlets'] input.bp-count-in"
    assert page.input_value(outlets) == "12"
    # Correct 12 outlets to 14: it asks first, like every other change.
    page.fill(outlets, "14")
    page.press(outlets, "Enter")
    page.wait_for_selector("#bp-count-question")
    assert "qty 12 → 14" in page.inner_text("#bp-count-question")
    page.click("#bp-count-yes")
    # Wait for the save to land: the guide badge only refreshes after the POST returns
    # (done -> refreshData -> drawTakeoffGuide), so this proves the edit reached the server.
    page.click("#bp-tab-guide")
    page.wait_for_function("() => document.querySelector('#bp-guide').innerText.includes('to review — 14 ea')",
        timeout=20000)
    assert float(db.execute("SELECT qty FROM measurements WHERE estimate_id = ? AND feeds = 'outlets'",
                            (ehouse["est"],)).fetchone()[0]) == 14
    page.click("#bp-tab-steps")   # back from the guide tab: the fans input lives here
    page.wait_for_selector("#bp-auto-count-table")
    # Fans had no measurement row (a zero count): typing 3 creates one.
    fans = "#bp-auto-count-table tr[data-feeds='fans'] input.bp-count-in"
    assert page.input_value(fans) == "0"
    assert page.get_attribute(fans, "data-mid") == ""
    page.fill(fans, "3")
    page.press(fans, "Enter")
    page.wait_for_selector("#bp-count-question")
    assert "Add 3.00 ea (count) for Electrical → fans?" in page.inner_text("#bp-count-question")
    page.click("#bp-count-yes")
    page.wait_for_function("() => { const i = document.querySelector(\"#bp-auto-count-table "
                           "tr[data-feeds='fans'] input.bp-count-in\");"
                           " return i && i.value === '3' && i.dataset.mid !== ''; }", timeout=20000)
    row = db.execute("SELECT qty, unit, kind, status, method FROM measurements"
                     " WHERE estimate_id = ? AND feeds = 'fans'", (ehouse["est"],)).fetchone()
    assert row is not None and float(row[0]) == 3 and row[1:] == ("ea", "count", "proposed", "typed")
    # The guide badge follows the new count, and the Measurements list has the new row.
    page.click("#bp-tab-guide")
    page.wait_for_function("() => document.querySelector('#bp-guide').innerText.includes('to review — 3 ea')")
    page.click("#bp-tab-list")
    assert "Ceiling fans" in page.inner_text("#bp-pane-list")


def test_E2E_click_a_count_row_to_highlight_its_symbols(page, db, ehouse):
    _open_electrical(page, db, ehouse)
    outlets = "#bp-auto-count-table tr[data-feeds='outlets']"
    # The sheet's receptacle is classified, so the Outlets row is clickable.
    assert "bp-step-link" in (page.get_attribute(outlets, "class") or "")
    page.click(outlets + " td:first-child")
    # The row shows "on", and the drawing selects the receptacle symbol.
    page.wait_for_function("() => document.querySelector(\"#bp-auto-count-table tr[data-feeds='outlets'].on\")")
    assert page.evaluate("() => RV.symbolType") == "duplex_receptacle"
    assert page.evaluate("() => RV.selected.size") == 1
    # The Symbols tab agrees: one symbol, showing "1 of 1".
    page.click("#bp-tab-symbols")
    page.wait_for_function("() => document.querySelector('#bp-symbol-where') && "
                           "document.querySelector('#bp-symbol-where').innerText === '1 of 1'")
    # Click again to clear it.
    page.click("#bp-tab-steps")
    page.click(outlets + " td:first-child")
    page.wait_for_function("() => !document.querySelector(\"#bp-auto-count-table tr[data-feeds='outlets'].on\")")
    assert page.evaluate("() => RV.selected.size") == 0
    # Circuits have no symbols behind them, and this sheet has no fans: those rows aren't clickable.
    for feeds in ("circuits_15a", "fans"):
        cls = page.get_attribute(f"#bp-auto-count-table tr[data-feeds='{feeds}']", "class") or ""
        assert "bp-step-link" not in cls, feeds
