"""E2E (Playwright, headless): the measurements guide lives in a "To measure" tab (2026-11-19, David).

David: the "What to measure" guide sat above the drawing, and he wants it at the right of
the drawing window as its own tab, scrolling so nothing clips in the 360px panel, with a
click on a measurement row lighting up the counted items — the same for every trade.
Now the guide renders into a "To measure" tab in the side panel (second, after
Measurements); count rows reuse the Measure steps highlight path.
"""
import pytest

from e2e_helpers import dismiss_tour
from test_e2e_ai_auto_run import ehouse, shed  # noqa: F401  (fixture reuse)


def _open(page, est):
    page.goto(page.base + f"#/takeoffs/{est}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)


def test_E2E_guide_is_a_tab_beside_the_drawing_not_a_panel_above_it(page, shed):
    _open(page, shed["est"])
    assert page.locator("#bp-guide-slot").count() == 0          # nothing above the drawing
    tab = page.locator("#bp-tab-guide")
    assert tab.count() == 1 and tab.inner_text() == "To measure"
    # The pane is inside the side panel (the scrolling region) and hidden until its tab is picked.
    assert page.evaluate("() => document.querySelector('#bp-pane-guide').closest('.bp-side') !== null")
    assert page.locator("#bp-pane-guide").is_hidden()
    page.click("#bp-tab-guide")
    assert page.locator("#bp-pane-guide").is_visible()
    guide = page.inner_text("#bp-guide")
    assert "What to measure" in guide and "Concrete" in guide
    # Calibration is still the first step, before any trade's questions.
    assert page.locator("#bp-guide-calibration").count() == 1


def test_E2E_two_trade_estimate_shows_both_trades_sections_in_the_tab(page, ehouse):
    _open(page, ehouse["est"])
    page.click("#bp-tab-guide")
    assert page.locator("#bp-guide-concrete").count() == 1
    assert page.locator("#bp-guide-electrical").count() == 1


def test_E2E_clicking_a_guide_count_row_highlights_its_symbols(page, ehouse):
    _open(page, ehouse["est"])
    page.select_option("#review-sheet", str(ehouse["elec"]))
    page.wait_for_function("(elec) => typeof RV !== 'undefined' && RV.sheetId === elec", arg=ehouse["elec"], timeout=20000)
    page.click("#bp-tab-guide")
    outlets = "#bp-pane-guide li[data-feeds='outlets']"
    page.wait_for_selector(outlets)
    # The electrical sheet's receptacle is classified, so the Outlets row is clickable.
    assert "bp-step-link" in (page.get_attribute(outlets, "class") or "")
    page.click(outlets)
    page.wait_for_function("() => document.querySelector(\"#bp-pane-guide li[data-feeds='outlets'].on\")")
    assert page.evaluate("() => RV.symbolType") == "duplex_receptacle"
    assert page.evaluate("() => RV.selected.size") == 1
    # Click again to clear it.
    page.click(outlets)
    page.wait_for_function("() => !document.querySelector(\"#bp-pane-guide li[data-feeds='outlets'].on\")")
    assert page.evaluate("() => RV.selected.size") == 0


def test_E2E_guide_pane_scrolls_horizontally(page, shed):
    _open(page, shed["est"])
    assert page.evaluate("() => getComputedStyle(document.querySelector('#bp-pane-guide')).overflowX") == "auto"
    assert page.evaluate("() => getComputedStyle(document.querySelector('.bp-side')).overflowY") == "auto"
