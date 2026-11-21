"""E2E (Playwright, headless): two overlapping sheet opens can't merge two sheets (2026-11-19, David).

David uploaded two DXFs to estimate 9 (the panel schematic and the floor plan) and the
takeoff view showed the floor-plan image with the panel sheet's objects overlaid. The
stored data was right: review.js openSheet had no guard against a stale response, so a
slow first call could land after a fast second one and win RV.objects while the tiles
followed RV.sheetId. openSheet now carries a generation guard: a stale response is
dropped whole. This test makes the first call slow on purpose (a route delay) and
proves the view stays consistent with the second sheet.
"""
import time

import pytest

from e2e_helpers import dismiss_tour
from test_e2e_ai_auto_run import shed  # noqa: F401  (fixture reuse)


def test_E2E_a_late_first_sheet_never_overwrites_the_second(page, shed):
    off, on = shed["off"], shed["on"]

    def delay_off(route):
        time.sleep(1.5)
        route.continue_()

    # The first sheet's API answers land late; the second sheet's answer fast.
    page.route(f"**/estimator-api/sheets/{off}", delay_off)
    page.route(f"**/estimator-api/sheets/{off}/objects", delay_off)
    page.goto(page.base + f"#/takeoffs/{shed['est']}")
    page.wait_for_selector("#bp-tools")
    dismiss_tour(page)
    # The page opens on the sheet that is on; switch to the off sheet and straight back.
    assert page.eval_on_selector("#review-sheet", "s => +s.value") == on
    page.select_option("#review-sheet", str(off))
    page.select_option("#review-sheet", str(on))
    # The fast call lands first; wait out the delayed one, then check the view is all sheet 2.
    page.wait_for_function("(on) => typeof RV !== 'undefined' && RV.sheetId === on && RV.sheet && RV.sheet.id === on",
                           arg=on, timeout=20000)
    page.wait_for_timeout(2500)
    assert page.evaluate("() => RV.sheetId") == on
    assert page.evaluate("() => RV.sheet.id") == on
    assert page.evaluate("() => RV.sheet.page_no") == 2
    assert page.evaluate("() => RV.objects.every(o => o.sheet_id === RV.sheetId)") is True
    assert page.eval_on_selector("#review-sheet", "s => +s.value") == on
