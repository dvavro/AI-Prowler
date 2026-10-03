"""Settings screen — the email/SMS switches, flipped the way a person does it
(R-060, David 2026-09-29). Database → Settings → tap the setting → change the
value → Save, then read it back from the database; then flip it back the same
way. Watch it in --human.

Only the three toggles the suite may touch (settings_switch.TOGGLES). Their
originals were saved by the pre-flight; the `toggles` fixture puts them back
after each test even if a step fails, and the end-of-run check fails the run
if any isn't back.

Run: run_tests_gui_jobs_e2e.bat --human -k test_settings_toggles
"""
import pytest
from playwright.sync_api import expect

from settings_switch import SWITCHES, TOGGLES
from test_database import _fill, _save, _tab, _wait


@pytest.fixture
def settings_tab(app, page):
    app.goto("sheet")
    _wait(page)
    _tab(app, page, "Settings")
    expect(page.locator("#sheetContent")).to_contain_text("Business Settings")
    return page


def _flip_in_app(app, page, key: str, value: str):
    row = page.locator(f"#sheetContent div[onclick^='_settingsItemClicked(\"{key}\"']").first
    row.scroll_into_view_if_needed()
    app.log(f"SETTINGS tap '{key}'")
    row.click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jfGenericInputs .spinner")).to_have_count(0, timeout=20_000)
    _fill(app, page, "Value", value)
    _save(app, page, "update_job_spreadsheet")
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _wait(page)


# Working Days (2026-10-02) is flipped only by CAL-06 (test_calendar.py), which
# first checks no REAL open "days" job would have its End Date re-counted.
_FLIPPABLE_HERE = [k for k in TOGGLES if k != "Working Days"]


@pytest.mark.parametrize("key", _FLIPPABLE_HERE, ids=["route_email", "reminder_email", "reminder_sms", "route_origin_mode"])
def test_SET_01_flip_toggle_in_settings_screen(settings_tab, app, page, toggles, guard, key):
    page = settings_tab
    original = toggles.saved[key]["Value"]
    other = next(v for v in SWITCHES[key] if v.lower() != original.lower())
    _flip_in_app(app, page, key, other)
    now = toggles.value(key)
    guard.observe_setting(key, now)
    assert now == other, f"after saving '{key}' = {other} the database says {now!r}"
    expect(page.locator("#sheetContent")).to_contain_text(key)
    _flip_in_app(app, page, key, original)
    now = toggles.value(key)
    guard.observe_setting(key, now)
    assert now == original, f"after flipping '{key}' back the database says {now!r} (was {original!r})"
    app.log(f"SETTINGS '{key}': {original} → {other} → {original} ✓")


@pytest.mark.expect_guard_block
def test_SET_02_guard_refuses_any_other_setting(api, toggles, guard):
    """The exception is only for the three toggles: a write to any other
    setting (here Tax Rate) is still blocked before it leaves the test."""
    from safety import GuardViolation
    try:
        with pytest.raises(GuardViolation):
            api.call("update_job_spreadsheet", {"sheet_name": "Settings", "id_column": "Setting",
                                                "job_identifier": "Tax Rate", "updates": {"Value": "0.99"}})
        with pytest.raises(GuardViolation):                  # a toggle, but not an on/off value
            api.call("update_job_spreadsheet", {"sheet_name": "Settings", "id_column": "Setting",
                                                "job_identifier": TOGGLES[0], "updates": {"Value": "Maybe"}})
        with pytest.raises(GuardViolation):                  # a toggle, but also changing its note
            api.call("update_job_spreadsheet", {"sheet_name": "Settings", "id_column": "Setting",
                                                "job_identifier": TOGGLES[0],
                                                "updates": {"Value": "Enabled", "Notes": "changed"}})
    finally:
        blocked = guard.take_violations()          # expected blocks — don't let them fail the next test
    assert len(blocked) == 3, blocked
