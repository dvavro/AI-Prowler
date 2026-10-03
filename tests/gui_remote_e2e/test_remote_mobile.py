"""Remote PWA — phone layouts (REMOTE_PWA_E2E_TEST_SPEC.md §5.9, RM). Read-only.

Every screen at Pixel 7 and iPhone 13 sizes: nothing scrolls sideways, the
bottom nav is fully on screen, and the always-there buttons (bottom nav, top-bar
↻) are at least 40 px — the same finger-size bar as the Jobs app (R-037).

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_mobile
"""
import pytest
from playwright.sync_api import expect

from remote_app import TABS

PHONES = {"pixel7": {"width": 412, "height": 915}, "iphone13": {"width": 390, "height": 844}}
MIN_TAP = 40


@pytest.fixture(params=list(PHONES), ids=list(PHONES))
def phone(request, ui, token):
    size = PHONES[request.param]
    ui.step(f"phone size {request.param} {size['width']}x{size['height']}")
    ui.page.set_viewport_size(size)
    ui.login(token).signed_in()
    return ui


def test_RM_01_no_sideways_scroll_and_nav_on_screen(phone):
    vw = phone.page.viewport_size["width"]
    vh = phone.page.viewport_size["height"]
    wide = {}
    for tab in TABS:
        phone.goto(tab)
        phone.page.wait_for_timeout(800)
        sw = phone.page.evaluate("() => document.documentElement.scrollWidth")
        if sw > vw + 1:
            wide[tab] = sw
    assert not wide, f"screens scroll sideways at {vw}px wide: {wide}"
    nav = phone.page.locator("#navDash").locator("xpath=..")
    box = nav.bounding_box()
    assert box and box["x"] >= -1 and box["x"] + box["width"] <= vw + 1 and box["y"] + box["height"] <= vh + 1, \
        f"bottom nav isn't fully on screen: {box}"


def test_RM_02_always_there_buttons_are_finger_sized(phone):
    small = {}
    for name in TABS.values():
        b = phone.page.locator(f"#nav{name}").bounding_box()
        if b and (b["height"] < MIN_TAP or b["width"] < MIN_TAP):
            small[f"nav {name}"] = (round(b["width"]), round(b["height"]))
    r = phone.page.locator("#refreshBtn").bounding_box()
    if r and (r["height"] < MIN_TAP or r["width"] < MIN_TAP):
        small["top-bar ↻"] = (round(r["width"]), round(r["height"]))
    assert not small, f"buttons smaller than {MIN_TAP}px (w, h): {small}"


# ── RM-03: both 👁 show/hide buttons are finger-sized (RM-R-010) ──────────────
@pytest.mark.parametrize("size", list(PHONES), ids=list(PHONES))
def test_RM_03_eye_buttons_are_finger_sized(ui, token, rapi, size):
    from remote_safety import SANDBOX
    ui.page.set_viewport_size(PHONES[size])
    b = ui.page.locator("#authEyeBtn").bounding_box()
    assert b and b["width"] >= MIN_TAP and b["height"] >= MIN_TAP, f"login 👁 is {b}"
    ui.login(token).signed_in()
    if rapi.sandbox_writable():                      # the modal only opens on a read-only folder
        rapi.call("revoke_write_access", {"directory": str(SANDBOX)})
    ui.refresh_all()
    ui.goto("perms")
    cb = ui.page.locator(f'xpath=//input[contains(@class,"perm-cb") and @data-path="{SANDBOX}"]')
    ui.step("tap the sandbox's write toggle to open the grant modal")
    cb.locator("xpath=..").click()
    expect(ui.page.locator("#reAuthModal")).to_be_visible()
    m = ui.page.locator("#reAuthModal .show-btn").bounding_box()
    ui.page.locator("#reAuthModal .btn-cancel").click()
    assert m and m["width"] >= MIN_TAP and m["height"] >= MIN_TAP, f"grant-modal 👁 is {m}"
