"""Mobile layouts (spec §6.9) — the app on a phone-sized screen, touch enabled.

Every test runs twice: a small Android phone (Pixel 5, 393 x 727) and an
iPhone-sized screen (390 x 664), emulated in Edge (Chromium) with touch on.
(A real iPhone runs Safari/WebKit; this checks the LAYOUT at that size, not
Safari itself.)

MOB-01  every screen opens from the bottom nav and fits: no sideways page scroll,
        the tapped nav button is on screen
MOB-02  tap targets: bottom-nav buttons and the main action buttons >= 40 px tall
MOB-03  Route on a phone (smoke of RB-03 / RE-01 / RE-11): build, ▲ moves a stop,
        help panel opens/closes, no sideways scroll
MOB-04  PS-11 on a phone: tapping a prescreen item highlights that job
MOB-05  touch drag (✋) reorders a stop — a REAL touch gesture (Chromium touch
        events), not a mouse drag
MOB-06  Route Selected Date / AI Route / Email in ONE row; the Route page scrolls
        and Approve / Un-approve sit below the map (scroll down to reach them)
MOB-07  ⛶ full-screen map + stop strip; a stop chip selects; Back and ✕ return

(The fixture is called `phone`, not `device`: pytest-playwright already has a
session-scoped `device` fixture, and shadowing it broke every test's setup.)

Run: run_tests_gui_jobs_e2e.bat --human --mobile
"""
import re

import pytest
from playwright.sync_api import expect

from app import SCREENS
from safety import SANDBOX_DATE

PHONES = {
    "pixel5": {"viewport": {"width": 393, "height": 727}, "device_scale_factor": 2.75,
               "is_mobile": True, "has_touch": True,
               "user_agent": "Mozilla/5.0 (Linux; Android 13; Pixel 5) AppleWebKit/537.36 "
                             "(KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"},
    "iphone": {"viewport": {"width": 390, "height": 664}, "device_scale_factor": 3,
               "is_mobile": True, "has_touch": True,
               "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
                             "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"},
}
MIN_TAP = 40


@pytest.fixture(params=list(PHONES), ids=list(PHONES))
def phone(request):
    return request.param


@pytest.fixture
def browser_context_args(browser_context_args, phone):
    return {**browser_context_args, **PHONES[phone]}


def _sideways_overflow(page) -> int:
    return page.evaluate("() => document.documentElement.scrollWidth - window.innerWidth")


def _in_viewport(page, loc) -> bool:
    b, vp = loc.bounding_box(), page.viewport_size
    return bool(b) and b["x"] >= -1 and b["y"] >= -1 and \
        b["x"] + b["width"] <= vp["width"] + 1 and b["y"] + b["height"] <= vp["height"] + 1


def _four_routed(data, route):
    ids = [data.job(f"MOB {i}", p) for i, p in enumerate(["city_hall", "brannon", "library", "flagler"], 1)]
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.expect_stops_include(ids)
    return ids


# ── MOB-01 ───────────────────────────────────────────────────────────────────
def test_mobile_MOB_01_every_screen_fits(app, page, phone):
    problems = []
    for s in app.visible_screens():
        app.goto(s)
        page.wait_for_timeout(700)
        over = _sideways_overflow(page)
        if over > 1:
            problems.append(f"{s}: page scrolls sideways by {over}px")
        if not _in_viewport(page, app.nav_button(s)):
            problems.append(f"{s}: its nav button isn't fully on screen after tapping it")
    assert not problems, f"[{phone}] " + "; ".join(problems)


# ── MOB-02 ───────────────────────────────────────────────────────────────────
def test_mobile_MOB_02_tap_targets(app, page, phone):
    small = []

    def check(label, loc):
        if loc.count() and loc.first.is_visible():
            h = loc.first.bounding_box()["height"]
            if h < MIN_TAP:
                small.append(f"{label} {h:.0f}px")

    for s in app.visible_screens():
        check(f"nav:{s}", app.nav_button(s))
    app.goto("jobs")
    check("jobs ↻", page.locator("#refreshJobsBtn"))
    app.goto("route")
    check("Route Selected Date", page.locator("#routeTodayBtnRoute"))
    check("route ↻", page.locator("#refreshRouteBtn"))
    assert not small, f"[{phone}] tap targets under {MIN_TAP}px: " + ", ".join(small)


# ── MOB-03 ───────────────────────────────────────────────────────────────────
def test_mobile_MOB_03_route_build_move_help(clean_slate, route, page, data, phone):
    _four_routed(data, route)
    assert _sideways_overflow(page) <= 1, f"[{phone}] Route screen scrolls sideways"
    third = route.stop(3).job_id()
    route.stop(3).move_up()
    route.pick_date(SANDBOX_DATE)
    assert route.stop(2).job_id() == third, f"[{phone}] ▲ on stop 3 didn't make it stop 2"
    toggle, body = page.get_by_test_id("route-help-toggle"), page.locator(".route-help-body")
    toggle.click()
    expect(body).to_be_visible()
    assert _sideways_overflow(page) <= 1, f"[{phone}] the help panel makes the page scroll sideways"
    toggle.click()
    expect(body).to_be_hidden()


# ── MOB-04 ───────────────────────────────────────────────────────────────────
def test_mobile_MOB_04_prescreen_tap_highlights(clean_slate, route, page, data, phone):
    jid = data.job("MOB04 no address", "city_hall", street="")
    data.job("MOB04 ok", "brannon")
    route.pick_date(SANDBOX_DATE)
    route.run_prescreen()
    route.wait_quiet()
    # Tap the card's TITLE, the way a person reads-and-taps it. (First run: a
    # tap on the card's centre — Playwright's default — hit the "✏️ JOB-…" fix
    # chip inside the card on a narrow screen, which opens the job instead.)
    app_log = route.step
    app_log("tap prescreen item 0 (on its title)")
    route.prescreen_items().nth(0).locator(".ps-title").click()
    expect(page.locator("#jobFormModal")).to_be_hidden()
    route.expect_highlighted_jobs([jid])
    assert _sideways_overflow(page) <= 1, f"[{phone}] the prescreen list makes the page scroll sideways"


# ── MOB-05 ───────────────────────────────────────────────────────────────────
def _touch_drag(page, start_x, start_y, end_y, steps=14):
    cdp = page.context.new_cdp_session(page)
    try:
        cdp.send("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [{"x": start_x, "y": start_y}]})
        for i in range(1, steps + 1):
            y = start_y + (end_y - start_y) * i / steps
            cdp.send("Input.dispatchTouchEvent", {"type": "touchMove", "touchPoints": [{"x": start_x, "y": y}]})
            page.wait_for_timeout(45)
        cdp.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
    finally:
        cdp.detach()


def test_mobile_MOB_05_touch_drag_reorders(clean_slate, route, page, data, app, phone):
    _four_routed(data, route)
    first = route.stop(1).job_id()
    handle = route.stop(1).row.get_by_test_id("stop-drag")
    target = route.stop(3).row
    target.scroll_into_view_if_needed()
    handle.scroll_into_view_if_needed()
    hb, tb = handle.bounding_box(), target.bounding_box()
    x, y0 = hb["x"] + hb["width"] / 2, hb["y"] + hb["height"] / 2
    y1 = tb["y"] + tb["height"] * 0.8                     # past stop 3's middle
    app.log(f"MOBILE touch-drag ✋ of stop 1 ({first}) from y={y0:.0f} to y={y1:.0f}")
    with page.expect_request(lambda r: "/pwa-api" in r.url and "reorder_route_stop" in (r.post_data or ""),
                             timeout=20_000):
        _touch_drag(page, x, y0, y1)
    route.wait_quiet()
    route.pick_date(SANDBOX_DATE)
    assert route.stop(3).job_id() == first, \
        f"[{phone}] after dragging stop 1 below stop 3 it isn't 3rd: {[s.job_id() for s in route.stops()]}"


# ── MOB-06 ───────────────────────────────────────────────────────────────────
def test_mobile_MOB_06_route_buttons_one_row_page_scrolls(clean_slate, route, page, data, app, phone):
    """David 2026-10-18: on a phone the 2 route buttons + Email sit in ONE row
    (short labels), and the page scrolls so Approve / Un-approve sit at the
    bottom (scroll down to reach them) instead of being pinned under the map."""
    _four_routed(data, route)
    # 2026-10-22: 🧠 AI Route (routeAiSuggestBtn) was replaced by 📋 Any AI (routeCopyAiBtn)
    # 2026-10-22: + 🗓️ Week (routeWeekPlanBtn) — four buttons, still one row
    btns = [page.locator(f"#{i}") for i in ("routeTodayBtnRoute", "routeCopyAiBtn", "routeWeekPlanBtn",
                                            "routeEmailRouteBtn")]
    boxes = [b.bounding_box() for b in btns]
    assert all(boxes), f"[{phone}] a route action button isn't on the page"
    tops = [round(b["y"]) for b in boxes]
    assert max(tops) - min(tops) <= 2, f"[{phone}] route/Any AI/Week/Email buttons aren't in one row (tops {tops})"
    vw = page.viewport_size["width"]
    for b, bx in zip(btns, boxes):
        assert bx["x"] >= 0 and bx["x"] + bx["width"] <= vw + 1, f"[{phone}] {b} runs off the screen"
    for b, bx in zip(btns, boxes):
        assert bx["height"] >= MIN_TAP, f"[{phone}] {b} is only {bx['height']:.0f}px tall"
    assert page.evaluate("() => getComputedStyle(document.getElementById('screen-route')).display") == "block", \
        f"[{phone}] Route screen isn't in page-scroll mode"
    approve = page.locator("#routeApproveRow")
    approve.scroll_into_view_if_needed()
    expect(approve).to_be_visible()
    ab = approve.bounding_box()
    mb = page.locator("#routeMap").bounding_box()
    assert ab["y"] > mb["y"] + mb["height"], f"[{phone}] Approve row isn't below the map"
    assert _sideways_overflow(page) <= 1, f"[{phone}] Route screen scrolls sideways"


# ── MOB-07 ───────────────────────────────────────────────────────────────────
def test_mobile_MOB_07_map_full_screen_and_back(clean_slate, route, page, data, app, phone):
    """⛶ opens the route map full screen with a stop strip; tapping a stop chip
    selects it; the phone's Back (history) and ✕ both return to the normal view."""
    _four_routed(data, route)
    fs = page.locator("#routeMapFsBtn")
    fs.scroll_into_view_if_needed()
    app.log("tap ⛶ full-screen map")
    fs.click()
    m = page.locator("#routeMap")
    expect(m).to_have_class(re.compile(r"\broute-map-full\b"))
    page.wait_for_timeout(400)
    vp, mb = page.viewport_size, m.bounding_box()
    assert mb["width"] >= vp["width"] - 2 and mb["height"] >= vp["height"] - 2, \
        f"[{phone}] map isn't full screen: {mb} vs {vp}"
    strip = page.get_by_test_id("route-map-full-strip")
    expect(strip).to_be_visible()
    chips = page.get_by_test_id("route-map-full-stop")
    assert chips.count() >= 4, f"[{phone}] full-screen strip shows {chips.count()} stops, expected 4"
    app.log("tap stop chip 2")
    chips.nth(1).click()
    expect(page.get_by_test_id("route-map-full-stop").nth(1)).to_have_class(re.compile(r"\bsel\b"))
    app.log("phone Back closes full screen")
    page.go_back()
    expect(strip).to_be_hidden()
    page.wait_for_timeout(300)
    assert m.bounding_box()["height"] < vp["height"] - 40, f"[{phone}] Back didn't shrink the map"
    expect(m).not_to_have_class(re.compile(r"\broute-map-full\b"))
    expect(page.locator("#screen-route")).to_be_visible()      # Back didn't leave the Route screen
    app.log("⛶ again, then ✕ closes it")
    fs.click()
    expect(strip).to_be_visible()
    page.locator("#routeMapFsBtn").click()
    expect(strip).to_be_hidden()
    expect(page.locator("#screen-route")).to_be_visible()

    # David 2026-10-19, real phone: the corner ✕ was hidden under the status bar /
    # notch (the page uses viewport-fit=cover) and an iPhone home-screen app has no
    # Back, so he was stuck. Emulators report a 0px safe area, so fake a 47px notch.
    NOTCH = 47
    page.evaluate(f"() => document.documentElement.style.setProperty('--safe-top', '{NOTCH}px')")
    app.log(f"fake a {NOTCH}px notch; ⛶ again")
    fs.click()
    expect(strip).to_be_visible()
    xb = page.locator("#routeMapFsBtn").bounding_box()
    assert xb["y"] >= NOTCH, f"[{phone}] full-screen ✕ is under the notch (top {xb['y']:.0f}px < {NOTCH}px)"
    assert xb["height"] >= MIN_TAP, f"[{phone}] full-screen ✕ is only {xb['height']:.0f}px tall"
    # Real phones clip a fixed element to its touch-scroll container (.main), hiding
    # the map's top under the top bar and the strip under the bottom nav. Emulators
    # don't, so check the cause directly: the full-screen map and strip must be
    # children of <body>, and the zoom buttons / ✕ Exit must be the topmost thing
    # where a finger would land.
    assert page.evaluate("""() => document.getElementById('routeMap').parentElement === document.body
        && document.getElementById('routeMapFullStrip').parentElement === document.body"""), \
        f"[{phone}] full-screen map/strip are still inside the scrolling page (real phones clip them)"
    for sel in (".leaflet-control-zoom-in", "#routeMapFsBtn", "#routeMapFullExit"):
        hit = page.evaluate("""s => { const el = document.querySelector(s); if (!el) return 'missing';
            const r = el.getBoundingClientRect();
            const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
            return top && (top === el || el.contains(top)) ? 'ok' : (top ? (top.id || top.className || top.tagName) : 'nothing'); }""", sel)
        assert hit == "ok", f"[{phone}] {sel} in full screen is covered by: {hit}"
    ex = page.get_by_test_id("route-map-full-exit")
    expect(ex).to_be_visible()
    eb, vp = ex.bounding_box(), page.viewport_size
    assert eb["height"] >= MIN_TAP - 4 and 0 <= eb["x"] and eb["y"] + eb["height"] <= vp["height"] + 1, \
        f"[{phone}] '✕ Exit' in the stop strip isn't fully on screen: {eb}"
    app.log("tap '✕ Exit' in the stop strip")
    ex.click()
    expect(strip).to_be_hidden()
    expect(m).not_to_have_class(re.compile(r"\broute-map-full\b"))
    expect(page.locator("#screen-route")).to_be_visible()
    assert page.evaluate("""() => !!document.getElementById('routeMap').closest('#screen-route')
        && !!document.getElementById('routeMapFullStrip').closest('#screen-route')
        && !document.getElementById('routeMapPlaceholder')"""), \
        f"[{phone}] after exit the map/strip didn't go back into the Route screen"
    page.evaluate("() => document.documentElement.style.removeProperty('--safe-top')")
    assert _sideways_overflow(page) <= 1, f"[{phone}] page scrolls sideways after full screen"


def test_mobile_screens_list_is_current():
    """Guard for this file: MOB-01/02 walk app.visible_screens(); make sure the
    page-object screen list still includes the screens a phone user relies on."""
    assert {"jobs", "route", "clock", "photos"} <= set(SCREENS)
