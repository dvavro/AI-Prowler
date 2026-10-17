"""
HR Portal in a real browser (sandbox server; see conftest.py):
  * an employee signs in through the real sign-in screen and every Portal page
    opens cleanly (no JS errors, not empty, no "undefined" / "coming in Week")
  * THREE employees signed in at the same time, in separate browsers, clock in
    and out together - each entry lands on the right person, nobody sees
    anyone else's
  * HR Admin and the Portal together: an HR announcement reaches the Feed and
    the employee's "reviewed" reaches HR; "Who clocks in = Nobody" hides the clock
"""
import asyncio
import threading

import pytest

from hr_gui_helpers import USERS, bad_words, new_page, sign_in_portal, visible_text

STAFF_PAGES = ["welcome", "about", "portfolio", "details", "emergency", "news", "feed", "schedule", "timeclock",
               "pay", "tasks", "directory", "docs", "help", "messages", "payroll", "deposits", "calendar",
               "companycalendar", "pto", "handbook", "writeup", "trainings", "incident-reports"]


@pytest.fixture(scope="module")
def anna(browser, hr_sandbox):
    ctx, page, watch = new_page(browser, "anna")
    sign_in_portal(page, hr_sandbox, "anna")
    yield page, watch
    ctx.close()


def _go(page, pid):
    el = page.locator(f'.nav-item[data-page="{pid}"]').first
    if el.is_visible():
        el.click()
    else:                                    # narrow layouts tuck the menu away: same handler either way
        el.evaluate("e => e.click()")
    page.wait_for_timeout(900)


def test_portal_real_sign_in(anna):
    page, watch = anna
    assert page.evaluate("authState.session.employee_id").startswith("EMP-")
    assert not watch.errors, watch.errors


@pytest.mark.parametrize("pid", STAFF_PAGES)
def test_every_portal_page_opens_cleanly(anna, pid):
    page, watch = anna
    before = len(watch.errors)
    _go(page, pid)
    sel = f"#page-{pid}"
    assert page.is_visible(sel), f"{pid}: page didn't show"
    txt = visible_text(page, sel)
    assert len(txt.strip()) > 10, f"{pid}: page is empty"
    assert not bad_words(txt), f"{pid}: shows {bad_words(txt)}"
    assert watch.errors[before:] == [], watch.errors[before:]


# ── three employees at the same time ────────────────────────────────────────
def test_three_employees_clock_in_and_out_at_the_same_time(hr_sandbox):
    names = ["anna", "ben", "cara"]
    result = {}

    async def one(pw_browser, who):
        ctx = await pw_browser.new_context(viewport={"width": 1280, "height": 900}, service_workers="block")
        page = await ctx.new_page()
        errs = []
        page.on("pageerror", lambda e: errs.append(str(e)))
        await page.add_init_script("try{localStorage.setItem('hr_gs_seen','1')}catch(e){}")
        await page.goto(f"{hr_sandbox.base}/hr_portal/")
        await page.fill("#login-name", USERS[who][0])
        await page.fill("#login-pass", USERS[who][1])
        await page.click("#login-btn")
        await page.wait_for_function("() => typeof authState !== 'undefined' && authState && authState.session",
                                     timeout=20000)
        await page.wait_for_timeout(1500)
        await page.evaluate("navigate(document.querySelector('[data-page=timeclock]'),'timeclock','Time Clock')")
        await page.wait_for_timeout(800)
        return ctx, page, errs

    async def main():
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            b = await p.chromium.launch(headless=True)
            sessions = await asyncio.gather(*[one(b, w) for w in names])          # sign in together
            await asyncio.gather(*[s[1].click("#clock-btn") for s in sessions])    # clock in together
            await asyncio.sleep(1.5)
            result["open"] = hr_sandbox.api("GET", "/timeclock/today")[1].get("entries", [])
            await asyncio.gather(*[s[1].click("#clock-btn") for s in sessions])    # clock out together
            await asyncio.sleep(1.5)
            for who, (ctx, page, errs) in zip(names, sessions):
                await page.evaluate("loadTimeClockEntries()")
                await asyncio.sleep(0.8)
                result[who] = (await page.inner_text("#timeclock-entries"), errs)
                await ctx.close()
            await b.close()

    t = threading.Thread(target=lambda: asyncio.run(main()))                       # own event loop
    t.start(); t.join(240)
    assert not t.is_alive(), "the three-employee run didn't finish"
    by_emp = {}
    for en in result["open"]:
        by_emp.setdefault(en["employee_id"], []).append(en)
    for who in names:
        eid = hr_sandbox.employee_id(who)
        assert len(by_emp.get(eid, [])) == 1, (who, by_emp)                         # exactly one, theirs
    st, j = hr_sandbox.api("GET", "/timeclock/today")
    mine = [en for en in j.get("entries", []) if en["employee_id"] in {hr_sandbox.employee_id(w) for w in names}]
    assert len(mine) == 3 and all(en.get("clock_out") for en in mine), mine          # all clocked out
    for who in names:
        txt, errs = result[who]
        assert not errs, (who, errs)
        others = [USERS[o][0] for o in names if o != who]
        assert not any(o in txt for o in others), (who, "sees someone else's entries", txt[:300])


# ── HR Admin and the Portal together ────────────────────────────────────────
def test_announcement_reaches_the_feed_and_review_reaches_hr(browser, hr_sandbox):
    st, j = hr_sandbox.api("POST", "/announcements", {"title": "ZTEST Safety meeting Friday", "body": "Bring boots.",
                                                      "tag": "urgent", "ack_required": True}, who="manager")
    assert st in (200, 201), j
    ann_id = (j.get("announcement") or j).get("id")
    ctx, page, watch = new_page(browser, "ben")
    sign_in_portal(page, hr_sandbox, "ben")
    _go(page, "feed")
    assert "ZTEST Safety meeting Friday" in visible_text(page, "#page-feed")
    page.locator("#page-feed button:has-text(\"I've reviewed this\")").first.click()
    page.wait_for_timeout(1200)
    st, j = hr_sandbox.api("GET", "/announcements", who="manager")
    ann = next(a for a in j.get("announcements", []) if a.get("id") == ann_id)
    acks = ann.get("acks")                          # HR sees how many reviewed it (HR Admin: "reviewed by 1 of N")
    assert acks == 1 or hr_sandbox.employee_id("ben") in str(acks), ann
    assert not watch.errors, watch.errors
    ctx.close()


def test_who_clocks_in_nobody_hides_the_clock(browser, hr_sandbox):
    assert hr_sandbox.api("POST", "/settings", {"time_clock_mode": "nobody"}, who="manager")[0] == 200
    try:
        ctx, page, watch = new_page(browser, "cara")
        sign_in_portal(page, hr_sandbox, "cara")
        _go(page, "timeclock")
        assert not page.is_visible("#clock-btn")
        assert page.is_visible("text=Running Late")
        assert "Running Late / Out" in visible_text(page, "#header-page-title")
        assert not watch.errors, watch.errors
        ctx.close()
    finally:
        hr_sandbox.api("POST", "/settings", {"time_clock_mode": "everyone"}, who="manager")
