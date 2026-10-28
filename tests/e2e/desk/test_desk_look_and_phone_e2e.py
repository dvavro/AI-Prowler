"""Service Desk E2E — looks like the other AI-Prowler apps, and works on a phone.

David 2026-10-28: "Make sure my app has the refresh, alert the version display
and has the look and feel like the rest of the apps that have the AI prowler
icon at the upper left corner and is usable for cell phones in terms of
scrolling in viewing and entering data for the tickets."

L1  Jobs-app look: AI-Prowler icon top-left, AI-PROWLER brand, who's signed in;
    the version badge is stamped by the server and tapping it says "latest";
    ↻ refresh keeps you on the ticket you're looking at; sign out
L2  The "new version" banner: shows, "Later" hides it until the next tab,
    "Refresh Now" reloads
L3  On phones (Android and iPhone sizes), every screen fits the width (nothing
    to scroll sideways but the Board), every box uses 16px text (iPhones zoom
    in otherwise), buttons are big enough to tap; a long ticket is filled in on
    the phone, scrolled to the bottom to add a note, and saving keeps your place

Run: tests\\run_desk_e2e.py -k test_L
"""
from __future__ import annotations

import re

import pytest

pytestmark = pytest.mark.e2e

TID = re.compile(r"T-\d{4,}")


def _no_sideways_scroll(p, where):
    w = p.page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
    assert w[0] <= w[1] + 1, f"{where}: page is {w[0]}px wide on a {w[1]}px screen (scrolls sideways)"


def _boxes_ok(p, where):
    bad = p.page.evaluate("""() => [...document.querySelectorAll('input,select,textarea')]
        .filter(e => e.offsetParent && e.type !== 'checkbox' && e.type !== 'file')
        .filter(e => parseFloat(getComputedStyle(e).fontSize) < 16)
        .map(e => e.id || e.name || e.outerHTML.slice(0, 60))""")
    assert not bad, f"{where}: boxes under 16px text (iPhone zooms in): {bad}"
    small = p.page.evaluate("""() => [...document.querySelectorAll('button.b, .ibtn, .tab')]
        .filter(e => e.offsetParent)
        .filter(e => e.getBoundingClientRect().height < 34)
        .map(e => (e.id || e.textContent.trim()).slice(0, 30))""")
    assert not small, f"{where}: buttons too small to tap: {small}"


def test_L1_looks_like_the_other_apps(business, people):
    o = people(business, "Olive (owner, phone)", phone=True)
    o.page.goto(f"{business.base}/desk/")
    # sign-in screen = the Jobs app's: logo, password box with 👁️, blue Unlock (David 2026-10-28)
    o.page.locator("#authScreen .auth-logo").wait_for()
    assert o.page.evaluate("document.querySelector('.auth-logo').naturalWidth") > 0, "logo didn't load"
    assert o.page.locator("header").is_hidden(), "the app's top bar shows on the sign-in screen"
    assert "Unlock" in o.page.locator("#lgGo").inner_text()
    o.type("#lgTok", "abc123")
    assert o.page.locator("#lgTok").get_attribute("type") == "password"
    o.click("#lgEye")
    assert o.page.locator("#lgTok").get_attribute("type") == "text", "the eye didn't show the password"
    o.click("#lgEye")
    assert o.page.locator("#lgTok").get_attribute("type") == "password"
    o.type("#lgName", "Olive Owner")
    o.click("#lgGo")                                          # wrong password → says so under the button
    o.page.locator("#lgErr:not(.hide)").wait_for()
    assert "invalid" in (o.page.locator("#lgTok").get_attribute("class") or "")
    # version badge, stamped by the server, tap → latest
    badge = o.page.locator("#apPwaVer")
    assert re.match(r"v\d+\.\d+\.\d+ · [0-9a-f]{6}$", badge.inner_text()), badge.inner_text()
    badge.click()
    o.page.locator("#apPwaVer.ok", has_text="latest").wait_for()
    o.sign_in("Olive Owner")
    # icon top-left, loaded
    icon = o.page.locator(".brand-icon img")
    icon.wait_for()
    assert o.page.evaluate("document.querySelector('.brand-icon img').naturalWidth") > 0, "icon didn't load"
    box = icon.bounding_box()
    assert box["x"] < 40 and box["y"] < 90, f"icon isn't at the upper left: {box}"
    assert o.page.locator(".brand-name").inner_text() == "AI-PROWLER"
    assert o.page.title() == "AI-Prowler Service Desk"
    # signed in: who, refresh, sign out
    assert "Olive Owner" in o.page.locator(".brand-role").inner_text()
    st, d = business.api("POST", "/desk-api/tickets", {"kind": "internal", "title": "ZTEST L1 refresh me"},
                         name="Olive Owner")
    tid = d["ticket"]["ticket_id"]
    o.tab("open")
    o.open_ticket(tid)
    business.api("POST", f"/desk-api/tickets/{tid}/messages", {"body": "ZTEST L1 note from the PC",
                                                              "visibility": "internal"}, name="Olive Owner")
    o.click("#refreshBtn")                                   # ↻ — same ticket, now with the new note
    o.page.locator(".msg", has_text="ZTEST L1 note from the PC").wait_for()
    assert o.page.locator("#back").count() == 1, "refresh left the ticket"
    o.answer(True)
    o.click("#signOutBtn")
    o.page.locator("#lgGo").wait_for()
    assert o.page.locator("#refreshBtn").is_hidden()


def test_L2_new_version_banner(business, people):
    o = people(business, "Olive (owner)")
    o.sign_in("Olive Owner")
    o.page.evaluate("showUpdateBanner()")                    # what a new sw.js triggers
    o.page.locator("#updateBanner.show").wait_for()
    o.click("#updLater")
    o.page.locator("#updateBanner.show").wait_for(state="detached")
    o.tab("open")                                            # "Later" = until the next tab
    o.page.locator("#updateBanner.show").wait_for()
    o.page.evaluate("window.__beforeReload = 1")
    o.click("#updNow")
    o.page.wait_for_function("window.__beforeReload === undefined")
    o.page.locator("#tabs").wait_for()                       # still signed in after the reload


def test_L4_cards_show_how_long_each_ticket_has_waited(business, people):
    """David 2026-10-28: show how long each open ticket has been waiting on the
    list cards — red once it's past its due date; Fixed/Closed show none."""
    import datetime
    mk = lambda title, pri: business.api("POST", "/desk-api/tickets", {"kind": "internal", "title": title,  # noqa: E731
                                                                     "priority": pri}, name="Olive Owner")[1]["ticket"]
    urgent, normal = mk("ZTEST L4 urgent leak", "P1"), mk("ZTEST L4 order squeegees", "P4")
    done = mk("ZTEST L4 already fixed", "P3")
    cris = business.api("GET", "/desk-api/me", name="Cris Crew")[1]["actor"]["id"]
    st, d = business.api("POST", f"/desk-api/tickets/{done['ticket_id']}/assign", {"assignee": cris}, name="Olive Owner")
    assert st == 200, d
    st, d = business.api("POST", f"/desk-api/tickets/{done['ticket_id']}/state", {"to_state": "Fixed"}, name="Olive Owner")
    assert st == 200, d
    o = people(business, "Olive (owner, phone)", phone=True)
    # the phone's clock 3 days later: the P1 is now overdue, the P4 isn't yet
    o.page.clock.install(time=datetime.datetime.now() + datetime.timedelta(days=3, hours=1))
    o.sign_in("Olive Owner")
    o.tab("open")

    def chip(tid):
        c = o.page.locator(f"[data-open='{tid}'] .chip.wait")
        return c.inner_text() if c.count() else "", (c.get_attribute("class") or "") if c.count() else ""

    o.page.locator(f"[data-open='{urgent['ticket_id']}']").wait_for()
    text, cls = chip(urgent["ticket_id"])
    assert text == "⏱ waiting 3d" and "late" in cls, (text, cls)
    text, cls = chip(normal["ticket_id"])
    assert text == "⏱ waiting 3d" and "late" not in cls, (text, cls)
    o.tab("board")                                           # the board's cards show it too
    o.page.locator(f".board [data-open='{urgent['ticket_id']}'] .chip.wait").wait_for()
    assert o.page.locator(f".board [data-open='{done['ticket_id']}'] .chip.wait").count() == 0, \
        "a Fixed ticket isn't waiting on anyone"


@pytest.mark.parametrize("phone", [False, True], ids=["desktop", "phone"])
def test_L5_settings_buttons_keep_their_words_inside(business, people, phone):
    """David 2026-10-28 (screenshot): "Save" and "Undo import" in Settings spilled
    out of their buttons. Every button's words must fit inside it."""
    o = people(business, "Olive (owner)" + (", phone" if phone else ""), phone=phone)
    o.sign_in("Olive Owner")
    o.tab("settings")
    o.page.locator("#undoGo").wait_for()
    spill = o.page.evaluate("""() => [...document.querySelectorAll('#app button')]
        .filter(b => b.offsetParent && b.scrollWidth > b.clientWidth + 1)
        .map(b => (b.id || b.textContent.trim()).slice(0, 30))""")
    assert not spill, f"words spill out of these buttons: {spill}"
    for sel in ("#acSave", "#undoGo"):
        bb, box = o.page.locator(sel).bounding_box(), o.page.locator(sel).locator("xpath=..").bounding_box()
        assert bb["width"] >= 60 and bb["x"] + bb["width"] <= box["x"] + box["width"] + 1, (sel, bb, box)


@pytest.mark.parametrize("device", ["Pixel 7", "iPhone 13"])
def test_L3_phone_scrolling_and_data_entry(business, browser, pw, device):
    from conftest import Person
    p = Person(browser, pw, business, f"Sam (staff, {device})", phone=True)
    try:
        if device != "Pixel 7":                              # Person() uses Pixel 7; swap the device
            p.ctx.close()
            p.ctx = browser.new_context(**pw.devices[device])
            p.page = p.ctx.new_page()
            p.page.set_default_timeout(15000)
            p.page.on("dialog", p._on_dialog)
        p.page.goto(f"{business.base}/desk/")
        p.page.locator("#lgGo").wait_for()
        _no_sideways_scroll(p, "sign-in"); _boxes_ok(p, "sign-in")
        p.sign_in("Sam Staff")
        _no_sideways_scroll(p, "my tickets")
        # ── fill in a long ticket on the phone ──
        p.click("#fab")
        _no_sideways_scroll(p, "new ticket"); _boxes_ok(p, "new ticket")
        p.page.select_option("#nKind", "external")
        p.type("#nTitle", "ZTEST L3 " + device + " — water heater pilot keeps going out after storms")
        long = ("Customer says it happens every time the wind picks up. " * 12).strip()
        p.page.fill("#nDesc", long)
        p.type("#nName", "ZTEST Ms Ortega")
        p.type("#nPhone", "555-010-0703")
        p.type("#nEmail", "ortega@example.test")
        p.page.locator("#nGo").scroll_into_view_if_needed()
        p.click("#nGo")
        p.toast("Filed")
        tid = TID.search(p.page.locator("#toast").inner_text()).group(0)
        p.page.locator("#back").wait_for()
        _no_sideways_scroll(p, "ticket page"); _boxes_ok(p, "ticket page")
        # ── scroll to the bottom and add a note ──
        p.page.locator("#msg").scroll_into_view_if_needed()
        y_before = p.page.evaluate("window.scrollY")
        assert y_before > 200, "the long ticket should need scrolling on a phone"
        p.type("#msg", "ZTEST L3 checked the thermocouple, ordering a new one")
        p.click("#msgGo")
        p.page.locator(".msg", has_text="ordering a new one").wait_for()
        y_after = p.page.evaluate("window.scrollY")
        assert abs(y_after - y_before) < 400, f"saving jumped the page from {y_before} to {y_after}"
        # ── the board scrolls inside itself, the page doesn't ──
        p.click("#back")
        p.tab("board")
        p.page.locator(".board").wait_for()
        _no_sideways_scroll(p, "board")
        assert p.page.evaluate("(b => b.scrollWidth > b.clientWidth)(document.querySelector('.board'))"), \
            "board columns should scroll sideways inside the board"
        # ── the tabs row scrolls sideways on its own too ──
        _no_sideways_scroll(p, "tabs")
        st, d = business.api("GET", f"/desk-api/tickets/{tid}", name="Olive Owner")
        assert any("thermocouple" in m["body"] for m in d["ticket"]["messages"])
    finally:
        p.close()
