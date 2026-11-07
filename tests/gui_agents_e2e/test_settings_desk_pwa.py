"""AG-SD-01…12 and AG-BK-01…07 — the Service Desk app's ⚙︎ Settings → 🤖 Agent card, field by field, on the Solo
sandbox (the owner is the one using the app; on a server this tab isn't shown — test_settings_server_readonly.py).

Every field: the value is typed / picked in the browser, saved with the card's own button, and then
  * the server's stored value is checked (GET /desk-api/agent), and
  * refused values show a message and leave the stored value as it was.
Known differences from the spec are marked xfail(strict=True) with the finding — they turn into failures the day
the app is changed, so the mark can't go stale.
"""
from __future__ import annotations

import pytest
from PIL import Image

from conftest import HUMAN

DEFAULTS = {"agent_enabled": True, "agent_shadow": True, "agent_provider": "claude_api", "agent_name": "",
            "agent_label": "Virtual assistant", "agent_reply_signoff": "", "agent_hours": [0, 24],
            "agent_monthly_budget_usd": 20, "agent_wait_hours": 4, "agent_include_service_link": False,
            "agent_bk_enabled": False, "agent_bk_shadow": True, "agent_bk_can_confirm": False,
            "agent_bk_confirm_per_day": 5, "agent_bk_check_hour": 16, "agent_bk_weather": True,
            **{f"agent_stage_{k}": "suggest" for k in ("intake", "first_reply", "resolution", "follow_through", "learn")},
            **{f"agent_bk_stage_{k}": "suggest" for k in ("check", "decide", "offer", "reply", "track", "learn")}}


class Card:
    """The 🤖 Agent card in the owner's Service Desk app."""

    def __init__(self, box, person):
        box.settings(desk=DEFAULTS)
        self.box = box
        self.p = person(box, "owner")
        self.page = self.p.page
        self.open()

    def open(self):
        self.p.desk_sign_in()
        self.page.locator("#tabSettings").click()
        self.page.locator("#agentCard").wait_for()
        self.p.pause(600)

    def stored(self, key):
        st, d = self.box.desk("GET", "/agent")
        assert st == 200, d
        return d["settings"][key]

    def toast(self, text):
        self.page.locator("#toast", has_text=text).first.wait_for(state="visible", timeout=10_000)
        self.page.wait_for_timeout(300 if not HUMAN else 900)

    def type(self, sel, value):
        loc = self.page.locator(sel)
        loc.scroll_into_view_if_needed()
        self.p.type(sel, value)

    def save(self, button="#agSave"):
        self.page.locator(button).scroll_into_view_if_needed()
        self.page.locator(button).click()

    def pick(self, key, value, attr="data-ag"):
        sel = self.page.locator(f"#agentCard select[{attr}='{key}']")
        sel.scroll_into_view_if_needed()
        sel.select_option(value)
        self.toast("Saved.")

    def tick(self, key, attr="data-agb"):
        box = self.page.locator(f"#agentCard input[{attr}='{key}']")
        box.scroll_into_view_if_needed()
        box.click()
        self.toast("Saved.")


@pytest.fixture
def card(solo, person):
    return Card(solo, person)


# ── AG-SD-01 / 02 / 12: the switches ─────────────────────────────────────────
def test_sd_01_02_12_switches(card):
    for key in ("agent_enabled", "agent_shadow", "agent_include_service_link"):
        before = card.stored(key)
        card.tick(key)
        assert card.stored(key) is (not before), key
        card.tick(key)
        assert card.stored(key) is before, key


def test_sd_01_agent_tab_follows_agent_on(card):
    assert card.page.locator("#tabAgent").is_visible()             # on (DEFAULTS) → the 🤖 tab shows
    card.tick("agent_enabled")                                      # off
    card.open()
    assert not card.page.locator("#tabAgent").is_visible()         # nothing waiting → no tab
    card.tick("agent_enabled")


# ── AG-SD-03: which AI runs it ───────────────────────────────────────────────
def test_sd_03_runner(card):
    for v in ("grok_api", "claude_api"):
        card.pick("agent_provider", v)
        assert card.stored("agent_provider") == v
    st, d = card.box.desk("POST", "/settings", {"key": "agent_provider", "value": "claude_code"})
    assert st == 400 and card.stored("agent_provider") == "claude_api", d      # the removed Claude CLI runner
    st, d = card.box.desk("POST", "/settings", {"key": "agent_provider", "value": "chat_only"})
    assert st == 400 and card.stored("agent_provider") == "claude_api", d      # Chat isn't a runner


# ── AG-SD-04: the five stages × Off / Suggest / Auto, and the diagram follows ──
@pytest.mark.parametrize("stage", ["intake", "first_reply", "resolution", "follow_through", "learn"])
def test_sd_04_stage_modes(card, stage):
    card.tick("agent_shadow")                                       # practice off — the diagram shows the mode
    for mode in ("off", "auto", "suggest"):
        card.pick(f"agent_stage_{stage}", mode)
        assert card.stored(f"agent_stage_{stage}") == mode
        step = card.page.locator(f"#agFlow [data-step='{stage}']")
        step.wait_for()
        assert step.get_attribute("data-chosen") == mode, (stage, mode)
    card.tick("agent_shadow")


# ── AG-SD-05: name ───────────────────────────────────────────────────────────
def test_sd_05_name(card):
    for good in ("Sam", "O'Brien-Lee", "Dr. Sam Wise", "A" * 40, ""):
        card.type("#agName", good)
        card.save()
        card.toast("Saved.")
        assert card.stored("agent_name") == good
    card.type("#agName", "B" * 45)                                  # the box stops at 40
    assert len(card.page.locator("#agName").input_value()) == 40
    card.type("#agName", "Sam")
    card.save()
    card.toast("Saved.")
    for bad in ("Sam2", "-Sam", "Sam!", "Sam<b>"):
        card.type("#agName", bad)
        card.save()
        card.toast("letters")
        assert card.stored("agent_name") == "Sam", bad
    st, d = card.box.desk("POST", "/settings", {"key": "agent_name", "value": "C" * 41})
    assert st == 400 and "40" in str(d), d


# ── AG-SD-06: shown as ───────────────────────────────────────────────────────
def test_sd_06_label(card):
    for v in ("AI assistant", "Digital assistant", "Virtual assistant"):
        card.pick("agent_label", v)
        assert card.stored("agent_label") == v
        assert v in card.page.locator("#agDisplay").inner_text()
    st, d = card.box.desk("POST", "/settings", {"key": "agent_label", "value": "Sales manager"})
    assert st == 400, d                                             # never free text — customers must see "assistant"


# ── AG-SD-07: photo ──────────────────────────────────────────────────────────
def test_sd_07_photo(card, tmp_path):
    good = []
    for fmt, ext in (("PNG", "png"), ("JPEG", "jpg"), ("WEBP", "webp")):
        f = tmp_path / f"zag_photo.{ext}"
        Image.new("RGB", (600, 400), (40, 120, 200)).save(f, fmt)
        good.append(f)
    for f in good:
        card.page.locator("#agPhoto").set_input_files(str(f))
        card.toast("Photo saved.")
        assert card.stored("agent_photo") == "agent/avatar.jpg", f.name
        card.page.locator("#agPic img").wait_for()
    card.page.locator("#agPhotoDel").click()
    card.toast("Photo removed.")
    assert card.stored("agent_photo") == ""
    fake = tmp_path / "not_a_picture.jpg"
    fake.write_text("ZAG this is text, not a picture", encoding="utf-8")
    card.page.locator("#agPhoto").set_input_files(str(fake))
    card.toast("isn't a picture")
    empty = tmp_path / "empty.jpg"
    empty.write_bytes(b"")
    card.page.locator("#agPhoto").set_input_files(str(empty))
    card.toast("empty")
    big = tmp_path / "too_big.jpg"
    big.write_bytes(b"\xff\xd8\xff" + b"0" * (8 * 1024 * 1024))    # 8 MB + 3 bytes
    card.page.locator("#agPhoto").set_input_files(str(big))
    card.toast("too big")
    assert card.stored("agent_photo") == ""


# ── AG-SD-08: sign-off ───────────────────────────────────────────────────────
def test_sd_08_signoff(card):
    for good in ("— Sam, ZAG Blue Wave", "S" * 80, ""):
        card.type("#agSignoff", good)
        card.save()
        card.toast("Saved.")
        assert card.stored("agent_reply_signoff") == good
    card.type("#agSignoff", "T" * 85)                               # the box stops at 80
    assert len(card.page.locator("#agSignoff").input_value()) == 80
    st, d = card.box.desk("POST", "/settings", {"key": "agent_reply_signoff", "value": "U" * 81})
    assert st == 400, d


# ── AG-SD-09: working hours ──────────────────────────────────────────────────
def test_sd_09_hours(card):
    for h0, h1 in ((9, 17), (23, 24), (0, 24)):
        card.type("#agH0", h0)
        card.type("#agH1", h1)
        card.save()
        card.toast("Saved.")
        assert card.stored("agent_hours") == [h0, h1]
    for h0, h1 in ((17, 9), (5, 5), (24, 24), (-1, 10), (8, 25)):
        card.type("#agH0", h0)
        card.type("#agH1", h1)
        card.save()
        card.toast("start before end")
        assert card.stored("agent_hours") == [0, 24], (h0, h1)


# ── AG-SD-10 / 11: budget and the customer-waits nudge ───────────────────────
def test_sd_10_budget_edges(card):
    for good in (0, 10000, 20):
        card.type("#agBudget", good)
        card.save()
        card.toast("Saved.")
        assert card.stored("agent_monthly_budget_usd") == good
    card.type("#agBudget", 10001)
    card.save()
    card.toast("between")
    assert card.stored("agent_monthly_budget_usd") == 20


def test_sd_10_budget_bad_input_refused(card):
    """F-1, fixed 2026-11-03: -1 or letters used to be saved as $0."""
    card.type("#agBudget", -1)
    card.save()
    card.page.wait_for_timeout(1500)
    assert card.stored("agent_monthly_budget_usd") == 20


def test_sd_11_wait_hours_edges(card):
    for good in (1, 168, 4):
        card.type("#agWait", good)
        card.save()
        card.toast("Saved.")
        assert card.stored("agent_wait_hours") == good
    card.type("#agWait", 169)
    card.save()
    card.toast("between")
    assert card.stored("agent_wait_hours") == 4


def test_sd_11_wait_zero_refused(card):
    """F-2, fixed 2026-11-03: a wait of 0 used to be saved as 4."""
    card.type("#agWait", 7)
    card.save()
    card.toast("Saved.")
    card.type("#agWait", 0)
    card.save()
    card.page.wait_for_timeout(1500)
    assert card.stored("agent_wait_hours") == 7


# ── AG-BK-01…07: Booking & scheduling ────────────────────────────────────────
def test_bk_01_02_04_06_switches(card):
    for key in ("agent_bk_enabled", "agent_bk_shadow", "agent_bk_can_confirm", "agent_bk_weather"):
        before = card.stored(key)
        card.tick(key)
        assert card.stored(key) is (not before), key
        card.tick(key)
        assert card.stored(key) is before, key


@pytest.mark.parametrize("stage", ["check", "decide", "offer", "reply", "track", "learn"])
def test_bk_03_stage_modes(card, stage):
    card.tick("agent_bk_enabled")
    card.tick("agent_bk_shadow")
    for mode in ("off", "auto", "suggest"):
        card.pick(f"agent_bk_stage_{stage}", mode)
        assert card.stored(f"agent_bk_stage_{stage}") == mode
        step = card.page.locator(f"#bkFlow [data-step='{stage}']")
        step.wait_for()
        assert step.get_attribute("data-chosen") == mode, (stage, mode)


def test_bk_05_07_per_day_and_check_hour(card):
    for per, hour in ((1, 0), (50, 23), (5, 16)):
        card.type("#bkPerDay", per)
        card.type("#bkCheckHour", hour)
        card.save("#bkSaveBooking")
        card.toast("Saved.")
        assert (card.stored("agent_bk_confirm_per_day"), card.stored("agent_bk_check_hour")) == (per, hour)
    for per, msg in ((0, "1 to 50"), (51, "1 to 50")):
        card.type("#bkPerDay", per)
        card.type("#bkCheckHour", 16)
        card.save("#bkSaveBooking")
        card.toast(msg)
    for hour in (-1, 24):
        card.type("#bkPerDay", 5)
        card.type("#bkCheckHour", hour)
        card.save("#bkSaveBooking")
        card.toast("0 to 23")
    assert (card.stored("agent_bk_confirm_per_day"), card.stored("agent_bk_check_hour")) == (5, 16)


def test_bk_01_needs_agent_on(solo):
    """AG-BK-01 / X-02: Booking on with Agent off queues nothing for bookings."""
    solo.settings(desk={**DEFAULTS, "agent_enabled": False, "agent_bk_enabled": True, "agent_provider": "claude_api",
                        "portal_enabled": True, "staff_booking": True, "booking_paths": ["book", "new", "problem"]})
    solo.ai_reset()
    st, d = solo.desk("POST", "/book", {"path": "new", "name": "ZAG BK01", "phone": "386-555-0161",
                                        "address": {"street": "1 Canal St", "city": "New Smyrna Beach", "state": "FL",
                                                    "zip": "32168"}, "service": "Gutter cleaning", "notify": False})
    assert st in (200, 201), d
    solo.agents_pass()
    assert not [c for c in solo.ai_calls() if c["kind"] == "booking"]
    solo.settings(desk=DEFAULTS)
