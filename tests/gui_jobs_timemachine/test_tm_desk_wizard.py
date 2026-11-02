"""Service Desk 🧙 "How tickets move" wizard, watched in a real browser (2026-10-29).

David 2026-10-29: a wizard icon top-right in the Desk app that demonstrates the
ticket flow and the state machine diagram; a human-mode browser test that
opens it and steps through it.

Runs in the time machine's throwaway server (never real data):
    run_tests_gui_jobs_e2e.bat --timemachine --human -k SDW_            (Solo)
    run_tests_gui_jobs_e2e.bat --server --timemachine --human -k SDW_   (Business)

  SDW_01  the 🧙 button is top-right; the Diagram draws 6 states and every move,
          dashed where a reason is needed; tapping each state lists its moves and
          who may make them; this edition's rules first, the other one on a tap
  SDW_02  the Walkthrough follows one sample ticket Open → … → Fixed → the
          customer confirms and rates → Closed, the current state lit up at each
          step, Back and Next, Finish closes it
  SDW_03  on a phone, with the network OFF: it still opens and steps through,
          and nothing spills off the screen
  SDW_04  (Business) a field-crew member has the button too
  SDW_05  📨 How to file: the customer request form, the app for the owner (Solo) or
          the whole team (Business), who may open which kind (2026-10-29)
  SDW_99  demo only: no ticket was created or changed, and the wizard sent nothing
"""
from __future__ import annotations

import json
import logging
import os

import pytest

MODE = (os.environ.get("E2E_TM_MODE") or "personal").strip().lower()
THINK_MS = int(os.environ.get("E2E_THINK_MS") or 0)          # --human: a pause after each step
ED = "business" if MODE == "server" else "solo"
OTHER = "solo" if ED == "business" else "business"

STATES = ["Open", "Assigned", "In Progress", "On Hold", "Fixed", "Closed"]
WALK = ["Open", "Assigned", "In Progress", "On Hold", "In Progress", "Fixed", "Closed", "Closed"]

_e2e_log = logging.getLogger("e2e")
S: dict = {"ok": [], "writes": []}


def _log(msg: str):
    _e2e_log.info(f"[SDW] {msg}")


@pytest.fixture(autouse=True)
def _in_order(browser_name):
    """Keep the tests in file order (same fix as test_tm_service_desk.py)."""
    yield


def _need(*steps):
    missing = [s for s in steps if s not in S["ok"]]
    if missing:
        pytest.skip(f"needs earlier step(s) {missing}")


def _tickets(tm) -> list:
    st, d = tm.desk("GET", "/tickets?open_only=0&limit=1000")
    assert st == 200, (st, d)
    return sorted((t["ticket_id"], t.get("state"), t.get("version")) for t in d["tickets"])


class Wiz:
    """The Service Desk app, used the way a person does, around the 🧙 wizard."""

    def __init__(self, page, tm, key="owner"):
        self.page, self.tm = page, tm
        tok = tm.desk_token(key, fresh=True)
        page.add_init_script("try{sessionStorage.setItem('desk_token'," + json.dumps(tok) + ")}catch(e){}")
        # anything the page sends that would change data (the wizard must send nothing)
        page.on("request", lambda q: S["writes"].append(f"{q.method} {q.url}")
                if "/desk-api" in q.url and q.method != "GET" else None)
        _log(f"browser: Service Desk as {key} ({ED})")

    def think(self):
        if THINK_MS:
            self.page.wait_for_timeout(THINK_MS)

    def click(self, sel):
        self.page.locator(sel).first.click()
        self.think()

    def open_app(self):
        self.page.goto(self.tm.origin + "/desk/")
        self.page.locator("#tabs").wait_for(state="visible")
        self.think()
        return self

    def open_wizard(self):
        self.click("#wizBtn")
        self.page.locator("#wiz.show").wait_for(state="visible")
        self.page.locator("#wzSvg").wait_for()
        return self

    def rules(self) -> dict:
        return self.page.evaluate("JSON.parse(document.getElementById('wizRules').textContent)")

    def text(self, sel) -> str:
        return self.page.locator(sel).first.inner_text().strip()


# ══════════════════════════════════════════════════════════════════════════════
def test_SDW_01_button_opens_the_state_diagram(tm, page):
    S["before"] = _tickets(tm)
    w = Wiz(page, tm).open_app()
    page.set_viewport_size({"width": 1280, "height": 900})

    # the button: in the top bar, right-hand side, next to ↻ refresh
    btn = page.locator("header .topbar #wizBtn")
    assert btn.is_visible()
    box, ref = btn.bounding_box(), page.locator("#refreshBtn").bounding_box()
    assert box["x"] > 1280 / 2, "the 🧙 button should sit on the right of the top bar"
    assert abs(box["y"] - ref["y"]) < 4 and abs(box["x"] + box["width"] - ref["x"]) < 20, "next to ↻"

    w.open_wizard()
    assert page.locator(f"#wz_ed_{ED}.on").is_visible(), f"opens on this install's edition ({ED})"
    assert "yours" in w.text(f"#wz_ed_{ED}")
    assert page.locator("#wzSvg g.wz-n").count() == 6
    R = w.rules()
    n_moves = sum(len(v) for v in R["transitions"].values())
    assert page.locator("#wzSvg path.wz-e").count() == n_moves == 16
    assert page.locator("#wzSvg path.wz-e.why").count() == len(R["needs_reason"]) == 8
    _log(f"diagram: 6 states, {n_moves} arrows, 8 need a reason")

    def check(ed):
        for s in STATES:
            w.click(f"#wzSvg g[data-state='{s}']")
            assert w.text("#wzInfo h3") == s
            assert page.locator(f"#wzSvg g.sel[data-state='{s}']").count() == 1, f"{s} is lit up"
            mv = page.locator("#wzInfo .wz-mv")
            assert mv.count() == len(R["transitions"][s]), s
            for i, to in enumerate(R["transitions"][s]):
                row = mv.nth(i)
                assert row.get_attribute("data-to") == to
                needs = [s, to] in R["needs_reason"]
                assert (row.locator(".wz-why").count() == 1) == needs, f"{s}→{to} reason mark"
        # each edition's own people
        w.click("#wzSvg g[data-state='Fixed']")
        who_close = w.text("#wzInfo .wz-mv[data-to='Closed'] .wz-who")
        if ed == "solo":
            assert "You (owner)" in who_close and "Customer" in who_close and "Manager" not in who_close, who_close
        else:
            assert "Manager" in who_close and "Customer" in who_close and "Field crew" not in who_close, who_close
            w.click("#wzSvg g[data-state='In Progress']")
            assert "Field crew" in w.text("#wzInfo .wz-mv[data-to='Fixed'] .wz-who")

    check(ED)
    w.click(f"#wz_ed_{OTHER}")                      # the other edition's rules
    assert page.locator(f"#wz_ed_{OTHER}.on").is_visible()
    check(OTHER)
    w.click(f"#wz_ed_{ED}")

    page.keyboard.press("Escape")                   # Esc closes it
    page.locator("#wiz").wait_for(state="hidden")
    assert page.evaluate("document.activeElement.id") == "wizBtn"
    S["ok"].append("diagram")


def test_SDW_02_walkthrough_follows_one_ticket_to_closed(tm, page):
    _need("diagram")
    w = Wiz(page, tm).open_app().open_wizard()
    w.click("#wz_tab_walk")
    n = len(WALK)
    for i, state in enumerate(WALK):
        assert w.text("#wzCount") == f"Step {i + 1} of {n}"
        assert w.text("#wzState") == state
        assert page.locator("#wzSvg g.wz-n.cur").get_attribute("data-state") == state, f"step {i + 1} lit up"
        if i and WALK[i] != WALK[i - 1]:
            assert page.locator("#wzSvg path.hot").get_attribute("data-edge") == f"{WALK[i - 1]}>{state}"
        _log(f"walkthrough step {i + 1}: {w.text('#wzStepTitle')} — {state} ({w.text('#wzBy')})")
        if i == 1:
            assert ("Morgan (manager)" if ED == "business" else "You (owner)") in w.text("#wzBy")
        if i == 3:
            assert page.locator("#wzReason").is_visible(), "On Hold shows its reason"
        if i == 6:
            assert "customer" in w.text("#wzBy").lower() and "★" in w.text("#wzStep")
        if i == n - 1:
            assert page.locator("#wzSvg path.hint").get_attribute("data-edge") == "Closed>Assigned"
            break
        w.click("#wzNext")
    # Back works, then Next again
    w.click("#wzPrev")
    assert w.text("#wzCount") == f"Step {n - 1} of {n}"
    w.click("#wzNext")
    assert "Finish" in w.text("#wzNext")
    w.click("#wzNext")
    page.locator("#wiz").wait_for(state="hidden")
    S["ok"].append("walk")


def test_SDW_03_on_a_phone_with_the_network_off(tm, page):
    _need("diagram")
    page.set_viewport_size({"width": 390, "height": 844})
    w = Wiz(page, tm).open_app()
    assert page.locator("#wizBtn").is_visible()
    page.context.set_offline(True)
    try:
        w.open_wizard()
        assert page.evaluate("document.getElementById('wiz').scrollWidth <= document.getElementById('wiz').clientWidth"), \
            "the wizard fits the phone screen"
        w.click("#wzSvg g[data-state='On Hold']")
        assert w.text("#wzInfo h3") == "On Hold"
        w.click("#wz_tab_walk")
        for _ in range(len(WALK) - 1):
            w.click("#wzNext")
        assert w.text("#wzCount") == f"Step {len(WALK)} of {len(WALK)}"
        w.click("#wzNext")                              # Finish
        page.locator("#wiz").wait_for(state="hidden")
        _log("phone, offline: opened and stepped through")
    finally:
        page.context.set_offline(False)
    S["ok"].append("offline")


BROWSER_USER = {"test_SDW_04_field_crew_has_the_button_too": "alex"}


@pytest.mark.skipif(MODE != "server", reason="Business edition (server mode)")
def test_SDW_04_field_crew_has_the_button_too(tm, page):
    _need("diagram")
    w = Wiz(page, tm, key="alex").open_app().open_wizard()
    assert page.locator("#wz_ed_business.on").is_visible()
    w.click("#wz_tab_walk")
    w.click("#wzNext")
    w.click("#wzNext")
    assert w.text("#wzState") == "In Progress" and "Alex (field crew)" in w.text("#wzBy")
    w.click("#wzClose")
    page.locator("#wiz").wait_for(state="hidden")


def test_SDW_05_how_to_file_shows_every_way_in(tm, page):
    """📨 How to file: the customer request form, the app for the owner (Solo)
    or the whole team (Business), and who may open which kind of ticket."""
    _need("diagram")
    w = Wiz(page, tm).open_app().open_wizard()
    w.click("#wz_tab_file")
    page.locator("#wzFile").wait_for()
    R = w.rules()
    # the sandbox runs on 127.0.0.1 — the page points to the Business tab for the real link
    sup, desk = w.text("#wzUrlSupport"), w.text("#wzUrlDesk")
    assert "/support/new" in sup and "Business tab" in sup, sup
    assert "/desk/" in desk, desk
    assert "Service Request Link" in w.text("#wzFileCust"), "points to the invoice/receipt setting"
    if ED == "solo":
        assert "You (owner)" in w.text("#wzFileTeam h3")
        assert page.locator("#wzFileStaff").is_visible(), "Solo explains helpers/employees"
    else:
        assert "team" in w.text("#wzFileTeam h3").lower()
        assert page.locator("#wzFileStaff").count() == 0
    rows = page.locator("#wzFileWho .wz-mv")
    assert rows.count() == 3
    for i, kind in enumerate(["external", "internal", "subcontractor"]):
        who = rows.nth(i).locator(".wz-who").inner_text()
        assert ("You (owner)" if ED == "solo" else "Owner") in who, (kind, who)
        if ED == "business":
            for name in ("Manager", "Staff", "Field crew"):
                assert name in who, (kind, who)
        assert len(R["create"][ED][kind]) == who.count(",") + 1, (kind, who)
    assert "Customer request" in w.text("#wzMine"), "the signed-in person's own kinds"
    _log(f"how to file ({ED}): {w.text('#wzMine')}")
    w.click(f"#wz_ed_{OTHER}")                      # the other edition's version
    assert ("team" in w.text("#wzFileTeam h3").lower()) == (OTHER == "business")
    w.click("#wzClose")
    page.locator("#wiz").wait_for(state="hidden")
    S["ok"].append("file")


def test_SDW_99_demo_only_nothing_changed(tm):
    _need("diagram")
    assert not S["writes"], f"the wizard sent changes to the server: {S['writes'][:5]}"
    after = _tickets(tm)
    assert after == S["before"], "a ticket was created or changed while using the wizard"
    _log(f"demo only: {len(after)} ticket(s) before and after, no writes sent")
