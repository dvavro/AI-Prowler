"""Server mode — SRV-SCR-05 (spec §6.11.5), Board and Calendar per role.

(The Jobs list part of SRV-SCR-05 is test_srv_crew.py · SRV_CREW_01.)

Setup (owner): one ZTEST job with Crew = Samual, one with Crew = Vicki, both on
the sandbox date. For each user:
  owner (David) / manager (Vicki)  → both jobs on the Board and the Calendar
  field_crew (Samual)              → only his own; Vicki's is absent
The Board's live-update feed (get_board_updates, polled every ~60 s) is a
separate read path from the Board's first load, so it's checked directly too,
through the user's own session.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_board_calendar
"""
import re

import pytest
from playwright.sync_api import expect

from safety import SANDBOX_DATE

CREW = "Samual Cronin"
OTHER = "Vicki Vavro"
SEES_ALL = {"U1": True, "U2": True, "U3": False}     # owner, manager: everything · field_crew: own only


def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


def _board_card(page, jid):
    return page.locator("#boardColumns .board-card").filter(
        has=page.locator(".board-card-id", has_text=re.compile(rf"^\s*{re.escape(jid)}\s*$")))


def _cal_chip(page, jid):
    return page.locator(f"#calendarContent .cal-job-chip[onclick*=\"'{jid}'\"]")


@pytest.fixture
def crew_jobs(clean_slate, data):
    return {"mine": data.job("SCR05 Samual", **{"Crew / Technician": CREW}),
            "theirs": data.job("SCR05 Vicki", "brannon", **{"Crew / Technician": OTHER})}


@pytest.mark.parametrize("key", ["U1", "U2", "U3"])
def test_SRV_SCR_05_board_and_calendar_per_role(windows, crew_jobs, key):
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    page, all_ = w.page, SEES_ALL[key]
    mine, theirs = crew_jobs["mine"], crew_jobs["theirs"]

    # ── Board ──
    w.app.goto("board")
    page.locator("#refreshBoardBtn").click()
    expect(page.locator("#boardColumns .loader")).to_have_count(0, timeout=20_000)
    expect(_board_card(page, mine)).to_have_count(1, timeout=20_000)     # everyone sees Samual's job
    page.wait_for_timeout(1000)
    n_theirs = _board_card(page, theirs).count()
    w.app.log(f"{key} Board: Samual's job shown, Vicki's job shown {n_theirs}x")
    if all_:
        assert n_theirs == 1, f"{key} ({w.user.name}) can't see Vicki's job on the Board"
    else:
        assert n_theirs == 0, f"field crew's Board shows another crew's job ({theirs})"

    # ── Board live-update feed, through this user's own session ──
    feed = str(w.app.mcp("get_board_updates", {"since": "2000-01-01T00:00:00", "sheet_name": "Jobs_Schedule"}))
    assert mine in feed, f"{key} Board feed is missing Samual's job: {feed[:200]!r}"
    assert (theirs in feed) == all_, (f"{key} Board feed {'is missing' if all_ else 'leaks'} "
                                     f"Vicki's job: {feed[:200]!r}")

    # ── Calendar ──
    w.app.goto("calendar")
    expect(page.locator("#refreshCalBtn")).to_be_enabled(timeout=30_000)
    expect(_cal_chip(page, mine).first).to_be_visible(timeout=30_000)
    page.wait_for_timeout(1000)
    n_theirs = _cal_chip(page, theirs).count()
    w.app.log(f"{key} Calendar ({SANDBOX_DATE}): Samual's job shown, Vicki's job chips {n_theirs}")
    if all_:
        assert n_theirs >= 1, f"{key} ({w.user.name}) can't see Vicki's job on the Calendar"
    else:
        assert n_theirs == 0, f"field crew's Calendar shows another crew's job ({theirs})"
