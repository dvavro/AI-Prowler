"""Server mode — screens by role, part 2 (spec §6.11.5 SRV-SCR-06/07/09),
with the G-02 evidence (SRV-SCOPE-06/07): does field crew get unfiltered
Route_Planner / TimeLog data?

U1 David (owner) · U3 Samual (field_crew). Test jobs (owner-made): one with
Crew = Samual, one with Crew = Vicki, on today's sandbox date.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_screens
"""
import json

import pytest
from playwright.sync_api import expect

from safety import SANDBOX_DATE

CREW = "Samual Cronin"
OTHER = "Vicki Vavro"


def _rows(text):
    """read_job_spreadsheet prints each row as a block of '  Field: value'
    lines separated by blank lines. Return one dict per row."""
    rows, cur = [], {}
    for line in str(text).splitlines():
        s = line.strip()
        if not s or s.startswith("\u2500"):
            if cur:
                rows.append(cur)
                cur = {}
            continue
        if line.startswith("  ") and ": " in s:
            k, v = s.split(": ", 1)
            cur[k.strip()] = v.strip()
    if cur:
        rows.append(cur)
    return rows


def _rows_for(text, jid):
    """Rows whose JobID is exactly jid (so JOB-0001 never matches JOB-00010)."""
    return [r for r in _rows(text) if any(k.startswith("JobID") and v == jid for k, v in r.items())]


def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


@pytest.fixture
def crew_jobs(clean_slate, data):
    mine = data.job("SCR mine", **{"Crew / Technician": CREW, "Est. Duration": 30, "Est. Duration Unit": "min"})
    theirs = data.job("SCR theirs", "brannon", **{"Crew / Technician": OTHER,
                                                  "Est. Duration": 30, "Est. Duration Unit": "min"})
    return {"mine": mine, "theirs": theirs}


# ── SRV-SCR-06 + SRV-SCOPE-07: Route screen / Route_Planner per role ─────────
def test_SRV_SCR_06_route_screen_crew_sees_only_own_route(windows, crew_jobs, owner_api):
    for crew in (CREW, OTHER):
        out = owner_api.call("build_daily_route", {"route_date": SANDBOX_DATE, "crew": crew, "email_link": False})
        assert not str(out).lstrip().startswith("❌"), f"owner couldn't build {crew}'s route: {out[:200]!r}"
    sam, david = windows("U3", "U1")
    sam.log_in()
    david.log_in()
    _signed_in(sam)
    _signed_in(david)
    # what the Route screen reads, through each person's own session
    sam_rp = sam.app.mcp("read_job_spreadsheet", {"sheet_name": "Route_Planner", "max_rows": 500})
    david_rp = david.app.mcp("read_job_spreadsheet", {"sheet_name": "Route_Planner", "max_rows": 500})
    assert crew_jobs["mine"] in david_rp and crew_jobs["theirs"] in david_rp, "owner can't see both routes"
    # the screen itself
    sam.app.goto("route")
    sam.page.locator("#routeDatePicker").select_option(SANDBOX_DATE)
    sam.page.wait_for_timeout(2500)
    stops = sam.page.locator("#routeStopsList").inner_text()
    sam.app.log(f"Samual's Route screen: {stops[:300]!r}")
    assert crew_jobs["mine"] in sam_rp, f"Samual can't see his own route stop: {sam_rp[:200]!r}"
    assert crew_jobs["theirs"] not in sam_rp, \
        "G-02: field crew's Route_Planner read includes ANOTHER crew's stop (Vicki's)"


# ── SRV-SCR-07 + SRV-SCOPE-06: Clock screen / TimeLog per role ───────────────
_CLOCK_STATE_JS = """(sel) => {
  const b = document.querySelector(sel);
  if (!b) return {found: false};
  const r = b.getBoundingClientRect();
  const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
  return {
    found: true, disabled: b.disabled, visible: !!(r.width && r.height),
    rect: [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)],
    covered_by: top && top !== b && !b.contains(top)
        ? (top.id ? '#' + top.id : top.tagName + '.' + top.className) : '',
    active_clock_job: (typeof state !== 'undefined' && state.activeClockJob) || '',   // `const state` isn't on window
    selected_job: (document.getElementById('clockJobSelect') || {}).value || '',
    status_text: (document.getElementById('clockStatusText') || {}).textContent || '',
    clock_result: (document.getElementById('clockResult') || {}).textContent || '',
    toast: (document.getElementById('toast') || {}).textContent || '',
  };
}"""


def _tap_clock_button(w, sel, jid, what):
    """Tap Clock In / Clock Out and wait for the server's answer — or say WHY
    the tap couldn't happen (2026-10-03: SRV-SCR-07 failed twice with a bare
    30 s "waiting for event response" — David's Clock In tap never sent a
    request, and the timeout said nothing about the reason)."""
    btn = w.page.locator(sel)
    try:
        expect(btn).to_be_enabled(timeout=15_000)
    except Exception:
        st = w.page.evaluate(_CLOCK_STATE_JS, sel)
        w.app.log(f"{what}: button not ready — {st}")
        raise AssertionError(f"{w.user.name}'s {what} button isn't usable for {jid}: {st}")
    is_log = lambda r: "/pwa-api" in r.url and "log_time_entry" in (r.request.post_data or "")
    try:
        with w.page.expect_response(is_log, timeout=30_000):
            btn.click(timeout=10_000)
    except Exception as e:
        st = w.page.evaluate(_CLOCK_STATE_JS, sel)
        w.app.log(f"{what}: no clock request sent — {st}")
        raise AssertionError(f"{w.user.name}'s {what} tap sent no request for {jid} "
                             f"({type(e).__name__}): {st}") from e


def _clock(w, jid):
    w.app.goto("jobs")
    w.page.evaluate("async () => { await loadJobs(); }")
    w.app.goto("clock")
    w.page.locator("#clockJobSelect").select_option(jid)
    # 2026-10-03: a job-list refresh landing after the pick used to reset the
    # picker to "— choose a job —" (app bug, fixed in populateSelects), and
    # Clock In then sent nothing. Make that failure say so if it ever returns.
    w.page.wait_for_timeout(1000)
    sel_now = w.page.locator("#clockJobSelect").input_value()
    assert sel_now == jid, (f"{w.user.name}'s Clock job picker was reset after choosing {jid} "
                            f"(now {sel_now!r}) — a job-list refresh wiped the choice")
    _tap_clock_button(w, "#clockInBtn", jid, "Clock In")
    expect(w.page.locator("#clockStatusText")).to_have_text(f"Clocked in: {jid}")
    w.page.wait_for_timeout(1500)
    _tap_clock_button(w, "#clockOutBtn", jid, "Clock Out")
    expect(w.page.locator("#clockStatusText")).to_have_text("Not clocked in")


def test_SRV_SCR_07_clock_entry_is_the_crew_members_own(windows, crew_jobs, owner_api):
    sam, david = windows("U3", "U1")
    sam.log_in()
    david.log_in()
    _signed_in(sam)
    _signed_in(david)
    _clock(sam, crew_jobs["mine"])
    _clock(david, crew_jobs["theirs"])
    everything = owner_api.call("read_job_spreadsheet", {"sheet_name": "TimeLog", "max_rows": 500})
    mine_rows = _rows_for(everything, crew_jobs["mine"])
    theirs_rows = _rows_for(everything, crew_jobs["theirs"])
    assert mine_rows and theirs_rows, f"owner doesn't see both clock entries: {everything[:300]!r}"
    sam.app.log(f"TimeLog row for Samual's clock-in: {mine_rows[0]!r}")
    sam.app.log(f"TimeLog row for David's clock-in: {theirs_rows[0]!r}")
    assert any(CREW in r.values() for r in mine_rows), \
        f"Samual's clock entry isn't under his name: {mine_rows[0]!r}"
    sam_tl = sam.app.mcp("read_job_spreadsheet", {"sheet_name": "TimeLog", "max_rows": 500})
    assert _rows_for(sam_tl, crew_jobs["mine"]), f"Samual can't see his own clock entry: {sam_tl[:200]!r}"
    assert not _rows_for(sam_tl, crew_jobs["theirs"]), \
        "G-02: field crew's TimeLog read includes SOMEONE ELSE's clock entry"


# ── SRV-SCOPE-08 (R-039, was G-01): route tools act only on the crew's own route ──
def test_SRV_SCOPE_08_crew_cannot_build_or_approve_another_crews_route(windows, crew_jobs, owner_api):
    for crew in (CREW, OTHER):
        out = owner_api.call("build_daily_route", {"route_date": SANDBOX_DATE, "crew": crew, "email_link": False})
        assert not str(out).lstrip().startswith("❌"), f"owner couldn't build {crew}'s route: {out[:200]!r}"
    before = _rows_for(owner_api.call("read_job_spreadsheet", {"sheet_name": "Route_Planner", "max_rows": 500}),
                       crew_jobs["theirs"])
    assert before, "owner can't see Vicki's route stop"
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    for tool, args in (
        ("build_daily_route", {"route_date": SANDBOX_DATE, "crew": OTHER, "email_link": False}),
        ("suggest_route_schedule", {"route_date": SANDBOX_DATE, "crew": OTHER}),
        ("approve_route_schedule", {"route_date": SANDBOX_DATE, "crew": OTHER}),
        ("unapprove_route_schedule", {"route_date": SANDBOX_DATE, "crew": OTHER}),
        ("prescreen_route_jobs", {"route_date": SANDBOX_DATE, "crew": OTHER}),
    ):
        out = str(sam.app.mcp(tool, args))
        sam.app.log(f"Samual {tool}(crew={OTHER!r}) -> {out[:160]!r}")
        assert "own route" in out, f"G-01: field crew's {tool} for another crew was not refused: {out[:200]!r}"
    # (Blank crew = the crew's own route is covered by tests\mcp_tests\test_r039_crew_read_scope.py —
    # not repeated live because a real approve re-times jobs.)
    after = _rows_for(owner_api.call("read_job_spreadsheet", {"sheet_name": "Route_Planner", "max_rows": 500}),
                      crew_jobs["theirs"])
    assert after == before, "Vicki's route stop changed after Samual's calls"


# ── SRV-SCR-09: Profile "Code" row (G-09) ─────────────────────────────────────
@pytest.mark.parametrize("key", ["U1", "U2", "U3"])
def test_SRV_SCR_09_profile_code_row_never_shows_a_token(windows, key):
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    w.app.goto("profile")
    row = w.page.locator("#profileCodeRow")
    code = w.page.locator("#profileCode").inner_text() if row.is_visible() else ""
    saved = json.loads(w.app.saved_auth() or "{}")
    assert w.user.token not in code and (saved.get("access_token") or "x") not in code, \
        "Profile shows a real token / session token"
    w.app.log(f"Profile Code row for {key}: visible={row.is_visible()} text={'«hidden»' if not code else code!r}")
    assert code.strip().lower() != "local", "G-09: Profile 'Code' row shows the literal text 'local' in server mode"
