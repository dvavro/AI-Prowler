"""Clock / Time Tracking screen (spec §6.7) — used the way a crew member uses
it: pick the job, ▶ Clock In, watch the timer run, ■ Clock Out. Checked on
screen AND in the database's TimeLog (these are payroll hours).

Also covers what happens on a real phone: the app gets closed / reloaded while
clocked in, and a clock-in made on another device.

Run: run_tests_gui_jobs_e2e.bat --human -k test_clock
"""
import re

from playwright.sync_api import expect

JOB_ID = "JobID (JOB-####)"


# ── helpers ──────────────────────────────────────────────────────────────────
def _entries(api, jid):
    return [r for r in api.read("TimeLog") if (r.get(JOB_ID) or r.get("JobID")) == jid]


def _open_entries(api, jid):
    return [r for r in _entries(api, jid) if not str(r.get("Clock Out") or "").strip()]


def _clock_screen(app, page, jid):
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("clock")
    app.log(f"CLOCK choose {jid}")
    page.locator("#clockJobSelect").select_option(jid)


def _log_request(r):
    return "/pwa-api" in r.url and "log_time_entry" in (r.post_data or "")


def _clock_in(app, page):
    app.log("CLOCK tap ▶ Clock In")
    with page.expect_response(lambda r: _log_request(r.request), timeout=30_000):
        page.locator("#clockInBtn").click()


def _clock_out(app, page):
    app.log("CLOCK tap ■ Clock Out")
    with page.expect_response(lambda r: _log_request(r.request), timeout=30_000):
        page.locator("#clockOutBtn").click()


# ── CLK-02: clock in, timer runs, clock out, hours recorded ──────────────────
def test_CLK_02_clock_in_and_out_records_the_hours(clean_slate, app, page, api, data):
    jid = data.job("CLK02")
    _clock_screen(app, page, jid)
    expect(page.locator("#clockStatusText")).to_have_text("Not clocked in")
    _clock_in(app, page)
    expect(page.locator("#clockStatusText")).to_have_text(f"Clocked in: {jid}")
    expect(page.locator("#clockInBtn")).to_be_disabled()
    expect(page.locator("#clockOutBtn")).to_be_enabled()
    elapsed = page.locator("#clockElapsed")
    expect(elapsed).to_be_visible()
    first = elapsed.text_content()
    page.wait_for_timeout(2500)
    assert elapsed.text_content() != first, "the elapsed timer isn't running"
    expect(page.locator("#activeClock")).to_contain_text(jid)          # banner
    assert len(_open_entries(api, jid)) == 1, "no open clock-in in the TimeLog"

    _clock_out(app, page)
    expect(page.locator("#clockStatusText")).to_have_text("Not clocked in")
    expect(page.locator("#clockElapsed")).to_be_hidden()
    expect(page.locator("#clockHistory")).to_contain_text(jid)          # Recent Entries
    expect(page.locator("#activeClock")).not_to_contain_text(jid)
    rows = _entries(api, jid)
    assert len(rows) == 1 and str(rows[0].get("Clock Out") or "").strip(), f"TimeLog: {rows}"


# ── CLK-03: a second clock-in is not possible while clocked in ───────────────
def test_CLK_03_no_second_clock_in_while_clocked_in(clean_slate, app, page, api, data):
    a, b = data.job("CLK03 A"), data.job("CLK03 B", "brannon")
    _clock_screen(app, page, a)
    _clock_in(app, page)
    app.log(f"CLOCK choose the other job {b}")
    page.locator("#clockJobSelect").select_option(b)
    expect(page.locator("#clockInBtn")).to_be_disabled()
    assert not _open_entries(api, b)
    # back to the job that's running, and clock out of it
    page.locator("#clockJobSelect").select_option(a)
    _clock_out(app, page)
    assert not _open_entries(api, a)


# ── CLK-04: app closed/reloaded while clocked in ─────────────────────────────
def test_CLK_04_still_clocked_in_after_the_app_is_reopened(clean_slate, app, page, api, data):
    """A phone closes background apps all the time. Re-opening the app while
    clocked in must still show the clock running, and Clock Out must work —
    otherwise the crew member can't clock out and the hours stay open."""
    jid = data.job("CLK04")
    _clock_screen(app, page, jid)
    _clock_in(app, page)
    expect(page.locator("#clockStatusText")).to_have_text(f"Clocked in: {jid}")
    app.log("CLOCK the phone closes the app — reopen it")
    page.reload(wait_until="domcontentloaded")
    expect(page.locator("#app")).to_be_visible(timeout=30_000)
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("clock")
    expect(page.locator("#clockStatusText")).to_have_text(f"Clocked in: {jid}", timeout=15_000)
    expect(page.locator("#clockOutBtn")).to_be_enabled()
    page.locator("#clockJobSelect").select_option(jid)
    _clock_out(app, page)
    expect(page.locator("#clockStatusText")).to_have_text("Not clocked in")
    assert not _open_entries(api, jid), "the clock-in was left open"


# ── CLK-05: clocked in on another device ─────────────────────────────────────
def test_CLK_05_clock_in_already_open_elsewhere_is_not_a_fresh_start(clean_slate, app, page, api, data):
    """The server already has an open clock-in for this job (made on another
    device / by voice). Tapping Clock In must not pretend a NEW shift started
    now (fresh 00:00 timer) — the app must show the existing clock-in."""
    jid = data.job("CLK05")
    app.log("CLOCK another device clocks in first")
    api.call("log_time_entry", {"job_identifier": jid, "action": "start", "gps_coords": ""})
    page.wait_for_timeout(2500)
    _clock_screen(app, page, jid)
    if page.locator("#clockInBtn").is_enabled():
        _clock_in(app, page)
    expect(page.locator("#clockStatusText")).to_have_text(f"Clocked in: {jid}")
    elapsed = page.locator("#clockElapsed")
    expect(elapsed).to_be_visible()
    # the shift started ≥ 2.5 s before this screen was opened, not just now
    secs = sum(int(x) * m for x, m in zip(elapsed.text_content().split(":"), [3600, 60, 1]))
    assert secs >= 2, f"timer restarted from zero ({elapsed.text_content()})"
    assert len(_open_entries(api, jid)) == 1
    _clock_out(app, page)
    assert not _open_entries(api, jid)


# ── CLK-06: nothing chosen → told to pick a job, nothing sent ────────────────
def test_CLK_06_clock_in_without_a_job_is_refused(clean_slate, app, page, data):
    data.job("CLK06")
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("clock")
    sent = []
    page.on("request", lambda r: sent.append(r.url) if _log_request(r) else None)
    page.locator("#clockJobSelect").select_option("")
    btn = page.locator("#clockInBtn")
    if btn.is_enabled():
        btn.click()
        expect(page.locator("#toast")).to_contain_text("Select a job first")
    page.wait_for_timeout(800)
    assert not sent
