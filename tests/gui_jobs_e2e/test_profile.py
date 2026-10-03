"""Profile / My Account screen (spec §6.8) — personal mode.

What a person sees there: who is signed in (the owner's name from Settings,
"Mode: Personal"), the session counters (open jobs loaded, clock entries made
on this device), and Sign Out.

Sign-out itself is AUTH-06; PRO-04 adds what a person actually relies on:
after signing out, a reload does NOT quietly sign them back in, and they can
sign back in with the password.

Run: run_tests_gui_jobs_e2e.bat --human -k test_profile
"""
import json

import pytest
from playwright.sync_api import expect

from app import JobsApp


def _stat(page, el_id: str) -> int:
    return int((page.locator(f"#{el_id}").text_content() or "0").strip() or 0)


def _reload_jobs(app, page):
    app.log("PROFILE reload the job list (as the Jobs screen does)")
    page.evaluate("async () => { await loadJobs(); }")


# ── PRO-01: who is signed in ─────────────────────────────────────────────────
def test_PRO_01_shows_owner_name_and_personal_mode(app, page, api):
    status, body = api.raw_get("/pwa-token")
    assert status == 200, f"/pwa-token answered {status}"
    info = json.loads(body)
    expected = (info.get("owner_name") or "").strip() or "Owner"
    app.log(f"PROFILE expected name: {expected!r}")

    app.goto("profile")
    expect(page.locator("#profileName")).to_have_text(expected)
    expect(page.locator("#topbarRole")).to_have_text(expected)       # same name in the top bar
    expect(page.locator("#profileRoleLabel")).to_have_text("Mode")
    expect(page.locator("#profileRole")).to_have_text("Personal")
    expect(page.locator("#profileCodeRow")).to_be_hidden()            # server-mode only
    expect(page.get_by_test_id("profile-signout")).to_be_visible()


# ── PRO-02: "Jobs Loaded" counts open jobs only ──────────────────────────────
def test_PRO_02_jobs_loaded_counts_open_jobs(clean_slate, app, page, data):
    _reload_jobs(app, page)
    app.goto("profile")
    before = _stat(page, "statJobs")
    app.log(f"PROFILE Jobs Loaded before: {before}")

    data.job("PRO02 open A")
    data.job("PRO02 open B", "brannon")
    data.job("PRO02 done", "library", **{"Job Status": "Complete"})

    app.goto("jobs")
    _reload_jobs(app, page)
    app.goto("profile")
    expect(page.locator("#statJobs")).to_have_text(str(before + 2))  # the Complete one isn't "open"


# ── PRO-03: "Clock Entries" goes up after a clock in / out ────────────────────
def test_PRO_03_clock_entries_counts_a_finished_clock(clean_slate, app, page, data):
    jid = data.job("PRO03")
    app.goto("profile")
    before = _stat(page, "statClocks")

    _reload_jobs(app, page)
    app.goto("clock")
    app.log(f"CLOCK choose {jid}")
    page.locator("#clockJobSelect").select_option(jid)
    is_log = lambda r: "/pwa-api" in r.url and "log_time_entry" in (r.request.post_data or "")
    app.log("CLOCK tap ▶ Clock In")
    with page.expect_response(is_log, timeout=30_000):
        page.locator("#clockInBtn").click()
    expect(page.locator("#clockStatusText")).to_have_text(f"Clocked in: {jid}")
    page.wait_for_timeout(1500)
    app.log("CLOCK tap ■ Clock Out")
    with page.expect_response(is_log, timeout=30_000):
        page.locator("#clockOutBtn").click()
    expect(page.locator("#clockStatusText")).to_have_text("Not clocked in")

    app.goto("profile")
    expect(page.locator("#statClocks")).to_have_text(str(before + 1))


# ── PRO-04: sign out from Profile stays signed out, then sign back in ────────
@pytest.mark.no_login
def test_PRO_04_sign_out_stays_out_and_can_sign_back_in(page, app_url, token):
    a = JobsApp(page, app_url).open_login_screen()
    a.login(token)
    expect(page.locator("#app")).to_be_visible()

    a.sign_out()                                           # taps the real Profile button
    expect(page.locator("#authScreen")).to_be_visible()
    assert a.saved_auth() is None, "the saved sign-in wasn't removed"

    a.step("reload after signing out — must NOT sign back in on its own")
    page.reload(wait_until="domcontentloaded")
    expect(page.locator("#authScreen")).to_be_visible(timeout=30_000)
    expect(page.locator("#app")).to_be_hidden()
    assert a.saved_auth() is None

    a.login(token)                                         # typed like a person
    expect(page.locator("#app")).to_be_visible()
    a.goto("profile")
    expect(page.locator("#profileRole")).to_have_text("Personal")
