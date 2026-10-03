"""BTN-OTHER (spec §6.15) — the button sweep for Board, Calendar, Clock, Photos,
Messages, Reports and Profile. Same pattern as the Jobs/Route sweep in
test_buttons.py: every button found by the BTN-00 inventory is classified and
clicked for real, and BTN_OTHER_COVERAGE fails if one of these screens gains a
button that isn't in KNOWN_OTHER below.

  SAFE     opens / refreshes / navigates
  WRITE    changes test data (a ZTEST job's clock entries / photo folder)
  GUARDED  outbound (send_sms): clicked for real, the write guard RECORDS the
           call instead of sending anything

The Database screen's buttons are covered by test_database.py (BTN-DB).

Run: run_tests_gui_jobs_e2e.bat --human -k BTN_OTHER
"""
import re

import pytest
from playwright.sync_api import expect

from app import JobsApp
from safety import SANDBOX_DATE, sandbox_day
from test_buttons import INVENTORY_JS, _key, screen_selector
from test_photos import TINY_PNG, disk  # noqa: F401  (disk is a fixture: deletes uploaded test files)

KNOWN_OTHER = {
    "board": {"refreshBoardBtn": "SAFE", "onBoardCardClick": "SAFE"},
    "calendar": {"refreshCalBtn": "SAFE",
                 # found by the coverage check once the calendar had loaded (2026-09-26):
                 "calDayRowClicked": "SAFE",      # tap a day: its jobs, or Add Job on an empty day
                 "stopPropagation": "SAFE"},      # a job chip inside a day (and the day's 📍 route link)
    "clock": {"clockInBtn": "WRITE", "clockOutBtn": "WRITE"},
    "photos": {"getElementById": "SAFE",          # 📷 Add Photos / 📎 Add Files (open the picker)
               "uploadBtn": "WRITE"},
    "messages": {"sendSmsBtn": "GUARDED", "checkSMSReplies": "SAFE"},
    "reports": {"refreshReportsBtn": "SAFE", "findStaleCustomers": "SAFE"},
    "profile": {"profile-signout": "SAFE"},
}
SMS_ON = "✅ SMS is configured (E2E fake)"


@pytest.fixture
def two_jobs(clean_slate, data, app, page):
    ids = [data.job("BTN A", "city_hall"), data.job("BTN B", "brannon")]
    page.evaluate("async () => { await loadJobs(); }")
    return ids


def _api(page, tool=None):
    """Expect the app's next /pwa-api request (for `tool`, if given)."""
    return page.expect_request(lambda r: "/pwa-api" in r.url and (tool is None or tool in (r.post_data or "")),
                               timeout=30_000)


# ── coverage ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("screen", list(KNOWN_OTHER))
def test_BTN_OTHER_COVERAGE_every_button_is_classified(app, page, two_jobs, screen):
    app.goto(screen)
    page.wait_for_timeout(1200)
    found = {_key(b) for b in page.evaluate(INVENTORY_JS, screen_selector(screen))}
    unknown = sorted(found - set(KNOWN_OTHER[screen]))
    assert not unknown, (f"New button(s) on the {screen} screen not covered by the sweep: {unknown}. "
                         "Add each to KNOWN_OTHER in test_buttons_other.py with a test.")


# ── Board ────────────────────────────────────────────────────────────────────
def _board_card(page, jid):
    return page.locator("#boardColumns .board-card").filter(
        has=page.locator(".board-card-id", has_text=re.compile(rf"^\s*{re.escape(jid)}\s*$")))


def test_BTN_OTHER_BOARD_refresh(app, page, two_jobs):
    app.goto("board")
    app.step("BOARD tap ↻")
    with _api(page):
        page.locator("#refreshBoardBtn").click()
    expect(page.locator("#boardColumns .loader")).to_have_count(0, timeout=20_000)
    for jid in two_jobs:
        expect(_board_card(page, jid)).to_have_count(1, timeout=20_000)


def test_BTN_OTHER_BOARD_card_opens_the_job(app, page, two_jobs):
    app.goto("board")
    card = _board_card(page, two_jobs[0])
    expect(card).to_have_count(1, timeout=20_000)
    app.step(f"BOARD tap card {two_jobs[0]}")
    card.click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jfJobId")).to_have_value(two_jobs[0])
    page.evaluate("() => closeJobFormModal()")


# ── Calendar ─────────────────────────────────────────────────────────────────
def test_BTN_OTHER_CALENDAR_refresh(app, page, two_jobs):
    app.goto("calendar")
    btn = page.locator("#refreshCalBtn")
    expect(btn).to_be_enabled(timeout=30_000)
    app.step("CALENDAR tap ↻")
    with _api(page):
        btn.click()
    expect(btn).to_be_enabled(timeout=30_000)
    expect(page.locator("#calendarContent")).not_to_contain_text("Could not")


def _cal_day(page, key):
    return page.locator(f"#calendarContent [onclick*=\"calDayRowClicked('{key}')\"]").first


def test_BTN_OTHER_CALENDAR_job_chip_opens_the_job(app, page, two_jobs):
    app.goto("calendar")
    chip = page.locator(f"#calendarContent .cal-job-chip[onclick*=\"'{two_jobs[0]}'\"]").first
    expect(chip).to_be_visible(timeout=30_000)
    app.step(f"CALENDAR tap job chip {two_jobs[0]}")
    chip.click()
    expect(page.locator("#jobModal")).to_have_class(re.compile(r"\bopen\b"))
    expect(page.locator("#jobModal")).to_contain_text(two_jobs[0])
    expect(page.locator("#calDayModal")).not_to_have_class(re.compile(r"\bopen\b"))   # chip only, not the day too
    page.locator("#jobModal").click(position={"x": 5, "y": 5})


def test_BTN_OTHER_CALENDAR_day_with_jobs_lists_them(app, page, two_jobs):
    app.goto("calendar")
    day = _cal_day(page, SANDBOX_DATE)
    expect(day).to_be_visible(timeout=30_000)
    app.step(f"CALENDAR tap the day {SANDBOX_DATE}")
    day.click(position={"x": 8, "y": 8})                     # the day itself, not a chip
    modal = page.locator("#calDayModal")
    expect(modal).to_have_class(re.compile(r"\bopen\b"))
    for jid in two_jobs:
        expect(page.locator("#calDayModalList")).to_contain_text(jid)
    modal.click(position={"x": 5, "y": 5})                   # tap outside closes
    expect(modal).not_to_have_class(re.compile(r"\bopen\b"))


def test_BTN_OTHER_CALENDAR_empty_day_opens_add_job_for_that_date(app, page, two_jobs):
    empty = sandbox_day(5)
    app.goto("calendar")
    day = _cal_day(page, empty)
    expect(day).to_be_visible(timeout=30_000)
    app.step(f"CALENDAR tap the empty day {empty}")
    day.click(position={"x": 8, "y": 8})
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jfDate")).to_have_value(empty)
    page.evaluate("() => closeJobFormModal()")


# ── Clock ────────────────────────────────────────────────────────────────────
def test_BTN_OTHER_CLOCK_in_and_out(app, page, api, two_jobs):
    jid = two_jobs[0]
    app.goto("clock")
    page.locator("#clockJobSelect").select_option(jid)
    app.step("CLOCK tap ▶ Clock In")
    with _api(page, "log_time_entry"):
        page.locator("#clockInBtn").click()
    expect(page.locator("#clockStatusText")).to_have_text(f"Clocked in: {jid}")
    expect(page.locator("#clockOutBtn")).to_be_enabled()
    app.step("CLOCK tap ■ Clock Out")
    with _api(page, "log_time_entry"):
        page.locator("#clockOutBtn").click()
    expect(page.locator("#clockStatusText")).to_have_text("Not clocked in")
    rows = [r for r in api.read("TimeLog") if (r.get("JobID (JOB-####)") or r.get("JobID")) == jid]
    assert len(rows) == 1 and str(rows[0].get("Clock Out") or "").strip(), f"TimeLog: {rows}"


# ── Photos ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("tile,name,mime,body", [
    ("📷 Add Photos", "btn-sweep.png", "image/png", TINY_PNG),
    ("📎 Add Files", "btn-sweep.txt", "text/plain", b"E2E button sweep"),
], ids=["add_photos", "add_files"])
def test_BTN_OTHER_PHOTOS_tiles_open_the_picker(app, page, two_jobs, tile, name, mime, body):
    app.goto("photos")
    app.step(f"PHOTOS tap {tile}")
    with page.expect_file_chooser(timeout=15_000) as fc:
        page.locator("#screen-photos").get_by_text(tile.split(" ", 1)[1], exact=True).click()
    fc.value.set_files([{"name": name, "mimeType": mime, "buffer": body}])
    expect(page.locator("#photoCount")).to_have_text("1 / 10")


def test_BTN_OTHER_PHOTOS_upload(app, page, two_jobs, disk):  # noqa: F811
    jid = disk(two_jobs[0])
    app.goto("photos")
    page.locator("#photoJobSelect").select_option(jid)
    page.locator("#fileInputCamera").set_input_files([{"name": "btn-sweep.png", "mimeType": "image/png",
                                                        "buffer": TINY_PNG}])
    btn = page.locator("#uploadBtn")
    expect(btn).to_be_enabled()
    app.step("PHOTOS tap ⬆ Upload")
    with page.expect_response(lambda r: "/photos/upload" in r.url, timeout=60_000):
        btn.click()
    expect(page.locator("#uploadStatus")).to_have_text("✓ 1 photo(s) saved to AI-Prowler")


# ── Messages ─────────────────────────────────────────────────────────────────
def test_BTN_OTHER_MESSAGES_send_is_guarded(app, page, guard):
    page.e2e_fakes["check_sms_configured"] = SMS_ON
    app.goto("messages")
    before = len(guard.recorded_calls("send_sms"))
    page.locator("#smsTo").fill("ZTEST E2E Customer")
    page.locator("#smsMessage").fill("E2E button sweep — never sent")
    app.step("MESSAGES tap 💬 Send (recorded by the guard, not sent)")
    with page.expect_response(lambda r: "/pwa-api" in r.url and "send_sms" in (r.request.post_data or "")):
        page.locator("#sendSmsBtn").click()
    calls = guard.recorded_calls("send_sms")
    assert len(calls) == before + 1 and calls[-1]["args"]["to"] == "ZTEST E2E Customer"


def test_BTN_OTHER_MESSAGES_check_replies(app, page):
    app.goto("messages")
    app.step("MESSAGES tap 🔄 Check")
    with _api(page, "check_sms_inbox"):
        page.locator("#screen-messages").get_by_role("button", name=re.compile("Check")).click()
    box = page.locator("#smsReplies")
    expect(box).not_to_contain_text("Checking…", timeout=30_000)
    expect(box).not_to_contain_text("Could not check replies")


# ── Reports ──────────────────────────────────────────────────────────────────
def test_BTN_OTHER_REPORTS_refresh(app, page, two_jobs):
    app.goto("reports")
    btn = page.locator("#refreshReportsBtn")
    expect(btn).to_be_enabled(timeout=30_000)
    app.step("REPORTS tap ↻")
    with _api(page):
        btn.click()
    expect(btn).to_be_enabled(timeout=30_000)
    expect(page.locator("#screen-reports")).not_to_contain_text("Could not load")


def test_BTN_OTHER_REPORTS_find_customers(app, page):
    app.goto("reports")
    app.step("REPORTS tap 🔍 Find Customers (a read)")
    with _api(page, "find_stale_customers"):
        page.locator("#screen-reports").get_by_role("button", name=re.compile("Find Customers")).click()
    res = page.locator("#staleCustomersResult")
    expect(res).not_to_contain_text("Searching…", timeout=30_000)
    assert res.inner_text().strip(), "Find Customers showed nothing at all"
    expect(res.locator("div[style*='#f87171']")).to_have_count(0)          # no red error line


# ── Profile ──────────────────────────────────────────────────────────────────
@pytest.mark.no_login
def test_BTN_OTHER_PROFILE_sign_out(page, app_url, token):
    a = JobsApp(page, app_url).open_login_screen()
    a.login(token)
    expect(page.locator("#app")).to_be_visible(timeout=30_000)
    a.step("PROFILE tap Sign Out / Change Device")
    a.sign_out()
    expect(page.locator("#authScreen")).to_be_visible(timeout=30_000)
    assert a.saved_auth() is None
