"""Job Board (spec §6.4) — the kanban screen used the way a person uses it:
open it, find the job's card in the right column, DRAG it to another column
with the mouse (the app's own pointer-drag code runs, exactly as on a phone),
tap a card to edit it. Every move is checked on screen AND in the database.
"Another device" changes are made straight through the API while the board is
open, then the board's own 60-second poll is run once.

Columns: Unscheduled | Scheduled | In Progress | Complete | Cancelled.
Only neighbouring columns are dragged between, so both are on screen at once.

Run: run_tests_gui_jobs_e2e.bat --human -k board
"""
import re

from playwright.sync_api import expect

from api import iso_date
from safety import SANDBOX_DATE

JOB_ID = "JobID (JOB-####)"


# ── helpers ──────────────────────────────────────────────────────────────────
def _db_job(api, jid):
    for j in api.read("Jobs_Schedule"):
        if j.get(JOB_ID) == jid:
            return j
    return None


def _col(page, status):
    return page.locator(f".board-col[data-status='{status}']")


def _card(page, jid, status=None):
    scope = _col(page, status) if status else page.locator("#boardColumns")
    return scope.locator(".board-card").filter(
        has=page.locator(".board-card-id", has_text=re.compile(rf"^\s*{re.escape(jid)}\s*$")))


def _open_board(app, page):
    # Opening the Board starts its own reload and ↻ starts another. Wait until
    # EVERY board load sent has come back, so a test that then changes the job
    # "on another device" isn't overtaken by a late reload that already sees the
    # change (2026-10-02, BRD-07: the late reload put the card in Cancelled
    # before the drag that was meant to be refused). Counted by the app's own
    # get_board_updates requests; the Board's next poll is 60 s away.
    sent, back = [0], [0]

    def _is_board_load(req):
        return "/pwa-api" in req.url and "get_board_updates" in (req.post_data or "")

    on_req = lambda req: sent.__setitem__(0, sent[0] + 1) if _is_board_load(req) else None
    on_resp = lambda resp: back.__setitem__(0, back[0] + 1) if _is_board_load(resp.request) else None
    on_fail = lambda req: back.__setitem__(0, back[0] + 1) if _is_board_load(req) else None
    page.on("request", on_req)
    page.on("response", on_resp)
    page.on("requestfailed", on_fail)
    try:
        app.goto("board")
        app.log("BOARD tap ↻ refresh")
        page.locator("#refreshBoardBtn").click()
        expect(page.locator("#boardColumns .loader")).to_have_count(0, timeout=20_000)
        expect(page.locator("#boardColumns .board-col")).to_have_count(5)
        for _ in range(100):                       # up to ~20 s
            if sent[0] and back[0] >= sent[0]:
                break
            page.wait_for_timeout(200)             # keeps the browser's events flowing
        page.wait_for_timeout(200)                 # let the last result render
    finally:
        page.remove_listener("request", on_req)
        page.remove_listener("response", on_resp)
        page.remove_listener("requestfailed", on_fail)


def _settled_box(page, locator, tries=5, scroll=True):
    """Scroll `locator` into view and return its bounding box, surviving a board
    redraw in between (2026-10-02, BRD-04: "Element is not attached to the
    DOM" — the Board re-renders its cards whenever its update poll runs, so a
    card found a moment earlier can be replaced by an identical fresh one).
    A Playwright locator re-finds the element on every call, so retrying picks
    up the fresh card; a redraw puts it back in the same place."""
    last = None
    for _ in range(tries):
        try:
            expect(locator).to_be_visible(timeout=10_000)
            if scroll:
                locator.scroll_into_view_if_needed(timeout=5_000)
            box = locator.bounding_box(timeout=5_000)
            if box:
                return box
        except Exception as e:          # detached mid-step by a redraw — find it again
            last = e
        page.wait_for_timeout(300)
    raise AssertionError(f"couldn't get a steady position for {locator}: {last}")


def _drag(app, page, jid, from_status, to_status):
    """Press on the card, move the mouse onto the neighbouring column, let go."""
    app.log(f"BOARD drag {jid}: {from_status} → {to_status}")
    card = _card(page, jid, from_status)
    target = _col(page, to_status).locator(".board-col-body")
    _settled_box(page, target)                        # scroll the drop column in
    cb = _settled_box(page, card)                     # then the card (as before)
    tb = _settled_box(page, target, scroll=False)     # measure — no more scrolling
    sx, sy = cb["x"] + cb["width"] / 2, cb["y"] + min(cb["height"] / 2, 20)
    tx, ty = tb["x"] + tb["width"] / 2, tb["y"] + min(tb["height"] / 2, 40)
    page.mouse.move(sx, sy)
    page.mouse.down()
    page.mouse.move(sx + 12, sy + 4, steps=3)          # past the 8px "it's a drag, not a tap" threshold
    page.mouse.move(tx, ty, steps=15)
    page.mouse.up()


def _update_request(r):
    return "/pwa-api" in r.url and "update_job_spreadsheet" in (r.post_data or "")


def _poll(page):
    """The board's own 60-second background poll, run once now."""
    page.evaluate("async () => { await loadBoard(false); }")


def _api_set(api, jid, updates):
    api.call("update_job_spreadsheet", {"job_identifier": jid, "id_column": JOB_ID,
                                         "sheet_name": "Jobs_Schedule", "updates": updates})


# ── BRD-01: columns + card placement ─────────────────────────────────────────
def test_BRD_01_columns_and_card_in_the_right_column(clean_slate, app, page, data):
    jid = data.job("BRD01", "brannon", **{"Start Time": "09:00", "End Time": "10:00",
                                          "Crew / Technician": "ZTEST Crew BRD01"})
    _open_board(app, page)
    for status in ["Unscheduled", "Scheduled", "In Progress", "Complete", "Cancelled"]:
        expect(_col(page, status)).to_be_visible()
    card = _card(page, jid, "Scheduled")
    expect(card).to_have_count(1)
    # the card shows the CUSTOMER RECORD's name (joined live from Customers)
    expect(card).to_contain_text("ZTEST E2E Customer")
    expect(card).to_contain_text("ZTEST Crew BRD01")
    expect(card).to_contain_text(SANDBOX_DATE)
    expect(card).to_contain_text("9:00")            # the time line
    expect(_card(page, jid)).to_have_count(1)       # on the board exactly once


# ── BRD-02: drag through the day's statuses ──────────────────────────────────
def test_BRD_02_drag_to_in_progress_then_complete(clean_slate, app, page, api, data):
    jid = data.job("BRD02")
    _open_board(app, page)
    for frm, to in [("Scheduled", "In Progress"), ("In Progress", "Complete")]:
        with page.expect_response(lambda r: _update_request(r.request), timeout=30_000):
            _drag(app, page, jid, frm, to)
        expect(page.locator("#toast")).to_contain_text(f"Moved to {to}")
        expect(_card(page, jid, to)).to_have_count(1)
        expect(_card(page, jid, frm)).to_have_count(0)
        assert _db_job(api, jid)["Job Status"] == to
    # a full reload shows the same thing the drag did
    page.locator("#refreshBoardBtn").click()
    expect(_card(page, jid, "Complete")).to_have_count(1, timeout=20_000)


# ── BRD-03: dropping on Unscheduled is refused, nothing is written ──────────
def test_BRD_03_drop_on_unscheduled_is_refused(clean_slate, app, page, api, data):
    jid = data.job("BRD03")
    _open_board(app, page)
    writes = []
    page.on("request", lambda r: writes.append(r.url) if _update_request(r) else None)
    _drag(app, page, jid, "Scheduled", "Unscheduled")
    expect(page.locator("#toast")).to_contain_text("clear its Service Date")
    expect(_card(page, jid, "Scheduled")).to_have_count(1)
    page.wait_for_timeout(1000)
    assert not writes, "dropping on Unscheduled must not write anything"
    j = _db_job(api, jid)
    assert j["Job Status"] == "Scheduled" and j.get("Service Date")


# ── BRD-04: an undated job, dragged to Scheduled, is scheduled for today ────
def test_BRD_04_undated_job_dragged_to_scheduled_gets_today(clean_slate, app, page, api, data):
    jid = data.job("BRD04 no date", date="")
    _open_board(app, page)
    expect(_card(page, jid, "Unscheduled")).to_have_count(1)
    with page.expect_response(lambda r: _update_request(r.request), timeout=30_000):
        _drag(app, page, jid, "Unscheduled", "Scheduled")
    expect(page.locator("#toast")).to_contain_text(f"Scheduled for today ({SANDBOX_DATE})")
    expect(_card(page, jid, "Scheduled")).to_have_count(1)
    assert iso_date(_db_job(api, jid).get("Service Date", "")) == SANDBOX_DATE


# ── BRD-05: tapping a card opens that job's edit form ────────────────────────
def test_BRD_05_tap_card_opens_the_job(clean_slate, app, page, data):
    jid = data.job("BRD05", **{"Service Details / Notes": "board tap check"})
    _open_board(app, page)
    app.log(f"BOARD tap card {jid}")
    _card(page, jid, "Scheduled").click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jfJobId")).to_have_value(jid)
    expect(page.locator("#jfNotes")).to_have_value("board tap check")


# ── BRD-06: a change made on another device shows up on the next poll ───────
def test_BRD_06_change_from_another_device_appears_on_poll(clean_slate, app, page, api, data):
    jid = data.job("BRD06")
    _open_board(app, page)
    expect(_card(page, jid, "Scheduled")).to_have_count(1)
    app.log("BOARD another device sets the job In Progress")
    _api_set(api, jid, {"Job Status": "In Progress"})
    _poll(page)
    expect(_card(page, jid, "In Progress")).to_have_count(1)
    expect(_card(page, jid, "Scheduled")).to_have_count(0)


# ── BRD-07: a stale drag is refused, the board shows the real state ──────────
def test_BRD_07_stale_drag_is_refused_and_board_reloads(clean_slate, app, page, api, data):
    """Another device cancelled the job while this board still showed it as
    Scheduled. Dragging it must NOT overwrite the other device's change: the
    server refuses (version conflict), the app says so and reloads."""
    jid = data.job("BRD07")
    _open_board(app, page)
    app.log("BOARD another device cancels the job (board not refreshed)")
    _api_set(api, jid, {"Job Status": "Cancelled"})
    with page.expect_response(lambda r: _update_request(r.request), timeout=30_000):
        _drag(app, page, jid, "Scheduled", "In Progress")
    expect(page.locator("#toast")).to_contain_text("❌")
    expect(_card(page, jid, "Cancelled")).to_have_count(1, timeout=20_000)
    assert _db_job(api, jid)["Job Status"] == "Cancelled"


# ── BRD-08: a job deleted on another device leaves the board ─────────────────
def test_BRD_08_job_deleted_elsewhere_leaves_the_board(clean_slate, app, page, api, data):
    keep, gone = data.job("BRD08 keep"), data.job("BRD08 gone")
    _open_board(app, page)
    expect(_card(page, gone, "Scheduled")).to_have_count(1)
    app.log(f"BOARD another device deletes {gone}")
    _api_set(api, gone, {"Job Status": "Cancelled"})
    api.call("delete_job", {"job_identifier": gone, "confirm": True})
    # the user goes elsewhere and comes back — the ordinary way to "look again"
    app.goto("jobs")
    app.goto("board")
    _poll(page)
    expect(_card(page, keep, "Scheduled")).to_have_count(1)
    expect(_card(page, gone)).to_have_count(0)


# ── BRD-09: text in a job is shown as text on the card, never run ────────────
def test_BRD_09_card_text_is_escaped(clean_slate, app, page, data):
    # Crew is shown on the card as typed (the customer name comes from the
    # customer record, so markup goes in the crew field)
    jid = data.job("BRD09", **{"Crew / Technician": '<img src=x onerror="window.__e2e_board_xss=1">Brd'})
    _open_board(app, page)
    expect(_card(page, jid)).to_contain_text('<img src=x onerror="window.__e2e_board_xss=1">')
    assert page.evaluate("() => window.__e2e_board_xss") is None
