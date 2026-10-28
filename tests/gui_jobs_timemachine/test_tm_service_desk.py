"""TIME MACHINE — Service Desk through time (2026-10-27).

David 2026-10-27: "Can you review and add if necessary, time machine test in
human mode for the service desks feature".

Everything in Service Desk that depends on the clock, walked day by day in the
time machine's throwaway AI-Prowler and watched in a real browser. Its timed
jobs (SLA checks, auto-close, morning digest, backups) run when the story says
so, at the simulated time (tm_server.py: POST /run {"job": "service_desk"});
every email and text lands in the outbox, never sent.

PERSONAL mode (Solo edition):
    run_tests_gui_jobs_e2e.bat --timemachine --human -k SD_
  P01 Mon 08:00  owner puts his alert email in Settings; auto-close shows 3 days
  P02 Mon 09:00  a customer asks for service at /support/new — the text code
                 runs out after 10 minutes, a new code works
  P03 Mon 09:30  owner files his own to-do, due Wednesday
  P04 Tue-Thu    morning digest: nothing before 7:00, once a day, "Due today"
                 on Wednesday, "Overdue" on Thursday — to the owner's email
  P05 Thu 08:00  the to-do is under Overdue with the late chip
  P06 Thu 10:00  owner marks the customer's ticket Fixed
  P07 +3 days    the customer stays quiet — it closes itself, not a minute early
  P08 +2 days    the customer reopens it from the status link (inside 7 days)
  P09 +8 days    the reopen button is gone and the server refuses a reopen
  P10 +29/+31 d  the status link still works at 29 days, not at 31
  P11            an import is undone on day 6 in Settings; day 8 is refused
  P12 nights     one scheduled backup a night, retention keeps 3 daily; two
                 failed nights in a row email the owner; then it recovers

SERVER mode (Business edition):
    run_tests_gui_jobs_e2e.bat --server --timemachine --human -k SD_
  B01 Mon 10:00  manager files a customer P2 ticket in the app and assigns it to
                 a crew member: first reply due +4 h, fix due +2 business days
  B02 Mon        the SLA clock: warning at 75%, breach, escalation at 2x — each
                 once, to the right people
  B03 Tue 07:00  the morning digest to the owner and manager only, once a day
  B04 Tue 08:30  crew replies to the customer by text and puts it On Hold
  B05 Tue-Thu    on hold the clock stops (no warning, no breach); back In
                 Progress, the fix due moves later by the time on hold
  B06 Thu-Fri    fix warning, then breach after the MOVED due time
  B07 Fri        the manager sees it Overdue and "SLA misses 2" in Reports
  B08 Fri-Wed    marked Fixed, 3 quiet days -> closed by itself; the customer
                 reopens it from the status link and the crew member is told
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse

import pytest

MODE = (os.environ.get("E2E_TM_MODE") or "personal").strip().lower()
TYPE_DELAY = int(os.environ.get("E2E_TYPE_DELAY") or 0)      # --human: key-by-key typing
THINK_MS = int(os.environ.get("E2E_THINK_MS") or 0)          # --human: a pause after each step

_e2e_log = logging.getLogger("e2e")                          # conftest writes it to <run folder>\run.log


def _log(msg: str):
    _e2e_log.info(f"[SD] {msg}")


personal_only = pytest.mark.skipif(MODE == "server", reason="Solo edition story (personal mode)")
server_only = pytest.mark.skipif(MODE != "server", reason="Business edition story (server mode)")

T_CUST = "ZTEST SD streaks on the front windows"
T_TODO = "ZTEST SD renew the pesticide license"
T_GUTTER = "ZTEST SD gutter overflowing onto the porch"
T_UNASSIGNED = "ZTEST SD forklift battery won't hold a charge"
# Made-up numbers in the +1 555 range the other time-machine stories check for
# ("nothing went to a real address").
CUST_PHONE, CUST_DIGITS = "555-010-0142", "5550100142"
HALE_PHONE, HALE_DIGITS = "555-010-0177", "5550100177"
OWNER_EMAIL = "owner@time-machine.test"

S: dict = {"ok": []}                    # the story's state


@pytest.fixture(autouse=True)
def _in_order(browser_name):
    """ONE story told in order. pytest-playwright parametrizes every browser
    test ("[chromium]") and pytest runs those as a group ahead of the rest —
    asking for browser_name in every test keeps them all in file order (the
    same fix as test_tm_six_weeks.py)."""
    yield


def _need(*steps):
    missing = [s for s in steps if s not in S["ok"]]
    if missing:
        pytest.skip(f"needs earlier step(s) {missing}")


def _done(step):
    S["ok"].append(step)


# ── time ──────────────────────────────────────────────────────────────────────
def _monday_on_or_after(d: dt.date) -> dt.date:
    return d + dt.timedelta(days=(7 - d.weekday()) % 7)


def _day(n: int) -> dt.date:
    return S["D0"] + dt.timedelta(days=n)


def _at(tm, n: int, hhmm: str) -> dt.datetime:
    tm.set_clock(_day(n), hhmm)
    return tm.now()


def _go(tm, when: dt.datetime) -> dt.datetime:
    """Move the clock to a moment (local, minute resolution)."""
    when = when.astimezone()
    tm.set_clock(when.date(), when.strftime("%H:%M"))
    return tm.now()


def _local(iso: str) -> dt.datetime:
    return dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00")).astimezone()


def _flags(did: dict, tid: str) -> set:
    return {f for t, f in (did.get("sla") or []) if t == tid}


# ── the people, in the browser ────────────────────────────────────────────────
class Person:
    """Someone using a page the way a person does (human mode: key-by-key)."""

    def __init__(self, page, tm):
        self.page, self.tm = page, tm
        self._answers: list = []
        page.on("dialog", self._dialog)

    def _dialog(self, d):
        a = self._answers.pop(0) if self._answers else True
        if a is False:
            d.dismiss()
        elif d.type == "prompt":
            d.accept(a if isinstance(a, str) else "")
        else:
            d.accept()

    def answer(self, *answers):
        """Queue answers for the next prompt()/confirm() dialogs (True = OK)."""
        self._answers.extend(answers)

    def sync_clock(self):
        self.page.clock.set_system_time(self.tm.now())

    def think(self):
        if THINK_MS:
            self.page.wait_for_timeout(THINK_MS)

    def type(self, sel, text):
        loc = self.page.locator(sel)
        loc.click()
        loc.fill("")
        if TYPE_DELAY:
            loc.press_sequentially(text, delay=TYPE_DELAY)
        else:
            loc.fill(text)
        self.think()

    def click(self, sel):
        self.page.locator(sel).first.click()
        self.think()

    def goto(self, path):
        self.sync_clock()
        self.page.goto(self.tm.origin + path)
        self.think()


class Desk(Person):
    """The Service Desk app (/desk/), signed in as one of the people."""

    def __init__(self, page, tm, key="owner"):
        super().__init__(page, tm)
        tok = tm.desk_token(key, fresh=True)
        page.add_init_script("try{sessionStorage.setItem('desk_token'," + json.dumps(tok) + ")}catch(e){}")
        _log(f"browser: Service Desk as {key}")

    def open(self):
        self.goto("/desk/")
        self.page.locator("#tabs").wait_for(state="visible")
        return self

    def tab(self, name):
        self.click(f".tab[data-filter='{name}']")

    def toast(self, text, timeout=15000):
        self.page.locator("#toast", has_text=text).wait_for(state="visible", timeout=timeout)

    def card(self, tid):
        return self.page.locator(f"#app [data-open='{tid}']").first

    def open_ticket(self, tid):
        self.card(tid).click()
        self.page.locator("#back").wait_for()
        self.think()

    def filed_id(self) -> str:
        self.toast("Filed")
        return re.search(r"T-\d{4,}", self.page.locator("#toast").inner_text()).group(0)


# ── the server side ───────────────────────────────────────────────────────────
def _ticket(tm, tid, key="owner") -> dict:
    st, d = tm.desk("GET", f"/tickets/{tid}", key=key)
    assert st == 200, (st, d)
    t = d["ticket"]
    for k, v in (t.get("sla") or {}).items():            # the full ticket keeps its clocks under "sla"
        t.setdefault(k, v)
    return t


def _wait_state(tm, tid, state, timeout=20) -> dict:
    end = time.time() + timeout
    while True:
        t = _ticket(tm, tid)
        if t["state"] == state:
            return t
        if time.time() > end:
            raise AssertionError(f"{tid} is {t['state']}, expected {state}")
        time.sleep(0.4)


def _portal(tm, method, path, body=None):
    """The customer's status page API (/support-api), no sign-in."""
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(tm.origin + "/support-api" + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except ValueError:
            return e.code, {}


def _import_csv(tm, filename, text):
    """POST /desk-api/import (multipart, dry_run=0) as the owner."""
    b = "----ZTEST" + uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"dry_run\"\r\n\r\n0\r\n"
            f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: text/csv\r\n\r\n").encode() + text.encode() + f"\r\n--{b}--\r\n".encode()
    r = urllib.request.Request(tm.origin + "/desk-api/import", data=body, method="POST")
    r.add_header("Content-Type", f"multipart/form-data; boundary={b}")
    r.add_header("Authorization", "Bearer " + tm.desk_token("owner", fresh=True))
    with urllib.request.urlopen(r, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))["result"]


def _emails(tm, after, to=None, subject=None):
    return [m for m in tm.outbox()[after:] if m.get("kind") == "email"
            and (to is None or to in m.get("to", "")) and (subject is None or subject in m.get("subject", ""))]


def _desk_root(tm) -> Path:
    hits = sorted(tm.home.rglob("ai_prowler_tickets.db"))
    assert hits, f"no Service Desk database in the sandbox {tm.home}"
    return hits[0].parent


# ══════════════════════════════════════════════════════════════════════════════
def test_SD_00_story_dates_and_service_desk_is_on(tm):
    """D0 is a Monday well past the other time-machine stories' dates. Service
    Desk is on in the sandbox and answers as the right edition."""
    S["D0"] = _monday_on_or_after(tm.start_day + dt.timedelta(days=420))
    _at(tm, 0, "07:30")
    st, d = tm.desk("GET", "/me")
    assert st == 200, (st, d)
    assert d["edition"] == ("business" if MODE == "server" else "solo"), d["edition"]
    S["ids"] = {}
    if MODE == "server":
        for k in tm.users:
            S["ids"][k] = tm.desk("GET", "/me", key=k)[1]["actor"]["id"]
    _log(f"story: D0={S['D0']} ({MODE}); people {S['ids']}")
    _done("dates")


# ══════════════════════════ PERSONAL (Solo) ═══════════════════════════════════
@personal_only
def test_SD_P01_owner_sets_alert_email(tm, page):
    _need("dates")
    _at(tm, 0, "08:00")
    app = Desk(page, tm).open()
    app.tab("settings")
    page.locator("#alEmail").wait_for()
    assert page.locator("#acDays").input_value() == "3", "auto-close should start at 3 days"
    app.type("#alEmail", OWNER_EMAIL)
    app.click("#alSave")
    app.toast("Saved")
    s = tm.desk("GET", "/settings")[1]["settings"]
    assert s["alert_email"] == OWNER_EMAIL and s["auto_close_days"] == 3
    _done("p_setup")


@personal_only
def test_SD_P02_customer_request_code_runs_out_after_10_minutes(tm, page):
    _need("p_setup")
    _at(tm, 0, "09:00")
    cust = Person(page, tm)
    cust.goto("/support/new")
    cust.type("#fName", "ZTEST Mrs Lopez")
    cust.type("#fPhone", CUST_PHONE)
    cust.type("#fTitle", T_CUST)

    def code_text(after):
        m = tm.wait_outbox(lambda m: m["kind"] == "sms" and m["to"].endswith(CUST_DIGITS)
                           and "code" in m["body"], after=after)
        return re.search(r"\b(\d{6})\b", m["body"]).group(1)

    n = len(tm.outbox())
    cust.click("#fSend")
    code = code_text(n)
    _at(tm, 0, "09:12")                      # 12 minutes later — the code was good for 10
    cust.type("#fCode", code)
    cust.click("#fVerify")
    page.locator("#cErr", has_text="expired").wait_for()
    assert "/support/new" in page.url
    n = len(tm.outbox())
    cust.click("#fResend")
    code = code_text(n)
    cust.type("#fCode", code)
    cust.click("#fVerify")
    page.wait_for_url(re.compile(r"/support/t/"))
    page.get_by_text(T_CUST).first.wait_for()
    S["status_path"] = urlparse(page.url).path
    S["status_token"] = S["status_path"].rsplit("/", 1)[1]
    S["cust"] = re.search(r"T-\d{4,}", page.locator("#h1").inner_text()).group(0)
    t = _ticket(tm, S["cust"])
    assert t["kind"] == "external" and t["title"] == T_CUST
    _log(f"customer ticket {S['cust']}")
    _done("p_request")


@personal_only
def test_SD_P03_owner_files_own_todo_due_wednesday(tm, page):
    _need("p_setup")
    _at(tm, 0, "09:30")
    app = Desk(page, tm).open()
    app.click("#fab")
    page.select_option("#nKind", "internal")
    app.type("#nTitle", T_TODO)
    page.fill("#nDue", _day(2).isoformat())
    app.click("#nGo")
    S["todo"] = app.filed_id()
    page.locator(".id", has_text=S["todo"]).wait_for()        # the ticket's own page is open
    chip = page.locator(".chip", has_text="due ").first
    chip.wait_for()
    assert "late" not in (chip.get_attribute("class") or "")
    t = _ticket(tm, S["todo"])
    assert t["kind"] == "internal" and _local(t["due_resolve_at"]).date() == _day(2)
    _done("p_todo")


@personal_only
def test_SD_P04_morning_digest_once_a_day_to_the_owner(tm):
    _need("p_todo")

    def digests(after):
        return _emails(tm, after, subject="Service Desk — today")

    _at(tm, 1, "06:30")                                   # Tuesday, before digest_hour 7
    n = len(tm.outbox())
    assert "digest" not in tm.desk_tick()
    _at(tm, 1, "07:05")
    did = tm.desk_tick()
    assert did.get("digest") is False and digests(n) == [], "nothing due Tuesday — no email"

    _at(tm, 2, "07:05")                                   # Wednesday: the to-do is due today
    n = len(tm.outbox())
    assert tm.desk_tick().get("digest") is True
    m = tm.wait_outbox(lambda m: m["kind"] == "email" and "Service Desk — today" in m["subject"], after=n)
    assert m["to"] == OWNER_EMAIL and "Due today" in m["body"] and S["todo"] in m["body"]
    _at(tm, 2, "08:00")
    assert "digest" not in tm.desk_tick(), "one digest a day"

    _at(tm, 3, "07:05")                                   # Thursday: now it's overdue
    n = len(tm.outbox())
    assert tm.desk_tick().get("digest") is True
    m = tm.wait_outbox(lambda m: m["kind"] == "email" and "Service Desk — today" in m["subject"], after=n)
    assert "Overdue" in m["body"] and S["todo"] in m["body"]
    assert len(digests(n)) == 1
    _done("p_digest")


@personal_only
def test_SD_P05_overdue_todo_shows_late_in_the_app(tm, page):
    _need("p_digest")
    _at(tm, 3, "08:00")
    app = Desk(page, tm).open()
    app.tab("overdue")
    c = app.card(S["todo"])
    c.wait_for()
    assert c.locator(".chip.late").count() == 1, "the overdue to-do should carry the late chip"
    if "cust" in S:
        assert app.card(S["cust"]).count() == 0, "a ticket with no due date is never overdue"
    _done("p_overdue")


@personal_only
def test_SD_P06_owner_marks_the_customer_ticket_fixed(tm, page):
    _need("p_request")
    _at(tm, 3, "10:00")
    app = Desk(page, tm).open()
    app.tab("mine")
    app.open_ticket(S["cust"])
    app.click("[data-move='In Progress']")
    _wait_state(tm, S["cust"], "In Progress")
    app.click("[data-move='Fixed']")
    t = _wait_state(tm, S["cust"], "Fixed")
    S["fixed_at"] = _local(t["fixed_at"])
    _log(f"{S['cust']} Fixed at {S['fixed_at']}")
    _done("p_fixed")


@personal_only
def test_SD_P07_three_quiet_days_close_it_by_itself(tm):
    _need("p_fixed")
    due = S["fixed_at"] + dt.timedelta(days=3)
    for when in (S["fixed_at"] + dt.timedelta(days=1), S["fixed_at"] + dt.timedelta(days=2),
                 due - dt.timedelta(minutes=10)):
        _go(tm, when)
        did = tm.desk_tick()
        assert S["cust"] not in did.get("auto_closed", []), f"closed too early ({when:%a %H:%M})"
        assert _ticket(tm, S["cust"])["state"] == "Fixed"
    _go(tm, due + dt.timedelta(minutes=10))
    did = tm.desk_tick()
    assert did.get("auto_closed") == [S["cust"]], did
    t = _ticket(tm, S["cust"])
    assert t["state"] == "Closed" and "automatically" in (t.get("close_reason") or ""), t.get("close_reason")
    S["closed_at"] = _local(t["closed_at"])
    _done("p_autoclosed")


@personal_only
def test_SD_P08_customer_reopens_from_the_status_link_within_7_days(tm, page):
    _need("p_autoclosed")
    _go(tm, S["closed_at"] + dt.timedelta(days=2))
    cust = Person(page, tm)
    cust.goto(S["status_path"])
    page.locator(".chip.st", has_text="Closed").wait_for()
    assert page.locator("#reopen").is_visible(), "inside 7 days the customer can reopen"
    cust.answer("ZTEST the streaks came back after the rain")
    cust.click("#reopen")
    page.locator(".chip.st", has_text="Assigned").wait_for()
    t = _ticket(tm, S["cust"])
    assert t["state"] == "Assigned" and not t.get("closed_at")
    # the owner fixes it again; this time the customer confirms right away
    for s in ("In Progress", "Fixed"):
        st, d = tm.desk("POST", f"/tickets/{S['cust']}/state", {"to_state": s})
        assert st == 200, (st, d)
    cust.goto(S["status_path"])
    cust.click("#yes")
    page.locator(".chip.st", has_text="Closed").wait_for()
    t = _wait_state(tm, S["cust"], "Closed")
    S["closed2"] = _local(t["closed_at"])
    _done("p_reopened")


@personal_only
def test_SD_P09_after_7_days_the_customer_cannot_reopen(tm, page):
    _need("p_reopened")
    _go(tm, S["closed2"] + dt.timedelta(days=8))
    cust = Person(page, tm)
    cust.goto(S["status_path"])
    page.locator(".chip.st", has_text="Closed").wait_for()
    assert page.locator("#reopen").count() == 0, "the reopen button should be gone after 7 days"
    st, d = _portal(tm, "POST", f"/t/{S['status_token']}/state",
                    {"to_state": "Assigned", "reason": "ZTEST still streaky"})
    assert st in (400, 403) and "7 days" in d.get("message", ""), (st, d)
    assert _ticket(tm, S["cust"])["state"] == "Closed"
    _done("p_window")


@personal_only
def test_SD_P10_status_link_works_29_days_after_close_not_31(tm, page):
    _need("p_window")
    cust = Person(page, tm)
    _go(tm, S["closed2"] + dt.timedelta(days=29))
    cust.goto(S["status_path"])
    page.get_by_text(T_CUST).first.wait_for()
    _go(tm, S["closed2"] + dt.timedelta(days=31))
    cust.goto(S["status_path"])
    page.locator(".card.err", has_text="not valid").wait_for()
    _done("p_link")


@personal_only
def test_SD_P11_import_undo_works_on_day_6_not_day_8(tm, page):
    _need("p_link")
    k = (S["closed2"] + dt.timedelta(days=32)).date()
    tm.set_clock(k, "09:00")
    # batch A: imported in the app (dry run first), undone 6 days later in the app
    csv_a = Path(tempfile.gettempdir()) / f"ztest_sd_import_{uuid.uuid4().hex[:6]}.csv"
    csv_a.write_text("Title,Description\nZTEST SD imported A1,old system\nZTEST SD imported A2,old system\n",
                     encoding="utf-8")
    app = Desk(page, tm).open()
    app.tab("settings")
    page.set_input_files("#impFile", str(csv_a))
    app.click("#impDry")
    page.locator("#impOut", has_text="Dry run").wait_for()
    app.answer(True)                                       # "Import now? A backup is taken first."
    app.click("#impGo")
    page.locator("#impOut", has_text="Imported as").wait_for()
    batch_a = re.search(r"Imported as (\S+) ", page.locator("#impOut").inner_text()).group(1)
    # batch B: imported the same morning (no browser needed)
    out_b = _import_csv(tm, "ztest_b.csv", "Title\nZTEST SD imported B1\n")
    batch_b = out_b["batch_id"]
    assert batch_a != batch_b

    tm.set_clock(k + dt.timedelta(days=6), "09:00")
    app.open()                                             # same page, clock moved: open again
    app.tab("settings")
    app.type("#undoId", batch_a)
    app.answer(True)                                       # "Remove every ticket imported in …?"
    app.click("#undoGo")
    app.toast("Removed 2 ticket(s)")

    tm.set_clock(k + dt.timedelta(days=8), "09:00")
    st, d = tm.desk("POST", "/import/undo", {"batch_id": batch_b})
    assert st == 400 and "7 days" in d.get("message", ""), (st, d)
    titles = {t["title"] for t in tm.desk("GET", "/tickets?open_only=0&limit=500")[1]["tickets"]}
    assert "ZTEST SD imported B1" in titles and not {"ZTEST SD imported A1", "ZTEST SD imported A2"} & titles
    S["after_import"] = k + dt.timedelta(days=8)
    _done("p_import")


@personal_only
def test_SD_P12_nightly_backups_retention_and_failure_alert(tm, page):
    _need("p_import")
    start = S["after_import"] + dt.timedelta(days=1)
    tm.set_clock(start, "09:00")
    app = Desk(page, tm).open()
    app.tab("settings")
    page.locator("#bkD").wait_for()
    for sel, v in (("#bkD", "3"), ("#bkW", "1"), ("#bkM", "1"), ("#bkHour", "2")):
        app.type(sel, v)
    app.click("#bkSave")
    app.toast("Saved")
    s = tm.desk("GET", "/backups")[1]["settings"]
    assert (s["backup_keep_daily"], s["backup_keep_weekly"], s["backup_keep_monthly"]) == (3, 1, 1)

    nights = [start + dt.timedelta(days=i) for i in range(1, 7)]
    for night in nights:                                   # six nights at 02:05, then 03:00
        tm.set_clock(night, "02:05")
        did = tm.desk_tick()
        assert str(did.get("backup", "")).startswith("desk-"), (night, did)
        tm.set_clock(night, "03:00")
        assert "backup" not in tm.desk_tick(), "one scheduled backup a night"
    sched = [b for b in tm.desk("GET", "/backups")[1]["backups"] if b["trigger"] == "scheduled"]
    assert sorted(b["made_at"][:10] for b in sched) == [n.isoformat() for n in nights[-3:]], sched
    assert all(b["verified"] for b in sched)
    assert any(b["trigger"] == "pre-import" for b in tm.desk("GET", "/backups")[1]["backups"]), \
        "safety backups (before an import) are kept 30 days"

    # The backup folder becomes unusable (a file where the folder should be).
    bdir = _desk_root(tm) / "backups"
    held = bdir.with_name("backups_ztest_held")
    bdir.rename(held)
    bdir.write_text("ZTEST: not a folder", encoding="utf-8")
    try:
        n = len(tm.outbox())
        tm.set_clock(nights[-1] + dt.timedelta(days=1), "02:05")
        assert "backup_error" in tm.desk_tick()
        assert _emails(tm, n, subject="backup problem") == [], "one failed night is not an alert yet"
        tm.set_clock(nights[-1] + dt.timedelta(days=2), "02:05")
        assert "backup_error" in tm.desk_tick()
        m = tm.wait_outbox(lambda m: m["kind"] == "email" and "backup problem" in m["subject"], after=n)
        assert m["to"] == OWNER_EMAIL and "2 times" in m["body"], m
    finally:
        bdir.unlink()
        held.rename(bdir)
    tm.set_clock(nights[-1] + dt.timedelta(days=3), "02:05")
    assert str(tm.desk_tick().get("backup", "")).startswith("desk-"), "backups recover by themselves"
    _done("p_backups")


# ══════════════════════════ SERVER (Business) ═════════════════════════════════
@server_only
def test_SD_B01_manager_files_customer_ticket_and_assigns_crew(tm, page):
    _need("dates")
    _at(tm, 0, "10:00")
    st, d = tm.desk("POST", "/tickets", {"kind": "internal", "title": T_UNASSIGNED}, key="staff")
    assert st == 201 and not d["ticket"]["assignee"], (st, d)
    S["unassigned"] = d["ticket"]["ticket_id"]

    mgr = Desk(page, tm, "manager").open()
    mgr.click("#fab")
    page.select_option("#nKind", "external")
    mgr.type("#nTitle", T_GUTTER)
    mgr.type("#nName", "ZTEST Mr Hale")
    mgr.type("#nPhone", HALE_PHONE)
    page.select_option("#nPri", "P2")
    mgr.click("#nGo")
    S["gutter"] = tid = mgr.filed_id()
    page.locator("#asg").wait_for()
    n = len(tm.outbox())
    mgr.type("#asg", S["ids"]["alex"])
    mgr.click("#asgGo")
    mgr.toast("Saved")
    t = _ticket(tm, tid)
    assert t["assignee"] == S["ids"]["alex"] and t["priority"] == "P2"
    created = _local(t["created_at"])
    resp, fix = _local(t["due_response_at"]), _local(t["due_resolve_at"])
    # P2: first reply in 4 business hours (same day), fix in 2 business days
    # (Monday mid-morning + 18 business hours = Wednesday, same time)
    assert abs((resp - created) - dt.timedelta(hours=4)) <= dt.timedelta(minutes=1), (created, resp)
    assert abs((fix - created) - dt.timedelta(hours=48)) <= dt.timedelta(minutes=1), (created, fix)
    m = tm.wait_outbox(lambda m: m["kind"] == "email" and m["to"] == "alex@time-machine.test"
                       and "assigned to you" in m["subject"], after=n)
    assert tid in m["subject"]
    S.update(created=created, resp_due=resp)
    _done("b_filed")


@server_only
def test_SD_B02_sla_warning_breach_escalation_each_once(tm):
    _need("b_filed")
    tid, c, due = S["gutter"], S["created"], S["resp_due"]
    span = due - c

    def tick_at(when):
        _go(tm, when)
        return _flags(tm.desk_tick(), tid)

    assert tick_at(c + span * 0.5) == set(), "half way: nothing yet"
    n = len(tm.outbox())
    assert tick_at(c + span * 0.8) == {"response_warn"}
    tm.wait_outbox(lambda m: m["kind"] == "email" and m["to"] == "alex@time-machine.test"
                   and "first reply is due soon" in m["subject"], after=n)
    assert tick_at(c + span * 0.95) == set(), "a warning is sent once"
    n = len(tm.outbox())
    assert tick_at(due + dt.timedelta(minutes=5)) == {"response_breach"}
    tm.wait_outbox(lambda m: m["kind"] == "email" and m["to"] == "alex@time-machine.test"
                   and "first reply is OVERDUE" in m["subject"], after=n)
    n = len(tm.outbox())
    assert tick_at(c + span * 2 + dt.timedelta(minutes=5)) == {"escalated"}
    tm.wait_outbox(lambda m: m["kind"] == "email" and "ESCALATED" in m["subject"], after=n)
    time.sleep(1.5)                                       # let every alert land
    told = {m["to"] for m in _emails(tm, n, subject="ESCALATED")}
    assert told == {"owner@time-machine.test", "manager@time-machine.test"}, told
    assert tick_at(c + span * 2 + dt.timedelta(minutes=40)) == set(), "escalated once"
    _done("b_sla")


@server_only
def test_SD_B03_morning_digest_to_owner_and_manager_once(tm):
    _need("b_sla")
    _at(tm, 1, "06:50")
    assert "digest" not in tm.desk_tick(), "not before 7:00"
    n = len(tm.outbox())
    _at(tm, 1, "07:05")
    assert tm.desk_tick().get("digest") is True
    tm.wait_outbox(lambda m: m["kind"] == "email" and "Service Desk — today" in m["subject"], after=n)
    time.sleep(1.5)
    got = _emails(tm, n, subject="Service Desk — today")
    assert {m["to"] for m in got} == {"owner@time-machine.test", "manager@time-machine.test"}, got
    assert all("Not assigned yet" in m["body"] and S["unassigned"] in m["body"] for m in got)
    _at(tm, 1, "07:40")
    assert "digest" not in tm.desk_tick(), "one digest a day"
    _done("b_digest")


@server_only
def test_SD_B04_crew_replies_to_the_customer_then_puts_it_on_hold(tm, page):
    _need("b_digest")
    tid = S["gutter"]
    _at(tm, 1, "08:30")
    crew = Desk(page, tm, "alex").open()
    crew.tab("mine")
    crew.open_ticket(tid)
    crew.click("[data-move='In Progress']")
    _wait_state(tm, tid, "In Progress")
    page.locator("#msg").wait_for()
    n = len(tm.outbox())
    crew.type("#msg", "ZTEST We'll clear it Thursday morning — waiting on a gutter guard")
    page.select_option("#msgVis", "public")
    crew.click("#msgGo")
    tm.wait_outbox(lambda m: m["kind"] == "sms" and m["to"].endswith(HALE_DIGITS)
                   and "Thursday" in m["body"], after=n)
    crew.answer("ZTEST waiting on the gutter guard part")
    crew.click("[data-move='On Hold']")
    t = _wait_state(tm, tid, "On Hold")
    assert t.get("first_response_at"), "the public reply counts as the first response"
    S["fix_due_before_hold"] = _local(t["due_resolve_at"])
    _done("b_hold")


@server_only
def test_SD_B05_on_hold_stops_the_clock_and_moves_the_due_time(tm, page):
    _need("b_hold")
    tid, due0 = S["gutter"], S["fix_due_before_hold"]
    for when in (S["created"] + (due0 - S["created"]) * 0.8,       # would have been a fix warning
                 due0 + dt.timedelta(hours=1)):                       # ...and a breach
        _go(tm, when)
        assert _flags(tm.desk_tick(), tid) == set(), f"on hold, nothing may fire ({when:%a %H:%M})"
    _at(tm, 3, "08:30")                                               # Thursday: back to work
    crew = Desk(page, tm, "alex").open()
    crew.tab("mine")
    crew.open_ticket(tid)
    crew.click("[data-move='In Progress']")
    t = _wait_state(tm, tid, "In Progress")
    moved = _local(t["due_resolve_at"]) - due0
    assert dt.timedelta(hours=47, minutes=30) <= moved <= dt.timedelta(hours=48, minutes=30), \
        f"the fix due should move ~2 days (time on hold), moved {moved}"
    S["fix_due"] = _local(t["due_resolve_at"])
    _done("b_resumed")


@server_only
def test_SD_B06_fix_warning_then_breach_after_the_moved_due_time(tm):
    _need("b_resumed")
    tid, c, due = S["gutter"], S["created"], S["fix_due"]
    n = len(tm.outbox())
    _go(tm, c + (due - c) * 0.8)
    assert _flags(tm.desk_tick(), tid) == {"resolve_warn"}
    tm.wait_outbox(lambda m: m["kind"] == "email" and m["to"] == "alex@time-machine.test"
                   and "fix is due soon" in m["subject"], after=n)
    _go(tm, due - dt.timedelta(minutes=10))
    assert _flags(tm.desk_tick(), tid) == set(), "not late before the moved due time"
    n = len(tm.outbox())
    _go(tm, due + dt.timedelta(minutes=10))
    assert _flags(tm.desk_tick(), tid) == {"resolve_breach"}
    tm.wait_outbox(lambda m: m["kind"] == "email" and m["to"] == "alex@time-machine.test"
                   and "fix is OVERDUE" in m["subject"], after=n)
    _done("b_breach")


@server_only
def test_SD_B07_manager_sees_it_overdue_and_two_sla_misses(tm, page):
    _need("b_breach")
    _go(tm, S["fix_due"] + dt.timedelta(minutes=30))
    mgr = Desk(page, tm, "manager").open()
    mgr.tab("overdue")
    c = mgr.card(S["gutter"])
    c.wait_for()
    assert c.locator(".chip.late").count() == 1
    mgr.tab("reports")
    row = page.locator("tr", has_text=S["ids"]["alex"]).first
    row.wait_for()
    cells = row.locator("td")
    assert cells.nth(6).inner_text().strip() == "2", \
        f"SLA misses for {S['ids']['alex']}: {cells.all_inner_texts()} (first reply + fix)"
    _done("b_report")


@server_only
def test_SD_B08_quiet_customer_auto_close_then_reopen_tells_the_crew(tm, page):
    _need("b_report")
    tid = S["gutter"]
    _go(tm, S["fix_due"] + dt.timedelta(hours=1))
    st, d = tm.desk("POST", f"/tickets/{tid}/state", {"to_state": "Fixed"}, key="alex")
    assert st == 200, (st, d)
    fixed = _local(_ticket(tm, tid)["fixed_at"])          # the reply is the trimmed list row
    st, d = tm.desk("POST", f"/tickets/{tid}/link", {}, key="manager")   # the customer's status link
    assert st == 200 and "/support/" in d.get("url", ""), (st, d)
    path = "/support/" + d["url"].split("/support/", 1)[1]           # the link's path, on the sandbox
    _go(tm, fixed + dt.timedelta(days=3) - dt.timedelta(minutes=10))
    assert tid not in tm.desk_tick().get("auto_closed", []), "not a minute early"
    _go(tm, fixed + dt.timedelta(days=3, minutes=10))
    assert tid in tm.desk_tick().get("auto_closed", [])
    t = _ticket(tm, tid)
    assert t["state"] == "Closed" and "automatically" in (t.get("close_reason") or "")

    _go(tm, _local(t["closed_at"]) + dt.timedelta(days=2))
    cust = Person(page, tm)
    cust.goto(path)
    page.locator(".chip.st", has_text="Closed").wait_for()
    n = len(tm.outbox())
    cust.answer("ZTEST it overflowed again in the storm")
    cust.click("#reopen")
    page.locator(".chip.st", has_text="Assigned").wait_for()
    t = _ticket(tm, tid)
    assert t["state"] == "Assigned" and t["assignee"] == S["ids"]["alex"], "a reopen goes back to its owner"
    tm.wait_outbox(lambda m: m["kind"] == "email" and m["to"] == "alex@time-machine.test"
                   and "reopened" in m["subject"], after=n)
    _done("b_reopen")


def test_SD_99_nothing_left_the_sandbox(tm):
    """Every Service Desk message went to the outbox; none tried the internet."""
    _need("dates")
    blocked = [m for m in tm.outbox() if m.get("kind") == "blocked_http"]
    assert not blocked, f"the sandbox tried to reach: {blocked[:5]}"
    for m in tm.outbox():                                 # same rule as the other stories
        if m.get("kind") in ("email", "sms", "whatsapp"):
            assert "time-machine" in m["to"] or m["to"].startswith("+1555"), f"a message to a real address: {m}"
    desk_msgs = [m for m in tm.outbox() if "Service Desk" in (m.get("subject") or "") + (m.get("body") or "")
                 or "ZTEST SD" in (m.get("subject") or "") + (m.get("body") or "")]
    _log(f"Service Desk messages caught in the outbox: {len(desk_msgs)}")
    assert desk_msgs, "the story should have produced Service Desk alerts"
