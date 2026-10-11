"""TIME MACHINE — Reports across a whole year: revenue, tax and hours, actual
and projected, checked week by week (personal mode, spec §6.8 / §6.19).

David 2026-10-09: "create new tests for the personal Jobs app that check if
the reports are correct for revenue, Hours, Taxes — recurring jobs in the past
and future that show across the year with actual revenue and projected
revenue in the charts, same for Hours and Taxes". Rules (David, same day):
today's Reports rules stay, and the calendar's 🔮 recurring visits are added
to PROJECTED.

  Revenue  actual    = money paid on the job's invoice (any status)
           projected = still owed on every non-cancelled job:
                         invoiced     -> TOTAL DUE − Amount Paid
                         not invoiced -> Quote − Discount (pre-tax)
                         the sweep's unpriced auto-listed recurring job ->
                                         the customer's Net Price
                       + every 🔮 recurring visit (customer's Net Price)
  Tax      actual    = invoice tax × paid/TOTAL DUE   (No Sales Tax -> 0)
           projected = the rest of the invoice tax, + 7% on each 🔮 visit
                       and each unpriced auto-listed recurring job
  Hours    actual    = Complete jobs (Actual Duration, else Est.)
           projected = every other non-cancelled job (Est.)
                       + each 🔮 visit (customer's Avg Job Duration)
  🔮 visits = exactly the calendar's: Last Service Date + Frequency, after
  today, up to 12 months out, skipped where that customer already has a real
  non-cancelled job that day.

Its OWN throwaway copy of the app (not the six-weeks sandbox), so moving the
clock across months can't disturb that story. The story:
  TR-01  day -1: the business is set up — four recurring customers with past
         visits (paid, unpaid, partly paid, never invoiced, tax-exempt), an
         inactive customer, a one-off job with a deposit, a rescheduled
         recurring visit, a cancelled job.
  TR-02  day 0: the calendar's 🔮 visits are exactly the oracle's, and every
         one of the 53 weeks (26 back, 26 ahead) of Reports — table AND the
         three charts — matches the oracle; a few weeks also hand-checked.
  TR-03  six weeks of work, one day at a time: each morning the app is opened
         (the recurring sweep runs), each auto-listed visit due that day is
         done, invoiced at 7% and paid (one left unpaid), the one-off job is
         done on its day.
  TR-04  day 42: calendar + all 53 weeks again — what was projected is now
         actual, new 🔮 visits have rolled into the year.

The oracle (expected_weeks / expected_projections below) is the rules above
written again in Python from the raw database rows — not the page's code.

Run: run_tests_gui_jobs_e2e.bat --timemachine --human -k test_tm_reports_year
"""
from __future__ import annotations

import calendar
import datetime as dt
import logging
import os
import re
import sys
from pathlib import Path

import pytest
from playwright.sync_api import expect

from api import ApiClient, iso_date

# This folder's conftest (already loaded by pytest). Found by path: a plain
# "import conftest" can pick up another suite's conftest.py of the same name.
_HERE = Path(__file__).resolve().parent
_tmc = next(m for m in list(sys.modules.values())
            if getattr(m, "__file__", None) and Path(m.__file__).resolve() == _HERE / "conftest.py")
RUN_DIR, TimeMachine, _OpenGuard = _tmc.RUN_DIR, _tmc.TimeMachine, _tmc._OpenGuard
_api_log, _log, next_monday = _tmc._api_log, _tmc._log, _tmc.next_monday

log = logging.getLogger("e2e")
MODE = (os.environ.get("E2E_TM_MODE") or "personal").strip().lower()
pytestmark = pytest.mark.skipif(MODE != "personal", reason="Reports year story is personal mode")

OWNER = "David Vavro"
WEEKS_EACH = 26                       # the Reports selector's widest range (~ a year)
WALK_DAYS = 42                        # TR-03: six weeks of work
TAX = 0.07
LEAD_DAYS = 5
AUTO_NOTE = "Auto-generated recurring job"
JOB_ID = "JobID (JOB-####)"
CUST_ID = "CustomerID (CUST-####)"

# key: (company, frequency, net price $, avg job minutes, active)
CUST = {
    "W": ("ZR Weekly Wash",       "Weekly",    100,  60, True),
    "B": ("ZR Biweekly Bistro",   "Biweekly",  200,  90, True),
    "M": ("ZR Monthly Mall",      "Monthly",   300, 120, True),
    "Q": ("ZR Quarterly Quay",    "Quarterly", 400, 240, True),
    "I": ("ZR Inactive Inn",      "Monthly",   500,  60, False),
    "O": ("ZR One-off Office",    "",          250, 120, True),
}


# ── small helpers ────────────────────────────────────────────────────────────
def _money(v) -> float:
    m = re.search(r"-?[\d,]*\.?\d+", str(v if v is not None else ""))
    return float(m.group(0).replace(",", "")) if m else 0.0


def _blank(v) -> bool:
    return str(v if v is not None else "").strip() == ""


def _add_months(d: dt.date, n: int) -> dt.date:
    """Month step clamped to month end (Jan 31 -> Feb 28) — the sweep's rule."""
    y, m = divmod(d.month - 1 + n, 12)
    y, m = d.year + y, m + 1
    return dt.date(y, m, min(d.day, calendar.monthrange(y, m)[1]))


def _step(d: dt.date, freq: str) -> dt.date:
    f = re.sub(r"[^a-z]", "", freq.lower())
    if f == "weekly":
        return d + dt.timedelta(days=7)
    if f == "biweekly":
        return d + dt.timedelta(days=14)
    return _add_months(d, {"monthly": 1, "bimonthly": 2, "quarterly": 3, "semiannually": 6,
                           "semiannual": 6, "annually": 12, "annual": 12}[f])


def _monday(d: dt.date) -> dt.date:
    return d - dt.timedelta(days=d.weekday())


def _label(d: dt.date) -> str:
    m = _monday(d)
    return f"{m.month}/{m.day}"


def _key(row: dict, *prefixes) -> str:
    """The value of the first column whose header starts with one of prefixes."""
    for p in prefixes:
        for k, v in row.items():
            if k.startswith(p):
                return v
    return ""


def _no_sales_tax(v) -> bool:
    return str(v if v is not None else "").strip().lower() in ("1", "1.0", "true", "yes", "y", "x")


# ── the oracle ───────────────────────────────────────────────────────────────
def expected_projections(today: dt.date, customers: list[dict], jobs: list[dict]) -> list[dict]:
    """The calendar's 🔮 visits, from the raw Customers/Jobs rows."""
    real = set()
    for j in jobs:
        if (j.get("Job Status") or "").strip().lower() == "cancelled":
            continue
        d = iso_date(j.get("Service Date", ""))
        if d:
            real.add((d, (j.get("CustomerID (Customers!A)") or j.get("CustomerID") or "").strip()))
    # the calendar: horizon = same day 12 months on; visits strictly after today
    horizon = _add_months(today, 12)
    out = []
    for c in customers:
        if (c.get("Status Active/Inactive") or "").strip().lower() == "inactive":
            continue
        freq = (c.get("Frequency") or "").strip()
        last = iso_date(c.get("Last Service Date", ""))
        if not freq or not last or not (c.get("Company Name") or "").strip():
            continue
        cid = (c.get(CUST_ID) or "").strip()
        d = dt.date.fromisoformat(last)
        for _ in range(60):
            d = _step(d, freq)
            if d > horizon:
                break
            if d <= today or (d.isoformat(), cid) in real:
                continue
            value = _customer_value(c)
            out.append({"date": d, "cust": cid, "revenue": value, "tax": round(value * TAX, 2),
                        "hours": _money(c.get("Avg Job Duration (min)")) / 60})
    return out


def _customer_value(c: dict) -> float:
    v = _money(c.get("Net Price ($)"))
    if not v:
        sq = _money(c.get("Standard Quote ($)"))
        v = sq - sq * _money(c.get("Discount (%)")) / 100
    return max(0.0, v)


def _hours(value, unit) -> float:
    n = _money(value)
    return n if str(unit or "min").strip().lower().startswith("h") else n / 60


def expected_weeks(today: dt.date, jobs, invoices, customers) -> dict[str, dict]:
    """label -> {actual_rev, proj_rev, actual_tax, proj_tax, actual_hrs, proj_hrs, current}"""
    weeks = {}
    for i in range(-WEEKS_EACH, WEEKS_EACH + 1):
        mon = _monday(today + dt.timedelta(days=7 * i))
        weeks.setdefault(mon, {"actual_rev": 0.0, "proj_rev": 0.0, "actual_tax": 0.0, "proj_tax": 0.0,
                               "actual_hrs": 0.0, "proj_hrs": 0.0, "current": mon == _monday(today)})
    inv_by_job = {}
    for inv in invoices:
        jid = inv.get(JOB_ID)
        if jid:
            inv_by_job[jid] = {"total": _money(_key(inv, "TOTAL DUE")), "paid": _money(_key(inv, "Amount Paid")),
                               "tax": _money(_key(inv, "Tax 7%", "Tax ("))}
    cust_by_id = {(c.get(CUST_ID) or "").strip(): c for c in customers}
    for j in jobs:
        status = (j.get("Job Status") or "").strip()
        if status == "Cancelled":
            continue
        d = iso_date(j.get("Service Date", ""))
        if not d:
            continue
        w = weeks.get(_monday(dt.date.fromisoformat(d)))
        if w is None:
            continue
        inv = inv_by_job.get(j.get(JOB_ID))
        exempt = _no_sales_tax(j.get("No Sales Tax"))
        if inv:
            w["actual_rev"] += inv["paid"]
            w["proj_rev"] += max(0.0, inv["total"] - inv["paid"])
            tax = 0.0 if exempt else inv["tax"]
            if tax > 0:
                got = tax * (inv["paid"] / inv["total"]) if inv["total"] > 0 else 0.0
                w["actual_tax"] += got
                w["proj_tax"] += max(0.0, tax - got)
        elif AUTO_NOTE in (j.get("Service Details / Notes") or "") and _blank(j.get("Quote Amount ($)")):
            c = cust_by_id.get((j.get("CustomerID (Customers!A)") or j.get("CustomerID") or "").strip())
            value = _customer_value(c) if c else 0.0
            w["proj_rev"] += value
            if not exempt:
                w["proj_tax"] += round(value * TAX, 2)
        else:
            w["proj_rev"] += max(0.0, _money(j.get("Quote Amount ($)")) - _money(j.get("Discount Applied ($)")))
        if status == "Complete":
            w["actual_hrs"] += (_hours(j.get("Actual Duration"), j.get("Actual Duration Unit"))
                                if not _blank(j.get("Actual Duration"))
                                else _hours(j.get("Est. Duration"), j.get("Est. Duration Unit")))
        else:
            w["proj_hrs"] += _hours(j.get("Est. Duration"), j.get("Est. Duration Unit"))
    for p in expected_projections(today, customers, jobs):
        w = weeks.get(_monday(p["date"]))
        if w is not None:
            w["proj_rev"] += p["revenue"]
            w["proj_tax"] += p["tax"]
            w["proj_hrs"] += p["hours"]
    return {_label(mon): v for mon, v in sorted(weeks.items())}


# ── reading the screens ──────────────────────────────────────────────────────
def _read_reports(app, page) -> dict:
    app.goto("reports")
    expect(page.locator("#reportsContent table tbody tr").first).to_be_visible(timeout=30_000)
    app.log(f"REPORTS weeks each direction → {WEEKS_EACH}")
    page.locator("#reportsWeeksSelect").select_option(str(WEEKS_EACH))
    expect(page.locator("#reportsContent table tbody tr")).to_have_count(2 * WEEKS_EACH + 1, timeout=30_000)
    page.wait_for_timeout(800)
    return page.evaluate(r"""() => {
      const num = s => { const m = String(s).replace(/,/g,'').match(/-?\d+(\.\d+)?/); return m ? parseFloat(m[0]) : 0; };
      const rows = [...document.querySelectorAll('#reportsContent table tbody tr')].map(tr => {
        const c = [...tr.querySelectorAll('td')].map(td => td.innerText.trim());
        return {label: c[0].replace(' (this week)', ''), current: c[0].includes('(this week)'),
                actual_rev: num(c[1]), proj_rev: num(c[2]), total_rev: num(c[3]),
                actual_tax: num(c[4]), proj_tax: num(c[5]), total_tax: num(c[6]),
                actual_hrs: num(c[7]), proj_hrs: num(c[8]), total_hrs: num(c[9])};
      });
      const charts = [...document.querySelectorAll('#reportsContent svg')].map(svg => {
        const bars = {};
        svg.querySelectorAll('rect > title').forEach(t => {
          const m = t.textContent.match(/^(.+?) \u2014 (actual|projected): (.+)$/);
          if (m) (bars[m[1]] = bars[m[1]] || {})[m[2]] = num(m[3]);
        });
        return bars;
      });
      return {rows, charts, titles: [...document.querySelectorAll('#reportsContent .card-title')].map(e => e.textContent)};
    }""")


def _read_calendar_projections(app, page) -> list[dict]:
    app.goto("calendar")
    expect(page.locator("#calendarContent .spinner")).to_have_count(0, timeout=30_000)
    page.wait_for_function("() => !!window._calLastByDate", timeout=30_000)
    return page.evaluate("""() => {
      const out = [];
      Object.values(window._calLastByDate || {}).forEach(list => (list || []).forEach(j => {
        if (j && j.projected) out.push({date: j.date, cust: j.custId || ''});
      }));
      return out;
    }""")


def _js_round(v: float, places: int) -> float:
    """What toFixed(places) shows for our values (all amounts here are exact)."""
    q = 10 ** places
    return int(v * q + 0.5 + 1e-9) / q


def check_calendar_and_reports(w, app, page, when: str):
    today = w.tm.today()
    jobs, invoices, customers = w.read_all()
    # 1. the calendar's 🔮 visits are exactly the oracle's
    want_proj = sorted((p["date"].isoformat(), p["cust"]) for p in expected_projections(today, customers, jobs))
    got_proj = sorted((p["date"], p["cust"]) for p in _read_calendar_projections(app, page))
    w.check(got_proj == want_proj,
            f"{when}: calendar 🔮 visits differ from the oracle\n  missing {sorted(set(want_proj) - set(got_proj))[:10]}"
            f"\n  extra   {sorted(set(got_proj) - set(want_proj))[:10]}")
    app.log(f"{when}: calendar shows {len(got_proj)} 🔮 recurring visits (12 months) — as expected")
    # 2. every week of Reports, table and charts
    want = expected_weeks(today, jobs, invoices, customers)
    got = _read_reports(app, page)
    w.last_reports[when] = (want, got)
    rows = {r["label"]: r for r in got["rows"]}
    assert list(rows) == list(want), f"{when}: Reports weeks {list(rows)[:3]}… expected {list(want)[:3]}…"
    bad = []
    for label, e in want.items():
        r = rows[label]
        if r["current"] != e["current"]:
            bad.append(f"{label}: '(this week)' marker wrong")
        for k, places in (("actual_rev", 0), ("proj_rev", 0), ("actual_tax", 0), ("proj_tax", 0),
                          ("actual_hrs", 1), ("proj_hrs", 1)):
            if abs(r[k] - _js_round(e[k], places)) > 0.001:
                bad.append(f"{label} {k}: shows {r[k]}, expected {_js_round(e[k], places)} (exact {round(e[k], 2)})")
    # charts: revenue, tax, hours — a bar is drawn when it's > 0.5px of a 130px chart
    for ci, (name, a, p_, rnd) in enumerate((("Revenue", "actual_rev", "proj_rev", 0),
                                             ("Tax", "actual_tax", "proj_tax", 0),
                                             ("Hours", "actual_hrs", "proj_hrs", 1))):
        bars = got["charts"][ci]
        top = max((e[a] + e[p_]) for e in want.values()) or 1
        for label, e in want.items():
            for kind, k in (("actual", a), ("projected", p_)):
                drawn = (bars.get(label) or {}).get(kind)
                should = e[k] / top * 130 > 0.5
                if should and drawn is None:
                    bad.append(f"{name} chart {label}: no {kind} bar, expected {round(e[k], 2)}")
                elif not should and drawn is not None:
                    bad.append(f"{name} chart {label}: {kind} bar {drawn} drawn, expected none")
                elif should and abs(drawn - (round(e[k]) if rnd == 0 else round(e[k], 1))) > 0.001:
                    bad.append(f"{name} chart {label}: {kind} bar {drawn}, expected {round(e[k], 2)}")
    tot = {k: round(sum(e[k] for e in want.values()), 2)
           for k in ("actual_rev", "proj_rev", "actual_tax", "proj_tax", "actual_hrs", "proj_hrs")}
    app.log(f"{when}: Reports year totals (53 weeks) {tot}")
    w.check(not bad, f"{when}: Reports differs from the rules in {len(bad)} place(s):\n  " + "\n  ".join(bad[:25]))
    return want, rows


# ── the world ────────────────────────────────────────────────────────────────
class World:
    def __init__(self, tm, api):
        self.tm, self.api = tm, api
        self.d0 = tm.start_day                       # a Monday
        self.cust_id: dict[str, str] = {}
        self.failures: list[str] = []
        self.unpaid_auto = ""                        # TR-03: one auto visit left unpaid
        self.one_off = ""
        self.done: set[str] = set()
        self.last_reports: dict = {}

    def check(self, ok: bool, msg: str):
        if not ok:
            log.info(f"[TR] CHECK FAILED: {msg}")
            self.failures.append(msg)
        assert ok, msg

    def read_all(self):
        jobs = [j for j in self.api.read("Jobs_Schedule")]
        invoices = self.api.read("Invoices")
        customers = self.api.read("Customers")
        return jobs, invoices, customers

    def set_setting(self, key, value):
        self.api.call("update_job_spreadsheet", {"sheet_name": "Settings", "id_column": "Setting",
                                                 "job_identifier": key, "updates": {"Value": str(value)}})

    def job(self, k: str, day: dt.date, *, status="Complete", quote=None, minutes=None, actual=True,
            **extra) -> str:
        name, freq, price, avg, _ = CUST[k]
        mins = minutes if minutes is not None else avg
        f = {"CustomerID": self.cust_id[k], "Customer Name / Company": name, "Service Date": day.isoformat(),
             "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168", "Service Type": "Window",
             "Job Status": status, "Crew / Technician": OWNER, "Schedule Type (Hard/Soft)": "Soft",
             "Quote Amount ($)": price if quote is None else quote,
             "Est. Duration": mins, "Est. Duration Unit": "min", "Start Time": "09:00"}
        if status == "Complete" and actual:
            f.update({"Actual Duration": mins, "Actual Duration Unit": "min"})
        f.update(extra)
        out = self.api.call("create_job", {"updates": f})
        return out.split("NEW_JOB_ID=")[1].split()[0]

    def invoice(self, jid: str, amount: float, rate: float = TAX) -> str:
        out = self.api.call("create_invoice", {"job_identifier": jid, "quote_amount": amount, "discount": 0,
                                               "tax_rate": rate, "due_days": 30})
        return re.search(r"INV-[\d-]*\d", out).group(0)

    def pay(self, inv: str, amount: float | None = None):
        upd = {"Payment Status": "Paid"} if amount is None else {"Amount Paid ($)": amount,
                                                                   "Payment Status": "Partial"}
        self.api.call("update_job_spreadsheet", {"sheet_name": "Invoices", "id_column": "InvoiceID (INV-####)",
                                                 "job_identifier": inv, "updates": upd})

    def complete(self, jid: str, minutes: int):
        self.api.call("update_job_spreadsheet", {
            "sheet_name": "Jobs_Schedule", "id_column": JOB_ID, "job_identifier": jid,
            "updates": {"Job Status": "Complete", "Actual Duration": minutes, "Actual Duration Unit": "min"}})


@pytest.fixture(scope="module")
def tm():
    """This story's own throwaway app copy (its own folder, port and clock)."""
    machine = TimeMachine(next_monday(dt.date.today()), "personal")
    machine.home = RUN_DIR / "sandbox_reports_year"
    machine.start()
    yield machine
    machine.stop()


@pytest.fixture(scope="module")
def api(tm) -> ApiClient:
    return ApiClient(tm.origin, tm.token, _OpenGuard(), log=_log, api_log=_api_log)


@pytest.fixture(scope="module")
def apis(api) -> dict:
    return {"owner": api}


@pytest.fixture(scope="module")
def world(tm, api):
    return World(tm, api)


# One story told in order (see test_tm_six_weeks.py for why every test asks
# for browser_name).
_story = {"broken": ""}


@pytest.fixture(autouse=True)
def _in_order(request, browser_name):
    if _story["broken"]:
        pytest.skip(f"an earlier step of the story failed ({_story['broken']})")
    yield
    rep = getattr(request.node, "rep_call", None)
    if rep is not None and rep.failed:
        _story["broken"] = request.node.name


# ── TR-01: the business, with its history ───────────────────────────────────
def test_TR_01_setup_a_business_with_history(world, tm, api):
    w, D = world, world.d0
    tm.set_clock(D - dt.timedelta(days=1), "07:00")           # Sunday before day 0
    api.read("Settings")
    w.set_setting("Recurring Job Lead Time (days)", LEAD_DAYS)
    for k, (name, freq, price, avg, active) in CUST.items():
        f = {"Company Name": name, "Customer Type Comm/Res": "Commercial", "City": "New Smyrna Beach",
             "State": "FL", "ZIP": "32168", "Status Active/Inactive": "Active" if active else "Inactive",
             "Standard Quote ($)": price, "Discount (%)": 0, "Avg Job Duration (min)": avg}
        if freq:
            f["Frequency"] = freq
        out = api.call("create_customer", {"updates": f})
        w.cust_id[k] = out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()

    # W — weekly on Fridays, the last eight weeks
    fri = [D - dt.timedelta(days=3 + 7 * n) for n in range(8)]
    j = w.job("W", fri[0]); w.pay(w.invoice(j, 100))                          # paid: 107 actual, 7 tax
    j = w.job("W", fri[1]); w.invoice(j, 100)                                 # invoiced, unpaid: 107 projected
    j = w.job("W", fri[2]); w.pay(w.invoice(j, 100, 0), 40)                   # 0% invoice, $40 paid
    w.job("W", fri[3], actual=False)                                           # never invoiced, no Actual Duration
    j = w.job("W", fri[4], **{"No Sales Tax": 1}); w.pay(w.invoice(j, 100))  # tax-exempt, paid
    for d in fri[5:]:
        j = w.job("W", d); w.pay(w.invoice(j, 100))
    # B — biweekly Tuesdays, paid
    for n in (0, 2, 4):
        j = w.job("B", D - dt.timedelta(days=6 + 7 * n)); w.pay(w.invoice(j, 200))
    # M — monthly, Q — quarterly, I — inactive monthly: one paid visit each
    j = w.job("M", D - dt.timedelta(days=20)); w.pay(w.invoice(j, 300))
    j = w.job("Q", D - dt.timedelta(days=45)); w.pay(w.invoice(j, 400))
    j = w.job("I", D - dt.timedelta(days=15)); w.pay(w.invoice(j, 500))
    # the future: a one-off job with a $100 deposit (0% invoice), B's visit
    # two cycles out already booked by hand at its own price (its 🔮 must
    # give way), and a cancelled W job (never counts)
    w.one_off = w.job("O", D + dt.timedelta(days=9), status="Scheduled")
    w.pay(w.invoice(w.one_off, 250, 0), 100)
    w.job("B", D + dt.timedelta(days=22), status="Scheduled", quote=210)
    w.job("W", D + dt.timedelta(days=2), status="Cancelled", quote=999)
    customers = api.read("Customers")
    log.info(f"[TR] day 0 = {D:%a %Y-%m-%d}; customers {w.cust_id}; "
             f"last service {[(c['Company Name'], c.get('Last Service Date')) for c in customers]}")
    last = {c[CUST_ID]: iso_date(c.get("Last Service Date", "")) for c in customers}
    assert last[w.cust_id["W"]] == fri[0].isoformat(), last
    assert last[w.cust_id["M"]] == (D - dt.timedelta(days=20)).isoformat(), last
    assert _money(next(c for c in customers if c[CUST_ID] == w.cust_id["W"]).get("Net Price ($)")) in (0, 100)


# ── TR-02: day 0 — the calendar and a whole year of Reports ──────────────────
def test_TR_02_day_zero_calendar_and_year_of_reports(world, tm, api, app, page):
    w, D = world, world.d0
    tm.set_clock(D, "07:00")
    page.clock.set_system_time(tm.now())
    want, rows = check_calendar_and_reports(w, app, page, "day 0")
    # hand-checked weeks (independent of the oracle):
    last_wk = rows[_label(D - dt.timedelta(days=7))]          # W paid 107 + B paid 214
    assert (last_wk["actual_rev"], last_wk["proj_rev"], last_wk["actual_tax"], last_wk["actual_hrs"]) \
        == (321, 0, 21, 2.5), last_wk
    two_wk = rows[_label(D - dt.timedelta(days=14))]          # W invoiced 107 unpaid
    assert (two_wk["actual_rev"], two_wk["proj_rev"], two_wk["proj_tax"], two_wk["actual_hrs"]) \
        == (0, 107, 7, 1.0), two_wk
    # W: 0% invoice, $40 of $100 paid; B paid 214; M paid 321; inactive I paid 535
    three_wk = rows[_label(D - dt.timedelta(days=21))]
    assert (three_wk["actual_rev"], three_wk["proj_rev"], three_wk["actual_tax"], three_wk["proj_tax"],
            three_wk["actual_hrs"]) == (40 + 214 + 321 + 535, 60, 14 + 21 + 35, 0, 1 + 1.5 + 2 + 1), three_wk
    four_wk = rows[_label(D - dt.timedelta(days=28))]         # W never invoiced: $100 projected, no tax,
    assert (four_wk["actual_rev"], four_wk["proj_rev"], four_wk["proj_tax"], four_wk["actual_hrs"]) \
        == (0, 100, 0, 1.0), four_wk                          # hours from the estimate (no Actual Duration)
    five_wk = rows[_label(D - dt.timedelta(days=35))]         # W tax-exempt paid 100; B paid 214
    assert (five_wk["actual_rev"], five_wk["actual_tax"]) == (314, 14), five_wk
    this_wk = rows[_label(D)]                                 # the sweep's W visit (Fri): $100 + 7% + 1h
    assert this_wk["current"] and (this_wk["proj_rev"], this_wk["proj_tax"], this_wk["proj_hrs"]) \
        == (100, 7, 1.0), f"this week should hold only W's auto-listed visit (cancelled job ignored): {this_wk}"
    nxt = rows[_label(D + dt.timedelta(days=7))]              # B 🔮 200/14/1.5h, O deposit 100 actual + 150, W 🔮 100/7/1h (+M 🔮 if it lands here)
    m_extra = [p for p in expected_projections(D, api.read("Customers"), api.read("Jobs_Schedule"))
               if p["cust"] == w.cust_id["M"] and _monday(p["date"]) == _monday(D + dt.timedelta(days=7))]
    m_rev = sum(p["revenue"] for p in m_extra)
    assert nxt["actual_rev"] == 100 and nxt["proj_rev"] == 200 + 150 + 100 + m_rev, nxt
    b_resched = rows[_label(D + dt.timedelta(days=22))]       # B's own $210 job, no 🔮 on top, no tax
    b_week_proj = [p for p in expected_projections(D, api.read("Customers"), api.read("Jobs_Schedule"))
                   if _monday(p["date"]) == _monday(D + dt.timedelta(days=22))]
    assert b_resched["proj_rev"] == 210 + sum(p["revenue"] for p in b_week_proj), b_resched
    assert not any(p["cust"] == w.cust_id["B"] for p in b_week_proj
                   if p["date"] == D + dt.timedelta(days=22)), "B's 🔮 visit wasn't skipped under its real job"
    assert not any(p["cust"] == w.cust_id["I"] for p in
                   expected_projections(D, api.read("Customers"), api.read("Jobs_Schedule"))), "inactive customer projected"
    ahead = [r for lbl, r in rows.items() if lbl in list(want)[WEEKS_EACH + 1:]]
    assert sum(1 for r in ahead if r["proj_rev"] > 0) >= 20, "the year ahead should be full of projected visits"
    page.screenshot(path=str(RUN_DIR / "TR-02_reports_day0.png"), full_page=True)


# ── TR-03: six weeks of work, one day at a time ──────────────────────────────
def test_TR_03_six_weeks_of_recurring_work(world, tm, api):
    w, D = world, world.d0
    for n in range(WALK_DAYS):
        day = D + dt.timedelta(days=n)
        tm.set_clock(day, "07:00")
        jobs = api.read("Jobs_Schedule")                      # opening the app: the sweep runs
        for j in jobs:
            jid, notes = j.get(JOB_ID, ""), j.get("Service Details / Notes", "")
            if jid in w.done or iso_date(j.get("Service Date", "")) != day.isoformat():
                continue
            if (j.get("Job Status") or "") in ("Complete", "Cancelled"):
                continue
            k = next((k for k, c in CUST.items() if c[0] == j.get("Customer Name / Company")), "?")
            if jid == w.one_off:                              # the one-off job: done, only the deposit paid
                tm.set_clock(day, "15:00")
                w.complete(jid, 120)
                w.done.add(jid)
                continue
            hand_b = k == "B" and AUTO_NOTE not in notes      # B's visit booked by hand at $210
            if AUTO_NOTE not in notes and not hand_b:
                continue
            tm.set_clock(day, "15:00")
            w.complete(jid, CUST[k][3])
            inv = w.invoice(jid, 210 if hand_b else CUST[k][2])
            if k == "M" and not w.unpaid_auto:
                w.unpaid_auto = jid                            # one auto visit invoiced but never paid
            else:
                w.pay(inv)
            w.done.add(jid)
            log.info(f"[TR] {day:%a %m/%d}: {k} {'hand-booked' if hand_b else 'auto'} visit {jid} done, invoiced"
                     f"{'' if jid == w.unpaid_auto else ' and paid'}")
    autos = [j for j in api.read("Jobs_Schedule") if AUTO_NOTE in (j.get("Service Details / Notes") or "")]
    per = {k: sum(1 for j in autos if j.get("Customer Name / Company") == CUST[k][0]) for k in CUST}
    log.info(f"[TR] auto-listed visits after six weeks: {per}")
    # B's hand-booked day-22 visit is "pending" until it's done, so the sweep
    # lists B's next visit only after it (its day-8 🔮 visit is never listed).
    assert per["W"] >= 5 and per["B"] >= 1 and per["M"] >= 1, f"the sweep didn't list the visits: {per}"
    assert per["I"] == 0 and per["O"] == 0, f"inactive / one-time customers got auto visits: {per}"
    assert w.unpaid_auto, "M's monthly visit never came up in six weeks"


# ── TR-04: day 42 — projected turned actual, the year rolled on ──────────────
def test_TR_04_six_weeks_later_calendar_and_year_of_reports(world, tm, api, app, page):
    w, D = world, world.d0
    day = D + dt.timedelta(days=WALK_DAYS)
    tm.set_clock(day, "07:00")
    api.read("Jobs_Schedule")                                 # the morning sweep
    page.clock.set_system_time(tm.now())
    want, rows = check_calendar_and_reports(w, app, page, "day 42")
    # hand-checks: the week that was "next week" on day 0 is now history
    # That week: W's auto visit paid (107, 7 tax, 1h), O done with only the
    # $100 deposit paid (150 still owed, 2h), M's auto visit done and invoiced
    # but unpaid (321 owed, 21 tax, 2h). B's day-8 🔮 visit was never listed
    # (its hand-booked day-22 visit was pending), so nothing of B's.
    wk = rows[_label(D + dt.timedelta(days=7))]
    m_day = iso_date(next(j for j in api.read("Jobs_Schedule") if j.get(JOB_ID) == w.unpaid_auto)["Service Date"])
    assert _monday(dt.date.fromisoformat(m_day)) == _monday(D + dt.timedelta(days=7)), m_day
    assert (wk["actual_rev"], wk["proj_rev"], wk["actual_tax"], wk["proj_tax"], wk["actual_hrs"], wk["proj_hrs"]) \
        == (207, 471, 7, 21, 5.0, 0), f"day 0's 'next week', six weeks later: {wk}"
    page.screenshot(path=str(RUN_DIR / "TR-04_reports_day42.png"), full_page=True)
