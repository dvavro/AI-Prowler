"""Every editable Job and Customer field, and how to drive it (2026-10-09).

Used by the field round-trip E2E tests (personal: test_field_roundtrip.py,
server: test_srv_field_roundtrip.py). For each field a test:
  1. sets value A through the app (typed like a person) and saves,
  2. reads the database back and checks it stored A,
  3. reopens the form and checks it SHOWS A,
  4. changes it to B (a field that saves once but can't be changed again is a
     real bug class) and repeats 2-3.
The AI path does the same through Claude's MCP tools (ai_client.py) and then
checks the app shows the new values.

Field lists come from the app itself (jobs/index.html saveJobForm / the
Database tab's generic editor) and the server's header maps
(db_write_ops.JOBS_HEADER_MAP / CUSTOMERS_HEADER_MAP). Read-only / computed
columns (Actual Amount, Tax, Invoice Total, InvoiceID, lat/long, Next Sched.
Date, Net Price, Lifetime Revenue, Total Jobs Completed, audit columns) are
deliberately absent — the app shows them locked.
"""
from __future__ import annotations

import datetime as dt
import re

from playwright.sync_api import Page, expect

from app import type_text
from safety import SANDBOX_DATE, ZTEST_PREFIX

D0 = dt.date.fromisoformat(SANDBOX_DATE)
DAY = lambda n: (D0 + dt.timedelta(days=n)).isoformat()      # noqa: E731


# ── value normalisation (database text <-> form value) ───────────────────────
def norm_date(v) -> str:
    v = str(v or "").strip()
    if len(v) == 10 and v[2] == "/" and v[5] == "/":
        return f"{v[6:]}-{v[:2]}-{v[3:5]}"
    return v[:10]


def norm_time(v) -> str:
    """'7:05 AM' / '07:05' / '19:05' -> '07:05' (24h); '' stays ''."""
    s = str(v or "").strip().upper()
    if not s:
        return ""
    m = re.match(r"^(\d{1,2}):(\d{2})\s*([AP])\.?M\.?$", s)
    if m:
        h = int(m.group(1)) % 12 + (12 if m.group(3) == "P" else 0)
        return f"{h:02d}:{m.group(2)}"
    m = re.match(r"^(\d{1,2}):(\d{2})", s)
    return f"{int(m.group(1)):02d}:{m.group(2)}" if m else s


def norm_num(v) -> float | None:
    s = str(v or "").strip().replace("$", "").replace(",", "")
    try:
        return round(float(s), 2) if s else None
    except ValueError:
        return None


def norm_bool(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on", "1.0")


def norm_days(v) -> set:
    return {t.strip().lower()[:3] for t in re.split(r"[/,;|&\s]+", str(v or "")) if t.strip()}


def norm_names(v) -> set:
    return {t.strip().lower() for t in str(v or "").split(",") if t.strip()}


NORM = {"date": norm_date, "time": norm_time, "number": norm_num, "checkbox": norm_bool,
        "prefdays": norm_days, "crew": norm_names}


def same(kind: str, a, b) -> bool:
    f = NORM.get(kind)
    if f:
        return f(a) == f(b)
    return str(a or "").strip() == str(b or "").strip()


# ── JOB FORM (#jobFormModal, Jobs_Schedule) ──────────────────────────────────
# (database column, form element id, kind, value A, value B)
# Order matters: Schedule Type / duration are set before the times, because a
# Hard job's End Time is calculated (start + duration) and locked.
JOB_FIELDS = [
    # Customer Type is NOT here: on a job it belongs to the customer (spec §13
    # Case B) and the form shows it read-only (R-081) — FR-04 checks that.
    ("Street Address",                    "jfAddress",           "text",     "105 S Riverside Dr",  "1 Flagler Ave"),
    ("City",                              "jfCity",              "text",     "Edgewater",           "New Smyrna Beach"),
    ("State",                             "jfState",             "text",     "GA",                  "FL"),
    ("ZIP",                               "jfZip",               "text",     "32141",               "32169"),
    ("Service Date",                      "jfDate",              "date",     DAY(0),                DAY(1)),
    ("End Date (blank = single-day job)", "jfEndDate",           "date",     DAY(1),                DAY(2)),
    ("Preferred Day(s)",                  "jfPrefDays",          "prefdays", "Monday/Wednesday",    "Friday"),
    ("Schedule Type (Hard/Soft)",         "jfSchedType",         "select",   "Soft",                "Hard"),
    ("Est. Duration",                     "jfDuration",          "number",   "45",                  "1.5"),
    ("Est. Duration Unit",                "jfDurationUnit",      "select",   "min",                 "hour"),
    ("Start Time",                        "jfStart",             "time",     "08:30",               "09:15"),
    ("End Time",                          "jfEnd",               "time",     "11:45",               "10:45"),  # B: Hard = 9:15 + 1.5 h
    ("Original Start Time",               "jfOriginalStart",     "time",     "08:00",               "09:00"),
    ("Original End Time",                 "jfOriginalEnd",       "time",     "12:00",               "10:00"),
    ("Service Type",                      "jfService",           "text",     "Window",              "Pressure"),
    ("Service Details / Notes",           "jfNotes",             "text",     "FR note A: gate on left", "FR note B: dog in yard"),
    ("Actual Duration",                   "jfActualDuration",    "number",   "50",                  "2"),
    ("Actual Duration Unit",              "jfActualDurationUnit", "select",  "min",                 "hour"),
    ("Job Status",                        "jfStatus",            "select",   "In Progress",         "Scheduled"),
    ("Payment Status",                    "jfPayment",           "select",   "Partial",             "Zelle"),
    ("No Sales Tax",                      "jfNoTax",             "checkbox", True,                  False),
    ("Recurrence",                        "jfRecurrence",        "select",   "Biweekly",            "Quarterly"),
    ("Quote Amount ($)",                  "jfQuote",             "number",   "123.45",              "210"),
    ("Discount Applied ($)",              "jfDiscount",          "number",   "10.5",                "25"),
    ("Invoice Sent Date",                 "jfInvoiceSentDate",   "date",     DAY(0),                DAY(1)),
]
# Crew / Technician is handled per mode: personal = free text (jfCrew),
# server = the team tick-list (#jfCrewPicker), see set_job_crew().
JOB_SET_A = {c: a for c, _e, _k, a, _b in JOB_FIELDS}
JOB_SET_B = {c: b for c, _e, _k, _a, b in JOB_FIELDS}
JOB_KIND = {c: k for c, _e, k, _a, _b in JOB_FIELDS}
JOB_KIND["Crew / Technician"] = "crew"

# Values Claude sets in the AI-path test (a third, different set).
JOB_SET_AI = {
    "Street Address": "210 Sams Ave", "City": "New Smyrna Beach",
    "State": "FL", "ZIP": "32168", "Service Date": DAY(2), "End Date (blank = single-day job)": DAY(3),
    "Preferred Day(s)": "Tuesday/Thursday", "Schedule Type (Hard/Soft)": "Soft",
    "Est. Duration": "2", "Est. Duration Unit": "hour", "Start Time": "1:00 PM", "End Time": "4:30 PM",
    "Original Start Time": "12:30 PM", "Original End Time": "5:00 PM", "Service Type": "Both",
    "Service Details / Notes": "FR note AI: set by Claude", "Actual Duration": "95",
    "Actual Duration Unit": "min", "Job Status": "In Progress", "Payment Status": "Check",
    "No Sales Tax": "1", "Recurrence": "Monthly", "Quote Amount ($)": "333.33",
    "Discount Applied ($)": "3.33", "Invoice Sent Date": DAY(2),
}


def _fill(page: Page, el_id: str, kind: str, value, log):
    loc = page.locator(f"#{el_id}")
    log(f"FIELD {el_id} = {value!r}")
    if kind == "select":
        loc.select_option(str(value))
        loc.dispatch_event("change")
    elif kind == "checkbox":
        loc.set_checked(bool(value))
        loc.dispatch_event("change")
    elif kind in ("date", "time", "number"):
        loc.fill(str(value))
        loc.dispatch_event("input")
        loc.dispatch_event("change")
    elif kind == "prefdays":
        want = norm_days(value)
        for i, day in enumerate(("mon", "tue", "wed", "thu", "fri", "sat", "sun")):
            cb = page.locator(f"#jfJobPrefDay_{i}")
            cb.set_checked(day in want)
            cb.dispatch_event("change")
    else:   # text / textarea — typed key by key in human mode
        loc.fill("")
        if value:
            type_text(page, loc, str(value))


def fill_job_form(page: Page, values: dict, log=lambda *a: None):
    for col, el_id, kind, _a, _b in JOB_FIELDS:
        if col not in values:
            continue
        if col == "End Time" and values.get("Schedule Type (Hard/Soft)") == "Hard":
            continue          # calculated + locked for Hard jobs
        _fill(page, el_id, kind, values[col], log)


def set_job_crew(page: Page, crew: str | list[str], server: bool, log=lambda *a: None):
    names = [crew] if isinstance(crew, str) else list(crew)
    if not server:
        _fill(page, "jfCrew", "text", ", ".join(names), log)
        return
    picker = page.locator("#jfCrewPicker")
    expect(picker).to_be_visible(timeout=15_000)
    want = {n.lower() for n in names}
    boxes = picker.locator("input[type=checkbox]")
    for i in range(boxes.count()):
        cb = boxes.nth(i)
        on = (cb.get_attribute("value") or "").strip().lower() in want
        log(f"CREW tick {cb.get_attribute('value')!r} = {on}")
        cb.set_checked(on)
        cb.dispatch_event("change")


def read_job_form(page: Page) -> dict:
    """What the open job form SHOWS, keyed by database column."""
    vals = page.evaluate("""() => {
        const v = id => { const e = document.getElementById(id); return e ? e.value : null; };
        const out = {};
        out.__crew = v('jfCrew');
        out.__noTax = document.getElementById('jfNoTax').checked;
        out.__days = [0,1,2,3,4,5,6].filter(i => { const c = document.getElementById('jfJobPrefDay_' + i);
                                                     return c && c.checked; });
        for (const id of ['jfCustomerType','jfAddress','jfCity','jfState','jfZip','jfDate','jfEndDate',
                          'jfSchedType','jfDuration','jfDurationUnit','jfStart','jfEnd','jfOriginalStart',
                          'jfOriginalEnd','jfService','jfNotes','jfActualDuration','jfActualDurationUnit',
                          'jfStatus','jfPayment','jfRecurrence','jfQuote','jfDiscount','jfInvoiceSentDate'])
            out[id] = v(id);
        return out;
    }""")
    names = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
    shown = {}
    for col, el_id, kind, _a, _b in JOB_FIELDS:
        if kind == "checkbox":
            shown[col] = vals["__noTax"]
        elif kind == "prefdays":
            shown[col] = "/".join(names[i] for i in vals["__days"])
        else:
            shown[col] = vals.get(el_id)
    shown["Crew / Technician"] = vals["__crew"]
    return shown


def compare(expected: dict, got: dict, kinds: dict) -> list[str]:
    """Field-by-field differences, normalised by kind."""
    out = []
    for col, want in expected.items():
        if not same(kinds.get(col, "text"), want, got.get(col)):
            out.append(f"{col}: expected {want!r}, got {got.get(col)!r}")
    return out


# ── CUSTOMER editor (Database tab → Customers → Edit, generic form) ──────────
# (column, kind, A, B). "select" columns are the server's DROPDOWN columns.
# Company Name keeps the ZTEST prefix so cleanup still finds the customer.
CUSTOMER_FIELDS = [
    ("Customer Type Comm/Res",          "select",   "Commercial",                 "Residential"),
    ("Company Name",                    "text",     f"{ZTEST_PREFIX} FR Cust A",  f"{ZTEST_PREFIX} FR Cust B"),
    ("First Name",                      "text",     "Pat",                        "Jordan"),
    ("Last Name",                       "text",     "Rivers",                     "Lake"),
    ("Phone",                           "text",     "386-555-0101",               "386-555-0202"),
    ("Email",                           "text",     "ztest-a@example.invalid",    "ztest-b@example.invalid"),
    ("Street Address",                  "text",     "105 S Riverside Dr",         "1001 S Dixie Fwy"),
    ("City",                            "text",     "New Smyrna Beach",           "Edgewater"),
    ("State",                           "text",     "FL",                         "GA"),
    ("ZIP",                             "text",     "32168",                      "32141"),
    ("Service Type(s) Win/Press/Both",  "text",     "Win",                        "Both"),
    ("Frequency",                       "select",   "Monthly",                    "Quarterly"),
    ("Schedule Type",                   "select",   "Hard",                       "Soft"),
    ("Preferred Day(s)",                "prefdays", "Tuesday/Thursday",           "Saturday"),
    ("Pref. Time Start",                "time",     "08:00",                      "13:30"),
    ("Pref. Time End",                  "time",     "11:00",                      "16:00"),
    ("Avg Job Duration (min)",          "number",   "75",                         "40"),
    ("Standard Quote ($)",              "number",   "150",                        "95.5"),
    ("Discount (%)",                    "number",   "5",                          "12.5"),
    # Last Service Date: computed from the last COMPLETED job, read-only (R-082)
    ("Gate Code / Access Notes",        "text",     "Gate 1234",                  "Gate 9876, buzz twice"),
    ("On-Site Contact",                 "text",     "Pat (manager)",              "Jordan (owner)"),
    ("Status Active/Inactive",          "select",   "Inactive",                   "Active"),
]
CUST_KIND = {c: k for c, k, _a, _b in CUSTOMER_FIELDS}
CUST_SET_A = {c: a for c, _k, a, _b in CUSTOMER_FIELDS}
CUST_SET_B = {c: b for c, _k, _a, b in CUSTOMER_FIELDS}
# Server mode: field crew may NOT change these on a customer (business fields,
# ai_prowler_mcp._FIELD_CREW_LOCKED_CUSTOMER_FIELDS) — everything else they may.
CREW_LOCKED_CUSTOMER = ("Frequency", "Standard Quote ($)", "Discount (%)", "Status Active/Inactive")
CUST_SET_AI = {
    "Customer Type Comm/Res": "Residential", "First Name": "Casey", "Last Name": "Shore",
    "Phone": "386-555-0303", "Email": "ztest-ai@example.invalid", "Street Address": "201 Sports Complex Dr",
    "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168", "Service Type(s) Win/Press/Both": "Press",
    "Frequency": "Weekly", "Schedule Type": "Soft", "Preferred Day(s)": "Monday",
    "Pref. Time Start": "7:30 AM", "Pref. Time End": "9:30 AM", "Avg Job Duration (min)": "33",
    "Standard Quote ($)": "77", "Discount (%)": "2",
    "Gate Code / Access Notes": "AI gate 4444", "On-Site Contact": "Casey (AI)",
}


def _cust_el(page: Page, col: str):
    return page.locator(f"#jfGenericInputs [data-col-name='{col}']").first


def fill_customer_form(page: Page, values: dict, log=lambda *a: None):
    for col, kind, _a, _b in CUSTOMER_FIELDS:
        if col not in values:
            continue
        v = values[col]
        log(f"CUSTOMER FIELD {col} = {v!r}")
        if kind == "prefdays":
            want = norm_days(v)
            for i, day in enumerate(("mon", "tue", "wed", "thu", "fri", "sat", "sun")):
                cb = page.locator(f"#jfPrefDay_{i}")
                cb.set_checked(day in want)
                cb.dispatch_event("change")
        elif col in ("Pref. Time Start", "Pref. Time End"):
            el = page.locator("#jfPrefTW_Start" if col == "Pref. Time Start" else "#jfPrefTW_End")
            el.fill(str(v))
            el.dispatch_event("change")
        else:
            el = _cust_el(page, col)
            tag = el.evaluate("e => e.tagName")
            if tag == "SELECT":
                el.select_option(str(v))
            elif kind in ("date", "number"):
                el.fill(str(v))
            else:
                el.fill("")
                if v:
                    type_text(page, el, str(v))


def read_customer_form(page: Page) -> dict:
    shown = {}
    names = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
    for col, kind, _a, _b in CUSTOMER_FIELDS:
        if kind == "prefdays":
            days = [names[i] for i in range(7) if page.locator(f"#jfPrefDay_{i}").is_checked()]
            shown[col] = "/".join(days)
        elif col == "Pref. Time Start":
            shown[col] = page.locator("#jfPrefTW_Start").input_value()
        elif col == "Pref. Time End":
            shown[col] = page.locator("#jfPrefTW_End").input_value()
        else:
            el = _cust_el(page, col)
            shown[col] = el.input_value() if el.count() else None
    return shown
