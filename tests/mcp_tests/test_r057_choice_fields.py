"""
R-057 (2026-09-28, David): fields that are dropdowns in the Jobs app (Job
Status, Payment Status, Recurrence, Frequency, Schedule Type, duration units,
Customer Type, customer Status, quote Status, and the on/off / Route Origin
Mode settings) could be saved with ANY text through Claude (voice/chat),
imports or the API. Found by the E2E suite: a job saved "Completed" (the app's
value is "Complete") looked done but never counted as serviced for customer
reminders. Now every write maps the value to the canonical one or refuses it
(nothing written); the recurring scheduler understands every accepted
wording; a one-time cleanup fixes existing rows. Same code in personal and
server mode (db_write_ops is shared).

Run: run_tests.bat tests\\mcp\\test_r057_choice_fields.py -v
"""
from __future__ import annotations

import datetime as dt
import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from db_access import init_db                       # noqa: E402
import db_write_ops as w                             # noqa: E402


@pytest.fixture
def db(tmp_path):
    p = str(tmp_path / "jobs.db")
    init_db(p)
    return p


def _cust(db, **extra):
    out = w.db_create_customer(db, {"Company Name": "Acme", **extra}, actor="t")
    assert out.startswith("✅"), out
    return out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


def _job(db, cid, **extra):
    out = w.db_create_job(db, {"CustomerID": cid, "Customer Name / Company": "Acme",
                               "Service Date": "2026-09-01", **extra}, actor="t")
    assert out.startswith("✅"), out
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _row(db, table, idcol, ident):
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    r = dict(c.execute(f"SELECT * FROM {table} WHERE {idcol} = ?", (ident,)).fetchone())
    c.close()
    return r


# ── the words people (and Claude) actually use ────────────────────────────────
@pytest.mark.parametrize("said,stored", [
    ("Completed", "Complete"), ("completed", "Complete"), ("DONE", "Complete"), ("finished", "Complete"),
    ("Complete", "Complete"), ("in-progress", "In Progress"), ("started", "In Progress"),
    ("canceled", "Cancelled"), ("Cancel", "Cancelled"), ("booked", "Scheduled"),
])
def test_job_status_update(said, stored, db):
    jid = _job(db, _cust(db))
    out = w.db_update_job(db, jid, {"Job Status": said}, actor="t")
    assert out.startswith("✅"), out
    assert _row(db, "jobs", "job_id", jid)["job_status"] == stored


def test_job_status_nonsense_refused_nothing_written(db):
    jid = _job(db, _cust(db), **{"Job Status": "Scheduled"})
    out = w.db_update_job(db, jid, {"Job Status": "Mostly done", "Service Details / Notes": "x"}, actor="t")
    assert out.startswith("❌") and "Scheduled, In Progress, Complete, Cancelled" in out and "Nothing was saved" in out
    r = _row(db, "jobs", "job_id", jid)
    assert r["job_status"] == "Scheduled" and not r["service_details"]


def test_create_job_normalised_and_refused(db):
    cid = _cust(db)
    jid = _job(db, cid, **{"Job Status": "completed", "Payment Status": "paid in full",
                           "Recurrence": "every other week", "Schedule Type (Hard/Soft)": "fixed",
                           "Est. Duration Unit": "hrs", "Actual Duration Unit": "Minutes",
                           "Customer Type": "home"})
    r = _row(db, "jobs", "job_id", jid)
    assert (r["job_status"], r["payment_status"], r["recurrence"], r["schedule_type"],
            r["est_duration_unit"], r["actual_duration_unit"], r["customer_type"]) == \
        ("Complete", "Paid", "Biweekly", "Hard", "hour", "min", "Residential")
    out = w.db_create_job(db, {"CustomerID": cid, "Customer Name / Company": "Acme",
                               "Payment Status": "credit card"}, actor="t")
    assert out.startswith("❌") and "Payment Status" in out and "Zelle" in out


def test_blank_still_clears(db):
    jid = _job(db, _cust(db), **{"Payment Status": "Unpaid"})
    assert w.db_update_job(db, jid, {"Payment Status": ""}, actor="t").startswith("✅")
    assert not _row(db, "jobs", "job_id", jid)["payment_status"]


@pytest.mark.parametrize("said,stored", [
    ("Semi-Annual", "Semi-Annually"), ("twice a year", "Semi-Annually"), ("Annual", "Annually"),
    ("yearly", "Annually"), ("Bi-weekly", "Biweekly"), ("every 2 weeks", "Biweekly"),
    ("Bimonthly", "Bi-Monthly"), ("every other month", "Bi-Monthly"), ("once", "One-time"),
    ("Quarterly", "Quarterly"), ("W", "Weekly"),
])
def test_customer_frequency(said, stored, db):
    cid = _cust(db, Frequency=said)
    assert _row(db, "customers", "customer_id", cid)["frequency"] == stored


def test_job_recurrence_keeps_its_own_spelling(db):
    jid = _job(db, _cust(db), Recurrence="Semi-Annually")
    assert _row(db, "jobs", "job_id", jid)["recurrence"] == "Semi-Annual"   # the Jobs app's option


def test_customer_status_type_and_quote_status(db):
    cid = _cust(db, **{"Customer Type Comm/Res": "business", "Status Active/Inactive": "archived"})
    r = _row(db, "customers", "customer_id", cid)
    assert (r["customer_type"], r["status"]) == ("Commercial", "Inactive")
    q = w.db_create_quote(db, {"CustomerID": cid, "Customer Name / Company": "Acme",
                               "Status (Open/Approved/Declined)": "accepted"}, actor="t")
    qid = q.split("NEW_QTE_ID=")[1].splitlines()[0].strip()
    assert _row(db, "quotes", "quote_id", qid)["status"] == "Approved"
    bad = w.db_update_row(db, "quotes", w.QUOTES_HEADER_MAP, "quote_id", qid,
                          {"Status (Open/Approved/Declined)": "maybe"}, actor="t")
    assert bad.startswith("❌") and "Open, Approved, Declined" in bad


# ── what the fix is for: "Completed" now counts as serviced ──────────────────
def test_completed_counts_as_serviced_for_reminders(db):
    cid = _cust(db)
    jid = _job(db, cid)
    w.db_update_job(db, jid, {"Job Status": "Completed", "Service Date": dt.date.today().isoformat()}, actor="t")
    due = {c["customer_id"] for c in w.db_find_stale_customers(db, days_threshold=30)}
    assert cid not in due, "a job marked 'Completed' must count as serviced"


# ── the recurring scheduler understands every accepted wording ──────────────
@pytest.mark.parametrize("stored,months,weeks", [
    ("Semi-Annual", 6, 0), ("Annual", 12, 0), ("Bi-weekly", 0, 2), ("every other month", 2, 0),
    ("Semi-Annually", 6, 0), ("Weekly", 0, 1),
])
def test_scheduler_reads_any_wording(stored, months, weeks, db):
    cid = _cust(db)
    c = sqlite3.connect(db)                        # an old row, written before R-057
    c.execute("UPDATE customers SET frequency = ? WHERE customer_id = ?", (stored, cid))
    c.commit()
    c.close()
    jid = _job(db, cid, **{"Job Status": "Complete"})
    out = w.db_schedule_next_recurring_job(db, jid, actor="t")
    assert out.startswith("✅"), out
    base = dt.date(2026, 9, 1)
    want = w._add_months(base, months) if months else base + dt.timedelta(weeks=weeks)
    assert want.isoformat() in out or want.strftime("%m/%d/%Y") in out, out


# ── settings ────────────────────────────────────────────────────────────────
def test_settings_toggles_and_route_origin(db):
    w.db_seed_default_settings(db)
    assert w.db_update_settings(db, "Email Route On Build", {"Value": "on"}, actor="t").startswith("✅")
    assert w.db_update_settings(db, "Route Origin Mode", {"Value": "office"}, actor="t").startswith("✅")
    c = sqlite3.connect(db)
    vals = dict(c.execute("SELECT key, value FROM settings").fetchall())
    c.close()
    assert vals["Email Route On Build"] == "Enabled" and vals["Route Origin Mode"] == "Company Location"
    bad = w.db_update_settings(db, "Route Origin Mode", {"Value": "the moon"}, actor="t")
    assert bad.startswith("❌") and "Jobs Only, Company Location" in bad
    # free-text settings are untouched
    assert w.db_update_settings(db, "Workday Start Time", {"Value": "7:30"}, actor="t").startswith("✅")


# ── one-time cleanup of existing rows ───────────────────────────────────────
def test_one_time_cleanup_fixes_existing_rows(db):
    cid = _cust(db)
    jid = _job(db, cid)
    c = sqlite3.connect(db)
    c.execute("UPDATE jobs SET job_status='Completed', est_duration_unit='hrs', payment_status='mystery' "
              "WHERE job_id=?", (jid,))
    c.execute("UPDATE customers SET frequency='Semi-Annual' WHERE customer_id=?", (cid,))
    c.commit()
    c.close()
    w._maybe_normalize_choice_fields(db)
    r = _row(db, "jobs", "job_id", jid)
    assert (r["job_status"], r["est_duration_unit"]) == ("Complete", "hour")
    assert r["payment_status"] == "mystery", "unrecognised values are left alone, never guessed"
    assert _row(db, "customers", "customer_id", cid)["frequency"] == "Semi-Annually"
    c = sqlite3.connect(db)
    marker = c.execute("SELECT notes FROM settings WHERE key = ?", (w._CHOICE_MARKER_KEY,)).fetchone()
    c.close()
    assert marker and "mystery" in marker[0]
    # runs once only
    c = sqlite3.connect(db)
    c.execute("UPDATE jobs SET job_status='Completed' WHERE job_id=?", (jid,))
    c.commit()
    c.close()
    w._maybe_normalize_choice_fields(db)
    assert _row(db, "jobs", "job_id", jid)["job_status"] == "Completed"


def test_cleanup_is_hooked_into_reads():
    src = (_SRC / "db_read_ops.py").read_text(encoding="utf-8")
    assert src.count("_maybe_normalize_choice_fields(db_path)") == 2


# ── the app's own dropdown lists and the server agree ───────────────────────
def test_database_tab_dropdowns_match_server_choices():
    from db_read_ops import _KNOWN_DROPDOWNS
    pairs = {("Customers", "Customer Type Comm/Res"): ("customers", "customer_type"),
             ("Customers", "Frequency"): ("customers", "frequency"),
             ("Customers", "Status Active/Inactive"): ("customers", "status"),
             ("Invoices", "Payment Status"): ("invoices", "payment_status"),
             ("Quotes", "Status (Open/Approved/Declined)"): ("quotes", "status")}
    for (sheet, col), key in pairs.items():
        assert set(_KNOWN_DROPDOWNS[sheet][col]) == set(w._CHOICE_FIELDS[key]), (sheet, col)


def test_job_form_dropdowns_match_server_choices():
    import re
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    for sel, key in [("jfStatus", ("jobs", "job_status")), ("jfPayment", ("jobs", "payment_status")),
                     ("jfRecurrence", ("jobs", "recurrence")), ("jfDurationUnit", ("jobs", "est_duration_unit")),
                     ("jfActualDurationUnit", ("jobs", "actual_duration_unit")),
                     ("jfCustomerType", ("jobs", "customer_type"))]:
        i = html.index(f'id="{sel}"')
        block = html[i:html.index("</select>", i)]
        opts = re.findall(r"<option[^>]*>([^<]+)</option>", block)
        vals = re.findall(r'<option value="([^"]+)"', block) or opts
        assert set(vals) == set(w._CHOICE_FIELDS[key]), (sel, vals)
    i = html.index('id="jfSchedType"')
    assert set(re.findall(r'<option value="([^"]+)"', html[i:html.index("</select>", i)])) == \
        set(w._CHOICE_FIELDS[("jobs", "schedule_type")])
