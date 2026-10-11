"""
tests/mcp_tests/test_recurring_job_generation.py
============================================
Review of the "proactive recurring-job generation" feature (built 2026-09-23):
customers with a recognized Frequency should get their next job auto-created
a configurable number of days before it's actually due
('Recurring Job Lead Time (days)', default 5).

2026-10-04: generated jobs carry the calculated Service Date (Last Service
Date + frequency interval) so they appear on the calendar at that date —
no longer unscheduled.
2026-10-07: the sweep honors the lead-time setting. The reader
(db_read_settings_recurring_job_lead_days) existed since 2026-09-23 but the
sweep never called it, so every recurring customer got their next job
immediately regardless of distance. These tests lock in the lead-window gate:
a job is only created when today is within lead_days before next-due.
"""
import datetime
import sqlite3
import sys
from pathlib import Path

import pytest

from db_access import init_db
from db_write_ops import (
    db_create_job,
    db_generate_upcoming_recurring_jobs,
    db_read_settings_recurring_job_lead_days,
    _maybe_sweep_recurring_jobs,
)
import db_write_ops as write_ops

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

TODAY = datetime.date.today()


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _sql(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def _create_customer(db_path, cust_id, name, frequency, status="Active"):
    _sql(db_path,
         "INSERT INTO customers (customer_id, company_name, customer_type, frequency, status, "
         "street_address, city, state, zip) VALUES (?, ?, 'Residential', ?, ?, '1 Main St', 'NSB', 'FL', '32168')",
         (cust_id, name, frequency, status))


def _create_past_job(db_path, cust_id, name, service_date, status="Complete"):
    out = db_create_job(db_path, {
        "CustomerID (Customers!A)": cust_id, "Customer Name / Company": name,
        "Service Date": service_date, "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Job Status": status,
    }, actor="test")
    job_id = out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    return job_id


def _generated_jobs_for(db_path, cust_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM jobs WHERE customer_id = ? AND service_details LIKE '%Auto-generated recurring job%'",
        (cust_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _set_lead_days(db_path, days):
    _sql(db_path,
         "INSERT OR REPLACE INTO settings (key, value) VALUES ('Recurring Job Lead Time (days)', ?)",
         (str(days),))


# ── db_read_settings_recurring_job_lead_days ───────────────────────────────

def test_default_lead_days_is_5_when_unset(db_path):
    assert db_read_settings_recurring_job_lead_days(db_path) == 5


def test_reads_the_configured_lead_days(db_path):
    _set_lead_days(db_path, 12)
    assert db_read_settings_recurring_job_lead_days(db_path) == 12


def test_zero_is_a_valid_lead_days_value(db_path):
    _set_lead_days(db_path, 0)
    assert db_read_settings_recurring_job_lead_days(db_path) == 0


def test_garbage_value_falls_back_to_default(db_path):
    _set_lead_days(db_path, "not a number")
    assert db_read_settings_recurring_job_lead_days(db_path) == 5


# ── db_generate_upcoming_recurring_jobs ─────────────────────────────────────

def test_creates_a_dated_job_within_the_lead_window(db_path):
    _set_lead_days(db_path, 5)
    # Weekly customer, last serviced 3 days ago -> next due in 4 days -> within a 5-day lead window
    last = (TODAY - datetime.timedelta(days=3)).isoformat()
    _create_customer(db_path, "CUST-0001", "Riverside Grill", "Weekly")
    _create_past_job(db_path, "CUST-0001", "Riverside Grill", last)

    res = db_generate_upcoming_recurring_jobs(db_path)
    assert "1 new job(s)" in res, res
    jobs = _generated_jobs_for(db_path, "CUST-0001")
    assert len(jobs) == 1
    assert jobs[0]["job_status"] == "Scheduled"          # same default status a hand-typed job gets
    expected_due = (TODAY - datetime.timedelta(days=3) + datetime.timedelta(weeks=1)).isoformat()
    assert jobs[0]["service_date"] == expected_due       # dated: last + interval, shows on the calendar
    assert "🔁 Auto-generated" in (jobs[0]["service_details"] or "")


def test_not_yet_within_the_lead_window_creates_nothing(db_path):
    _set_lead_days(db_path, 5)
    # Weekly, serviced yesterday -> next due in 6 days -> outside a 5-day lead window
    last = (TODAY - datetime.timedelta(days=1)).isoformat()
    _create_customer(db_path, "CUST-0002", "Coastal Dental", "Weekly")
    _create_past_job(db_path, "CUST-0002", "Coastal Dental", last)

    res = db_generate_upcoming_recurring_jobs(db_path)
    assert "0 new job(s)" in res
    assert "not yet within the" in res and "lead window" in res
    assert _generated_jobs_for(db_path, "CUST-0002") == []


def test_exactly_at_the_lead_boundary_creates(db_path):
    _set_lead_days(db_path, 5)
    # Weekly, serviced 2 days ago -> next due in exactly 5 days -> at the boundary, creates
    last = (TODAY - datetime.timedelta(days=2)).isoformat()
    _create_customer(db_path, "CUST-0020", "Boundary Cafe", "Weekly")
    _create_past_job(db_path, "CUST-0020", "Boundary Cafe", last)

    res = db_generate_upcoming_recurring_jobs(db_path)
    assert "1 new job(s)" in res, res
    assert len(_generated_jobs_for(db_path, "CUST-0020")) == 1


def test_a_larger_lead_window_surfaces_the_same_customer_earlier(db_path):
    # Same data as the "not yet due" case above, but a 30-day lead window
    # (the owner's own "surface it well ahead of time" example) DOES create it.
    _set_lead_days(db_path, 30)
    last = (TODAY - datetime.timedelta(days=1)).isoformat()
    _create_customer(db_path, "CUST-0002", "Coastal Dental", "Weekly")
    _create_past_job(db_path, "CUST-0002", "Coastal Dental", last)

    res = db_generate_upcoming_recurring_jobs(db_path)
    assert "1 new job(s)" in res
    assert len(_generated_jobs_for(db_path, "CUST-0002")) == 1


def test_one_time_customer_is_never_auto_scheduled(db_path):
    _create_customer(db_path, "CUST-0003", "Blue Wave Cafe", "One-time")
    _create_past_job(db_path, "CUST-0003", "Blue Wave Cafe", (TODAY - datetime.timedelta(days=100)).isoformat())
    res = db_generate_upcoming_recurring_jobs(db_path)
    assert "0 new job(s)" in res
    assert _generated_jobs_for(db_path, "CUST-0003") == []


def test_customer_with_no_job_history_is_skipped(db_path):
    _create_customer(db_path, "CUST-0004", "New Prospect", "Monthly")
    res = db_generate_upcoming_recurring_jobs(db_path)
    assert "no job history yet" in res
    assert _generated_jobs_for(db_path, "CUST-0004") == []


def test_inactive_customer_is_never_auto_scheduled(db_path):
    _create_customer(db_path, "CUST-0005", "Closed Account", "Weekly", status="Inactive")
    _create_past_job(db_path, "CUST-0005", "Closed Account", (TODAY - datetime.timedelta(days=10)).isoformat())
    res = db_generate_upcoming_recurring_jobs(db_path)
    assert _generated_jobs_for(db_path, "CUST-0005") == []


def test_unrecognized_frequency_is_skipped_and_reported(db_path):
    # not a dropdown value nor a recognised wording (R-057 accepts "Fortnightly"
    # as Biweekly and refuses unknown words on save, so this is legacy data)
    _create_customer(db_path, "CUST-0006", "Odd Freq", "Whenever convenient")
    _create_past_job(db_path, "CUST-0006", "Odd Freq", (TODAY - datetime.timedelta(days=10)).isoformat())
    res = db_generate_upcoming_recurring_jobs(db_path)
    assert "unrecognized frequency" in res
    assert _generated_jobs_for(db_path, "CUST-0006") == []


def test_does_not_create_a_second_pending_job_while_one_exists(db_path):
    _set_lead_days(db_path, 5)
    last = (TODAY - datetime.timedelta(days=3)).isoformat()
    _create_customer(db_path, "CUST-0007", "Riverside Grill", "Weekly")
    _create_past_job(db_path, "CUST-0007", "Riverside Grill", last)

    first = db_generate_upcoming_recurring_jobs(db_path)
    assert "1 new job(s)" in first
    second = db_generate_upcoming_recurring_jobs(db_path)          # running it again the same day
    assert "0 new job(s)" in second
    assert "already have a pending/future job" in second
    assert len(_generated_jobs_for(db_path, "CUST-0007")) == 1   # still just the one


def test_r080_overdue_customer_gets_one_job_not_one_per_sweep(db_path):
    """R-080 (2026-10-09): an OVERDUE customer's generated job is dated in the
    past (last service + interval < today). The 'pending' guard only counted
    jobs dated today-or-later, so every daily sweep created another copy of
    the same overdue visit until someone completed or cancelled one."""
    _set_lead_days(db_path, 5)
    last = (TODAY - datetime.timedelta(days=40)).isoformat()
    _create_customer(db_path, "CUST-0080", "Overdue Deli", "Weekly")
    _create_past_job(db_path, "CUST-0080", "Overdue Deli", last)
    assert "1 new job(s)" in db_generate_upcoming_recurring_jobs(db_path)
    second = db_generate_upcoming_recurring_jobs(db_path)      # the next day's sweep
    assert "0 new job(s)" in second, second
    assert len(_generated_jobs_for(db_path, "CUST-0080")) == 1


def test_r080_completing_the_overdue_job_lets_the_next_one_come(db_path):
    _set_lead_days(db_path, 5)
    last = (TODAY - datetime.timedelta(days=40)).isoformat()
    _create_customer(db_path, "CUST-0081", "Overdue Deli", "Weekly")
    _create_past_job(db_path, "CUST-0081", "Overdue Deli", last)
    db_generate_upcoming_recurring_jobs(db_path)
    (job,) = _generated_jobs_for(db_path, "CUST-0081")
    _sql(db_path, "UPDATE jobs SET job_status = 'Complete', service_date = ? WHERE job_id = ?",
         ((TODAY - datetime.timedelta(days=3)).isoformat(), job["job_id"]))
    assert "1 new job(s)" in db_generate_upcoming_recurring_jobs(db_path)
    assert len(_generated_jobs_for(db_path, "CUST-0081")) == 2


def test_a_cancelled_pending_job_does_not_block_a_new_one(db_path):
    _set_lead_days(db_path, 5)
    last = (TODAY - datetime.timedelta(days=3)).isoformat()
    _create_customer(db_path, "CUST-0008", "Riverside Grill", "Weekly")
    _create_past_job(db_path, "CUST-0008", "Riverside Grill", last)
    db_generate_upcoming_recurring_jobs(db_path)
    pending = _generated_jobs_for(db_path, "CUST-0008")
    assert len(pending) == 1
    _sql(db_path, "UPDATE jobs SET job_status = 'Cancelled' WHERE job_id = ?", (pending[0]["job_id"],))

    res = db_generate_upcoming_recurring_jobs(db_path)
    assert "1 new job(s)" in res                                   # the cancelled one no longer blocks it
    assert len(_generated_jobs_for(db_path, "CUST-0008")) == 2    # the cancelled one + the fresh one


def test_new_job_carries_the_customers_address(db_path):
    _set_lead_days(db_path, 5)
    # Weekly (not Monthly) so the due-date arithmetic is unambiguous — this
    # test is about address carryover, not frequency timing (already covered
    # above).
    _sql(db_path,
         "INSERT INTO customers (customer_id, company_name, customer_type, frequency, status, "
         "street_address, city, state, zip) VALUES ('CUST-0009', 'Sunset Villas', 'Commercial', 'Weekly', "
         "'Active', '42 Sunset Blvd', 'Edgewater', 'FL', '32132')")
    _create_past_job(db_path, "CUST-0009", "Sunset Villas", (TODAY - datetime.timedelta(days=3)).isoformat())
    db_generate_upcoming_recurring_jobs(db_path)
    pending = _generated_jobs_for(db_path, "CUST-0009")
    assert len(pending) == 1
    assert pending[0]["street_address"] == "42 Sunset Blvd"
    assert pending[0]["city"] == "Edgewater"
    assert pending[0]["customer_type"] == "Commercial"


# ── _maybe_sweep_recurring_jobs (the once-a-day throttle) ──────────────────

def test_sweep_runs_once_and_creates_the_job(db_path):
    _set_lead_days(db_path, 5)
    last = (TODAY - datetime.timedelta(days=3)).isoformat()
    _create_customer(db_path, "CUST-0010", "Riverside Grill", "Weekly")
    _create_past_job(db_path, "CUST-0010", "Riverside Grill", last)

    _maybe_sweep_recurring_jobs(db_path)
    assert len(_generated_jobs_for(db_path, "CUST-0010")) == 1


def test_sweep_does_not_run_twice_in_the_same_day(db_path, monkeypatch):
    _set_lead_days(db_path, 5)
    last = (TODAY - datetime.timedelta(days=3)).isoformat()
    _create_customer(db_path, "CUST-0011", "Riverside Grill", "Weekly")
    _create_past_job(db_path, "CUST-0011", "Riverside Grill", last)

    _maybe_sweep_recurring_jobs(db_path)
    assert len(_generated_jobs_for(db_path, "CUST-0011")) == 1

    # Mark that pending job Cancelled — if the sweep ran again it WOULD create
    # a second one (per the cancelled-doesn't-block test above); it must not,
    # since it already ran today.
    pending = _generated_jobs_for(db_path, "CUST-0011")
    _sql(db_path, "UPDATE jobs SET job_status = 'Cancelled' WHERE job_id = ?", (pending[0]["job_id"],))
    _maybe_sweep_recurring_jobs(db_path)
    assert len(_generated_jobs_for(db_path, "CUST-0011")) == 1   # unchanged — didn't run again


def test_sweep_runs_again_on_a_new_day(db_path):
    _set_lead_days(db_path, 5)
    last = (TODAY - datetime.timedelta(days=3)).isoformat()
    _create_customer(db_path, "CUST-0012", "Riverside Grill", "Weekly")
    _create_past_job(db_path, "CUST-0012", "Riverside Grill", last)
    _maybe_sweep_recurring_jobs(db_path)
    assert len(_generated_jobs_for(db_path, "CUST-0012")) == 1

    pending = _generated_jobs_for(db_path, "CUST-0012")
    _sql(db_path, "UPDATE jobs SET job_status = 'Cancelled' WHERE job_id = ?", (pending[0]["job_id"],))
    # Back-date the marker to simulate a real new calendar day.
    _sql(db_path, "UPDATE settings SET value = '2000-01-01' WHERE key = 'internal_recurring_job_sweep_last_run'")
    _maybe_sweep_recurring_jobs(db_path)
    assert len(_generated_jobs_for(db_path, "CUST-0012")) == 2   # ran again, created a fresh one


def test_sweep_never_raises_on_bad_data(db_path):
    # A customer row with a frequency but a completely unparsable date on
    # its one job — must be skipped quietly, not crash the whole sweep.
    _create_customer(db_path, "CUST-0013", "Bad Data Co", "Weekly")
    _sql(db_path,
         "INSERT INTO jobs (job_id, customer_id, customer_name, service_date, job_status) "
         "VALUES ('JOB-BAD', 'CUST-0013', 'Bad Data Co', 'not-a-real-date', 'Complete')")
    _maybe_sweep_recurring_jobs(db_path)   # must not raise


# ── The two read-path hooks (the actual gap this review found) ─────────────

@pytest.fixture
def sweep_spy(monkeypatch):
    calls = []
    original = write_ops._maybe_sweep_recurring_jobs

    def spy(db_path):
        calls.append(db_path)
        return original(db_path)

    monkeypatch.setattr(write_ops, "_maybe_sweep_recurring_jobs", spy)
    # db_read_ops.py imported the name directly, so patch its own reference too.
    import db_read_ops
    monkeypatch.setattr(db_read_ops, "_maybe_sweep_recurring_jobs", spy)
    return calls


def test_read_job_spreadsheet_triggers_the_sweep_for_jobs_schedule(db_path, sweep_spy):
    from db_read_ops import db_read_job_spreadsheet
    db_read_job_spreadsheet(db_path, sheet_name="Jobs_Schedule")
    assert sweep_spy == [db_path]


def test_read_job_spreadsheet_does_not_trigger_the_sweep_for_other_sheets(db_path, sweep_spy):
    from db_read_ops import db_read_job_spreadsheet
    db_read_job_spreadsheet(db_path, sheet_name="Customers")
    db_read_job_spreadsheet(db_path, sheet_name="Settings")
    assert sweep_spy == []


def test_board_poll_triggers_the_sweep_the_more_important_path(db_path, sweep_spy):
    # get_board_updates (the Job Board's actual live-poll tool) calls
    # db_get_jobs_changed_since, NOT db_read_job_spreadsheet — this is the
    # real gap the review found: without this hook, a job the sweep created
    # would never appear on the Board until someone separately opened the
    # plain Jobs tab.
    from db_read_ops import db_get_jobs_changed_since
    db_get_jobs_changed_since(db_path, since_iso="2000-01-01T00:00:00", sheet_name="Jobs_Schedule")
    assert sweep_spy == [db_path]


def test_board_poll_does_not_trigger_the_sweep_for_other_sheets(db_path, sweep_spy):
    from db_read_ops import db_get_jobs_changed_since
    db_get_jobs_changed_since(db_path, since_iso="2000-01-01T00:00:00", sheet_name="Customers")
    assert sweep_spy == []


def test_a_job_the_sweep_creates_is_visible_in_the_same_board_poll_that_triggered_it(db_path):
    # End-to-end: a due customer + a Board poll -> the new unscheduled job
    # comes back in THAT SAME poll's results, matching "appears immediately,
    # same as a job an employee or admin added." since_iso is from well in
    # the past (real last_edited_at values use utcnow_iso()'s +00:00-suffixed
    # format — a razor-thin "a few seconds ago" naive-datetime window isn't
    # the point of this test and risks a format/clock-skew false negative).
    _set_lead_days(db_path, 5)
    last = (TODAY - datetime.timedelta(days=3)).isoformat()
    _create_customer(db_path, "CUST-0014", "Riverside Grill", "Weekly")
    _create_past_job(db_path, "CUST-0014", "Riverside Grill", last)

    from db_read_ops import db_get_jobs_changed_since
    rows = db_get_jobs_changed_since(db_path, since_iso="2000-01-01T00:00:00+00:00", sheet_name="Jobs_Schedule")
    # The sweep-created job carries its calculated Service Date (2026-10-04
    # design) — verify it is the one visible in this same poll.
    gen = _generated_jobs_for(db_path, "CUST-0014")
    assert len(gen) == 1
    new_job_ids = {r["JobID (JOB-####)"] for r in rows
                   if r.get("CustomerID (Customers!A)") == "CUST-0014"}
    assert gen[0]["job_id"] in new_job_ids


# ── Settings visibility (the second gap the review found) ──────────────────

def test_lead_time_setting_key_matches_what_the_reader_expects():
    # Locks the exact key string the create_setting call used against what
    # db_read_settings_recurring_job_lead_days actually reads — a live row
    # under a slightly different key would silently never be seen.
    import inspect
    src = inspect.getsource(db_read_settings_recurring_job_lead_days)
    assert "'Recurring Job Lead Time (days)'" in src
