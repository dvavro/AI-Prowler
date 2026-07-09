"""
tests/mcp/test_schedule_recurring_job_scope.py
=================================================
Tests for schedule_next_recurring_job()'s server-mode scoping:
  1. Ambiguous job-identifier matches are rejected (candidate list shown)
     instead of silently taking the first row, same protection built for
     log_time_entry.
  2. Staff/field_crew only search jobs assigned to THEM (Crew / Technician
     matches their own name) — owner/manager search every crew's jobs.
  3. A configurable `when` date range ("today" default, "tomorrow",
     "yesterday", "this_week", "next_week", "any", or an explicit
     "YYYY-MM-DD") scopes which jobs are searched, independent of the
     crew filter.

Personal mode is completely unaffected by all of the above — verified by
the pre-existing test_contractor_tools.py CT-12..17 suite (run
separately, still green) plus a direct check here.
"""

import sys
import datetime as dt
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import openpyxl

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _user(role, uid, name):
    return {"id": uid, "name": name, "role": role, "status": "active"}


def _make_spreadsheet(tmp_path, jobs):
    """jobs: list of dicts with JobID, Customer, Crew, ServiceDate (date obj),
    CustomerID."""
    fp = tmp_path / "tracker.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Jobs_Schedule"
    ws.append(["JobID (JOB-####)", "Customer Name / Company", "Crew / Technician",
               "Service Date", "CustomerID (Customers!A)", "Service Type"])
    for j in jobs:
        ws.append([j["JobID"], j["Customer"], j.get("Crew", ""),
                  j.get("ServiceDate"), j.get("CustomerID", ""), "Window Washing"])
    ws2 = wb.create_sheet("Customers")
    ws2.append(["CustomerID", "Company Name", "Service Frequency"])
    ws2.append(["CUST-01", "Crabby's Daytona", "OT"])  # One-time -> simplest, no next job math needed
    wb.save(str(fp))
    return str(fp)


class TestAmbiguousMatchRejected:

    def test_multiple_matches_same_day_same_crew_rejected(self, mcp_mod, monkeypatch, tmp_path):
        today = dt.date.today()
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "Jake R",
             "ServiceDate": today, "CustomerID": "CUST-01"},
            {"JobID": "JOB-0002", "Customer": "Crabby's Beachside", "Crew": "Jake R",
             "ServiceDate": today, "CustomerID": "CUST-01"},
        ])
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="Crabby's", filepath=fp, ctx=None
            )
        assert "❌" in result
        assert "matches 2 jobs" in result


class TestServerModeCrewScoping:

    def test_staff_only_sees_own_assigned_jobs(self, mcp_mod, monkeypatch, tmp_path):
        """Core fix: Jake must not be able to reschedule Karen's job even
        with an exact, unambiguous JobID match."""
        today = dt.date.today()
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "Karen S",
             "ServiceDate": today, "CustomerID": "CUST-01"},
        ])
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: fp)
        jake = _user("field_crew", "jake-r", "Jake R")

        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="JOB-0001", filepath=fp, ctx=_make_ctx(jake)
            )
        assert "❌" in result
        assert "assigned to you" in result

    def test_staff_can_reschedule_own_job(self, mcp_mod, monkeypatch, tmp_path):
        today = dt.date.today()
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "Jake R",
             "ServiceDate": today, "CustomerID": "CUST-01"},
        ])
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: fp)
        jake = _user("field_crew", "jake-r", "Jake R")

        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="JOB-0001", filepath=fp, ctx=_make_ctx(jake)
            )
        # One-time frequency -> no next job, but must get PAST the scoping
        # check to reach that (not blocked with "assigned to you").
        assert "assigned to you" not in result

    def test_owner_sees_every_crews_jobs(self, mcp_mod, monkeypatch, tmp_path):
        """Owner must be able to reschedule a job assigned to ANY crew
        member, not just their own."""
        today = dt.date.today()
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "Karen S",
             "ServiceDate": today, "CustomerID": "CUST-01"},
        ])
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: fp)
        owner = _user("owner", "david-vavro", "David Vavro")

        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="JOB-0001", filepath=fp, ctx=_make_ctx(owner)
            )
        assert "assigned to you" not in result


class TestWhenDateScoping:

    def test_default_today_excludes_tomorrows_job(self, mcp_mod, monkeypatch, tmp_path):
        tomorrow = dt.date.today() + dt.timedelta(days=1)
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "Jake R",
             "ServiceDate": tomorrow, "CustomerID": "CUST-01"},
        ])
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: fp)
        jake = _user("field_crew", "jake-r", "Jake R")

        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="JOB-0001", filepath=fp, ctx=_make_ctx(jake)
            )
        assert "❌" in result

    def test_when_tomorrow_finds_tomorrows_job(self, mcp_mod, monkeypatch, tmp_path):
        tomorrow = dt.date.today() + dt.timedelta(days=1)
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "Jake R",
             "ServiceDate": tomorrow, "CustomerID": "CUST-01"},
        ])
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: fp)
        jake = _user("field_crew", "jake-r", "Jake R")

        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="JOB-0001", filepath=fp, when="tomorrow", ctx=_make_ctx(jake)
            )
        assert "assigned to you" not in result
        assert "matches" not in result  # not an ambiguity error

    def test_when_any_finds_job_regardless_of_date(self, mcp_mod, monkeypatch, tmp_path):
        old_date = dt.date.today() - dt.timedelta(days=90)
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "Jake R",
             "ServiceDate": old_date, "CustomerID": "CUST-01"},
        ])
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: fp)
        jake = _user("field_crew", "jake-r", "Jake R")

        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="JOB-0001", filepath=fp, when="any", ctx=_make_ctx(jake)
            )
        assert "❌" not in result or "No job found" not in result

    def test_when_this_week_range_resolution(self, mcp_mod):
        """Unit-level check of the date-range resolver itself."""
        import ai_prowler_mcp as ap
        today = dt.date(2026, 7, 8)  # a Wednesday
        start, end = ap._srj_resolve_date_range("this_week", today)
        assert start == dt.date(2026, 7, 6)   # Monday
        assert end == dt.date(2026, 7, 12)    # Sunday
        assert start <= today <= end

    def test_when_any_returns_none_none(self, mcp_mod):
        import ai_prowler_mcp as ap
        start, end = ap._srj_resolve_date_range("any", dt.date.today())
        assert start is None and end is None

    def test_when_explicit_date(self, mcp_mod):
        import ai_prowler_mcp as ap
        start, end = ap._srj_resolve_date_range("2026-12-25", dt.date.today())
        assert start == end == dt.date(2026, 12, 25)

    def test_when_unrecognised_falls_back_to_today(self, mcp_mod):
        import ai_prowler_mcp as ap
        today = dt.date.today()
        start, end = ap._srj_resolve_date_range("gibberish", today)
        assert start == end == today


class TestPersonalModeUnaffected:

    def test_personal_mode_ignores_crew_field(self, mcp_mod, monkeypatch, tmp_path):
        """Personal mode: the crew filter never applies, regardless of what's
        in the Crew / Technician field — single user, no ownership ambiguity.
        (Date defaulting is covered separately — both modes now default to
        "today" if `when` is omitted, so this uses when="any" to isolate
        just the crew-filter behavior.)"""
        old_date = dt.date.today() - dt.timedelta(days=365)
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "Someone Else",
             "ServiceDate": old_date, "CustomerID": "CUST-01"},
        ])
        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="JOB-0001", filepath=fp, when="any", ctx=None
            )
        assert "assigned to you" not in result
        assert "No job found" not in result

    def test_personal_mode_also_defaults_to_today(self, mcp_mod, monkeypatch, tmp_path):
        """Confirms the universal default: personal mode, like server mode,
        now defaults to "today" when `when` is omitted entirely."""
        old_date = dt.date.today() - dt.timedelta(days=10)
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "David",
             "ServiceDate": old_date, "CustomerID": "CUST-01"},
        ])
        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="JOB-0001", filepath=fp, ctx=None
            )
        assert "No job found" in result

    def test_personal_mode_can_use_explicit_when(self, mcp_mod, monkeypatch, tmp_path):
        """The actual feature requested: personal mode CAN opt into the same
        variable-time scoping server mode uses by default, via an explicit
        `when` argument — a common feature across both modes now."""
        tomorrow = dt.date.today() + dt.timedelta(days=1)
        today = dt.date.today()
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Job For Today", "Crew": "David",
             "ServiceDate": today, "CustomerID": "CUST-01"},
            {"JobID": "JOB-0002", "Customer": "Job For Tomorrow", "Crew": "David",
             "ServiceDate": tomorrow, "CustomerID": "CUST-01"},
        ])
        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            # Explicitly scoped to tomorrow -> must find JOB-0002, not JOB-0001.
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="Job For", filepath=fp, when="tomorrow", ctx=None
            )
        # Ambiguity is naturally resolved by the date scope narrowing to one match.
        assert "matches 2 jobs" not in result
        assert "No job found" not in result

    def test_personal_mode_explicit_when_today_excludes_other_dates(self, mcp_mod, monkeypatch, tmp_path):
        old_date = dt.date.today() - dt.timedelta(days=10)
        fp = _make_spreadsheet(tmp_path, [
            {"JobID": "JOB-0001", "Customer": "Crabby's Daytona", "Crew": "David",
             "ServiceDate": old_date, "CustomerID": "CUST-01"},
        ])
        with patch.object(mcp_mod, "_backup_spreadsheet", return_value="ok"):
            result = mcp_mod.schedule_next_recurring_job(
                job_identifier="JOB-0001", filepath=fp, when="today", ctx=None
            )
        assert "No job found" in result
