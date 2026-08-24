"""
tests/mcp/test_read_job_spreadsheet_crew_scope.py
===================================================
Tests for read_job_spreadsheet's new server-mode crew-filtering logic
(Phase 3 of the server-mode Jobs PWA plan).

Reuses a REAL temp .xlsx workbook (openpyxl) rather than mocking — header
detection, column matching, and row filtering are exactly the kind of logic
that needs real parsing coverage, not a mocked stand-in. Follows the same
_make_ctx()/_server_user() pattern already established in
test_job_spreadsheet_scope.py.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

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


def _crew_user(uid="jake-r", name="Jake R", role="field_crew"):
    return {"id": uid, "name": name, "role": role, "status": "active", "scopes": []}


def _make_jobs_workbook(path, rows, headers=None, sheet_name="Jobs_Schedule"):
    """
    rows: list of dicts using header names as keys. Any header not present
    in a row defaults to blank. Always includes at least JobID, Customer
    Name / Company, Service Date, Crew / Technician unless headers is
    overridden (used for the "no Crew column at all" Model-B test).
    """
    import openpyxl
    if headers is None:
        headers = ["JobID (JOB-####)", "Customer Name / Company",
                   "Service Date", "Crew / Technician"]
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet_name
    ws.append(headers)
    for r in rows:
        ws.append([r.get(h, "") for h in headers])
    wb.save(str(path))


class TestModelAsharedSpreadsheetCrewFiltering:
    """4a-4d from the server-mode plan's testing section."""

    def test_field_crew_sees_only_own_rows(self, mcp_mod, monkeypatch, tmp_path):
        fp = tmp_path / "master.xlsx"
        _make_jobs_workbook(fp, [
            {"JobID (JOB-####)": "JOB-0001", "Customer Name / Company": "Alpha Co",
             "Crew / Technician": "Jake R"},
            {"JobID (JOB-####)": "JOB-0002", "Customer Name / Company": "Beta Co",
             "Crew / Technician": "Someone Else"},
        ])
        user = _crew_user()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(fp))
        monkeypatch.setattr(mcp_mod, "_resolve_job_spreadsheet_path", lambda ctx, fp_arg: str(fp))

        result = mcp_mod.read_job_spreadsheet(ctx=_make_ctx(user))
        assert "JOB-0001" in result
        assert "JOB-0002" not in result

    def test_owner_sees_every_row_unfiltered(self, mcp_mod, monkeypatch, tmp_path):
        fp = tmp_path / "master.xlsx"
        _make_jobs_workbook(fp, [
            {"JobID (JOB-####)": "JOB-0001", "Crew / Technician": "Jake R"},
            {"JobID (JOB-####)": "JOB-0002", "Crew / Technician": "Someone Else"},
        ])
        owner = {"id": "owner-1", "name": "David", "role": "owner", "status": "active", "scopes": []}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: owner)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(fp))
        monkeypatch.setattr(mcp_mod, "_resolve_job_spreadsheet_path", lambda ctx, fp_arg: str(fp))

        result = mcp_mod.read_job_spreadsheet(ctx=_make_ctx(owner))
        assert "JOB-0001" in result
        assert "JOB-0002" in result

    def test_blank_crew_row_excluded_from_field_crew(self, mcp_mod, monkeypatch, tmp_path):
        """4c: an unassigned row must NOT leak to every crew member."""
        fp = tmp_path / "master.xlsx"
        _make_jobs_workbook(fp, [
            {"JobID (JOB-####)": "JOB-0001", "Crew / Technician": "Jake R"},
            {"JobID (JOB-####)": "JOB-0003", "Crew / Technician": ""},
        ])
        user = _crew_user()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(fp))
        monkeypatch.setattr(mcp_mod, "_resolve_job_spreadsheet_path", lambda ctx, fp_arg: str(fp))

        result = mcp_mod.read_job_spreadsheet(ctx=_make_ctx(user))
        assert "JOB-0001" in result
        assert "JOB-0003" not in result

    def test_crew_matching_is_case_and_whitespace_tolerant(self, mcp_mod, monkeypatch, tmp_path):
        """4d: matches schedule_next_recurring_job's tolerant comparison."""
        fp = tmp_path / "master.xlsx"
        _make_jobs_workbook(fp, [
            {"JobID (JOB-####)": "JOB-0001", "Crew / Technician": "  JAKE r  "},
        ])
        user = _crew_user(name="Jake R")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(fp))
        monkeypatch.setattr(mcp_mod, "_resolve_job_spreadsheet_path", lambda ctx, fp_arg: str(fp))

        result = mcp_mod.read_job_spreadsheet(ctx=_make_ctx(user))
        assert "JOB-0001" in result

    def test_customers_sheet_never_filtered_regardless_of_role(self, mcp_mod, monkeypatch, tmp_path):
        """Filtering must be scoped to Jobs_Schedule only — Customers stays
        fully readable for send_email/send_sms lookups, per the original
        design intent this feature must not break."""
        fp = tmp_path / "master.xlsx"
        _make_jobs_workbook(
            fp,
            [{"Name": "Alpha Co", "Email": "alpha@example.com", "Phone": "386-555-0101"},
             {"Name": "Beta Co", "Email": "beta@example.com", "Phone": "386-555-0102"}],
            headers=["Name", "Email", "Phone"],
            sheet_name="Customers",
        )
        user = _crew_user()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(fp))
        monkeypatch.setattr(mcp_mod, "_resolve_job_spreadsheet_path", lambda ctx, fp_arg: str(fp))

        result = mcp_mod.read_job_spreadsheet(ctx=_make_ctx(user), sheet_name="Customers")
        assert "Alpha Co" in result
        assert "Beta Co" in result


class TestModelBperUserFileSkipsFiltering:
    """5a from the server-mode plan's testing section."""

    def test_own_file_sees_all_rows_with_no_filtering_even_without_crew_column(
        self, mcp_mod, monkeypatch, tmp_path
    ):
        """A user resolved to their OWN per-user file must see every row in
        it, with no additional Crew-column filtering — even if that file
        has no Crew/Technician column at all, which would otherwise be
        misread as "every row is unassigned, therefore hidden.\""""
        master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
        own_file = tmp_path / "jake-r.xlsx"
        _make_jobs_workbook(
            own_file,
            [{"JobID (JOB-####)": "JOB-0009", "Customer Name / Company": "Own Customer",
              "Service Date": "2026-08-16"}],
            headers=["JobID (JOB-####)", "Customer Name / Company", "Service Date"],  # no Crew column at all
        )
        user = _crew_user(uid="jake-r")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
        # Real resolver behavior: per-user file wins because it exists.
        monkeypatch.setattr(mcp_mod, "_resolve_job_spreadsheet_path",
                             lambda ctx, fp_arg: str(own_file))

        result = mcp_mod.read_job_spreadsheet(ctx=_make_ctx(user))
        assert "JOB-0009" in result


class TestPersonalModeUnaffected:

    def test_personal_mode_no_ctx_sees_everything_unfiltered(self, mcp_mod, monkeypatch, tmp_path):
        """Regression guard: ctx=None (personal mode) must behave exactly
        as it did before this feature existed — no filtering whatsoever."""
        fp = tmp_path / "master.xlsx"
        _make_jobs_workbook(fp, [
            {"JobID (JOB-####)": "JOB-0001", "Crew / Technician": "Anyone"},
            {"JobID (JOB-####)": "JOB-0002", "Crew / Technician": ""},
        ])
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(fp))
        monkeypatch.setattr(mcp_mod, "_resolve_job_spreadsheet_path", lambda ctx, fp_arg: str(fp))

        result = mcp_mod.read_job_spreadsheet(ctx=None)
        assert "JOB-0001" in result
        assert "JOB-0002" in result
