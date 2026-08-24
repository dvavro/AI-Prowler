"""
tests/gui/test_pwa_status_vocabulary_and_edit_form.py
========================================================
Structural tests for the controlled-vocabulary fix requested after a
real bug was found: isJobComplete() was doing substring matching
(s.includes('done')), which would incorrectly match "Not Done" and hide
an explicitly unfinished job. Fixed to exact match against the Excel
dropdown's controlled vocabulary (Scheduled/In Progress/Complete/
Cancelled for Job Status; Unpaid/Paid/Partial for Payment Status).

Also covers a separate, more serious pre-existing bug found while
wiring up the new Payment Status field: window._allSheetJobs (used by
the Jobs Spreadsheet screen's Edit button) only captured 6 of the ~15
fields the edit form actually reads/writes. Opening the edit modal for
an existing job left Date, Times, Service Type, Notes, Crew, Job
Status, Payment Status, and Quote blank, and saving would have written
those blanks back to the spreadsheet — silent data loss on every edit.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
PWA_FILE = SRC_ROOT / "jobs" / "index.html"


@pytest.fixture(scope="module")
def pwa_source():
    return PWA_FILE.read_text(encoding="utf-8")


class TestIsJobCompleteExactMatch:
    def test_no_longer_uses_substring_matching(self, pwa_source):
        """The old buggy line — real code, not the explanatory comment
        that references it — must be gone from the return statement."""
        idx = pwa_source.index("function isJobComplete(j)")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        return_line = body[body.index("return "):]
        assert ".includes(" not in return_line

    def test_uses_exact_equality_against_complete_and_cancelled(self, pwa_source):
        idx = pwa_source.index("function isJobComplete(j)")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "s === 'complete'" in body
        assert "s === 'cancelled'" in body

    def test_normalizes_case_and_whitespace_before_comparing(self, pwa_source):
        idx = pwa_source.index("function isJobComplete(j)")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert ".trim()" in body
        assert ".toLowerCase()" in body


class TestPaymentPaidCheckCaseInsensitive:
    def test_no_longer_case_sensitive_strict_equals(self, pwa_source):
        assert "j.payment==='Paid'" not in pwa_source

    def test_normalizes_before_comparing(self, pwa_source):
        # The normalization is now split across two lines:
        # const _pm = (j.payment||'').trim().toLowerCase()
        # if (_pm === 'paid')
        # Both halves must be present.
        assert "(j.payment||'').trim().toLowerCase()" in pwa_source
        assert "_pm === 'paid'" in pwa_source


class TestJobFormPaymentStatusDropdown:
    """The Payment Status field the request asked to be extended into
    the PWA's own editing form — none existed before this."""

    def test_dropdown_field_exists(self, pwa_source):
        assert 'id="jfPayment"' in pwa_source

    def test_options_match_the_approved_vocabulary(self, pwa_source):
        idx = pwa_source.index('id="jfPayment"')
        nearby = pwa_source[idx:idx + 400]
        for opt in ["Unpaid", "Partial", "Paid"]:
            assert f"<option>{opt}</option>" in nearby, f"Missing payment option: {opt}"

    def test_prefilled_when_editing_existing_job(self, pwa_source):
        idx = pwa_source.index("function openEditJobModal(jobId)")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "jfPayment').value" in body and "j.payment" in body

    def test_included_in_save_updates_payload(self, pwa_source):
        idx = pwa_source.index("const updates = {")
        end_idx = pwa_source.index("};", idx)
        body = pwa_source[idx:end_idx]
        # Strip extra alignment whitespace before checking
        body_compact = ' '.join(body.split())
        assert "'Payment Status': document.getElementById('jfPayment').value" in body_compact


class TestAllSheetJobsFieldMappingFixed:
    """Regression guard for the more serious bug found alongside this
    work — every field the edit form reads or writes must be present in
    window._allSheetJobs, not just the original 6."""

    REQUIRED_FIELDS = [
        "id", "customer", "address", "city", "state", "zip",
        "date", "start", "end", "service", "notes", "crew",
        "status", "payment", "quote",
    ]

    def test_all_required_fields_present_in_mapping(self, pwa_source):
        idx = pwa_source.index("window._allSheetJobs = sheetName === 'Jobs_Schedule'")
        end_idx = pwa_source.index("}; }) : [];", idx)
        body = pwa_source[idx:end_idx]
        for field in self.REQUIRED_FIELDS:
            assert f"{field}:" in body or f"{field}: " in body, f"Missing field mapping: {field}"

    def test_uses_correct_full_header_names_from_backend(self, pwa_source):
        """These must match the exact header text read_job_spreadsheet()
        emits (post _join_header_lines() fix) — not abbreviated or
        guessed names."""
        idx = pwa_source.index("window._allSheetJobs = sheetName === 'Jobs_Schedule'")
        end_idx = pwa_source.index("}; }) : [];", idx)
        body = pwa_source[idx:end_idx]
        assert "r['JobID (JOB-####)']" in body
        assert "r['Customer Name / Company']" in body
        assert "r['Service Date']" in body
        assert "r['Job Status']" in body
        assert "r['Payment Status']" in body
        assert "r['Crew / Technician']" in body
        assert "r['Quote Amount ($)']" in body

    def test_status_and_payment_specifically_no_longer_missing(self, pwa_source):
        """The exact two fields this whole investigation started from —
        confirms they're both now mapped, not just present in the
        broader field list above."""
        idx = pwa_source.index("window._allSheetJobs = sheetName === 'Jobs_Schedule'")
        end_idx = pwa_source.index("}; }) : [];", idx)
        body = pwa_source[idx:end_idx]
        assert "status:  r['Job Status']" in body
        assert "payment: r['Payment Status']" in body


class TestOpenEditJobModalActiveForJobsSchedule:
    """Confirms openEditJobModal() (the function that reads from
    _allSheetJobs) is genuinely the active edit path for Jobs_Schedule
    specifically, not dead code superseded by a different generic
    editor — this is what makes the _allSheetJobs bug actually matter
    in practice, not just in theory."""

    def test_jobs_schedule_routes_to_open_edit_job_modal(self, pwa_source):
        idx = pwa_source.index("if (sheetN === 'Jobs_Schedule') openEditJobModal(rowId);")
        assert idx > 0


class TestJobFormRecurrenceDropdown:
    """Recurrence, expanded and turned into a dropdown alongside Job
    Status / Payment Status. Note: Jobs_Schedule!Recurrence is purely
    informational (never read by any code logic) — the functionally
    important column is Customers!Frequency, which
    schedule_next_recurring_job() actually reads. Both use the same
    expanded vocabulary; see tests/unit/test_contractor_tools.py::
    TestScheduleNextRecurringJobExpandedFrequencies for that side."""

    def test_dropdown_field_exists(self, pwa_source):
        assert 'id="jfRecurrence"' in pwa_source

    def test_options_include_all_eight_expanded_choices(self, pwa_source):
        idx = pwa_source.index('id="jfRecurrence"')
        nearby = pwa_source[idx:idx + 500]
        for opt in ["One-time", "Weekly", "Biweekly", "Monthly",
                    "Bimonthly", "Quarterly", "Semi-Annual", "Annual"]:
            assert f"<option>{opt}</option>" in nearby, f"Missing recurrence option: {opt}"

    def test_prefilled_when_editing_existing_job(self, pwa_source):
        idx = pwa_source.index("function openEditJobModal(jobId)")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "jfRecurrence').value" in body and "j.recurrence" in body

    def test_included_in_save_updates_payload(self, pwa_source):
        idx = pwa_source.index("const updates = {")
        end_idx = pwa_source.index("};", idx)
        body = pwa_source[idx:end_idx]
        body_compact = ' '.join(body.split())
        assert "'Recurrence': document.getElementById('jfRecurrence').value" in body_compact

    def test_recurrence_field_present_in_all_sheet_jobs_mapping(self, pwa_source):
        idx = pwa_source.index("window._allSheetJobs = sheetName === 'Jobs_Schedule'")
        end_idx = pwa_source.index("}; }) : [];", idx)
        body = pwa_source[idx:end_idx]
        assert "recurrence: r['Recurrence']" in body
