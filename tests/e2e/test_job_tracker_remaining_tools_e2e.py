"""
tests/e2e/test_job_tracker_remaining_tools_e2e.py
====================================================
Automated coverage for the job-tracker tools NOT already covered by
test_job_tracker_e2e.py or test_contractor_workflow_e2e.py:

  email_receipt, text_invoice, text_receipt, schedule_next_recurring_job,
  get_weather, geocode_address, get_ar_aging_report

This suite captures, as permanent regression tests, everything found and
fixed during the manual walkthrough that first exercised these tools:

  1. email_receipt() had a hardcoded raw-SMTP-only send that ignored the
     configured Outlook-first backend (same class of bug as email_invoice).
  2. email_receipt()'s HTML table used insufficient line-height, causing
     large unwanted vertical gaps between rows in Outlook.
  3. schedule_next_recurring_job() looked up a Customers-sheet column named
     "Frequency W/BW/M/Q/OT" that does not exist in the current schema
     (the real column is just "Frequency") — this silently made EVERY
     customer's frequency resolve to blank, turning every recurring
     customer into a false "one-time customer", with no error at all.

REQUIREMENTS
------------
  pip install openpyxl
  No ANTHROPIC_API_KEY needed for most of this suite — it calls the
  installed tools directly rather than routing through a Claude tool-use
  eval, since the bugs found here were about tool CORRECTNESS, not tool
  SELECTION (see test_contractor_workflow_e2e.py for the eval-layer tests
  on the tools that overlap).
  SMS tests (text_invoice/text_receipt) do NOT require live Twilio
  credentials — they assert the tool correctly progresses through
  invoice/customer/phone lookup and fails cleanly at the SMS-provider
  check, which is the only thing testable without real credentials.

RUN
---
  pytest tests/e2e/test_job_tracker_remaining_tools_e2e.py -v -s -m job_sheet_e2e
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))
SPREADSHEET_PATH = Path(os.environ.get(
    "AI_PROWLER_JOB_TRACKER_PATH",
    r"C:\Users\david\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx",
))
TEST_EMAIL_TO = "david.vavro1@gmail.com"

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


@pytest.fixture(scope="session")
def pre_suite_backup_path(mcp_module):
    backup_msg = mcp_module._backup_spreadsheet(str(SPREADSHEET_PATH))
    assert "Backup saved" in backup_msg, f"Pre-suite backup failed: {backup_msg}"
    rel_path = backup_msg.split("Backup saved:")[1].split("(")[0].strip()
    return SPREADSHEET_PATH.parent / rel_path


# ---------------------------------------------------------------------------
# Helpers — shared header-detection convention, fixed to derive the data
# start row from the ACTUAL detected header row (see the row-skip bug found
# and fixed in test_job_tracker_e2e.py's find_ztest_job / this suite's own
# earlier draft — never hardcode min_row).
# ---------------------------------------------------------------------------
def _load_sheet_rows(sheet_name: str) -> list[dict]:
    import openpyxl
    wb = openpyxl.load_workbook(str(SPREADSHEET_PATH), data_only=True)
    ws = wb[sheet_name]

    header_row_num = None
    headers = None
    for row in ws.iter_rows(min_row=1, max_row=5):
        non_empty = [c for c in row if c.value is not None]
        if len(non_empty) >= 3:
            header_row_num = row[0].row
            headers = [str(c.value).strip().replace("\n", " ") if c.value else ""
                       for c in row]
            break
    assert headers, f"Could not detect header row in {sheet_name}"

    rows = []
    for row in ws.iter_rows(min_row=header_row_num + 1, values_only=True):
        if any(v is not None for v in row):
            rows.append(dict(zip(headers, row)))
    return rows


def find_row_by_name(sheet_name: str, name_col: str, name_val: str) -> "dict | None":
    for row in _load_sheet_rows(sheet_name):
        if row.get(name_col) == name_val:
            return row
    return None


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------
@pytest.mark.job_sheet_e2e
class TestRemainingJobTrackerTools:

    job_id: "str | None" = None
    invoice_id: "str | None" = None
    customer_id: "str | None" = None

    # ── Setup: one job + invoice + paid customer, shared by several tests ──

    def test_00_seed_job_invoice_customer(self, mcp_module, pre_suite_backup_path):
        cust_result = mcp_module.create_customer(
            updates={
                "Company Name": "ZTEST Remaining Tools",
                "Phone": "386-555-0199",
                "State": "FL",
                "Frequency": "Monthly",
                "Status Active/Inactive": "Active",
            },
            backup=True,
        )
        assert cust_result.startswith("✅"), f"create_customer failed: {cust_result}"
        TestRemainingJobTrackerTools.customer_id = (
            cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip())

        job_result = mcp_module.create_job(
            updates={
                "CustomerID (Customers!A)": self.customer_id,
                "Customer Name / Company": "ZTEST Remaining Tools",
                "Street Address": "412 Pelican Dr",
                "City": "Daytona Beach",
                "State": "FL",
                "ZIP": "32118",
                "Job Status": "Completed",
                "Quote Amount ($)": 100,
                "Service Date": "2026-07-01",
                "Service Type": "Window Washing",
            },
            backup=True,
        )
        assert job_result.startswith("✅"), f"create_job failed: {job_result}"
        TestRemainingJobTrackerTools.job_id = (
            job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip())

        inv_result = mcp_module.create_invoice(job_identifier=self.job_id)
        assert inv_result.startswith("✅"), f"create_invoice failed: {inv_result}"
        TestRemainingJobTrackerTools.invoice_id = (
            inv_result.split("NEW_INVOICE_ID=")[1].splitlines()[0].strip())

        mcp_module.update_job_spreadsheet(
            job_identifier=self.job_id,
            id_column="JobID (JOB-####)",
            updates={"Payment Status": "Paid"},
        )

    # ── email_receipt ────────────────────────────────────────────────────

    def test_01_email_receipt_sends_via_configured_backend(self, mcp_module):
        """Regression test for the hardcoded-raw-SMTP bug: email_receipt()
        used to bypass _send_smtp() entirely, so an Outlook-configured
        install (no password needed) would still fail here if the SMTP
        app password field happened to be blank/stale. This just asserts
        the call succeeds using WHATEVER backend is actually configured —
        it does not assume Outlook specifically, since that depends on
        the machine running the suite.
        """
        result = mcp_module.email_receipt(
            invoice_identifier=self.invoice_id,
            payment_method="Cash",
            to=TEST_EMAIL_TO,
        )
        assert result.startswith("✅"), (
            f"email_receipt failed — possible regression of the "
            f"hardcoded-SMTP bug (see email_invoice's identical fix): {result}"
        )

    def test_01b_email_receipt_html_has_no_missing_line_height(
            self, mcp_module):
        """Regression test for the excess-vertical-space bug: the receipt's
        Receipt Details table rows lacked an explicit line-height, letting
        Outlook fall back to a much larger default and producing big gaps
        between rows. Intercepts the real HTML the send would have used
        (no second live email — test_01 above already sent one)."""
        captured = {}

        def _fake_send_smtp(to, subject, body, body_html=None, **kwargs):
            captured["body_html"] = body_html
            return (True, "✅ intercepted, not actually sent")

        import ai_prowler_mcp as _m
        _real_send_smtp = _m._send_smtp
        _m._send_smtp = _fake_send_smtp
        try:
            mcp_module.email_receipt(
                invoice_identifier=self.invoice_id,
                payment_method="Cash",
                to=TEST_EMAIL_TO,
            )
        finally:
            _m._send_smtp = _real_send_smtp

        html = captured.get("body_html", "")
        assert html, "email_receipt did not produce an HTML body to inspect"
        assert "line-height" in html, (
            "REGRESSION: Receipt Details table rows have no explicit "
            "line-height again — this previously caused large unwanted "
            "vertical gaps between rows in Outlook."
        )
        assert "display: flex" not in html, (
            "REGRESSION: receipt template uses display:flex — unreliable "
            "in email clients, same class of bug fixed in email_invoice."
        )

    # ── text_invoice / text_receipt ──────────────────────────────────────

    def test_02_text_invoice_reaches_sms_provider_check(self, mcp_module):
        """Without live Twilio/SignalWire/Vonage credentials, the only
        testable assertion is that text_invoice() correctly resolves the
        invoice and the customer's phone number, and fails specifically at
        the SMS-provider-not-configured step — not at an earlier lookup
        step, which would indicate a real regression in invoice/customer
        resolution rather than a missing (expected, in CI) SMS provider.
        """
        result = mcp_module.text_invoice(invoice_identifier=self.invoice_id)
        assert "Twilio is not configured" in result or "✅" in result, (
            f"Expected either a successful send (if SMS IS configured on "
            f"this machine) or a clean 'Twilio is not configured' failure "
            f"— got something else, which may indicate a regression in "
            f"invoice or phone-number resolution: {result}"
        )

    def test_02b_text_receipt_reaches_sms_provider_check(self, mcp_module):
        result = mcp_module.text_receipt(
            invoice_identifier=self.invoice_id, payment_method="Cash")
        assert "Twilio is not configured" in result or "✅" in result, (
            f"Expected either a successful send or a clean "
            f"'Twilio is not configured' failure: {result}"
        )

    # ── schedule_next_recurring_job ──────────────────────────────────────

    def test_03_schedule_next_recurring_job_reads_frequency_correctly(
            self, mcp_module):
        """Regression test for the stale-column-name bug: this tool used
        to look up "Frequency W/BW/M/Q/OT" (a column name that does not
        exist in the current Customers sheet schema — the real column is
        "Frequency"), so frequency ALWAYS resolved to blank and every
        customer was silently treated as one-time, with no error message
        indicating anything was wrong. This test's customer has
        Frequency=Monthly set explicitly in test_00 — if this regresses,
        the tool will incorrectly report "one-time customer" here.
        """
        result = mcp_module.schedule_next_recurring_job(
            job_identifier=self.job_id, when="any")
        assert result.startswith("✅"), (
            f"REGRESSION: schedule_next_recurring_job did not create a "
            f"next job for a Monthly-frequency customer — likely the "
            f"stale 'Frequency W/BW/M/Q/OT' column-name bug is back: "
            f"{result}"
        )
        assert "Monthly" in result, (
            f"Expected 'Monthly' frequency to be reported: {result}"
        )

        # Verify the actual next Service Date is +1 calendar month from
        # the completed job's Service Date (2026-07-01 -> 2026-08-01),
        # not just that SOME row got created.
        row = find_row_by_name(
            "Jobs_Schedule", "Customer Name / Company",
            "ZTEST Remaining Tools")
        # find_row_by_name returns the FIRST match — with 2 jobs for this
        # customer now (the original + the new recurring one), get all of
        # them and check the newest Service Date specifically.
        all_rows = [r for r in _load_sheet_rows("Jobs_Schedule")
                    if r.get("Customer Name / Company") == "ZTEST Remaining Tools"]
        assert len(all_rows) == 2, (
            f"Expected exactly 2 jobs (original + 1 recurring), "
            f"found {len(all_rows)}"
        )
        import datetime as _dt
        dates = []
        for r in all_rows:
            sd = r.get("Service Date")
            if isinstance(sd, (_dt.date, _dt.datetime)):
                dates.append(sd.date() if isinstance(sd, _dt.datetime) else sd)
        dates.sort()
        assert dates[0] == _dt.date(2026, 7, 1)
        assert dates[1] == _dt.date(2026, 8, 1), (
            f"Expected next Service Date to be exactly 1 month after "
            f"2026-07-01 (i.e. 2026-08-01), got {dates[1]}"
        )

    def test_03b_new_recurring_row_lands_adjacent_to_real_data(self, mcp_module):
        """Same row-placement regression check used in test_job_tracker_e2e.py
        for create_job — schedule_next_recurring_job shares the identical
        'next empty row' logic and the identical historical bug."""
        import openpyxl
        wb = openpyxl.load_workbook(str(SPREADSHEET_PATH), data_only=True)
        ws = wb["Jobs_Schedule"]

        header_row_idx = None
        for row in ws.iter_rows(min_row=1, max_row=5):
            non_empty = [c for c in row if c.value is not None]
            if len(non_empty) >= 3:
                header_row_idx = row[0].row
                break
        assert header_row_idx is not None

        job_rows = []
        for row in ws.iter_rows(min_row=header_row_idx + 1):
            val = row[0].value
            if val and str(val).startswith("JOB-"):
                job_rows.append(row[0].row)

        assert job_rows, "No JobID rows found"
        assert max(job_rows) - min(job_rows) <= 5, (
            f"REGRESSION: recurring job row landed far from the other "
            f"job rows ({job_rows}) — the next-empty-row placement bug "
            f"may be back."
        )

    # ── get_weather ───────────────────────────────────────────────────────

    def test_04_get_weather_returns_forecast(self, mcp_module):
        result = mcp_module.get_weather(location="Daytona Beach, FL", days=3)
        assert "❌" not in result, f"get_weather failed: {result}"
        assert "°F" in result or "°C" in result, (
            f"Expected a temperature in the forecast: {result}"
        )

    # ── geocode_address ───────────────────────────────────────────────────

    def test_05_geocode_address_returns_coordinates(self, mcp_module):
        """Not asserting a SPECIFIC lat/lon — free-tier Nominatim geocoding
        was found to be genuinely ambiguous for at least one real address
        in this project's own test data (resolved to a different street
        name and ZIP than requested). This test only confirms the tool
        itself works correctly (returns parseable coordinates), which is
        a different concern than whether a given address string happens
        to be unambiguous."""
        result = mcp_module.geocode_address(
            address="1500 Shadow Pines Dr, New Smyrna Beach FL 32168")
        assert "❌" not in result, f"geocode_address failed: {result}"
        assert "Latitude:" in result and "Longitude:" in result, (
            f"Expected lat/lon in output: {result}"
        )

    # ── get_ar_aging_report ───────────────────────────────────────────────

    def test_06_ar_aging_report_current_bucket(self, mcp_module):
        """The seeded invoice (test_00) is due 30 days out from today —
        it should land in the 'Current (not yet due)' bucket."""
        result = mcp_module.get_ar_aging_report()
        assert "❌" not in result, f"get_ar_aging_report failed: {result}"
        assert self.invoice_id in result, (
            f"Expected {self.invoice_id} in the AR aging report: {result}"
        )
        assert "Current" in result, (
            f"Expected the seeded invoice in the Current bucket: {result}"
        )

    def test_06b_ar_aging_report_90_plus_bucket(self, mcp_module):
        """Same invoice, viewed from far enough in the future that it's
        now well past its due date — should move to the 90+ bucket."""
        result = mcp_module.get_ar_aging_report(as_of_date="2027-02-01")
        assert "❌" not in result, f"get_ar_aging_report failed: {result}"
        assert self.invoice_id in result
        assert "90+" in result, (
            f"Expected the seeded invoice in the 90+ overdue bucket when "
            f"viewed from 2027-02-01: {result}"
        )

    # ── Cleanup ───────────────────────────────────────────────────────────

    def test_99_restore_backup_on_full_pass(self, mcp_module,
                                             pre_suite_backup_path):
        import shutil
        assert pre_suite_backup_path.exists(), (
            f"Pre-suite backup missing: {pre_suite_backup_path}"
        )
        shutil.copy2(str(pre_suite_backup_path), str(SPREADSHEET_PATH))

        assert find_row_by_name(
            "Jobs_Schedule", "Customer Name / Company",
            "ZTEST Remaining Tools") is None
        assert find_row_by_name(
            "Customers", "Company Name", "ZTEST Remaining Tools") is None
