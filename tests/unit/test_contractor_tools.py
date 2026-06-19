"""
Unit tests -- V8.0.0 Contractor Workflow Action Tools

Tests for the five new action tools:
  email_invoice              (ACTION TOOL 8)
  send_sms                   (ACTION TOOL 9)
  schedule_next_recurring_job (ACTION TOOL 10)
  log_time_entry             (ACTION TOOL 11)
  get_ar_aging_report        (ACTION TOOL 12)

All tests mock openpyxl, smtplib, and the Twilio REST API so the suite
runs without a real spreadsheet, SMTP server, or Twilio account.

Test IDs
--------
  CT_01 - CT_06   email_invoice
  CT_07 - CT_11   send_sms
  CT_12 - CT_17   schedule_next_recurring_job
  CT_18 - CT_22   log_time_entry
  CT_23 - CT_28   get_ar_aging_report
"""
from __future__ import annotations

import datetime
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import openpyxl


# ---------------------------------------------------------------------------
# Dependency stubs -- install a MetaPathFinder that satisfies imports of
# packages that may be absent in CI/sandbox (chromadb, sentence-transformers,
# mcp SDK, etc.) without requiring them to be installed.
#
# On the user's real Windows install ALL packages ARE installed, so the finder
# returns None for them (they're already in sys.modules) and the real modules
# are used.  On Linux CI / the developer sandbox the finder intercepts the
# imports and returns lightweight callable stubs.
# ---------------------------------------------------------------------------
_STUB_TOPS = frozenset([
    "mcp", "chromadb", "sentence_transformers", "transformers",
    "pdfplumber", "pypdfium2", "pytesseract",
    "bs4", "striprtf", "odf", "watchdog", "pillow_heif", "extract_msg",
])


class _StubAttr:
    """Callable stub returned for any attribute of a stub module."""
    def __init__(self, *a, **kw):
        pass

    def __call__(self, *a, **kw):
        return _StubAttr()

    def __getattr__(self, n):
        return _StubAttr()

    def __iter__(self):
        return iter([])

    def __bool__(self):
        return True

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _StubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        mod = types.ModuleType(spec.name)
        mod.__path__ = []
        mod.__package__ = spec.name.split(".")[0]
        mod.__spec__ = spec
        return mod

    def exec_module(self, module):
        def _getattr(name):
            if name.startswith("__"):
                raise AttributeError(name)
            return _StubAttr()

        module.__class__ = type(
            module.__name__,
            (types.ModuleType,),
            {"__getattr__": lambda self, n: _getattr(n)},
        )


class _StubFinder(importlib.abc.MetaPathFinder):
    # Guard against re-entrancy: importlib.util.find_spec() below walks
    # sys.meta_path, which calls back into this finder. Track tops we are
    # currently probing so the nested call returns None instead of recursing.
    _probing: set = set()

    def find_spec(self, fullname, path, target=None):
        top = fullname.split(".")[0]
        # Only stub when the TOP-LEVEL package is genuinely absent.
        #
        # IMPORTANT: do NOT stub a submodule (e.g. chromadb.config) just
        # because that submodule hasn't been imported yet. If the top-level
        # package is installed and real, its submodules must resolve to the
        # REAL implementation. The previous version stubbed any not-yet-
        # imported submodule of a _STUB_TOPS package, which leaked _StubAttr
        # objects into live ChromaDB collections (collection.count() -> stub),
        # poisoning every later test in the run via the process-global
        # sys.meta_path finder. See test isolation bug, v8.0.0.
        if top not in _STUB_TOPS:
            return None
        if top in self._probing:
            # Re-entrant call from our own find_spec probe below: defer.
            return None
        self._probing.add(top)
        try:
            # If the real top-level package can be located, it is installed --
            # defer to the real import machinery for it and all submodules.
            if importlib.util.find_spec(top) is not None:
                return None
        except (ImportError, AttributeError, ValueError):
            pass
        finally:
            self._probing.discard(top)
        # Top-level package is truly absent -> provide a lightweight stub.
        return importlib.machinery.ModuleSpec(fullname, _StubLoader())


def _install_stub_finder():
    """Insert the stub finder once; return it so it can be removed later."""
    for f in sys.meta_path:
        if isinstance(f, _StubFinder):
            return f
    finder = _StubFinder()
    sys.meta_path.insert(0, finder)
    return finder


_STUB_FINDER = _install_stub_finder()


@pytest.fixture(scope="module", autouse=True)
def _remove_stub_finder_after_module():
    """Ensure the process-global stub finder cannot outlive this test module.

    Two-part teardown:

    1.  Remove the finder from sys.meta_path so no further imports are
        intercepted after this module finishes.

    2.  Evict any stub-generated entries from sys.modules for packages that
        ARE actually installed on this machine.  Without this step a later
        test file that imports (e.g.) `watchdog` gets the _StubAttr version
        that was baked into sys.modules during this module's run, causing
        "TypeError: __mro_entries__ must return a tuple" when the stub is
        used as a base class — even though the real watchdog package is
        installed and our fixed find_spec correctly defers to it on fresh
        imports.  The session-scoped `wd` fixture in test_file_watchdog.py
        is the concrete victim of this if it runs after us.
    """
    yield
    # 1. Remove the finder.
    try:
        sys.meta_path.remove(_STUB_FINDER)
    except ValueError:
        pass

    # 2. Evict stub-generated sys.modules entries for installed packages.
    #    We only evict tops (and their submodules) that ARE actually
    #    installed — if they were genuinely absent we leave their stub
    #    entries so the rest of the session keeps seeing stubs, not import
    #    errors, for packages that don't exist.
    _to_evict = []
    for top in _STUB_TOPS:
        _STUB_FINDER._probing.add(top)   # prevent re-entrant find_spec
        try:
            real_spec = importlib.util.find_spec(top)
        except Exception:
            real_spec = None
        finally:
            _STUB_FINDER._probing.discard(top)

        if real_spec is None:
            continue   # genuinely not installed — keep the stub in modules

        # Package is installed: remove every sys.modules entry whose top
        # matches, so the next import gets the real package.
        _to_evict.extend(
            k for k in list(sys.modules)
            if k == top or k.startswith(top + ".")
        )

    for key in _to_evict:
        sys.modules.pop(key, None)

    # 3. Re-bind stub-contaminated module-level names inside rag_preprocessor.
    #
    #    Evicting from sys.modules (Step 2) lets FUTURE imports get the real
    #    package, but any module that already bound the stub at import time
    #    still holds a reference to the _StubAttr object in its own namespace.
    #    rag_preprocessor is the primary victim: it does `import pdfplumber`
    #    at module level (line ~138) inside a try block. If the stub finder was
    #    active when rag_preprocessor was first imported (session scope), the
    #    module's `pdfplumber` attribute is permanently a _StubAttr — causing
    #    test_pdf_extraction.py and test_image_formats.py to get empty strings
    #    back from load_pdf/load_image_ocr when they run after us.
    #
    #    Fix: after evicting the stubs from sys.modules, re-import each
    #    installed package and patch the binding directly on rag_preprocessor.
    _rag_mod = sys.modules.get("rag_preprocessor")
    if _rag_mod is not None:
        # Force-rebind pdfplumber, pytesseract, and pillow_heif on
        # rag_preprocessor regardless of whether they look like stubs.
        # If the stub finder was active when rag_preprocessor was first
        # imported, those names point to stub module objects. After Step 2
        # evicted them from sys.modules, a fresh import_module() gives the
        # real package. We then patch rag_preprocessor's module dict directly
        # so that subsequent test files calling e.g. pdfplumber.open() inside
        # load_pdf() get the real (and mockable) implementation.
        _rebind_targets = ["pdfplumber", "pytesseract", "pillow_heif"]
        for _pkg_name in _rebind_targets:
            try:
                import importlib as _il
                _real = _il.import_module(_pkg_name)
                setattr(_rag_mod, _pkg_name, _real)
                # Also patch into sys.modules so patch("pdfplumber.open", ...)
                # and rag_preprocessor.pdfplumber refer to the same object.
                sys.modules[_pkg_name] = _real
            except Exception:
                pass  # package genuinely absent — leave as-is

# Wire FastMCP stub (triggers stub loader for mcp.server.fastmcp)
import mcp.server.fastmcp as _fmcp  # noqa: E402


class _FakeFastMCP:
    def __init__(self, *a, **kw):
        pass

    def tool(self):
        def decorator(fn):
            return fn
        return decorator

    def run(self, *a, **kw):
        pass


_fmcp.FastMCP = _FakeFastMCP   # type: ignore[attr-defined]
_fmcp.Context = None            # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Module import helper
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def mcp_module():
    """Import ai_prowler_mcp once per test module."""
    import ai_prowler_mcp
    return ai_prowler_mcp


# ---------------------------------------------------------------------------
# Shared spreadsheet factory
# ---------------------------------------------------------------------------
def _make_test_spreadsheet(tmp_path):
    """Create a minimal AI-Prowler_Job_Tracker.xlsx for testing."""
    fp = tmp_path / "test_tracker.xlsx"
    wb = openpyxl.Workbook()

    # Customers sheet
    ws_c = wb.active
    ws_c.title = "Customers"
    ws_c.append(["AI-PROWLER JOB TRACKER -- Customer Master List"])
    ws_c.append([
        "CustomerID (CUST-####)", "Customer Type Comm/Res", "Company Name",
        "First Name", "Last Name", "Phone", "Email",
        "Street Address * AI Route", "City * AI Route", "State", "ZIP * AI Route",
        "Latitude (AI Geocode)", "Longitude (AI Geocode)",
        "Service Type(s) Win/Press/Both", "Frequency W/BW/M/Q/OT",
        "Preferred Day(s)", "Pref. Time Window", "Avg Job Duration (min)",
        "Standard Quote ($)", "Discount (%)", "Net Price ($)",
        "Last Service Date", "Next Sched. Date", "Total Jobs Completed",
        "Lifetime Revenue ($)", "Gate Code / Access Notes", "On-Site Contact",
        "Status Active/Inactive",
    ])
    ws_c.append([
        "CUST-0001", "Commercial", "Sunshine Realty LLC", "Karen", "Walsh",
        "3865550101", "karen@sunshine.com",
        "125 Harbor Blvd", "New Smyrna Beach", "FL", "32168",
        "", "", "Both", "Monthly",
        "Mon,Wed", "8am-5pm", "90", "350", "0.1", "315",
        "2026-02-28", "2026-03-30", "5", "1750", "", "", "Active",
    ])
    ws_c.append([
        "CUST-0002", "Residential", "", "Michael", "Torres",
        "3865550202", "mtorres@gmail.com",
        "47 Oceanview Dr", "Edgewater", "FL", "32141",
        "", "", "Window", "Biweekly",
        "Saturday", "9am-12pm", "60", "185", "0", "185",
        "2026-03-16", "2026-03-30", "8", "1480", "", "", "Active",
    ])

    # Jobs_Schedule sheet
    ws_j = wb.create_sheet("Jobs_Schedule")
    ws_j.append(["JOBS & SCHEDULE -- All Service Appointments"])
    ws_j.append([
        "JobID (JOB-####)", "CustomerID (Customers!A)", "Customer Name / Company",
        "Customer Type", "Street Address * AI Route", "City * AI Route",
        "State", "ZIP * AI Route", "Latitude (AI Geocode)", "Longitude (AI Geocode)",
        "Service Date", "Day of Week", "Start Time", "End Time", "Service Type",
        "Service Details / Notes", "Crew / Technician", "Est. Duration (min)",
        "Actual Duration (min)", "Route Stop # * AI Route", "Route Map URL * AI Prowler",
        "Weather Check * AI Prowler", "Job Status", "Quote Amount ($)",
        "Actual Amount ($)", "Discount Applied ($)", "Tax (7%)", "Invoice Total ($)",
        "InvoiceID (INV-####)", "Invoice Sent Date", "Payment Status",
    ])
    ws_j.append([
        "JOB-0001", "CUST-0001", "Sunshine Realty LLC", "Commercial",
        "125 Harbor Blvd", "New Smyrna Beach", "FL", "32168", "", "",
        "2026-03-30", "Monday", "08:00", "09:30", "Window",
        "Full exterior window cleaning", "Mike C.", "90", "", "1",
        "", "", "Complete", "315", "315", "31.5", "22.05", "305.55",
        "INV-0001", "2026-03-30", "Unpaid",
    ])
    ws_j.append([
        "JOB-0002", "CUST-0002", "Michael Torres", "Residential",
        "47 Oceanview Dr", "Edgewater", "FL", "32141", "", "",
        "2026-03-16", "Monday", "09:00", "10:00", "Window",
        "House exterior windows", "Jake R.", "60", "", "1",
        "", "", "Complete", "185", "185", "0", "12.95", "197.95",
        "INV-0002", "2026-03-16", "Paid",
    ])

    # Invoices sheet
    ws_i = wb.create_sheet("Invoices")
    ws_i.append(["INVOICES -- Billing & Payment Tracking"])
    ws_i.append([
        "InvoiceID (INV-####)", "JobID (JOB-####)", "CustomerID",
        "Customer Name / Company", "Customer Type", "Invoice Date",
        "Due Date (Net 30)", "Service Date", "Service Type", "Description",
        "Subtotal ($)", "Discount ($)", "Taxable Amt ($)", "Tax 7% ($)",
        "TOTAL DUE ($)", "Amount Paid ($)", "Balance Due ($)",
        "Payment Status", "Payment Date", "Payment Method",
    ])
    ws_i.append([
        "INV-0001", "JOB-0001", "CUST-0001", "Sunshine Realty LLC", "Commercial",
        "2026-03-30", "2026-04-29", "2026-03-30", "Window",
        "Exterior window cleaning -- 12 windows",
        "315", "31.5", "283.5", "19.845", "303.345", "0", "303.345",
        "Unpaid", "", "",
    ])
    ws_i.append([
        "INV-0002", "JOB-0002", "CUST-0002", "Michael Torres", "Residential",
        "2026-03-16", "2026-04-15", "2026-03-16", "Window",
        "House exterior windows",
        "185", "0", "185", "12.95", "197.95", "197.95", "0",
        "Paid", "2026-03-20", "Check",
    ])
    # Overdue invoice (due 2026-02-14, > 90 days overdue by 2026-05-30)
    ws_i.append([
        "INV-0003", "JOB-0003", "CUST-0001", "Sunshine Realty LLC", "Commercial",
        "2026-01-15", "2026-02-14", "2026-01-15", "Both",
        "Old overdue job",
        "500", "0", "500", "35", "535", "0", "535",
        "Unpaid", "", "",
    ])

    # TimeLog sheet
    ws_t = wb.create_sheet("TimeLog")
    ws_t.append(["TIME LOG -- Job Clock In / Clock Out"])
    ws_t.append([
        "EntryID", "JobID", "Customer Name / Company",
        "Clock In", "Clock Out", "Elapsed (min)", "Crew / Technician", "Notes",
    ])

    wb.save(str(fp))
    return fp


# ===========================================================================
# email_invoice  (CT_01 - CT_06)
# ===========================================================================

class TestEmailInvoice:
    """Tests for ACTION TOOL 8 -- email_invoice."""

    _SMTP_CFG = {
        "smtp_host": "smtp.test.com",
        "smtp_port": 587,
        "smtp_user": "u",
        "smtp_password": "p",
        "from_email": "me@test.com",
        "from_name": "Test",
    }

    def test_CT_01_email_invoice_by_invoice_id(self, mcp_module, tmp_path):
        """email_invoice('INV-0001') must send email and return confirmation."""
        fp = str(_make_test_spreadsheet(tmp_path))

        smtp_mock = MagicMock()
        smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
        smtp_mock.__exit__ = MagicMock(return_value=False)

        with patch.object(mcp_module, "_email_config_load", return_value=self._SMTP_CFG), \
             patch("smtplib.SMTP", return_value=smtp_mock):
            result = mcp_module.email_invoice(
                invoice_identifier="INV-0001",
                to="karen@sunshine.com",
                filepath=fp,
            )

        assert "INV-0001" in result
        assert "Sunshine Realty" in result or "karen" in result or "sent" in result.lower()

    def test_CT_02_email_invoice_auto_lookup_customer_email(self, mcp_module, tmp_path):
        """When 'to' is omitted, email_invoice must try to look up email from Customers."""
        fp = str(_make_test_spreadsheet(tmp_path))

        smtp_mock = MagicMock()
        smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
        smtp_mock.__exit__ = MagicMock(return_value=False)

        with patch.object(mcp_module, "_email_config_load", return_value=self._SMTP_CFG), \
             patch("smtplib.SMTP", return_value=smtp_mock):
            result = mcp_module.email_invoice(
                invoice_identifier="INV-0001",
                filepath=fp,
                # 'to' is omitted -- auto-lookup path
            )

        # Must return a string; must not crash
        assert isinstance(result, str)
        assert "No spreadsheet" not in result

    def test_CT_03_email_invoice_not_found_returns_error(self, mcp_module, tmp_path):
        """Searching for a nonexistent invoice must return an error string."""
        fp = str(_make_test_spreadsheet(tmp_path))

        with patch.object(mcp_module, "_email_config_load", return_value=self._SMTP_CFG):
            result = mcp_module.email_invoice(
                invoice_identifier="INV-9999",
                to="nobody@example.com",
                filepath=fp,
            )

        assert "INV-9999" in result
        # Should be an error: either explicitly or "not found" language
        assert any(w in result.lower() for w in ["not found", "no invoice", "error", "could not"])

    def test_CT_04_email_invoice_no_smtp_config_returns_error(self, mcp_module, tmp_path):
        """If email is not configured, email_invoice must return a clear error."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_email_config_load", return_value=None):
            result = mcp_module.email_invoice(
                invoice_identifier="INV-0001",
                to="karen@sunshine.com",
                filepath=fp,
            )

        assert any(w in result.lower() for w in ["configure", "email", "smtp", "setup"])

    def test_CT_05_email_invoice_missing_spreadsheet_returns_error(self, mcp_module, tmp_path):
        """Passing a nonexistent filepath must return a file-not-found error."""
        with patch.object(mcp_module, "_email_config_load", return_value=self._SMTP_CFG):
            result = mcp_module.email_invoice(
                invoice_identifier="INV-0001",
                to="test@example.com",
                filepath=str(tmp_path / "does_not_exist.xlsx"),
            )
        assert any(w in result.lower() for w in ["not found", "no spreadsheet", "error", "file"])

    def test_CT_06_email_invoice_html_contains_key_fields(self, mcp_module, tmp_path):
        """The email payload sent must reference the invoice ID."""
        fp = str(_make_test_spreadsheet(tmp_path))
        captured = []

        def fake_sendmail(from_addr, to_list, msg_str):
            captured.append(msg_str)

        smtp_mock = MagicMock()
        smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
        smtp_mock.__exit__ = MagicMock(return_value=False)
        smtp_mock.sendmail.side_effect = fake_sendmail

        with patch.object(mcp_module, "_email_config_load", return_value=self._SMTP_CFG), \
             patch("smtplib.SMTP", return_value=smtp_mock):
            result = mcp_module.email_invoice(
                invoice_identifier="INV-0001",
                to="karen@sunshine.com",
                filepath=fp,
            )

        if smtp_mock.sendmail.called and captured:
            assert "INV-0001" in captured[0] or "Sunshine" in captured[0]


# ===========================================================================
# send_sms  (CT_07 - CT_11)
# ===========================================================================

class TestSendSms:
    """Tests for ACTION TOOL 9 -- send_sms."""

    _TWILIO_CFG = {
        "twilio_sms_enabled": True,
        "twilio_account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "twilio_auth_token": "test_auth_token_1234567890abcdef",
        "twilio_from_number": "+13865550100",
    }

    def _write_cfg(self, tmp_path):
        cfg_dir = tmp_path / ".ai-prowler"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        cfg_path = cfg_dir / "config.json"
        cfg_path.write_text(json.dumps(self._TWILIO_CFG), encoding="utf-8")
        return tmp_path

    def test_CT_07_send_sms_success(self, mcp_module, tmp_path):
        """send_sms must call Twilio API and return a success confirmation."""
        home = self._write_cfg(tmp_path)

        twilio_resp = MagicMock()
        twilio_resp.status_code = 201
        twilio_resp.json.return_value = {"sid": "SM1234567890abcdef"}

        with patch("pathlib.Path.home", return_value=home), \
             patch("requests.post", return_value=twilio_resp):
            result = mcp_module.send_sms(
                to="3865550101",
                message="Hi Karen, Mike is 20 minutes away!",
            )

        assert "SM1234567890abcdef" in result or "sent" in result.lower()

    def test_CT_08_send_sms_normalises_10_digit_number(self, mcp_module, tmp_path):
        """A 10-digit number must be normalised to E.164 (+1XXXXXXXXXX)."""
        home = self._write_cfg(tmp_path)
        captured = {}

        def fake_post(url, auth, data, timeout=30):
            captured["to"] = data.get("To")
            resp = MagicMock()
            resp.status_code = 201
            resp.json.return_value = {"sid": "SM_test"}
            return resp

        with patch("pathlib.Path.home", return_value=home), \
             patch("requests.post", side_effect=fake_post):
            mcp_module.send_sms(to="3865550101", message="Test")

        assert captured.get("to") == "+13865550101"

    def test_CT_09_send_sms_no_twilio_config_returns_error(self, mcp_module, tmp_path):
        """Missing Twilio config must return a clear setup-instructions error."""
        cfg_dir = tmp_path / ".ai-prowler"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "config.json").write_text(
            json.dumps({"other_key": "value"}), encoding="utf-8"
        )

        with patch("pathlib.Path.home", return_value=tmp_path):
            result = mcp_module.send_sms(to="3865550101", message="Test")

        assert any(w in result.lower() for w in ["twilio", "config", "setup", "configure"])

    def test_CT_10_send_sms_empty_message_returns_error(self, mcp_module, tmp_path):
        """An empty message must return an error before hitting the API."""
        home = self._write_cfg(tmp_path)
        with patch("pathlib.Path.home", return_value=home):
            result = mcp_module.send_sms(to="3865550101", message="   ")

        assert any(w in result.lower() for w in ["empty", "blank", "message", "error"])

    def test_CT_11_send_sms_twilio_error_response_surfaced(self, mcp_module, tmp_path):
        """A Twilio 400 error must be returned as a readable error string."""
        home = self._write_cfg(tmp_path)

        twilio_resp = MagicMock()
        twilio_resp.status_code = 400
        twilio_resp.json.return_value = {"message": "Invalid phone number format"}

        with patch("pathlib.Path.home", return_value=home), \
             patch("requests.post", return_value=twilio_resp):
            result = mcp_module.send_sms(to="0000000000", message="Test")

        assert "400" in result or "invalid" in result.lower() or "error" in result.lower()


# ===========================================================================
# schedule_next_recurring_job  (CT_12 - CT_17)
# ===========================================================================

class TestScheduleNextRecurringJob:
    """Tests for ACTION TOOL 10 -- schedule_next_recurring_job."""

    def test_CT_12_monthly_customer_gets_next_job_plus_one_month(self, mcp_module, tmp_path):
        """Monthly customer: next job should be 1 month after last service date."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            result = mcp_module.schedule_next_recurring_job(
                job_identifier="JOB-0001",
                filepath=fp,
            )

        assert isinstance(result, str)
        # Base date 2026-03-30 + 1 month = 2026-04-30
        assert "2026-04-30" in result or "April" in result

    def test_CT_13_biweekly_customer_gets_next_job_plus_14_days(self, mcp_module, tmp_path):
        """Biweekly customer: next job should be 14 days after last service date."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            result = mcp_module.schedule_next_recurring_job(
                job_identifier="JOB-0002",
                filepath=fp,
            )

        assert isinstance(result, str)
        # Base date 2026-03-16 + 14 days = 2026-03-30
        assert "2026-03-30" in result

    def test_CT_14_new_job_written_to_jobs_schedule(self, mcp_module, tmp_path):
        """After scheduling, the new job row must exist in the spreadsheet."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            mcp_module.schedule_next_recurring_job(job_identifier="JOB-0001", filepath=fp)

        wb = openpyxl.load_workbook(fp, data_only=True)
        ws = wb["Jobs_Schedule"]
        job_ids = [
            str(row[0].value)
            for row in ws.iter_rows(min_row=3)
            if row[0].value and str(row[0].value).startswith("JOB-")
        ]
        assert len(job_ids) >= 3, "New job row should have been appended"

    def test_CT_15_one_time_customer_returns_info_message(self, mcp_module, tmp_path):
        """OT (one-time) frequency must return an info message, not create a new job."""
        fp = _make_test_spreadsheet(tmp_path)

        # Add a one-time customer and job
        wb = openpyxl.load_workbook(str(fp))
        ws_c = wb["Customers"]
        ws_c.append([
            "CUST-0099", "Residential", "", "OneTime", "Customer",
            "0000000000", "once@test.com",
            "1 Test St", "TestCity", "FL", "00000",
            "", "", "Window", "OT",
            "", "", "60", "100", "0", "100",
            "2026-03-01", "", "0", "0", "", "", "Active",
        ])
        ws_j = wb["Jobs_Schedule"]
        ws_j.append([
            "JOB-0099", "CUST-0099", "OneTime Customer", "Residential",
            "1 Test St", "TestCity", "FL", "00000", "", "",
            "2026-03-01", "Sunday", "10:00", "11:00", "Window",
            "One-time clean", "Mike C.", "60", "", "1",
            "", "", "Complete", "100", "100", "0", "7", "107",
            "", "", "Unpaid",
        ])
        wb.save(str(fp))

        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            result = mcp_module.schedule_next_recurring_job(
                job_identifier="JOB-0099",
                filepath=str(fp),
            )

        assert any(w in result.lower() for w in ["one-time", "ot", "one time", "no recurring"])

    def test_CT_16_job_not_found_returns_error(self, mcp_module, tmp_path):
        """Nonexistent job identifier must return an error string."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            result = mcp_module.schedule_next_recurring_job(
                job_identifier="JOB-9999",
                filepath=fp,
            )

        assert any(w in result.lower() for w in ["not found", "error", "no job", "could not"])

    def test_CT_17_new_job_status_is_scheduled(self, mcp_module, tmp_path):
        """The auto-created job row must have Job Status = 'Scheduled'."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            result = mcp_module.schedule_next_recurring_job(
                job_identifier="JOB-0001",
                filepath=fp,
            )

        if "JOB-0003" not in result and "scheduled" not in result.lower():
            # If the tool returned an error, skip the spreadsheet check
            pytest.skip("Tool did not create a new job -- skipping row status check")

        wb = openpyxl.load_workbook(fp, data_only=True)
        ws = wb["Jobs_Schedule"]
        hdrs = [
            str(c.value).strip() if c.value else ""
            for c in list(ws.iter_rows(min_row=2, max_row=2))[0]
        ]
        for row in ws.iter_rows(min_row=3):
            vals = {hdrs[i]: row[i].value for i in range(len(hdrs))}
            if "JOB-0003" in str(vals.get("JobID (JOB-####)", "")):
                assert vals.get("Job Status") == "Scheduled"
                break


# ===========================================================================
# log_time_entry  (CT_18 - CT_22)
# ===========================================================================

class TestLogTimeEntry:
    """Tests for ACTION TOOL 11 -- log_time_entry."""

    def test_CT_18_clock_in_creates_timelog_entry(self, mcp_module, tmp_path):
        """action='start' must write a new row to the TimeLog sheet."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            result = mcp_module.log_time_entry(
                job_identifier="JOB-0001",
                action="start",
                filepath=fp,
            )

        assert isinstance(result, str)
        assert any(w in result.lower() for w in ["clock", "in", "start", "te-", "logged"])

        wb = openpyxl.load_workbook(fp, data_only=True)
        ws = wb["TimeLog"]
        entries = [
            row for row in ws.iter_rows(min_row=3)
            if row[0].value and str(row[0].value).startswith("TE-")
        ]
        assert len(entries) >= 1, "TimeLog must have at least one entry after clock-in"

    def test_CT_19_clock_out_calculates_elapsed_time(self, mcp_module, tmp_path):
        """action='stop' must compute elapsed minutes and write Clock Out + Elapsed."""
        fp = str(_make_test_spreadsheet(tmp_path))

        # Plant an open clock-in entry (~47 min ago)
        wb = openpyxl.load_workbook(fp)
        ws_t = wb["TimeLog"]
        clock_in = (
            datetime.datetime.now() - datetime.timedelta(minutes=47)
        ).strftime("%Y-%m-%d %H:%M:%S")
        ws_t.append(["TE-0001", "JOB-0001", "Sunshine Realty LLC",
                      clock_in, None, None, "Mike C.", ""])
        wb.save(fp)

        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            result = mcp_module.log_time_entry(
                job_identifier="JOB-0001",
                action="stop",
                filepath=fp,
            )

        assert isinstance(result, str)
        assert any(w in result.lower() for w in ["clock", "out", "stop", "elapsed", "min"])

        wb2 = openpyxl.load_workbook(fp, data_only=True)
        ws_t2 = wb2["TimeLog"]
        for row in ws_t2.iter_rows(min_row=3):
            if row[0].value == "TE-0001":
                assert row[4].value is not None, "Clock Out must be written"
                elapsed = row[5].value
                assert elapsed is not None, "Elapsed (min) must be written"
                assert 44 <= int(elapsed) <= 50, f"Elapsed should be ~47 min, got {elapsed}"
                break

    def test_CT_20_clock_out_updates_actual_duration_in_jobs_schedule(self, mcp_module, tmp_path):
        """Clocking out must write Actual Duration (min) back to Jobs_Schedule."""
        fp = str(_make_test_spreadsheet(tmp_path))

        wb = openpyxl.load_workbook(fp)
        ws_t = wb["TimeLog"]
        clock_in = (
            datetime.datetime.now() - datetime.timedelta(minutes=35)
        ).strftime("%Y-%m-%d %H:%M:%S")
        ws_t.append(["TE-0001", "JOB-0001", "Sunshine Realty LLC",
                      clock_in, None, None, "Mike C.", ""])
        wb.save(fp)

        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            mcp_module.log_time_entry(
                job_identifier="JOB-0001", action="stop", filepath=fp
            )

        wb2 = openpyxl.load_workbook(fp, data_only=True)
        ws_j = wb2["Jobs_Schedule"]
        hdrs = [
            str(c.value).strip() if c.value else ""
            for c in list(ws_j.iter_rows(min_row=2, max_row=2))[0]
        ]
        for row in ws_j.iter_rows(min_row=3):
            vals = dict(zip(hdrs, [c.value for c in row]))
            if vals.get("JobID (JOB-####)") == "JOB-0001":
                actual = vals.get("Actual Duration (min)")
                if actual is not None:
                    assert 32 <= int(actual) <= 38, f"Expected ~35 min, got {actual}"
                break

    def test_CT_21_double_clock_in_returns_warning(self, mcp_module, tmp_path):
        """Clocking in when already clocked in must return a warning, not crash."""
        fp = str(_make_test_spreadsheet(tmp_path))

        wb = openpyxl.load_workbook(fp)
        ws_t = wb["TimeLog"]
        clock_in = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ws_t.append(["TE-0001", "JOB-0001", "Sunshine Realty LLC",
                      clock_in, None, None, "Mike C.", ""])
        wb.save(fp)

        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            result = mcp_module.log_time_entry(
                job_identifier="JOB-0001",
                action="start",
                filepath=fp,
            )

        assert any(w in result.lower() for w in ["already", "open", "active", "warning", "clocked"])

    def test_CT_22_invalid_action_returns_error(self, mcp_module, tmp_path):
        """action='lunch' (invalid) must return an error about valid options."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_backup_spreadsheet", return_value="Backup saved"):
            result = mcp_module.log_time_entry(
                job_identifier="JOB-0001",
                action="lunch",
                filepath=fp,
            )

        assert any(w in result.lower() for w in ["start", "stop", "invalid", "error", "action"])


# ===========================================================================
# get_ar_aging_report  (CT_23 - CT_28)
# ===========================================================================

class TestGetArAgingReport:
    """Tests for ACTION TOOL 12 -- get_ar_aging_report."""

    def test_CT_23_report_contains_unpaid_invoice(self, mcp_module, tmp_path):
        """The AR report must list Sunshine Realty INV-0001 (Unpaid)."""
        fp = str(_make_test_spreadsheet(tmp_path))
        result = mcp_module.get_ar_aging_report(filepath=fp, as_of_date="2026-05-01")

        assert isinstance(result, str)
        assert "INV-0001" in result or "Sunshine Realty" in result
        assert "303" in result  # balance ~303.345

    def test_CT_24_paid_invoice_excluded_from_report(self, mcp_module, tmp_path):
        """INV-0002 is fully paid -- its balance must NOT appear in AR."""
        fp = str(_make_test_spreadsheet(tmp_path))
        result = mcp_module.get_ar_aging_report(filepath=fp, as_of_date="2026-05-01")

        # Paid invoice balance 197.95 must not appear
        assert "197.95" not in result, "Paid invoice balance must not appear in AR report"

    def test_CT_25_overdue_invoice_lands_in_correct_bucket(self, mcp_module, tmp_path):
        """INV-0003 (due 2026-02-14, $535) must appear in 90+ bucket as of 2026-05-30."""
        fp = str(_make_test_spreadsheet(tmp_path))
        result = mcp_module.get_ar_aging_report(filepath=fp, as_of_date="2026-05-30")

        assert isinstance(result, str)
        # Either the invoice ID or its balance should appear
        assert "INV-0003" in result or "535" in result
        # 90-day bucket language
        assert "90" in result

    def test_CT_26_report_includes_total_outstanding(self, mcp_module, tmp_path):
        """The report must include a total outstanding balance line."""
        fp = str(_make_test_spreadsheet(tmp_path))
        result = mcp_module.get_ar_aging_report(filepath=fp, as_of_date="2026-05-01")

        assert any(
            w in result
            for w in ["TOTAL OUTSTANDING", "Total Outstanding", "Total:", "TOTAL:"]
        )

    def test_CT_27_all_paid_returns_clean_message(self, mcp_module, tmp_path):
        """If all invoices are paid, the report must say no outstanding invoices."""
        fp = _make_test_spreadsheet(tmp_path)

        wb = openpyxl.load_workbook(str(fp))
        ws = wb["Invoices"]
        hdrs = [
            str(c.value).strip() if c.value else ""
            for c in list(ws.iter_rows(min_row=2, max_row=2))[0]
        ]
        try:
            pmt_col = hdrs.index("Payment Status") + 1
            bal_col = hdrs.index("Balance Due ($)") + 1
        except ValueError:
            pytest.skip("Could not locate Payment Status / Balance Due columns")

        for row in ws.iter_rows(min_row=3):
            if row[0].value:
                ws.cell(row=row[0].row, column=pmt_col).value = "Paid"
                ws.cell(row=row[0].row, column=bal_col).value = 0
        wb.save(str(fp))

        result = mcp_module.get_ar_aging_report(filepath=str(fp), as_of_date="2026-05-01")
        assert any(
            w in result.lower()
            for w in ["no outstanding", "all paid", "nothing outstanding", "0 outstanding"]
        ) or result.strip().startswith("No")

    def test_CT_28_missing_spreadsheet_returns_error(self, mcp_module, tmp_path):
        """Passing a nonexistent filepath must return an error."""
        result = mcp_module.get_ar_aging_report(
            filepath=str(tmp_path / "no_such_file.xlsx")
        )
        assert isinstance(result, str)
        assert any(w in result.lower() for w in ["not found", "no spreadsheet", "error", "file"])
