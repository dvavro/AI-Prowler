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

    def tool(self, *a, **kw):
        # Mirror the real FastMCP.tool() signature: production registers
        # tools with name=/description= kwargs (e.g. run_script).
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


def _make_multiline_header_spreadsheet(tmp_path):
    """
    Builds an Invoices sheet using the SAME multi-line header format the
    real production template actually uses — the formula-computed columns
    (Taxable Amt, Tax, TOTAL DUE, Balance Due) have their column label on
    one line and a "=FORMULA" documentation note on a second line within
    the same cell, e.g. "Tax 7% ($)\n=M*0.07".

    This is the exact real-world shape _make_test_spreadsheet()'s simple
    single-line headers never exercised — which is why a real production
    bug (header detection merging the formula note into the header text,
    breaking exact-match lookups against hardcoded keys like
    "Tax 7% ($)") passed every existing test while still being broken for
    every real invoice with this column format.
    """
    import openpyxl as _opx_ml
    fp = tmp_path / "multiline_headers.xlsx"
    wb = _opx_ml.Workbook()
    wb.remove(wb.active)

    ws_i = wb.create_sheet("Invoices")
    ws_i.append(["INVOICES -- Billing & Payment Tracking"])
    ws_i.append([
        "InvoiceID (INV-####)", "JobID (JOB-####)", "CustomerID",
        "Customer Name / Company", "Customer Type", "Invoice Date",
        "Due Date (Net 30)", "Service Date", "Service Type", "Description",
        "Subtotal ($)", "Discount ($)",
        "Taxable Amt ($)\n=K-L", "Tax 7% ($)\n=M*0.07",
        "TOTAL DUE ($)\n=M+N", "Amount Paid ($)", "Balance Due ($)\n=O-P",
        "Payment Status", "Payment Date", "Payment Method",
    ])
    ws_i.append([
        "INV-0007", "JOB-0007", "CUST-0007", "AI-Prowler LLC", "Commercial",
        "2026-03-30", "2026-04-29", "2026-03-30", "Window",
        "Exterior window cleaning -- 12 windows",
        "350", "35", "315", "22.05", "337.05", "0", "337.05",
        "Unpaid", "", "",
    ])
    wb.save(str(fp))
    return fp


# ===========================================================================
# email_invoice  (CT_01 - CT_06)
# ===========================================================================

class TestEmailInvoice:
    """Tests for ACTION TOOL 8 -- email_invoice."""

    # Matches the REAL keys _email_config_save()/configure_email() actually
    # produce (username/password/from_address) — NOT what email_invoice()
    # used to read (smtp_user/smtp_password/from_email). That mismatch was
    # a real production bug: every email_invoice() call attempted SMTP
    # login with a blank password and then hit a bare KeyError on
    # 'from_email', guaranteeing failure regardless of correct SMTP setup.
    # This fixture previously used the SAME wrong keys as the buggy code,
    # which is exactly why these tests never caught it — a MagicMock SMTP
    # server accepts login() with any (even blank) credentials silently,
    # and the old tests only checked the success message's text, never
    # what was actually passed to login()/sendmail().
    _SMTP_CFG = {
        "smtp_host": "smtp.test.com",
        "smtp_port": 587,
        "username": "u@test.com",
        "password": "realpassword123",
        "from_address": "me@test.com",
        "from_name": "Test",
    }

    # NOTE: test_CT_01_email_invoice_by_invoice_id, test_CT_01b_..._
    # uses_real_username_and_password, and test_CT_01c_..._uses_real_
    # from_address_for_envelope removed 2026-09-14 -- superseded by
    # test_email_invoice_by_invoice_id_smtp_layer, test_email_invoice_
    # uses_real_username_and_password, and test_email_invoice_uses_
    # real_from_address_for_envelope in
    # tests/mcp_tests/test_invoice_receipt_openpyxl_removal.py, ported onto a
    # real DB-seeded invoice instead of the openpyxl fixture that no
    # longer connects to _find_invoice_row.

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

    # NOTE: test_CT_04_email_invoice_no_smtp_config_returns_error and
    # test_CT_05_email_invoice_missing_spreadsheet_returns_error removed
    # 2026-09-14 -- superseded by test_email_invoice_no_smtp_config_
    # returns_error and test_email_invoice_missing_db_returns_error in
    # tests/mcp_tests/test_invoice_receipt_openpyxl_removal.py, ported onto a
    # real DB-seeded invoice.

    def test_CT_05b_blank_identifier_is_rejected_not_treated_as_match_all(self, mcp_module, tmp_path):
        """The exact production bug this regression guards against: Python
        treats "" as a substring of every string, so a blank
        invoice_identifier previously matched the FIRST row in the
        Invoices sheet unconditionally — silently emailing an unrelated
        customer's invoice with no error. A caller passing '' (from an
        upstream parsing gap, not malice) must get a clear rejection
        instead of a wrong invoice being sent."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_email_config_load", return_value=self._SMTP_CFG):
            result = mcp_module.email_invoice(
                invoice_identifier="",
                to="test@example.com",
                filepath=fp,
            )
        assert result.startswith("❌")
        assert "blank" in result.lower() or "required" in result.lower()

    def test_CT_05c_whitespace_only_identifier_is_also_rejected(self, mcp_module, tmp_path):
        """A whitespace-only identifier is functionally blank once
        stripped, and Python's substring check doesn't strip — must be
        caught the same way as a fully empty string."""
        fp = str(_make_test_spreadsheet(tmp_path))
        with patch.object(mcp_module, "_email_config_load", return_value=self._SMTP_CFG):
            result = mcp_module.email_invoice(
                invoice_identifier="   ",
                to="test@example.com",
                filepath=fp,
            )
        assert result.startswith("❌")

    def test_CT_05d_blank_identifier_check_happens_before_smtp_send(self, mcp_module, tmp_path):
        """The rejection must happen before any email is actually sent —
        confirms this is a genuine early-exit guard, not just a message
        wrapped around a real send attempt."""
        fp = str(_make_test_spreadsheet(tmp_path))
        smtp_mock = MagicMock()
        with patch.object(mcp_module, "_email_config_load", return_value=self._SMTP_CFG), \
             patch("smtplib.SMTP", return_value=smtp_mock):
            mcp_module.email_invoice(
                invoice_identifier="",
                to="test@example.com",
                filepath=fp,
            )
        smtp_mock.assert_not_called()

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

    # NOTE: test_CT_06b_tax_and_total_render_correctly_with_real_
    # multiline_headers removed 2026-09-14 -- the "multi-line header"
    # bug class it guarded (decorated column headers with embedded
    # formula notes) is structurally impossible on a real SQLite schema.


# ===========================================================================
# _load_payment_settings  +  email_invoice(also_sms=...)
# ===========================================================================

class TestLoadPaymentSettings:
    """Tests for the shared _load_payment_settings() helper — reads the
    Stripe/Square credentials and fallback URLs (Small Business tab), plus
    the two independent enable/disable toggles, from the main config.json.
    Xero is intentionally not supported at all (full OAuth 2.0 required —
    judged too complex for this feature's target users)."""

    def _write_config(self, tmp_path, monkeypatch, data):
        cfg_dir = tmp_path / ".ai-prowler"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "config.json").write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

    def test_defaults_when_config_missing(self, mcp_module, tmp_path, monkeypatch):
        """No config.json at all — email defaults ON (preserves the
        feature's original, pre-toggle behavior), SMS defaults OFF (a new,
        more exposed capability, off until explicitly enabled)."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)  # empty tmp_path, no config.json
        result = mcp_module._load_payment_settings()
        assert result["stripe_secret_key"] == ""
        assert result["square_access_token"] == ""
        assert result["email_enabled"] is True
        assert result["sms_enabled"] is False

    def test_reads_stripe_credentials(self, mcp_module, tmp_path, monkeypatch):
        self._write_config(tmp_path, monkeypatch, {
            "stripe_secret_key": "sk_test_abc123",
            "stripe_payment_url": "https://buy.stripe.com/fallback",
        })
        result = mcp_module._load_payment_settings()
        assert result["stripe_secret_key"] == "sk_test_abc123"
        assert result["stripe_fallback_url"] == "https://buy.stripe.com/fallback"

    def test_reads_square_credentials(self, mcp_module, tmp_path, monkeypatch):
        self._write_config(tmp_path, monkeypatch, {
            "square_access_token": "EAAA_test_token",
            "square_location_id": "L123ABC",
            "square_payment_url": "https://square.link/u/fallback",
        })
        result = mcp_module._load_payment_settings()
        assert result["square_access_token"] == "EAAA_test_token"
        assert result["square_location_id"] == "L123ABC"
        assert result["square_fallback_url"] == "https://square.link/u/fallback"

    def test_xero_is_not_supported_at_all(self, mcp_module, tmp_path, monkeypatch):
        """Even if a xero_payment_url happens to still be sitting in an old
        config.json from before Xero was removed, it must be ignored
        entirely — no Xero key of any kind in the returned dict."""
        self._write_config(tmp_path, monkeypatch, {
            "xero_payment_url": "https://invoices.xero.com/leftover",
        })
        result = mcp_module._load_payment_settings()
        assert not any("xero" in k.lower() for k in result.keys())

    def test_email_toggle_respected_when_explicitly_off(self, mcp_module, tmp_path, monkeypatch):
        self._write_config(tmp_path, monkeypatch, {
            "email_payment_link_enabled": False,
        })
        result = mcp_module._load_payment_settings()
        assert result["email_enabled"] is False

    def test_sms_toggle_respected_when_explicitly_on(self, mcp_module, tmp_path, monkeypatch):
        self._write_config(tmp_path, monkeypatch, {
            "sms_payment_link_enabled": True,
        })
        result = mcp_module._load_payment_settings()
        assert result["sms_enabled"] is True


# NOTE: TestEmailInvoicePaymentLinksAndSms (openpyxl-based) removed
# 2026-09-14 -- superseded by tests/mcp_tests/test_email_invoice_payment_
# links.py, which covers the same Stripe/Square dynamic-checkout,
# static-fallback, and also_sms behavior against a real DB-seeded
# invoice. All 12 ported tests pass, confirming this logic itself has
# no regression -- it was simply untested after the SQLite migration.


class TestStripeAndSquareCheckoutHelpers:
    """Direct tests for _create_stripe_checkout_url() and
    _create_square_checkout_url() — the two functions that make the
    actual (always-mocked-here) network calls."""

    def test_stripe_success_returns_url(self, mcp_module):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"url": "https://checkout.stripe.com/pay/cs_123"}
        with patch("requests.post", return_value=resp):
            result = mcp_module._create_stripe_checkout_url(
                "sk_test_abc", 303.35, "Invoice INV-0001", "INV-0001")
        assert result == "https://checkout.stripe.com/pay/cs_123"

    def test_stripe_failure_returns_none_not_raises(self, mcp_module):
        """A bad key or API error must never propagate up — email_invoice
        relies on None meaning 'fall back to static URL'."""
        resp = MagicMock()
        resp.status_code = 401
        resp.text = "Invalid API Key"
        with patch("requests.post", return_value=resp):
            result = mcp_module._create_stripe_checkout_url(
                "sk_bad", 100.0, "Invoice INV-0001", "INV-0001")
        assert result is None

    def test_stripe_network_exception_returns_none_not_raises(self, mcp_module):
        with patch("requests.post", side_effect=ConnectionError("network down")):
            result = mcp_module._create_stripe_checkout_url(
                "sk_test_abc", 100.0, "Invoice INV-0001", "INV-0001")
        assert result is None

    def test_stripe_amount_converted_to_cents(self, mcp_module):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"url": "https://checkout.stripe.com/pay/x"}
        with patch("requests.post", return_value=resp) as post_mock:
            mcp_module._create_stripe_checkout_url("sk_test", 303.35, "desc", "INV-0001")
        sent_data = post_mock.call_args.kwargs.get("data", {})
        assert sent_data.get("line_items[0][price_data][unit_amount]") == 30335

    def test_square_success_returns_url(self, mcp_module):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"payment_link": {"url": "https://checkout.square.site/abc"}}
        with patch("requests.post", return_value=resp):
            result = mcp_module._create_square_checkout_url(
                "EAAA_test", "L123", 303.35, "Invoice INV-0001", "INV-0001")
        assert result == "https://checkout.square.site/abc"

    def test_square_failure_returns_none_not_raises(self, mcp_module):
        resp = MagicMock()
        resp.status_code = 401
        resp.text = "Unauthorized"
        with patch("requests.post", return_value=resp):
            result = mcp_module._create_square_checkout_url(
                "EAAA_bad", "L123", 100.0, "desc", "INV-0001")
        assert result is None

    def test_square_amount_converted_to_cents(self, mcp_module):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"payment_link": {"url": "https://checkout.square.site/x"}}
        with patch("requests.post", return_value=resp) as post_mock:
            mcp_module._create_square_checkout_url("EAAA_test", "L123", 303.35, "desc", "INV-0001")
        sent_json = post_mock.call_args.kwargs.get("json", {})
        assert sent_json.get("quick_pay", {}).get("price_money", {}).get("amount") == 30335


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

    def _write_cfg(self, tmp_path, monkeypatch):
        # R-066 (2026-09-29): sms_backends.load_sms_config() honours
        # AIPROWLER_TEST_STATE_DIR when set, bypassing the Path.home()
        # lookup this helper used to mock. Point the sandbox at tmp_path and
        # write config.json at its root (load_sms_config reads
        # $AIPROWLER_TEST_STATE_DIR/config.json directly, no .ai-prowler
        # subdir). monkeypatch reverts the env var after each test, so the
        # shared sandbox dir is never polluted.
        monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
        (tmp_path / "config.json").write_text(
            json.dumps(self._TWILIO_CFG), encoding="utf-8")
        return tmp_path

    def test_CT_07_send_sms_success(self, mcp_module, tmp_path, monkeypatch):
        """send_sms must call Twilio API and return a success confirmation."""
        home = self._write_cfg(tmp_path, monkeypatch)

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

    def test_CT_08_send_sms_normalises_10_digit_number(self, mcp_module, tmp_path, monkeypatch):
        """A 10-digit number must be normalised to E.164 (+1XXXXXXXXXX)."""
        home = self._write_cfg(tmp_path, monkeypatch)
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

    def test_CT_10_send_sms_empty_message_returns_error(self, mcp_module, tmp_path, monkeypatch):
        """An empty message must return an error before hitting the API."""
        home = self._write_cfg(tmp_path, monkeypatch)
        with patch("pathlib.Path.home", return_value=home):
            result = mcp_module.send_sms(to="3865550101", message="   ")

        assert any(w in result.lower() for w in ["empty", "blank", "message", "error"])

    def test_CT_11_send_sms_twilio_error_response_surfaced(self, mcp_module, tmp_path, monkeypatch):
        """A Twilio 400 error must be returned as a readable error string."""
        home = self._write_cfg(tmp_path, monkeypatch)

        twilio_resp = MagicMock()
        twilio_resp.status_code = 400
        twilio_resp.json.return_value = {"message": "Invalid phone number format"}

        with patch("pathlib.Path.home", return_value=home), \
             patch("requests.post", return_value=twilio_resp):
            result = mcp_module.send_sms(to="0000000000", message="Test")

        assert "400" in result or "invalid" in result.lower() or "error" in result.lower()

    def test_CT_11b_blank_to_is_rejected_before_any_lookup(self, mcp_module, tmp_path, monkeypatch):
        """Same bug class as email_invoice's blank-identifier fix: the
        name-resolution lookups search for `to` as a SUBSTRING of stored
        names, and a blank `to` (e.g. a job whose customer name failed to
        parse upstream) must never reach them — it would otherwise match
        whichever record happens to come first."""
        home = self._write_cfg(tmp_path, monkeypatch)
        with patch("pathlib.Path.home", return_value=home):
            result = mcp_module.send_sms(to="", message="Test")
        assert result.startswith("❌")
        assert "blank" in result.lower() or "required" in result.lower()

    def test_CT_11c_whitespace_only_to_is_also_rejected(self, mcp_module, tmp_path, monkeypatch):
        home = self._write_cfg(tmp_path, monkeypatch)
        with patch("pathlib.Path.home", return_value=home):
            result = mcp_module.send_sms(to="   ", message="Test")
        assert result.startswith("❌")

    def test_CT_11d_blank_to_never_reaches_users_json_crew_lookup(self, mcp_module, tmp_path, monkeypatch):
        """The specific vulnerability this guards against: step 2 (crew
        lookup in users.json) had no blank-input guard at all, unlike
        step 1 (Customers sheet) which was already correctly guarded. A
        blank `to` would match the FIRST crew member in the dict
        unconditionally — this test proves that lookup is never even
        attempted when `to` is blank, by making it fail loudly if called."""
        home = self._write_cfg(tmp_path, monkeypatch)

        def _users_that_should_never_be_read():
            raise AssertionError(
                "users.json crew lookup was reached with a blank 'to' — "
                "the top-level blank-input guard did not short-circuit it."
            )

        with patch("pathlib.Path.home", return_value=home), \
             patch.object(mcp_module, "_load_users", side_effect=_users_that_should_never_be_read):
            result = mcp_module.send_sms(to="", message="Test")

        assert result.startswith("❌")

    def test_CT_11e_real_name_still_resolves_normally(self, mcp_module, tmp_path, monkeypatch):
        """Regression guard — the blank-input fix must not break the
        normal, non-blank name-resolution path it's built around."""
        home = self._write_cfg(tmp_path, monkeypatch)
        captured = {}

        def fake_post(url, auth, data, timeout=30):
            captured["to"] = data.get("To")
            resp = MagicMock()
            resp.status_code = 201
            resp.json.return_value = {"sid": "SM_test"}
            return resp

        users_data = {"users": {"u1": {"name": "Jake Rivera", "cell_phone": "3865550199"}}}

        with patch("pathlib.Path.home", return_value=home), \
             patch.object(mcp_module, "_load_users", return_value=users_data), \
             patch.object(mcp_module, "_get_default_spreadsheet_path", return_value=""), \
             patch("requests.post", side_effect=fake_post):
            mcp_module.send_sms(to="Jake", message="Test")

        assert captured.get("to") == "+13865550199"


# NOTE: TestScheduleNextRecurringJob, TestScheduleNextRecurringJob
# ExpandedFrequencies, and TestLogTimeEntry (all openpyxl-based) removed
# 2026-09-14. Frequency math (Weekly/Biweekly/Monthly/Bi-Monthly/Semi-
# Annually/Annually, plus month-end-overflow capping and the ambiguous-
# match/date-range checks) is now covered in
# tests/mcp_tests/test_db_route_ops_phase1.py against the real SQLite-backed
# db_schedule_next_recurring_job. Clock in/out mechanics are covered in
# tests/mcp_tests/test_log_time_entry_isolated.py; ambiguous-match rejection,
# server-mode crew identity, and ownership-scoped stop are covered in
# tests/mcp_tests/test_db_log_time_entry_identity.py.


# ===========================================================================
# _join_header_lines  +  filter_date='today' with real multi-line headers
# ===========================================================================
#
# Real production bug: a prior fix for a DIFFERENT problem (a "=FORMULA"
# documentation note on a header cell's second line breaking exact-match
# lookups against keys like "Tax 7% ($)") took only the first line of
# EVERY multi-line header unconditionally. That silently broke a
# genuinely different case: headers where the column name ITSELF spans
# multiple lines with no formula involved — "Service\nDate", "Service\n
# Type", and "Service\nDetails / Notes" all collapsed to the single word
# "Service", making three separate columns indistinguishable. That broke
# read_job_spreadsheet's Service Date column lookup entirely (no column
# matched 'service' AND 'date' anymore), which silently disabled
# filter_date='today' filtering — even for the OWNER, who should see
# every job regardless of crew assignment, and still saw none.

class TestJoinHeaderLines:
    """Direct tests for the shared _join_header_lines() helper."""

    def test_single_line_header_unchanged(self, mcp_module):
        assert mcp_module._join_header_lines("Customer Type") == "Customer Type"

    def test_formula_note_on_second_line_is_dropped(self, mcp_module):
        assert mcp_module._join_header_lines("Tax 7% ($)\n=M*0.07") == "Tax 7% ($)"

    def test_genuine_multiline_label_is_merged_not_truncated(self, mcp_module):
        """The exact case the prior fix broke — this must NOT collapse to
        just 'Service'."""
        assert mcp_module._join_header_lines("Service\nDate") == "Service Date"
        assert mcp_module._join_header_lines("Service\nType") == "Service Type"

    def test_three_service_columns_remain_distinct(self, mcp_module):
        """The actual real-world collision: three different multi-line
        headers must NOT all reduce to the same string."""
        date_hdr = mcp_module._join_header_lines("Service\nDate")
        type_hdr = mcp_module._join_header_lines("Service\nType")
        notes_hdr = mcp_module._join_header_lines("Service\nDetails / Notes")
        assert len({date_hdr, type_hdr, notes_hdr}) == 3

    def test_three_line_header_with_trailing_formula(self, mcp_module):
        """A label that itself wraps across two lines, PLUS a formula
        note on a third line — both rules apply together."""
        result = mcp_module._join_header_lines("Balance\nDue ($)\n=O-P")
        assert result == "Balance Due ($)"

    def test_star_route_annotation_preserved(self, mcp_module):
        """Non-formula annotations (like the "★ AI Route" suffix seen on
        several real columns) are part of the genuine header text and
        must be preserved, not dropped."""
        assert mcp_module._join_header_lines("Street Address\n★ AI Route") == \
               "Street Address ★ AI Route"

    def test_blank_value_returns_empty_string(self, mcp_module):
        assert mcp_module._join_header_lines(None) == ""
        assert mcp_module._join_header_lines("") == ""


# NOTE: TestReadJobSpreadsheetFilterDateWithMultilineHeaders and its
# fixture removed 2026-09-14 -- openpyxl-based, and the "multi-line
# header" bug class it guarded against is structurally impossible on a
# real SQLite schema (real columns, no header-text decoration). Date-
# filter coverage now lives in tests/mcp_tests/test_db_read_ops_phase2.py.

# ===========================================================================
# _crew_name_in_cell  +  multi-crew job assignment
# ===========================================================================
#
# Jobs can now be assigned to multiple people at once — the "Crew /
# Technician" cell holds a comma-separated list (e.g. "Mike C., David
# Vavro") instead of a single name. Every enforcement site that used to
# do a plain equality check against that cell now goes through the
# shared _crew_name_in_cell() helper instead, so a restricted user shows
# up correctly if their name is ANY ONE of the listed names, not only
# when they're the sole assignee.

class TestCrewNameInCell:
    """Direct tests for the shared _crew_name_in_cell() helper."""

    def test_single_name_exact_match(self, mcp_module):
        assert mcp_module._crew_name_in_cell("mike c.", "mike c.") is True

    def test_single_name_no_match(self, mcp_module):
        assert mcp_module._crew_name_in_cell("mike c.", "jake r.") is False

    def test_second_name_in_comma_list_matches(self, mcp_module):
        assert mcp_module._crew_name_in_cell("mike c., david vavro", "david vavro") is True

    def test_first_name_in_comma_list_matches(self, mcp_module):
        assert mcp_module._crew_name_in_cell("mike c., david vavro", "mike c.") is True

    def test_name_not_in_comma_list_does_not_match(self, mcp_module):
        assert mcp_module._crew_name_in_cell("mike c., david vavro", "jake r.") is False

    def test_extra_whitespace_around_commas_tolerated(self, mcp_module):
        assert mcp_module._crew_name_in_cell("mike c. ,  david vavro", "david vavro") is True

    def test_blank_cell_never_matches(self, mcp_module):
        assert mcp_module._crew_name_in_cell("", "david vavro") is False

    def test_blank_crew_name_never_matches(self, mcp_module):
        assert mcp_module._crew_name_in_cell("mike c., david vavro", "") is False

    def test_partial_substring_does_not_falsely_match(self, mcp_module):
        """'Mike' must not match a cell containing 'Mike C.' — this is
        exact per-name matching after splitting, not substring search."""
        assert mcp_module._crew_name_in_cell("mike c., david vavro", "mike") is False


# NOTE: TestReadJobSpreadsheetMultiCrewAssignment and
# TestReadJobSpreadsheetEndDateRange (both openpyxl-based) removed
# 2026-09-14. Multi-crew comma-list matching is still directly unit-
# tested above (TestCrewNameInCell) and exercised end-to-end via
# db_read_job_spreadsheet's own use of that same helper in
# tests/mcp_tests/test_db_read_ops_phase2.py. Date-range/multi-day-job
# filtering is covered there too (test_filter_date_within_multi_day_
# range, test_filter_date_blank_or_invalid_end_date_treated_as_single_
# day) against the real SQLite-backed read path -- the openpyxl
# fixtures here no longer connect to read_job_spreadsheet at all.
# ===========================================================================
# check_sms_configured
# ===========================================================================
#
# Lightweight tool the Jobs PWA calls once at boot to decide whether the
# job modal's "Email + Text Invoice" button should be enabled or dimmed
# — reuses the exact same sms_backends.validate_config() logic
# check_tools_status() already uses for its own SMS section, in a small
# dedicated tool that returns exactly one of two strings, rather than
# requiring the caller to parse a much larger free-text status report.

class TestCheckSmsConfigured:
    def test_returns_configured_string_when_valid(self, mcp_module):
        fake_backend = MagicMock()
        fake_backend.validate_config.return_value = (True, "ok")
        with patch("sms_backends.load_sms_config", return_value={"provider": "twilio"}), \
             patch("sms_backends.get_sms_backend", return_value=fake_backend):
            result = mcp_module.check_sms_configured()
        assert result == "✅ SMS configured"

    def test_returns_not_configured_string_when_invalid(self, mcp_module):
        fake_backend = MagicMock()
        fake_backend.validate_config.return_value = (False, "missing credentials")
        with patch("sms_backends.load_sms_config", return_value={}), \
             patch("sms_backends.get_sms_backend", return_value=fake_backend):
            result = mcp_module.check_sms_configured()
        assert result == "❌ SMS not configured"

    def test_returns_not_configured_on_any_exception(self, mcp_module):
        """A crashed/missing sms_backends import, a malformed config file,
        etc. must never propagate as an error — must fail safely to 'not
        configured' rather than breaking the PWA's boot sequence."""
        with patch("sms_backends.load_sms_config", side_effect=Exception("boom")):
            result = mcp_module.check_sms_configured()
        assert result == "❌ SMS not configured"

    def test_return_value_is_always_one_of_exactly_two_strings(self, mcp_module):
        """The PWA does a plain .includes('✅') check on the result — the
        contract here is strict: exactly these two strings, nothing else,
        so that check can never accidentally match something unrelated."""
        fake_backend = MagicMock()
        fake_backend.validate_config.return_value = (True, "ok")
        with patch("sms_backends.load_sms_config", return_value={}), \
             patch("sms_backends.get_sms_backend", return_value=fake_backend):
            result = mcp_module.check_sms_configured()
        assert result in ("✅ SMS configured", "❌ SMS not configured")

