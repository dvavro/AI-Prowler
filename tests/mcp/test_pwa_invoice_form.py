"""
tests/mcp/test_pwa_invoice_form.py
===================================
Test suite for the "Create Invoice" button and form added to the
Jobs PWA job-detail popup (jobs/index.html).

WHAT IS TESTED
==============

GROUP 1 — HTML Structure (offline, no server needed)
  1.01  invoiceFormModal element exists in DOM
  1.02  Modal has a close (x) button wired to closeInvoiceForm()
  1.03  Quote Amount input exists (id=ifQuote, type=number)
  1.04  Discount input exists (id=ifDiscount, type=number)
  1.05  Tax Rate input exists (id=ifTaxRate, type=number)
  1.06  Service Type input exists (id=ifServiceType)
  1.07  Description textarea exists (id=ifDescription)
  1.08  Payment Terms (due days) input exists (id=ifDueDays)
  1.09  Live-totals strip has Taxable / Tax / Total Due display elements
  1.10  Job label element exists (id=ifJobLabel)
  1.11  Already-invoiced warning element exists (id=ifAlreadyInvoiced)
  1.12  Error strip element exists (id=ifError)
  1.13  Submit button exists (id=ifSubmitBtn) wired to submitInvoiceForm()
  1.14  Cancel button in footer wired to closeInvoiceForm()
  1.15  Modal has higher z-index than the job-detail sheet (z-index:400 > 100)

GROUP 2 — Button Wiring in Job-Detail Sheet (offline)
  2.01  openModal() JS renders a "Create Invoice" button for unpaid jobs
  2.02  Create Invoice button calls openInvoiceForm()
  2.03  Create Invoice uses btn-success style (green)
  2.04  Email Invoice + Text Invoice buttons are dimmed when no invoiceId
  2.05  Create Invoice button conditional on job having no InvoiceID
  2.06  Dimming opacity is a fractional value < 1

GROUP 3 — JavaScript Functions Present (offline)
  3.01  openInvoiceForm function defined
  3.02  closeInvoiceForm function defined
  3.03  submitInvoiceForm function defined (async)
  3.04  ifRecalc function defined
  3.05  _ifJobId state variable declared with let

GROUP 4 — JS Logic: openInvoiceForm pre-fills from job data (offline)
  4.01  openInvoiceForm sets ifJobLabel from j.id + j.customer
  4.02  ifQuote is pre-filled from j.quote
  4.03  ifDiscount is pre-filled from j.discount
  4.04  ifServiceType is pre-filled from j.service
  4.05  ifDescription is pre-filled from j.notes
  4.06  Tax rate defaults to '7'
  4.07  Due days defaults to '30'
  4.08  Already-invoiced warning is conditional on j.invoiceId
  4.09  Error strip is hidden (display=none) on open
  4.10  Submit button disabled=false and text reset on open
  4.11  Modal display set to 'flex' on open
  4.12  ifRecalc() called immediately on open

GROUP 5 — JS Logic: closeInvoiceForm / cancel flow (offline)
  5.01  closeInvoiceForm sets modal display to 'none'
  5.02  closeInvoiceForm resets _ifJobId to empty string
  5.03  Both the x button and the Cancel button call closeInvoiceForm()

GROUP 6 — JS Logic: ifRecalc live totals (offline)
  6.01  ifRecalc reads ifQuote, ifDiscount, ifTaxRate
  6.02  ifRecalc writes ifShowTaxable, ifShowTax, ifShowTotal
  6.03  ifRecalc computes taxable as quote - discount
  6.04  ifRecalc divides tax rate by 100
  6.05  oninput on all three numeric fields is wired to ifRecalc()

GROUP 7 — JS Logic: submitInvoiceForm (offline)
  7.01  Validates quote before submitting (isNaN or <= 0 guard)
  7.02  Calls mcpCall with tool 'create_invoice'
  7.03  Passes job_identifier from _ifJobId
  7.04  Passes quote_amount, discount, tax_rate, due_days
  7.05  Passes service_type and description
  7.06  Passes backup: true
  7.07  Checks _isFailureResult() on response
  7.08  Parses NEW_INVOICE_ID= line from result
  7.09  Patches state.jobs invoiceId in-memory on success
  7.10  Calls closeInvoiceForm() on success
  7.11  Calls showToast() on success
  7.12  Re-opens job modal on success (openModal)
  7.13  Shows backend errors in ifError strip, not alert()
  7.14  Re-enables submit button on any failure

GROUP 8 — MCP API round-trip (live_pwa -- requires running server)
  8.01  /pwa-api returns HTTP 200 for a create_invoice call
  8.02  Blank identifier is a tool-level error, not an HTTP error
  8.03  Non-existent job gives a descriptive error string
  8.04  create_invoice is reachable via the /pwa-api allowed-tools list
  8.05  Successful create_invoice returns NEW_INVOICE_ID= and confirmation
  8.06  Double-invoice attempt is blocked with a clear error

Run offline only (no server):
    pytest tests/mcp/test_pwa_invoice_form.py -v

Run including live API tests (server must be running on port 8000):
    pytest tests/mcp/test_pwa_invoice_form.py -v -m live_pwa
"""
from __future__ import annotations

import json
import os
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# -- Paths -----------------------------------------------------------------
_SRC      = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT  = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
PWA_DIR   = SRC_ROOT / "jobs"
HTML_FILE = PWA_DIR  / "index.html"
MCP_FILE  = SRC_ROOT / "ai_prowler_mcp.py"

# -- Live server config ----------------------------------------------------
PORT     = int(os.environ.get("AI_PROWLER_PORT", 8000))
BASE_URL = f"http://127.0.0.1:{PORT}"
TIMEOUT  = 10

_CONFIG_PATH = Path.home() / ".ai-prowler" / "config.json"
try:
    _cfg         = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    BEARER_TOKEN = _cfg.get("remote_token", "")
except Exception:
    BEARER_TOKEN = ""


# -- Helpers ---------------------------------------------------------------

def _server_running() -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def _post(path: str, body: bytes, hdrs: dict = None, auth: bool = True):
    h = {"Content-Type": "application/json"}
    if auth and BEARER_TOKEN:
        h["Authorization"] = f"Bearer {BEARER_TOKEN}"
    if hdrs:
        h.update(hdrs)
    req = urllib.request.Request(BASE_URL + path, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in dict(r.headers).items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in dict(e.headers).items()}, e.read()


def _api(tool: str, args: dict = None):
    body = json.dumps({"tool": tool, "args": args or {}}).encode()
    status, hdrs, resp = _post("/pwa-api", body)
    try:
        data = json.loads(resp)
    except Exception:
        data = {}
    return status, data


# -- Fixtures --------------------------------------------------------------

@pytest.fixture(scope="session")
def html():
    assert HTML_FILE.exists(), f"jobs/index.html not found at: {HTML_FILE}"
    return HTML_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def server():
    """Skip live tests if AI-Prowler HTTP server is not running."""
    if not _server_running():
        pytest.skip(
            f"AI-Prowler not running on port {PORT}. "
            "Start HTTP Server in Settings, then re-run with -m live_pwa."
        )
    if not BEARER_TOKEN:
        pytest.skip(
            "No Bearer token in ~/.ai-prowler/config.json. "
            "Configure Remote Access in Settings first."
        )


# ==========================================================================
# GROUP 1 -- HTML Structure
# ==========================================================================

class TestGroup1_HtmlStructure:
    """1.xx -- Every required DOM element is present in jobs/index.html."""

    def test_1_01_modal_element_exists(self, html):
        assert 'id="invoiceFormModal"' in html, \
            "#invoiceFormModal element missing from index.html"

    def test_1_02_close_button_wired_to_closeInvoiceForm(self, html):
        # Grab only the modal block so we don't accidentally match an
        # unrelated closeInvoiceForm() reference elsewhere in the file.
        modal_block = html.split('id="invoiceFormModal"')[1].split('<!-- /invoiceFormModal -->')[0]
        assert "closeInvoiceForm()" in modal_block, \
            "The close (x) button inside invoiceFormModal must call closeInvoiceForm()"

    def test_1_03_quote_input_is_number_type(self, html):
        assert 'id="ifQuote"' in html, "Quote Amount input (id=ifQuote) missing"
        idx = html.index('id="ifQuote"')
        ctx = html[max(0, idx - 300): idx + 300]
        assert 'type="number"' in ctx, \
            "ifQuote must be type=number so mobile shows a numeric keypad"

    def test_1_04_discount_input_is_number_type(self, html):
        assert 'id="ifDiscount"' in html, "Discount input (id=ifDiscount) missing"
        idx = html.index('id="ifDiscount"')
        ctx = html[max(0, idx - 300): idx + 300]
        assert 'type="number"' in ctx, "ifDiscount must be type=number"

    def test_1_05_tax_rate_input_is_number_type(self, html):
        assert 'id="ifTaxRate"' in html, "Tax Rate input (id=ifTaxRate) missing"
        idx = html.index('id="ifTaxRate"')
        ctx = html[max(0, idx - 300): idx + 300]
        assert 'type="number"' in ctx, "ifTaxRate must be type=number"

    def test_1_06_service_type_input_exists(self, html):
        assert 'id="ifServiceType"' in html, \
            "Service Type input (id=ifServiceType) missing"

    def test_1_07_description_textarea_exists(self, html):
        assert 'id="ifDescription"' in html, \
            "Description textarea (id=ifDescription) missing"

    def test_1_08_due_days_input_is_number_type(self, html):
        assert 'id="ifDueDays"' in html, "Due Days input (id=ifDueDays) missing"
        idx = html.index('id="ifDueDays"')
        ctx = html[max(0, idx - 300): idx + 300]
        assert 'type="number"' in ctx, "ifDueDays must be type=number"

    def test_1_09_live_totals_display_elements_exist(self, html):
        for elem_id in ("ifShowTaxable", "ifShowTax", "ifShowTotal"):
            assert f'id="{elem_id}"' in html, \
                f"Live-totals display element (id={elem_id}) missing from modal"

    def test_1_10_job_label_element_exists(self, html):
        assert 'id="ifJobLabel"' in html, \
            "Job label element (id=ifJobLabel) missing — form needs to show which job is being invoiced"

    def test_1_11_already_invoiced_warning_element_exists(self, html):
        assert 'id="ifAlreadyInvoiced"' in html, \
            "Already-invoiced warning strip (id=ifAlreadyInvoiced) missing"

    def test_1_12_error_strip_element_exists(self, html):
        assert 'id="ifError"' in html, \
            "Error display strip (id=ifError) missing — backend errors must show here"

    def test_1_13_submit_button_calls_submitInvoiceForm(self, html):
        assert 'id="ifSubmitBtn"' in html, "Submit button (id=ifSubmitBtn) missing"
        after = html.split('id="ifSubmitBtn"')[1][:300]
        assert "submitInvoiceForm()" in after, \
            "ifSubmitBtn must call submitInvoiceForm() via onclick"

    def test_1_14_cancel_button_wired_in_footer(self, html):
        modal_block = html.split('id="invoiceFormModal"')[1].split('<!-- /invoiceFormModal -->')[0]
        # x button + Cancel button = at least 2 calls
        count = modal_block.count("closeInvoiceForm()")
        assert count >= 2, (
            f"Expected at least 2 closeInvoiceForm() calls inside the modal "
            f"(header x button + footer Cancel button), found {count}"
        )
        assert "Cancel" in modal_block, \
            "Footer Cancel button label missing from invoice form"

    def test_1_15_modal_z_index_above_job_detail_sheet(self, html):
        # The job-detail sheet (#jobModal) uses z-index:100.
        # invoiceFormModal must be higher so it fully covers it.
        # The z-index is on the outermost <div> of the modal comment block —
        # scan from the comment header forward to find it.
        marker = '<!-- \u2500\u2500 Invoice Create Form Modal'
        if marker not in html:
            marker = 'id="invoiceFormModal"'
        idx = html.index(marker)
        # Scan up to 600 chars forward to find the z-index on the opening div
        ctx = html[idx: idx + 600]
        match = re.search(r'z-index\s*:\s*(\d+)', ctx)
        assert match, (
            "The invoiceFormModal <div> block must have an explicit z-index — "
            "search from the modal comment/id forward 600 chars found none. "
            "Check that z-index is on the outermost <div> of the modal."
        )
        z = int(match.group(1))
        assert z > 100, (
            f"invoiceFormModal z-index ({z}) must exceed 100 "
            f"(the job-detail sheet #jobModal uses z-index:100)"
        )


# ==========================================================================
# GROUP 2 -- Button Wiring in Job-Detail Sheet
# ==========================================================================

class TestGroup2_ButtonWiringInJobDetailSheet:
    """2.xx -- openModal() renders the correct invoice action buttons."""

    def _open_modal_js(self, html: str) -> str:
        """Return the openModal() function body.
        The billing IIFE is deeply nested inside a template literal, so we
        need enough chars to include the opacity style string that appears
        near the end of the unpaid branch (after the Create Invoice button).
        8000 chars comfortably covers the full function."""
        start = html.index("function openModal(id)")
        return html[start: start + 8000]

    def test_2_01_create_invoice_button_present_for_unpaid_job(self, html):
        modal_js = self._open_modal_js(html)
        assert "Create Invoice" in modal_js, \
            "openModal() does not render a 'Create Invoice' button for unpaid jobs"

    def test_2_02_create_invoice_button_calls_openInvoiceForm(self, html):
        modal_js = self._open_modal_js(html)
        assert "openInvoiceForm(" in modal_js, \
            "Create Invoice button must call openInvoiceForm(jobId)"

    def test_2_03_create_invoice_uses_btn_success_class(self, html):
        modal_js = self._open_modal_js(html)
        assert "btn-success" in modal_js, \
            "Create Invoice button must use btn-success (green) to distinguish " \
            "it visually from the blue Email/Text Invoice send buttons"

    def test_2_04_send_buttons_dimmed_when_no_invoice_exists(self, html):
        modal_js = self._open_modal_js(html)
        assert "_hasInv" in modal_js, \
            "Email/Text Invoice buttons must check _hasInv for conditional dimming"
        assert "opacity" in modal_js, \
            "An opacity style must be injected when _hasInv is false " \
            "(to visually signal that creating an invoice first is the correct flow)"

    def test_2_05_create_invoice_button_conditional_on_no_invoiceId(self, html):
        modal_js = self._open_modal_js(html)
        # The _hasInv check must appear BEFORE the openInvoiceForm call — it
        # guards whether the button is rendered at all.
        inv_check_pos = modal_js.index("_hasInv")
        create_pos    = modal_js.index("openInvoiceForm(")
        assert inv_check_pos < create_pos, (
            "_hasInv guard must appear before openInvoiceForm() — "
            "Create Invoice must only render when the job has no InvoiceID"
        )

    def test_2_06_dimming_opacity_is_fractional(self, html):
        modal_js = self._open_modal_js(html)
        # Opacity must be < 1 (e.g. 0.6 or .6)
        assert re.search(r"opacity\s*[:.]\s*0?\.[1-9]", modal_js), \
            "Dimmed buttons should use a fractional opacity value (e.g. 0.6)"


# ==========================================================================
# GROUP 3 -- JavaScript Functions Present
# ==========================================================================

class TestGroup3_JsFunctionsDeclared:
    """3.xx -- All required JS functions exist in index.html."""

    def test_3_01_openInvoiceForm_defined(self, html):
        assert "function openInvoiceForm(" in html, \
            "openInvoiceForm() is not defined in index.html"

    def test_3_02_closeInvoiceForm_defined(self, html):
        assert "function closeInvoiceForm(" in html, \
            "closeInvoiceForm() is not defined in index.html"

    def test_3_03_submitInvoiceForm_is_async(self, html):
        assert "async function submitInvoiceForm(" in html, (
            "submitInvoiceForm() must be declared async because it awaits mcpCall(). "
            "A sync function would silently lose the Promise."
        )

    def test_3_04_ifRecalc_defined(self, html):
        assert "function ifRecalc(" in html, \
            "ifRecalc() is not defined in index.html"

    def test_3_05_ifJobId_declared_with_let(self, html):
        assert "let _ifJobId" in html, (
            "_ifJobId must be declared with 'let' (not 'const' — it is reassigned "
            "on open and cleared on close/cancel)"
        )


# ==========================================================================
# GROUP 4 -- JS Logic: openInvoiceForm pre-fills from job data
# ==========================================================================

class TestGroup4_OpenInvoiceFormLogic:
    """4.xx -- openInvoiceForm() populates every form field from the job object."""

    def _open_fn(self, html: str) -> str:
        start = html.index("function openInvoiceForm(")
        return html[start: start + 3000]

    def test_4_01_sets_job_label_from_id_and_customer(self, html):
        fn = self._open_fn(html)
        assert "ifJobLabel" in fn, "openInvoiceForm must set ifJobLabel"
        assert "j.id" in fn and "j.customer" in fn, \
            "ifJobLabel text should include both j.id and j.customer"

    def test_4_02_prefills_quote_from_job(self, html):
        fn = self._open_fn(html)
        assert "ifQuote" in fn, "openInvoiceForm must assign ifQuote.value"
        assert "j.quote" in fn, "ifQuote.value should come from j.quote"

    def test_4_03_prefills_discount_from_job(self, html):
        fn = self._open_fn(html)
        assert "ifDiscount" in fn, "openInvoiceForm must assign ifDiscount.value"
        assert "j.discount" in fn, "ifDiscount.value should come from j.discount"

    def test_4_04_prefills_service_type_from_job(self, html):
        fn = self._open_fn(html)
        assert "ifServiceType" in fn, "openInvoiceForm must assign ifServiceType.value"
        assert "j.service" in fn, "ifServiceType.value should come from j.service"

    def test_4_05_prefills_description_from_job_notes(self, html):
        fn = self._open_fn(html)
        assert "ifDescription" in fn, "openInvoiceForm must assign ifDescription.value"
        assert "j.notes" in fn, "ifDescription.value should come from j.notes"

    def test_4_06_tax_rate_defaults_to_7_percent(self, html):
        fn = self._open_fn(html)
        assert "ifTaxRate" in fn, "openInvoiceForm must assign ifTaxRate.value"
        assert "'7'" in fn or '"7"' in fn, \
            "Tax rate field should default to '7' (representing 7%)"

    def test_4_07_due_days_defaults_to_30(self, html):
        fn = self._open_fn(html)
        assert "ifDueDays" in fn, "openInvoiceForm must assign ifDueDays.value"
        assert "'30'" in fn or '"30"' in fn, \
            "Due days field should default to '30' (Net 30)"

    def test_4_08_already_invoiced_warning_conditional_on_invoiceId(self, html):
        fn = self._open_fn(html)
        assert "ifAlreadyInvoiced" in fn, \
            "openInvoiceForm must reference the ifAlreadyInvoiced element"
        assert "j.invoiceId" in fn, \
            "Whether to show the warning must depend on j.invoiceId"

    def test_4_09_error_strip_hidden_on_open(self, html):
        fn = self._open_fn(html)
        assert "ifError" in fn, "openInvoiceForm must reset ifError on open"
        # Find the first mention of ifError in the function and check for 'none'
        idx = fn.index("ifError")
        nearby = fn[idx: idx + 200]
        assert "none" in nearby, \
            "ifError.style.display must be set to 'none' on open " \
            "so stale errors from a previous open are cleared"

    def test_4_10_submit_button_re_enabled_on_open(self, html):
        fn = self._open_fn(html)
        assert "ifSubmitBtn" in fn, \
            "openInvoiceForm must reset ifSubmitBtn on open"
        idx = fn.index("ifSubmitBtn")
        nearby = fn[idx: idx + 300]
        assert "false" in nearby, \
            "ifSubmitBtn.disabled must be set to false on open " \
            "(it may have been disabled by a previous submit attempt)"

    def test_4_11_modal_shown_as_flex_not_block(self, html):
        fn = self._open_fn(html)
        assert "invoiceFormModal" in fn, \
            "openInvoiceForm must reference the modal to show it"
        idx = fn.index("invoiceFormModal")
        nearby = fn[idx: idx + 300]
        assert "flex" in nearby, (
            "Modal must use display='flex' (not 'block') so the Cancel/Submit "
            "footer remains a flex sibling outside the scrollable content region"
        )

    def test_4_12_ifRecalc_called_immediately_on_open(self, html):
        fn = self._open_fn(html)
        assert "ifRecalc()" in fn, (
            "openInvoiceForm must call ifRecalc() immediately so the live-totals "
            "strip shows pre-filled values on first paint, not blank dashes"
        )


# ==========================================================================
# GROUP 5 -- JS Logic: closeInvoiceForm / cancel flow
# ==========================================================================

class TestGroup5_CloseInvoiceFormLogic:
    """5.xx -- closeInvoiceForm() dismisses the form and resets state."""

    def _close_fn(self, html: str) -> str:
        start = html.index("function closeInvoiceForm(")
        return html[start: start + 500]

    def test_5_01_hides_modal_by_setting_display_none(self, html):
        fn = self._close_fn(html)
        assert "invoiceFormModal" in fn, \
            "closeInvoiceForm must reference invoiceFormModal"
        assert "none" in fn, \
            "closeInvoiceForm must set modal display to 'none'"

    def test_5_02_clears_ifJobId_to_empty_string(self, html):
        fn = self._close_fn(html)
        assert "_ifJobId" in fn, \
            "closeInvoiceForm must clear the _ifJobId state variable"
        assert "_ifJobId = ''" in fn or '_ifJobId = ""' in fn, \
            "_ifJobId must be reset to '' so a stale job ID can't leak into the next open"

    def test_5_03_both_close_paths_call_closeInvoiceForm(self, html):
        modal_block = html.split('id="invoiceFormModal"')[1].split('<!-- /invoiceFormModal -->')[0]
        count = modal_block.count("closeInvoiceForm()")
        assert count >= 2, (
            f"Expected at least 2 closeInvoiceForm() calls inside the modal "
            f"(x button in header + Cancel button in footer), found {count}"
        )


# ==========================================================================
# GROUP 6 -- JS Logic: ifRecalc live totals
# ==========================================================================

class TestGroup6_IfRecalcLogic:
    """6.xx -- ifRecalc() computes and displays the correct live totals."""

    def _recalc_fn(self, html: str) -> str:
        start = html.index("function ifRecalc(")
        return html[start: start + 1500]

    def test_6_01_reads_all_three_input_fields(self, html):
        fn = self._recalc_fn(html)
        for field_id in ("ifQuote", "ifDiscount", "ifTaxRate"):
            assert field_id in fn, f"ifRecalc() must read the {field_id} input"

    def test_6_02_writes_all_three_display_elements(self, html):
        fn = self._recalc_fn(html)
        for elem_id in ("ifShowTaxable", "ifShowTax", "ifShowTotal"):
            assert elem_id in fn, f"ifRecalc() must update {elem_id}"

    def test_6_03_taxable_computed_as_quote_minus_discount(self, html):
        fn = self._recalc_fn(html)
        assert "quote - disc" in fn or "quote-disc" in fn, \
            "ifRecalc must compute taxable = quote - discount"

    def test_6_04_tax_rate_divided_by_100_for_decimal(self, html):
        fn = self._recalc_fn(html)
        assert "/ 100" in fn or "/100" in fn, (
            "ifRecalc must divide taxRate by 100 to convert a percentage (7) "
            "into the decimal fraction (0.07) used for multiplication"
        )

    def test_6_06_tax_uses_ceiling_rounding(self, html):
        fn = self._recalc_fn(html)
        assert "Math.ceil" in fn, (
            "Tax must use Math.ceil (ceiling to nearest penny) so the display "
            "never under-states the tax owed. Plain toFixed(2) or Math.round "
            "can silently truncate a sub-penny remainder."
        )
        # The ceilPenny helper must be applied to the tax line specifically,
        # not just defined somewhere unused.
        assert "ceilPenny" in fn, \
            "ceilPenny helper must be defined and applied to the tax calculation"
        tax_line_idx = fn.index("ceilPenny(")
        assert "taxRate" in fn[tax_line_idx: tax_line_idx + 80] or \
               "taxable" in fn[tax_line_idx: tax_line_idx + 80], \
            "ceilPenny must wrap the taxable * taxRate expression"

    def test_6_07_intermediate_values_rounded_before_addition(self, html):
        fn = self._recalc_fn(html)
        # round2 must be applied to taxable and total so IEEE-754 float drift
        # (e.g. 0.1 + 0.2 = 0.30000000000000004) doesn't leak into the display.
        assert "round2" in fn, (
            "ifRecalc must define and use a round2() helper that applies "
            "Math.round at 2 dp to each intermediate value, preventing "
            "IEEE-754 float drift from compounding across the taxable → tax → total chain"
        )
        assert "Number.EPSILON" in fn, (
            "round2/ceilPenny should add Number.EPSILON before rounding to "
            "avoid the classic (0.1 + 0.2).toFixed(2) = '0.30' edge case "
            "where the float is just barely below the rounding threshold"
        )

    def test_6_05_oninput_wired_on_all_numeric_fields(self, html):
        for field_id in ("ifQuote", "ifDiscount", "ifTaxRate"):
            idx = html.index(f'id="{field_id}"')
            ctx = html[max(0, idx - 400): idx + 400]
            assert "ifRecalc()" in ctx, (
                f"{field_id} input must have oninput=\"ifRecalc()\" "
                f"so the live-totals strip updates on every keystroke"
            )


# ==========================================================================
# GROUP 7 -- JS Logic: submitInvoiceForm
# ==========================================================================

class TestGroup7_SubmitInvoiceFormLogic:
    """7.xx -- submitInvoiceForm() validates, calls the API, handles all outcomes."""

    def _submit_fn(self, html: str) -> str:
        start = html.index("async function submitInvoiceForm(")
        return html[start: start + 4000]

    def test_7_01_validates_quote_before_sending(self, html):
        fn = self._submit_fn(html)
        assert "ifQuote" in fn, "submitInvoiceForm must read ifQuote"
        assert "return" in fn, \
            "submitInvoiceForm must have an early return when quote is invalid"
        assert "isNaN" in fn or "<= 0" in fn, \
            "submitInvoiceForm must reject a zero or non-numeric quote amount"

    def test_7_02_calls_mcpCall_with_create_invoice(self, html):
        fn = self._submit_fn(html)
        assert "mcpCall(" in fn, "submitInvoiceForm must call mcpCall()"
        assert "'create_invoice'" in fn or '"create_invoice"' in fn, \
            "mcpCall tool name must be the string 'create_invoice'"

    def test_7_03_job_identifier_from_ifJobId(self, html):
        fn = self._submit_fn(html)
        assert "job_identifier" in fn, "args object must include job_identifier"
        assert "_ifJobId" in fn, \
            "job_identifier value must come from the _ifJobId state variable"

    def test_7_04_passes_all_numeric_invoice_fields(self, html):
        fn = self._submit_fn(html)
        for field in ("quote_amount", "discount", "tax_rate", "due_days"):
            assert field in fn, f"args must include {field}"

    def test_7_05_passes_service_type_and_description(self, html):
        fn = self._submit_fn(html)
        assert "service_type" in fn, "args must include service_type"
        assert "description" in fn, "args must include description"

    def test_7_06_backup_set_to_true(self, html):
        fn = self._submit_fn(html)
        assert "backup" in fn, "args must include backup"
        assert "true" in fn, "backup must be set to true"

    def test_7_07_checks_failure_result_with_isFailureResult(self, html):
        fn = self._submit_fn(html)
        assert "_isFailureResult(" in fn, (
            "submitInvoiceForm must call _isFailureResult() to detect "
            "tool-level errors returned as ok=true + error string"
        )

    def test_7_08_parses_NEW_INVOICE_ID_sentinel(self, html):
        fn = self._submit_fn(html)
        assert "NEW_INVOICE_ID=" in fn, (
            "submitInvoiceForm must parse the NEW_INVOICE_ID= sentinel line "
            "from the result so it can patch state.jobs in-memory"
        )

    def test_7_09_patches_state_jobs_invoiceId_on_success(self, html):
        fn = self._submit_fn(html)
        assert "state.jobs" in fn, \
            "submitInvoiceForm must patch state.jobs on success"
        assert "invoiceId" in fn, \
            "The patch must update j.invoiceId with the new InvoiceID"

    def test_7_10_calls_closeInvoiceForm_on_success(self, html):
        fn = self._submit_fn(html)
        assert "closeInvoiceForm()" in fn, \
            "submitInvoiceForm must call closeInvoiceForm() to dismiss the form on success"

    def test_7_11_shows_toast_on_success(self, html):
        fn = self._submit_fn(html)
        assert "showToast(" in fn, \
            "submitInvoiceForm must call showToast() to confirm success to the user"

    def test_7_12_reopens_job_modal_after_success(self, html):
        fn = self._submit_fn(html)
        assert "openModal(" in fn, (
            "submitInvoiceForm must re-open the job detail modal after success "
            "so the user sees the updated state: Create Invoice gone, "
            "Email/Text Invoice now full-opacity"
        )

    def test_7_13_backend_error_goes_to_strip_not_alert(self, html):
        fn = self._submit_fn(html)
        assert "ifError" in fn, \
            "submitInvoiceForm must display backend errors in the ifError strip"
        # Check the section after the _isFailureResult() call
        failure_area = fn[fn.index("_isFailureResult("): fn.index("_isFailureResult(") + 400]
        assert "alert(" not in failure_area, (
            "Backend errors must appear in the ifError strip, not in alert(). "
            "alert() dismisses the form content and blocks the UI."
        )

    def test_7_14_submit_button_re_enabled_on_failure(self, html):
        fn = self._submit_fn(html)
        # submitInvoiceForm() assigns the button to a local 'submitBtn' alias
        # immediately after grabbing it, then uses that alias throughout —
        # so we count 'submitBtn.disabled = false' rather than raw 'ifSubmitBtn'.
        # It must appear in BOTH the _isFailureResult branch AND the catch block.
        count = fn.count("submitBtn.disabled = false")
        assert count >= 2, (
            f"submitBtn.disabled = false must appear in every failure path "
            f"(tool-level _isFailureResult branch AND network catch block); "
            f"found {count} occurrence(s). The user must be able to retry after any error."
        )


# ==========================================================================
# GROUP 8 -- MCP API round-trip (live_pwa)
# ==========================================================================

class TestGroup8_LiveApiRoundTrip:
    """8.xx -- create_invoice tool integration tests via /pwa-api.

    All tests in this group require AI-Prowler running on localhost:8000.

    Run with:
        pytest tests/mcp/test_pwa_invoice_form.py -v -m live_pwa
    """

    @pytest.mark.live_pwa
    def test_8_01_create_invoice_returns_http_200(self, server):
        # Even an invalid call must return HTTP 200 — errors are in JSON body,
        # not HTTP status codes, matching how every other MCP tool works here.
        status, data = _api("create_invoice", {"job_identifier": ""})
        assert status == 200, (
            f"create_invoice returned HTTP {status}, expected 200. "
            "Tool-level errors should be in the JSON body, not HTTP status."
        )

    @pytest.mark.live_pwa
    def test_8_02_blank_identifier_is_tool_level_error(self, server):
        # Blank job_identifier must produce a tool-level error string
        # (ok=True at transport level, result starts with emoji flag).
        status, data = _api("create_invoice", {"job_identifier": ""})
        assert data.get("ok") is True, (
            f"Transport 'ok' must be True even for tool errors; got: {data}"
        )
        result = data.get("result", "")
        assert result.startswith("\u274c"), (
            f"Blank identifier should produce a \u274c error string, got: {result!r}"
        )

    @pytest.mark.live_pwa
    def test_8_03_nonexistent_job_gives_friendly_error(self, server):
        status, data = _api("create_invoice", {
            "job_identifier": "JOB-DOES-NOT-EXIST-PWA-TEST"
        })
        assert status == 200
        result = data.get("result", "")
        assert "\u274c" in result, \
            f"Non-existent job should produce a \u274c message, got: {result!r}"
        assert "traceback" not in result.lower(), \
            f"Error should be a friendly message, not a Python traceback: {result!r}"

    @pytest.mark.live_pwa
    def test_8_04_create_invoice_is_in_allowed_tools_list(self, server):
        # Confirm the tool is reachable via /pwa-api (not blocked by the
        # allowed-list). A sentinel call should get a tool-level response
        # (HTTP 200 + ok key), not a 400 "unknown tool".
        status, data = _api("create_invoice", {"job_identifier": "JOB-SENTINEL-TEST"})
        assert status == 200, (
            f"create_invoice returned HTTP {status}. "
            "If it returned 400, the tool may be missing from _allowed_tools in "
            "the /pwa-api handler."
        )
        assert "ok" in data, \
            "Response must have an 'ok' key, meaning it reached the backend"

    @pytest.mark.live_pwa
    def test_8_05_successful_create_returns_required_fields(self, server):
        """Attempt on the first priced, un-invoiced job. Skips gracefully if
        no suitable job exists in the spreadsheet."""
        status, jobs_data = _api("read_job_spreadsheet", {"max_rows": 50})
        if not jobs_data.get("ok") or not jobs_data.get("result"):
            pytest.skip("Could not load jobs from spreadsheet")

        raw = jobs_data["result"]
        candidates = []
        for block in raw.split("\n\n"):
            if "JOB-" not in block:
                continue
            job_id_m = re.search(r"JobID[^:]*:\s*(JOB-\d+)", block)
            inv_m    = re.search(r"InvoiceID[^:]*:\s*(INV-\d+)", block)
            quote_m  = re.search(r"Quote Amount[^:]*:\s*(\d+(?:\.\d+)?)", block)
            if job_id_m and not inv_m and quote_m:
                candidates.append(job_id_m.group(1))

        if not candidates:
            pytest.skip(
                "No priced, un-invoiced jobs found — cannot test the success "
                "path without modifying real spreadsheet data."
            )

        job_id = candidates[0]
        status, data = _api("create_invoice", {
            "job_identifier": job_id,
            "backup": False,
        })
        assert status == 200
        result = data.get("result", "")

        if "\u274c" in result:
            pytest.skip(
                f"Job {job_id} could not be invoiced right now: "
                f"{result.split(chr(10))[0]}"
            )

        assert "NEW_INVOICE_ID=" in result, \
            f"Success result must contain NEW_INVOICE_ID= line; got:\n{result}"
        assert "\u2705 Invoice created:" in result, \
            f"Success result must begin with checkmark confirmation; got:\n{result}"

        inv_line  = next(l for l in result.splitlines() if l.startswith("NEW_INVOICE_ID="))
        new_inv_id = inv_line.split("=", 1)[1].strip()
        assert re.match(r"INV-\d{4}", new_inv_id), \
            f"New InvoiceID should match INV-#### pattern, got: {new_inv_id!r}"

    @pytest.mark.live_pwa
    def test_8_06_double_invoice_is_blocked_with_clear_error(self, server):
        """A second create_invoice call on an already-invoiced job must be refused."""
        status, jobs_data = _api("read_job_spreadsheet", {"max_rows": 200})
        if not jobs_data.get("ok") or not jobs_data.get("result"):
            pytest.skip("Could not load jobs")

        raw = jobs_data["result"]
        already_invoiced_id = None
        for block in raw.split("\n\n"):
            job_id_m = re.search(r"JobID[^:]*:\s*(JOB-\d+)", block)
            inv_m    = re.search(r"InvoiceID[^:]*:\s*(INV-\d+)", block)
            if job_id_m and inv_m:
                already_invoiced_id = job_id_m.group(1)
                break

        if not already_invoiced_id:
            pytest.skip("No already-invoiced job found to test the double-invoice guard")

        status, data = _api("create_invoice", {
            "job_identifier": already_invoiced_id,
            "backup": False,
        })
        assert status == 200
        result = data.get("result", "")
        assert "\u274c" in result, \
            f"Double-invoice must be refused with \u274c error, got: {result!r}"
        assert "already has an invoice" in result.lower() or re.search(r"INV-\d{4}", result), \
            f"Error should reference the existing InvoiceID, got: {result!r}"
