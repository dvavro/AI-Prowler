"""
test_pwa_sheet.py — Tests for the Jobs Spreadsheet screen in the PWA Jobs app.
Checks HTML structure, JS functions, div balance, and parseJobs logic.

Architecture note (current as of v9.1):
  - loadSheetScreen()  : thin coordinator — attaches event delegation,
                         renders tab buttons, then calls loadSheet(_activeSheet).
  - loadSheet(name)    : does the actual work — fetches data, parses, renders
                         the tab table with XSS safety, handles errors/empty.
  - parseJobs(raw)     : parses the raw text from read_job_spreadsheet.
  - navSheet nav button: calls showScreen('sheet', this) — the sheet screen's
                         onshow / showScreen dispatch triggers loadSheetScreen.

Run: pytest tests/mcp/test_pwa_sheet.py -v
"""
import re
import os
from pathlib import Path
import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parents[2]
PWA_HTML = SRC_ROOT / "jobs" / "index.html"


@pytest.fixture(scope="module")
def html():
    assert PWA_HTML.exists(), f"Not found: {PWA_HTML}"
    return PWA_HTML.read_text(encoding="utf-8", errors="replace")


@pytest.fixture(scope="module")
def js(html):
    start = html.rfind("<script>") + len("<script>")
    end   = html.rfind("</script>")
    assert end > start
    return html[start:end]


def _fn(js, name):
    start = js.find(f"function {name}(")
    if start == -1:
        start = js.find(f"async function {name}(")
    if start == -1:
        return ""
    depth, i, n = 0, start, len(js)
    while i < n:
        if js[i] == "{": depth += 1
        elif js[i] == "}":
            depth -= 1
            if depth == 0: return js[start:i+1]
        i += 1
    return js[start:]


# ── HTML Structure ─────────────────────────────────────────────────────────────

class TestSheetHTML:

    def test_screen_exists(self, html):
        assert 'id="screenSheet"' in html, "Sheet screen div missing"

    def test_sheet_content_exists(self, html):
        assert 'id="sheetContent"' in html, "sheetContent div missing"

    def test_debug_log_exists(self, html):
        assert 'id="sheetDebug"' in html, \
            "sheetDebug div missing — needed for in-page diagnostics"

    def test_job_form_modal_exists(self, html):
        assert 'id="jobFormModal"' in html, "Add/Edit job modal missing"

    def test_form_fields_exist(self, html):
        for fid in ["jfJobId","jfCustomer","jfAddress","jfCity","jfState",
                    "jfDate","jfStart","jfEnd","jfService","jfNotes",
                    "jfCrew","jfStatus","jfQuote","jobFormError","jobFormSaveBtn"]:
            assert f'id="{fid}"' in html, f"Form field #{fid} missing"

    def test_nav_sheet_button_exists(self, html):
        assert 'id="navSheet"' in html, "Sheet nav button missing"

    def test_nav_sheet_triggers_sheet_screen(self, html):
        # navSheet calls showScreen('sheet', this) which dispatches to
        # loadSheetScreen() — not a direct call to loadSheetScreen().
        idx = html.find('id="navSheet"')
        ctx = html[idx:idx+200]
        assert "sheet" in ctx, \
            "navSheet must navigate to the sheet screen"

    def test_div_balance(self, html):
        opens  = html.count("<div")
        closes = html.count("</div>")
        assert opens == closes, \
            f"Unbalanced divs: {opens} opens vs {closes} closes — causes black screen"

    def test_screen_inside_app(self, html):
        app_pos    = html.find('id="app"')
        sheet_pos  = html.find('id="screenSheet"')
        nav_pos    = html.find('<nav class="bottomnav"')
        assert app_pos < sheet_pos < nav_pos, \
            "screenSheet must be inside #app div, before <nav>"


# ── JS Functions ───────────────────────────────────────────────────────────────

class TestSheetFunctions:

    def test_sheet_log_defined(self, js):
        assert "function sheetLog(" in js, \
            "sheetLog() missing — debug logging unavailable"

    def test_load_sheet_screen_defined(self, js):
        assert "async function loadSheetScreen(" in js, \
            "loadSheetScreen() missing"

    def test_load_sheet_defined(self, js):
        # loadSheet(name) is the workhorse called by loadSheetScreen
        assert "function loadSheet(" in js, \
            "loadSheet() missing — the tab-aware data fetcher"

    def test_open_edit_job_modal_defined(self, js):
        assert "function openEditJobModal(" in js

    def test_open_add_job_modal_defined(self, js):
        assert "function openAddJobModal(" in js

    def test_save_job_form_defined(self, js):
        assert "async function saveJobForm(" in js

    def test_close_job_form_modal_defined(self, js):
        assert "function closeJobFormModal(" in js

    def test_parse_jobs_defined(self, js):
        assert "function parseJobs(" in js


class TestLoadSheetScreen:
    """loadSheetScreen() is the coordinator that sets up event delegation
    and then delegates to loadSheet(_activeSheet). The actual data-fetch,
    parse, render, error-handling, and XSS-safety logic lives in loadSheet().
    Tests below verify both functions where appropriate."""

    def test_calls_load_sheet(self, js):
        fn = _fn(js, "loadSheetScreen")
        assert "loadSheet(" in fn, \
            "loadSheetScreen must delegate to loadSheet()"

    def test_attaches_event_delegation(self, js):
        fn = _fn(js, "loadSheetScreen")
        assert "addEventListener" in fn or "_sheetDelegation" in fn, \
            "loadSheetScreen must attach click delegation (not inline onclick)"

    def test_calls_render_sheet_tabs(self, js):
        fn = _fn(js, "loadSheetScreen")
        assert "_renderSheetTabs" in fn or "renderSheetTabs" in fn, \
            "loadSheetScreen must render the tab buttons"

    def test_load_sheet_calls_read_job_spreadsheet(self, js):
        fn = _fn(js, "loadSheet")
        assert "read_job_spreadsheet" in fn, \
            "loadSheet must call read_job_spreadsheet"

    def test_load_sheet_calls_render_generic_table(self, js):
        # loadSheet delegates rendering to _renderGenericTable, not parseJobs.
        # parseJobs is used by loadJobs() (the Jobs tab), not the Sheet tab.
        fn = _fn(js, "loadSheet")
        assert "_renderGenericTable(" in fn, \
            "loadSheet must call _renderGenericTable to render the tab table"

    def test_load_sheet_shows_spinner_while_loading(self, js):
        fn = _fn(js, "loadSheet")
        assert "spinner" in fn, "loadSheet must show spinner while loading"

    def test_load_sheet_uses_sheet_log_for_debug(self, js):
        fn = _fn(js, "loadSheet")
        assert "sheetLog(" in fn, \
            "loadSheet must log progress via sheetLog()"

    def test_load_sheet_handles_empty_result(self, js):
        fn = _fn(js, "loadSheet")
        assert "No jobs" in fn or "empty" in fn.lower() or "no data" in fn.lower() \
            or "length" in fn, \
            "loadSheet must handle empty state when no data returned"

    def test_load_sheet_handles_errors(self, js):
        fn = _fn(js, "loadSheet")
        assert "catch" in fn, \
            "loadSheet must catch and handle errors"

    def test_load_sheet_uses_esc_for_safety(self, js):
        # Either loadSheet or the render helper uses esc() for XSS safety
        fn_load  = _fn(js, "loadSheet")
        fn_sheet = _fn(js, "loadSheetScreen")
        # Also check _renderSheetTabs which uses esc()
        i = js.find("function _renderSheetTabs(")
        fn_tabs  = js[i:i+500] if i != -1 else ""
        assert "esc(" in fn_load or "esc(" in fn_sheet or "esc(" in fn_tabs, \
            "Sheet rendering must escape user data with esc() to prevent XSS"

    def test_edit_button_uses_data_attribute(self, js):
        # Event delegation uses data-rowid or data-rowjson, not inline onclick
        fn = _fn(js, "loadSheetScreen")
        fn2 = _fn(js, "loadSheet")
        assert "data-rowid" in fn or "data-rowjson" in fn \
            or "data-rowid" in fn2 or "data-rowjson" in fn2 \
            or "data-jobid" in fn or "data-jobid" in fn2, \
            "Edit button must use data-* attribute for event delegation"


class TestParseJobs:

    def test_splits_on_jobid(self, js):
        fn = _fn(js, "parseJobs")
        assert "JobID" in fn, "parseJobs must split on JobID: pattern"

    def test_positional_service_extraction(self, js):
        fn = _fn(js, "parseJobs")
        has_positional = "svc" in fn or "Service" in fn
        assert has_positional, \
            "parseJobs must handle positional Service column extraction"

    def test_filters_to_job_prefix(self, js):
        fn = _fn(js, "parseJobs")
        assert "JOB-" in fn, \
            "parseJobs must filter to entries starting with JOB-"

    def test_extracts_crew(self, js):
        fn = _fn(js, "parseJobs")
        assert "Crew" in fn, "Must extract Crew field"

    def test_extracts_status_field(self, js):
        fn = _fn(js, "parseJobs")
        # parseJobs must extract Job Status into a 'status' property —
        # the popup button logic (isJobComplete) reads j.status directly.
        assert "status" in fn, \
            "parseJobs must extract Job Status field into j.status"

    def test_extracts_payment_field(self, js):
        fn = _fn(js, "parseJobs")
        # parseJobs must extract Payment Status into a 'payment' property —
        # the popup invoice button logic reads j.payment to decide whether
        # to show invoice buttons or receipt buttons.
        assert "payment" in fn, \
            "parseJobs must extract Payment field into j.payment"

    def test_returns_array(self, js):
        fn = _fn(js, "parseJobs")
        assert ".filter(" in fn, "parseJobs must filter results"


class TestEditJobModal:

    def test_prefills_all_fields(self, js):
        fn = _fn(js, "openEditJobModal")
        for fid in ["jfCustomer","jfAddress","jfDate","jfStart","jfEnd",
                    "jfService","jfCrew","jfStatus"]:
            assert fid in fn, f"Edit modal must prefill #{fid}"

    def test_save_calls_update_tool(self, js):
        fn = _fn(js, "saveJobForm")
        assert "update_job_spreadsheet" in fn, \
            "saveJobForm must call update_job_spreadsheet"

    def test_save_shows_error_on_failure(self, js):
        fn = _fn(js, "saveJobForm")
        assert "jobFormError" in fn, "Must show error in #jobFormError on failure"

    def test_close_hides_modal(self, js):
        fn = _fn(js, "closeJobFormModal")
        assert "display" in fn or "style" in fn, \
            "closeJobFormModal must hide the modal"
