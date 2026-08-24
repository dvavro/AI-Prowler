"""
test_pwa_sheet_tabs.py — Tests for the 8-tab Jobs Spreadsheet screen.
Run: pytest tests/mcp/test_pwa_sheet_tabs.py -v
"""
import re, os
from pathlib import Path
import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parents[2]
PWA_HTML = SRC_ROOT / "jobs" / "index.html"

@pytest.fixture(scope="module")
def html():
    assert PWA_HTML.exists()
    return PWA_HTML.read_text(encoding="utf-8", errors="replace")

@pytest.fixture(scope="module")
def js(html):
    start = html.rfind("<script>") + len("<script>")
    end   = html.rfind("</script>")
    return html[start:end]

def _fn(js, name):
    for prefix in (f"async function {name}(", f"function {name}("):
        start = js.find(prefix)
        if start == -1: continue
        depth, i = 0, start
        while i < len(js):
            if js[i] == "{": depth += 1
            elif js[i] == "}":
                depth -= 1
                if depth == 0: return js[start:i+1]
            i += 1
    return ""


class TestSheetTabHTML:
    def test_sheet_tabs_container(self, html):
        assert 'id="sheetTabs"' in html, "sheetTabs container missing"

    def test_sheet_content_container(self, html):
        assert 'id="sheetContent"' in html

    def test_sheet_debug_log(self, html):
        assert 'id="sheetDebug"' in html

    def test_nav_sheet_button(self, html):
        assert 'id="navSheet"' in html

    def test_nav_sheet_no_double_call(self, html):
        idx = html.find('id="navSheet"')
        ctx = html[idx:idx+150]
        # Must NOT call loadSheetScreen() directly — showScreen() does it
        assert "loadSheetScreen()" not in ctx, \
            "navSheet onclick must not call loadSheetScreen() explicitly — " \
            "showScreen() already does this, causing double-load"


class TestSheetFunctions:
    def test_switch_sheet_defined(self, js):
        assert "function _switchSheet(" in js or "async function _switchSheet(" in js

    def test_load_sheet_defined(self, js):
        assert "async function loadSheet(" in js

    def test_render_sheet_tabs_defined(self, js):
        assert "function _renderSheetTabs(" in js

    def test_render_generic_table_defined(self, js):
        assert "function _renderGenericTable(" in js

    def test_sheets_array_defined(self, js):
        assert "_SHEETS" in js, "_SHEETS array defining all 8 tabs must exist"

    def test_all_8_sheets_present(self, js):
        required = ["Jobs_Schedule", "Customers", "Invoices", "Quotes",
                    "TimeLog", "Route_Planner", "Services_Pricing"]
        for s in required:
            assert s in js, f"Sheet '{s}' missing from _SHEETS"


class TestTabButtonSafety:
    """Tab buttons must NOT use inline onclick with double-quoted strings."""

    def test_render_tabs_uses_data_attribute(self, js):
        fn = _fn(js, "_renderSheetTabs")
        # Must use data-sheet attribute, NOT inline onclick with JSON.stringify
        assert "data-sheet" in fn or "data-name" in fn, \
            "_renderSheetTabs must use data-* attributes for sheet name — " \
            "JSON.stringify() in onclick puts double-quotes inside the attribute " \
            "which closes the onclick prematurely: onclick=\"_switchSheet(\"name\")\" breaks"

    def test_no_json_stringify_in_onclick(self, js):
        fn = _fn(js, "_renderSheetTabs")
        assert "JSON.stringify" not in fn or "onclick" not in fn, \
            "JSON.stringify in onclick generates double-quoted strings that break HTML"

    def test_tab_event_delegation(self, js):
        fn = _fn(js, "_renderSheetTabs")
        # Either uses data attributes with delegation, or safe single-quote wrapping
        has_data = "data-sheet" in fn or "data-name" in fn
        has_safe_onclick = "onclick=\'_switchSheet(" in fn  # escaped single quotes
        assert has_data or has_safe_onclick, \
            "Tab buttons must use data-* attributes + delegation OR safe single-quoted onclick"


class TestSwitchSheet:
    def test_switch_sheet_updates_active(self, js):
        fn = _fn(js, "_switchSheet")
        assert "_activeSheet" in fn, "_switchSheet must update _activeSheet"

    def test_switch_sheet_renders_tabs(self, js):
        fn = _fn(js, "_switchSheet")
        assert "_renderSheetTabs" in fn, "_switchSheet must re-render tabs to update active highlight"

    def test_switch_sheet_calls_load_sheet(self, js):
        fn = _fn(js, "_switchSheet")
        assert "loadSheet(" in fn, "_switchSheet must call loadSheet()"

    def test_switch_sheet_toggles_add_btn(self, js):
        fn = _fn(js, "_switchSheet")
        assert "sheetAddBtn" in fn or "addable" in fn, \
            "_switchSheet should show/hide + Add Row button based on sheet.addable"


class TestLoadSheet:
    def test_calls_read_job_spreadsheet(self, js):
        fn = _fn(js, "loadSheet")
        assert "read_job_spreadsheet" in fn

    def test_passes_sheet_name(self, js):
        fn = _fn(js, "loadSheet")
        assert "sheet_name" in fn, "Must pass sheet_name parameter to read_job_spreadsheet"

    def test_calls_render_generic_table(self, js):
        fn = _fn(js, "loadSheet")
        assert "_renderGenericTable" in fn

    def test_handles_errors(self, js):
        fn = _fn(js, "loadSheet")
        assert "catch" in fn


class TestGenericTableRender:
    def test_no_replace_child(self, js):
        fn = _fn(js, "_renderGenericTable")
        assert "replaceChild" not in fn, \
            "Must NOT use replaceChild — causes null parentNode on second call " \
            "because el is detached from DOM after first replaceChild"

    def test_no_clone_node(self, js):
        fn = _fn(js, "_renderGenericTable")
        assert "cloneNode" not in fn, \
            "Must NOT use cloneNode — event delegation should be on stable screenSheet"

    def test_renders_table(self, js):
        fn = _fn(js, "_renderGenericTable")
        assert "<table" in fn

    def test_renders_thead(self, js):
        fn = _fn(js, "_renderGenericTable")
        assert "<thead" in fn

    def test_sticky_header(self, js):
        fn = _fn(js, "_renderGenericTable")
        assert "sticky" in fn, "Table header should be sticky for scroll usability"

    def test_edit_button_data_attrs(self, js):
        fn = _fn(js, "_renderGenericTable")
        assert "data-sheet" in fn and "data-rowid" in fn, \
            "Edit button must use data-sheet and data-rowid attributes"

    def test_sheet_delegation_on_screenshee(self, js):
        fn = _fn(js, "loadSheetScreen")
        assert "screenSheet" in fn and "_sheetDelegation" in fn, \
            "Event delegation must be on stable screenSheet div, not dynamic sheetContent"
