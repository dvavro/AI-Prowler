"""Test expanded list_tracked_directories (R-072)."""
import sys
from pathlib import Path as _Path
# 2026-10-21: this used to insert a hard-coded OLD work folder at the front of
# sys.path at collection time, so every test collected after it imported that
# folder's setup_wizard.py etc. instead of this repo's. Use this repo's root.
_ROOT = str(_Path(__file__).resolve().parents[2])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# We test the formatting logic in isolation (not the full MCP tool,
# which needs server context). Import the helpers.
import ai_prowler_mcp as mcp

def test_both_sections_present():
    """The tool output must have both labeled sections."""
    # Mock the data sources
    orig_load = mcp.load_auto_update_list
    orig_access = mcp.access_allowlist_load
    orig_writable = mcp._writable_allowlist_load
    try:
        mcp.load_auto_update_list = lambda: [r"C:\Test\Indexed"]
        mcp.access_allowlist_load = lambda: [r"C:\Test\AccessOnly"]
        mcp._writable_allowlist_load = lambda: [r"C:\Test\Indexed"]
        # Personal mode: _current_user returns None, _IS_SERVER_MODE False
        result = mcp.list_tracked_directories()
        assert "Indexed directories (in ChromaDB):" in result, "Missing indexed section"
        assert "Access-only folders (readable, not indexed):" in result, "Missing access-only section"
        assert r"C:\Test\Indexed" in result, "Indexed path missing"
        assert r"C:\Test\AccessOnly" in result, "Access-only path missing"
        print("PASS: both sections present")
    finally:
        mcp.load_auto_update_list = orig_load
        mcp.access_allowlist_load = orig_access
        mcp._writable_allowlist_load = orig_writable

def test_write_badges():
    """[W] for writable, [R] for read-only."""
    orig_load = mcp.load_auto_update_list
    orig_access = mcp.access_allowlist_load
    orig_writable = mcp._writable_allowlist_load
    try:
        mcp.load_auto_update_list = lambda: [r"C:\W\Indexed", r"C:\R\Indexed"]
        mcp.access_allowlist_load = lambda: [r"C:\W\Access", r"C:\R\Access"]
        mcp._writable_allowlist_load = lambda: [r"C:\W"]
        result = mcp.list_tracked_directories()
        # C:\W\Indexed should be [W] (inside C:\W)
        # C:\R\Indexed should be [R]
        for line in result.split("\n"):
            if r"C:\W\Indexed" in line:
                assert "[W]" in line, f"Expected [W] for writable: {line}"
            if r"C:\R\Indexed" in line:
                assert "[R]" in line, f"Expected [R] for read-only: {line}"
            if r"C:\W\Access" in line:
                assert "[W]" in line, f"Expected [W] for writable access-only: {line}"
            if r"C:\R\Access" in line:
                assert "[R]" in line, f"Expected [R] for read-only access-only: {line}"
        print("PASS: write badges correct")
    finally:
        mcp.load_auto_update_list = orig_load
        mcp.access_allowlist_load = orig_access
        mcp._writable_allowlist_load = orig_writable

def test_empty_sections():
    """Empty lists show (none) placeholders."""
    orig_load = mcp.load_auto_update_list
    orig_access = mcp.access_allowlist_load
    orig_writable = mcp._writable_allowlist_load
    try:
        mcp.load_auto_update_list = lambda: []
        mcp.access_allowlist_load = lambda: []
        mcp._writable_allowlist_load = lambda: []
        result = mcp.list_tracked_directories()
        assert "(none)" in result, "Missing (none) for empty indexed"
        assert "grant_access()" in result, "Missing grant_access hint"
        print("PASS: empty sections handled")
    finally:
        mcp.load_auto_update_list = orig_load
        mcp.access_allowlist_load = orig_access
        mcp._writable_allowlist_load = orig_writable

if __name__ == "__main__":
    test_both_sections_present()
    test_write_badges()
    test_empty_sections()
    print("ALL TESTS PASSED")
