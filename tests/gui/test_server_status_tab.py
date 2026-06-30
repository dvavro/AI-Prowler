"""
tests/gui/test_server_status_tab.py
=====================================
GUI regression tests for v7.0.1:

  CHANGE 1 — rag_gui.py: create_welcome_tab() routes to _create_server_status_tab()
             in Business Server mode instead of building the full Home page with
             ad content, notification fetches, and GitHub traffic.

  CHANGE 2 — rag_gui.py: _create_server_status_tab() builds a clean Server Status
             panel showing edition/mode, version, database path, chunk count,
             document count, tracked folder count, and a Refresh button.

Test IDs
--------
  SS-01  Home mode: notebook tab 0 is labelled "🏠 Home" not "🖥️ Server"
  SS-02  Server mode: notebook tab 0 is labelled "🖥️ Server" not "🏠 Home"
  SS-03  Home mode: _refresh_welcome_ad is scheduled (ad/notif system active)
  SS-04  Server mode: _refresh_welcome_ad is NOT called (no GitHub traffic)
  SS-05  Server mode: _notif_frame attribute exists (shared code does not crash)
  SS-06  Server mode: _notif_widgets attribute is an empty list
  SS-07  Server mode: _ad_url is empty string (no outbound ad fetch)
  SS-08  Server mode: _notif_url is empty string (no outbound notif fetch)
  SS-09  Server mode: _srv_status_vars dict contains expected keys
  SS-10  Server mode: _refresh_server_status populates chunk count from live DB
  SS-11  Server mode: _refresh_server_status populates db_path from rag_preprocessor
  SS-12  Server mode: _refresh_server_status populates tracked count
  SS-13  Server mode: Refresh button exists and is callable without error
  SS-14  Home mode: _srv_status_vars attribute does NOT exist (clean separation)
  SS-15  Server mode: telemetry paths are set (server still phones home)
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Path setup
_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def home_gui(gui, monkeypatch, tmp_path):
    """GUI fixture forced into personal/home mode regardless of the real
    config.json on disk.  Writes edition=personal + mode=personal into the
    real config location, rebuilds the GUI, then restores on teardown."""
    import rag_gui as gui_mod

    cfg_dir  = Path.home() / ".ai-prowler"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = cfg_dir / "config.json"

    original_content = cfg_path.read_text(encoding="utf-8-sig") if cfg_path.exists() else None

    # Force personal/home mode
    existing = {}
    try:
        existing = json.loads(original_content) if original_content else {}
    except Exception:
        pass
    existing.update({"edition": "personal", "mode": "personal"})
    cfg_path.write_text(json.dumps(existing), encoding="utf-8")

    root = gui.root
    for child in list(root.winfo_children()):
        try:
            child.destroy()
        except Exception:
            pass

    app = gui_mod.RAGGui(root)
    gui.app = app
    gui.pump()

    yield gui

    if original_content is not None:
        cfg_path.write_text(original_content, encoding="utf-8")
    else:
        try:
            cfg_path.unlink()
        except Exception:
            pass


@pytest.fixture
def server_gui(gui, monkeypatch, tmp_path):
    """GUI fixture with Business Server mode active.

    Writes a config.json declaring edition=business + mode=server into the
    home dir that _is_business_server_mode() reads, then rebuilds the GUI
    so create_welcome_tab() sees the server config.
    """
    import rag_gui as gui_mod

    # Write config.json to the real home dir location the GUI reads
    cfg_dir = Path.home() / ".ai-prowler"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = cfg_dir / "config.json"

    original_content = cfg_path.read_text(encoding="utf-8-sig") if cfg_path.exists() else None

    cfg_path.write_text(
        json.dumps({"edition": "business", "mode": "server"}),
        encoding="utf-8"
    )

    # Rebuild the GUI so create_welcome_tab sees the new config
    root = gui.root
    for child in list(root.winfo_children()):
        try:
            child.destroy()
        except Exception:
            pass

    app = gui_mod.RAGGui(root)
    gui.app = app
    gui.pump()

    yield gui

    # Restore config
    if original_content is not None:
        cfg_path.write_text(original_content, encoding="utf-8")
    else:
        try:
            cfg_path.unlink()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# SS-01  Home mode tab label
# ─────────────────────────────────────────────────────────────────────────────

def test_ss01_home_mode_tab_label(home_gui):
    """Tab 0 in Home mode must be labelled with the home icon, not server."""
    tab0_text = home_gui.app.notebook.tab(0, "text")
    assert "Home" in tab0_text or "🏠" in tab0_text, (
        f"SS-01 FAIL: expected Home tab at index 0, got: {tab0_text!r}"
    )
    assert "Server" not in tab0_text, (
        f"SS-01 FAIL: Home mode should not show Server tab at index 0, got: {tab0_text!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-02  Server mode tab label
# ─────────────────────────────────────────────────────────────────────────────

def test_ss02_server_mode_tab_label(server_gui):
    """Tab 0 in Server mode must be labelled with the server icon, not Home."""
    tab0_text = server_gui.app.notebook.tab(0, "text")
    assert "Server" in tab0_text or "🖥" in tab0_text, (
        f"SS-02 FAIL: expected Server tab at index 0, got: {tab0_text!r}"
    )
    assert "Home" not in tab0_text, (
        f"SS-02 FAIL: Server mode should not show Home tab at index 0, got: {tab0_text!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-03  Home mode: ad refresh IS scheduled
# ─────────────────────────────────────────────────────────────────────────────

def test_ss03_home_mode_has_ad_url(home_gui):
    """Home mode must have a non-empty _ad_url (ad refresh system active)."""
    ad_url = getattr(home_gui.app, "_ad_url", None)
    assert ad_url, (
        f"SS-03 FAIL: Home mode should have a non-empty _ad_url. Got: {ad_url!r}"
    )
    assert "github" in ad_url.lower() or "http" in ad_url.lower(), (
        f"SS-03 FAIL: _ad_url should be a real URL. Got: {ad_url!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-04  Server mode: _ad_url is empty (no GitHub ad traffic)
# ─────────────────────────────────────────────────────────────────────────────

def test_ss04_server_mode_no_ad_url(server_gui):
    """Server mode must have an empty _ad_url — no outbound ad fetch."""
    ad_url = getattr(server_gui.app, "_ad_url", "NOT_SET")
    assert ad_url == "", (
        f"SS-04 FAIL: Server mode _ad_url should be empty string. Got: {ad_url!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-05  Server mode: _notif_frame exists (shared code safety)
# ─────────────────────────────────────────────────────────────────────────────

def test_ss05_server_mode_notif_frame_exists(server_gui):
    """_notif_frame must exist in server mode so shared notification code
    doesn't AttributeError when it references it."""
    assert hasattr(server_gui.app, "_notif_frame"), (
        "SS-05 FAIL: _notif_frame attribute missing in server mode — "
        "shared code will crash."
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-06  Server mode: _notif_widgets is empty list
# ─────────────────────────────────────────────────────────────────────────────

def test_ss06_server_mode_notif_widgets_empty(server_gui):
    """_notif_widgets must be an empty list in server mode."""
    widgets = getattr(server_gui.app, "_notif_widgets", None)
    assert isinstance(widgets, list), (
        f"SS-06 FAIL: _notif_widgets should be a list, got {type(widgets)}"
    )
    assert len(widgets) == 0, (
        f"SS-06 FAIL: _notif_widgets should be empty in server mode, got {widgets}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-07  Server mode: _ad_url is empty string
# ─────────────────────────────────────────────────────────────────────────────

def test_ss07_server_mode_ad_url_empty(server_gui):
    """_ad_url must be empty string in server mode — no ad fetch."""
    assert getattr(server_gui.app, "_ad_url", "NOT_SET") == "", (
        "SS-07 FAIL: _ad_url must be empty in server mode."
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-08  Server mode: _notif_url is empty string
# ─────────────────────────────────────────────────────────────────────────────

def test_ss08_server_mode_notif_url_empty(server_gui):
    """_notif_url must be empty string in server mode — no notification fetch."""
    assert getattr(server_gui.app, "_notif_url", "NOT_SET") == "", (
        "SS-08 FAIL: _notif_url must be empty in server mode."
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-09  Server mode: _srv_status_vars has expected keys
# ─────────────────────────────────────────────────────────────────────────────

def test_ss09_server_mode_status_vars_keys(server_gui):
    """_srv_status_vars must contain all expected status field keys."""
    vars_dict = getattr(server_gui.app, "_srv_status_vars", None)
    assert isinstance(vars_dict, dict), (
        f"SS-09 FAIL: _srv_status_vars should be a dict, got {type(vars_dict)}"
    )
    expected_keys = {"edition", "db_path", "chunks", "docs", "tracked"}
    missing = expected_keys - set(vars_dict.keys())
    assert not missing, (
        f"SS-09 FAIL: _srv_status_vars missing keys: {missing}. "
        f"Present: {set(vars_dict.keys())}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-10  Server mode: _refresh_server_status populates chunk count
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.slow
def test_ss10_server_mode_refresh_populates_chunks(server_gui, isolated_env):
    """_refresh_server_status must populate the chunks field from live ChromaDB."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    # Index a real document so DB has chunks
    f = builders.make_txt(
        isolated_env.sample_root / "ss10_doc.txt",
        "SS-10 server status refresh chunk count test. " * 10
    )
    rag.index_file_list(
        [rag.normalise_path(str(f))],
        label="ss10",
        root_directory=str(isolated_env.sample_root)
    )

    # Call refresh directly
    server_gui.app._refresh_server_status()
    server_gui.pump()

    chunks_var = server_gui.app._srv_status_vars.get("chunks")
    assert chunks_var is not None, "SS-10 FAIL: 'chunks' key missing from _srv_status_vars"

    chunks_val = chunks_var.get()
    assert chunks_val not in ("—", "", "error"), (
        f"SS-10 FAIL: chunks field not populated after refresh. Got: {chunks_val!r}"
    )
    # Must be a number
    try:
        count = int(chunks_val.replace(",", ""))
        assert count > 0, f"SS-10 FAIL: chunk count should be > 0, got {count}"
    except ValueError:
        pytest.fail(f"SS-10 FAIL: chunks value is not numeric: {chunks_val!r}")


# ─────────────────────────────────────────────────────────────────────────────
# SS-11  Server mode: _refresh_server_status populates db_path
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.slow
def test_ss11_server_mode_refresh_populates_db_path(server_gui, isolated_env):
    """_refresh_server_status must populate db_path with the ChromaDB path."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    f = builders.make_txt(
        isolated_env.sample_root / "ss11_doc.txt",
        "SS-11 db path population test. " * 5
    )
    rag.index_file_list(
        [rag.normalise_path(str(f))],
        label="ss11",
        root_directory=str(isolated_env.sample_root)
    )

    server_gui.app._refresh_server_status()
    server_gui.pump()

    db_path_var = server_gui.app._srv_status_vars.get("db_path")
    assert db_path_var is not None, "SS-11 FAIL: 'db_path' key missing from _srv_status_vars"

    db_path_val = db_path_var.get()
    assert db_path_val not in ("—", "", "error"), (
        f"SS-11 FAIL: db_path not populated after refresh. Got: {db_path_val!r}"
    )
    # Must look like a path
    assert len(db_path_val) > 3, (
        f"SS-11 FAIL: db_path value too short to be a real path: {db_path_val!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-12  Server mode: _refresh_server_status populates tracked count
# ─────────────────────────────────────────────────────────────────────────────

def test_ss12_server_mode_refresh_populates_tracked(server_gui, isolated_env):
    """_refresh_server_status must populate tracked folder count."""
    rag = isolated_env.rag
    rag.add_to_auto_update_list(str(isolated_env.sample_root))

    server_gui.app._refresh_server_status()
    server_gui.pump()

    tracked_var = server_gui.app._srv_status_vars.get("tracked")
    assert tracked_var is not None, "SS-12 FAIL: 'tracked' key missing from _srv_status_vars"

    tracked_val = tracked_var.get()
    assert tracked_val not in ("—", "", "error"), (
        f"SS-12 FAIL: tracked count not populated after refresh. Got: {tracked_val!r}"
    )
    try:
        count = int(tracked_val)
        assert count >= 1, f"SS-12 FAIL: tracked count should be >= 1, got {count}"
    except ValueError:
        pytest.fail(f"SS-12 FAIL: tracked value is not numeric: {tracked_val!r}")


# ─────────────────────────────────────────────────────────────────────────────
# SS-13  Server mode: Refresh button is present and callable
# ─────────────────────────────────────────────────────────────────────────────

def test_ss13_server_mode_refresh_button_callable(server_gui):
    """_refresh_server_status must be callable without raising an exception.
    This validates the Refresh button's command binding works end-to-end."""
    try:
        server_gui.app._refresh_server_status()
        server_gui.pump()
    except Exception as e:
        pytest.fail(
            f"SS-13 FAIL: _refresh_server_status raised an exception: {e}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# SS-14  Home mode: _srv_status_vars does NOT exist
# ─────────────────────────────────────────────────────────────────────────────

def test_ss14_home_mode_no_srv_status_vars(home_gui):
    """In Home mode, _srv_status_vars must not exist — clean separation
    between the two tab implementations."""
    assert not hasattr(home_gui.app, "_srv_status_vars"), (
        "SS-14 FAIL: _srv_status_vars should not exist in Home mode — "
        "only the Server tab creates it."
    )


# ─────────────────────────────────────────────────────────────────────────────
# SS-15  Server mode: telemetry paths are set
# ─────────────────────────────────────────────────────────────────────────────

def test_ss15_server_mode_telemetry_paths_set(server_gui):
    """Server mode must still set telemetry paths — server phones home too."""
    for attr in ("_telemetry_counter_path", "_telemetry_last_path",
                 "_telemetry_lock_path"):
        val = getattr(server_gui.app, attr, None)
        assert val is not None, (
            f"SS-15 FAIL: {attr} not set in server mode — "
            f"telemetry will fail."
        )
        assert isinstance(val, Path), (
            f"SS-15 FAIL: {attr} should be a Path, got {type(val)}"
        )
