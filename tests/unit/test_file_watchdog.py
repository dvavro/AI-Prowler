"""
tests/unit/test_file_watchdog.py
=================================
Automated tests for the AI-Prowler File Watchdog daemon (file_watchdog.py).

Test plan IDs (WD-*)
---------------------
Unit — daemon internals (no real filesystem events, no real ChromaDB):
  WD-01  _should_skip_always — tmp/part/crdownload/swp extensions are skipped
  WD-02  _should_skip_always — Office lock files (~$) skipped
  WD-03  _should_skip_always — LibreOffice lock files (.~lock.) skipped
  WD-04  _should_skip_always — desktop.ini skipped
  WD-05  _should_skip_always — $RECYCLE.BIN paths skipped
  WD-06  _should_skip_always — normal supported extensions are NOT skipped

Smart Scan parity:
  WD-07  _smart_scan_allows — .txt/.pdf/.docx pass the Smart Scan filter
  WD-08  _smart_scan_allows — .exe/.mp3/.zip are rejected by Smart Scan filter
  WD-09  _smart_scan_allows — .bakN backup files rejected by is_backup_filename
  WD-10  _smart_scan_allows — unknown extension (.xyz) rejected (not in SUPPORTED)
  WD-11  _is_skip_dir — .git/__pycache__/node_modules are SKIP_DIRECTORIES
  WD-12  _is_skip_dir — a normal user folder is NOT a skip dir

Tracked dirs:
  WD-13  _load_tracked_dirs — returns empty list when JSON missing
  WD-14  _load_tracked_dirs — reads directories from valid JSON
  WD-15  _load_tracked_dirs — returns empty list on corrupt JSON
  WD-16  _load_tracked_dirs — returns empty list for empty directories key

Daemon control:
  WD-17  is_running — returns False when PID file is absent
  WD-18  is_running — returns False when PID file has stale/dead PID
  WD-19  is_running — returns True when PID file has a live PID
  WD-20  is_running — removes stale PID file automatically
  WD-21  stop_daemon — returns error when PID file is missing
  WD-22  stop_daemon — calls os.kill with SIGTERM on valid PID

Integration — event -> index pipeline (mocked ChromaDB + index_file_list):
  WD-23  file created event -> queued after Smart Scan pre-filter passes
  WD-24  file modified event -> queued after Smart Scan pre-filter passes
  WD-25  file moved event -> queued on dest_path (not src_path)
  WD-26  directory created event -> queued with __DIR__ prefix
  WD-27  skip-extension file -> NOT queued (Smart Scan pre-filter drops it)
  WD-28  always-skip file (lock/tmp) -> NOT queued
  WD-29  _do_reindex_file -- purges stale chunks before re-indexing
  WD-30  _do_reindex_file -- Smart Scan rejects .exe at index time
  WD-31  _do_reindex_file -- skips gracefully when file disappears before index
  WD-32  _do_index_directory -- uses scan_directory (Smart Scan ON path)
  WD-33  _do_index_directory -- skips gracefully when dir disappears before index

Release gate -- package + installer integration:
  WD-34  watchdog pip package is importable (installed in the environment)
  WD-35  file_watchdog.py is present in the AI-Prowler source directory
  WD-36  requirements.txt contains watchdog entry
  WD-37  AI-Prowler-Setup.iss deploys file_watchdog.py

Run individually:
    tests\\run_tests.bat watchdog
Or via full suite:
    tests\\run_tests.bat
"""
from __future__ import annotations

import json
import os
import signal
import sys
import time
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, ANY

import pytest

# ---- Ensure source root is on sys.path --------------------------------------
_SRC = os.environ.get("AI_PROWLER_SRC")
if _SRC:
    SRC_ROOT = Path(_SRC).resolve()
else:
    SRC_ROOT = Path(__file__).resolve().parent.parent.parent

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


# ---- Session-scoped module import -------------------------------------------
@pytest.fixture(scope="session")
def wd():
    """Import file_watchdog once per session."""
    import file_watchdog as _wd
    return _wd


# ---- Temp PID file ----------------------------------------------------------
@pytest.fixture
def pid_file(tmp_path, wd, monkeypatch):
    fake = tmp_path / "file_watchdog.pid"
    monkeypatch.setattr(wd, "PID_FILE", fake)
    return fake


# ---- Temp tracked-dirs JSON -------------------------------------------------
@pytest.fixture
def tracked_json(tmp_path, wd, monkeypatch):
    fake_json = tmp_path / "auto_update_dirs.json"

    def _load():
        if not fake_json.exists():
            return []
        try:
            data = json.loads(fake_json.read_text(encoding="utf-8"))
            return [str(Path(d)) for d in data.get("directories", [])]
        except Exception:
            return []

    monkeypatch.setattr(wd, "_load_tracked_dirs", _load)
    return fake_json


# ---- Mock rag_preprocessor extension sets -----------------------------------
@pytest.fixture
def mock_rag_sets(wd, monkeypatch):
    """Patch _get_rag_sets with realistic sets — no real rag_preprocessor needed."""
    SKIP_EXT = {
        ".exe", ".dll", ".zip", ".mp3", ".mp4", ".tmp", ".bak",
        ".doc", ".ppt", ".pyc", ".db", ".iso",
    }
    SUPPORTED_EXT = {
        ".txt", ".md", ".pdf", ".docx", ".xlsx", ".pptx", ".csv",
        ".json", ".html", ".py", ".rtf", ".odt",
    }
    SKIP_DIRS = {
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        "build", "dist", "$RECYCLE.BIN",
    }

    monkeypatch.setattr(wd, "_get_rag_sets", lambda: (SKIP_EXT, SUPPORTED_EXT, SKIP_DIRS))

    import re as _re
    _BAK_RE = _re.compile(r'\.bak\d+$', _re.IGNORECASE)

    def _fake_is_backup(f):
        return bool(_BAK_RE.search(f))

    if "rag_preprocessor" in sys.modules:
        monkeypatch.setattr(sys.modules["rag_preprocessor"],
                            "is_backup_filename", _fake_is_backup)

    return SimpleNamespace(
        skip_ext=SKIP_EXT,
        supported_ext=SUPPORTED_EXT,
        skip_dirs=SKIP_DIRS,
        is_backup=_fake_is_backup,
    )


# =============================================================================
# WD-01 to WD-06 -- _should_skip_always
# =============================================================================

class TestShouldSkipAlways:

    def test_WD_01_always_skip_extensions(self, wd):
        """WD-01: Lock/temp extensions always skipped regardless of Smart Scan."""
        for ext in (".tmp", ".part", ".crdownload", ".~lock", ".swp", ".swo"):
            assert wd._should_skip_always(f"C:\\folder\\file{ext}"), ext

    def test_WD_02_office_lock_files(self, wd):
        """WD-02: Office ~$ lock files always skipped."""
        assert wd._should_skip_always("C:\\folder\\~$document.docx")
        assert wd._should_skip_always("C:\\folder\\~$sheet.xlsx")

    def test_WD_03_libreoffice_lock_files(self, wd):
        """WD-03: LibreOffice .~lock.* files always skipped."""
        assert wd._should_skip_always("C:\\folder\\.~lock.doc.odt")

    def test_WD_04_desktop_ini(self, wd):
        """WD-04: desktop.ini always skipped."""
        assert wd._should_skip_always("C:\\folder\\desktop.ini")

    def test_WD_05_recycle_bin(self, wd):
        """WD-05: Paths inside $RECYCLE.BIN always skipped."""
        assert wd._should_skip_always("C:\\$recycle.bin\\file.txt")

    def test_WD_06_normal_files_not_always_skipped(self, wd):
        """WD-06: Normal file types are NOT in the always-skip list."""
        for ext in (".txt", ".pdf", ".docx", ".py", ".md", ".csv", ".xlsx"):
            assert not wd._should_skip_always(f"C:\\folder\\file{ext}"), ext


# =============================================================================
# WD-07 to WD-12 -- Smart Scan filter
# =============================================================================

class TestSmartScanFilter:

    def test_WD_07_supported_extensions_allowed(self, wd, mock_rag_sets):
        """WD-07: SUPPORTED_EXTENSIONS pass _smart_scan_allows."""
        for ext in (".txt", ".pdf", ".docx", ".xlsx", ".csv", ".py", ".md"):
            assert wd._smart_scan_allows(f"C:\\inbox\\file{ext}"), ext

    def test_WD_08_skip_extensions_rejected(self, wd, mock_rag_sets):
        """WD-08: SKIP_EXTENSIONS are rejected by _smart_scan_allows."""
        for ext in (".exe", ".dll", ".zip", ".mp3", ".mp4"):
            assert not wd._smart_scan_allows(f"C:\\inbox\\file{ext}"), ext

    def test_WD_09_bakN_files_rejected(self, wd, mock_rag_sets):
        """WD-09: .bakN backup files rejected by is_backup_filename."""
        for bak in ("rag_gui.py.bak1", "file.bak2", "data.bak10"):
            assert not wd._smart_scan_allows(f"C:\\folder\\{bak}"), bak

    def test_WD_10_unknown_extension_rejected(self, wd, mock_rag_sets):
        """WD-10: Unknown extensions not in SUPPORTED_EXTENSIONS rejected."""
        assert not wd._smart_scan_allows("C:\\folder\\file.xyz")
        assert not wd._smart_scan_allows("C:\\folder\\data.unknown")

    def test_WD_11_skip_directories_detected(self, wd, mock_rag_sets):
        """WD-11: .git, __pycache__, node_modules detected as SKIP_DIRECTORIES."""
        assert wd._is_skip_dir("C:\\project\\.git")
        assert wd._is_skip_dir("C:\\project\\__pycache__")
        assert wd._is_skip_dir("C:\\project\\node_modules")

    def test_WD_12_normal_dir_not_skipped(self, wd, mock_rag_sets):
        """WD-12: Normal user folders are NOT skip dirs."""
        assert not wd._is_skip_dir("C:\\Users\\david\\Documents\\AI-Prowler-Inbox")
        assert not wd._is_skip_dir("C:\\Users\\david\\sales")


# =============================================================================
# WD-13 to WD-16 -- _load_tracked_dirs
# =============================================================================

class TestLoadTrackedDirs:

    def test_WD_13_missing_json_returns_empty(self, tracked_json, wd):
        """WD-13: Missing JSON returns empty list."""
        assert not tracked_json.exists()
        assert wd._load_tracked_dirs() == []

    def test_WD_14_valid_json_returns_dirs(self, tracked_json, wd, tmp_path):
        """WD-14: Valid JSON list returned correctly."""
        dir_a = tmp_path / "sales"
        dir_b = tmp_path / "field"
        dir_a.mkdir()
        dir_b.mkdir()
        tracked_json.write_text(json.dumps({
            "directories": [str(dir_a), str(dir_b)],
        }), encoding="utf-8")
        result = wd._load_tracked_dirs()
        assert len(result) == 2
        assert str(dir_a) in result
        assert str(dir_b) in result

    def test_WD_15_corrupt_json_returns_empty(self, tracked_json, wd):
        """WD-15: Corrupt JSON returns empty list without raising."""
        tracked_json.write_text("{bad json!", encoding="utf-8")
        assert wd._load_tracked_dirs() == []

    def test_WD_16_empty_directories_key(self, tracked_json, wd):
        """WD-16: Empty directories list returns empty list."""
        tracked_json.write_text(json.dumps({"directories": []}), encoding="utf-8")
        assert wd._load_tracked_dirs() == []


# =============================================================================
# WD-17 to WD-22 -- is_running / stop_daemon
# =============================================================================

class TestDaemonControl:

    def test_WD_17_no_pid_file(self, pid_file, wd):
        """WD-17: is_running False when PID file absent."""
        assert not pid_file.exists()
        assert not wd.is_running()

    def test_WD_18_dead_pid(self, pid_file, wd):
        """WD-18: is_running False for non-existent PID."""
        pid_file.write_text("9999999")
        assert not wd.is_running()

    def test_WD_19_live_pid(self, pid_file, wd):
        """WD-19: is_running True for our own PID."""
        pid_file.write_text(str(os.getpid()))
        assert wd.is_running()

    def test_WD_20_stale_pid_file_removed(self, pid_file, wd):
        """WD-20: Stale PID file removed automatically."""
        pid_file.write_text("9999999")
        wd.is_running()
        assert not pid_file.exists()

    def test_WD_21_stop_no_pid_file(self, pid_file, wd):
        """WD-21: stop_daemon returns (False, msg) with no PID file."""
        ok, msg = wd.stop_daemon()
        assert ok is False
        assert "No running watchdog" in msg or "PID" in msg

    def test_WD_22_stop_sends_sigterm(self, pid_file, wd):
        """WD-22: stop_daemon calls os.kill(pid, SIGTERM)."""
        pid_file.write_text("12345")
        with patch("os.kill") as mock_kill:
            ok, msg = wd.stop_daemon()
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)
        assert ok is True
        assert "12345" in msg


# =============================================================================
# WD-23 to WD-28 -- Event handler queuing
# =============================================================================

class TestEventHandlerQueuing:

    @pytest.fixture
    def handler_env(self, wd, mock_rag_sets, monkeypatch):
        fake_pending = {}
        monkeypatch.setattr(wd, "_pending", fake_pending)
        handler = wd._make_handler()

        class FakeEvent:
            def __init__(self, src, is_directory=False, dest=None):
                self.src_path = src
                self.dest_path = dest or src
                self.is_directory = is_directory

        return SimpleNamespace(handler=handler, pending=fake_pending,
                               FakeEvent=FakeEvent, wd=wd)

    def test_WD_23_supported_file_created(self, handler_env):
        """WD-23: Supported file on_created is queued."""
        ev = handler_env.FakeEvent("C:\\inbox\\report.pdf")
        handler_env.handler.on_created(ev)
        assert "C:\\inbox\\report.pdf" in handler_env.pending

    def test_WD_24_supported_file_modified(self, handler_env):
        """WD-24: Supported file on_modified is queued."""
        ev = handler_env.FakeEvent("C:\\inbox\\notes.txt")
        handler_env.handler.on_modified(ev)
        assert "C:\\inbox\\notes.txt" in handler_env.pending

    def test_WD_25_moved_file_queues_dest(self, handler_env):
        """WD-25: on_moved queues dest_path not src_path."""
        ev = handler_env.FakeEvent("C:\\inbox\\tmp.pdf",
                                   dest="C:\\inbox\\final.pdf")
        handler_env.handler.on_moved(ev)
        assert "C:\\inbox\\final.pdf" in handler_env.pending
        assert "C:\\inbox\\tmp.pdf" not in handler_env.pending

    def test_WD_26_directory_created(self, handler_env):
        """WD-26: Directory on_created queued with __DIR__ prefix."""
        ev = handler_env.FakeEvent("C:\\inbox\\new_folder", is_directory=True)
        handler_env.handler.on_created(ev)
        assert "__DIR__C:\\inbox\\new_folder" in handler_env.pending

    def test_WD_27_skip_ext_not_queued(self, handler_env):
        """WD-27: Smart-Scan-skipped extensions never queued."""
        for f in ("virus.exe", "archive.zip", "song.mp3", "film.mp4"):
            handler_env.handler.on_created(
                handler_env.FakeEvent(f"C:\\inbox\\{f}"))
        assert handler_env.pending == {}

    def test_WD_28_always_skip_not_queued(self, handler_env):
        """WD-28: Always-skip lock/temp files never queued."""
        for f in ("upload.tmp", "~$report.docx", "desktop.ini", "file.swp"):
            handler_env.handler.on_created(
                handler_env.FakeEvent(f"C:\\inbox\\{f}"))
        assert handler_env.pending == {}


# =============================================================================
# WD-29 to WD-33 -- Index pipeline
# =============================================================================

class TestIndexPipeline:

    @pytest.fixture
    def index_env(self, tmp_path, wd, mock_rag_sets, monkeypatch):
        test_file = tmp_path / "invoice.txt"
        test_file.write_text("Invoice #1001 $500", encoding="utf-8")

        test_dir = tmp_path / "field_docs"
        test_dir.mkdir()
        (test_dir / "job_notes.txt").write_text("Window cleaning notes", encoding="utf-8")
        (test_dir / "photo.mp3").write_text("fake audio bytes", encoding="utf-8")

        def _fake_scan(path, recursive=True):
            return {
                "to_index": [(str(test_dir / "job_notes.txt"), ".txt")],
                "skipped_bin": [(str(test_dir / "photo.mp3"), ".mp3")],
                "unsupported": [],
            }

        mock_rp = MagicMock()
        mock_rp.normalise_path.side_effect = lambda p: p.replace("/", "\\")
        mock_rp.index_file_list.return_value = {"chunks": 3}
        mock_rp.scan_directory.side_effect = _fake_scan
        mock_rp.is_backup_filename.return_value = False
        mock_rp.COLLECTION_NAME = "documents"
        mock_rp.SKIP_EXTENSIONS = mock_rag_sets.skip_ext
        mock_rp.SUPPORTED_EXTENSIONS = mock_rag_sets.supported_ext
        mock_rp.SKIP_DIRECTORIES = mock_rag_sets.skip_dirs

        mock_coll = MagicMock()
        mock_client = MagicMock()
        mock_client.get_or_create_collection.return_value = mock_coll
        mock_rp.get_chroma_client.return_value = (mock_client, MagicMock())

        monkeypatch.setitem(sys.modules, "rag_preprocessor", mock_rp)
        monkeypatch.setattr(wd, "_rag_preprocessor", mock_rp)

        return SimpleNamespace(wd=wd, test_file=test_file, test_dir=test_dir,
                               mock_rp=mock_rp, mock_coll=mock_coll)

    def test_WD_29_reindex_purges_then_indexes(self, index_env):
        """WD-29: _do_reindex_file purges stale chunks then calls index_file_list."""
        index_env.wd._do_reindex_file(str(index_env.test_file))
        index_env.mock_coll.delete.assert_called_once()
        index_env.mock_rp.index_file_list.assert_called_once()
        files = index_env.mock_rp.index_file_list.call_args[0][0]
        assert any("invoice.txt" in str(p) for p in files)

    def test_WD_30_reindex_rejects_exe(self, index_env):
        """WD-30: _do_reindex_file skips .exe (Smart Scan rejects it)."""
        exe = index_env.test_file.parent / "prog.exe"
        exe.write_text("MZ stub", encoding="utf-8")
        index_env.wd._do_reindex_file(str(exe))
        index_env.mock_rp.index_file_list.assert_not_called()

    def test_WD_31_reindex_missing_file(self, index_env):
        """WD-31: _do_reindex_file graceful when file gone before index."""
        index_env.wd._do_reindex_file("C:\\ghost\\missing.txt")
        index_env.mock_rp.index_file_list.assert_not_called()

    def test_WD_32_index_dir_uses_scan_directory(self, index_env):
        """WD-32: _do_index_directory calls scan_directory (Smart Scan ON path)."""
        index_env.wd._do_index_directory(str(index_env.test_dir))
        index_env.mock_rp.scan_directory.assert_called_once()
        index_env.mock_rp.index_file_list.assert_called_once()
        files = index_env.mock_rp.index_file_list.call_args[0][0]
        assert any("job_notes.txt" in str(p) for p in files)
        assert not any("photo.mp3" in str(p) for p in files)

    def test_WD_33_index_dir_missing(self, index_env):
        """WD-33: _do_index_directory graceful when dir gone before index."""
        index_env.wd._do_index_directory("C:\\ghost\\missing_dir")
        index_env.mock_rp.index_file_list.assert_not_called()


# =============================================================================
# WD-38 to WD-46 -- Server-mode collection awareness
#
# HISTORY: originally added 2026-07-13 after the Christina incident (the
# watchdog always indexed into the single "documents" collection, silently
# ignoring server-mode per-user/per-scope collections). The fix made
# _do_reindex_file/_do_index_directory consult collection_map via
# _resolve_unattended_collection before indexing, skipping unmatched paths
# rather than guessing.
#
# SUPERSEDED 2026-07-16 (SCOPE_SIMPLIFICATION_SPEC.md section 3.7, Phase 7
# cutover): that consultation has been REMOVED from both functions. Not a
# regression -- the incident it guarded against ("lands in the WRONG
# collection") is structurally impossible now that there is only one
# collection. Every file, matched scope_map entry or not, is indexed
# normally; access control is enforced by "scope" chunk metadata at query
# time instead of by which physical collection a file's chunks live in.
# _resolve_unattended_collection() itself is left in file_watchdog.py as
# dead code for now, pending the final Phase 7 cleanup pass across the
# whole codebase -- it is no longer called from anywhere.
# =============================================================================

class TestServerModeCollectionAwareness:

    @pytest.fixture
    def server_env(self, tmp_path, wd, mock_rag_sets, monkeypatch):
        """Same shape as index_env, but with ~/.ai-prowler/users.json
        present -- historically put the watchdog into "server mode"; kept
        for the tests that confirm users.json presence/absence no longer
        changes anything about how these functions behave."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        test_file = tmp_path / "personal" / "christina" / "notes.docx"
        test_file.parent.mkdir(parents=True)
        test_file.write_text("meeting notes", encoding="utf-8")

        mock_rp = MagicMock()
        mock_rp.normalise_path.side_effect = lambda p: p.replace("/", "\\")
        mock_rp.index_file_list.return_value = {"chunks": 2}
        mock_rp.is_backup_filename.return_value = False
        mock_rp.COLLECTION_NAME = "documents"
        mock_rp.SKIP_EXTENSIONS = mock_rag_sets.skip_ext
        mock_rp.SUPPORTED_EXTENSIONS = mock_rag_sets.supported_ext
        mock_rp.SKIP_DIRECTORIES = mock_rag_sets.skip_dirs

        mock_coll = MagicMock()
        mock_client = MagicMock()
        mock_client.get_or_create_collection.return_value = mock_coll
        mock_rp.get_chroma_client.return_value = (mock_client, MagicMock())

        monkeypatch.setitem(sys.modules, "rag_preprocessor", mock_rp)
        monkeypatch.setattr(wd, "_rag_preprocessor", mock_rp)

        def _write_users_json(rules, users=None):
            data = {
                "collection_map": {"rules": rules},
                "users": users or {
                    "tok-christina": {"id": "christina01", "role": "staff"},
                    "tok-david": {"id": "david-owner", "role": "owner"},
                },
            }
            users_dir = tmp_path / ".ai-prowler"
            users_dir.mkdir(parents=True, exist_ok=True)
            (users_dir / "users.json").write_text(
                json.dumps(data), encoding="utf-8")

        return SimpleNamespace(
            wd=wd, test_file=test_file, mock_rp=mock_rp, mock_coll=mock_coll,
            mock_client=mock_client, write_users_json=_write_users_json,
            tmp_path=tmp_path,
        )

    def test_WD_38_no_users_json_indexes_into_single_collection(self, server_env):
        """WD-38: no ~/.ai-prowler/users.json at all -- single "documents"
        collection, no collection_resolver, unchanged."""
        server_env.wd._do_reindex_file(str(server_env.test_file))
        server_env.mock_rp.index_file_list.assert_called_once()
        _, kwargs = server_env.mock_rp.index_file_list.call_args
        assert "collection_resolver" not in kwargs
        server_env.mock_client.get_or_create_collection.assert_called_with(
            name="documents", embedding_function=ANY)

    def test_WD_39_matched_rule_no_longer_changes_anything(self, server_env):
        """WD-39: the old Christina scenario -- a file with a matching
        collection_map rule present -- now indexes exactly like an
        unmatched one. No collection_resolver is ever built or passed."""
        server_env.write_users_json(rules=[
            {"prefix": str(server_env.test_file.parent).replace("\\", "/"),
             "collection": "user:christina01"},
        ])
        server_env.wd._do_reindex_file(str(server_env.test_file))

        server_env.mock_rp.index_file_list.assert_called_once()
        _, kwargs = server_env.mock_rp.index_file_list.call_args
        assert "collection_resolver" not in kwargs
        server_env.mock_client.get_or_create_collection.assert_called_with(
            name="documents", embedding_function=ANY)

    def test_WD_40_deleted_user_rule_no_longer_matters(self, server_env):
        """WD-40: a rule pointing at a user who no longer exists used to be
        specifically detected and skipped. That detection is gone -- the
        file indexes normally regardless, since collection_map is never
        consulted by this function anymore."""
        server_env.write_users_json(
            rules=[{"prefix": str(server_env.test_file.parent).replace("\\", "/"),
                   "collection": "user:christina01"}],
            users={"tok-david": {"id": "david-owner", "role": "owner"}},
        )
        server_env.wd._do_reindex_file(str(server_env.test_file))
        server_env.mock_rp.index_file_list.assert_called_once()

    def test_WD_41_unmatched_path_is_indexed_never_skipped(self, server_env):
        """WD-41: direct product decision (SCOPE_SIMPLIFICATION_SPEC.md
        section 3.4) -- an unmatched path is never skipped anymore. This
        is the intentional opposite of the pre-2026-07-16 behavior."""
        server_env.write_users_json(rules=[
            {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"},
        ])
        server_env.wd._do_reindex_file(str(server_env.test_file))
        server_env.mock_rp.index_file_list.assert_called_once()

    def test_WD_42_default_collection_key_is_irrelevant_now(self, server_env):
        """WD-42: a configured default_collection has no effect either way
        -- collection_map isn't read by this function at all anymore."""
        users_dir = server_env.tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "collection_map": {
                "rules": [{"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}],
                "default_collection": "shared",
            },
            "users": {"tok-david": {"id": "david-owner", "role": "owner"}},
        }
        (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")

        server_env.wd._do_reindex_file(str(server_env.test_file))
        server_env.mock_rp.index_file_list.assert_called_once()

    def test_WD_43_team_scope_rule_also_no_longer_changes_anything(self, server_env):
        """WD-43: a non-personal (team scope) rule -- same as WD-39, now a
        no-op as far as routing is concerned."""
        scope_dir = server_env.tmp_path / "CompanyDocs" / "Sales"
        scope_dir.mkdir(parents=True)
        sales_file = scope_dir / "q3.pdf"
        sales_file.write_text("deal terms", encoding="utf-8")

        server_env.write_users_json(rules=[
            {"prefix": str(scope_dir).replace("\\", "/"), "collection": "role:sales"},
        ])
        server_env.wd._do_reindex_file(str(sales_file))

        _, kwargs = server_env.mock_rp.index_file_list.call_args
        assert "collection_resolver" not in kwargs

    def test_WD_44_corrupt_users_json_still_does_not_crash(self, server_env):
        """WD-44: a corrupt users.json must not crash the watchdog -- true
        trivially now (the file is never read by this path), but worth
        keeping as a regression guard."""
        users_dir = server_env.tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True, exist_ok=True)
        (users_dir / "users.json").write_text("{not valid json", encoding="utf-8")

        server_env.wd._do_reindex_file(str(server_env.test_file))
        server_env.mock_rp.index_file_list.assert_called_once()
        _, kwargs = server_env.mock_rp.index_file_list.call_args
        assert "collection_resolver" not in kwargs

    def test_WD_45_index_directory_never_builds_a_resolver(self, server_env):
        """WD-45: _do_index_directory (newly-dropped folder) -- same
        removal as _do_reindex_file, confirmed for the directory-drop path."""
        server_env.mock_rp.scan_directory.return_value = {
            "to_index": [(str(server_env.test_file), ".docx")],
            "skipped_bin": [], "unsupported": [],
        }
        server_env.write_users_json(rules=[
            {"prefix": str(server_env.test_file.parent).replace("\\", "/"),
             "collection": "user:christina01"},
        ])
        server_env.wd._do_index_directory(str(server_env.test_file.parent))

        server_env.mock_rp.index_file_list.assert_called_once()
        _, kwargs = server_env.mock_rp.index_file_list.call_args
        assert "collection_resolver" not in kwargs

    def test_WD_46_index_directory_unmatched_is_indexed_never_skipped(self, server_env):
        """WD-46: same default-to-indexed (never skipped) behavior for the
        directory-drop path as WD-41."""
        server_env.mock_rp.scan_directory.return_value = {
            "to_index": [(str(server_env.test_file), ".docx")],
            "skipped_bin": [], "unsupported": [],
        }
        server_env.write_users_json(rules=[
            {"prefix": "C:/SomewhereElse", "collection": "role:sales"},
        ])
        server_env.wd._do_index_directory(str(server_env.test_file.parent))
        server_env.mock_rp.index_file_list.assert_called_once()
        server_env.mock_rp.scan_directory.assert_called_once()


# =============================================================================
# WD-34 to WD-37 -- Release gate
# =============================================================================

class TestReleaseGate:

    def test_WD_34_watchdog_importable(self):
        """WD-34: watchdog pip package installed and importable."""
        try:
            import watchdog           # noqa: F401
            import watchdog.observers # noqa: F401
            import watchdog.events    # noqa: F401
        except ImportError as exc:
            pytest.fail(f"watchdog not installed: {exc}\nFix: pip install watchdog>=4.0.0")

    def test_WD_35_script_exists(self):
        """WD-35: file_watchdog.py present in source directory."""
        assert (SRC_ROOT / "file_watchdog.py").exists(), \
            f"file_watchdog.py not found at {SRC_ROOT}"

    def test_WD_36_requirements_contains_watchdog(self):
        """WD-36: requirements.txt lists watchdog."""
        req = SRC_ROOT / "requirements.txt"
        assert req.exists()
        assert "watchdog" in req.read_text(encoding="utf-8").lower(), \
            "watchdog missing from requirements.txt"

    def test_WD_37_iss_deploys_watchdog(self):
        """WD-37: AI-Prowler-Setup.iss deploys file_watchdog.py."""
        iss = SRC_ROOT / "AI-Prowler-Setup.iss"
        assert iss.exists()
        assert "file_watchdog.py" in iss.read_text(encoding="utf-8"), \
            "file_watchdog.py not in AI-Prowler-Setup.iss [Files] section"
