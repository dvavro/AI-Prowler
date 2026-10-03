"""
AI-Prowler 6.0.0 — pytest harness conftest.py
=============================================

Shared fixtures used by every functional test.

Design goals
------------
1. **Total isolation per test** — every test gets a brand-new ChromaDB,
   a brand-new tracking JSON, and a brand-new auto-update list. Tests
   never see each other's state.

2. **No cross-talk with the user's real install** — the user keeps their
   real database at ~/AI-Prowler/rag_database and ~/.rag_file_tracking.json.
   We MUST NOT touch those. Every fixture redirects the module-level
   globals to per-test temp paths BEFORE any indexing runs.

3. **Cache invalidation** — rag_preprocessor caches the ChromaDB client
   at module level (_chroma_client_cache). Pointing CHROMA_DB_PATH at a
   new temp dir is not enough; we have to call invalidate_chroma_cache()
   too. Otherwise test #2 reuses test #1's client and writes to the wrong
   directory.

4. **Don't load the embedding model 50 times** — it takes ~3-8 seconds.
   We accept this cost once per test in exchange for total isolation,
   but if the test suite gets too slow we can scope the heavy fixture
   to "module" instead of "function" and reset the *collection* between
   tests rather than the whole client.
"""
from __future__ import annotations

import json
import os
import gc
import shutil
import sys

# ── Raise the Windows CRT stdio handle limit ─────────────────────────────────
# Python on Windows defaults to 512 open file descriptors (the CRT _setmaxstdio
# default). A 1,400+ test suite that creates a ChromaDB PersistentClient per
# test exhausts this rapidly — leading to OSError [Errno 24] "Too many open
# files" late in the run even after the per-test invalidate_chroma_cache()
# teardown. Raising to 2048 (the CRT maximum) gives the GC headroom to reclaim
# handles before the limit is hit. This is a no-op on non-Windows platforms.
try:
    import ctypes as _ctypes
    _crt = _ctypes.cdll.msvcrt
    _new_limit = _crt._setmaxstdio(2048)
    print(f"\n[conftest] _setmaxstdio(2048) returned {_new_limit} "
          f"(2048=success, negative=error)", flush=True)
except (AttributeError, OSError) as _e:
    print(f"\n[conftest] _setmaxstdio failed: {_e}", flush=True)
from pathlib import Path

import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Path setup: tell Python where rag_preprocessor.py lives.
#
# The user's repo layout is expected to be:
#
#   AI-Prowler/
#   ├── rag_preprocessor.py
#   ├── ai_prowler_mcp.py
#   ├── rag_gui.py
#   └── tests/
#       ├── conftest.py          <-- you are here
#       ├── unit/
#       └── ...
#
# So tests/.. is the source root. If your layout differs, set
# AI_PROWLER_SRC=/path/to/source in your environment before running pytest.
# ──────────────────────────────────────────────────────────────────────────────
_SRC = os.environ.get("AI_PROWLER_SRC")
if _SRC:
    SRC_ROOT = Path(_SRC).resolve()
else:
    SRC_ROOT = Path(__file__).resolve().parent.parent

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


# ──────────────────────────────────────────────────────────────────────────────
# Windows console-signal guard (2026-10-01).
# On Windows, os.kill(pid, 0) and os.kill(pid, 1) do NOT probe a process: 0 is
# CTRL_C_EVENT and 1 is CTRL_BREAK_EVENT, sent to the whole console. One test
# doing that (WCS-01) killed run_tests.bat's PowerShell Tee-Object pipe, so full
# runs never showed pytest's end summary of failures and warnings. Any test that
# tries it now fails loudly instead of silently cutting off the run. Tests that
# mock os.kill (patch("os.kill")) are unaffected.
# ──────────────────────────────────────────────────────────────────────────────
if sys.platform == "win32":
    _real_os_kill = os.kill

    def _guarded_os_kill(pid, sig):
        if sig in (0, 1):
            raise RuntimeError(
                f"Test tried os.kill({pid}, {sig}) — on Windows that sends "
                f"{'Ctrl+C' if sig == 0 else 'Ctrl+Break'} to the console and kills "
                f"run_tests.bat's output. Mock os.kill instead.")
        return _real_os_kill(pid, sig)

    os.kill = _guarded_os_kill


# ──────────────────────────────────────────────────────────────────────────────
# Module import — done lazily inside a fixture so that ANY pytest collection
# error (e.g. missing chromadb) shows up as a fixture failure for one test
# rather than a collection failure for the whole suite.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def rag():
    """Import rag_preprocessor exactly once per test session and return the module.

    Importing it has side effects (env vars, stdout wrapping, suppressing
    warnings) so we do it in a fixture rather than at the top of conftest —
    this keeps the import errors local to the tests that actually need it.
    """
    import rag_preprocessor as rag_module
    return rag_module


# ──────────────────────────────────────────────────────────────────────────────
# Per-test isolation fixture.
#
# This is the workhorse. Every functional test depends on it (directly or
# transitively). It:
#
#   1. Creates four temp paths (db dir, tracking JSON, auto-update JSON,
#      email index JSON) under pytest's tmp_path.
#   2. Saves the rag module's current globals so we can restore them.
#   3. Patches the globals to point at the temp paths.
#   4. Invalidates the ChromaDB client cache so the next get_chroma_client()
#      call opens a fresh client on the new path.
#   5. Yields the temp paths to the test.
#   6. On teardown: restores globals, invalidates cache again so the next
#      test starts clean.
#
# The reason we restore globals (rather than just leaving the temp ones in
# place) is so a developer running pytest can also have a normal AI-Prowler
# install on the same machine without it getting clobbered.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def isolated_env(tmp_path, rag, monkeypatch):
    """Yield a namespace containing per-test paths; auto-restores on teardown."""
    db_dir       = tmp_path / "chroma_db"
    tracking_db  = tmp_path / "tracking.json"
    auto_update  = tmp_path / "auto_update.json"
    email_index  = tmp_path / "email_index.json"
    sample_root  = tmp_path / "samples"

    db_dir.mkdir()
    sample_root.mkdir()
    # Touch the JSON files as empty so load_*_database() returns {} cleanly
    tracking_db.write_text("{}", encoding="utf-8")
    email_index.write_text("{}", encoding="utf-8")
    auto_update.write_text(json.dumps({"directories": []}), encoding="utf-8")

    # Patch module globals — monkeypatch handles restore for us.
    # NOTE: we patch by attribute name on the module, NOT by re-importing,
    # because the rag module's own functions reference these as module-scope
    # globals (not via 'from module import X' aliases).
    monkeypatch.setattr(rag, "CHROMA_DB_PATH", str(db_dir))
    monkeypatch.setattr(rag, "TRACKING_DB",    tracking_db)
    monkeypatch.setattr(rag, "AUTO_UPDATE_LIST", auto_update)
    monkeypatch.setattr(rag, "EMAIL_INDEX_DB", email_index)

    # v9.0.1: default the ChromaDB cold-init settle delay (see
    # get_chroma_client()'s docstring) to 0 for every isolated_env-backed
    # test. isolated_env is the thing that forces a fresh cold client init
    # per test via invalidate_chroma_cache() below, so without this every
    # test in the suite would pay the real ~1.5s delay on top of the model
    # load it already pays. tests/unit/test_chroma_cold_init_settle.py
    # overrides this back to a small nonzero value in its own tests to
    # actually exercise the delay.
    monkeypatch.setattr(rag, "_CHROMA_COLD_INIT_SETTLE_SECONDS", 0)

    # Cache invalidation — must run AFTER the patch so the next call rebuilds
    # against the new path.
    rag.invalidate_chroma_cache()

    # ── Production-database guard ─────────────────────────────────────────────
    # Record the real production database path and its mtime BEFORE the test
    # runs so teardown can assert it was never written to.  This turns a silent
    # corruption event into a loud, immediately-actionable test failure.
    _real_db_path = Path.home() / "AI-Prowler" / "rag_database"
    _real_db_mtime_before: float | None = None
    if _real_db_path.exists():
        try:
            _real_db_mtime_before = _real_db_path.stat().st_mtime
        except OSError:
            pass

    # Record every database folder THIS test process opens (2026-10-01).
    # The mtime check alone can't tell who changed the folder: the live
    # AI-Prowler on the same PC (file watcher, MCP re-index) writes to it too,
    # and whichever test happened to be running got blamed. rag_preprocessor
    # opens ChromaDB in exactly one place — chromadb.PersistentClient(path=...)
    # — so wrapping it shows whether this test really touched the real database.
    _opened_db_paths: list[str] = []
    try:
        import chromadb as _chromadb
        _real_persistent_client = _chromadb.PersistentClient

        def _recording_persistent_client(*args, **kwargs):
            _opened_db_paths.append(str(kwargs.get("path", args[0] if args else "")))
            return _real_persistent_client(*args, **kwargs)

        monkeypatch.setattr(_chromadb, "PersistentClient", _recording_persistent_client)
    except Exception:
        pass   # chromadb missing — the rag fixture reports that on its own

    class Env:
        pass
    env = Env()
    env.db_dir       = db_dir
    env.tracking_db  = tracking_db
    env.auto_update  = auto_update
    env.email_index  = email_index
    env.sample_root  = sample_root
    env.tmp_path     = tmp_path
    env.rag          = rag

    yield env

    # Teardown — invalidate the cache one more time so the NEXT test gets a
    # fresh client, not the one we just opened against the now-deleted tmp dir.
    # invalidate_chroma_cache() now also calls clear_system_cache() + gc.collect()
    # internally to release Rust-side SQLite/HNSW file handles promptly.
    # Without this, 1,400+ tests accumulate orphaned PersistentClient objects
    # faster than the GC can reclaim them, exhausting the OS file-handle limit
    # (Errno 24 "Too many open files") late in the full suite run.
    rag.invalidate_chroma_cache()
    # Belt-and-suspenders: run gc.collect() three times — each pass may
    # free more cyclic garbage that the previous pass made unreachable.
    # This is especially important for ChromaDB's Rust-backed PersistentClient
    # which holds ~35 kernel handles that only close when Python GC drops the
    # object. Three generations ensures even long-lived cyclic structures
    # are collected before the next test creates a new client.
    gc.collect()
    gc.collect()
    gc.collect()

    # ── Post-test production-database integrity check ─────────────────────────
    # If the real production database directory was modified during this test,
    # something bypassed the isolation sandbox and wrote to the live install.
    # Fail loudly NOW (at teardown) so pytest identifies the exact test
    # responsible, rather than letting the corruption silently accumulate and
    # only surface as a crash when the user next clicks Reindex in the GUI.
    if _real_db_mtime_before is not None and _real_db_path.exists():
        try:
            _real_db_mtime_after = _real_db_path.stat().st_mtime
        except OSError:
            _real_db_mtime_after = _real_db_mtime_before   # can't stat — don't crash teardown
        if _real_db_mtime_after != _real_db_mtime_before:
            def _is_real(p):
                try:
                    return Path(p).resolve() == _real_db_path.resolve()
                except Exception:
                    return False
            _this_test_opened_real = (any(_is_real(p) for p in _opened_db_paths)
                                      or _is_real(rag.CHROMA_DB_PATH))
            assert not _this_test_opened_real, (
                f"\n\n*** PRODUCTION DATABASE CORRUPTED BY THIS TEST ***\n"
                f"    Path:   {_real_db_path}\n"
                f"    Before: {_real_db_mtime_before}\n"
                f"    After:  {_real_db_mtime_after}\n"
                f"This test opened the real ~/AI-Prowler/rag_database and it changed.\n"
                f"Fix: ensure the test uses `isolated_env` and that\n"
                f"rag_preprocessor.CHROMA_DB_PATH was patched before any ChromaDB call,\n"
                f"OR ensure AIPROWLER_TEST_STATE_DIR is set in the environment\n"
                f"(run_tests.bat sets this automatically)."
            )
            # This test never opened the real database, so another program —
            # normally the AI-Prowler running on this PC (file watcher, an MCP
            # re-index) — changed it during the test. Report it, don't blame
            # the test.
            import warnings
            warnings.warn(
                f"{_real_db_path} changed during this test, but the test never opened "
                f"it — another program (most likely the AI-Prowler running on this PC) "
                f"wrote to it. Not a test failure.",
                UserWarning,
            )


# ──────────────────────────────────────────────────────────────────────────────
# Sample-file builders.
#
# Tests that need "a folder with one of every supported extension" get it
# via this fixture rather than building it inline. Keeps tests short and
# means if a new extension is added we update one place.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def sample_files(isolated_env):
    """Populate isolated_env.sample_root with a deterministic test corpus.

    Returns a dict {extension: Path} so tests can assert on specific files.
    Only formats with a pure-Python writer are produced here. PDFs, DOCXs,
    XLSXs etc. are produced by helpers.sample_files only when the test
    actually needs them, because building one is much slower than a .txt.
    """
    from tests.helpers import sample_files as builders
    root = isolated_env.sample_root

    files = {}
    files[".txt"] = builders.make_txt(root / "alpha.txt",
                                      "The quick brown fox jumps over the lazy dog. " * 60)
    files[".md"]  = builders.make_md(root / "bravo.md",
                                     "# Heading\n\n"
                                     "Body paragraph with some **bold** text. " * 60)
    files[".csv"] = builders.make_csv(root / "charlie.csv",
                                      [["name", "score"], ["Alice", "90"], ["Bob", "82"]])
    files[".json"] = builders.make_txt(root / "delta.json",
                                       json.dumps({"key": "value", "list": [1, 2, 3]}))
    files[".py"]  = builders.make_txt(root / "echo.py",
                                      "def hello():\n    return 'world'\n" * 30)
    files[".html"] = builders.make_txt(root / "foxtrot.html",
                                       "<html><body><p>Hello world</p></body></html>")
    return files


@pytest.fixture
def small_text_file(isolated_env):
    """Just a single .txt file — for tests that don't need a whole corpus."""
    from tests.helpers import sample_files as builders
    return builders.make_txt(
        isolated_env.sample_root / "single.txt",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 80,
    )


@pytest.fixture
def mbox_file(isolated_env):
    """A small deterministic .mbox file — 5 messages, stable Message-IDs."""
    from tests.helpers import mbox_builder
    return mbox_builder.make_mbox(
        isolated_env.sample_root / "test.mbox",
        n_messages=5,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Markers
# ──────────────────────────────────────────────────────────────────────────────
def pytest_addoption(parser):
    """Add --fd-track option for the handle leak tracker."""
    try:
        parser.addoption(
            "--fd-track",
            action="store_true",
            default=False,
            help="Enable per-test OS handle leak tracking (writes fd_track.log).",
        )
    except ValueError:
        pass  # already registered (e.g. if fd_tracker.py is also on sys.path)


def pytest_configure(config):
    """Register custom markers so `pytest --strict-markers` doesn't complain."""
    config.addinivalue_line(
        "markers",
        "slow: tests that take >5 seconds (embedding model load, OCR, etc.)",
    )
    config.addinivalue_line(
        "markers",
        "ocr: tests requiring Tesseract on PATH",
    )
    config.addinivalue_line(
        "markers",
        "regression: 10-minute smoke test (Section 8 of the test plan)",
    )

    # Load and register the fd_tracker plugin when --fd-track is requested.
    # We do this here (rather than via -p fd_tracker on the command line) so
    # pytest can find it without sys.path gymnastics — it lives in tests/.
    if config.getoption("--fd-track", default=False):
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location(
            "fd_tracker",
            Path(__file__).parent / "fd_tracker.py",
        )
        _mod = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        # Instantiate and register the plugin directly; pytest_addoption was
        # already handled above so FdTrackerPlugin can safely call getoption.
        config.pluginmanager.register(
            _mod.FdTrackerPlugin(config), "fd_tracker_plugin"
        )
