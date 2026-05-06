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
import shutil
import sys
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

    # Cache invalidation — must run AFTER the patch so the next call rebuilds
    # against the new path.
    rag.invalidate_chroma_cache()

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
    rag.invalidate_chroma_cache()


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
