"""
R-069 (2026-10-08): Stop Indexing.

Covers:
  1. stop_event halts rag_preprocessor.index_directory mid-run
     (pre-set event -> 0 files; event set mid-run -> current file finishes,
     later files skipped; event set during a batch add -> remaining batches skipped).
  2. cancel_indexing MCP tool sets the shared stop event and returns a message.
  3. indexing_status MCP tool reports the _index_progress dict.
  4. New-tool checklist: catalog entry, JOBS_APP_TOOLS, both /pwa-api allowlists.

Run: run_tests.bat tests\\mcp_tests\\test_r069_stop_indexing.py -v
"""
import ast
import sys
import threading
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_MCP_SRC = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture(scope="module")
def cat():
    import mcp_tool_catalog as c
    return c


@pytest.fixture()
def clean_stop(mcp_mod):
    """The shared stop event / progress dict, restored after the test."""
    mcp_mod._index_stop_event.clear()
    mcp_mod._index_progress.update(
        {"running": False, "current_file": "", "files_done": 0,
         "files_total": 0, "phase": ""}
    )
    yield
    mcp_mod._index_stop_event.clear()
    mcp_mod._index_progress.update(
        {"running": False, "current_file": "", "files_done": 0,
         "files_total": 0, "phase": ""}
    )


# ── fake ChromaDB so index_directory runs hermetically ─────────────────────

class _FakeColl:
    def __init__(self, added, on_add=None):
        self._added = added
        self._on_add = on_add

    def delete(self, where=None):
        return None

    def count(self):
        return 0

    def add(self, documents=None, metadatas=None, ids=None):
        fp = metadatas[0].get("filepath") if metadatas else None
        self._added.append((fp, len(documents or [])))
        if self._on_add:
            self._on_add()


class _FakeClient:
    def __init__(self, added, on_add=None):
        self._added = added
        self._on_add = on_add

    def get_or_create_collection(self, **kw):
        return _FakeColl(self._added, self._on_add)


@pytest.fixture()
def fake_indexer(monkeypatch):
    """Stub the heavy I/O in rag_preprocessor; returns the `added` log."""
    import rag_preprocessor as rag
    added = []
    state = {"on_add": None}

    def _client():
        return _FakeClient(added, state["on_add"]), None

    monkeypatch.setattr(rag, "get_chroma_client", _client)
    monkeypatch.setattr(rag, "build_scope_resolver", lambda: None)
    monkeypatch.setattr(rag, "scan_directory_for_changes", lambda *a, **k: ([], []))
    monkeypatch.setattr(rag, "save_tracking_database", lambda *a, **k: None)
    monkeypatch.setattr(rag, "add_to_auto_update_list", lambda *a, **k: False)
    return added, state


def _three_files(tmp_path):
    for i in range(1, 4):
        (tmp_path / f"doc{i}.txt").write_text(
            f"This is test document number {i}. " * 20, encoding="utf-8")
    return tmp_path


# ── 1. stop_event halts index_directory ─────────────────────────────────────

def test_index_directory_preset_stop_processes_no_files(tmp_path, fake_indexer):
    import rag_preprocessor as rag
    added, _ = fake_indexer
    _three_files(tmp_path)
    ev = threading.Event()
    ev.set()  # stop requested before the run starts
    rag.index_directory(str(tmp_path), stop_event=ev)
    assert added == [], f"expected no files indexed, got {added}"


def test_index_directory_midrun_stop_finishes_current_file(tmp_path, fake_indexer):
    import rag_preprocessor as rag
    added, _ = fake_indexer
    _three_files(tmp_path)
    ev = threading.Event()
    started = []

    def _cb(i, total, fp):
        started.append(Path(fp).name)
        if i == 2:  # second file starts (1-indexed) -> request stop
            ev.set()

    rag.index_directory(str(tmp_path), stop_event=ev, progress_callback=_cb)
    # finish-current-file: files 1 and 2 start, file 3 never starts
    assert "doc1.txt" in started
    assert "doc2.txt" in started
    assert "doc3.txt" not in started, f"doc3 should be skipped, started={started}"
    # file 1 was fully indexed before the stop was requested
    assert any(n == 1 for _, n in added), "file 1's chunks should have been added"


def test_index_directory_batch_loop_honours_stop(tmp_path, fake_indexer):
    import rag_preprocessor as rag
    added, state = fake_indexer
    # one big file -> more than one 166-chunk batch
    big = tmp_path / "big.txt"
    big.write_text(
        "".join(f"Paragraph {n}: the quick brown fox jumps over the lazy dog. " * 4 + "\n"
                for n in range(400)),
        encoding="utf-8")
    ev = threading.Event()
    state["on_add"] = ev.set  # stop requested during the first batch add
    rag.index_directory(str(tmp_path), stop_event=ev)
    assert len(added) == 1, f"expected exactly one batch add, got {len(added)}"


# ── 2. cancel_indexing ──────────────────────────────────────────────────────

def test_cancel_indexing_sets_event(mcp_mod, clean_stop):
    msg = mcp_mod.cancel_indexing(ctx=None)
    assert mcp_mod._index_stop_event.is_set()
    assert "Stop requested" in msg


def test_cancel_indexing_reports_running_phase(mcp_mod, clean_stop):
    mcp_mod._index_progress.update({"running": True, "phase": "rebuilding",
                                    "current_file": "x.txt", "files_done": 3,
                                    "files_total": 10})
    msg = mcp_mod.cancel_indexing(ctx=None)
    assert "rebuilding" in msg and "x.txt" in msg


# ── 3. indexing_status ─────────────────────────────────────────────────────

def test_indexing_status_idle(mcp_mod, clean_stop):
    msg = mcp_mod.indexing_status(ctx=None)
    assert "idle" in msg.lower()


def test_indexing_status_running(mcp_mod, clean_stop):
    mcp_mod._index_progress.update({"running": True, "phase": "rebuilding",
                                    "current_file": "y.txt", "files_done": 4,
                                    "files_total": 8})
    msg = mcp_mod.indexing_status(ctx=None)
    assert "RUNNING" in msg
    assert "4/8" in msg
    assert "y.txt" in msg


# ── 4. new-tool checklist ───────────────────────────────────────────────────

def _allow_list(var_name: str) -> set:
    """The string-set literal assigned to var_name inside ai_prowler_mcp.py."""
    for node in ast.walk(ast.parse(_MCP_SRC)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == var_name
                and isinstance(node.value, ast.Set)):
            return {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
    raise AssertionError(f"{var_name} set literal not found")


def test_checklist_catalog_entries(cat):
    for name in ("cancel_indexing", "indexing_status"):
        assert name in cat.TOOL_CATALOG, f"{name} missing from TOOL_CATALOG"
        entry = cat.TOOL_CATALOG[name]
        assert entry.category == "core_kb"
        assert entry.locked, f"{name} should be locked like the other reindex tools"


def test_checklist_jobs_app_tools(cat):
    for name in ("cancel_indexing", "indexing_status"):
        assert name in cat.JOBS_APP_TOOLS, f"{name} missing from JOBS_APP_TOOLS"


def test_checklist_both_pwa_api_allowlists():
    for var in ("_srv_pa_allowed", "_allowed_tools"):
        allow = _allow_list(var)
        for name in ("cancel_indexing", "indexing_status"):
            assert name in allow, f"{name} missing from {var}"


def test_checklist_tools_are_decorated(mcp_mod):
    # the @mcp.tool() defs exist and are callable
    assert callable(mcp_mod.cancel_indexing)
    assert callable(mcp_mod.indexing_status)
