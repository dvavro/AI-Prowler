"""R-056 (2026-10-08): index corruption protection.

Covers:
  1. Startup integrity check raises IndexCorruptError on a deliberately
     corrupted sqlite file (and passes on healthy / missing files).
    2. Crash marker is written at start and deleted on success (no backup — removed 2026-10-08).
  3. Crash marker is written at start, deleted on success, and reported by
     check_ai_prowler_status when present (warning only, check still passes).

Run: run_tests.bat tests\\mcp_tests\\test_r056_index_corruption_protection.py -v
"""
import asyncio
import json
import sqlite3

import pytest


# ── helpers ──────────────────────────────────────────────────────────────

def _tiny_sqlite(path, marker_text):
    """Create a minimal valid sqlite file with a marker row we can read back."""
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS r056 (note TEXT)")
        conn.execute("DELETE FROM r056")
        conn.execute("INSERT INTO r056 (note) VALUES (?)", (marker_text,))
        conn.commit()
    finally:
        conn.close()


def _read_marker_text(path):
    conn = sqlite3.connect(str(path))
    try:
        row = conn.execute("SELECT note FROM r056 LIMIT 1").fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _boom(*a, **k):
    raise RuntimeError("simulated rebuild failure")


class _FakeCollection:
    """Cooperative stand-in: purge deletes one id and mutates the live db."""
    def __init__(self, db_file, target):
        self._db_file = db_file
        self._target = target

    def get(self, where=None, include=None):
        return {"ids": ["a.txt__chunk_0"],
                "metadatas": [{"source": str(self._target / "a.txt")}]}

    def delete(self, ids=None):
        assert ids == ["a.txt__chunk_0"], ids
        _tiny_sqlite(self._db_file, "PURGED")  # simulate the purge


class _FakeClient:
    def __init__(self, db_file, target):
        self._db_file = db_file
        self._target = target

    def get_or_create_collection(self, name=None, embedding_function=None):
        return _FakeCollection(self._db_file, self._target)

    def list_collections(self):
        return []


@pytest.fixture
def fake_live_db(tmp_path, monkeypatch, rag):
    """A fake ChromaDB directory (valid chroma.sqlite3) as CHROMA_DB_PATH."""
    live = tmp_path / "rag_database"
    live.mkdir()
    _tiny_sqlite(live / "chroma.sqlite3", "BEFORE")
    monkeypatch.setattr(rag, "CHROMA_DB_PATH", str(live))
    monkeypatch.setattr(rag, "_chroma_integrity_check_done", False)
    return live


@pytest.fixture
def reindex_env(mcp_env, monkeypatch, tmp_path, fake_live_db):
    """reindex_directory wired for fast hermetic tests (no model load)."""
    mcp = mcp_env.mcp
    rag = mcp_env.rag
    live = fake_live_db
    target = tmp_path / "docs"
    target.mkdir()
    (target / "a.txt").write_text("hello", encoding="utf-8")

    monkeypatch.setattr(mcp, "_resolve_allowlisted_path",
                        lambda p: (str(target), None))
    monkeypatch.setattr(rag, "get_chroma_client",
                        lambda: (_FakeClient(live / "chroma.sqlite3", target), None))
    mcp._prewarm_event.set()

    class Env:
        pass
    e = Env()
    e.mcp = mcp
    e.rag = rag
    e.live = live
    e.target = target
    return e


# ── 1. integrity check ───────────────────────────────────────────────────

def test_integrity_check_raises_on_corrupt_sqlite(fake_live_db, rag):
    (fake_live_db / "chroma.sqlite3").write_bytes(b"\x00\x01not-a-database" * 64)
    with pytest.raises(rag.IndexCorruptError):
        rag.check_chroma_db_integrity()


def test_integrity_check_passes_on_healthy_sqlite(fake_live_db, rag):
    rag.check_chroma_db_integrity()  # must not raise
    assert rag._chroma_integrity_check_done is True
    rag.check_chroma_db_integrity()  # second call is a no-op (once per process)


def test_integrity_check_passes_when_no_db_yet(tmp_path, monkeypatch, rag):
    empty = tmp_path / "fresh_rag_database"
    empty.mkdir()
    monkeypatch.setattr(rag, "CHROMA_DB_PATH", str(empty))
    monkeypatch.setattr(rag, "_chroma_integrity_check_done", False)
    rag.check_chroma_db_integrity()  # fresh install — nothing to check


def test_get_chroma_client_lets_corrupt_error_propagate(fake_live_db, monkeypatch, rag):
    # Interior-page corruption (valid header, damaged pages): PersistentClient
    # still constructs — like the real 2026-10-08 incident — so the integrity
    # gate must raise IndexCorruptError instead of handing out the client.
    import gc
    db_file = fake_live_db / "chroma.sqlite3"
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE t (a TEXT, b BLOB)")
    conn.executemany("INSERT INTO t VALUES (?, ?)", [("x" * 200, b"y" * 500)] * 300)
    conn.commit()
    conn.close()
    size = db_file.stat().st_size
    with open(db_file, "r+b") as fh:
        fh.seek(int(size * 0.6))
        fh.write(b"\x00" * 2048)
    assert not rag.sqlite_quick_check_ok(str(db_file))
    monkeypatch.setattr(rag, "_chroma_client_cache", None)
    monkeypatch.setattr(rag, "_embedding_func_cache", None)
    monkeypatch.setattr(rag, "_CHROMA_COLD_INIT_SETTLE_SECONDS", 0)
    with pytest.raises(rag.IndexCorruptError):
        rag.get_chroma_client()
    gc.collect()  # release the orphaned client's file handles for tmp cleanup


# ── 2. no backup; crash marker left on failure ──

def test_no_backup_taken_and_marker_left_on_failure(reindex_env, monkeypatch):
    e = reindex_env
    monkeypatch.setattr(e.mcp, "index_directory", _boom)
    out = e.mcp.reindex_directory(str(e.target), purge_first=True, ctx=None)
    assert out.startswith("❌ Reindex failed"), out
    assert "simulated rebuild failure" in out

    # no backup is taken anymore (removed 2026-10-08) ...
    assert not list(e.live.parent.glob(e.live.name + ".backup.*"))
    # ... the purge still happened, and the crash marker is left behind:
    # the run was interrupted
    assert _read_marker_text(e.live / "chroma.sqlite3") == "PURGED"
    marker = json.loads((e.live / ".reindex_in_progress.json").read_text(encoding="utf-8"))
    assert marker["dirs"] == [str(e.target)]
    assert marker["started_at"]


def test_marker_written_at_start_deleted_on_success(reindex_env, monkeypatch):
    e = reindex_env
    monkeypatch.setattr(e.mcp, "index_directory",
                        lambda *a, **k: {"files_indexed": 1, "chunks_added": 2})
    out = e.mcp.reindex_directory(str(e.target), purge_first=True, ctx=None)
    assert out.startswith("✅"), out
    assert "Files indexed : 1" in out
    assert not (e.live / ".reindex_in_progress.json").exists()


def test_reindex_all_takes_no_backup_and_clears_marker(reindex_env, monkeypatch):
    e = reindex_env
    monkeypatch.setattr(e.mcp, "load_auto_update_list", lambda: [str(e.target)])
    monkeypatch.setattr(e.mcp, "index_directory",
                        lambda *a, **k: {"files_indexed": 1, "chunks_added": 2})
    out = e.mcp.reindex_all(purge_first=True, ctx=None)
    assert "Full reindex complete" in out, out
    assert not list(e.live.parent.glob(e.live.name + ".backup.*"))  # no backup for the run
    assert not (e.live / ".reindex_in_progress.json").exists()


# ── 3. crash marker + status check ───────────────────────────────────────

def test_status_check_warns_on_interrupted_reindex(reindex_env):
    e = reindex_env
    e.rag.write_reindex_marker([str(e.target)])
    out = asyncio.run(e.mcp.check_ai_prowler_status(ctx=None))
    assert "reindex interrupted at" in out.lower()  # spec: "previous reindex interrupted at <started_at>"
    assert "✅ ChromaDB  : connected" in out  # warning only — check still passes


def test_status_check_reports_corrupt_index_distinctly(reindex_env, monkeypatch):
    e = reindex_env

    def _raise_corrupt():
        raise e.rag.IndexCorruptError("PRAGMA quick_check failed")

    monkeypatch.setattr(e.rag, "get_chroma_client", _raise_corrupt)
    out = asyncio.run(e.mcp.check_ai_prowler_status(ctx=None))
    # the distinct recovery message (not a generic exception string)
    assert "index corrupted \u2014 run reindex_all(purge_first=True)" in out
    assert "PRAGMA quick_check failed" in out
