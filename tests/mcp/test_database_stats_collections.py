"""
tests/mcp/test_database_stats_collections.py
=============================================
Regression tests for v7.0.1 bug fix:

  CHANGE: get_database_stats() now uses client.list_collections() to enumerate
          ALL ChromaDB collections instead of _scoped_collections_for_ctx(ctx)
          which in personal mode (ctx=None) only returned the single default
          'documents' collection — missing any scoped collections written by
          Business Server mode and causing a chunk count discrepancy vs
          check_ai_prowler_status().

Test IDs
--------
  DS-01  get_database_stats returns non-zero total after indexing
  DS-02  get_database_stats and check_ai_prowler_status agree on chunk count
  DS-03  get_database_stats returns empty message on fresh database
  DS-04  get_database_stats chunk count increases after adding a file
  DS-05  get_database_stats chunk count decreases after untracking
  DS-06  get_database_stats output contains Total chunks line
  DS-07  get_database_stats output contains Unique documents line
  DS-08  get_database_stats output contains Database path line
  DS-09  get_database_stats output contains file type breakdown
  DS-10  COLLECTION SPLIT MOCK: get_database_stats returns correct count even
         when _scoped_collections_for_ctx() is poisoned to return empty —
         proves the fix uses list_collections() not _scoped_collections_for_ctx()
         (this test WOULD HAVE FAILED against the pre-fix code)
"""
from __future__ import annotations

import re
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _total_chunks_from_stats(stats_output: str) -> int:
    """Parse 'Total chunks : N' from get_database_stats output."""
    m = re.search(r"Total chunks\s*:\s*([\d,]+)", stats_output)
    if not m:
        return 0
    return int(m.group(1).replace(",", ""))


def _chunk_count_from_status(status_output: str) -> int:
    """Parse 'Chunks : N' from check_ai_prowler_status output."""
    m = re.search(r"Chunks\s*:\s*([\d,]+)", status_output)
    assert m, f"Could not find 'Chunks : N' in status output:\n{status_output}"
    return int(m.group(1).replace(",", ""))


def _write_sample(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# DS-01  get_database_stats returns non-zero after indexing
# ─────────────────────────────────────────────────────────────────────────────

def test_ds01_stats_nonzero_after_index(mcp_env):
    """get_database_stats must report > 0 chunks after indexing a file."""
    _write_sample(
        mcp_env.sample_root / "ds01_doc.txt",
        "DS-01 document for stats test. " * 10
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))

    stats = mcp_env.mcp.get_database_stats()
    count = _total_chunks_from_stats(stats)
    assert count > 0, (
        f"DS-01 FAIL: get_database_stats reported 0 chunks after indexing.\n"
        f"Output:\n{stats}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# DS-02  get_database_stats and check_ai_prowler_status agree
# ─────────────────────────────────────────────────────────────────────────────

def test_ds02_stats_and_status_agree(mcp_env):
    """get_database_stats and check_ai_prowler_status must report the same
    chunk count. This is the direct regression test for the v7.0.1 bug
    where _scoped_collections_for_ctx(None) in get_database_stats missed
    scoped collections that list_collections() in check_ai_prowler_status
    correctly enumerated."""
    _write_sample(
        mcp_env.sample_root / "ds02_doc.txt",
        "DS-02 agreement test document. " * 10
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))

    stats  = mcp_env.mcp.get_database_stats()
    status = mcp_env.mcp.check_ai_prowler_status()

    stats_count  = _total_chunks_from_stats(stats)
    status_count = _chunk_count_from_status(status)

    assert stats_count == status_count, (
        f"DS-02 FAIL: chunk count mismatch — "
        f"get_database_stats={stats_count}, "
        f"check_ai_prowler_status={status_count}.\n"
        f"This is the v7.0.1 regression.\n\n"
        f"stats output:\n{stats}\n\n"
        f"status output:\n{status}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# DS-03  get_database_stats returns empty message on fresh database
# ─────────────────────────────────────────────────────────────────────────────

def test_ds03_stats_empty_on_fresh_db(mcp_env):
    """get_database_stats on a fresh empty database must return an empty
    indicator message, not crash or return garbage."""
    stats = mcp_env.mcp.get_database_stats()
    # Acceptable: either an empty indicator or 0 chunks
    is_empty_msg = any(
        kw in stats.lower()
        for kw in ("empty", "no documents", "not yet", "📭")
    )
    is_zero = _total_chunks_from_stats(stats) == 0
    assert is_empty_msg or is_zero, (
        f"DS-03 FAIL: unexpected stats output on fresh database:\n{stats}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# DS-04  get_database_stats chunk count increases after adding a file
# ─────────────────────────────────────────────────────────────────────────────

def test_ds04_stats_increases_after_adding_file(mcp_env):
    """Chunk count in get_database_stats must increase when a new file is added."""
    _write_sample(
        mcp_env.sample_root / "ds04_file_a.txt",
        "DS-04 first file baseline. " * 5
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    count_before = _total_chunks_from_stats(mcp_env.mcp.get_database_stats())

    _write_sample(
        mcp_env.sample_root / "ds04_file_b.txt",
        "DS-04 second file addition. " * 20
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    count_after = _total_chunks_from_stats(mcp_env.mcp.get_database_stats())

    assert count_after > count_before, (
        f"DS-04 FAIL: chunk count did not increase after adding file "
        f"({count_before} → {count_after})."
    )


# ─────────────────────────────────────────────────────────────────────────────
# DS-05  get_database_stats chunk count decreases after untracking
# ─────────────────────────────────────────────────────────────────────────────

def test_ds05_stats_decreases_after_untrack(mcp_env):
    """Chunk count must decrease after untrack_directory removes a folder."""
    sub_a = mcp_env.sample_root / "ds05_sub_a"
    sub_b = mcp_env.sample_root / "ds05_sub_b"
    sub_a.mkdir(exist_ok=True)
    sub_b.mkdir(exist_ok=True)

    _write_sample(sub_a / "a.txt", "DS-05 sub_a content. " * 10)
    _write_sample(sub_b / "b.txt", "DS-05 sub_b content. " * 10)

    mcp_env.mcp.index_path(directory=str(sub_a))
    mcp_env.mcp.index_path(directory=str(sub_b))
    count_before = _total_chunks_from_stats(mcp_env.mcp.get_database_stats())

    mcp_env.mcp.untrack_directory(directory=str(sub_b))
    count_after = _total_chunks_from_stats(mcp_env.mcp.get_database_stats())

    assert count_after < count_before, (
        f"DS-05 FAIL: chunk count did not decrease after untrack "
        f"({count_before} → {count_after})."
    )


# ─────────────────────────────────────────────────────────────────────────────
# DS-06  get_database_stats output contains Total chunks line
# ─────────────────────────────────────────────────────────────────────────────

def test_ds06_stats_output_has_total_chunks(mcp_env):
    """get_database_stats output must contain 'Total chunks :' line."""
    _write_sample(
        mcp_env.sample_root / "ds06_doc.txt",
        "DS-06 total chunks line test."
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    stats = mcp_env.mcp.get_database_stats()
    assert re.search(r"Total chunks\s*:", stats), (
        f"DS-06 FAIL: 'Total chunks :' line not found.\nOutput:\n{stats}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# DS-07  get_database_stats output contains Unique documents line
# ─────────────────────────────────────────────────────────────────────────────

def test_ds07_stats_output_has_unique_docs(mcp_env):
    """get_database_stats output must contain 'Unique documents :' line."""
    _write_sample(
        mcp_env.sample_root / "ds07_doc.txt",
        "DS-07 unique documents line test."
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    stats = mcp_env.mcp.get_database_stats()
    assert re.search(r"Unique documents\s*:", stats), (
        f"DS-07 FAIL: 'Unique documents :' line not found.\nOutput:\n{stats}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# DS-08  get_database_stats output contains Database path line
# ─────────────────────────────────────────────────────────────────────────────

def test_ds08_stats_output_has_db_path(mcp_env):
    """get_database_stats output must contain 'Database path :' line."""
    _write_sample(
        mcp_env.sample_root / "ds08_doc.txt",
        "DS-08 database path line test."
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    stats = mcp_env.mcp.get_database_stats()
    assert re.search(r"Database path\s*:", stats), (
        f"DS-08 FAIL: 'Database path :' line not found.\nOutput:\n{stats}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# DS-09  get_database_stats output contains file type breakdown
# ─────────────────────────────────────────────────────────────────────────────

def test_ds09_stats_output_has_filetype_breakdown(mcp_env):
    """get_database_stats output must contain a file-type breakdown section."""
    _write_sample(
        mcp_env.sample_root / "ds09_doc.txt",
        "DS-09 file type breakdown test."
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    stats = mcp_env.mcp.get_database_stats()
    # Should show at least one file type like "TXT : 1 file(s)"
    assert re.search(r"\w+\s*:\s*\d+\s*file", stats, re.IGNORECASE), (
        f"DS-09 FAIL: file type breakdown not found in stats output.\n"
        f"Output:\n{stats}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# DS-10  COLLECTION SPLIT MOCK — get_database_stats uses list_collections
# ─────────────────────────────────────────────────────────────────────────────

def test_ds10_collection_split_mock(mcp_env):
    """DS-10: get_database_stats returns correct count even when
    _scoped_collections_for_ctx() is poisoned to return an empty collection.

    This directly reproduces the scenario where _scoped_collections_for_ctx
    only returned the default 'documents' collection and missed scoped
    collections in Business Server mode.

    The fixed code uses client.list_collections() which enumerates ALL real
    collections — bypassing _scoped_collections_for_ctx entirely.

    This test WOULD HAVE FAILED against the pre-fix code.
    """
    import unittest.mock as mock
    import rag_preprocessor as rag

    # ── Step 1: index real documents ─────────────────────────────────────────
    _write_sample(
        mcp_env.sample_root / "ds10_doc_a.txt",
        "DS-10 collection split test document A. " * 10
    )
    _write_sample(
        mcp_env.sample_root / "ds10_doc_b.txt",
        "DS-10 collection split test document B. " * 10
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))

    # Confirm real chunk count before applying mock
    real_client, real_emb = rag.get_chroma_client()
    real_count = sum(
        real_client.get_collection(name=col.name, embedding_function=real_emb).count()
        for col in real_client.list_collections()
    )
    assert real_count > 0, "DS-10 precondition: DB must have chunks before mock"

    # ── Step 2: build a fake empty collection list ────────────────────────────
    # Simulates _scoped_collections_for_ctx returning only the default
    # 'documents' collection which — in the HTTP server split — had 0 chunks.
    class _FakeEmptyCollection:
        """A ChromaDB collection instance that lies about its chunk count.
        Simulates the stale HTTP collection instance from the original bug."""
        name = "documents"
        def count(self):
            return 0  # the lie that caused the original bug
        def get(self, *args, **kwargs):
            return {"ids": [], "documents": [], "metadatas": []}

    # ── Step 3: patch _scoped_collections_for_ctx to return the fake ─────────
    # The fixed get_database_stats should NOT call this function at all,
    # using list_collections() instead. We poison it to prove it's bypassed.
    import ai_prowler_mcp as mcp_mod

    with mock.patch.object(
        mcp_mod,
        "_scoped_collections_for_ctx",
        return_value=[_FakeEmptyCollection()]
    ) as patched:
        stats = mcp_env.mcp.get_database_stats()
        stats_count = _total_chunks_from_stats(stats)
        scoped_was_called = patched.called

    # ── Step 4: assert correct behaviour ─────────────────────────────────────
    assert stats_count == real_count, (
        f"DS-10 FAIL: get_database_stats reported {stats_count} chunks "
        f"but the real database has {real_count} chunks.\n"
        f"This is the v7.0.1 regression — the tool is still using "
        f"_scoped_collections_for_ctx() instead of list_collections().\n\n"
        f"_scoped_collections_for_ctx was called: {scoped_was_called}\n"
        f"stats output:\n{stats}"
    )

    # Bonus: confirm the fixed code never calls _scoped_collections_for_ctx
    assert not scoped_was_called, (
        f"DS-10 WARNING: get_database_stats still calls "
        f"_scoped_collections_for_ctx() — this is the risky pre-fix path. "
        f"The fix should use list_collections() exclusively.\n"
        f"stats output:\n{stats}"
    )
