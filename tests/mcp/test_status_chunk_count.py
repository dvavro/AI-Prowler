"""
tests/mcp/test_status_chunk_count.py
======================================
Regression tests for v7.0.1 bug fix:

  BUG:  check_ai_prowler_status() reported 0 (or stale) chunk count while
        get_database_stats() correctly reported the real count.

  ROOT CAUSE: check_ai_prowler_status() called
        client.get_or_create_collection() directly, which in Business Server
        mode can return a different collection instance than what the indexer
        uses. get_database_stats() uses client.list_collections() which always
        reflects the true total across ALL collections.

  FIX:  check_ai_prowler_status() now uses client.list_collections() to
        enumerate every real collection and sums counts across all of them —
        the same approach as get_database_stats().

Test IDs
--------
  SC-01  After indexing, check_ai_prowler_status reports non-zero chunk count
  SC-02  check_ai_prowler_status and get_database_stats agree on chunk count
  SC-03  check_ai_prowler_status reports 0 on a fresh empty database
  SC-04  check_ai_prowler_status reports correct count after second index call
  SC-05  check_ai_prowler_status chunk count increases after adding a file
  SC-06  check_ai_prowler_status chunk count decreases after untracking
  SC-07  get_database_stats and check_ai_prowler_status stay in sync across
         multiple index/untrack cycles
  SC-08  check_ai_prowler_status output contains expected header line
  SC-09  check_ai_prowler_status output contains ChromaDB connected indicator
  SC-10  check_ai_prowler_status output contains the chunk count line
  SC-11  SERVER SPLIT: check_ai_prowler_status returns correct count even when
         get_or_create_collection() returns a stale/empty collection instance
         (simulates the Business Server HTTP collection split that caused the
         original bug — this test WOULD HAVE FAILED against the unfixed code)
"""
from __future__ import annotations

import re
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _chunk_count_from_status(status_output: str) -> int:
    """Parse the 'Chunks : N' line from check_ai_prowler_status output."""
    m = re.search(r"Chunks\s*:\s*([\d,]+)", status_output)
    assert m, (
        f"Could not find 'Chunks : N' in check_ai_prowler_status output:\n"
        f"{status_output}"
    )
    return int(m.group(1).replace(",", ""))


def _chunk_count_from_stats(stats_output: str) -> int:
    """Parse the 'Total chunks : N' line from get_database_stats output."""
    m = re.search(r"Total chunks\s*:\s*([\d,]+)", stats_output)
    if not m:
        # Empty database — get_database_stats returns a short message
        return 0
    return int(m.group(1).replace(",", ""))


def _write_sample_file(path: Path, content: str = "Sample content for AI-Prowler test.") -> Path:
    """Write a text file and return its Path."""
    path.write_text(content, encoding="utf-8")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# SC-01  After indexing, check_ai_prowler_status reports non-zero chunk count
# ─────────────────────────────────────────────────────────────────────────────

def test_sc01_status_nonzero_after_index(mcp_env):
    """check_ai_prowler_status must report > 0 chunks after indexing a file."""
    _write_sample_file(
        mcp_env.sample_root / "sc01_sample.txt",
        "SC-01 test document. Contains enough text to produce at least one chunk."
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))

    status = mcp_env.mcp.check_ai_prowler_status()
    count = _chunk_count_from_status(status)
    assert count > 0, (
        f"SC-01 FAIL: check_ai_prowler_status reported 0 chunks after indexing.\n"
        f"Output:\n{status}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SC-02  check_ai_prowler_status and get_database_stats agree on chunk count
# ─────────────────────────────────────────────────────────────────────────────

def test_sc02_status_and_stats_agree(mcp_env):
    """The chunk count from check_ai_prowler_status must equal get_database_stats.

    This is the direct regression test for the v7.0.1 bug where the two tools
    returned different numbers from the same database.
    """
    _write_sample_file(
        mcp_env.sample_root / "sc02_sample.txt",
        "SC-02 regression test — both status tools must agree on chunk count."
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))

    status = mcp_env.mcp.check_ai_prowler_status()
    stats  = mcp_env.mcp.get_database_stats()

    status_count = _chunk_count_from_status(status)
    stats_count  = _chunk_count_from_stats(stats)

    assert status_count == stats_count, (
        f"SC-02 FAIL: chunk count mismatch — "
        f"check_ai_prowler_status={status_count}, "
        f"get_database_stats={stats_count}.\n"
        f"This is the v7.0.1 regression.\n\n"
        f"status output:\n{status}\n\n"
        f"stats output:\n{stats}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SC-03  check_ai_prowler_status reports 0 on a fresh empty database
# ─────────────────────────────────────────────────────────────────────────────

def test_sc03_status_zero_on_empty_db(mcp_env):
    """On a fresh isolated database with nothing indexed, status must show 0."""
    # mcp_env gives us a clean isolated DB — nothing indexed yet
    status = mcp_env.mcp.check_ai_prowler_status()

    # Either "Chunks : 0" or an empty-DB hint message is acceptable
    if "Chunks" in status:
        count = _chunk_count_from_status(status)
        assert count == 0, (
            f"SC-03 FAIL: expected 0 chunks on empty DB, got {count}.\n"
            f"Output:\n{status}"
        )
    else:
        # Empty-DB message path — also acceptable
        assert any(
            kw in status for kw in ("empty", "no documents", "nothing indexed", "0")
        ), (
            f"SC-03 FAIL: unexpected status output on empty DB:\n{status}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# SC-04  check_ai_prowler_status reports correct count after second index call
# ─────────────────────────────────────────────────────────────────────────────

def test_sc04_status_correct_after_reindex(mcp_env):
    """Chunk count stays consistent after calling index_path twice on same dir."""
    _write_sample_file(
        mcp_env.sample_root / "sc04_sample.txt",
        "SC-04 first index pass."
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    count_first = _chunk_count_from_status(mcp_env.mcp.check_ai_prowler_status())

    # Re-index same directory — chunk count should stay the same (dedup)
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    count_second = _chunk_count_from_status(mcp_env.mcp.check_ai_prowler_status())

    assert count_second == count_first, (
        f"SC-04 FAIL: chunk count changed after re-indexing same directory "
        f"({count_first} → {count_second}). Expected no change."
    )


# ─────────────────────────────────────────────────────────────────────────────
# SC-05  check_ai_prowler_status chunk count increases after adding a file
# ─────────────────────────────────────────────────────────────────────────────

def test_sc05_status_increases_after_adding_file(mcp_env):
    """Chunk count reported by status must increase when a new file is indexed."""
    _write_sample_file(
        mcp_env.sample_root / "sc05_file_a.txt",
        "SC-05 first file — baseline chunk count."
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    count_before = _chunk_count_from_status(mcp_env.mcp.check_ai_prowler_status())

    # Add a second, larger file
    _write_sample_file(
        mcp_env.sample_root / "sc05_file_b.txt",
        "SC-05 second file. " + ("Additional content. " * 20)
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))
    count_after = _chunk_count_from_status(mcp_env.mcp.check_ai_prowler_status())

    assert count_after > count_before, (
        f"SC-05 FAIL: chunk count did not increase after adding a file "
        f"({count_before} → {count_after})."
    )


# ─────────────────────────────────────────────────────────────────────────────
# SC-06  check_ai_prowler_status chunk count decreases after untracking
# ─────────────────────────────────────────────────────────────────────────────

def test_sc06_status_decreases_after_untrack(mcp_env):
    """Chunk count reported by status must decrease after untrack_directory."""
    # Create two separate subdirectories so we can untrack just one
    sub_a = mcp_env.sample_root / "sub_a"
    sub_b = mcp_env.sample_root / "sub_b"
    sub_a.mkdir(exist_ok=True)
    sub_b.mkdir(exist_ok=True)

    _write_sample_file(sub_a / "doc_a.txt", "SC-06 sub_a document. " * 10)
    _write_sample_file(sub_b / "doc_b.txt", "SC-06 sub_b document. " * 10)

    mcp_env.mcp.index_path(directory=str(sub_a))
    mcp_env.mcp.index_path(directory=str(sub_b))
    count_before = _chunk_count_from_status(mcp_env.mcp.check_ai_prowler_status())

    # Untrack sub_b — its chunks should be purged
    mcp_env.mcp.untrack_directory(directory=str(sub_b))
    count_after = _chunk_count_from_status(mcp_env.mcp.check_ai_prowler_status())

    assert count_after < count_before, (
        f"SC-06 FAIL: chunk count did not decrease after untrack_directory "
        f"({count_before} → {count_after})."
    )


# ─────────────────────────────────────────────────────────────────────────────
# SC-07  get_database_stats and check_ai_prowler_status stay in sync across
#        multiple index/untrack cycles
# ─────────────────────────────────────────────────────────────────────────────

def test_sc07_sync_across_cycles(mcp_env):
    """Both tools must agree at every step of index → untrack → reindex cycle."""
    sub = mcp_env.sample_root / "cycle_sub"
    sub.mkdir(exist_ok=True)

    mismatches = []

    def _check_agreement(label: str):
        status = mcp_env.mcp.check_ai_prowler_status()
        stats  = mcp_env.mcp.get_database_stats()
        sc = _chunk_count_from_status(status)
        gc = _chunk_count_from_stats(stats)
        if sc != gc:
            mismatches.append(
                f"  [{label}] status={sc}, stats={gc}"
            )

    # Step 1 — index
    _write_sample_file(sub / "cycle_doc.txt", "SC-07 cycle document. " * 15)
    mcp_env.mcp.index_path(directory=str(sub))
    _check_agreement("after first index")

    # Step 2 — untrack
    mcp_env.mcp.untrack_directory(directory=str(sub))
    _check_agreement("after untrack")

    # Step 3 — reindex
    mcp_env.mcp.index_path(directory=str(sub))
    _check_agreement("after reindex")

    assert not mismatches, (
        "SC-07 FAIL: check_ai_prowler_status and get_database_stats "
        "disagreed at the following steps:\n" + "\n".join(mismatches)
    )


# ─────────────────────────────────────────────────────────────────────────────
# SC-08  check_ai_prowler_status output contains expected header line
# ─────────────────────────────────────────────────────────────────────────────

def test_sc08_status_output_has_header(mcp_env):
    """check_ai_prowler_status output must contain the status header."""
    status = mcp_env.mcp.check_ai_prowler_status()
    assert "AI-Prowler Status Check" in status, (
        f"SC-08 FAIL: header 'AI-Prowler Status Check' not found in output:\n{status}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SC-09  check_ai_prowler_status output contains ChromaDB connected indicator
# ─────────────────────────────────────────────────────────────────────────────

def test_sc09_status_output_chroma_connected(mcp_env):
    """check_ai_prowler_status must report ChromaDB as connected."""
    status = mcp_env.mcp.check_ai_prowler_status()
    assert "ChromaDB" in status, (
        f"SC-09 FAIL: 'ChromaDB' not found in status output:\n{status}"
    )
    assert "connected" in status.lower(), (
        f"SC-09 FAIL: 'connected' not found in status output:\n{status}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SC-10  check_ai_prowler_status output contains the chunk count line
# ─────────────────────────────────────────────────────────────────────────────

def test_sc10_status_output_has_chunk_line(mcp_env):
    """check_ai_prowler_status output must contain a 'Chunks :' line."""
    _write_sample_file(
        mcp_env.sample_root / "sc10_sample.txt",
        "SC-10 sample document for chunk line presence check."
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))

    status = mcp_env.mcp.check_ai_prowler_status()
    assert re.search(r"Chunks\s*:", status), (
        f"SC-10 FAIL: 'Chunks :' line not found in status output:\n{status}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SC-11  SERVER SPLIT — mock the HTTP collection divergence
#
# This is the test that WOULD HAVE CAUGHT the original bug.
#
# What the bug was:
#   In Business Server mode, ChromaDB runs as an HTTP server. Two separate
#   calls to get_or_create_collection() can return DIFFERENT collection
#   objects pointing at different in-memory state — one held by the indexer,
#   one freshly created by check_ai_prowler_status. The fresh one has 0
#   chunks even though the indexer's copy has the real data.
#
# How we simulate it without a real HTTP server:
#   After indexing real documents, we monkey-patch the ChromaDB client's
#   get_or_create_collection() to return a brand-new EMPTY collection.
#   This simulates the HTTP split: the indexer's collection has chunks,
#   but get_or_create_collection() hands back a stale empty one.
#
# What the test asserts:
#   FIXED code: uses client.list_collections() → iterates real collections
#               → sees actual chunk count → PASSES
#   BROKEN code: called get_or_create_collection() → gets empty mock
#               → reports 0 chunks → FAILS
# ─────────────────────────────────────────────────────────────────────────────

def test_sc11_server_split_mock(mcp_env):
    """SC-11: check_ai_prowler_status reports correct count even when
    get_or_create_collection() is poisoned to return a stale empty collection.

    This directly reproduces the Business Server HTTP collection split that
    caused the original v7.0.1 bug. The fixed code uses list_collections()
    which bypasses get_or_create_collection() entirely.

    This test WOULD HAVE FAILED against the pre-fix code.
    """
    import unittest.mock as mock

    # ── Step 1: index real documents so the DB has actual chunks ─────────────
    _write_sample_file(
        mcp_env.sample_root / "sc11_doc_a.txt",
        "SC-11 server split test document A. " * 10
    )
    _write_sample_file(
        mcp_env.sample_root / "sc11_doc_b.txt",
        "SC-11 server split test document B. " * 10
    )
    mcp_env.mcp.index_path(directory=str(mcp_env.sample_root))

    # Confirm real chunks exist before we apply the mock
    import rag_preprocessor as rag
    real_client, real_emb = rag.get_chroma_client()
    real_count = sum(
        real_client.get_collection(name=col.name, embedding_function=real_emb).count()
        for col in real_client.list_collections()
    )
    assert real_count > 0, "SC-11 precondition: DB must have chunks before mock"

    # ── Step 2: build a fake empty collection (the "stale HTTP instance") ────
    # This is what get_or_create_collection() would return in the split case:
    # a collection object that exists but has zero chunks.
    class _FakeEmptyCollection:
        """Simulates a ChromaDB collection instance that is out of sync with
        the real HTTP server state — it reports 0 chunks even though the
        actual server collection has data. This is exactly the object that
        get_or_create_collection() returned in Business Server mode before
        the fix."""
        name = "documents"
        def count(self):
            return 0  # <- the lie that caused the bug
        def get(self, *args, **kwargs):
            return {"ids": [], "documents": [], "metadatas": []}
        def query(self, *args, **kwargs):
            return {"ids": [[]], "documents": [[]], "metadatas": [[]]}

    fake_empty = _FakeEmptyCollection()

    # ── Step 3: patch get_or_create_collection on the live client ────────────
    # We patch ONLY get_or_create_collection — list_collections and
    # get_collection are left intact so the fixed code path still works.

    with mock.patch.object(
        real_client,
        "get_or_create_collection",
        return_value=fake_empty
    ) as patched:

        # ── Step 4: call check_ai_prowler_status under the poisoned condition ─
        status = mcp_env.mcp.check_ai_prowler_status()
        status_count = _chunk_count_from_status(status)

        # Confirm the mock was actually called (so we know the patch landed)
        # If the fixed code NEVER calls get_or_create_collection, that's
        # also acceptable — the count will be correct regardless.
        mock_was_called = patched.called

    # ── Step 5: assert correct behaviour ─────────────────────────────────────
    assert status_count == real_count, (
        f"SC-11 FAIL: check_ai_prowler_status reported {status_count} chunks "
        f"but the real collection has {real_count} chunks.\n"
        f"This is the v7.0.1 regression — the tool is using "
        f"get_or_create_collection() (which returned the stale fake) instead "
        f"of list_collections() + get_collection() (which return real data).\n\n"
        f"get_or_create_collection was called: {mock_was_called}\n"
        f"status output:\n{status}"
    )

    # Bonus assertion: if the fix is correct, get_or_create_collection should
    # NOT have been called at all (the fixed code doesn't use it).
    assert not mock_was_called, (
        f"SC-11 WARNING: check_ai_prowler_status still calls "
        f"get_or_create_collection() — this is the risky code path. "
        f"The fix should use list_collections() exclusively.\n"
        f"status output:\n{status}"
    )
