"""
tests/unit/test_chroma_cold_init_settle.py
============================================
Tests for the v9.0.1 ChromaDB cold-init settle delay in get_chroma_client().

Background
----------
A fresh chromadb.PersistentClient's Rust-side segment manager spins up
background HNSW compaction/bookkeeping work that is not guaranteed to be
finished the instant the constructor returns. Writing to a collection
immediately after a cold init has been observed in the wild to race that
startup work and permanently corrupt the on-disk HNSW vector segment — not a
soft error, but one where every subsequent read (even a bare .count(), no
write involved) crashes the whole process with a native access violation,
because the corruption lives in the persisted HNSW binary files themselves.

get_chroma_client() now sleeps for _CHROMA_COLD_INIT_SETTLE_SECONDS after a
COLD client init (not on cache hits) before caching/returning the client, so
the client is paid at most once per process lifetime. See that function's
docstring in rag_preprocessor.py for the full rationale.

Test IDs: CCS-01 to CCS-05

SAFETY — these tests NEVER touch the real installed AI-Prowler database
-------------------------------------------------------------------------
Every test here uses the `isolated_env` fixture (tests/conftest.py), which
redirects rag_preprocessor.CHROMA_DB_PATH to a fresh pytest tmp_path before
any ChromaDB client is created, and calls invalidate_chroma_cache() so no
cached client from a previous test (or from the real install) can leak in.
CCS-01/02/03 additionally mock out chromadb.PersistentClient and the
embedding-model loader entirely, so they never construct a real ChromaDB
client at all — only the sleep-timing logic in get_chroma_client() is
exercised. Nothing in this file makes a real chromadb.PersistentClient call
against a real directory that isn't a pytest tmp_path.

What these tests verify
------------------------
  CCS-01  Cold init pays the settle delay when
          _CHROMA_COLD_INIT_SETTLE_SECONDS > 0.
  CCS-02  A cached (warm) call pays NO delay, even right after a cold init
          that did pay one.
  CCS-03  Setting the delay to 0 means cold init pays no delay at all — this
          is the mechanism the rest of the test suite relies on via
          isolated_env's default override, so it's tested explicitly here.
  CCS-04  isolated_env itself defaults _CHROMA_COLD_INIT_SETTLE_SECONDS to 0
          (regression guard for the conftest.py change — if someone removes
          that override, this test fails immediately instead of every other
          test in the suite silently getting ~1.5s slower).
  CCS-05  End-to-end regression: real indexing (get_chroma_client ->
          create_or_get_collection -> index_file_list) still produces
          correct chunks with the new conditional-sleep branch in place.
          Runs against a real (but sandboxed, tmp_path-backed) ChromaDB and
          a real embedding model — marked @pytest.mark.slow like other
          real-model tests in this suite.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ── Locate rag_preprocessor ───────────────────────────────────────────────────
SRC_ROOT = Path(__file__).parent.parent.parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


# ── Shared fixture: get_chroma_client() with the heavy parts mocked out ───────
@pytest.fixture
def mocked_cold_init(isolated_env, monkeypatch):
    """Mock chromadb.PersistentClient and the embedding-model loader so
    get_chroma_client()'s cold-init branch runs in milliseconds instead of
    seconds, isolating the settle-delay logic itself from real I/O and real
    model loading. isolated_env has already redirected CHROMA_DB_PATH to a
    tmp_path and invalidated the cache before this fixture runs.
    """
    rag = isolated_env.rag

    fake_client = MagicMock(name="fake_chromadb_client")
    monkeypatch.setattr(rag.chromadb, "PersistentClient",
                        lambda path: fake_client)
    monkeypatch.setattr(rag, "get_best_embedding_device", lambda: "cpu")
    monkeypatch.setattr(rag, "_SentenceTransformerEmbedding",
                        lambda model, device: MagicMock(name="fake_embedding_func"))

    # Belt-and-suspenders: make sure we're starting from a genuinely cold
    # cache, since a mocked client must never be "warm" from a previous test.
    rag.invalidate_chroma_cache()

    return rag


# =============================================================================
# CCS-01  Cold init pays the settle delay
# =============================================================================

class TestColdInitPaysDelay:

    def test_CCS_01_cold_init_sleeps_for_configured_duration(self, mocked_cold_init, monkeypatch):
        """CCS-01: With _CHROMA_COLD_INIT_SETTLE_SECONDS > 0, a cold
        get_chroma_client() call takes at least that long."""
        rag = mocked_cold_init
        monkeypatch.setattr(rag, "_CHROMA_COLD_INIT_SETTLE_SECONDS", 0.25)

        t0 = time.monotonic()
        client, embedding_func = rag.get_chroma_client()
        elapsed = time.monotonic() - t0

        assert client is not None
        assert embedding_func is not None
        assert elapsed >= 0.20, (
            f"Cold init only took {elapsed*1000:.1f}ms — expected >= 200ms "
            f"(configured delay was 250ms). The settle-delay sleep may not "
            f"be firing on cold init."
        )


# =============================================================================
# CCS-02  Cached call pays no delay
# =============================================================================

class TestCachedCallPaysNoDelay:

    def test_CCS_02_second_call_is_instant_even_after_delayed_first_call(
            self, mocked_cold_init, monkeypatch):
        """CCS-02: The delay is a cold-init-only cost — a second call that
        hits the module-level cache must not pay it again."""
        rag = mocked_cold_init
        monkeypatch.setattr(rag, "_CHROMA_COLD_INIT_SETTLE_SECONDS", 0.25)

        # First call — cold, pays the delay (also proves the fixture/mocks work)
        first_client, _ = rag.get_chroma_client()

        # Second call — must hit the cache and skip the sleep entirely.
        t0 = time.monotonic()
        second_client, _ = rag.get_chroma_client()
        elapsed = time.monotonic() - t0

        assert second_client is first_client, (
            "Second call did not return the cached client instance"
        )
        assert elapsed < 0.05, (
            f"Cached call took {elapsed*1000:.1f}ms — expected < 50ms. "
            f"The settle delay appears to be re-applied on cache hits."
        )


# =============================================================================
# CCS-03  Zero delay means no delay at all
# =============================================================================

class TestZeroDelayIsNoOp:

    def test_CCS_03_zero_settle_seconds_skips_sleep_on_cold_init(
            self, mocked_cold_init, monkeypatch):
        """CCS-03: Setting the delay to 0 must not sleep at all on cold init.
        This is the exact mechanism isolated_env relies on (CCS-04) to keep
        the rest of the test suite fast."""
        rag = mocked_cold_init
        monkeypatch.setattr(rag, "_CHROMA_COLD_INIT_SETTLE_SECONDS", 0)

        t0 = time.monotonic()
        client, embedding_func = rag.get_chroma_client()
        elapsed = time.monotonic() - t0

        assert client is not None
        assert elapsed < 0.05, (
            f"Cold init with settle=0 took {elapsed*1000:.1f}ms — expected "
            f"< 50ms (no sleep should occur at all)."
        )


# =============================================================================
# CCS-04  isolated_env defaults the delay to 0
# =============================================================================

class TestIsolatedEnvDefaultsToZero:

    def test_CCS_04_isolated_env_sets_settle_seconds_to_zero(self, isolated_env):
        """CCS-04: Regression guard for the conftest.py override. If this
        ever regresses (e.g. someone removes the monkeypatch.setattr line in
        isolated_env), every other test in the suite that uses isolated_env
        silently gets ~1.5s slower per test instead of failing loudly — so
        we assert the override explicitly here."""
        rag = isolated_env.rag
        assert rag._CHROMA_COLD_INIT_SETTLE_SECONDS == 0, (
            "isolated_env is expected to default "
            "_CHROMA_COLD_INIT_SETTLE_SECONDS to 0 for test speed. Got "
            f"{rag._CHROMA_COLD_INIT_SETTLE_SECONDS!r} instead — check the "
            "monkeypatch.setattr call in tests/conftest.py's isolated_env "
            "fixture."
        )


# =============================================================================
# CCS-05  End-to-end regression: real indexing still works with the guard
# =============================================================================

class TestRealIndexingStillWorks:

    @pytest.mark.slow
    def test_CCS_05_index_file_list_produces_chunks_with_guard_in_place(
            self, isolated_env, small_text_file):
        """CCS-05: A real (sandboxed) end-to-end index_file_list() call —
        real chromadb.PersistentClient, real embedding model, real
        create_or_get_collection() — still succeeds and produces chunks with
        the new conditional-sleep branch present in get_chroma_client().
        settle seconds is 0 (isolated_env's default, verified by CCS-04) so
        this doesn't also pay the real 1.5s delay on top of model load —
        it's here to catch a logic/indentation bug in the guard itself, not
        to re-verify timing.

        Never touches the real installed AI-Prowler database: isolated_env
        has redirected CHROMA_DB_PATH to a pytest tmp_path.
        """
        rag = isolated_env.rag

        stats = rag.index_file_list(
            [str(small_text_file)],
            label="CCS-05",
            root_directory=str(small_text_file.parent),
        )

        assert stats["chunks"] > 0, (
            f"Expected at least one chunk to be indexed, got stats={stats}"
        )
        assert stats["processed"] == 1, (
            f"Expected exactly 1 file processed, got stats={stats}"
        )

        # Confirm the chunk actually landed in the sandboxed collection —
        # not just that index_file_list returned a plausible-looking dict.
        client, embedding_func = rag.get_chroma_client()
        collection = rag.create_or_get_collection(client, embedding_func)
        assert collection.count() >= stats["chunks"], (
            "Collection chunk count is lower than what index_file_list "
            "reported adding."
        )

        # Sanity check we really are in the sandbox, never in the real
        # installed database.
        real_prod_path = str(Path.home() / "AI-Prowler" / "rag_database")
        assert rag.CHROMA_DB_PATH != real_prod_path, (
            "CHROMA_DB_PATH points at the real production database — "
            "isolated_env failed to redirect it!"
        )
        assert str(isolated_env.tmp_path) in rag.CHROMA_DB_PATH, (
            f"CHROMA_DB_PATH ({rag.CHROMA_DB_PATH}) is not under this "
            f"test's tmp_path ({isolated_env.tmp_path})."
        )
