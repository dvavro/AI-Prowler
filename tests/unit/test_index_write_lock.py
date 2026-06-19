"""
tests/unit/test_index_write_lock.py
====================================
Tests for the _index_write_lock serialisation that prevents concurrent
ChromaDB writes from the MCP server and the file watchdog daemon.

Test IDs: WL-01 to WL-05

Background
----------
rag_preprocessor.index_file_list() acquires _index_write_lock (an RLock)
before touching ChromaDB.  The file watchdog daemon (file_watchdog.py) and
MCP tool calls both call index_file_list() — potentially from different OS
threads at the same time.  Without this lock their delete+add sequences can
interleave, producing duplicate chunks or HNSW index corruption.

What these tests verify
-----------------------
  WL-01  Mutual exclusion: a second thread calling index_file_list()
         blocks until the first thread's call finishes.

  WL-02  Serialisation order: two concurrent callers produce no interleaving
         of their ChromaDB operations (all of caller A's ops complete before
         any of caller B's ops start).

  WL-03  Error safety: the lock is always released even when index_file_list()
         raises an exception — no deadlock on error paths.

  WL-04  Reentrancy: the same thread can call index_file_list() recursively
         (RLock) without deadlocking itself.

  WL-05  Lock is exported: _index_write_lock is accessible from rag_preprocessor
         so the watchdog can check it in tests without private name mangling.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# ── Locate rag_preprocessor ───────────────────────────────────────────────────
SRC_ROOT = Path(__file__).parent.parent.parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

import rag_preprocessor as rp


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def fake_rp_env(tmp_path, monkeypatch):
    """
    Patch out the heavy parts of rag_preprocessor so index_file_list()
    runs fast without real ChromaDB or embedding models.

    The mock _index_file_list_impl records call start/finish times so
    concurrency tests can inspect the call timeline.
    """
    call_log: list[dict] = []   # filled by the mock impl

    def _slow_impl(*args, **kwargs):
        """Simulates a slow indexing operation (50ms) and records timing."""
        thread_name = threading.current_thread().name
        call_log.append({"thread": thread_name, "event": "start",
                         "time": time.monotonic()})
        time.sleep(0.05)  # simulate work (50 ms)
        call_log.append({"thread": thread_name, "event": "finish",
                         "time": time.monotonic()})
        return {"processed": 1, "skipped": 0, "chunks": 2,
                "words": 10, "stopped_at": 0}

    monkeypatch.setattr(rp, "_index_file_list_impl", _slow_impl)

    # Also stub get_chroma_client so the real lock path never hits ChromaDB
    mock_client = MagicMock()
    mock_ef = MagicMock()
    monkeypatch.setattr(rp, "get_chroma_client", lambda: (mock_client, mock_ef))

    # Provide a real temp file so path checks in _slow_impl don't trip
    test_file = tmp_path / "doc.txt"
    test_file.write_text("hello", encoding="utf-8")

    return SimpleNamespace(call_log=call_log, test_file=test_file,
                           tmp_path=tmp_path)


# =============================================================================
# WL-01  Mutual exclusion
# =============================================================================

class TestMutualExclusion:

    def test_WL_01_second_thread_blocks_until_first_finishes(self, fake_rp_env):
        """WL-01: A thread calling index_file_list blocks until the holder finishes."""
        env = fake_rp_env

        thread_a_holding = threading.Event()   # set when A has the lock
        thread_b_started  = threading.Event()  # set when B has been launched
        results: dict      = {}

        def thread_a():
            # Acquire the lock directly to hold it while B tries to enter
            with rp._index_write_lock:
                thread_a_holding.set()
                time.sleep(0.1)   # hold for 100ms — B should block here
            results["a_done"] = time.monotonic()

        def thread_b():
            thread_b_started.set()
            t_start = time.monotonic()
            rp.index_file_list([str(env.test_file)])
            results["b_done"]  = time.monotonic()
            results["b_wait"]  = results["b_done"] - t_start

        ta = threading.Thread(target=thread_a, name="A", daemon=True)
        tb = threading.Thread(target=thread_b, name="B", daemon=True)

        ta.start()
        thread_a_holding.wait(timeout=2)   # wait until A holds the lock
        tb.start()
        thread_b_started.wait(timeout=2)

        ta.join(timeout=3)
        tb.join(timeout=3)

        assert "a_done" in results, "Thread A did not finish"
        assert "b_done" in results, "Thread B did not finish"

        # B must have waited at least 50ms (A held lock for ~100ms)
        assert results["b_wait"] >= 0.04, \
            f"Thread B did not block — wait was only {results['b_wait']*1000:.1f}ms"

        # B must finish AFTER A released the lock
        assert results["b_done"] > results["a_done"] - 0.01, \
            "Thread B finished before Thread A released the lock"


# =============================================================================
# WL-02  Serialisation order — no interleaving
# =============================================================================

class TestSerialisationOrder:

    def test_WL_02_concurrent_calls_do_not_interleave(self, fake_rp_env):
        """WL-02: Two concurrent index_file_list calls execute sequentially."""
        env = fake_rp_env

        errors: list[str] = []

        def caller(name: str):
            try:
                rp.index_file_list([str(env.test_file)],
                                   label=name)
            except Exception as exc:
                errors.append(f"{name}: {exc}")

        threads = [
            threading.Thread(target=caller, args=(f"caller-{i}",), daemon=True)
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Errors during concurrent calls: {errors}"

        # Verify no interleaving: every "start" from thread X is followed by
        # "finish" from the SAME thread X before any other thread starts.
        log = env.call_log
        assert len(log) == 8, f"Expected 8 log entries (4 start+finish), got {len(log)}"

        for i in range(0, len(log), 2):
            start_entry  = log[i]
            finish_entry = log[i + 1]
            assert start_entry["event"]  == "start",  \
                f"Entry {i} should be 'start': {start_entry}"
            assert finish_entry["event"] == "finish", \
                f"Entry {i+1} should be 'finish': {finish_entry}"
            assert start_entry["thread"] == finish_entry["thread"], \
                (f"Interleaving detected: start from {start_entry['thread']} "
                 f"followed by finish from {finish_entry['thread']}")


# =============================================================================
# WL-03  Error safety — lock released on exception
# =============================================================================

class TestErrorSafety:

    def test_WL_03_lock_released_after_exception(self, monkeypatch):
        """WL-03: Lock is released even when _index_file_list_impl raises."""
        def _raising_impl(*args, **kwargs):
            raise RuntimeError("simulated ChromaDB failure")

        monkeypatch.setattr(rp, "_index_file_list_impl", _raising_impl)
        monkeypatch.setattr(rp, "get_chroma_client",
                            lambda: (MagicMock(), MagicMock()))

        with pytest.raises(RuntimeError, match="simulated ChromaDB failure"):
            rp.index_file_list(["dummy.txt"])

        # The lock must be acquirable immediately — not stuck
        acquired = rp._index_write_lock.acquire(blocking=False)
        assert acquired, "Lock was NOT released after exception — deadlock risk!"
        rp._index_write_lock.release()


# =============================================================================
# WL-04  Reentrancy — same thread can re-enter (RLock)
# =============================================================================

class TestReentrancy:

    def test_WL_04_same_thread_reentrant(self, monkeypatch):
        """WL-04: Same thread can acquire the RLock twice without deadlocking."""
        call_count = {"n": 0}

        def _reentrant_impl(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call re-enters index_file_list from within the lock
                rp.index_file_list(["inner.txt"])
            return {"processed": 1, "skipped": 0, "chunks": 1,
                    "words": 1, "stopped_at": 0}

        monkeypatch.setattr(rp, "_index_file_list_impl", _reentrant_impl)
        monkeypatch.setattr(rp, "get_chroma_client",
                            lambda: (MagicMock(), MagicMock()))

        # Should not deadlock (RLock allows same-thread re-entry)
        result = rp.index_file_list(["outer.txt"])
        assert call_count["n"] == 2, \
            f"Expected 2 impl calls (outer + inner), got {call_count['n']}"


# =============================================================================
# WL-05  Lock is exported from rag_preprocessor
# =============================================================================

class TestLockExported:

    def test_WL_05_lock_attribute_exists(self):
        """WL-05: _index_write_lock is accessible from rag_preprocessor."""
        assert hasattr(rp, "_index_write_lock"), \
            "_index_write_lock not found on rag_preprocessor module"
        lock = rp._index_write_lock
        # Must be an RLock-like object (has acquire/release)
        assert callable(getattr(lock, "acquire", None)), \
            "_index_write_lock has no acquire() method"
        assert callable(getattr(lock, "release", None)), \
            "_index_write_lock has no release() method"
        # Must be currently unlocked (acquirable without blocking)
        acquired = lock.acquire(blocking=False)
        assert acquired, "_index_write_lock is locked at module load time!"
        lock.release()
