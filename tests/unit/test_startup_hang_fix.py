"""
tests/unit/test_startup_hang_fix.py
===================================
Cold-start hang on "Preparing embedding model…" (2026-10-19, David).

On a first start of the day the GUI sometimes froze on "Preparing embedding
model…" and the HTTP MCP server (started by a 6 s Tk timer) never came up; a
second start was fine. The index is 1.86 GB (rollback-journal SQLite). At
startup the Settings tab's "Index healthy" button ran a full PRAGMA
quick_check at 3 s while the embedding prewarm (4 s) opened ChromaDB on the
same file and then ran ANOTHER quick_check. Cold cache + Defender made the scans
slow enough to overlap ChromaDB's startup writes; native code waiting on the
reader's lock while holding the GIL froze the Tk loop.

The fix, tested here:
  SH-01..03  one quick_check at a time per process; its result is remembered
  SH-04..07  get_chroma_client(): integrity check BEFORE ChromaDB opens the
             file, one cold init at a time, timed steps to the startup log,
             corrupt index -> ChromaDB never opened
  SH-08..09  GUI: the "Index healthy" button reuses the prewarm's result and no
             longer starts its own scan on a 3 s timer
  SH-10..11  hang recorder: a frozen Tk loop dumps every thread's stack to
             hang_dump.log; a live loop never does
"""
from __future__ import annotations

import sqlite3
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

_SRC = Path(__file__).resolve().parents[2]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import rag_preprocessor as rp  # noqa: E402


def _make_db(path: Path):
    c = sqlite3.connect(path)
    c.execute("create table t(x)")
    c.executemany("insert into t values (?)", [(i,) for i in range(200)])
    c.commit()
    c.close()


# ══ quick_check: one at a time, result remembered ════════════════════════════

def test_SH_01_quick_checks_never_overlap(tmp_path):
    db = tmp_path / "chroma.sqlite3"
    _make_db(db)
    real_connect = sqlite3.connect
    active, peak, lock = [0], [0], threading.Lock()

    def slow_connect(*a, **k):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.15)
        try:
            return real_connect(*a, **k)
        finally:
            with lock:
                active[0] -= 1

    results = []
    with patch.object(sqlite3, "connect", slow_connect):
        ts = [threading.Thread(target=lambda: results.append(rp.sqlite_quick_check_ok(str(db))))
              for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(20)
    assert results == [True] * 4
    assert peak[0] == 1, f"{peak[0]} quick_checks ran at the same time"


def test_SH_02_result_is_remembered(tmp_path):
    good, bad, missing = tmp_path / "good.sqlite3", tmp_path / "bad.sqlite3", tmp_path / "none.sqlite3"
    _make_db(good)
    bad.write_bytes(b"this is not a database" * 100)
    assert rp.sqlite_quick_check_ok(str(good)) is True
    assert rp.sqlite_quick_check_ok(str(bad)) is False
    assert rp.sqlite_quick_check_ok(str(missing)) is True          # fresh install
    ok, at, secs = rp.last_quick_check_result(str(good))
    assert ok is True and abs(at - time.time()) < 60 and secs >= 0
    assert rp.last_quick_check_result(str(bad))[0] is False
    assert rp.last_quick_check_result(str(missing)) is None          # nothing was scanned


def test_SH_03_default_path_is_the_index_db(tmp_path):
    db = tmp_path / "chroma.sqlite3"
    _make_db(db)
    with patch.object(rp, "CHROMA_DB_PATH", str(tmp_path)):
        rp.sqlite_quick_check_ok(str(db))
        assert rp.last_quick_check_result()[0] is True


# ══ get_chroma_client(): order, single init, timed steps ═════════════════════

@pytest.fixture
def fake_init(tmp_path):
    """get_chroma_client() with ChromaDB and the model faked; records call order."""
    calls = []

    class FakeClient:
        def __init__(self, path):
            calls.append(("client", path))
            time.sleep(0.2)

    class FakeEmb:
        def __init__(self, name, device=None):
            calls.append(("model", name))

    def fake_check(db_path=None):
        calls.append(("integrity", db_path))

    with patch.object(rp, "_chroma_client_cache", None), \
            patch.object(rp, "_embedding_func_cache", None), \
            patch.object(rp, "_CHROMA_COLD_INIT_SETTLE_SECONDS", 0), \
            patch.object(rp, "CHROMA_DB_PATH", str(tmp_path)), \
            patch.object(rp.chromadb, "PersistentClient", FakeClient), \
            patch.object(rp, "_SentenceTransformerEmbedding", FakeEmb), \
            patch.object(rp, "get_best_embedding_device", lambda: "cpu"), \
            patch.object(rp, "check_chroma_db_integrity", fake_check):
        yield calls


def test_SH_04_integrity_check_runs_before_chromadb_opens(fake_init):
    client, emb = rp.get_chroma_client()
    order = [c[0] for c in fake_init]
    assert order == ["integrity", "client", "model"], order


def test_SH_05_one_cold_init_at_a_time(fake_init):
    got = []
    ts = [threading.Thread(target=lambda: got.append(rp.get_chroma_client())) for _ in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(20)
    assert [c[0] for c in fake_init].count("client") == 1, fake_init
    assert len(got) == 5 and all(g[0] is got[0][0] for g in got)


def test_SH_06_init_steps_reach_the_startup_log(fake_init):
    steps = []
    with patch.object(rp, "_INIT_STEP_HOOK", steps.append):
        rp.get_chroma_client()
    joined = " | ".join(steps)
    assert "integrity check OK" in joined and "ChromaDB opened" in joined and "embedding model" in joined
    assert steps.index(next(s for s in steps if "integrity check OK" in s)) < \
        steps.index(next(s for s in steps if "ChromaDB opened" in s))


def test_SH_07_corrupt_index_never_opens_chromadb(tmp_path):
    opened = []
    bad_dir = tmp_path / "idx"
    bad_dir.mkdir()
    (bad_dir / "chroma.sqlite3").write_bytes(b"not a database" * 500)
    with patch.object(rp, "_chroma_client_cache", None), \
            patch.object(rp, "_embedding_func_cache", None), \
            patch.object(rp, "_chroma_integrity_check_done", False), \
            patch.object(rp, "CHROMA_DB_PATH", str(bad_dir)), \
            patch.object(rp.chromadb, "PersistentClient", lambda path: opened.append(path)):
        with pytest.raises(rp.IndexCorruptError):
            rp.get_chroma_client()
    assert opened == [], "ChromaDB was opened on a corrupt index"


# ══ GUI: "Index healthy" button ══════════════════════════════════════════════

def _gui():
    return pytest.importorskip("rag_gui")


def test_SH_08_button_reuses_the_prewarm_result():
    rg = _gui()
    seen = []
    stub = SimpleNamespace(_set_corrupt_btn_state=lambda c: seen.append(("state", c)),
                           _check_index_integrity_async=lambda: seen.append(("scan", None)))
    with patch.object(rp, "last_quick_check_result", lambda p=None: (True, time.time(), 1.2)):
        rg.RAGGui._apply_startup_integrity_result(stub)
    assert seen == [("state", False)]                    # green, no second scan
    seen.clear()
    with patch.object(rp, "last_quick_check_result", lambda p=None: (False, time.time(), 1.2)):
        rg.RAGGui._apply_startup_integrity_result(stub)
    assert seen == [("state", True)]                     # red
    seen.clear()
    with patch.object(rp, "last_quick_check_result", lambda p=None: None):
        rg.RAGGui._apply_startup_integrity_result(stub)
    assert seen == [("scan", None)]                      # nothing cached -> normal check


def test_SH_09_no_parallel_scan_on_a_startup_timer():
    src = (_SRC / "rag_gui.py").read_text(encoding="utf-8")
    i = src.index("self._corrupt_btn = tk.Button(")
    block = src[i:i + 2500]
    timer = "self.root.after(3000, self._check_index_integrity_async)"
    assert timer in block and "if not RAG_AVAILABLE:" in block.split(timer)[0][-300:], \
        "the Settings check must only use the startup timer when there is no prewarm"
    j = src.index("elif msg_type == 'embedding_ready':")
    assert "_apply_startup_integrity_result()" in src[j:j + 1500]
    k = src.index("elif msg_type == 'embedding_ready_error':")
    assert "_apply_startup_integrity_result()" in src[k:k + 2000]


# ══ hang recorder ════════════════════════════════════════════════════════════

def _watchdog_stub(after):
    return SimpleNamespace(HANG_WATCHDOG_SECONDS=45, root=SimpleNamespace(after=after))


def test_SH_10_frozen_loop_writes_a_stack_dump(tmp_path):
    rg = _gui()
    stub = _watchdog_stub(after=lambda ms, fn: None)        # loop frozen: never re-arms
    try:
        rg.RAGGui._start_hang_watchdog(stub, timeout=1, log_dir=tmp_path, force=True)
        time.sleep(2.5)
    finally:
        rg.RAGGui._stop_hang_watchdog(stub)
        stub._hang_watchdog_file.close()
    txt = (tmp_path / "hang_dump.log").read_text(encoding="utf-8", errors="replace")
    assert "stopped responding for 1 s" in txt                 # header
    assert "Timeout (0:00:01)!" in txt and "Thread 0x" in txt and "File " in txt, txt[-600:]


def test_SH_11_live_loop_never_dumps(tmp_path):
    rg = _gui()
    stop = threading.Event()

    def after(ms, fn):                                    # a running loop: re-arm every 0.2 s
        if not stop.is_set():
            threading.Timer(0.2, fn).start()

    stub = _watchdog_stub(after=after)
    try:
        rg.RAGGui._start_hang_watchdog(stub, timeout=1, log_dir=tmp_path, force=True)
        time.sleep(2.5)
    finally:
        stop.set()
        time.sleep(0.3)
        rg.RAGGui._stop_hang_watchdog(stub)
        stub._hang_watchdog_file.close()
    txt = (tmp_path / "hang_dump.log").read_text(encoding="utf-8", errors="replace")
    assert "Timeout (" not in txt, txt[-600:]


def test_SH_12_watchdog_off_under_tests_unless_forced(tmp_path):
    rg = _gui()
    stub = _watchdog_stub(after=lambda ms, fn: None)
    rg.RAGGui._start_hang_watchdog(stub, timeout=1, log_dir=tmp_path)   # no force
    assert not (tmp_path / "hang_dump.log").exists()
    assert not hasattr(stub, "_hang_watchdog_file")
