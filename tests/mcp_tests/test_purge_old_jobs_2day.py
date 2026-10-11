"""
tests/mcp_tests/test_purge_old_jobs_2day.py
===========================================
(2026-10-08) 2-day auto-cleanup for the ~/.ai-prowler/jobs spool — David's
policy: no legitimate script run takes 2 days, so anything older than 48h is
deleted (manifest + log + wrapper triplet). A "running" manifest gets a PID
liveness check: dead/missing PID → deleted; live PID → taskkilled via
taskkill /F /T, then deleted. No keep_last floor.

purge_old_jobs() runs on every MCP server startup AND on each
run_script_start, so cleanup happens automatically.

Complements test_cleanup_job_logs.py, whose TestPurgeOldJobs section now
also asserts the 2-day policy (dead-PID running jobs deleted).

IMPORTANT: tqa.AI_PROWLER_HOME is monkeypatched to a tmp dir per test —
the real ~/.ai-prowler/jobs is never touched.

Run: run_tests.bat tests\\mcp_tests\\test_purge_old_jobs_2day.py -v
"""
import datetime
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import task_queue_automation as tqa


@pytest.fixture
def purge_home(tmp_path, monkeypatch):
    """Redirect tqa.AI_PROWLER_HOME to an isolated tmp dir for this test."""
    home = tmp_path / ".ai-prowler"
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", home)
    return home / "jobs"


def _make_triplet(jobs_dir, job_id, *, status="done", pid=None, age_days=0):
    """Create the manifest .json + .log + _wrapper.py triplet for a fake job.

    age_days back-dates the mtime of all three files (purge_old_jobs keys
    off the manifest's mtime, not its started_at field).
    """
    assert job_id.startswith("job_"), "purge globs job_*.json"
    jobs_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"job_id": job_id, "status": status}
    if pid is not None:
        manifest["pid"] = pid
    mani = jobs_dir / f"{job_id}.json"
    log = jobs_dir / f"{job_id}.log"
    wrap = jobs_dir / f"{job_id}_wrapper.py"
    mani.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    log.write_text("fake stdout\n", encoding="utf-8")
    wrap.write_text("# fake wrapper\n", encoding="utf-8")
    if age_days:
        old = (datetime.datetime.now()
               - datetime.timedelta(days=age_days)).timestamp()
        for p in (mani, log, wrap):
            os.utime(p, (old, old))
    return mani, log, wrap


def _triplet_exists(jobs_dir, job_id):
    return [(jobs_dir / f"{job_id}{ext}").exists()
            for ext in (".json", ".log", "_wrapper.py")]


# ── Default policy ────────────────────────────────────────────────────────

def test_default_max_age_days_is_two():
    sig = inspect.signature(tqa.purge_old_jobs)
    assert sig.parameters["max_age_days"].default == 2


# ── Old vs recent ─────────────────────────────────────────────────────────

def test_old_triplet_all_three_files_deleted(purge_home):
    mani, log, wrap = _make_triplet(purge_home, "job_old", age_days=3)
    deleted = tqa.purge_old_jobs()  # default max_age_days=2
    assert deleted == 1
    assert not mani.exists()
    assert not log.exists()
    assert not wrap.exists()


def test_recent_triplet_is_kept(purge_home):
    _make_triplet(purge_home, "job_recent", age_days=1)
    deleted = tqa.purge_old_jobs()
    assert deleted == 0
    assert _triplet_exists(purge_home, "job_recent") == [True, True, True]


def test_old_and_recent_side_by_side(purge_home):
    _make_triplet(purge_home, "job_old", age_days=3)
    _make_triplet(purge_home, "job_new", age_days=1)
    deleted = tqa.purge_old_jobs()
    assert deleted == 1
    assert _triplet_exists(purge_home, "job_old") == [False, False, False]
    assert _triplet_exists(purge_home, "job_new") == [True, True, True]


# ── Running manifests: PID liveness ───────────────────────────────────────

_DEAD_PID = 2147483647  # 2**31 - 1: tasklist will never list this PID


def test_running_manifest_with_dead_pid_is_deleted(purge_home):
    # The 2026-10-08 policy change: "running" no longer protects a job —
    # a dead PID means the run is over, so the triplet is purged.
    _make_triplet(purge_home, "job_zombie", status="running",
                  pid=_DEAD_PID, age_days=3)
    deleted = tqa.purge_old_jobs()
    assert deleted == 1
    assert _triplet_exists(purge_home, "job_zombie") == [False, False, False]


def test_running_manifest_with_missing_pid_is_deleted(purge_home):
    _make_triplet(purge_home, "job_nopid", status="running", age_days=3)
    deleted = tqa.purge_old_jobs()
    assert deleted == 1
    assert _triplet_exists(purge_home, "job_nopid") == [False, False, False]


@pytest.mark.skipif(sys.platform != "win32",
                    reason="taskkill/tasklist are Windows-only")
def test_running_manifest_with_live_pid_is_taskkilled_then_deleted(purge_home):
    # Spawn a real (sleeping) child, then purge: the policy kills the live
    # PID via taskkill /F /T before deleting the triplet.
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert child.poll() is None  # sanity: it really is alive
        _make_triplet(purge_home, "job_live", status="running",
                      pid=child.pid, age_days=3)
        deleted = tqa.purge_old_jobs()
        assert deleted == 1
        assert child.poll() is not None, "live PID must be taskkilled"
        assert _triplet_exists(purge_home, "job_live") == [False, False, False]
    finally:
        if child.poll() is None:
            child.kill()


# ── Orphaned wrappers (no manifest) ──────────────────────────────────────

def test_orphaned_old_wrapper_is_deleted(purge_home):
    # Backlog from the old missing-wrapper-deletion bug: wrapper with no
    # manifest left to key off. Aged off by its own mtime.
    purge_home.mkdir(parents=True, exist_ok=True)
    wrap = purge_home / "job_orphan_wrapper.py"
    wrap.write_text("# orphan\n", encoding="utf-8")
    old = (datetime.datetime.now()
           - datetime.timedelta(days=3)).timestamp()
    os.utime(wrap, (old, old))
    tqa.purge_old_jobs()
    assert not wrap.exists()


def test_orphaned_recent_wrapper_is_kept(purge_home):
    purge_home.mkdir(parents=True, exist_ok=True)
    wrap = purge_home / "job_orphan_new_wrapper.py"
    wrap.write_text("# orphan\n", encoding="utf-8")
    tqa.purge_old_jobs()
    assert wrap.exists()


# ── Return count ──────────────────────────────────────────────────────────

def test_return_count_counts_purged_jobs_only(purge_home):
    _make_triplet(purge_home, "job_old_a", age_days=3)
    _make_triplet(purge_home, "job_old_b", age_days=5)
    _make_triplet(purge_home, "job_new", age_days=1)
    # An orphaned old wrapper is deleted too, but does NOT count as a job.
    purge_home.mkdir(parents=True, exist_ok=True)
    orphan = purge_home / "job_orphan_wrapper.py"
    orphan.write_text("# orphan\n", encoding="utf-8")
    old = (datetime.datetime.now()
           - datetime.timedelta(days=3)).timestamp()
    os.utime(orphan, (old, old))

    assert tqa.purge_old_jobs() == 2
    assert not orphan.exists()
    assert _triplet_exists(purge_home, "job_new") == [True, True, True]


# ── Best-effort: never raises ─────────────────────────────────────────────

def test_missing_jobs_dir_returns_zero_never_raises(purge_home):
    assert not purge_home.exists()
    assert tqa.purge_old_jobs() == 0
    assert not purge_home.exists()


def test_corrupt_manifest_old_mtime_purged_never_raises(purge_home):
    purge_home.mkdir(parents=True, exist_ok=True)
    bad = purge_home / "job_corrupt.json"
    bad.write_text("{not valid json", encoding="utf-8")
    old = (datetime.datetime.now()
           - datetime.timedelta(days=3)).timestamp()
    os.utime(bad, (old, old))
    assert tqa.purge_old_jobs() == 1  # unreadable → purged anyway
    assert not bad.exists()


def test_unlink_failure_never_raises(purge_home, monkeypatch):
    _make_triplet(purge_home, "job_old", age_days=3)

    def _boom(*a, **kw):
        raise OSError("simulated permission denied")

    monkeypatch.setattr(Path, "unlink", _boom)
    tqa.purge_old_jobs()  # must not raise
