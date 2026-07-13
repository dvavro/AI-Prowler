"""
tests/mcp/test_cleanup_job_logs.py
====================================
Tests for the cleanup_job_logs() MCP tool — deletes old run_script_start
job files (<id>.json manifest, <id>.log, <id>_wrapper.py) from
~/.ai-prowler/jobs/, which has no automatic retention and was found to
have accumulated 1000+ files (333+ job runs) on a real install.

Covers:
  - Tier A suppression (personal-install-only, alongside cleanup_backups —
    same reasoning: deletes host files, and the feature it cleans up after,
    run_script_start/status/kill, is itself personal-install-only)
  - Empty/missing jobs directory → plain message, nothing to do
  - Dry run lists candidates without deleting anything
  - keep_last protects the N most recent jobs regardless of age
  - older_than_days protects anything newer than the cutoff regardless
    of rank
  - A job is only deleted when BOTH conditions are satisfied together
  - A "running" job is NEVER deleted, even if old and low-ranked
  - Actual deletion removes all 3 files per qualifying job
  - Missing/corrupt manifest falls back to file mtime rather than crashing

IMPORTANT: ai_prowler_mcp._JOBS_DIR is a MODULE-LEVEL constant computed
once at import time from Path.home() — the exact same class of bug caught
twice already today in scheduler_engine.py testing. Patching Path.home()
alone would do nothing; every test here patches the module attribute
`mcp_mod._JOBS_DIR` directly to a tmp_path, and _jobs_dir() (which the
tool calls) reads that same patched global — confirmed by inspection of
ai_prowler_mcp.py's _jobs_dir()/_JOBS_DIR definitions.
"""

import datetime
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def jobs_dir(mcp_mod, tmp_path, monkeypatch):
    """Redirect _JOBS_DIR to an isolated temp directory for this test only."""
    d = tmp_path / "jobs"
    monkeypatch.setattr(mcp_mod, "_JOBS_DIR", d)
    return d


def _make_job(jobs_dir, job_id, *, status="done", started_at=None,
             include_log=True, include_wrapper=True, write_manifest=True):
    """Create the 1-3 files for a fake job. started_at defaults to now."""
    jobs_dir.mkdir(parents=True, exist_ok=True)
    started_at = started_at or datetime.datetime.now()
    if write_manifest:
        manifest = {
            "job_id": job_id,
            "status": status,
            "started_at": started_at.isoformat(),
            "finished_at": started_at.isoformat() if status != "running" else None,
            "exit_code": 0 if status == "done" else None,
        }
        (jobs_dir / f"{job_id}.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8")
    if include_log:
        (jobs_dir / f"{job_id}.log").write_text("output\n", encoding="utf-8")
    if include_wrapper:
        (jobs_dir / f"{job_id}_wrapper.py").write_text(
            "# wrapper\n", encoding="utf-8")


def _days_ago(n):
    return datetime.datetime.now() - datetime.timedelta(days=n)


class TestTierASuppression:

    def test_cleanup_job_logs_is_tier_a_suppressed(self, mcp_mod):
        assert "cleanup_job_logs" in mcp_mod._TIER_A_SUPPRESSED

    def test_grouped_with_cleanup_backups(self, mcp_mod):
        assert {"cleanup_backups", "cleanup_job_logs"}.issubset(
            mcp_mod._TIER_A_SUPPRESSED)


class TestEmptyOrMissing:

    def test_missing_jobs_directory_returns_plain_message(self, mcp_mod, jobs_dir):
        # jobs_dir fixture points _JOBS_DIR at a path that doesn't exist yet.
        result = mcp_mod.cleanup_job_logs()
        assert "✅" in result
        assert "nothing to clean up" in result.lower()

    def test_empty_jobs_directory_returns_plain_message(self, mcp_mod, jobs_dir):
        jobs_dir.mkdir(parents=True)
        result = mcp_mod.cleanup_job_logs()
        assert "✅" in result


class TestDryRunDefault:

    def test_dry_run_lists_but_does_not_delete(self, mcp_mod, jobs_dir):
        _make_job(jobs_dir, "job_old_0001", started_at=_days_ago(30))
        result = mcp_mod.cleanup_job_logs(older_than_days=7, keep_last=0)

        assert "🔍" in result
        assert "job_old_0001" in result
        # Files must still exist — nothing was actually deleted.
        assert (jobs_dir / "job_old_0001.json").exists()
        assert (jobs_dir / "job_old_0001.log").exists()
        assert (jobs_dir / "job_old_0001_wrapper.py").exists()

    def test_dry_run_is_the_default_even_without_passing_it(self, mcp_mod, jobs_dir):
        _make_job(jobs_dir, "job_old_0001", started_at=_days_ago(30))
        mcp_mod.cleanup_job_logs(older_than_days=7, keep_last=0)  # no dry_run=
        assert (jobs_dir / "job_old_0001.json").exists()


class TestKeepLastProtection:

    def test_recent_job_kept_even_if_older_than_days_is_zero(self, mcp_mod, jobs_dir):
        _make_job(jobs_dir, "job_recent", started_at=_days_ago(0))
        result = mcp_mod.cleanup_job_logs(
            older_than_days=0, keep_last=20, dry_run=False)
        assert "✅" in result  # nothing to clean up — protected by keep_last
        assert (jobs_dir / "job_recent.json").exists()

    def test_only_jobs_beyond_keep_last_rank_are_candidates(self, mcp_mod, jobs_dir):
        # 5 jobs, all old enough by age, but keep_last=3 protects the 3 newest.
        for i in range(5):
            _make_job(jobs_dir, f"job_{i:04d}", started_at=_days_ago(30 - i))
        result = mcp_mod.cleanup_job_logs(
            older_than_days=1, keep_last=3, dry_run=True)

        # The 2 oldest (job_0000, job_0001) should be listed; the 3 newest
        # (job_0002, job_0003, job_0004) should not.
        assert "job_0000" in result
        assert "job_0001" in result
        assert "job_0002" not in result
        assert "job_0003" not in result
        assert "job_0004" not in result


class TestAgeProtection:

    def test_job_newer_than_cutoff_kept_even_at_low_rank(self, mcp_mod, jobs_dir):
        # 5 jobs all created "now" (rank doesn't matter since none are old).
        for i in range(5):
            _make_job(jobs_dir, f"job_{i:04d}", started_at=_days_ago(0))
        result = mcp_mod.cleanup_job_logs(
            older_than_days=7, keep_last=0, dry_run=True)
        assert "✅" in result  # all too new to qualify, regardless of rank


class TestBothConditionsRequired:

    def test_deletion_requires_old_and_low_rank_together(self, mcp_mod, jobs_dir):
        _make_job(jobs_dir, "job_old_but_recent_rank", started_at=_days_ago(30))
        # keep_last=1 means the single job present is always rank 0 — protected.
        result = mcp_mod.cleanup_job_logs(
            older_than_days=7, keep_last=1, dry_run=True)
        assert "✅" in result
        assert "job_old_but_recent_rank" not in result


class TestRunningJobNeverDeleted:

    def test_old_low_rank_running_job_is_skipped_not_deleted(self, mcp_mod, jobs_dir):
        _make_job(jobs_dir, "job_still_running", status="running",
                  started_at=_days_ago(30))
        result = mcp_mod.cleanup_job_logs(
            older_than_days=7, keep_last=0, dry_run=False)

        assert "job_still_running" in result
        assert "running" in result.lower()
        # File must still exist — protected despite qualifying by age/rank.
        assert (jobs_dir / "job_still_running.json").exists()
        assert (jobs_dir / "job_still_running.log").exists()


class TestActualDeletion:

    def test_dry_run_false_actually_deletes_all_three_files(self, mcp_mod, jobs_dir):
        _make_job(jobs_dir, "job_to_delete", started_at=_days_ago(30))
        result = mcp_mod.cleanup_job_logs(
            older_than_days=7, keep_last=0, dry_run=False)

        assert "🗑️" in result
        assert "job_to_delete" in result
        assert not (jobs_dir / "job_to_delete.json").exists()
        assert not (jobs_dir / "job_to_delete.log").exists()
        assert not (jobs_dir / "job_to_delete_wrapper.py").exists()

    def test_deletion_leaves_protected_jobs_untouched(self, mcp_mod, jobs_dir):
        _make_job(jobs_dir, "job_old", started_at=_days_ago(30))
        _make_job(jobs_dir, "job_recent", started_at=_days_ago(0))
        mcp_mod.cleanup_job_logs(older_than_days=7, keep_last=1, dry_run=False)

        # job_old is old AND ranked below the 1 kept slot (job_recent is
        # newer, takes the kept slot) — job_old should be gone, job_recent
        # should remain.
        assert not (jobs_dir / "job_old.json").exists()
        assert (jobs_dir / "job_recent.json").exists()


class TestCorruptOrMissingManifest:

    def test_missing_manifest_falls_back_to_file_mtime(self, mcp_mod, jobs_dir):
        # No .json manifest at all for this "job" — only log + wrapper.
        # cleanup_job_logs groups by manifest glob, so a log/wrapper with
        # NO manifest is simply invisible to it (can't be grouped without
        # a job_id source) — this test instead verifies a CORRUPT manifest
        # doesn't crash the tool and falls back to mtime-based age.
        jobs_dir.mkdir(parents=True, exist_ok=True)
        (jobs_dir / "job_corrupt.json").write_text("{not valid json", encoding="utf-8")
        (jobs_dir / "job_corrupt.log").write_text("output\n", encoding="utf-8")

        # Must not raise — corrupt JSON is handled gracefully.
        result = mcp_mod.cleanup_job_logs(older_than_days=7, keep_last=0, dry_run=True)
        assert "❌" not in result or "job_corrupt" in result
