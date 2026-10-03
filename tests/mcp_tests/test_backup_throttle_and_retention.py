"""
tests/mcp_tests/test_backup_throttle_and_retention.py
===================================================
Real problem found live: 77 near-identical automatic per-write backups
(~13.5 MB) accumulated in under 2 days because the old keep_days=30
default meant nothing pruned yet at any realistic write volume. Fixes
_backup_job_db() with a throttle (skip if a recent-enough backup already
exists) and tighter, count-floored retention.

Run with:
    run_tests.bat tests\\mcp\\test_backup_throttle_and_retention.py -v
"""
from __future__ import annotations

import os
import sys
import time
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


def _make_fake_db(path):
    with open(path, "w") as f:
        f.write("fake db content")


def test_backup_creates_a_file(mcp_mod, tmp_path):
    db_path = str(tmp_path / "ai_prowler_jobs.db")
    _make_fake_db(db_path)
    result = mcp_mod._backup_job_db(db_path)
    assert result.startswith("Backup saved:")
    backups_dir = tmp_path / "backup"
    assert backups_dir.is_dir()
    assert len(list(backups_dir.iterdir())) == 1


def test_throttle_skips_rapid_successive_backups(mcp_mod, tmp_path):
    """The core fix: a burst of writes in quick succession (exactly what
    normal use looks like — several field edits, a quote then an
    invoice) must produce ONE backup, not one per write."""
    db_path = str(tmp_path / "ai_prowler_jobs.db")
    _make_fake_db(db_path)

    first = mcp_mod._backup_job_db(db_path, min_interval_seconds=120)
    assert first.startswith("Backup saved:")

    # Immediately call again — should be throttled (empty string, not a
    # new "Backup saved:" message).
    second = mcp_mod._backup_job_db(db_path, min_interval_seconds=120)
    assert second == ""

    backups_dir = tmp_path / "backup"
    assert len(list(backups_dir.iterdir())) == 1  # still just the one


def test_throttle_allows_backup_after_interval_elapses(mcp_mod, tmp_path):
    db_path = str(tmp_path / "ai_prowler_jobs.db")
    _make_fake_db(db_path)

    first = mcp_mod._backup_job_db(db_path, min_interval_seconds=0)
    assert first.startswith("Backup saved:")
    time.sleep(0.05)
    second = mcp_mod._backup_job_db(db_path, min_interval_seconds=0)
    assert second.startswith("Backup saved:")

    backups_dir = tmp_path / "backup"
    assert len(list(backups_dir.iterdir())) == 2


def test_retention_keeps_at_least_keep_last_even_if_old(mcp_mod, tmp_path):
    """A quiet stretch with no writes for days must never leave zero
    backups just because everything crossed keep_days at once."""
    db_path = str(tmp_path / "ai_prowler_jobs.db")
    _make_fake_db(db_path)
    backups_dir = tmp_path / "backup"
    backups_dir.mkdir()

    # Simulate 5 old backups (mtime far in the past).
    old_time = time.time() - (10 * 86400)  # 10 days old
    for i in range(5):
        p = backups_dir / f"ai_prowler_jobs_old_{i}.db"
        p.write_text("old backup")
        os.utime(p, (old_time, old_time))

    # New backup triggers a retention pass with keep_days=2, keep_last=3.
    mcp_mod._backup_job_db(db_path, keep_days=2, keep_last=3, min_interval_seconds=0)

    remaining = list(backups_dir.iterdir())
    # At least keep_last (3) files must survive, even though they're all
    # technically past keep_days — the newest one just created plus
    # enough of the old ones to reach the floor.
    assert len(remaining) >= 3


def test_retention_prunes_old_beyond_keep_last(mcp_mod, tmp_path):
    db_path = str(tmp_path / "ai_prowler_jobs.db")
    _make_fake_db(db_path)
    backups_dir = tmp_path / "backup"
    backups_dir.mkdir()

    old_time = time.time() - (10 * 86400)
    for i in range(10):
        p = backups_dir / f"ai_prowler_jobs_old_{i}.db"
        p.write_text("old backup")
        os.utime(p, (old_time - i, old_time - i))  # stagger mtimes

    mcp_mod._backup_job_db(db_path, keep_days=2, keep_last=3, min_interval_seconds=0)

    remaining = list(backups_dir.iterdir())
    # 10 old + 1 new = 11 total before pruning; keep_last=3 floor means
    # at most 3 survive (all past keep_days).
    assert len(remaining) == 3


def test_nonexistent_db_returns_blank(mcp_mod, tmp_path):
    result = mcp_mod._backup_job_db(str(tmp_path / "does_not_exist.db"))
    assert result == ""


def test_different_databases_dont_cross_throttle(mcp_mod, tmp_path):
    """Two different db base names (e.g. a per-user sibling database)
    must not throttle each other — each has its own independent
    freshest-backup check."""
    db_a = str(tmp_path / "ai_prowler_jobs.db")
    db_b = str(tmp_path / "jake-r.db")
    _make_fake_db(db_a)
    _make_fake_db(db_b)

    result_a = mcp_mod._backup_job_db(db_a, min_interval_seconds=120)
    result_b = mcp_mod._backup_job_db(db_b, min_interval_seconds=120)
    assert result_a.startswith("Backup saved:")
    assert result_b.startswith("Backup saved:")


def test_pruning_never_touches_manual_or_scheduled_backup_files(mcp_mod, tmp_path):
    """2026-09-16 fix: after consolidating this folder with
    db_backup_database's own default folder (manual "Backup Now"/
    scheduled/pre-delete-safety backups all land here too, named
    "AI-Prowler-Backup-<timestamp>.db"), the retention pass used to list
    EVERY file in the folder with no name filter — unlike the throttle
    check, which already scoped itself to this function's own
    "{base}_<timestamp>.db" files. A real, if dormant, bug: an old
    manual/scheduled backup could get silently deleted by a pass that
    never created it. This asserts the fix directly — an old,
    non-matching file must survive even when it's the only thing that
    would otherwise be pruned."""
    db_path = str(tmp_path / "ai_prowler_jobs.db")
    _make_fake_db(db_path)
    backups_dir = tmp_path / "backup"
    backups_dir.mkdir()

    # A manual/scheduled-style backup file — old enough and alone enough
    # that the old, unfiltered code would have deleted it as soon as a
    # new per-write backup pushed the count past keep_last.
    manual_backup = backups_dir / "AI-Prowler-Backup-20200101_000000.db"
    manual_backup.write_text("manual backup — must never be touched")
    old_time = time.time() - (10 * 86400)
    os.utime(manual_backup, (old_time, old_time))

    mcp_mod._backup_job_db(db_path, keep_days=2, keep_last=0, min_interval_seconds=0)

    assert manual_backup.exists(), "pruning deleted a backup it never created"
    assert manual_backup.read_text() == "manual backup — must never be touched"
