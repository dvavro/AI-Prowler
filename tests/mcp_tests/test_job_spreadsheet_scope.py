"""
tests/mcp_tests/test_job_spreadsheet_scope.py
=========================================
Tests for server-mode job-spreadsheet path resolution and write locking.

Background
----------
read_job_spreadsheet, update_job_spreadsheet, email_invoice,
schedule_next_recurring_job, log_time_entry, and get_ar_aging_report
previously accepted a raw `filepath` argument with ZERO access control —
any server-mode role could point them at an arbitrary .xlsx file anywhere
on the host filesystem.

Server mode now ignores the filepath argument entirely and always uses the
one shared SQLite job database (_resolve_job_db_path; Section D below). The
old _resolve_job_spreadsheet_path() and its per-user "<user_id>.xlsx" files
were removed with R-046 (2026-09-28).

_spreadsheet_write_lock (an RLock, mirroring rag_preprocessor.py's
_index_write_lock) serialises the load->modify->save cycle in
update_job_spreadsheet, schedule_next_recurring_job, and log_time_entry
so two concurrent server-mode writers can never interleave and silently
drop each other's changes.
"""

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _server_user(uid="jake-r"):
    return {
        "id": uid, "name": "Jake R", "role": "field_crew",
        "status": "active", "scopes": [],
    }


# Sections A/B (tests of _resolve_job_spreadsheet_path, incl. per-user
# "<user_id>.xlsx" files) removed 2026-09-28 with R-046: that resolver had no
# callers left after the SQLite move, and per-user job files are gone — every
# server-mode user shares the one job database.

# ═══════════════════════════════════════════════════════════════════════════
# SECTION C — _spreadsheet_write_lock
# ═══════════════════════════════════════════════════════════════════════════

class TestSpreadsheetWriteLock:

    def test_C01_lock_exists_and_is_reentrant(self, mcp_mod):
        assert hasattr(mcp_mod, "_spreadsheet_write_lock")
        # RLock: acquiring twice from the same thread must not deadlock.
        acquired_twice = mcp_mod._spreadsheet_write_lock.acquire(timeout=2)
        assert acquired_twice
        try:
            acquired_again = mcp_mod._spreadsheet_write_lock.acquire(timeout=2)
            assert acquired_again
            mcp_mod._spreadsheet_write_lock.release()
        finally:
            mcp_mod._spreadsheet_write_lock.release()

    def test_C02_second_thread_blocks_until_first_releases(self, mcp_mod):
        """Mutual exclusion: two threads racing for the lock must run one
        at a time, never both inside the critical section simultaneously."""
        lock = mcp_mod._spreadsheet_write_lock
        events = []
        barrier_entered = threading.Event()

        def worker(name, hold_seconds):
            with lock:
                events.append(f"{name}-enter")
                if name == "first":
                    barrier_entered.set()
                    time.sleep(hold_seconds)
                events.append(f"{name}-exit")

        t1 = threading.Thread(target=worker, args=("first", 0.3))
        t1.start()
        barrier_entered.wait(timeout=2)
        t2 = threading.Thread(target=worker, args=("second", 0))
        t2.start()
        t1.join(timeout=3)
        t2.join(timeout=3)

        # "first" must fully exit before "second" enters — no interleaving.
        assert events == ["first-enter", "first-exit", "second-enter", "second-exit"]

    def test_C03_lock_released_after_exception(self, mcp_mod):
        """A crash inside the critical section must not leave the lock
        held forever (would deadlock every future spreadsheet write)."""
        lock = mcp_mod._spreadsheet_write_lock
        with pytest.raises(ValueError):
            with lock:
                raise ValueError("simulated write failure")
        # Lock must be free again — acquiring with a short timeout must succeed.
        acquired = lock.acquire(timeout=1)
        assert acquired
        lock.release()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION D — Integration: update_job_spreadsheet ignores filepath in server mode
# ═══════════════════════════════════════════════════════════════════════════

class TestUpdateJobSpreadsheetIntegration:

    def test_D01_server_mode_ignores_custom_filepath_argument(self, mcp_mod, monkeypatch, tmp_path):
        """End-to-end: a server-mode caller cannot redirect
        update_job_spreadsheet to an arbitrary file via the filepath arg —
        it always resolves through _resolve_job_db_path() (the DB-backed
        sibling of _resolve_job_spreadsheet_path(), Job Board Architecture
        Spec Phase 1). update_job_spreadsheet's internals now write to the
        SQLite job store next to whatever _get_default_spreadsheet_path()
        points at, rather than the .xlsx file itself, so this seeds a job
        directly into that db instead of into an .xlsx workbook."""
        from db_access import init_db
        from db_write_ops import db_create_customer, db_create_job

        master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
        master.write_text("not a real workbook — only its path/folder matter now")

        db_path = tmp_path / "ai_prowler_jobs.db"
        init_db(str(db_path))
        db_create_customer(str(db_path), {"Company Name": "Crabby's Daytona"}, actor="test")
        db_create_job(str(db_path), {
            "CustomerID (Customers!A)": "CUST-0001",
            "Customer Name / Company": "Crabby's Daytona",
            "Job Status": "Scheduled",
            "Service Type": "Window Washing",
        }, actor="test")

        decoy = tmp_path / "decoy_target.xlsx"
        decoy.write_text("should never be touched")

        # Manager (unrestricted crew scope) so this test isolates path
        # resolution from the separate crew-scoping question — the job
        # deliberately has no "Crew / Technician" assignment, which would
        # otherwise trip make_jobs_crew_check for a restricted role.
        user = {"id": "manager-1", "name": "Pat Manager", "role": "manager",
                "status": "active", "scopes": []}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
        monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))

        result = mcp_mod.update_job_spreadsheet(
            job_identifier="Crabby's",
            updates={"Job Status": "Complete"},
            filepath=str(decoy),
            id_column="Customer Name / Company",
            backup=False,
            ctx=_make_ctx(user),
        )

        assert "✅" in result
        # The decoy file must be completely untouched.
        assert decoy.read_text() == "should never be touched"
        # The real job db (resolved from default_spreadsheet_path's folder,
        # never from the decoy filepath argument) must have been updated.
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        row = conn.execute("SELECT job_status FROM jobs WHERE customer_name = ?",
                            ("Crabby's Daytona",)).fetchone()
        conn.close()
        assert row[0] == "Complete"
