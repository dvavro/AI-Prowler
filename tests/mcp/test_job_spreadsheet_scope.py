"""
tests/mcp/test_job_spreadsheet_scope.py
=========================================
Tests for server-mode job-spreadsheet path resolution and write locking.

Background
----------
read_job_spreadsheet, update_job_spreadsheet, email_invoice,
schedule_next_recurring_job, log_time_entry, and get_ar_aging_report
previously accepted a raw `filepath` argument with ZERO access control —
any server-mode role could point them at an arbitrary .xlsx file anywhere
on the host filesystem.

_resolve_job_spreadsheet_path() closes this gap:

  - Personal mode (ctx has no user): unrestricted, exactly as before —
    an explicit filepath argument is honored; otherwise falls back to
    the configured default_spreadsheet_path.
  - Server mode: the filepath argument is IGNORED entirely. Instead:
      1. If the calling user has a per-user file named exactly
         "<user_id>.xlsx" sitting in the same folder as
         default_spreadsheet_path, that file is used.
      2. Otherwise, falls back to default_spreadsheet_path itself (the
         shared "master" spreadsheet everyone uses).

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


# ═══════════════════════════════════════════════════════════════════════════
# SECTION A — _resolve_job_spreadsheet_path(): personal mode (unrestricted)
# ═══════════════════════════════════════════════════════════════════════════

class TestPersonalModeUnrestricted:

    def test_A01_explicit_filepath_honored(self, mcp_mod, monkeypatch):
        """Personal mode: an explicit filepath argument is used as-is,
        exactly like every version before this feature existed."""
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path",
                            lambda: "C:/default/master.xlsx")
        result = mcp_mod._resolve_job_spreadsheet_path(None, "C:/custom/one_off.xlsx")
        assert result == "C:/custom/one_off.xlsx"

    def test_A02_empty_filepath_falls_back_to_default(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path",
                            lambda: "C:/default/master.xlsx")
        result = mcp_mod._resolve_job_spreadsheet_path(None, "")
        assert result == "C:/default/master.xlsx"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION B — _resolve_job_spreadsheet_path(): server mode (scoped, gap closed)
# ═══════════════════════════════════════════════════════════════════════════

class TestServerModeScoped:

    def test_B01_custom_filepath_argument_is_IGNORED(self, mcp_mod, monkeypatch, tmp_path):
        """THE CORE FIX: in server mode, whatever filepath the caller passes
        is completely ignored — this is what closes the arbitrary-file gap.
        No per-user file exists here, so it must fall back to the master."""
        master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
        master.write_text("fake xlsx")
        user = _server_user()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))

        result = mcp_mod._resolve_job_spreadsheet_path(
            _make_ctx(user), "C:/some/attacker/controlled/path.xlsx"
        )
        assert result == str(master)
        assert "attacker" not in result

    def test_B02_per_user_file_takes_priority(self, mcp_mod, monkeypatch, tmp_path):
        """If <folder>/<user_id>.xlsx exists next to the master, it wins."""
        master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
        master.write_text("master")
        per_user = tmp_path / "jake-r.xlsx"
        per_user.write_text("jake's own tracker")
        user = _server_user(uid="jake-r")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))

        result = mcp_mod._resolve_job_spreadsheet_path(_make_ctx(user), "")
        assert result == str(per_user)

    def test_B03_no_per_user_file_falls_back_to_master(self, mcp_mod, monkeypatch, tmp_path):
        """Model 2 (single shared spreadsheet): no per-user file for this
        user exists, so everyone lands on the same master file."""
        master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
        master.write_text("master")
        user = _server_user(uid="vicki-vavro")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))

        result = mcp_mod._resolve_job_spreadsheet_path(_make_ctx(user), "")
        assert result == str(master)

    def test_B04_different_users_get_different_files(self, mcp_mod, monkeypatch, tmp_path):
        """Model 1 (per-user tracking): two different users in the SAME
        folder resolve to two DIFFERENT files."""
        master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
        master.write_text("master")
        (tmp_path / "jake-r.xlsx").write_text("jake")
        (tmp_path / "vicki-vavro.xlsx").write_text("vicki")

        jake = _server_user(uid="jake-r")
        vicki = _server_user(uid="vicki-vavro")
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: jake)
        jake_result = mcp_mod._resolve_job_spreadsheet_path(_make_ctx(jake), "")

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: vicki)
        vicki_result = mcp_mod._resolve_job_spreadsheet_path(_make_ctx(vicki), "")

        assert jake_result == str(tmp_path / "jake-r.xlsx")
        assert vicki_result == str(tmp_path / "vicki-vavro.xlsx")
        assert jake_result != vicki_result

    def test_B05_no_default_configured_returns_empty(self, mcp_mod, monkeypatch):
        user = _server_user()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: "")

        result = mcp_mod._resolve_job_spreadsheet_path(_make_ctx(user), "C:/anything.xlsx")
        assert result == ""

    def test_B06_user_with_no_id_falls_back_to_master(self, mcp_mod, monkeypatch, tmp_path):
        master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
        master.write_text("master")
        user = {"id": "", "name": "No ID", "role": "field_crew"}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))

        result = mcp_mod._resolve_job_spreadsheet_path(_make_ctx(user), "")
        assert result == str(master)

    def test_B07_custom_master_filename_honored(self, mcp_mod, monkeypatch, tmp_path):
        """The 'master filename' isn't hardcoded — it's whatever the manager
        picked via the Business tab's Browse button. A custom name works
        exactly the same as the AI-Prowler_Job_Tracker.xlsx default."""
        custom_master = tmp_path / "MyCompanyJobs.xlsx"
        custom_master.write_text("custom-named master")
        user = _server_user(uid="jake-r")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(custom_master))

        result = mcp_mod._resolve_job_spreadsheet_path(_make_ctx(user), "")
        assert result == str(custom_master)


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
        it always resolves through _resolve_job_spreadsheet_path()."""
        import openpyxl
        master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["Customer", "Job Status", "Service Type"])
        ws.append(["Crabby's Daytona", "Scheduled", "Window Washing"])
        wb.save(str(master))

        decoy = tmp_path / "decoy_target.xlsx"
        decoy.write_text("should never be touched")

        user = _server_user()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))

        result = mcp_mod.update_job_spreadsheet(
            job_identifier="Crabby's",
            updates={"Job Status": "Complete"},
            filepath=str(decoy),
            backup=False,
            ctx=_make_ctx(user),
        )

        assert "✅" in result
        assert str(master.name) in result
        # The decoy file must be completely untouched.
        assert decoy.read_text() == "should never be touched"
        # The master file must actually have been updated.
        wb2 = openpyxl.load_workbook(str(master))
        assert wb2.active["B2"].value == "Complete"
