"""
tests/gui/test_auto_update_schedule_ru.py
============================================
v8.1.14 fix: the "AI Prowler Auto-Update" scheduled task (Update Index
tab's set_schedule()) had the exact same bug just fixed in
task_queue_automation.py's Autonomous AI Task Queue scheduler — no
explicit /RU on the schtasks /create call, which defaults schtasks.exe to
the "Run only when user is logged on" logon type (INTERACTIVE_TOKEN).
That logon type requires an active interactive desktop session and can
silently fail to launch its process while the screen is locked or the
screensaver is active, even though the user is technically still logged
on — a real-world bug report confirmed this exact symptom for the
Autonomous Task Queue, and this is a second, independent place with the
identical root cause. /RU <username> WITHOUT /RP switches to S4U logon
("Run whether user is logged on or not"), which works regardless of lock
state.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import rag_gui as gui_mod


@pytest.fixture(autouse=True)
def _mock_schedule_side_effects(monkeypatch):
    """set_schedule() calls generate_auto_update_script() (real file I/O
    against the tracked-directories list) and shows a messagebox on
    success/failure — mock both so these tests only exercise the schtasks
    command string construction."""
    monkeypatch.setattr(gui_mod, "generate_auto_update_script", lambda: None)
    monkeypatch.setattr(gui_mod.messagebox, "showinfo", lambda *a, **kw: None)
    monkeypatch.setattr(gui_mod.messagebox, "showerror", lambda *a, **kw: None)


def _capture_subprocess_run(monkeypatch):
    calls = []
    def _fake_run(cmd, **kw):
        calls.append(cmd)
        class _R:
            returncode = 0
            stdout = ""
            stderr = ""
        return _R()
    monkeypatch.setattr(gui_mod.subprocess, "run", _fake_run)
    return calls


def _find_create_call(calls):
    """set_schedule() also triggers refresh_schedule_status(), which makes
    its own /query subprocess call right after -- filter down to the
    actual /create call these tests care about."""
    matches = [c for c in calls if "/create" in c]
    assert len(matches) == 1, f"expected exactly one /create call, got: {calls}"
    return matches[0]


class TestAutoUpdateScheduleRunAsUser:

    def test_daily_schedule_includes_ru_flag(self, gui, monkeypatch):
        monkeypatch.setenv("USERNAME", "david")
        calls = _capture_subprocess_run(monkeypatch)
        gui.app.set_schedule("06:00", ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"])
        assert '/RU "david"' in _find_create_call(calls)

    def test_weekly_partial_days_schedule_includes_ru_flag(self, gui, monkeypatch):
        monkeypatch.setenv("USERNAME", "david")
        calls = _capture_subprocess_run(monkeypatch)
        gui.app.set_schedule("06:00", ["MON", "WED", "FRI"])
        assert '/RU "david"' in _find_create_call(calls)

    def test_no_rp_password_flag_present(self, gui, monkeypatch):
        # Confirming S4U specifically -- /RU without /RP, never a stored
        # password.
        monkeypatch.setenv("USERNAME", "david")
        calls = _capture_subprocess_run(monkeypatch)
        gui.app.set_schedule("06:00", ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"])
        assert "/RP" not in _find_create_call(calls)

    def test_missing_username_env_omits_ru_rather_than_crashing(self, gui, monkeypatch):
        # Defensive: if USERNAME somehow isn't set, still produce a valid
        # (if imperfect) schtasks command rather than crashing or
        # embedding an empty /RU "" that schtasks would reject.
        monkeypatch.delenv("USERNAME", raising=False)
        calls = _capture_subprocess_run(monkeypatch)
        gui.app.set_schedule("06:00", ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"])
        create_call = _find_create_call(calls)
        assert "/RU" not in create_call
        # The rest of the command must still be well-formed.
        assert '/tn "AI Prowler Auto-Update"' in create_call
        assert "/sc daily" in create_call
        assert "/st 06:00" in create_call
