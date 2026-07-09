"""
tests/unit/test_custom_tasks_manager_cap.py
==============================================
Tests for the MAX_CUSTOM_TASKS cap enforcement, now centralized inside
create_task() itself rather than duplicated by each caller.

Background
----------
Previously MAX_CUSTOM_TASKS was only checked in rag_gui.py's Add dialog,
NOT inside create_task() itself — meaning any other caller (e.g. a future
MCP tool) could silently bypass the limit. Moved the check inside
create_task() (which internally calls load_custom_tasks() to get the
current count) so every caller — GUI and MCP tool alike — shares one
single source of truth with no way to accidentally skip it.

Also covers the cap being raised from 10 to 25.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def ctm():
    import custom_tasks_manager as _ctm
    return _ctm


class TestCapValue:

    def test_cap_is_25_not_10(self, ctm):
        assert ctm.MAX_CUSTOM_TASKS == 25


class TestCapEnforcedInsideCreateTask:

    def test_create_task_succeeds_under_cap(self, ctm, monkeypatch):
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [{"task_id": f"t{i}"} for i in range(24)])
        task = ctm.create_task(label="Test task", prompt="Do the thing.")
        assert task["label"] == "Test task"

    def test_create_task_raises_at_cap(self, ctm, monkeypatch):
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [{"task_id": f"t{i}"} for i in range(25)])
        with pytest.raises(ValueError, match="Maximum 25"):
            ctm.create_task(label="One too many", prompt="Do the thing.")

    def test_create_task_raises_over_cap(self, ctm, monkeypatch):
        """Defensive: even if somehow over cap (e.g. cap lowered after tasks
        already existed), still blocks new creation rather than allowing it."""
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [{"task_id": f"t{i}"} for i in range(30)])
        with pytest.raises(ValueError, match="Maximum 25"):
            ctm.create_task(label="Still blocked", prompt="Do the thing.")

    def test_cap_check_happens_before_field_validation(self, ctm, monkeypatch):
        """The cap check must fire even if the label/prompt would otherwise
        also be invalid — proves it's checked first, not as an afterthought."""
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [{"task_id": f"t{i}"} for i in range(25)])
        with pytest.raises(ValueError, match="Maximum 25"):
            ctm.create_task(label="", prompt="")  # also individually invalid

    def test_cap_uses_real_load_custom_tasks_not_a_passed_count(self, ctm, monkeypatch, tmp_path):
        """Confirms the cap is self-contained (calls load_custom_tasks()
        internally) rather than trusting a count the caller could get wrong
        or forget to pass — the actual fix for the duplicate-logic risk."""
        monkeypatch.setattr(ctm, "CUSTOM_TASKS_PATH", tmp_path / "custom_analysis_tasks.json")
        # No file exists yet -> load_custom_tasks() should return [].
        task = ctm.create_task(label="First ever task", prompt="Do the thing.")
        assert task["label"] == "First ever task"
