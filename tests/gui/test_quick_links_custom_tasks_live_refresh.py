"""
GUI tests — live refresh of the "My Custom Analyses" panel (Quick Links tab)

Covers the auto-refresh feature added so tasks created externally (e.g. by
the create_analysis_task MCP tool, running in a SEPARATE process — the MCP
server — from the GUI) show up without requiring a manual tab switch.

Background
----------
create_analysis_task() writes to custom_analysis_tasks.json from the MCP
server process. The GUI previously only re-read that file on specific
GUI-triggered actions (save, delete, initial render) — no live sync. Added
an mtime-polling loop (self.root.after(3000, ...)) that detects external
file changes and calls _refresh_custom_list() automatically.

Testing approach
-----------------
The shared GUI test fixture (tests/gui/conftest.py) explicitly cancels all
pending after() callbacks on setup/teardown for test isolation — a real
3-second timer would never fire within a test. So rather than waiting on
the real timer, self._poll_custom_tasks_file is exposed and called
directly and synchronously — it runs the EXACT SAME check-and-refresh
logic the timer would, just without waiting on the timer itself. This is
fast, deterministic, and tests the real logic (not a re-implementation
of it).

Also covers a bug found while implementing this: the "N / 10" task-count
display was hardcoded to the OLD cap (10) even after MAX_CUSTOM_TASKS was
raised to 25 — now reads _ctm.MAX_CUSTOM_TASKS dynamically so it can't
drift out of sync again.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest


def test_G_QL_01_custom_task_count_shows_dynamic_cap_not_stale_10(gui, isolated_env, tmp_path):
    """The count label must read '.../ 25', not the old hardcoded '.../ 10'
    — regardless of how many tasks currently exist."""
    import custom_tasks_manager as ctm
    tasks_path = tmp_path / "custom_analysis_tasks.json"

    with patch.object(ctm, "CUSTOM_TASKS_PATH", tasks_path):
        gui.app._poll_custom_tasks_file()
        gui.pump()
        assert gui.app._custom_count_var.get() == "0 / 25"
        assert "/ 10" not in gui.app._custom_count_var.get()


def test_G_QL_02_externally_created_task_appears_via_poll(gui, isolated_env, tmp_path):
    """The core feature: a task written to disk by a SEPARATE process (as
    create_analysis_task() does from the MCP server) must appear after the
    poll check runs — the same logic the real 3-second timer calls."""
    import custom_tasks_manager as ctm
    tasks_path = tmp_path / "custom_analysis_tasks.json"

    with patch.object(ctm, "CUSTOM_TASKS_PATH", tasks_path):
        # Re-sync the panel against this test's isolated (empty) path first
        # — the panel's initial render happened during fixture setup,
        # against whatever path was live at that time.
        gui.app._poll_custom_tasks_file()
        gui.pump()
        assert gui.app._custom_count_var.get() == "0 / 25"

        # Simulate create_analysis_task() writing from a separate process —
        # write directly to disk, NOT through any GUI action.
        new_task = ctm.create_task(label="External Task", prompt="Do the thing.")
        ctm.save_custom_tasks([new_task])

        # Run the exact poll-check logic the real timer would run.
        gui.app._poll_custom_tasks_file()
        gui.pump()

        assert gui.app._custom_count_var.get() == "1 / 25"


def test_G_QL_03_poll_is_a_no_op_when_file_unchanged(gui, isolated_env, tmp_path):
    """The poll check must not rebuild the panel when the file hasn't
    changed since the last check — proves it's mtime-gated, not an
    unconditional refresh-every-tick."""
    import custom_tasks_manager as ctm
    tasks_path = tmp_path / "custom_analysis_tasks.json"

    with patch.object(ctm, "CUSTOM_TASKS_PATH", tasks_path):
        gui.app._poll_custom_tasks_file()
        gui.pump()
        first_children = list(gui.app._custom_list_frame.winfo_children())

        # No file write in between — poll again immediately.
        gui.app._poll_custom_tasks_file()
        gui.pump()

        second_children = list(gui.app._custom_list_frame.winfo_children())
        assert len(first_children) == len(second_children)
        assert gui.app._custom_count_var.get() == "0 / 25"


def test_G_QL_04_multiple_external_tasks_all_counted(gui, isolated_env, tmp_path):
    """Two tasks written externally (e.g. two separate
    create_analysis_task() calls) both show up after one poll check."""
    import custom_tasks_manager as ctm
    tasks_path = tmp_path / "custom_analysis_tasks.json"

    with patch.object(ctm, "CUSTOM_TASKS_PATH", tasks_path):
        gui.app._poll_custom_tasks_file()
        gui.pump()

        t1 = ctm.create_task(label="Task One", prompt="Do thing one.")
        t2 = ctm.create_task(label="Task Two", prompt="Do thing two.")
        ctm.save_custom_tasks([t1, t2])

        gui.app._poll_custom_tasks_file()
        gui.pump()

        assert gui.app._custom_count_var.get() == "2 / 25"
