"""
GUI tests — live refresh of the Learnings tab (v8.1.3)

Covers the auto-refresh feature added so learnings recorded by Claude
during a live session (a SEPARATE process — the MCP server — from the
GUI) appear in the Learnings tab without requiring a manual Refresh click,
while the user is actively looking at that tab.

Design, per an explicit user request during implementation:
  1. Only refreshes while the Learnings tab is the CURRENTLY SELECTED
     notebook tab — no background work for a tab nobody is looking at.
  2. Never refreshes while Semantic search is toggled ON, since a refresh
     in that mode also fires a live ChromaDB query (check_learned) — that
     should only happen on an explicit user action, never as a side
     effect of a background timer.
  3. Filter/search selections and the current table row selection both
     survive a refresh — _refresh_table() reads filters fresh from their
     own StringVars every call (never resets them), and selection is
     preserved by the learning's own stable UUID (see _refresh_table's
     own docstring-comment in rag_gui.py for why the Treeview's iid alone
     can't be used for this).

Testing approach — IMPORTANT
-----------------------------
_learnings_file is computed once, as a closure variable, when
create_learnings_tab() runs (Path.home() / '.ai-prowler' / 'learnings' /
'self_learning_data.json') — the same closure-capture situation already
documented for LOG_PATH in test_scheduler.py's
test_TC_SCHED_008_get_log_tail_returns_string. Neither the `gui` nor
`isolated_env` fixture patches Path.home(), so patching it inside a test
would have NO effect on the already-built GUI's _learnings_file. Instead,
following that same established pattern: back up the REAL
~/.ai-prowler/learnings/self_learning_data.json (if any), run the test
against it directly, then restore/delete in a finally block.

Also, following test_quick_links_custom_tasks_live_refresh.py's approach:
the shared GUI test fixture cancels all pending after() callbacks for
isolation, so a real 3-second timer never fires in a test.
self._poll_learnings_file is exposed and called directly and
synchronously — the exact same check-and-refresh logic the timer uses.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def real_learnings_file():
    """Back up ~/.ai-prowler/learnings/self_learning_data.json (if it
    exists), yield the real path, then restore/delete on teardown."""
    fp = Path.home() / ".ai-prowler" / "learnings" / "self_learning_data.json"
    backup = None
    if fp.exists():
        backup = fp.read_text(encoding="utf-8")
    fp.parent.mkdir(parents=True, exist_ok=True)
    try:
        yield fp
    finally:
        if backup is not None:
            fp.write_text(backup, encoding="utf-8")
        elif fp.exists():
            fp.unlink()


def _write_learnings(fp: Path, learnings: list):
    fp.write_text(json.dumps({"learnings": learnings}), encoding="utf-8")


def _make_learning(id_, title, **overrides):
    l = {
        "id": id_, "title": title, "content": "content", "context": "",
        "category": "general", "status": "active", "confidence": 0.8,
        "outcome": "unknown", "applied_count": 0, "tags": [],
        "source": "operator", "created_at": "2026-07-16T10:00:00",
    }
    l.update(overrides)
    return l


def _select_learnings_tab(gui):
    """Switch the notebook to the Learnings tab — required for the poll
    gate (tab must be the currently selected one) to pass."""
    for tab_id in gui.app.notebook.tabs():
        if gui.app.notebook.tab(tab_id, "text") == "🧠 Learnings":
            gui.app.notebook.select(tab_id)
            return
    raise AssertionError("Learnings tab not found in notebook")


class TestLearningsAutoRefreshOnlyWhileTabActive:

    def test_refreshes_when_learnings_tab_is_selected(self, gui, real_learnings_file):
        _select_learnings_tab(gui)
        _write_learnings(real_learnings_file, [])
        gui.app._poll_learnings_file()
        gui.pump()

        _write_learnings(real_learnings_file, [_make_learning("id-1", "New Learning")])

        gui.app._poll_learnings_file()
        gui.pump()

        assert gui.app._sl_stat_total.get() == "1"

    def test_does_not_refresh_when_a_different_tab_is_active(self, gui, real_learnings_file):
        """Core requirement: writing new data must NOT be picked up while
        some other tab is the active one — only while Learnings itself is
        being looked at."""
        # Reset to a known state WHILE the Learnings tab is active, so the
        # reset itself actually takes effect (the tab-gate would otherwise
        # correctly refuse it too, same as the real feature refusing any
        # other change made while a different tab is showing).
        _select_learnings_tab(gui)
        _write_learnings(real_learnings_file, [])
        gui.app._poll_learnings_file()
        gui.pump()
        assert gui.app._sl_stat_total.get() == "0"

        # Now switch to any other tab (Home/Welcome is index 0 in every build).
        gui.app.notebook.select(gui.app.notebook.tabs()[0])
        assert gui.app.notebook.tab(gui.app.notebook.select(), "text") != "🧠 Learnings"

        _write_learnings(real_learnings_file, [_make_learning("id-1", "Missed Learning")])
        gui.app._poll_learnings_file()
        gui.pump()

        assert gui.app._sl_stat_total.get() == "0"

    def test_refresh_resumes_once_tab_becomes_active_again(self, gui, real_learnings_file):
        """A change that happened while looking elsewhere isn't lost
        forever — it's picked up on the next poll after switching back."""
        _select_learnings_tab(gui)
        _write_learnings(real_learnings_file, [])
        gui.app._poll_learnings_file()
        gui.pump()
        assert gui.app._sl_stat_total.get() == "0"

        gui.app.notebook.select(gui.app.notebook.tabs()[0])
        _write_learnings(real_learnings_file, [_make_learning("id-1", "Delayed Learning")])
        gui.app._poll_learnings_file()
        gui.pump()
        assert gui.app._sl_stat_total.get() == "0"

        _select_learnings_tab(gui)
        gui.app._poll_learnings_file()
        gui.pump()
        assert gui.app._sl_stat_total.get() == "1"


class TestLearningsAutoRefreshSkipsWithSemanticSearchOn:

    def test_no_refresh_while_semantic_search_toggled_on(self, gui, real_learnings_file):
        """Refreshing in semantic mode also fires a live ChromaDB query —
        must not happen as a side effect of the background timer."""
        _select_learnings_tab(gui)
        _write_learnings(real_learnings_file, [])
        gui.app._poll_learnings_file()
        gui.pump()
        assert gui.app._sl_stat_total.get() == "0"

        gui.app._sl_semantic_search.set(True)
        _write_learnings(real_learnings_file, [_make_learning("id-1", "Semantic Miss")])

        gui.app._poll_learnings_file()
        gui.pump()

        assert gui.app._sl_stat_total.get() == "0"

    def test_refresh_resumes_once_semantic_search_toggled_off(self, gui, real_learnings_file):
        _select_learnings_tab(gui)
        _write_learnings(real_learnings_file, [])
        gui.app._poll_learnings_file()
        gui.pump()
        assert gui.app._sl_stat_total.get() == "0"

        gui.app._sl_semantic_search.set(True)
        _write_learnings(real_learnings_file, [_make_learning("id-1", "Delayed")])
        gui.app._poll_learnings_file()
        gui.pump()
        assert gui.app._sl_stat_total.get() == "0"

        gui.app._sl_semantic_search.set(False)
        gui.app._poll_learnings_file()
        gui.pump()
        assert gui.app._sl_stat_total.get() == "1"


class TestLearningsAutoRefreshIsMtimeGated:

    def test_poll_is_a_no_op_when_file_unchanged(self, gui, real_learnings_file):
        """Proves this is mtime-gated, not an unconditional refresh every
        tick — same guard as the proven Custom Tasks pattern."""
        _select_learnings_tab(gui)
        _write_learnings(real_learnings_file, [_make_learning("id-1", "Stable")])
        gui.app._poll_learnings_file()
        gui.pump()

        first_children = list(gui.app._sl_tree.get_children())
        gui.app._poll_learnings_file()
        gui.pump()
        second_children = list(gui.app._sl_tree.get_children())

        assert len(first_children) == len(second_children) == 1


class TestLearningsAutoRefreshPreservesUserState:

    def test_filter_selection_untouched_across_auto_refresh(self, gui, real_learnings_file):
        _write_learnings(real_learnings_file, [
            _make_learning("id-1", "Sales Note", category="business_lesson"),
            _make_learning("id-2", "Tech Note", category="technical_note"),
        ])
        gui.app._poll_learnings_file()
        gui.pump()
        _select_learnings_tab(gui)

        gui.app._sl_filter_cat.set("technical_note")
        gui.app._refresh_learnings_all()
        gui.pump()
        assert gui.app._sl_stat_total.get() == "2"  # stats are unfiltered
        assert len(gui.app._sl_tree.get_children()) == 1  # table IS filtered

        _write_learnings(real_learnings_file, [
            _make_learning("id-1", "Sales Note", category="business_lesson"),
            _make_learning("id-2", "Tech Note", category="technical_note"),
            _make_learning("id-3", "New Sales Note", category="business_lesson"),
        ])
        gui.app._poll_learnings_file()
        gui.pump()

        # Filter selection must still be exactly what the user set.
        assert gui.app._sl_filter_cat.get() == "technical_note"
        # And the table must still only show the one matching row.
        assert len(gui.app._sl_tree.get_children()) == 1

    def test_row_selection_preserved_across_refresh(self, gui, real_learnings_file):
        """Even the manual/always-on refresh path had this bug — the
        Treeview is fully rebuilt (delete + reinsert) on every refresh, so
        selection by iid alone silently vanishes. Fixed by re-selecting
        the same LEARNING (its own stable id), not the Treeview's iid."""
        _write_learnings(real_learnings_file, [
            _make_learning("id-1", "First"),
            _make_learning("id-2", "Second"),
        ])
        gui.app._refresh_learnings_all()
        gui.pump()

        # Select the row for "id-2".
        target_iid = next(iid for iid, l in gui.app._sl_data_map.items()
                          if l["id"] == "id-2")
        gui.app._sl_tree.selection_set(target_iid)
        gui.pump()

        gui.app._refresh_learnings_all()
        gui.pump()

        sel = gui.app._sl_tree.selection()
        assert sel, "selection was lost across refresh"
        assert gui.app._sl_data_map[sel[0]]["id"] == "id-2"
