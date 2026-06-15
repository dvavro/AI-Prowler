"""
GUI tests — Update Index tab (G-UPD-* of the test plan)

Exercises the listbox of tracked directories and the buttons that act on
selections.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# Path comparison helper — see explanation in tests/mcp/test_mcp_tools.py.
# Repeated here to keep gui/ self-contained (no cross-test-package imports).
def _canon(p: str) -> str:
    return os.path.normcase(os.path.abspath(p))


def _path_in_list(path: str, path_list: list) -> bool:
    target = _canon(path)
    return any(_canon(p) == target for p in path_list)


# ──────────────────────────────────────────────────────────────────────────────
# G-UPD-01 — refresh_tracked_dirs populates the listbox
# ──────────────────────────────────────────────────────────────────────────────
def test_G_UPD_01a_empty_state_shows_helpful_placeholder(gui):
    """When nothing is tracked, the listbox shows a friendly placeholder
    rather than being empty (which would be ambiguous — empty list vs
    error)."""
    gui.app.refresh_tracked_dirs()
    gui.pump()

    items = list(gui.app.tracked_listbox.get(0, "end"))
    assert len(items) == 1
    assert items[0].startswith("("), (
        f"Empty placeholder should be wrapped in parens. Got: {items[0]!r}"
    )
    assert "no tracked" in items[0].lower() or "first" in items[0].lower()


def test_G_UPD_01b_listbox_populates_from_auto_update_list(gui, isolated_env):
    """If the auto-update list has entries, they appear in the listbox."""
    rag = isolated_env.rag
    # Track two folders directly via the engine
    rag.add_to_auto_update_list(str(isolated_env.sample_root / "alpha"))
    rag.add_to_auto_update_list(str(isolated_env.sample_root / "bravo"))

    gui.app.refresh_tracked_dirs()
    gui.pump()

    items = list(gui.app.tracked_listbox.get(0, "end"))
    assert len(items) == 2, f"Expected 2 entries; got {items}"
    # Order matches insertion order
    assert any("alpha" in i for i in items)
    assert any("bravo" in i for i in items)


# ──────────────────────────────────────────────────────────────────────────────
# G-UPD-02 — Remove Selected without selection shows a warning
# ──────────────────────────────────────────────────────────────────────────────
def test_G_UPD_02_remove_with_no_selection_warns(gui, isolated_env):
    """Calling _remove_tracked_directory with nothing selected should
    pop a warning, not crash."""
    rag = isolated_env.rag
    rag.add_to_auto_update_list(str(isolated_env.sample_root / "alpha"))
    gui.app.refresh_tracked_dirs()
    gui.pump()
    # Make sure nothing is selected
    gui.app.tracked_listbox.selection_clear(0, "end")

    gui.app._remove_tracked_directory()
    gui.pump()

    warn = gui.dialogs.last_call("showwarning")
    assert warn is not None
    assert "select" in (warn["message"] or "").lower() \
           or "selection" in (warn["title"] or "").lower(), (
        f"Should warn about no selection. Got: {warn}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# G-UPD-03 — Remove Selected pops a confirm dialog with sensible content
# ──────────────────────────────────────────────────────────────────────────────
def test_G_UPD_03a_remove_confirmation_dialog_content(gui, isolated_env):
    """Remove triggers an askyesno with content that explains what's about
    to happen — including the 'files on disk are NOT touched' guarantee
    that protects users from accidentally thinking their data is gone."""
    rag = isolated_env.rag
    folder = isolated_env.sample_root / "to_be_removed"
    folder.mkdir()
    rag.add_to_auto_update_list(str(folder))

    gui.app.refresh_tracked_dirs()
    gui.pump()
    gui.app.tracked_listbox.selection_set(0)

    # Dialog default response is False (cancel) so this won't actually
    # remove anything — we're only verifying the dialog content.
    gui.app._remove_tracked_directory()
    gui.pump()

    confirm = gui.dialogs.last_call("askyesno")
    assert confirm is not None, "Should pop a confirmation dialog"
    msg = (confirm["message"] or "").lower()
    # The dialog must mention what will and won't happen — partial match is
    # fine, exact wording is wording-not-API.
    assert "remove" in msg or "delete" in msg
    assert "files on disk" in msg or "not touched" in msg, (
        f"Confirmation should reassure user that disk files survive. Got: {msg}"
    )


def test_G_UPD_03b_cancel_keeps_directory_tracked(gui, isolated_env):
    """When the user clicks Cancel on the confirmation dialog, the directory
    must remain tracked. Default dialog response is False (cancel) so this
    is the typical case."""
    rag = isolated_env.rag
    folder = isolated_env.sample_root / "kept"
    folder.mkdir()
    rag.add_to_auto_update_list(str(folder))

    gui.app.refresh_tracked_dirs()
    gui.pump()
    gui.app.tracked_listbox.selection_set(0)

    gui.dialogs.set_response("askyesno", False)   # explicit cancel
    gui.app._remove_tracked_directory()
    gui.pump()

    auto = json.loads(isolated_env.auto_update.read_text(encoding="utf-8"))
    assert _path_in_list(str(folder.resolve()), auto["directories"]), (
        "Cancelled removal should leave the entry in the auto-update list"
    )


# ──────────────────────────────────────────────────────────────────────────────
# G-UPD-04 — Confirm Remove actually removes (worker thread completes)
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_UPD_04_remove_actually_removes_when_confirmed(gui, isolated_env):
    """Confirm = True → the worker runs to completion, the directory is
    untracked, the listbox refreshes."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    folder = isolated_env.sample_root / "really_remove"
    builders.make_txt(folder / "doc.txt", "content " * 30)

    # Index it first so there's actual ChromaDB state to clean up
    rag.index_file_list(
        [rag.normalise_path(str(folder / "doc.txt"))],
        label="initial", root_directory=str(folder),
    )
    rag.add_to_auto_update_list(str(folder))

    gui.app.refresh_tracked_dirs()
    gui.pump()

    # Find and select the entry (the listbox may also contain a placeholder
    # if other entries exist; just pick the one that matches our folder name)
    items = list(gui.app.tracked_listbox.get(0, "end"))
    target_idx = next((i for i, item in enumerate(items)
                       if "really_remove" in item), None)
    assert target_idx is not None, f"Folder not in listbox: {items}"
    gui.app.tracked_listbox.selection_set(target_idx)

    # Confirm the dialog
    gui.dialogs.set_response("askyesno", True)
    gui.app._remove_tracked_directory()

    # Wait for worker to finish — we know it's done when the auto-update
    # list no longer contains our folder.
    def removal_complete():
        auto = json.loads(isolated_env.auto_update.read_text(encoding="utf-8"))
        return not _path_in_list(str(folder.resolve()), auto["directories"])

    gui.wait_until(removal_complete, timeout_s=30.0)


# ──────────────────────────────────────────────────────────────────────────────
# G-UPD-05 — Reload List button works after external state change
# ──────────────────────────────────────────────────────────────────────────────
def test_G_UPD_05_reload_picks_up_external_changes(gui, isolated_env):
    """Edit the auto-update list outside the GUI (e.g. simulating an MCP
    add), then click Reload — listbox should reflect the change."""
    rag = isolated_env.rag
    # Initial state — nothing tracked
    gui.app.refresh_tracked_dirs()
    gui.pump()
    initial = list(gui.app.tracked_listbox.get(0, "end"))
    assert initial[0].startswith("("), "Initial state should show placeholder"

    # External actor adds a folder (this is what MCP does)
    rag.add_to_auto_update_list(str(isolated_env.sample_root / "external"))

    # User clicks Reload
    gui.app.refresh_tracked_dirs()
    gui.pump()

    after = list(gui.app.tracked_listbox.get(0, "end"))
    assert any("external" in i for i in after), (
        f"Reload didn't pick up external change. Listbox: {after}"
    )
