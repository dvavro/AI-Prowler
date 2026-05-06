"""
GUI tests — Database management (G-DB-* of the test plan)

These tests cover the Settings → Database area: the Clear Database button
and the way the GUI keeps the Tracked listbox in sync after a wipe.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# G-DB-01 — Clear Database confirmation dialog
# ──────────────────────────────────────────────────────────────────────────────
def test_G_DB_01a_clear_database_pops_confirmation(gui):
    """Clicking Clear Database must always pop a confirmation dialog before
    doing anything destructive."""
    gui.dialogs.set_response("askyesno", False)   # cancel
    gui.app.clear_database()
    gui.pump()

    confirm = gui.dialogs.last_call("askyesno")
    assert confirm is not None
    assert "clear" in (confirm["title"] or "").lower() \
           or "delete" in (confirm["message"] or "").lower()
    assert "undone" in (confirm["message"] or "").lower() \
           or "cannot" in (confirm["message"] or "").lower(), (
        f"Confirmation should warn this is irreversible. Got: {confirm}"
    )


def test_G_DB_01b_cancel_keeps_database_intact(gui, isolated_env):
    """Cancelling the confirmation dialog must not touch any state files."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    f = builders.make_txt(isolated_env.sample_root / "doc.txt", "content " * 30)
    rag.index_file_list([rag.normalise_path(str(f))], label="seed",
                        root_directory=str(isolated_env.sample_root))
    rag.add_to_auto_update_list(str(isolated_env.sample_root))

    # Snapshot before
    auto_before = isolated_env.auto_update.read_text(encoding="utf-8")
    tracking_before = isolated_env.tracking_db.read_text(encoding="utf-8")

    gui.dialogs.set_response("askyesno", False)   # cancel
    gui.app.clear_database()
    gui.pump()

    # Snapshot after must be identical
    assert isolated_env.auto_update.read_text(encoding="utf-8") == auto_before
    assert isolated_env.tracking_db.read_text(encoding="utf-8") == tracking_before


# ──────────────────────────────────────────────────────────────────────────────
# G-DB-02 — Confirm Clear: wipes everything AND refreshes Tracked listbox
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_DB_02_clear_database_wipes_all_and_refreshes_listbox(
        gui, isolated_env):
    """Confirmed Clear Database:
       • Wipes ChromaDB collection
       • Wipes tracking DB
       • Wipes email index (via engine's clear_database — B-04 fix)
       • Wipes auto-update list (via engine's clear_database — B-04 fix)
       • Refreshes the Tracked listbox so it reflects the wipe
    """
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    folder = isolated_env.sample_root / "before_clear"
    f = builders.make_txt(folder / "doc.txt", "content " * 30)
    rag.index_file_list([rag.normalise_path(str(f))], label="seed",
                        root_directory=str(folder))
    rag.add_to_auto_update_list(str(folder))

    # Sanity check: state populated
    auto = json.loads(isolated_env.auto_update.read_text(encoding="utf-8"))
    assert auto["directories"], "Pre-condition: auto-update list should be populated"

    gui.app.refresh_tracked_dirs()
    gui.pump()
    pre_listbox = list(gui.app.tracked_listbox.get(0, "end"))
    assert any("before_clear" in i for i in pre_listbox)

    # User confirms the wipe
    gui.dialogs.set_response("askyesno", True)
    gui.app.clear_database()
    gui.pump()

    # 1. Tracking DB is empty
    tracking = json.loads(isolated_env.tracking_db.read_text(encoding="utf-8"))
    assert tracking == {}, f"Tracking DB should be empty; got {tracking}"

    # 2. Auto-update list is empty (B-04 fix)
    auto_after = json.loads(isolated_env.auto_update.read_text(encoding="utf-8"))
    assert auto_after["directories"] == [], (
        f"Auto-update list should be empty after Clear; got {auto_after}"
    )

    # 3. Tracked listbox refreshed → now shows placeholder
    post_listbox = list(gui.app.tracked_listbox.get(0, "end"))
    assert len(post_listbox) == 1
    assert post_listbox[0].startswith("("), (
        f"Listbox should show placeholder after Clear. Got: {post_listbox}"
    )

    # 4. Success dialog was shown (or partial-error if there were issues)
    info = gui.dialogs.last_call("showinfo")
    err  = gui.dialogs.last_call("showerror")
    assert info is not None or err is not None, (
        "Clear should report outcome via dialog"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Cross-tab consistency: changes made via Index tab visible on Update tab
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_G_CRO_index_then_update_tab_sees_tracked(gui, isolated_env):
    """After indexing via the Index tab's worker (or its underlying call),
    switching to Update tab and clicking Reload List should show the new
    folder. This is the most common workflow: index something, then come
    back later to update it."""
    from tests.helpers import sample_files as builders
    rag = isolated_env.rag

    folder = isolated_env.sample_root / "cross_tab_test"
    builders.make_txt(folder / "x.txt", "content " * 30)

    # Simulate the indexing workflow: queue → start (we call the underlying
    # registration directly to skip the heavyweight worker-thread path)
    gui.app._register_directory_for_tracking(str(folder), recursive=True)
    gui.pump()

    # Now navigate to the Update tab (in-process equivalent: just call the
    # refresh handler) and verify the folder appears
    gui.app.refresh_tracked_dirs()
    gui.pump()

    items = list(gui.app.tracked_listbox.get(0, "end"))
    assert any("cross_tab_test" in i for i in items), (
        f"Update tab doesn't see folder added via Index tab. Listbox: {items}"
    )
