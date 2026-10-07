"""
tests/gui/test_owner_name_not_preselected.py
============================================
Switching to the Settings tab gives focus to its first focusable widget
(the Owner Name "Full name:" entry) through ttk's <<TraverseIn>> event,
whose default TEntry binding selects all the text. The entry overrides
that so the name is NOT shown highlighted when the tab opens.

Run with:
    run_tests.bat tests\\gui\\test_owner_name_not_preselected.py -v
"""
from tkinter import ttk

import pytest


def _walk(w):
    yield w
    for c in w.winfo_children():
        yield from _walk(c)


def _owner_entry(gui):
    for w in _walk(gui.root):
        if isinstance(w, ttk.Label) and w.cget("text") == "Full name:":
            for sib in w.master.winfo_children():
                if isinstance(sib, ttk.Entry):
                    return sib
    pytest.skip("Owner Name entry not built in this mode")


def test_traverse_in_does_not_select_owner_name(gui):
    entry = _owner_entry(gui)
    entry.delete(0, "end")
    entry.insert(0, "David Vavro")
    entry.selection_clear()
    entry.event_generate("<<TraverseIn>>")
    gui.pump()
    assert not entry.selection_present(), "owner name must not be pre-selected"
    assert entry.index("insert") == len("David Vavro")


def test_other_entries_keep_default_select_all(gui):
    """Guard: the override is scoped to the owner-name entry only."""
    owner = _owner_entry(gui)
    other = next((w for w in _walk(gui.root)
                  if isinstance(w, ttk.Entry) and w is not owner
                  and not w.bind("<<TraverseIn>>")), None)
    if other is None:
        pytest.skip("no other plain entry to compare against")
    other.delete(0, "end")
    other.insert(0, "abc")
    other.event_generate("<<TraverseIn>>")
    gui.pump()
    assert other.selection_present()
