"""
tests/gui/test_about_window.py
==============================
Help → About AI Prowler (2026-09-24): a resizable, scrollable Toplevel
with word-wrapped text (reflows on resize) instead of a fixed messagebox,
and no MCP tool counts in the text — tools are user-configurable, so the
About box points at Settings → MCP Tool Configuration instead.

Run with:
    run_tests.bat tests\\gui\\test_about_window.py -v
"""
import re
import tkinter as tk


def _about_windows(gui):
    return [w for w in gui.root.winfo_children()
            if isinstance(w, tk.Toplevel) and w.winfo_exists()
            and w.title() == "About AI Prowler"]


def _text_widget(win):
    stack = [win]
    while stack:
        w = stack.pop()
        if isinstance(w, tk.Text):
            return w
        stack.extend(w.winfo_children())
    raise AssertionError("no Text widget in About window")


def test_about_content_has_no_tool_counts(gui):
    text = "\n".join(t for _k, t in gui.app.get_about_content())
    assert not re.search(r"\b\d+\s+(MCP\s+)?tools\b", text, re.I), \
        "About text must not quote tool counts"
    assert not re.search(r"\b\d+\s+categories\b", text, re.I)
    assert "MCP Tool Configuration" in text
    assert "fuzzy_replace" not in text          # tool no longer exists


def test_about_is_resizable_scrollable_wrapping_window(gui, dialogs):
    gui.app.show_about()
    gui.pump()
    wins = _about_windows(gui)
    assert len(wins) == 1
    win = wins[0]
    assert not dialogs.last_call("showinfo"), "must not be a messagebox anymore"
    assert win.resizable() == (True, True)
    txt = _text_widget(win)
    assert str(txt.cget("wrap")) == "word"      # reflows with window width
    assert str(txt.cget("state")) == "disabled"  # read-only
    assert txt.cget("yscrollcommand"), "text must be wired to a scrollbar"
    assert "MCP Tool Configuration" in txt.get("1.0", "end")


def test_about_reuses_open_window_and_closes(gui):
    gui.app.show_about()
    gui.app.show_about()
    gui.pump()
    wins = _about_windows(gui)
    assert len(wins) == 1, "second click should reuse the open window"
    # Key events can't reach an unmapped window under the withdrawn test
    # root, so close via the Close button (same _close handler as Escape).
    from tkinter import ttk
    stack, close_btn = [wins[0]], None
    while stack:
        w = stack.pop()
        if isinstance(w, ttk.Button) and w.cget("text") == "Close":
            close_btn = w
        stack.extend(w.winfo_children())
    close_btn.invoke()
    gui.pump()
    assert not _about_windows(gui)
    gui.app.show_about()        # can reopen after closing
    gui.pump()
    assert len(_about_windows(gui)) == 1
