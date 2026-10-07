"""
tests/gui/test_tool_config_group_popups.py
==========================================
Settings tab -> MCP Tool Configuration, compact layout (2026-09-24).

Each catalog category collapses to ONE row on the Settings page:
    [group checkbox or 🔒 label]  "N of M enabled"  [Configure… / Details…]
and all per-tool content (descriptions, locked reasons, individual
checkboxes, Enable all / Disable all) lives in a popup Toplevel.

Run with:
    run_tests.bat tests\\gui\\test_tool_config_group_popups.py -v
"""
from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk

import pytest

import mcp_tool_catalog as tc

PANEL_TITLE = "🧩 MCP Tool Configuration"


@pytest.fixture
def state_dir(monkeypatch, tmp_path):
    """Must be requested BEFORE `gui` so the panel reads/writes here."""
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    return tmp_path


def _walk(w):
    yield w
    for c in w.winfo_children():
        yield from _walk(c)


def _fold_button(gui):
    """The panel's ▸/▾ header button (2026-10-01: the panel is collapsible, like
    the Home page's Set up AI-Prowler panel — the title moved onto this button)."""
    for w in _walk(gui.root):
        if isinstance(w, ttk.Button) and str(w.cget("text")).endswith(PANEL_TITLE):
            return w
    pytest.fail("MCP Tool Configuration panel not found")


def _panel(gui):
    """The panel's outer frame, unfolded so its rows are on screen."""
    btn = _fold_button(gui)
    if str(btn.cget("text")).startswith("▸"):     # folded (the default) — open it
        btn.invoke()
        gui.pump()
    w = btn
    while w is not None and not isinstance(w, ttk.Labelframe):
        w = w.master
    if w is None:
        pytest.fail("MCP Tool Configuration panel frame not found")
    return w


def _mode(panel):
    for w in _walk(panel):
        if isinstance(w, ttk.Label):
            t = str(w.cget("text"))
            if "applies to this install's server mode" in t:
                return "server"
    return "personal"


def _categories(mode):
    out = []
    for c in tc.CATEGORY_ORDER:
        tools = [n for n in tc.tools_in_category(c.key) if mode in tc.modes_of(n)]
        if tools:
            out.append((c, tools))
    return out


def _toggleable(tools):
    return [n for n in tools if not tc.is_locked(n)
            and not tc.category_is_locked(tc.category_of(n))]


def _buttons(root, *texts):
    return [w for w in _walk(root) if isinstance(w, ttk.Button)
            and w.cget("text") in texts]


def _row_widgets(panel, cat_label):
    """(group checkbutton or None, count label, configure button) for a category row."""
    for w in _walk(panel):
        if w.winfo_manager() != "grid":
            continue
        txt = str(w.cget("text")) if "text" in w.keys() else ""
        if txt in (cat_label, f"🔒 {cat_label}"):
            row = int(w.grid_info()["row"])
            parent = w.master
            cells = {int(c.grid_info()["column"]): c for c in parent.grid_slaves(row=row)}
            cb = cells[0] if isinstance(cells[0], ttk.Checkbutton) else None
            return cb, cells[1], cells[2]
    pytest.fail(f"row for {cat_label!r} not found")


def _open_popup(gui, btn):
    before = {str(w) for w in gui.root.winfo_children()}
    btn.invoke()
    gui.pump()
    new = [w for w in gui.root.winfo_children()
           if isinstance(w, tk.Toplevel) and str(w) not in before]
    assert len(new) == 1, "Configure… should open exactly one popup"
    return new[0]


def _first_toggleable_category(mode):
    for c, tools in _categories(mode):
        if _toggleable(tools):
            return c, tools
    pytest.skip("catalog has no toggleable category in this mode")


# ─────────────────────────────────────────────────────────────────────────────

def test_one_row_per_category_and_no_per_tool_widgets_on_page(state_dir, gui):
    panel = _panel(gui)
    cats = _categories(_mode(panel))
    assert len(_buttons(panel, "Configure…", "Details…")) == len(cats)
    # No info buttons, and no per-tool checkboxes on the page itself —
    # only group checkboxes (one per toggleable category).
    assert not _buttons(panel, "ⓘ")
    cbs = [w for w in _walk(panel) if isinstance(w, ttk.Checkbutton)]
    assert len(cbs) == sum(1 for _c, t in cats if _toggleable(t))
    for w in _walk(panel):
        if isinstance(w, ttk.Label):
            assert str(w.cget("text")) not in {tc.TOOL_CATALOG[n].label
                                               for _c, t in cats for n in t}


def test_locked_category_popup_has_descriptions_and_no_checkboxes(state_dir, gui):
    panel = _panel(gui)
    locked = [(c, t) for c, t in _categories(_mode(panel)) if not _toggleable(t)]
    if not locked:
        pytest.skip("no locked category in this mode")
    cat, tools = locked[0]
    cb, count, btn = _row_widgets(panel, cat.label)
    assert cb is None and btn.cget("text") == "Details…"
    assert "always on" in str(count.cget("text"))
    pop = _open_popup(gui, btn)
    texts = " ".join(str(w.cget("text")) for w in _walk(pop) if isinstance(w, ttk.Label))
    assert cat.description in texts
    for n in tools:
        assert tc.TOOL_CATALOG[n].description in texts
    assert not [w for w in _walk(pop) if isinstance(w, ttk.Checkbutton)]
    assert not _buttons(pop, "Enable all", "Disable all")
    _buttons(pop, "Close")[0].invoke()
    gui.pump()
    assert not pop.winfo_exists()


def test_popup_toggle_updates_group_row_tristate_and_save(state_dir, gui, dialogs):
    dialogs.set_response("askyesno", True)   # accept any live-feature warning
    panel = _panel(gui)
    mode = _mode(panel)
    cat, tools = _first_toggleable_category(mode)
    toggle = _toggleable(tools)
    cb, count, btn = _row_widgets(panel, cat.label)
    assert btn.cget("text") == "Configure…"
    assert count.cget("text") == f"{len(tools)} of {len(tools)} enabled"
    assert not cb.instate(["alternate"])

    pop = _open_popup(gui, btn)
    pop_cbs = {w.cget("text"): w for w in _walk(pop) if isinstance(w, ttk.Checkbutton)}
    assert set(pop_cbs) == {tc.TOOL_CATALOG[n].label for n in toggle}

    if len(toggle) > 1:
        pop_cbs[tc.TOOL_CATALOG[toggle[0]].label].invoke()   # one tool off
        gui.pump()
        assert count.cget("text") == f"{len(tools) - 1} of {len(tools)} enabled"
        assert cb.instate(["alternate"]), "partly-on group should show the dash"

    _buttons(pop, "Disable all")[0].invoke()
    gui.pump()
    assert count.cget("text") == f"{len(tools) - len(toggle)} of {len(tools)} enabled"
    assert not cb.instate(["alternate"])
    _buttons(pop, "Close")[0].invoke()
    gui.pump()

    _buttons(panel, "💾 Save (restart required)")[0].invoke()
    data = json.loads((state_dir / "tool_config.json").read_text(encoding="utf-8"))
    assert set(data[mode]["disabled_tools"]) == set(toggle)

    # Group checkbox on the page re-enables the whole group
    cb.invoke()
    gui.pump()
    assert count.cget("text") == f"{len(tools)} of {len(tools)} enabled"


def test_popup_text_rewraps_when_window_resized(state_dir, gui):
    panel = _panel(gui)
    cat, tools = _categories(_mode(panel))[0]
    _cb, _count, btn = _row_widgets(panel, cat.label)
    pop = _open_popup(gui, btn)
    pop.deiconify()
    notes = [w for w in _walk(pop) if isinstance(w, ttk.Label)
             and str(w.cget("text")) in {tc.TOOL_CATALOG[n].description for n in tools}
             or (isinstance(w, ttk.Label) and any(
                 str(w.cget("text")).startswith(tc.TOOL_CATALOG[n].description)
                 for n in tools))]
    hdr = next(w for w in _walk(pop) if isinstance(w, ttk.Label)
               and w.cget("text") == cat.description)
    assert notes

    def _wraps():
        return (int(str(hdr.cget("wraplength"))),
                [int(str(n.cget("wraplength"))) for n in notes])

    # The session root is withdrawn, so a transient popup is never mapped and
    # the window manager sends no real resize events — fire the same
    # <Configure> events a user drag would produce on the header and list.
    canvas = next(w for w in _walk(pop) if isinstance(w, tk.Canvas))

    def _resize(width):
        hdr.master.event_generate("<Configure>", width=width, height=120)
        canvas.event_generate("<Configure>", width=width - 30, height=400)
        gui.pump()

    _resize(600)
    h_small, n_small = _wraps()
    _resize(1200)
    h_big, n_big = _wraps()
    assert h_big > h_small + 400, "header description should widen with the window"
    assert all(b > s + 400 for s, b in zip(n_small, n_big)), \
        "tool notes should widen with the window"
    _resize(600)
    assert _wraps()[1] == n_small, "and narrow again when shrunk"


def test_declining_live_feature_warning_keeps_tool_enabled(state_dir, gui, dialogs):
    dialogs.set_response("askyesno", False)
    panel = _panel(gui)
    mode = _mode(panel)
    for cat, tools in _categories(mode):
        deps = [n for n in _toggleable(tools) if tc.TOOL_CATALOG[n].pwa_dependency]
        if deps:
            break
    else:
        pytest.skip("no toggleable live-feature tool in this mode")
    _cb, count, btn = _row_widgets(panel, cat.label)
    pop = _open_popup(gui, btn)
    target = next(w for w in _walk(pop) if isinstance(w, ttk.Checkbutton)
                  and w.cget("text") == tc.TOOL_CATALOG[deps[0]].label)
    target.invoke()
    gui.pump()
    assert dialogs.last_call("askyesno") is not None
    assert target.instate(["selected"]), "cancelled warning must re-check the tool"
    assert count.cget("text") == f"{len(tools)} of {len(tools)} enabled"


def test_panel_folds_like_setup_center_and_remembers(state_dir, gui):
    """2026-10-01 (Vicki): collapsible like the Home page's Set up AI-Prowler
    panel — folded by default, ▸/▾ toggles the body, the tool count stays in
    the header, and the choice is saved to gui_sections.json."""
    btn = _fold_button(gui)
    assert str(btn.cget("text")).startswith("▸"), "should start folded"
    head = btn.master
    counter = [w for w in head.winfo_children() if isinstance(w, ttk.Label)
               and "tools" in str(w.cget("text")) and "enabled" in str(w.cget("text"))]
    assert counter, "the N of M tools enabled count belongs in the always-visible header"
    body = [w for w in head.master.winfo_children() if w is not head][0]
    assert not body.winfo_manager(), "folded body must not be packed"

    btn.invoke()
    gui.pump()
    assert str(btn.cget("text")).startswith("▾") and body.winfo_manager() == "pack"
    saved = json.loads((state_dir / "gui_sections.json").read_text(encoding="utf-8"))
    assert saved["mcp_tool_config"] is False            # remembered as open

    btn.invoke()
    gui.pump()
    assert str(btn.cget("text")).startswith("▸") and not body.winfo_manager()
    saved = json.loads((state_dir / "gui_sections.json").read_text(encoding="utf-8"))
    assert saved["mcp_tool_config"] is True
