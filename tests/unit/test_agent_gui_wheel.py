"""Scrolling the Small Business tab never changes a setting (Vicki 2026-10-31: "had all set to auto,
then change a setting in the service desk agent and two other setting changed from auto to suggest").
Tk's drop-downs and number boxes step their value when the mouse wheel turns over them, so scrolling
down the page changed whatever passed under the pointer and the next Save kept it.
This also runs Vicki's check: every step on Auto, then one by one change a step, scroll over every
control, press each Save on its own, and nothing else may change in any of the three databases.
Run: run_tests.bat tests\\unit\\test_agent_gui_wheel.py
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent_hr_store as hstore  # noqa: E402
import desk_agent_settings as das  # noqa: E402
import desk_agent_store as store  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import desk_gui_links  # noqa: E402
import desk_gui_settings  # noqa: E402

tk = pytest.importorskip("tkinter")
from tkinter import messagebox, ttk  # noqa: E402

AUTO, SUG = das.STAGE_MODE_LABELS["auto"], das.STAGE_MODE_LABELS["suggest"]


@pytest.fixture(params=["personal", "server"])
def tab(request, tmp_path, monkeypatch):
    mode = request.param
    ed = "solo" if mode == "personal" else "business"
    tdb = str(tmp_path / "tickets.db")
    monkeypatch.setattr(store, "PATH_OVERRIDE", tmp_path / "agent.db")
    monkeypatch.setattr(hstore, "PATH_OVERRIDE", tmp_path / "hr" / "agent" / "hr_agent.db")
    monkeypatch.setattr(desk_gui_links, "_state_dir", lambda: tmp_path)
    monkeypatch.setattr(desk_gui_links, "mode_of", lambda: mode)
    monkeypatch.setattr(desk_gui_links, "desk_switched_on", lambda: True)
    monkeypatch.setattr(desk_db, "default_db_path", lambda: tdb)
    for n in ("showinfo", "showerror", "showwarning"):
        monkeypatch.setattr(messagebox, n, lambda *a, **k: None)
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **k: True)
    desk_db.init_db(tdb)

    def put(w, k, v):
        if w == "desk":
            desk_db.set_setting(tdb, k, v, edition=ed)
        elif w == "jobs":
            store.set_setting(k, v, edition=ed)
        else:
            hstore.set_setting(k, v, edition=ed)

    for w, keys in (("desk", [k for k in das.DEFAULTS if k.startswith(("agent_stage_", "agent_bk_stage_"))]),
                    ("jobs", [k for k in das.JB_KEYS if "_stage_" in k]),
                    ("hr", [k for k in das.DEFAULTS if k.startswith("agent_hr_stage_")])):
        for k in keys:
            put(w, k, "auto")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    # 2026-11-02: the settings builders make their tk variables without a window, so they join Tk's
    # default window — in a full run that's a window an earlier test left open, and every drop-down
    # here then shows blank instead of Auto (failed only in the full run). This test's window is it.
    monkeypatch.setattr(tk, "_default_root", root)

    class App:
        status_var = tk.StringVar(master=root)
    App.root = root
    fr = ttk.Frame(root); fr.pack()
    secs = {"desk": desk_gui_settings.build_section(App(), fr),
            "jobs": dga.build_standalone_section(App(), fr, "jobs"),
            "hr": dga.build_standalone_section(App(), fr, "hr")}
    secs["jobs"]["frame"].pack(); secs["hr"]["frame"].pack()
    root.update()

    def snap():
        out = {}
        for w, s in (("desk", desk_db.get_settings(tdb)), ("jobs", store.settings()), ("hr", hstore.all_settings())):
            out.update({(w, k): v for k, v in s.items()})
        return out

    yield {"root": root, "secs": secs, "snap": snap}
    root.destroy()


def walk(w, kinds, acc):
    for c in w.winfo_children():
        if isinstance(c, kinds):
            acc.append(c)
        walk(c, kinds, acc)
    return acc


def scroll_over(t, widgets):
    for w in widgets:
        for d in (-120, -120, 120):
            w.event_generate("<MouseWheel>", delta=d, when="now")
    t["root"].update()


def test_the_mouse_wheel_scrolls_the_page_but_never_changes_a_value(tab):
    reached = []
    tab["root"].bind_all("<MouseWheel>", lambda e: reached.append(1), add="+")
    ctrls = [c for s in tab["secs"].values() for c in walk(s["frame"], (ttk.Combobox, ttk.Spinbox, tk.Spinbox), [])]
    assert len(ctrls) > 40
    before = [c.get() for c in ctrls]
    scroll_over(tab, ctrls)
    assert [c.get() for c in ctrls] == before
    assert len(reached) == 3 * len(ctrls)                 # the page's own scroll handler still gets every turn


def test_all_auto_then_one_change_at_a_time_changes_nothing_else(tab):
    secs, snap, root = tab["secs"], tab["snap"], tab["root"]
    saves = [(n, b) for n, s in secs.items() for b in walk(s["frame"], ttk.Button, []) if "Save" in str(b.cget("text"))]
    combos = [(n, c) for n, s in secs.items() for c in walk(s["frame"], ttk.Combobox, [])
              if AUTO in tuple(c.cget("values"))]
    ctrls = [c for s in secs.values() for c in walk(s["frame"], (ttk.Combobox, ttk.Spinbox, tk.Spinbox), [])]
    assert len(combos) >= 30 and all(c.get() == AUTO for _, c in combos)
    base = snap()
    for n, c in combos:
        scroll_over(tab, ctrls)
        c.set(SUG); c.event_generate("<<ComboboxSelected>>"); root.update()
        scroll_over(tab, ctrls)
        for _sn, b in saves:                              # every Save, one at a time
            b.invoke(); root.update()
        now = snap()
        moved = {k: (base[k], now[k]) for k in base if now[k] != base[k]}
        assert len(moved) == 1 and list(moved.values())[0] == ("auto", "suggest"), (n, moved)
        c.set(AUTO); c.event_generate("<<ComboboxSelected>>"); root.update()
        for sn, b in saves:
            if sn == n:
                b.invoke(); root.update()
        assert snap() == base
