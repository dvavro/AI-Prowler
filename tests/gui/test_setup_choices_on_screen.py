"""David 2026-11-06: the Setup picker and the folding sections, on real windows."""
from tkinter import ttk

import pytest

import setup_wizard as sw
import tool_config_store as tcs


def _walk(w):
    yield w
    for c in w.winfo_children():
        yield from _walk(c)


@pytest.fixture
def panel(gui, tmp_path, monkeypatch):
    monkeypatch.setattr(tcs, "_state_dir", lambda: tmp_path)
    monkeypatch.setattr(sw, "SYNC_SWITCHES", False)
    import tkinter.messagebox as mb
    monkeypatch.setattr(mb, "askyesno", lambda *a, **k: True)
    tcs.set_group_enabled(sw.desk_mode(), "job_tracker", True)
    p = sw.Progress(path=tmp_path / "p.json", picked=True)
    p.choose(["files", "email", "phone", "analyses", "business"])

    class App:
        notebook = gui.app.notebook
    panel = sw.SetupCenterPanel(ttk.Frame(gui.root), App(), progress=p)
    panel.restarted = []
    panel.offer_tool_restart = lambda: panel.restarted.append(True)
    return panel, p, gui


def _open(panel):
    panel.open_picker()
    win = [w for w in _walk(panel.frame) if w.winfo_class() == "Toplevel"][-1]
    boxes = {w.cget("text"): w for w in _walk(win) if w.winfo_class() == "TCheckbutton"}
    btn = {w.cget("text"): w for w in _walk(win) if w.winfo_class() == "TButton"}
    return win, boxes, btn


def _box(boxes, word):
    return next(b for t, b in boxes.items() if word in t)


def test_bug_1_and_2_unticking_jobs_turns_it_and_its_routes_off(panel):
    p, prog, gui = panel
    win, boxes, btn = _open(p)
    _box(boxes, "service business").invoke()
    gui.root.update()
    assert not [t for t in boxes if "Plan routes" in t], "routes aren't a separate choice"
    btn["Save"].invoke()
    gui.root.update()
    assert not sw.jobs_switched_on()
    assert "business" not in prog.services
    assert not {"jobs", "payments", "routes"} & {m.id for m in prog.plan()}, "the lights still list it"
    assert p.restarted


@pytest.mark.parametrize("word,sid", [("review things", "analyses"), ("Send emails", "email"), ("from my phone", "phone")])
def test_bugs_3_4_5_unticking_saves_the_switch_and_offers_the_restart(panel, word, sid):
    p, prog, gui = panel
    win, boxes, btn = _open(p)
    _box(boxes, word).invoke()
    btn["Save"].invoke()
    gui.root.update()
    assert not tcs.feature_on(sid) and sid not in prog.services and p.restarted


def test_bug_6_off_then_on_then_off(panel):
    p, prog, gui = panel
    tcs.save_disabled_tools(["create_quote"], sw.desk_mode())
    prog.set_state("email", sw.DONE)
    for want in (False, True, False):
        win, boxes, btn = _open(p)
        _box(boxes, "Send emails").invoke()
        btn["Save"].invoke()
        gui.root.update()
        assert tcs.feature_on("email") is want
        assert prog.states["email"] == sw.DONE, "the step's progress was lost"
        assert "create_quote" in tcs.load_tool_config()[sw.desk_mode()]["disabled_tools"]


def test_a_section_folds_up_and_comes_back(gui):
    box = ttk.LabelFrame(gui.root, text="Email Configuration")
    a = ttk.Entry(box)
    a.insert(0, "kept")
    a.pack()
    b = ttk.Button(box, text="Save")
    b.pack()
    state = {"on": False}
    apply = sw.gate_section(gui.root, box, lambda: state["on"])
    apply()
    assert not a.winfo_manager() and not b.winfo_manager()
    assert any("not enabled" in str(w.cget("text")) for w in box.winfo_children() if w.winfo_class() == "TLabel" and w.winfo_manager())
    state["on"] = True
    apply()
    assert a.winfo_manager() == "pack" and b.winfo_manager() == "pack" and a.get() == "kept"
    assert not [w for w in box.winfo_children() if w.winfo_class() == "TLabel" and w.winfo_manager()]


def test_remote_access_is_named_and_the_picker_says_what_needs_it(panel):
    p, prog, gui = panel
    assert sw.BY_ID["remote"].title == "Remote Access (mobile secure link, phone apps, power settings)"
    win, boxes, btn = _open(p)
    marked = {t for t in boxes if sw.NEEDS_REMOTE_MARK in t}
    assert {_t for _t in marked if "from my phone" in _t or "service business" in _t or "tickets" in _t} == marked and len(marked) == 3
    assert not [t for t in boxes if "Send emails" in t and sw.NEEDS_REMOTE_MARK in t]
    text = " ".join(str(w.cget("text")) for w in _walk(win) if w.winfo_class() == "TLabel")
    for word in ("Jobs app", "Service Desk app", "Remote app", "Remote Access", "subscription"):
        assert word in text, word
    btn["Cancel"].invoke()


def test_every_step_has_a_dashed_line_to_its_buttons(panel):
    p, prog, gui = panel
    p.progress.set_collapsed(False)
    p.render()
    gui.root.update()
    lines = [w for w in _walk(p.frame) if getattr(w, "leader", False)]
    assert len(lines) == len(prog.plan()), (len(lines), len(prog.plan()))
    for ln in lines:
        assert ln.winfo_manager() == "pack" and ln.pack_info()["expand"] and ln.pack_info()["fill"] == "x"


def test_unticking_remote_access_takes_the_apps_with_it(panel, monkeypatch):
    """David 2026-11-06: phone off with every feature on left the server and the apps running."""
    p, prog, gui = panel
    tcs.set_group_enabled(sw.desk_mode(), "service_desk", True)
    import tkinter.messagebox as mb
    asked = []
    monkeypatch.setattr(mb, "askyesno", lambda title, *a, **k: asked.append(title) or True)
    win, boxes, btn = _open(p)
    assert _box(boxes, "service business").instate(["selected"]) and _box(boxes, "tickets").instate(["selected"])
    _box(boxes, "from my phone").invoke()
    gui.root.update()
    assert not _box(boxes, "service business").instate(["selected"]) and not _box(boxes, "tickets").instate(["selected"])
    btn["Save"].invoke()
    gui.root.update()
    assert asked == ["Turn these off?"], asked                  # one question, not three
    assert not tcs.http_server_wanted(sw.desk_mode()) and not sw.http_wanted()
    assert not sw.jobs_switched_on() and not sw.desk_switched_on()
    assert not {"phone", "business", "desk"} & set(prog.services)
    assert not {"remote", "remote_pwa", "jobs", "payments", "routes", "desk"} & {m.id for m in prog.plan()}


def test_ticking_an_app_ticks_remote_access(panel):
    p, prog, gui = panel
    tcs.set_feature_on("phone", False)
    win, boxes, btn = _open(p)
    assert not _box(boxes, "from my phone").instate(["selected"])
    _box(boxes, "tickets").invoke()
    gui.root.update()
    assert _box(boxes, "from my phone").instate(["selected"])
    btn["Cancel"].invoke()
