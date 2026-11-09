"""Sprint 16: the 🏗 Estimator tab and its Setup AI-Prowler step, drawn with tkinter (S16-G..).

Needs a screen: skipped where tkinter can't open a window. On AI-Prowler's PC the real setup_wizard is used;
anywhere else a small stand-in with the same names is.
"""
import sys
import types

import pytest

tk = pytest.importorskip("tkinter")
from tkinter import ttk  # noqa: E402

from estimator.ui import model  # noqa: E402


@pytest.fixture(scope="module")
def _tk_root():
    """One Tk for the whole file: on Windows, making a new Tk for every test now and then fails to start Tcl."""
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no screen for tkinter")
    r.withdraw()
    yield r
    r.destroy()


@pytest.fixture
def root(_tk_root):
    frame = ttk.Frame(_tk_root)                      # each test draws in its own frame, thrown away after
    frame.winfo_toplevel = lambda: _tk_root
    yield frame
    frame.destroy()


@pytest.fixture
def db_home(tmp_path, monkeypatch):
    monkeypatch.setenv("ESTIMATOR_DATA_DIR", str(tmp_path / "est"))
    yield tmp_path


@pytest.fixture
def switch(monkeypatch):
    store = {}
    fake = types.SimpleNamespace(feature_on=lambda n: store.get(n, True),
                                 set_feature_on=lambda n, on: store.__setitem__(n, on))
    monkeypatch.setitem(sys.modules, "tool_config_store", fake)
    return store


def _stand_in_wizard():
    """The few names of AI-Prowler's setup_wizard the Estimator uses, for machines without AI-Prowler."""
    sw = types.ModuleType("setup_wizard")
    sw.DONE, sw.SKIPPED = "done", "skipped"
    sw.BY_ID = {"estimator": types.SimpleNamespace(why="Estimates and bids.", tab="🏗 Estimator")}

    def gate_section(root, frame, is_on, note=""):
        label = ttk.Label(frame, text=note)
        hidden = []

        def apply():
            if not is_on() and not hidden:
                for c in frame.winfo_children():
                    if c is not label and c.winfo_manager() == "pack":
                        hidden.append((c, c.pack_info()))
                        c.pack_forget()
                label.pack()
            elif is_on() and hidden:
                label.pack_forget()
                for c, info in hidden:
                    c.pack(**info)
                hidden.clear()
        apply()
        return apply
    sw.gate_section = gate_section

    class _SimpleFlow:
        def __init__(self, panel, title, module_id):
            self.panel, self.app, self.tk, self.ttk, self.module_id = panel, panel.app, tk, ttk, module_id
            self.win = tk.Toplevel(panel.frame)
            self.body = ttk.Frame(self.win)
            self.body.pack()

        def _footer(self, action_text, action):
            self.msg = ttk.Label(self.body, text="")
            self.msg.pack()
            self._footer_bar = ttk.Frame(self.body)
            self._footer_bar.pack()

        def _say(self, text, ok=True):
            self.msg.config(text=text)

        def _done(self):
            self.panel.progress.set_state(self.module_id, sw.DONE)
    sw._SimpleFlow = _SimpleFlow
    return sw


@pytest.fixture
def wizard(monkeypatch):
    try:
        import setup_wizard as sw                       # AI-Prowler's own, on its PC
        if "estimator" in sw.BY_ID:
            return sw
    except Exception:  # noqa: BLE001
        pass
    sw = _stand_in_wizard()
    monkeypatch.setitem(sys.modules, "setup_wizard", sw)
    return sw


class FakeApp:
    def __init__(self, root):
        self.root = root
        self.notebook = ttk.Notebook(root)
        self.notebook.pack()
        self.notebook.add(ttk.Frame(self.notebook), text="🏢 Small Business")


def _texts(widget):
    out = []
    for c in widget.winfo_children():
        try:
            out.append(str(c.cget("text")))
        except tk.TclError:
            pass
        out += _texts(c)
    return out


def _find(widget, text_start):
    for c in widget.winfo_children():
        try:
            if str(c.cget("text")).startswith(text_start):
                return c
        except tk.TclError:
            pass
        hit = _find(c, text_start)
        if hit is not None:
            return hit
    return None


def test_tab_is_added_with_its_sections(root, db_home, switch, wizard):  # S16-G01
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    frame = build_estimator_tab(app)
    assert frame is not None and app.notebook.tab(1, "text") == model.TAB_TITLE
    tab = app._estimator_tab
    assert set(tab.sections) == {"setup", "company", "trades", "agents", "director", "modules", "data", "cad", "phone",
                                 "help"}
    texts = _texts(frame)
    assert any(t.startswith("🧭 Estimator setup") for t in texts)        # Setup AI-Prowler scrolls to this
    assert any("The Estimator is ON" in t for t in texts) and any("Setup checklist: 0 of 10" in t for t in texts)
    assert len(tab.trade_vars) == 15 and all(v.get() for v in tab.trade_vars.values())


def test_company_form_saves(root, db_home, switch, wizard):  # S16-G02
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    for k, v in {"name": "Vavro Roofing", "tax_pct": "8.6", "overhead_pct": "10", "profit_pct": "15"}.items():
        tab.company_vars[k].set(v)
    _find(tab.sections["company"], "💾 Save company").invoke()
    assert model.profile()["name"] == "Vavro Roofing" and model.setup_light() is True
    assert any("2 of 10" in t or "3 of 10" in t for t in _texts(tab.check_frame))


def test_switch_off_folds_sections(root, db_home, switch, wizard):  # S16-G03
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    tab.switch_btn.invoke()                                           # turn it off
    assert switch["estimator"] is False and "OFF" in tab.state_lbl.cget("text")
    assert not tab.check_frame.winfo_children()                        # no checklist while it's off
    tab.switch_btn.invoke()
    assert switch["estimator"] is True


def test_trade_checkbox_saves(root, db_home, switch, wizard):  # S16-G04
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    _find(tab.sections["trades"], "Fencing").invoke()
    assert next(t for t in model.trades() if t["module_id"] == "fencing")["enabled"] is False


def test_tab_never_breaks_the_gui(root, monkeypatch, switch, wizard):  # S16-G05
    from estimator.ui import gui_tab
    monkeypatch.setattr(gui_tab, "EstimatorTab", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    app = FakeApp(root)
    assert gui_tab.build_estimator_tab(app) is None                  # printed, not raised


def test_setup_step_saves_and_turns_on(root, db_home, switch, wizard):  # S16-G06
    from estimator.ui.setup_flow import make_flow
    switch["estimator"] = False
    states = {}
    panel = types.SimpleNamespace(frame=ttk.Frame(root), app=FakeApp(root), render=lambda: None,
                                  progress=types.SimpleNamespace(set_state=states.__setitem__, services=[]))
    flow = make_flow(panel)
    flow.vars["name"].set("Garcia Pools")
    flow.vars["tax_pct"].set("7")
    flow.save()
    assert switch["estimator"] is True and states["estimator"] == wizard.DONE
    assert model.profile()["name"] == "Garcia Pools" and model.profile()["tax_pct"] == "7"
    flow.win.destroy()


def test_setup_step_shows_errors(root, db_home, switch, wizard):  # S16-G07
    from estimator.ui.setup_flow import make_flow
    states = {}
    panel = types.SimpleNamespace(frame=ttk.Frame(root), app=FakeApp(root), render=lambda: None,
                                  progress=types.SimpleNamespace(set_state=states.__setitem__, services=[]))
    flow = make_flow(panel)
    flow.vars["name"].set("")
    flow.save()
    assert "estimator" not in states and "name" in flow.msg.cget("text").lower()
    flow.win.destroy()


def test_register_skips_when_off(switch):  # S16-G08
    from estimator.mcp_tools import est_tools
    added = []
    mcp = types.SimpleNamespace(tool=lambda: added.append)
    switch["estimator"] = False
    assert est_tools.register(mcp) == [] and added == []


def test_setup_wizard_knows_the_estimator(wizard):  # S16-G09
    """On AI-Prowler's PC: the Estimator is a choice, a step, a switch and a guided window in Setup AI-Prowler."""
    if not hasattr(wizard, "SERVICES"):
        pytest.skip("AI-Prowler's setup_wizard isn't here")
    assert "estimator" in wizard.FEATURE_SERVICES and "estimator" in wizard.SERVICE_IDS
    m = wizard.BY_ID["estimator"]
    assert m.tab == model.TAB_TITLE and m.detect is wizard.detect_estimator and "estimator" in wizard.GUIDED
    assert wizard.SECTIONS["estimator"] == ("🧭 Estimator setup",)
    assert [x.id for x in wizard.modules_for(["estimator"])] == ["estimator"]
