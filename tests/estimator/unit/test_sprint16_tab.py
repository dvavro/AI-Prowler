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
    assert set(tab.sections) == {"setup", "company", "labor", "trades", "agents", "director", "modules", "data", "sync",
                                 "cad", "phone", "help"}
    texts = _texts(frame)
    assert any("🧭 Estimator setup" in t for t in texts)                  # Setup AI-Prowler scrolls to this
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


def _setup_buttons(widget):
    """Every ttk.Button under widget whose text is "Set up"."""
    out = []
    for c in widget.winfo_children():
        try:
            if isinstance(c, ttk.Button) and str(c.cget("text")) == "Set up":
                out.append(c)
        except tk.TclError:
            pass
        out += _setup_buttons(c)
    return out


def _buttons_named(widget, text):
    """Every ttk.Button under widget whose text is exactly `text`."""
    out = []
    for c in widget.winfo_children():
        try:
            if isinstance(c, ttk.Button) and str(c.cget("text")) == text:
                out.append(c)
        except tk.TclError:
            pass
        out += _buttons_named(c, text)
    return out


def _leaders(widget):
    """Every Canvas under widget flagged as a checklist leader line."""
    out = []
    for c in widget.winfo_children():
        if isinstance(c, tk.Canvas) and getattr(c, "leader", False):
            out.append(c)
        out += _leaders(c)
    return out


def test_labor_section_lists_labor_rates(root, db_home, switch, wizard):  # S16-G10 (tab bug 7)
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    assert "labor" in tab.sections
    assert tab._section_title["labor"] == "💰 Labor rates"
    assert "hc_labor_hr" in tab.labor_vars and tab.labor_vars["hc_labor_hr"].get() == "50.00"
    rates = model.labor_rates()
    assert rates and all(r["price_key"] for r in rates)
    assert any(r["price_key"] == "hc_labor_hr" for r in rates)


def test_labor_rates_save_marks_step_done(root, db_home, switch, wizard):  # S16-G11 (tab bug 7)
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    tab.labor_vars["hc_labor_hr"].set("55")
    _find(tab.sections["labor"], "💾 Save labor rates").invoke()
    got = next(r for r in model.labor_rates() if r["price_key"] == "hc_labor_hr")
    assert got["cost_cents"] == 5500 and got["sample"] is False
    assert any("1 of 10" in t for t in _texts(tab.check_frame))


def test_labor_rates_save_refuses_non_labor(db_home, switch):  # S16-G12 (tab bug 7)
    ok, msg = model.save_labor_rates({"pw_driveway_sqft": "0.20"})
    assert ok is False and "aren't labor rates" in msg


def test_checklist_has_setup_for_every_step(root, db_home, switch, wizard):  # S16-G13 (tab bug 1)
    """Every one of the 10 checklist steps has a Set up button while it is not done."""
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    assert any("Setup checklist: 0 of 10" in t for t in _texts(tab.check_frame))
    assert len(_setup_buttons(tab.check_frame)) == 10


def test_services_listed_in_trades(root, db_home, switch, wizard):  # S16-G14 (tab bug 3)
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    texts = " ".join(_texts(tab.sections["trades"]))
    for name in ("Pressure Washing", "Window Cleaning", "House Cleaning", "Pest Control"):
        assert name in texts
    assert [s["name"] for s in model.services()] == sorted(s["name"] for s in model.services())


def test_web_app_mentions_jobs_app(db_home, switch):  # S16-G15 (tab bug 5)
    assert any("Jobs app" in ln and "Estimates" in ln for ln in model.web_app_access()["lines"])


def test_company_note_explains_overhead(root, db_home, switch, wizard):  # S16-G16 (tab bug 2)
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    texts = " ".join(_texts(tab.sections["company"]))
    assert "Overhead % is the slice added to every bid" in texts
    assert "Profit % is then charged on top of cost + overhead" in texts


def test_help_button_opens_user_guide_at_chapter_29(root, db_home, switch, wizard):  # S16-G17 (tab bug 6)
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    calls = {}
    app.show_user_guide = lambda section=None: calls.__setitem__("section", section)
    build_estimator_tab(app)
    tab = app._estimator_tab
    _find(tab.sections["help"], "📖 Open the User Guide").invoke()
    assert calls.get("section") == "29. Estimator"


def test_done_checklist_steps_keep_a_change_button(root, db_home, switch, wizard):  # S16-G18
    """A done step keeps a Change button (same action as Set up); it stays done."""
    from estimator.ui import gui_tab
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    # mark_step() with no data cannot finish these steps (the company name, a trade,
    # a tax rate and the markups are all required) — complete them with real data,
    # the way the setup wizard does.
    from contextlib import closing
    from estimator.context import personal_context
    from estimator.database import open_database
    from estimator.estimating import setup
    data = {
        "company_profile": {"name": "Test Co", "phone": "480-555-0100"},
        "services": {"modules": ["pressure_washing"]},
        "tax": {"tax_pct": "0.08"},
        "markups": {"overhead_pct": "0.10", "profit_pct": "0.20", "minimum_charge": "125"},
    }
    with closing(open_database()) as conn:
        for step, d in data.items():
            setup.setup_step(conn, personal_context(), step, d)
    tab.refresh_setup()
    assert any("Setup checklist: 4 of 10" in x for x in _texts(tab.check_frame))
    assert len(_buttons_named(tab.check_frame, "Change")) == 4
    assert len(_setup_buttons(tab.check_frame)) == 6
    # Change on Company profile scrolls to the Company section — same as Set up did.
    calls = []
    tab._scroll_to = lambda title: calls.append(title)
    change = _buttons_named(tab.check_frame, "Change")
    # the Change button in the same grid row as the "Company profile" label
    row = None
    for c in tab.check_frame.winfo_children():
        for w in c.winfo_children():
            try:
                if str(w.cget("text")).startswith("✅  Company profile"):
                    row = w.grid_info()["row"]
            except tk.TclError:
                pass
    assert row is not None
    btn = [b for b in change if b.grid_info()["row"] == row]
    assert len(btn) == 1
    btn[0].invoke()
    assert calls == ["🏢 Company and pricing"]
    # clicking Change does not un-done the step
    steps = {s["step"]: s["status"] for s in model.overview()["setup"]["steps"]}
    assert steps["company_profile"] == "done"


def test_checklist_rows_have_leader_lines(root, db_home, switch, wizard):  # S16-G19
    """Every checklist row has a dashed leader line from its text to its buttons."""
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    root.update_idletasks()
    leaders = _leaders(tab.check_frame)
    assert len(leaders) == 10
    for line in leaders:
        assert line.grid_info()["column"] == 1
        assert len(line.find_all()) >= 1  # the dashed line is drawn
    rows = leaders[0].master
    assert rows.columnconfigure(1)["weight"] == 1


def test_labor_rate_lines_do_not_say_sample(root, db_home, switch, wizard):  # S16-G20
    """No labor-rate line says 'sample' — the description's own '(sample)' and the
    flag's '— sample' suffix doubled it on every line."""
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    labels = []

    def walk(w):
        for c in w.winfo_children():
            try:
                txt = str(c.cget("text"))
            except tk.TclError:
                txt = ""
            if "(per " in txt:
                labels.append(txt)
            walk(c)

    walk(tab.sections["labor"])
    assert labels, "no labor rate rows found"
    for txt in labels:
        assert "sample" not in txt.lower(), txt


def test_section_title_collapses_and_expands(root, db_home, switch, wizard):  # S16-G21
    """Selecting a section title collapses it; selecting it again expands it."""
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    body = tab.sections["labor"]
    header = tab._section_header["labor"]
    assert header.bind("<Button-1>"), "title has no click binding"
    assert body.winfo_manager() == "pack"
    tab._toggle_section("labor")
    assert body.winfo_manager() == ""
    assert tab._section_collapsed["labor"] is True
    assert header.cget("text").startswith("▶ ")
    tab._toggle_section("labor")
    assert body.winfo_manager() == "pack"
    assert tab._section_collapsed["labor"] is False
    assert header.cget("text").startswith("▼ ")


def test_scroll_to_expands_a_collapsed_section(root, db_home, switch, wizard):  # S16-G22
    """Going to a section (Set up / Change) opens it if it was collapsed."""
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    tab._toggle_section("company")
    assert tab._section_collapsed["company"] is True
    tab._scroll_to("🏢 Company and pricing")
    assert tab._section_collapsed["company"] is False
    assert tab.sections["company"].winfo_manager() == "pack"


def test_collapsed_section_shrinks_to_its_title(root, db_home, switch, wizard):  # S16-G23
    """A collapsed section takes only its title's height — no big empty box.
    (A LabelFrame keeps its expanded height after its content is unpacked.)"""
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    root.update_idletasks()
    outer = tab._section_box["labor"]
    before = outer.winfo_reqheight()
    assert before > 200, f"labor section should be tall when expanded, got {before}"
    tab._toggle_section("labor")
    root.update_idletasks()
    after = outer.winfo_reqheight()
    assert after < before // 3, f"collapsed {after} vs expanded {before}"
    tab._toggle_section("labor")
    root.update_idletasks()
    assert outer.winfo_reqheight() == before


def test_scrollbar_reaches_bottom_after_collapse_all_and_expand(root, db_home, switch, wizard):  # S16-G24
    """The scrollbar's range follows the content when sections collapse/expand:
    collapse all, expand one, and the scrollbar must still reach the sections
    further down. (Forcing the canvas window height to max(content, canvas) went
    stale — the inner frame kept the old height, so the scrollbar could not reach
    the sections further down. The inner frame height is the discriminating check:
    the scrollregion alone happens to stay right in a withdrawn window.)"""
    import rag_gui
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    app._make_scrollable_tab = lambda o: rag_gui.RAGGui._make_scrollable_tab(None, o)
    build_estimator_tab(app)
    tab = app._estimator_tab
    inner = tab.parent
    canvas = inner.master
    assert canvas.winfo_class() == "Canvas"

    def check(tag):
        # the inner frame and the scrollbar range must both match the content
        root.update_idletasks()
        assert abs(inner.winfo_height() - inner.winfo_reqheight()) <= 2, tag
        assert abs(int(canvas.cget("scrollregion").split()[3]) - inner.winfo_reqheight()) <= 2, tag

    check("start")
    for k in list(tab._section_collapsed):
        if not tab._section_collapsed[k]:
            tab._toggle_section(k)
    check("collapse-all")
    tab._toggle_section("labor")
    check("expand labor")
    for k in ("setup", "company", "trades"):
        tab._toggle_section(k)
    check("expand setup+company+trades")
    canvas.yview_moveto(1.0)
    root.update_idletasks()
    assert canvas.yview()[1] == 1.0, "scrollbar must reach the bottom"


# ---------------------------------------------------------------- 🤖 AI agents, set up like the other agents (2026-11-13)

def _roles():
    from estimator.agents import roles
    with model._open() as conn:
        return {r["role"]: r for r in roles.overview(conn, "default")["roles"]}


def test_agents_section_sets_each_step_and_one_runner(root, db_home, switch, wizard):  # S16-G20
    from estimator.ui import agents_flow as af
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    v = tab._agent_vars
    assert {k for k in v if k.startswith("mode_")} == {"mode_" + r for r, _s, _st in af.STEPS}
    assert all(v["mode_" + r].get() == "Off" for r, _s, _st in af.STEPS)        # everything starts Off
    v["runner"].set("Grok (API key)")
    v["backup"].set("Claude (API key)")
    v["mode_llm_takeoff"].set("Suggest (a person approves)")
    v["mode_reviewer"].set("From chat only")
    v["day"].set("3.50")
    tab._agent_save()
    got = _roles()
    assert (got["llm_takeoff"]["provider"], got["llm_takeoff"]["fallback_provider"]) == ("grok_api", "claude_api")
    assert got["reviewer"]["provider"] == "chat_only" and got["reviewer"]["fallback_provider"] is None
    assert got["bid_writer"]["provider"] == "off"
    assert model.agents()["budget"]["daily_cents"] == 350
    v["mode_llm_takeoff"].set("Off")                                             # and back off again
    tab._agent_save()
    assert _roles()["llm_takeoff"]["provider"] == "off"


def test_each_agent_can_have_its_own_model(root, db_home, switch, wizard):  # S16-G22
    from estimator.agents import providers
    from estimator.ui import agents_flow as af
    from estimator.ui.gui_tab import build_estimator_tab
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    v = tab._agent_vars
    assert v["model_llm_takeoff"].get() == af.GROUP_DEFAULT                     # follows the Small Business tab
    v["mode_llm_takeoff"].set("Suggest (a person approves)")
    v["model_llm_takeoff"].set("Claude Opus 5.5")
    tab._agent_save()
    r = _roles()["llm_takeoff"]
    assert r["provider"] == "claude_api" and r["model_pinned"] == "claude-opus-5-5"
    assert providers.model_for_step("claude_api", "llm_takeoff", "classify", r["model_pinned"]) == "claude-opus-5-5"
    v["runner"].set("Grok (API key)")                                            # a Claude model can't run on Grok
    assert v["model_llm_takeoff"].get() == af.GROUP_DEFAULT
    tab._agent_save()
    assert _roles()["llm_takeoff"]["model_pinned"] is None


def test_cad_check_again_and_phone_link(root, db_home, switch, wizard, monkeypatch, tmp_path):  # S16-G23
    from estimator.ui.gui_tab import build_estimator_tab
    calls = []
    monkeypatch.setattr(model, "recheck_tools", lambda: calls.append(1) or
                        [{"tool": "Tesseract OCR (reads scanned plans)", "ok": True, "detail": "Found at C:\\t.exe."}])
    monkeypatch.setattr(model, "phone_link", lambda: "https://ap-test.ai-prowler.com/estimator/")
    monkeypatch.setattr(model, "jobs_link", lambda: "https://ap-test.ai-prowler.com/jobs/")
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    tab.cad_recheck()
    assert calls == [1]
    assert any("Tesseract OCR" in w.cget("text") and w.cget("text").startswith("✅")
               for w in tab.cad_lines.winfo_children())
    assert tab.phone_url.get() == "https://ap-test.ai-prowler.com/estimator/"
    assert tab.jobs_url.get() == "https://ap-test.ai-prowler.com/jobs/"
    buttons = [w.cget("text") for w in _walk(tab.sections["phone"]) if isinstance(w, ttk.Button)]
    assert buttons[0] == "🌐 Open Estimator in browser"                         # the desktop one comes first
    assert buttons.count("📋 Copy") == 2 and buttons.count("📧 Email to user") == 2 and buttons.count("📱 QR") == 2
    frames = [w.cget("text") for w in _walk(tab.sections["phone"]) if isinstance(w, ttk.LabelFrame)]
    assert frames[0].startswith("🖥 On this PC") and frames[1].startswith("📱 Estimator") and frames[2].startswith("🧰 Jobs App")


def _walk(w):
    for c in w.winfo_children():
        yield c
        yield from _walk(c)


def test_send_project_to_server_section(root, db_home, switch, wizard, monkeypatch, tmp_path):  # S16-G24
    from estimator.ui.gui_tab import build_estimator_tab
    from estimator.estimating import service
    from estimator.context import personal_context
    from estimator.database import open_database
    conn = open_database()
    eid = service.create_estimate(conn, personal_context(), "Smith house", address="12 Oak St")["id"]
    conn.close()
    sent = []
    monkeypatch.setattr(model, "send_project", lambda e, via, password="", replace=False:
                        sent.append((e, via, password, replace)) or (True, "Copied to the server's inbox."))
    app = FakeApp(root)
    build_estimator_tab(app)
    tab = app._estimator_tab
    texts = [w.cget("text") for w in _walk(tab.sections["sync"]) if isinstance(w, ttk.Button)]
    assert "🏢 Send through the office network (faster)" in texts and "🌐 Send over the internet" in texts
    v = tab._sync_vars
    assert v["project"].get().startswith(f"#{eid}  Smith house")
    share = tmp_path / "exchange"
    share.mkdir()
    v["share"].set(str(share))
    v["url"].set("acme.example.com/jobs/")
    v["user"].set("dana")
    v["password"].set("secret")
    tab._sync_go("internet")
    for _ in range(50):
        root.update()
        if sent and tab._sync_status.cget("text").startswith("✅"):
            break
        import time
        time.sleep(0.05)
    assert sent == [(eid, "internet", "secret", False)], tab._sync_status.cget("text")
    assert tab._sync_status.cget("text").startswith("✅") and v["password"].get() == ""   # never kept around
    saved = model.sync_settings()
    assert saved == {"server_url": "https://acme.example.com", "username": "dana", "share_path": str(share)}


def test_agents_flow_colours_each_step_by_its_mode():  # S16-G21
    from estimator.ui import agents_flow as af
    pic = af.flow({"llm_takeoff": "on", "reviewer": "chat_only", "plan_reader": "on"},
                  {"plan_reader": False, "takeoff": False}, "claude_api")
    steps = {s["id"]: s for s in pic["steps"]}
    assert steps["llm_takeoff"]["color"] == af.COLORS["on"] and steps["llm_takeoff"]["word"] == "waits for OK"
    assert steps["reviewer"]["color"] == af.COLORS["chat_only"] and steps["bid_writer"]["word"] == "off"
    assert steps["plan_reader"]["word"] == "needs plans"                          # on, but waits for the Plan Engine
    lit = {s["id"] for s in pic["states"] if s["lit"]}
    assert lit == {"Takeoff", "Review"}                                          # Plans isn't lit: it can't run yet
    assert "AI takeoff" in pic["summary"] and "Reviewer" in pic["summary"]
    assert "complex step" in steps["llm_takeoff"]["help"] and "internal step" in steps["reviewer"]["help"]
