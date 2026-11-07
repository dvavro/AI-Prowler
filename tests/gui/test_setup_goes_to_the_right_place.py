"""David 4 Nov: every Setup step goes to the right tab and the right place on it, on the real pages."""
from tkinter import ttk

import pytest

import setup_wizard as sw

STEPS = [m for m in sw.MODULES if not m.info_only]


def _walk(w):
    yield w
    for c in w.winfo_children():
        yield from _walk(c)


def _view(w):
    """(where the widget sits on its page, top of the view, bottom of the view), as fractions. None if it doesn't scroll."""
    inner, cv = w, w
    while cv is not None and cv.winfo_class() != "Canvas":
        inner, cv = cv, cv.master
    if cv is None:
        return None
    return (w.winfo_rooty() - inner.winfo_rooty()) / inner.winfo_height(), *cv.yview()


@pytest.fixture
def panel(gui, tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "SYNC_SWITCHES", False)
    nb = gui.app.notebook

    class App:
        notebook = nb
    prog = sw.Progress(path=tmp_path / "p.json", picked=True)
    prog.choose(["files"])
    return sw.SetupCenterPanel(ttk.Frame(gui.root), App(), progress=prog), nb, gui


def test_every_step_has_a_place_and_a_guided_window():
    assert {m.id for m in STEPS} | {"agent_key"} == set(sw.SECTIONS)
    assert {m.id for m in STEPS} == set(sw.GUIDED)


@pytest.mark.parametrize("mid", [m.id for m in STEPS])
def test_step_opens_its_tab_with_its_section_in_view(panel, mid):
    p, nb, gui = panel
    m = sw.BY_ID[mid]
    for other in nb.tabs():                             # start from somewhere else, scrolled to the end
        if nb.tab(other, "text").strip() != m.tab:
            nb.select(other)
            break
    gui.pump(20)
    trace = []
    p.open_tab(m)
    trace.append(nb.tab(nb.select(), "text").strip())
    gui.pump(20)
    trace.append(nb.tab(nb.select(), "text").strip())
    assert nb.tab(nb.select(), "text").strip() == m.tab, (trace, [nb.tab(t, "text") for t in nb.tabs()])
    page = gui.root.nametowidget(nb.select())
    w = sw.find_section(page, mid)
    assert w is not None, f"{mid}: nothing on {m.tab} starts with {sw.SECTIONS[mid]}"
    view = _view(w)
    if view is not None:                                # the tests' window is hidden, so read the scroll, not the screen
        where, top, bottom = view
        inner = w
        while inner.master.winfo_class() != "Canvas":
            inner = inner.master
        below_the_top = (where - top) * inner.winfo_height()   # pixels; the hidden test window's view can be tiny
        assert 0 <= below_the_top <= 14 or bottom >= 0.999, (mid, below_the_top, top, bottom)


@pytest.mark.parametrize("mid", ["email", "remote", "remote_pwa", "payments", "desk"])
def test_scrolling_really_moves_a_long_page(panel, mid):
    p, nb, gui = panel
    p.open_tab(sw.BY_ID[mid])
    gui.pump(20)
    where, top, _bottom = _view(sw.find_section(gui.root.nametowidget(nb.select()), mid))
    assert top > 0 and top <= where, (mid, where, top)


def test_going_back_up_the_same_page(panel):
    p, nb, gui = panel
    p.open_tab(sw.BY_ID["remote_pwa"])
    gui.pump(20)
    far = _view(sw.find_section(gui.root.nametowidget(nb.select()), "remote_pwa"))[1]
    p.open_tab(sw.BY_ID["email"])
    gui.pump(20)
    w = sw.find_section(gui.root.nametowidget(nb.select()), "email")
    where, top, bottom = _view(w)
    inner = w
    while inner.master.winfo_class() != "Canvas":
        inner = inner.master
    below_the_top = (where - top) * inner.winfo_height()   # pixels: the hidden test window's view is only a few pixels tall
    assert top < far and (0 <= below_the_top <= 14 or bottom >= 0.999), (top, far, below_the_top, bottom)


def test_change_my_key_goes_to_the_top_of_small_business(panel):
    p, nb, gui = panel
    nb.select(nb.tabs()[0])
    gui.pump(20)
    p.open_tab(sw.AGENT_KEY_TARGET)
    gui.pump(20)
    assert nb.tab(nb.select(), "text").strip() == "🏢 Small Business"
    assert sw.find_section(gui.root.nametowidget(nb.select()), "agent_key") is not None
    assert _view(sw.find_section(gui.root.nametowidget(nb.select()), "agent_key"))[1] == 0


def test_the_real_key_rows_have_lights(panel):
    p, nb, gui = panel
    keys = gui.app._agent_key_panel
    for prov in ("anthropic", "grok"):
        assert keys[prov]["light"].winfo_exists() and keys[prov]["light"].cget("text") == "●"


def test_a_missing_section_is_not_an_error(panel):
    p, nb, gui = panel
    nb.select(nb.tabs()[0])
    gui.pump(20)
    assert sw.scroll_to_section(gui.root.nametowidget(nb.tabs()[0]), "payments") is False


@pytest.mark.parametrize("mid", [m.id for m in STEPS if m.id != "connect_ai"])
def test_check_again_opens_that_steps_own_window(panel, mid, monkeypatch):
    p, nb, gui = panel
    opened = []
    monkeypatch.setitem(sw.GUIDED, mid, lambda pnl: opened.append(mid))
    p.start(sw.BY_ID[mid])
    assert opened == [mid]
