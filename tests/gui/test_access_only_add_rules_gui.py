"""Access-only ADD rules on the DESKTOP (Update Index tab → Access-Only Folders),
personal mode (David 2026-10-10). Same shared check as Claude's grant_access and
the Remote app — see tests\\mcp_tests\\test_access_only_add_rules.py.

  AG-01  a folder is added (and listed)
  AG-02  a duplicate → "Can't add access-only folder … already an access-only folder"
  AG-03  a folder inside an access-only folder → "… already covered by …"
  AG-04  a folder inside an indexed folder → "… inside indexed folder …"
  AG-05  a parent of access-only folders → added, the inner ones folded in (info popup)
  AG-06  a file (e.g. typed/picked by mistake) → "… is a file … folders only …"
  AG-07  server window: the Access-Only panel isn't shown at all

Run: run_tests.bat tests\\gui\\test_access_only_add_rules_gui.py -v
"""
import pytest


def _rebuild_gui(gui):
    import rag_gui as gui_mod
    for child in list(gui.root.winfo_children()):
        try:
            child.destroy()
        except Exception:
            pass
    gui.app = gui_mod.RAGGui(gui.root)
    gui.pump()
    return gui


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    import urllib.request

    def _offline(*a, **kw):
        raise OSError("network is switched off in the desktop GUI tests")
    monkeypatch.setattr(urllib.request, "urlopen", _offline)


@pytest.fixture
def win(gui, sandbox_state, tmp_path, monkeypatch):
    sandbox_state.set_config(edition="home", mode="personal")
    g = _rebuild_gui(gui)
    # the panel's list file → a temp file
    import rag_gui as gui_mod
    monkeypatch.setattr(gui_mod.RAGGui, "_access_only_dirs_file",
                        property(lambda self: tmp_path / ".rag_access_only_dirs.json"))
    return g


@pytest.fixture
def tree(isolated_env):
    root = isolated_env.sample_root / "ao_gui"
    for p in ("Docs/Manuals", "Docs/Other", "Indexed/Inside"):
        (root / p).mkdir(parents=True, exist_ok=True)
    (root / "Docs" / "note.txt").write_text("x", encoding="utf-8")
    return root


def _warnings(dialogs, title="Can't add access-only folder"):
    return [c for c in dialogs.calls if c["title"] == title]


def _listed(win):
    return [p.lower() for p in win.app._load_access_only_paths()]


def test_AG_01_add(win, dialogs, tree):
    assert win.app._add_access_only_path(str(tree / "Docs")) is True
    assert str((tree / "Docs").resolve()).lower() in _listed(win)
    assert not _warnings(dialogs)


def test_AG_02_duplicate(win, dialogs, tree):
    win.app._add_access_only_path(str(tree / "Docs"))
    dialogs.reset()
    assert win.app._add_access_only_path(str(tree / "Docs")) is False
    w = _warnings(dialogs)
    assert w and "already an access-only folder" in w[-1]["message"], dialogs.calls
    assert len(_listed(win)) == 1


def test_AG_03_inside_access_only_folder(win, dialogs, tree):
    win.app._add_access_only_path(str(tree / "Docs"))
    dialogs.reset()
    assert win.app._add_access_only_path(str(tree / "Docs" / "Manuals")) is False
    w = _warnings(dialogs)
    assert w and "already covered by access-only folder" in w[-1]["message"], dialogs.calls


def test_AG_04_inside_indexed_folder(win, dialogs, tree, isolated_env):
    isolated_env.rag.add_to_auto_update_list(str(tree / "Indexed"))
    dialogs.reset()
    assert win.app._add_access_only_path(str(tree / "Indexed" / "Inside")) is False
    w = _warnings(dialogs)
    assert w and "inside indexed folder" in w[-1]["message"], dialogs.calls
    assert _listed(win) == []


def test_AG_05_parent_folds_inner_folders(win, dialogs, tree):
    win.app._add_access_only_path(str(tree / "Docs" / "Manuals"))
    win.app._add_access_only_path(str(tree / "Docs" / "Other"))
    dialogs.reset()
    assert win.app._add_access_only_path(str(tree / "Docs")) is True
    assert _listed(win) == [str((tree / "Docs").resolve()).lower()]
    info = [c for c in dialogs.calls if c["title"] == "Access-only folder added"]
    assert info and "Manuals" in info[-1]["message"] and "Other" in info[-1]["message"], dialogs.calls
    # the listbox shows just the one row now
    rows = [p for p in win.app._access_only_raw_paths if p]
    assert len(rows) == 1


def test_AG_06_a_file_is_refused(win, dialogs, tree):
    assert win.app._add_access_only_path(str(tree / "Docs" / "note.txt")) is False
    w = _warnings(dialogs)
    assert w and "is a file" in w[-1]["message"] and "folders only" in w[-1]["message"], dialogs.calls


def test_AG_07_server_window_has_no_access_only_panel(gui, sandbox_state):
    sandbox_state.set_config(edition="business", mode="server")
    g = _rebuild_gui(gui)
    lb = g.app.access_only_listbox
    # built but never shown on a server (rag_gui: packed only when not server mode)
    assert not lb.winfo_ismapped(), "the Access-Only panel is visible in server mode"
    frame = lb.master
    while frame is not None and frame.winfo_class() != "TLabelframe":
        frame = frame.master
    assert frame is not None and frame.winfo_manager() == "", "the panel's frame is packed in server mode"
