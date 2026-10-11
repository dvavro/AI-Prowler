"""R-070 duplicate / overlapping index paths — the DESKTOP, in personal AND
server mode (David 2026-10-09: "check how all that works in personal mode and
server mode and make sure there's tests for both").

Update Index tab:
  OV-01  queue a folder INSIDE an already-indexed folder  -> "Overlapping Index
         Path" warning (…is inside already-indexed…); still queued (warning only)
  OV-02  queue a folder that CONTAINS an already-indexed one -> warning (contains)
  OV-03  queue a folder inside an already-QUEUED one      -> warning (already-queued)
  OV-04  queue an unrelated folder                        -> no warning
  OV-05  tracked list: a row inside another tracked row turns RED; its parent and
         unrelated rows don't; after the parent is untracked + refresh, it's not red
  OV-06  registering an overlapping folder for tracking   -> "Duplicate or
         Overlapping Path" popup

Each runs on a window built as a personal (Home) install and as a Business
Server — sandbox config only (tests/gui/conftest.py sandbox_state).

Run: run_tests.bat tests\\gui\\test_r070_overlap_gui.py -v
"""
import pytest


def _rebuild_gui(gui):
    import rag_gui as gui_mod
    root = gui.root
    for child in list(root.winfo_children()):
        try:
            child.destroy()
        except Exception:
            pass
    gui.app = gui_mod.RAGGui(root)
    gui.pump()
    return gui


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    import urllib.request

    def _offline(*a, **kw):
        raise OSError("network is switched off in the desktop GUI tests")
    monkeypatch.setattr(urllib.request, "urlopen", _offline)


@pytest.fixture(params=["personal", "server"])
def win(request, gui, sandbox_state):
    if request.param == "server":
        sandbox_state.set_config(edition="business", mode="server")
    else:
        sandbox_state.set_config(edition="home", mode="personal")
    g = _rebuild_gui(gui)
    g.mode = request.param
    return g


@pytest.fixture
def tree(isolated_env):
    root = isolated_env.sample_root / "r070gui"
    for p in ("Docs/Sub", "Other/Child", "Unrelated"):
        (root / p).mkdir(parents=True, exist_ok=True)
    return root


def _queue(win, path):
    win.app.index_dir_var.set(str(path))
    win.app._queue_add_directory()
    win.pump()


def _overlap_warnings(dialogs):
    return [c for c in dialogs.calls if c["type"] == "showwarning"
            and c["title"] in ("Overlapping Index Path", "Duplicate or Overlapping Path")]


# ── OV-01..04: queue-time warning ────────────────────────────────────────────
def test_OV_01_inside_indexed_folder_warns(win, dialogs, isolated_env, tree):
    isolated_env.rag.add_to_auto_update_list(str(tree / "Docs"))
    dialogs.reset()
    _queue(win, tree / "Docs" / "Sub")
    w = _overlap_warnings(dialogs)
    assert w and "is inside already-indexed" in w[-1]["message"], f"[{win.mode}] {dialogs.calls}"
    assert str(tree / "Docs" / "Sub") in win.app.queue_listbox.get(0, "end"), "warning only — must still queue"


def test_OV_02_contains_indexed_folder_warns(win, dialogs, isolated_env, tree):
    isolated_env.rag.add_to_auto_update_list(str(tree / "Docs" / "Sub"))
    dialogs.reset()
    _queue(win, tree / "Docs")
    w = _overlap_warnings(dialogs)
    assert w and "contains already-indexed" in w[-1]["message"], f"[{win.mode}] {dialogs.calls}"


def test_OV_03_inside_queued_folder_warns(win, dialogs, tree):
    _queue(win, tree / "Other")
    dialogs.reset()
    _queue(win, tree / "Other" / "Child")
    w = _overlap_warnings(dialogs)
    assert w and "already-queued" in w[-1]["message"], f"[{win.mode}] {dialogs.calls}"


def test_OV_04_unrelated_folder_no_warning(win, dialogs, isolated_env, tree):
    isolated_env.rag.add_to_auto_update_list(str(tree / "Docs"))
    dialogs.reset()
    _queue(win, tree / "Unrelated")
    assert not _overlap_warnings(dialogs), f"[{win.mode}] unexpected warning: {dialogs.calls}"


# ── OV-05: red rows ─────────────────────────────────────────────────────────
def _row_colors(win) -> dict:
    lb, raw = win.app.tracked_listbox, win.app._tracked_raw_paths
    return {str(p): str(lb.itemcget(i, "fg")) for i, p in enumerate(raw) if p}


def _norm(isolated_env, p):
    from pathlib import Path
    return isolated_env.rag.normalise_path(str(Path(p).resolve()))


def test_OV_05_subsumed_row_is_red(win, isolated_env, tree):
    rag = isolated_env.rag
    for p in (tree / "Docs", tree / "Docs" / "Sub", tree / "Unrelated"):
        rag.add_to_auto_update_list(str(p))
    win.app.refresh_tracked_dirs()
    win.pump()
    colors = _row_colors(win)
    sub, docs, other = (_norm(isolated_env, p) for p in (tree / "Docs" / "Sub", tree / "Docs", tree / "Unrelated"))
    assert colors.get(sub) == "red", f"[{win.mode}] the nested row isn't red: {colors}"
    assert colors.get(docs) != "red" and colors.get(other) != "red", f"[{win.mode}] {colors}"
    # untrack the parent → after a refresh the nested row is no longer red
    rag.remove_from_auto_update_list(str(tree / "Docs"))
    win.app.refresh_tracked_dirs()
    win.pump()
    assert _row_colors(win).get(sub) != "red", f"[{win.mode}] stale red after refresh: {_row_colors(win)}"


# ── OV-06: registration popup ───────────────────────────────────────────────
def test_OV_06_register_overlapping_folder_pops_warning(win, dialogs, isolated_env, tree):
    isolated_env.rag.add_to_auto_update_list(str(tree / "Docs"))
    dialogs.reset()
    win.app._register_directory_for_tracking(str(tree / "Docs" / "Sub"), True)
    win.pump()
    w = [c for c in dialogs.calls if c["title"] == "Duplicate or Overlapping Path"]
    assert w and "is inside already-indexed" in w[-1]["message"], f"[{win.mode}] {dialogs.calls}"
