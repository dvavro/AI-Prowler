"""desk_gui_agent.live_sync (2026-11-03, David): an open settings section follows a change saved elsewhere (the app, on a
personal install), keeps a box the person is editing, and stops when the section is gone."""
from __future__ import annotations

import time

import pytest

import desk_gui_agent as dga

tk = pytest.importorskip("tkinter")


@pytest.fixture
def root(monkeypatch):
    monkeypatch.setattr(dga, "LIVE_SYNC_MS", 10)
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    monkeypatch.setattr(tk, "_default_root", r)
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


def _spin(root, until, secs=3):
    t0 = time.time()
    while not until() and time.time() - t0 < secs:
        root.update()
        time.sleep(0.005)
    assert until()


def test_follows_a_change_saved_elsewhere_and_reports_it(root):
    saved = {"a": "Suggest", "b": True}
    v = {"a": tk.StringVar(root, "Suggest"), "b": tk.BooleanVar(root, True)}
    seen = []
    dga.live_sync(root, v, lambda: dict(saved), lambda shown: seen.append(dict(shown)))
    saved.update(a="Auto", b=False)
    _spin(root, lambda: v["a"].get() == "Auto" and v["b"].get() is False)
    assert seen[-1] == {"a": "Auto", "b": False}


def test_an_unsaved_edit_is_kept_and_the_baseline_still_moves(root):
    saved = {"a": "1", "b": "x"}
    v = {"a": tk.StringVar(root, "1"), "b": tk.StringVar(root, "x")}
    seen = []
    dga.live_sync(root, v, lambda: dict(saved), lambda shown: seen.append(dict(shown)))
    v["a"].set("typed")
    saved.update(a="2", b="y")
    _spin(root, lambda: v["b"].get() == "y")
    assert v["a"].get() == "typed"
    assert seen[-1]["a"] == "2"                                 # Save compares with what's really saved


def test_changing_a_box_again_right_after_its_save_is_kept(root):
    """A Save updates the returned dict; without it the next tick sees "saved differs, box still equals the old value"
    and puts the box back (found by test_agent_gui_wheel, only when a tick fell between the Save and the next edit)."""
    saved = {"a": "Auto"}
    v = {"a": tk.StringVar(root, "Auto")}
    shown = dga.live_sync(root, v, lambda: dict(saved))
    v["a"].set("Suggest")                                       # pick and Save …
    saved["a"] = "Suggest"
    shown.update(saved)
    v["a"].set("Auto")                                          # … and change it back before the next tick
    t0 = time.time()
    while time.time() - t0 < 0.1:
        root.update()
        time.sleep(0.005)
    assert v["a"].get() == "Auto"


def test_a_failed_read_waits_for_the_next_one(root):
    saved = {"a": "1"}
    calls = {"n": 0}

    def stored():
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("database busy")
        return dict(saved)
    v = {"a": tk.StringVar(root, "1")}
    dga.live_sync(root, v, stored)
    saved["a"] = "2"
    _spin(root, lambda: v["a"].get() == "2")


def test_stops_when_the_section_is_gone(root):
    calls = {"n": 0}

    def stored():
        calls["n"] += 1
        return {"a": "1"}
    fr = tk.Frame(root)
    dga.live_sync(fr, {"a": tk.StringVar(root, "1")}, stored)
    _spin(root, lambda: calls["n"] >= 2)
    fr.destroy()
    n = calls["n"]
    t0 = time.time()
    while time.time() - t0 < 0.1:
        root.update()
        time.sleep(0.005)
    assert calls["n"] == n
