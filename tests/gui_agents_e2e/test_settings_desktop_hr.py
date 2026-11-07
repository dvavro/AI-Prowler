"""AG-HR-01…15 on the DESKTOP — 🏢 Small Business → 👥 HR Agent & settings. This is the only place the HR agent can
be set up: the HR apps run on a server only, and on a server their agent settings are greyed out
(test_settings_hr_admin.py). Personal and server installs both — the server PC is where a server is set up.

Drives the real Tk section (desk_gui_agent.build_standalone_section) on throwaway databases in a temp folder;
every message box is captured instead of shown. Findings are xfail(strict=True), as in the app tests.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from conftest import HUMAN

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent_hr_store as hstore  # noqa: E402
import desk_agent_settings as das  # noqa: E402
import desk_agent_store as store  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import desk_gui_links  # noqa: E402

tk = pytest.importorskip("tkinter")
from tkinter import messagebox, ttk  # noqa: E402

LABEL = das.STAGE_MODE_LABELS
HR_STAGES = [k for k, _ in das.HR_STAGES]
GOOD = {"agent_hr_timeoff_max_days": "2", "agent_hr_timeoff_notice_days": "14", "agent_hr_timeoff_max_off": "1",
        "agent_hr_timeoff_per_day": "5", "agent_hr_overtime_warn_hours": "36", "agent_hr_quiet_hours": "8-18",
        "agent_hr_expiry_days": "60, 30, 7"}


class Desk:
    def __init__(self, root, sec, said):
        self.root, self.sec, self.v, self.said = root, sec, sec["vars"], said
        self.save_btn = next(b for b in _walk(sec["frame"], ttk.Button) if "Save HR agent" in str(b.cget("text")))

    def show(self, ms=700):
        self.root.update()
        if HUMAN:
            time.sleep(ms / 1000)

    def set(self, **vals):
        for k, x in vals.items():
            self.v[k].set(x)
        self.show(300)

    def save(self):
        self.said.clear()
        self.save_btn.invoke()
        self.show()
        assert len(self.said) == 1, self.said
        return self.said[0]

    @staticmethod
    def stored(key=None):
        s = hstore.settings()
        return s if key is None else s[key]


def _walk(w, kinds, acc=None):
    acc = [] if acc is None else acc
    for c in w.winfo_children():
        if isinstance(c, kinds):
            acc.append(c)
        _walk(c, kinds, acc)
    return acc


@pytest.fixture(params=["personal", "server"])
def desk(request, tmp_path, monkeypatch):
    mode = request.param
    tdb = str(tmp_path / "tickets.db")
    monkeypatch.setattr(store, "PATH_OVERRIDE", tmp_path / "agent.db")
    monkeypatch.setattr(hstore, "PATH_OVERRIDE", tmp_path / "hr" / "agent" / "hr_agent.db")
    monkeypatch.setattr(desk_gui_links, "_state_dir", lambda: tmp_path)
    monkeypatch.setattr(desk_gui_links, "mode_of", lambda: mode)
    monkeypatch.setattr(desk_gui_links, "desk_switched_on", lambda: True)
    monkeypatch.setattr(desk_db, "default_db_path", lambda: tdb)
    said = []
    monkeypatch.setattr(messagebox, "showinfo", lambda t, m, **k: said.append(("info", m)))
    monkeypatch.setattr(messagebox, "showerror", lambda t, m, **k: said.append(("error", m)))
    monkeypatch.setattr(messagebox, "showwarning", lambda t, m, **k: said.append(("warning", m)))
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **k: True)
    desk_db.init_db(tdb)
    hstore.init()
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    monkeypatch.setattr(tk, "_default_root", root)             # see test_agent_gui_wheel.py (2026-11-02)
    root.title(f"ZAG desktop HR agent settings — {mode}")

    class App:
        status_var = tk.StringVar(master=root)
    App.root = root
    fr = ttk.Frame(root); fr.pack(fill="both", expand=True)
    sec = dga.build_standalone_section(App(), fr, "hr")
    sec["frame"].pack(fill="x")
    sec["show"].set(True)
    d = Desk(root, sec, said)
    d.show()
    yield d
    root.destroy()


def test_hr_01_02_05_15_switches_and_header(desk):
    for key in dga.HR_BOOLS:
        before = desk.stored(key)
        desk.set(**{key: not before})
        kind, msg = desk.save()
        assert kind == "info", msg
        assert desk.stored(key) is (not before), key
        desk.set(**{key: before})
        desk.save()
        assert desk.stored(key) is before, key
    desk.set(agent_hr_enabled=True, agent_hr_shadow=True); desk.save()
    assert desk.sec["status"].cget("text") == "(on — practice mode)"
    desk.set(agent_hr_shadow=False); desk.save()
    assert desk.sec["status"].cget("text") == "(on)"
    desk.set(agent_hr_enabled=False); desk.save()
    assert desk.sec["status"].cget("text") == "(off)"


def test_hr_03_every_stage_every_mode(desk):
    for stage in HR_STAGES:
        for mode in ("off", "auto", "suggest"):
            desk.set(**{f"agent_hr_stage_{stage}": LABEL[mode]})
            kind, msg = desk.save()
            assert kind == "info", (stage, mode, msg)
            assert desk.stored(f"agent_hr_stage_{stage}") == mode, (stage, mode)
    assert desk.stored("agent_hr_stage_timeclock") == "suggest"


def test_hr_10_11_reviewers_and_incidents(desk):
    for code, lab in das.HR_REVIEWERS:
        desk.set(agent_hr_reviewers=lab); desk.save()
        assert desk.stored("agent_hr_reviewers") == code
    for code, lab in das.HR_INCIDENTS:
        desk.set(agent_hr_incidents_access=lab); desk.save()
        assert desk.stored("agent_hr_incidents_access") == code


@pytest.mark.parametrize("vals,want", [
    ({"agent_hr_timeoff_max_days": "1", "agent_hr_timeoff_notice_days": "0", "agent_hr_timeoff_max_off": "1",
      "agent_hr_timeoff_per_day": "1", "agent_hr_overtime_warn_hours": "20", "agent_hr_quiet_hours": "0-24",
      "agent_hr_expiry_days": "30"},
     {"agent_hr_timeoff_max_days": 1, "agent_hr_timeoff_notice_days": 0, "agent_hr_timeoff_max_off": 1,
      "agent_hr_timeoff_per_day": 1, "agent_hr_overtime_warn_hours": 20, "agent_hr_quiet_hours": [0, 24],
      "agent_hr_expiry_days": [30]}),
    ({"agent_hr_timeoff_max_days": "10", "agent_hr_timeoff_notice_days": "90", "agent_hr_timeoff_max_off": "20",
      "agent_hr_timeoff_per_day": "50", "agent_hr_overtime_warn_hours": "60", "agent_hr_quiet_hours": "7-8",
      "agent_hr_expiry_days": "365"},
     {"agent_hr_timeoff_max_days": 10, "agent_hr_timeoff_notice_days": 90, "agent_hr_timeoff_max_off": 20,
      "agent_hr_timeoff_per_day": 50, "agent_hr_overtime_warn_hours": 60, "agent_hr_quiet_hours": [7, 8],
      "agent_hr_expiry_days": [365]}),
    ({"agent_hr_quiet_hours": "8, 18", "agent_hr_expiry_days": "60 30 7"},
     {"agent_hr_quiet_hours": [8, 18], "agent_hr_expiry_days": [60, 30, 7]}),
], ids=["lowest", "highest", "other-separators"])
def test_hr_06_to_14_valid(desk, vals, want):
    desk.set(**{**GOOD, **vals})
    kind, msg = desk.save()
    assert kind == "info", msg
    got = desk.stored()
    for k, v in want.items():
        assert got[k] == v, (k, got[k], v)


@pytest.mark.parametrize("key,value,msg", [
    ("agent_hr_timeoff_max_days", "0", "between 1 and 10"), ("agent_hr_timeoff_max_days", "11", "between 1 and 10"),
    ("agent_hr_timeoff_max_days", "2.5", "whole number"), ("agent_hr_timeoff_max_days", "", "whole number"),
    ("agent_hr_timeoff_notice_days", "-1", "between 0 and 90"), ("agent_hr_timeoff_notice_days", "91", "between 0 and 90"),
    ("agent_hr_timeoff_max_off", "0", "between 1 and 20"), ("agent_hr_timeoff_max_off", "21", "between 1 and 20"),
    ("agent_hr_timeoff_per_day", "0", "between 1 and 50"), ("agent_hr_timeoff_per_day", "51", "between 1 and 50"),
    ("agent_hr_overtime_warn_hours", "19", "between 20 and 60"), ("agent_hr_overtime_warn_hours", "61", "between 20 and 60"),
    ("agent_hr_quiet_hours", "18-8", "start < end"), ("agent_hr_quiet_hours", "8-8", "start < end"),
    ("agent_hr_quiet_hours", "8", "start < end"), ("agent_hr_quiet_hours", "8-25", "start < end"),
    ("agent_hr_quiet_hours", "8am-6pm", "two hours"),
    ("agent_hr_expiry_days", "7, 30", "largest first"), ("agent_hr_expiry_days", "30, 30", "largest first"),
    ("agent_hr_expiry_days", "400", "largest first"), ("agent_hr_expiry_days", "90, 60, 30, 7", "largest first"),
    ("agent_hr_expiry_days", "", "largest first"), ("agent_hr_expiry_days", "30 days", "numbers"),
])
def test_hr_06_to_14_refused(desk, key, value, msg):
    before = desk.stored(key)
    desk.set(**{key: value})
    kind, said = desk.save()
    assert kind == "error" and msg in said, (key, value, said)
    assert desk.stored(key) == before, (key, value)


def test_hr_refused_value_saves_nothing_else(desk):
    """F-6, fixed 2026-11-03: one bad box used to leave the boxes before it saved."""
    desk.set(agent_hr_timeoff_max_days="5", agent_hr_overtime_warn_hours="40", agent_hr_expiry_days="7, 30")
    kind, _ = desk.save()
    assert kind == "error"
    got = desk.stored()
    assert (got["agent_hr_timeoff_max_days"], got["agent_hr_overtime_warn_hours"]) == (2, 36)


def test_hr_nothing_changed_says_so(desk):
    kind, msg = desk.save()
    assert (kind, msg) == ("info", "Nothing changed.")


def test_hr_runner_is_never_a_chat(desk, monkeypatch):
    """AG-HR-04 from the desktop side: the HR agent's runner list only offers API runners."""
    import desk_gui_settings
    monkeypatch.setattr(desk_gui_settings, "section_status", lambda: {"enabled": False})
    fr = ttk.Frame(desk.root); fr.pack()

    class App:
        status_var = tk.StringVar(master=desk.root)
    App.root = desk.root
    sec = dga.build_standalone_section(App(), fr, "hr")
    sec["show"].set(True)
    desk.show()
    combos = [c for c in _walk(sec["frame"], ttk.Combobox) if any("API" in str(x) or "Grok" in str(x)
                                                                    for x in c.cget("values"))]
    assert combos, "no runner list shown"
    offered = list(combos[0].cget("values"))
    allowed = {lab for code, lab in das.providers_for("solo") if code in das.HR_RUNNERS} | \
              {lab for code, lab in das.providers_for("business") if code in das.HR_RUNNERS}
    assert offered and set(offered) <= allowed, offered
