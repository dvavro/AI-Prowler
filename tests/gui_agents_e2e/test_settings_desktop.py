"""AG-KEY-01…09, AG-SD / AG-BK / AG-JB / AG-RT on the DESKTOP — 🏢 Small Business tab: 🔑 Agent API Key, Service Desk
Agent & settings (with 📅 Booking & scheduling) and 🧰 Jobs App Agent & settings (with 🗺 Route flow). The HR section
is in test_settings_desktop_hr.py; the same fields in the apps are in test_settings_*_pwa.py.

Drives the real Tk sections on throwaway files in a temp folder, personal and server. Every message box and file
picker is captured instead of shown. Every way out to a network raises, so the 📊 Cost analysis popup can't spend
anything. Findings are xfail(strict=True), as in the other settings tests: they fail the day the app is fixed, so a
mark can't go stale.
"""
from __future__ import annotations

import re
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

import pytest
from PIL import Image

from conftest import HUMAN

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent_budget as budget  # noqa: E402
import desk_agent_hr_store as hstore  # noqa: E402
import desk_agent_providers as prov  # noqa: E402
import desk_agent_settings as das  # noqa: E402
import desk_agent_store as store  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import desk_gui_links  # noqa: E402
import task_queue_automation as tqa  # noqa: E402

tk = pytest.importorskip("tkinter")
from tkinter import filedialog, messagebox, ttk  # noqa: E402

LABEL = das.STAGE_MODE_LABELS
REAL = Path.home() / ".ai-prowler"
REAL_FILES = [REAL / n for n in ("agent_claude_api_key.txt", "agent_grok_api_key.txt", "task_automation_config.json",
                                 "agent_budget_alerts.json")]


def _fingerprint():
    return {str(f): (f.stat().st_size, int(f.stat().st_mtime)) for f in REAL_FILES if f.exists()}


_BEFORE = _fingerprint()


def _walk(w, kinds, acc=None):
    acc = [] if acc is None else acc
    for c in w.winfo_children():
        if isinstance(c, kinds):
            acc.append(c)
        _walk(c, kinds, acc)
    return acc


def _button(frame, text, nth=0):
    return [b for b in _walk(frame, ttk.Button) if text in str(b.cget("text"))][nth]


def _canvas_words(canvas):
    return sorted(canvas.itemcget(i, "text") for i in canvas.find_all() if canvas.type(i) == "text")


def shared_value(db, key):
    """A setting copied into an agent's own database, as stored (sync_shared)."""
    con = sqlite3.connect(str(db))
    try:
        row = con.execute("SELECT value FROM desk_settings WHERE key = ?", (key,)).fetchone()
    finally:
        con.close()
    return None if row is None else str(row[0])


def _label_texts(frame):
    """What the labels under a frame say now, including those fed by a text variable (the flow summaries)."""
    out = []
    for w in _walk(frame, ttk.Label):
        var = str(w.cget("textvariable"))
        out.append(str(w.getvar(var)) if var else str(w.cget("text")))
    return out


class Env:
    def __init__(self, root, mode, tmp, said, picks):
        self.root, self.mode, self.tmp, self.said, self.picks = root, mode, tmp, said, picks
        self.edition = "business" if mode == "server" else "solo"
        self.tdb = desk_db.default_db_path()

    def show(self, ms=500):
        self.root.update()
        if HUMAN:
            time.sleep(ms / 1000)

    def desk(self, key=None):
        s = desk_db.get_settings(self.tdb)
        return s if key is None else s[key]

    def frame(self):
        fr = ttk.Frame(self.root)
        fr.pack(fill="both", expand=True)
        return fr

    def last(self):
        assert self.said, "no message box was shown"
        return self.said[-1]


@pytest.fixture(params=["personal", "server"])
def env(request, tmp_path, monkeypatch):
    mode = request.param
    tdb = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(store, "PATH_OVERRIDE", tmp_path / "agent.db")
    monkeypatch.setattr(hstore, "PATH_OVERRIDE", tmp_path / "hr" / "agent" / "hr_agent.db")
    monkeypatch.setattr(desk_gui_links, "_state_dir", lambda: tmp_path)
    monkeypatch.setattr(desk_gui_links, "mode_of", lambda: mode)
    monkeypatch.setattr(desk_gui_links, "desk_switched_on", lambda: True)
    monkeypatch.setattr(desk_db, "default_db_path", lambda *a, **k: tdb)
    monkeypatch.setattr(prov, "AGENT_KEY_DIR", tmp_path / "agent_keys")
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / "tq")
    monkeypatch.setattr(tqa, "CONFIG_PATH", tmp_path / "tq" / "task_automation_config.json")
    monkeypatch.setattr(tqa, "runs_db_path", lambda *a, **k: str(tmp_path / "no_task_runs.db"))
    monkeypatch.setattr(budget, "STATE_PATH", tmp_path / "agent_budget_alerts.json")
    monkeypatch.setattr(dga, "alert_recipients_text", lambda edition: "ZAG budget alerts go to the test.")
    import desk_portal
    monkeypatch.setattr(desk_portal, "_jobs_db", lambda *a, **k: str(tmp_path / "no_jobs.db"))

    def no_network(*a, **k):
        raise AssertionError(f"a desktop settings test tried to reach the network: {a[:1]}")
    monkeypatch.setattr(urllib.request, "urlopen", no_network)

    said, picks = [], []
    monkeypatch.setattr(messagebox, "showinfo", lambda t, m, **k: said.append(("info", m)))
    monkeypatch.setattr(messagebox, "showerror", lambda t, m, **k: said.append(("error", m)))
    monkeypatch.setattr(messagebox, "showwarning", lambda t, m, **k: said.append(("warning", m)))
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **k: True)
    monkeypatch.setattr(filedialog, "askopenfilename", lambda *a, **k: picks.pop(0) if picks else "")
    desk_db.init_db(tdb)
    store.init()
    hstore.init()
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    monkeypatch.setattr(tk, "_default_root", root)
    root.title(f"ZAG desktop agent settings — {mode}")
    e = Env(root, mode, tmp_path, said, picks)
    e.show()
    yield e
    root.destroy()


# ── 🔑 Agent API Key ─────────────────────────────────────────────────────────
class Keys:
    def __init__(self, env):
        self.env = env
        self.fr = env.frame()
        self.panel = dga.build_agent_key_section(self.fr, env.edition)
        self.b = self.panel["budget"]
        env.show()


@pytest.fixture
def keys(env):
    return Keys(env)


@pytest.mark.parametrize("provider,good,other_kind", [
    ("anthropic", "sk-ant-api03-ZAGdesktop", "xai-ZAGwrongrow"),
    ("grok", "xai-ZAGdesktop", "sk-ant-api03-ZAGwrongrow"),
])
def test_key_01_02_save_masked_remove(env, keys, provider, good, other_kind):
    row, runner = keys.panel[provider], {"anthropic": "claude_api", "grok": "grok_api"}[provider]
    assert row["status"].get() == "Not saved"
    assert row["entry"].cget("show") == "•"
    assert prov.ready(runner, env.edition)[0] is False
    for bad in ("", "   ", "••••", other_kind):                  # blank, only the mask, the other AI's key
        row["var"].set(bad)
        row["save"]()
        assert env.last()[0] == "warning", bad
        assert row["status"].get() == "Not saved", bad
    row["var"].set(f"  {good}  ")                                # pasted with spaces
    row["save"]()
    assert env.last()[0] == "info"
    assert row["var"].get() == "" and row["status"].get() == "✅ Saved"
    assert good not in " ".join(m for _, m in env.said)          # the key is never shown back
    assert prov.load_agent_key(provider) == good
    assert prov.ready(runner, env.edition) == (True, "")
    row["clear"]()
    assert row["status"].get() == "Not saved" and not prov.has_agent_key(provider)
    assert prov.ready(runner, env.edition)[0] is False


def test_key_01_subscription_token_refused(env, keys):
    row = keys.panel["anthropic"]
    row["var"].set("sk-ant-oat01-ZAGsubscription")
    row["save"]()
    kind, msg = env.last()
    assert kind == "warning" and "subscription" in msg
    assert row["status"].get() == "Not saved"


@pytest.mark.parametrize("runner,read", [
    ("claude_api", lambda: prov.model_for("claude_api")),
    ("claude_light", lambda: prov.light_model()),
    ("grok_api", lambda: prov.model_for("grok_api")),
])
def test_key_03_04_05_every_listed_model(keys, runner, read):
    m = keys.panel["models"][runner]
    for code, lab in m["choices"]:
        m["var"].set(lab)
        m["pick"]()
        keys.env.show(200)
        assert read() == code, (runner, code)


def test_key_04_light_blank_means_same_as_main(keys):
    m = keys.panel["models"]["claude_light"]
    prov.set_agent_model("claude_api", "claude-opus-5-5")
    m["var"].set(dict(m["choices"])["claude-haiku-5-5"]); m["pick"]()
    assert prov.model_for_item("claude_api", {"kind": "ticket", "stage": "intake"}) == "claude-haiku-5-5"
    m["var"].set(dict(m["choices"])[""]); m["pick"]()
    assert prov.light_model() == ""
    assert prov.model_for_item("claude_api", {"kind": "ticket", "stage": "intake"}) == "claude-opus-5-5"


@pytest.mark.parametrize("value,want", [("0", 0), ("20", 20), ("10000", 10000), ("$1,500", 1500)])
def test_key_06_budget_valid(env, keys, value, want):
    keys.b["var"].set(value)
    keys.b["save"]()
    assert env.last()[0] == "info", env.last()
    assert env.desk("agent_monthly_budget_usd") == want
    assert f"of ${want}" in keys.b["spent"].get() or keys.b["spent"].get() == ""
    # copied at once to the Jobs and HR agents' own databases (their settings() lists only their own keys)
    assert shared_value(store.path(), "agent_monthly_budget_usd") == str(want)
    assert shared_value(hstore.path(), "agent_monthly_budget_usd") == str(want)


@pytest.mark.parametrize("value", ["-1", "10001", "abc", "12.5", ""])
def test_key_06_budget_refused(env, keys, value):
    before = env.desk("agent_monthly_budget_usd")
    keys.b["var"].set(value)
    keys.b["save"]()
    assert env.last()[0] == "warning", (value, env.last())
    assert env.desk("agent_monthly_budget_usd") == before, value


@pytest.mark.parametrize("value", ["0", "80", "100"])
def test_key_07_alert_valid(env, keys, value):
    keys.b["warn"].set(value)
    keys.b["save"]()
    assert env.last()[0] == "info", env.last()
    assert env.desk("agent_budget_alert_pct") == int(value)


@pytest.mark.parametrize("value", ["-1", "101", "x"])
def test_key_07_alert_refused(env, keys, value):
    before = env.desk("agent_budget_alert_pct")
    keys.b["warn"].set(value)
    keys.b["save"]()
    assert env.last()[0] == "warning", (value, env.last())
    assert env.desk("agent_budget_alert_pct") == before, value


def test_key_06_07_refused_alert_saves_nothing(env, keys):
    """F-7, fixed 2026-11-03: the budget used to be saved even when the alert % was refused."""
    before = env.desk("agent_monthly_budget_usd")
    keys.b["var"].set(str(before + 5))
    keys.b["warn"].set("101")
    keys.b["save"]()
    assert env.last()[0] == "warning"
    assert env.desk("agent_monthly_budget_usd") == before


def _record_run(env, cost):
    con = sqlite3.connect(env.tdb)
    try:
        cols = con.execute("PRAGMA table_info(agent_runs)").fetchall()
        vals = {c[1]: ("" if "TEXT" in (c[2] or "").upper() else 0) for c in cols if c[3] and c[4] is None and not c[5]}
        vals.update(started_at=time.strftime("%Y-%m-%dT%H:%M:%S"), cost_usd=cost, input_tokens=1000, output_tokens=200)
        con.execute(f"INSERT INTO agent_runs ({','.join(vals)}) VALUES ({','.join('?' * len(vals))})", list(vals.values()))
        con.commit()
    finally:
        con.close()


def test_key_08_spent_line_refreshes_on_its_own(env, monkeypatch):
    monkeypatch.setattr(dga, "FORECAST_REFRESH_MS", 50)
    k = Keys(env)
    assert "$0.00" in k.b["forecast"].get(), k.b["forecast"].get()
    _record_run(env, 1.5)
    t0 = time.time()
    while "$1.50" not in k.b["forecast"].get() and time.time() - t0 < 5:
        env.root.update()
        time.sleep(0.02)
    assert "$1.50" in k.b["forecast"].get(), k.b["forecast"].get()
    assert "$1.50" in k.b["spent"].get()                       # no button was pressed


def test_key_09_cost_analysis_opens_and_closes_free(env, keys):
    def popup():
        return [w for w in keys.panel["frame"].winfo_children() if isinstance(w, tk.Toplevel)]
    for _ in range(2):                                          # close, then open again
        _button(keys.fr, "Cost analysis").invoke()
        env.show()
        win = popup()
        assert win, env.said
        assert win[0].title() == "📊 Agent cost analysis"
        trees = _walk(win[0], ttk.Treeview)
        est = trees[1]
        assert est.get_children(), "no model rows in the estimates table"
        _button(win[0], "Refresh").invoke()
        env.show(200)
        _button(win[0], "Close").invoke()
        env.show(200)
        assert not popup()
    assert not [m for k, m in env.said if k == "error"], env.said


# ── Service Desk Agent & settings, with 📅 Booking & scheduling ──────────────
class Agent:
    def __init__(self, env):
        self.env = env
        self.fr = env.frame()

        class App:
            status_var = tk.StringVar(master=env.root, value="Ready")
        App.root = env.root
        self.app = App
        self.v = dga.build_agent_settings(App(), self.fr)
        assert self.v, "the Agent settings didn't build"
        self.flows = _walk(self.fr, tk.Canvas)
        env.show()

    def save(self):
        self.env.said.clear()
        _button(self.fr, "Save agent settings").invoke()
        self.env.show(300)
        return self.env.said[-1] if self.env.said else ("ok", self.app.status_var.get())


@pytest.fixture
def agent(env):
    return Agent(env)


def test_sd_01_02_12_bk_01_02_04_06_switches(env, agent):
    for key in dga.BOOL_KEYS:
        before = env.desk(key)
        agent.v[key].set(not before)
        kind, msg = agent.save()
        assert kind == "ok", (key, msg)
        assert env.desk(key) is (not before), key
        agent.v[key].set(before)
        agent.save()
        assert env.desk(key) is before, key


def test_sd_03_runners_by_edition(env, agent):
    labels = dict(das.providers_for(env.edition))
    combo = next(c for c in _walk(agent.fr, ttk.Combobox) if any("API" in str(x) for x in c.cget("values")))
    assert set(combo.cget("values")) == set(labels.values())
    assert "claude_code" not in labels
    assert "chat_only" not in labels
    for code, lab in labels.items():
        agent.v["agent_provider"].set(lab)
        kind, msg = agent.save()
        assert kind == "ok", (code, msg)
        assert env.desk("agent_provider") == code
        # AG-SYNC-03: the shared runner reaches the other agents
        assert store.sync_shared(env.tdb)["agent_provider"] == code


@pytest.mark.parametrize("prefix,stages,idx", [("agent_stage_", das.STAGES, 0), ("agent_bk_stage_", das.BK_STAGES, 1)])
def test_sd_04_bk_03_every_stage_mode_and_diagram(env, agent, prefix, stages, idx):
    agent.v["agent_enabled"].set(True)
    agent.v["agent_shadow"].set(False)
    agent.v["agent_bk_enabled"].set(True)
    agent.v["agent_bk_shadow"].set(False)
    env.root.update()
    canvas = agent.flows[idx]
    for k, _ in stages:
        agent.v[f"{prefix}{k}"].set(LABEL["suggest"]); env.root.update()
        base = _canvas_words(canvas)
        for mode in ("off", "auto"):
            agent.v[f"{prefix}{k}"].set(LABEL[mode])
            env.show(100)
            assert _canvas_words(canvas) != base, (k, mode)      # the diagram follows before Save
            stored = env.desk(f"{prefix}{k}")
            kind, msg = agent.save()
            assert kind == "ok", (k, mode, msg)
            assert env.desk(f"{prefix}{k}") == mode and stored != mode, (k, mode)
        agent.v[f"{prefix}{k}"].set(LABEL["suggest"])
        assert agent.save()[0] == "ok"
        assert env.desk(f"{prefix}{k}") == "suggest"


@pytest.mark.parametrize("value,ok", [
    ("", True), ("Sam", True), ("O'Brien-Lee", True), ("A" * 40, True),
    ("A" * 41, False), ("Sam2", False), ("-Sam", False), ("Sam!", False)])
def test_sd_05_name(env, agent, value, ok):
    agent.v["agent_name"].set("Before")
    assert agent.save()[0] == "ok"
    agent.v["agent_name"].set(value)
    kind, msg = agent.save()
    assert (kind == "ok") is ok, (value, msg)
    assert env.desk("agent_name") == (value if ok else "Before")


def test_sd_06_labels_and_preview(env, agent):
    agent.v["agent_name"].set("Sam")
    for lab in das.LABELS:
        agent.v["agent_label"].set(lab)
        assert agent.save()[0] == "ok"
        assert env.desk("agent_label") == lab
        assert das.persona(env.desk())["display"] == f"Sam · {lab}"
    combo = next(c for c in _walk(agent.fr, ttk.Combobox) if tuple(c.cget("values")) == das.LABELS)
    assert str(combo.cget("state")) == "readonly"
    agent.v["agent_label"].set("Real person")                   # the box can't produce this; the save must refuse it
    assert agent.save()[0] == "warning"
    assert env.desk("agent_label") in das.LABELS


def _picture(path, fmt):
    Image.new("RGB", (400, 300), (30, 90, 160)).save(path, fmt)
    return str(path)


@pytest.mark.parametrize("fmt,name", [("JPEG", "a.jpg"), ("PNG", "a.png"), ("WEBP", "a.webp")])
def test_sd_07_photo_good(env, agent, fmt, name):
    env.picks.append(_picture(env.tmp / name, fmt))
    _button(agent.fr, "Choose photo").invoke()
    env.show()
    assert not [m for k, m in env.said if k == "error"], env.said
    data = das.photo_bytes(env.tdb)
    assert data
    import io
    with Image.open(io.BytesIO(data)) as im:
        assert max(im.size) <= das.PHOTO_SIDE
    _button(agent.fr, "Remove photo").invoke()
    env.show()
    assert not das.photo_bytes(env.tdb)


def test_sd_07_photo_at_the_size_limit(env, agent):
    p = env.tmp / "exact.png"
    _picture(p, "PNG")
    p.write_bytes(p.read_bytes() + b"\0" * (das.PHOTO_MAX_BYTES - p.stat().st_size))    # 8 MB exactly
    env.picks.append(str(p))
    _button(agent.fr, "Choose photo").invoke()
    env.show()
    assert not env.said, env.said
    assert das.photo_bytes(env.tdb)


@pytest.mark.parametrize("name,make,msg", [
    ("too_big.png", lambda p: (_picture(p, "PNG"), p.write_bytes(p.read_bytes() + b"\0" * das.PHOTO_MAX_BYTES)),
     "too big"),
    ("fake.jpg", lambda p: p.write_text("ZAG this is not a picture"), ""),
    ("empty.jpg", lambda p: p.write_bytes(b""), "empty"),
])
def test_sd_07_photo_refused(env, agent, name, make, msg):
    p = env.tmp / name
    make(p)
    env.picks.append(str(p))
    _button(agent.fr, "Choose photo").invoke()
    env.show()
    kind, said = env.last()
    assert kind == "error" and msg in said, env.said
    assert not das.photo_bytes(env.tdb)


def test_sd_07_cancel_the_picker_changes_nothing(env, agent):
    _button(agent.fr, "Choose photo").invoke()
    env.show(100)
    assert not env.said and not das.photo_bytes(env.tdb)


@pytest.mark.parametrize("value,ok", [("", True), ("— Sam, Blue Wave", True), ("x" * 80, True), ("x" * 81, False)])
def test_sd_08_signoff(env, agent, value, ok):
    kind, msg = (agent.v["agent_reply_signoff"].set(value), agent.save())[1]
    assert (kind == "ok") is ok, (value, msg)
    assert env.desk("agent_reply_signoff") == (value if ok else das.DEFAULTS["agent_reply_signoff"])


@pytest.mark.parametrize("h0,h1,ok", [
    ("0", "24", True), ("9", "17", True), ("23", "24", True),
    ("17", "9", False), ("5", "5", False), ("24", "24", False), ("-1", "5", False), ("5", "25", False),
    ("x", "5", False), ("", "5", False)])
def test_sd_09_hours(env, agent, h0, h1, ok):
    agent.v["h0"].set("8"); agent.v["h1"].set("20")
    assert agent.save()[0] == "ok"
    agent.v["h0"].set(h0); agent.v["h1"].set(h1)
    kind, msg = agent.save()
    assert (kind == "ok") is ok, (h0, h1, msg)
    assert env.desk("agent_hours") == ([int(h0), int(h1)] if ok else [8, 20])


@pytest.mark.parametrize("key,good,bad", [
    ("agent_monthly_budget_usd", ("0", "10000"), ("-1", "10001", "x", "")),
    ("agent_wait_hours", ("1", "4", "168"), ("0", "169", "x", "")),
    ("agent_bk_confirm_per_day", ("1", "5", "50"), ("0", "51", "2.5")),
    ("agent_bk_check_hour", ("0", "16", "23"), ("-1", "24")),
])
def test_sd_10_11_bk_05_07_numbers(env, agent, key, good, bad):
    for value in good:
        agent.v[key].set(value)
        assert agent.save()[0] == "ok", (key, value)
        assert env.desk(key) == int(value), (key, value)
    keep = env.desk(key)
    for value in bad:
        agent.v[key].set(value)
        kind, msg = agent.save()
        assert kind == "warning", (key, value, msg)
        assert env.desk(key) == keep, (key, value)


def test_sd_refused_value_saves_nothing_else(env, agent):
    """F-6, fixed 2026-11-03: dga.save used to keep the valid boxes while saying 'Not saved'."""
    before = env.desk("agent_wait_hours")
    agent.v["agent_wait_hours"].set(str(before + 1))
    agent.v["agent_reply_signoff"].set("x" * 81)
    assert agent.save()[0] == "warning"
    assert env.desk("agent_wait_hours") == before


def test_sd_a_save_keeps_what_the_app_saved_since(env, agent):
    """The 2026-10-31 bug: a Save must write only the fields changed on this form."""
    desk_db.set_setting(env.tdb, "agent_stage_learn", "off", edition=env.edition)     # saved elsewhere meanwhile
    agent.v["agent_wait_hours"].set("9")
    assert agent.save()[0] == "ok"
    assert env.desk("agent_stage_learn") == "off" and env.desk("agent_wait_hours") == 9


# ── 🧰 Jobs App Agent & settings, with 🗺 Route flow ─────────────────────────
class Jobs:
    def __init__(self, env):
        self.env = env
        self.fr = env.frame()

        class App:
            status_var = tk.StringVar(master=env.root)
        App.root = env.root
        self.sec = dga.build_standalone_section(App(), self.fr, "jobs")
        self.sec["frame"].pack(fill="x")
        self.sec["show"].set(True)
        self.v = self.sec["vars"]
        env.show()

    def stored(self, key=None):
        s = store.settings()
        return s if key is None else s[key]

    def save(self):
        self.env.said.clear()
        _button(self.sec["frame"], "Save Jobs agent settings").invoke()
        self.env.show(300)
        assert len(self.env.said) == 1, self.env.said
        return self.env.said[0]


@pytest.fixture
def jobs(env):
    return Jobs(env)


def test_jb_01_02_04_09_rt_01_02_switches_and_header(jobs):
    for key in ("agent_jb_enabled", "agent_jb_shadow", "agent_jb_can_send_invoices", "agent_jb_weather",
                "agent_jb_rt_enabled", "agent_jb_rt_shadow"):
        before = jobs.stored(key)
        jobs.v[key].set(not before)
        assert jobs.save()[0] == "info", key
        assert jobs.stored(key) is (not before), key
        jobs.v[key].set(before)
        jobs.save()
    jobs.v["agent_jb_enabled"].set(True); jobs.v["agent_jb_shadow"].set(True); jobs.v["agent_jb_rt_enabled"].set(False)
    jobs.save()
    # David 2026-11-06: with the Jobs app off the label says so, whatever the agent's own switches are.
    import desk_gui_links
    import tool_config_store as tcs
    mode = desk_gui_links.mode_of()
    was = tcs.group_enabled(mode, "job_tracker")
    tcs.set_group_enabled(mode, "job_tracker", False)
    jobs.save()
    assert jobs.sec["status"].cget("text") == "(not enabled)"
    tcs.set_group_enabled(mode, "job_tracker", True)
    try:
        jobs.save()
        assert jobs.sec["status"].cget("text") == "(jobs on — practice mode · routes off)"
        jobs.v["agent_jb_shadow"].set(False); jobs.v["agent_jb_rt_enabled"].set(True); jobs.v["agent_jb_rt_shadow"].set(True)
        jobs.save()
        assert jobs.sec["status"].cget("text") == "(jobs on · routes on — practice mode)"
    finally:
        tcs.set_group_enabled(mode, "job_tracker", was)


@pytest.mark.parametrize("prefix,stages,idx", [("agent_jb_stage_", das.JB_STAGES, 0), ("agent_jb_rt_stage_", das.RT_STAGES, 1)])
def test_jb_03_rt_03_every_stage_mode_and_diagram(jobs, prefix, stages, idx):
    canvas = _walk(jobs.sec["frame"], tk.Canvas)[idx]
    for key in ("agent_jb_enabled", "agent_jb_rt_enabled"):
        jobs.v[key].set(True)
    for key in ("agent_jb_shadow", "agent_jb_rt_shadow"):
        jobs.v[key].set(False)
    jobs.env.root.update()
    for k, _ in stages:
        jobs.v[f"{prefix}{k}"].set(LABEL["suggest"]); jobs.env.root.update()
        base = _canvas_words(canvas)
        for mode in ("off", "auto"):
            jobs.v[f"{prefix}{k}"].set(LABEL[mode]); jobs.env.show(50)
            assert _canvas_words(canvas) != base, (k, mode)    # redrawn before Save
            assert jobs.save()[0] == "info", (k, mode)
            assert jobs.stored(f"{prefix}{k}") == mode, (k, mode)
        jobs.v[f"{prefix}{k}"].set(LABEL["suggest"])
        jobs.save()
        assert jobs.stored(f"{prefix}{k}") == "suggest"


@pytest.mark.parametrize("key,good,bad", [
    ("agent_jb_invoice_max", ("0", "1000", "100000", "$2,500"), ("-1", "100001", "12.50", "abc", "")),
    ("agent_jb_invoices_per_day", ("1", "10", "100"), ("0", "101", "x")),
    ("agent_jb_quote_days", ("1", "5", "60"), ("0", "61")),
    ("agent_jb_prep_hour", ("0", "16", "23"), ("-1", "24")),
    ("agent_jb_route_send_hour", ("0", "18", "23"), ("-1", "24", "x")),
])
def test_jb_05_06_07_10_rt_06_numbers(jobs, key, good, bad):
    for value in good:
        jobs.v[key].set(value)
        kind, msg = jobs.save()
        assert kind == "info", (key, value, msg)
        assert jobs.stored(key) == int(re.sub(r"[$,]", "", value)), (key, value)
    keep = jobs.stored(key)
    for value in bad:
        jobs.v[key].set(value)
        kind, msg = jobs.save()
        assert kind == "error", (key, value, msg)
        assert jobs.stored(key) == keep, (key, value)


@pytest.mark.parametrize("value,want", [("7", [7]), ("7, 14, 30", [7, 14, 30]), ("1, 120", [1, 120]), ("7 14", [7, 14])])
def test_jb_08_reminder_days_valid(jobs, value, want):
    jobs.v["agent_jb_remind_days"].set(value)
    kind, msg = jobs.save()
    assert kind == "info", (value, msg)
    assert jobs.stored("agent_jb_remind_days") == want


@pytest.mark.parametrize("value", ["30, 7", "7, 7", "7, 14, 30, 60", "0", "121", "", "7 x"])
def test_jb_08_reminder_days_refused(jobs, value):
    keep = jobs.stored("agent_jb_remind_days")
    jobs.v["agent_jb_remind_days"].set(value)
    kind, msg = jobs.save()
    assert kind == "error", (value, msg)
    assert jobs.stored("agent_jb_remind_days") == keep, value


def test_jb_refused_value_saves_nothing_else(jobs):
    """F-6, fixed 2026-11-03: save_jobs used to keep the boxes before the bad one."""
    before = jobs.stored("agent_jb_invoice_max")
    jobs.v["agent_jb_invoice_max"].set(str(before + 1))
    jobs.v["agent_jb_remind_days"].set("30, 7")
    assert jobs.save()[0] == "error"
    assert jobs.stored("agent_jb_invoice_max") == before


def test_rt_04_05_scope_and_every_weekday(jobs):
    """The scope and weekday show in the line under the route diagram, not in its boxes (same boxes either way)."""
    jobs.v["agent_jb_rt_enabled"].set(True); jobs.env.root.update()
    for code, lab in das.RT_SCOPES:
        jobs.v["agent_jb_route_scope"].set(lab); jobs.env.show(100)
        said = " ".join(_label_texts(jobs.sec["frame"]))
        assert f"routes {lab.lower()}" in said, (code, said)      # before Save
        assert jobs.save()[0] == "info"
        assert jobs.stored("agent_jb_route_scope") == code
    for i, day in enumerate(das.WEEKDAYS):
        jobs.v["agent_jb_sort_weekday"].set(day); jobs.env.show(50)
        assert f"coming week on {day}s" in " ".join(_label_texts(jobs.sec["frame"])), day
        assert jobs.save()[0] == "info", day
        assert jobs.stored("agent_jb_sort_weekday") == i


def test_jb_saved_values_are_back_after_a_rebuild(env, jobs):
    jobs.v["agent_jb_quote_days"].set("9")
    jobs.v["agent_jb_remind_days"].set("3, 7")
    jobs.v["agent_jb_stage_quotes"].set(LABEL["auto"])
    jobs.v["agent_jb_sort_weekday"].set(das.WEEKDAYS[2])
    assert jobs.save()[0] == "info"
    again = Jobs(env)
    assert again.v["agent_jb_quote_days"].get() == "9"
    assert again.v["agent_jb_remind_days"].get() == "3, 7"
    assert again.v["agent_jb_stage_quotes"].get() == LABEL["auto"]
    assert again.v["agent_jb_sort_weekday"].get() == das.WEEKDAYS[2]


def test_sd_saved_values_are_back_after_a_rebuild(env, agent):
    agent.v["agent_name"].set("Sam")
    agent.v["agent_wait_hours"].set("9")
    agent.v["agent_bk_stage_track"].set(LABEL["off"])
    assert agent.save()[0] == "ok"
    again = Agent(env)
    assert again.v["agent_name"].get() == "Sam"
    assert again.v["agent_wait_hours"].get() == "9"
    assert again.v["agent_bk_stage_track"].get() == LABEL["off"]


# ── AG-SAFE-03 for this file ─────────────────────────────────────────────────
def test_zz_real_key_and_config_files_untouched():
    assert _fingerprint() == _BEFORE, "a real AI-Prowler key or config file changed during the run"
