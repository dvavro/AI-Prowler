"""🔑 Agent API Key (2026-11-01, David) at the top of the Small Business tab, both editions: the agents'
OWN Claude / Grok keys ("the Agents use the API Keys in the small business tab only" — not the Task Queue's
keys, not environment variables) and the monthly dollar limit every agent shares. On a server there's no
chat runner: every agent needs a key.

Run: run_tests.bat tests\\unit\\test_agent_api_keys_gui.py
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_agent_providers as prov  # noqa: E402
import desk_agent_settings as das  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import task_queue_automation as tqa  # noqa: E402

WHERE = "🔑 Agent API Key"


@pytest.fixture(autouse=True)
def keys(tmp_path, monkeypatch):
    monkeypatch.setattr(prov, "AGENT_KEY_DIR", tmp_path / "agent_keys")
    monkeypatch.setattr(tqa, "CONFIG_PATH", tmp_path / "tq" / "task_automation_config.json")
    return tmp_path


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    return path


@pytest.fixture
def shared(tmp_path, monkeypatch):
    """The Service Desk settings database in tmp, and the copies to the Jobs / HR agents recorded."""
    import desk_agent_hr_store
    import desk_agent_store
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    monkeypatch.setattr(desk_db, "default_db_path", lambda *a, **k: path)
    synced = []
    monkeypatch.setattr(desk_agent_store, "sync_shared", lambda db: synced.append(db) or {})
    monkeypatch.setattr(desk_agent_hr_store, "path", lambda: str(tmp_path / "no_hr" / "hr_agent.db"))
    return {"db": path, "synced": synced}


# ── the agents' own keys ─────────────────────────────────────────────────────────────

def test_save_claude_key_goes_to_the_agents_own_file(keys):
    ok, msg = dga.save_agent_key("anthropic", "  sk-ant-api03-test  ")
    assert ok, msg
    assert prov.load_agent_key("anthropic") == "sk-ant-api03-test"
    assert prov.agent_key_path("anthropic").name == "agent_claude_api_key.txt"
    assert dga.key_status("anthropic").endswith("Saved") and dga.key_status("grok") == "Not saved"


def test_save_grok_key(keys):
    ok, _ = dga.save_agent_key("grok", "xai-test")
    assert ok and prov.load_agent_key("grok") == "xai-test" and not prov.has_agent_key("anthropic")


def test_agents_and_task_queue_share_the_agent_key_and_ignore_the_environment(keys, monkeypatch):
    """2026-11-01: one key for everything — the Task Queue runs on the Agent API Key too. The old
    Task Queue key files and the environment variables are never used."""
    for name in ("claude_api_key.txt", "grok_api_key.txt"):
        (prov.AGENT_KEY_DIR / name).parent.mkdir(parents=True, exist_ok=True)
        (prov.AGENT_KEY_DIR / name).write_text("old-task-queue-key", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-env")
    monkeypatch.setenv("XAI_API_KEY", "xai-env")
    for edition in ("solo", "business"):
        assert prov.ready("claude_api", edition)[0] is False
        assert prov.ready("grok_api", edition)[0] is False
    assert not tqa.has_key({"provider": "claude"})
    dga.save_agent_key("anthropic", "sk-ant-api03-agents")
    assert prov._key("claude_api") == "sk-ant-api03-agents"
    assert tqa.has_key({"provider": "claude"}) and tqa._load_key({"provider": "claude"}) == "sk-ant-api03-agents"


@pytest.mark.parametrize("provider,key,word", [
    ("anthropic", "", "Paste"),
    ("anthropic", "••••", "Paste"),
    ("anthropic", "sk-ant-oat01-abc", "subscription"),     # the CLI token is not an API key
    ("anthropic", "xai-abc", "Grok row"),
    ("grok", "sk-ant-api03-abc", "Claude row"),
])
def test_wrong_keys_are_refused(keys, provider, key, word):
    ok, msg = dga.save_agent_key(provider, key)
    assert not ok and word in msg
    assert not prov.has_agent_key(provider)


def test_remove_key(keys):
    dga.save_agent_key("grok", "xai-test")
    assert dga.clear_agent_key("grok")[0] and not prov.has_agent_key("grok")
    assert dga.clear_agent_key("grok") == (True, "No key was saved.")


# ── no chat runner on a server; no Claude CLI runner anywhere (2026-11-01) ───────────

def test_every_install_offers_only_the_api_keys():
    for ed in ("business", "solo"):
        assert [p for p, _ in das.providers_for(ed)] == ["claude_api", "grok_api"]


def test_chat_runner_cant_be_saved_anywhere(db):
    for ed in ("business", "solo"):
        with pytest.raises(desk_db.DeskError, match="API key"):
            desk_db.set_setting(db, "agent_provider", "chat_only", edition=ed)
        ok, msg = dga.save(db, {"agent_provider": "chat_only"}, edition=ed)
        assert not ok and "API key" in msg


def test_unset_runner_still_means_not_running_on_its_own(monkeypatch):
    monkeypatch.setattr(prov, "_key", lambda p: "")
    assert das.effective_provider({}, "business") == "chat_only"
    for ed in ("business", "solo"):
        assert das.effective_provider({"agent_provider": "claude_code"}, ed) == "chat_only"
    assert das.effective_provider({"agent_provider": "grok_api"}, "business") == "grok_api"
    with pytest.raises(ValueError, match="removed"):
        das.validate("agent_provider", "claude_code", "solo")


def test_messages_point_to_the_agent_api_key(keys):
    ok, why = prov.ready("chat_only", "business")
    assert not ok and WHERE in why and "API key" in why
    assert WHERE in prov.ready("chat_only", "solo")[1]
    for edition in ("business", "solo"):
        ok, why = prov.ready("claude_api", edition)
        assert not ok and WHERE in why and "Task Queue" not in why
    dga.save_agent_key("anthropic", "sk-ant-api03-test")
    assert prov.ready("claude_api", "business") == (True, "")


# ── the monthly budget every agent shares ────────────────────────────────────────────

def test_budget_saves_the_shared_setting_and_copies_it_to_the_other_agents(shared):
    ok, msg = dga.save_agent_budget("$35", "solo")
    assert ok and "$35" in msg
    assert desk_db.get_settings(shared["db"])["agent_monthly_budget_usd"] == 35
    assert shared["synced"] == [shared["db"]]
    assert dga.load_agent_budget()[0] == 35
    assert dga.save_agent_budget("0", "business")[0]


@pytest.mark.parametrize("value", ["abc", "12.5", "-1", "20000"])
def test_bad_budget_is_refused(shared, value):
    ok, _msg = dga.save_agent_budget(value, "solo")
    assert not ok
    assert dga.load_agent_budget()[0] == das.DEFAULTS["agent_monthly_budget_usd"]


# ── GUI ──────────────────────────────────────────────────────────────────────────────

def _tk():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    return tk, root


def _labelframes(w, out=None):
    out = [] if out is None else out
    for c in w.winfo_children():
        try:
            if c.winfo_class() == "TLabelframe":
                out.append(c.cget("text"))
        except Exception:  # noqa: BLE001
            pass
        _labelframes(c, out)
    return out


def _texts(w, out=None):
    out = [] if out is None else out
    for c in w.winfo_children():
        try:
            out.append(str(c.cget("text")))
        except Exception:  # noqa: BLE001
            pass
        _texts(c, out)
    return out


@pytest.mark.parametrize("edition,note", [("business", "without one they don't run"), ("solo", "runs on these same keys")])
def test_agent_api_key_section_on_both_editions(shared, edition, note):
    tk, root = _tk()
    try:
        frame = tk.Frame(root)
        panel = dga.build_agent_key_section(frame, edition)
        assert panel and dga.AGENT_KEY_TITLE in _labelframes(frame)
        assert any(note in t for t in _texts(frame))
        assert any("Monthly budget" in t for t in _texts(frame))
        assert panel["budget"]["var"].get() == str(das.DEFAULTS["agent_monthly_budget_usd"])
    finally:
        root.destroy()


def test_small_business_tab_builds_the_key_section_first():
    gui = (ROOT / "rag_gui.py").read_text(encoding="utf-8")
    tab = gui[gui.index("def create_small_business_tab"):]
    assert tab.index("build_agent_key_section(f)") < tab.index("# ── 1. OVERVIEW BANNER")


@pytest.mark.parametrize("edition", ["business", "solo"])
def test_agent_settings_have_no_key_box_and_offer_chat(db, monkeypatch, edition):
    tk, root = _tk()

    class App:
        pass
    app = App(); app.root = root; app.status_var = tk.StringVar(value="Ready")
    monkeypatch.setattr(dga, "db_and_edition", lambda: (db, edition))
    try:
        frame = tk.Frame(root)
        v = dga.build_agent_settings(app, frame)
        assert dga.AGENT_KEY_TITLE not in _labelframes(frame)            # it's at the top of the tab
        text = " ".join(_texts(frame))
        assert WHERE in text and "Task Queue" not in text
        assert "Run the AI-Prowler agent" not in text and not v["agent_provider"].get().startswith("Chat")
        assert "With no key saved it doesn't run" in text
    finally:
        root.destroy()


def test_key_and_budget_buttons(keys, shared, monkeypatch):
    tk, root = _tk()
    from tkinter import messagebox
    monkeypatch.setattr(messagebox, "showinfo", lambda *a, **k: None)
    monkeypatch.setattr(messagebox, "showwarning", lambda *a, **k: None)
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **k: True)
    try:
        panel = dga.build_agent_key_section(tk.Frame(root), "solo")
        row = panel["anthropic"]
        assert row["entry"].cget("show") == "•"
        row["var"].set("sk-ant-api03-gui")
        row["save"]()
        assert prov.load_agent_key("anthropic") == "sk-ant-api03-gui"
        assert row["var"].get() == "" and row["status"].get().endswith("Saved")
        row["clear"]()
        assert not prov.has_agent_key("anthropic") and row["status"].get() == "Not saved"
        panel["budget"]["var"].set("50")
        panel["budget"]["save"]()
        assert desk_db.get_settings(shared["db"])["agent_monthly_budget_usd"] == 50
        assert panel["budget"]["spent"].get().endswith("of $50")
        assert panel["budget"]["forecast"].get().startswith("Spent this month: $0.00 of $50")
    finally:
        root.destroy()


def test_spent_this_month_line_refreshes_itself(shared, monkeypatch):
    """2026-11-03 (David: "I dont see these cost added to the number"): spend recorded after the tab was built
    shows up on its own — the line re-reads the run records every FORECAST_REFRESH_MS, no button needed."""
    tk, root = _tk()
    spent = {"v": 0.0}
    monkeypatch.setattr(dga, "forecast_line", lambda edition: f"Spent this month: ${spent['v']:.2f} of $20")
    monkeypatch.setattr(dga, "load_agent_budget", lambda: (20, spent["v"]))
    monkeypatch.setattr(dga, "FORECAST_REFRESH_MS", 50)
    try:
        panel = dga.build_agent_key_section(tk.Frame(root), "solo")
        assert panel["budget"]["forecast"].get() == "Spent this month: $0.00 of $20"
        spent["v"] = 0.27                                    # an agent run / AI task recorded its cost
        for _ in range(100):
            root.update()
            if panel["budget"]["forecast"].get().startswith("Spent this month: $0.27"):
                break
            __import__("time").sleep(0.01)
        assert panel["budget"]["forecast"].get() == "Spent this month: $0.27 of $20"
        assert panel["budget"]["spent"].get() == "Spent this month: $0.27 of $20"
    finally:
        root.destroy()


def test_key_lights_follow_the_saved_state(keys, shared, monkeypatch):
    """David 4 Nov: green when saved, grey when not, and a key saved elsewhere (the Setup popup) shows by itself."""
    tk, root = _tk()
    from tkinter import messagebox
    monkeypatch.setattr(messagebox, "showinfo", lambda *a, **k: None)
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **k: True)
    monkeypatch.setattr(dga, "KEY_REFRESH_MS", 20)
    try:
        panel = dga.build_agent_key_section(tk.Frame(root), "solo")
        light = panel["anthropic"]["light"]
        assert str(light.cget("foreground")) == dga.KEY_LIGHT_NONE
        panel["anthropic"]["var"].set("sk-ant-api03-gui")
        panel["anthropic"]["save"]()
        panel["refresh_keys"]()
        assert str(light.cget("foreground")) == dga.KEY_LIGHT_SAVED
        assert str(panel["grok"]["light"].cget("foreground")) == dga.KEY_LIGHT_NONE
        dga.clear_agent_key("anthropic")                     # removed somewhere else
        import time
        end = time.time() + 2
        while time.time() < end and str(light.cget("foreground")) != dga.KEY_LIGHT_NONE:
            root.update()
            time.sleep(0.01)
        assert str(light.cget("foreground")) == dga.KEY_LIGHT_NONE
        assert panel["anthropic"]["status"].get() == "Not saved"
    finally:
        root.destroy()
