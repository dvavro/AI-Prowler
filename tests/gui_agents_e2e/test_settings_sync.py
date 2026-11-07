"""AG-SYNC-01…03 — the desktop and the apps show the same settings. The real Tk sections are pointed at the Solo
sandbox's own database files (never the real install), so a value saved on one screen must show on the other. On a
server the apps only read (test_settings_server_readonly.py), so the app → desktop direction is Solo only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import desk_agent_hr_store as hstore
import desk_agent_providers as prov
import desk_agent_settings as das
import desk_agent_store as store
import desk_db
import desk_gui_links
import task_queue_automation as tqa
from test_settings_desk_pwa import Card
from test_settings_desktop import Agent, Env, Jobs, LABEL, messagebox, shared_value, tk
from test_settings_jobs_pwa import JobsSettings


@pytest.fixture
def desktop(solo, tmp_path, monkeypatch):
    state = Path(solo.control("GET", "/state")["sandbox"])
    tdb = state / "tickets_database" / desk_db.DEFAULT_DB_FILENAME
    assert tdb.exists(), tdb
    assert "_home" in str(state), state                        # only ever a sandbox
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(state))
    monkeypatch.setattr(desk_db, "default_db_path", lambda *a, **k: str(tdb))
    monkeypatch.setattr(store, "PATH_OVERRIDE", state / "agent_database" / "agent.db")
    monkeypatch.setattr(hstore, "PATH_OVERRIDE", state / "hr" / "agent" / "hr_agent.db")
    monkeypatch.setattr(desk_gui_links, "_state_dir", lambda: tmp_path)
    monkeypatch.setattr(desk_gui_links, "mode_of", lambda: "personal")
    monkeypatch.setattr(desk_gui_links, "desk_switched_on", lambda: True)
    monkeypatch.setattr(prov, "AGENT_KEY_DIR", tmp_path / "keys")
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / "tq")
    monkeypatch.setattr(tqa, "CONFIG_PATH", tmp_path / "tq" / "cfg.json")
    said = []
    for fn, kind in (("showinfo", "info"), ("showerror", "error"), ("showwarning", "warning")):
        monkeypatch.setattr(messagebox, fn, lambda t, m, k=kind, **_: said.append((k, m)))
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    monkeypatch.setattr(tk, "_default_root", root)
    root.title("ZAG desktop ↔ app settings")
    yield Env(root, "personal", tmp_path, said, [])
    root.destroy()


def test_sync_01_service_desk_app_to_desktop(solo, person, desktop):
    card = Card(solo, person)
    card.type("#agName", "Sync Sam")
    card.type("#agSignoff", "ZAG from the app")
    card.save()
    card.toast("Saved")
    card.tick("agent_include_service_link")
    card.pick("agent_stage_learn", "off")
    card.pick("agent_bk_stage_track", "auto")
    v = Agent(desktop).v
    assert v["agent_name"].get() == "Sync Sam"
    assert v["agent_reply_signoff"].get() == "ZAG from the app"
    assert v["agent_include_service_link"].get() is True
    assert v["agent_stage_learn"].get() == LABEL["off"]
    assert v["agent_bk_stage_track"].get() == LABEL["auto"]


def test_sync_02_desktop_to_service_desk_app(solo, person, desktop):
    card = Card(solo, person)                                  # sets the known defaults first
    a = Agent(desktop)
    a.v["agent_name"].set("Desk Top")
    a.v["agent_wait_hours"].set("11")
    a.v["agent_stage_intake"].set(LABEL["auto"])
    assert a.save()[0] == "ok"
    card.page.reload()
    card.open()
    assert card.page.locator("#agName").input_value() == "Desk Top"
    assert card.page.locator("#agWait").input_value() == "11"
    assert card.page.locator("#agentCard select[data-ag='agent_stage_intake']").input_value() == "auto"
    assert card.stored("agent_wait_hours") == 11


def test_sync_01_jobs_app_to_desktop(solo, person, desktop):
    js = JobsSettings(solo, person)
    js.save_jobs(agQuote=9, agRemind="3, 7")
    js.toast("Saved.")
    js.pick("agent_jb_stage_quotes", "auto")
    js.pick("agent_jb_sort_weekday", 2)
    v = Jobs(desktop).v
    assert v["agent_jb_quote_days"].get() == "9"
    assert v["agent_jb_remind_days"].get() == "3, 7"
    assert v["agent_jb_stage_quotes"].get() == LABEL["auto"]
    assert v["agent_jb_sort_weekday"].get() == "Wednesday"


def test_sync_02_desktop_to_jobs_app(solo, person, desktop):
    js = JobsSettings(solo, person)
    j = Jobs(desktop)
    j.v["agent_jb_quote_days"].set("12")
    j.v["agent_jb_remind_days"].set("5, 10")
    j.v["agent_jb_rt_stage_send"].set(LABEL["off"])
    assert j.save()[0] == "info"
    js.page.reload()
    js.page.locator("#navAgent").click()
    js.page.locator("#agSettingsBox summary").click()
    js.page.locator("#agSettings select").first.wait_for()
    assert js.page.locator("#agQuote").input_value() == "12"
    assert js.page.locator("#agRemind").input_value().replace(" ", "") == "5,10"
    assert js.page.locator("#agSettings select[data-agk='agent_jb_rt_stage_send']").input_value() == "off"


def test_sync_03_shared_budget_and_runner_reach_every_agent(solo, person, desktop):
    card = Card(solo, person)
    a = Agent(desktop)
    a.v["agent_monthly_budget_usd"].set("77")
    assert a.save()[0] == "ok"
    a.v["agent_provider"].set(dict(das.providers_for("solo"))["grok_api"])
    assert a.save()[0] == "ok"
    st, d = solo.desk("GET", "/agent")
    assert st == 200 and d["settings"]["agent_monthly_budget_usd"] == 77
    assert card.stored("agent_provider") == "grok_api"
    # Copied to the Jobs agent's database before each run: after one pass it agrees.
    solo.agents_pass()
    assert shared_value(store.path(), "agent_monthly_budget_usd") == "77"
    assert "grok_api" in shared_value(store.path(), "agent_provider")
    solo.settings(desk={"agent_monthly_budget_usd": 20, "agent_enabled": False})
    solo.settings(desk={"agent_provider": "claude_api"})
