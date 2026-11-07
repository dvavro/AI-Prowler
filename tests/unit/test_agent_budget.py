"""Agent prices, AI model choice, the Claude-subscription runner fix, the budget forecast and the owner's
budget alert (2026-11-01, David).

Run: run_tests.bat tests\\unit\\test_agent_budget.py
"""
import datetime as dt
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_agent_budget as ab  # noqa: E402
import desk_agent_providers as prov  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import task_queue_automation as tqa  # noqa: E402

NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.timezone.utc)      # 10.5 days into a 30-day month


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(tqa, "CONFIG_PATH", tmp_path / "task_automation_config.json")
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path)
    return tmp_path


def runs_db(path, rows):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE agent_runs (run_id INTEGER PRIMARY KEY, provider TEXT, model TEXT, started_at TEXT, "
                "ended_at TEXT, items INT, ok INT, input_tokens INT, output_tokens INT, cost_usd REAL, summary TEXT)")
    for started, inp, out, cost in rows:
        con.execute("INSERT INTO agent_runs (started_at, input_tokens, output_tokens, cost_usd) VALUES (?, ?, ?, ?)",
                    (started, inp, out, cost))
    con.commit()
    con.close()
    return str(path)


# ── prices and models ────────────────────────────────────────────────────────────────

def test_prices_are_current():
    assert prov.price_for("claude-sonnet-5-5", {}) == [2.0, 10.0]
    assert prov.price_for("claude-haiku-5-5", {}) == [0.10, 0.50]
    assert prov.price_for("claude-opus-5-5", {}) == [4.0, 20.0]
    assert prov.price_for("grok-4.3", {}) == [1.25, 2.50]
    assert prov.price_for("grok-9", {}) == [1.25, 2.50]                  # any other grok-* model
    assert prov.cost("claude-haiku-5-5", {"input": 3000, "output": 400}, {}) == pytest.approx(0.0005)
    assert prov.price_for("claude-sonnet-5-5", {"agent_prices": {"claude-sonnet-5-5": [1, 2]}}) == [1, 2]


def test_model_choice_is_saved_and_used(cfg):
    labels = [lab for _, lab in prov.model_choices("claude_api")]
    assert any("Haiku" in x and "$0.1 / $0.5" in x for x in labels)
    assert prov.model_for("claude_api") == "claude-sonnet-5-5"           # default
    prov.set_agent_model("claude_api", "claude-haiku-5-5")
    assert prov.model_for("claude_api") == "claude-haiku-5-5"
    assert json.loads((cfg / "task_automation_config.json").read_text())["agent_claude_model"] == "claude-haiku-5-5"
    with pytest.raises(ValueError):
        prov.set_agent_model("claude_api", "gpt-9")


# ── the Claude subscription (CLI) runner is gone (2026-11-01, "Remove CLI everywhere") ───

def test_subscription_runner_is_gone():
    assert not hasattr(prov, "_claude_code") and not hasattr(prov, "_claude_exe")
    ok, why = prov.ready("claude_code", "solo")
    assert not ok and "unknown runner" in why          # F-26: an old saved value is converted when it's read
    with pytest.raises(prov.ProviderError):
        prov.ask("claude_code", "s", "u")


def test_task_queue_runs_count_in_the_shared_budget(cfg, monkeypatch):
    """Task Queue runs are recorded in their own agent_runs table, which the budget reads too."""
    tqa._record_run("claude_api", "claude-sonnet-5-5", NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), 2, True,
                    {"input": 1000, "cache_write": 0, "cache_read": 0, "output": 100}, 1.25, "run now: ok")
    from pathlib import Path
    assert str(Path(tqa.runs_db_path()).resolve()) in ab.agent_db_paths(None, {})
    assert ab.month_totals([tqa.runs_db_path()], NOW.strftime("%Y-%m"))["cost"] == pytest.approx(1.25)
    names = [r["name"] for r in ab.per_agent([tqa.runs_db_path()], NOW.strftime("%Y-%m"))]
    assert names == ["Task Queue"]


# ── forecast ─────────────────────────────────────────────────────────────────────────

def test_forecast_pace_runout_and_tokens_left():
    f = ab.forecast(20, {"cost": 10.5, "input": 900_000, "output": 100_000, "runs": 40}, NOW, "claude-sonnet-5-5", {})
    assert f["daily"] == pytest.approx(1.0) and f["projected"] == pytest.approx(30.0)
    assert f["runout"] == "2026-11-21" and f["used_pct"] == pytest.approx(52.5)
    # $9.50 left at 90 % input $2 + 10 % output $10 = $2.80 per 1M → about 3.39M tokens
    assert 3_300_000 < f["tokens_left"] < 3_450_000
    txt = ab.forecast_text(f)
    assert "runs out about Nov 21" in txt and "tokens left on claude-sonnet-5-5" in txt


def test_forecast_lasts_the_month_and_no_runs():
    f = ab.forecast(20, {"cost": 2.1, "input": 1, "output": 1, "runs": 5}, NOW, "claude-haiku-5-5", {})
    assert f["runout"] is None and f["lasts_the_month"] and "lasts the month" in ab.forecast_text(f)
    assert ab.forecast_text(ab.forecast(20, {"cost": 0, "input": 0, "output": 0, "runs": 0}, NOW)) == \
        "Spent this month: $0.00 of $20"


def test_month_totals_add_every_agent_database(tmp_path):
    a = runs_db(tmp_path / "a.db", [("2026-11-02T10:00:00Z", 1000, 100, 0.5), ("2026-10-30T10:00:00Z", 9, 9, 9.0)])
    b = runs_db(tmp_path / "b.db", [("2026-11-05T10:00:00Z", 2000, 200, 1.25)])
    t = ab.month_totals([a, b, str(tmp_path / "missing.db")], "2026-11")
    assert t == {"cost": 1.75, "input": 3000, "output": 300, "runs": 2}


# ── the owner's alert ────────────────────────────────────────────────────────────────

@pytest.fixture
def spend(tmp_path, monkeypatch):
    db = runs_db(tmp_path / "agent.db", [])
    monkeypatch.setattr(ab, "agent_db_paths", lambda db=None, s=None: [db_path])
    db_path = db
    sent = []
    monkeypatch.setattr(ab, "send_fn", lambda subject, body, sms, edition: sent.append((subject, body, sms)) or
                        [("email", "owner@x.com")])
    monkeypatch.setattr(ab, "STATE_PATH", tmp_path / "state.json")

    def add(cost, when="2026-11-10T10:00:00Z"):
        con = sqlite3.connect(db_path)
        con.execute("INSERT INTO agent_runs (started_at, input_tokens, output_tokens, cost_usd) VALUES (?, 1000, 100, ?)",
                    (when, cost))
        con.commit()
        con.close()
    return {"add": add, "sent": sent}


S = {"agent_monthly_budget_usd": 20, "agent_budget_alert_pct": 80, "agent_provider": "claude_api"}


def test_alert_at_warn_pct_once_then_at_100(spend):
    spend["add"](10)
    assert ab.check_and_alert(S, edition="solo", now=NOW) == []                  # 50 %
    spend["add"](6.5)                                                             # 82.5 %
    assert ab.check_and_alert(S, edition="solo", now=NOW) == [80]
    assert "82% of this month's AI budget" in spend["sent"][0][0] and "Agent API Key" in spend["sent"][0][1]
    assert ab.check_and_alert(S, edition="solo", now=NOW) == []                  # once a month
    spend["add"](4)                                                               # 102.5 %
    assert ab.check_and_alert(S, edition="solo", now=NOW) == [100]
    assert "stopped" in spend["sent"][1][0] and len(spend["sent"]) == 2


def test_jumping_past_both_sends_one_alert_and_a_new_month_starts_over(spend):
    spend["add"](25)
    assert ab.check_and_alert(S, edition="solo", now=NOW) == [80, 100] and len(spend["sent"]) == 1
    spend["add"](17, when="2026-12-03T10:00:00Z")
    dec = dt.datetime(2026, 12, 5, tzinfo=dt.timezone.utc)
    assert ab.check_and_alert(S, edition="solo", now=dec) == [80]


def test_no_alert_when_turned_off_or_nobody_to_tell(spend, monkeypatch):
    spend["add"](19)
    assert ab.check_and_alert(dict(S, agent_budget_alert_pct=0), edition="solo", now=NOW) == []
    monkeypatch.setattr(ab, "send_fn", lambda *a: [])                           # no email / mobile set up
    assert ab.check_and_alert(S, edition="solo", now=NOW) == []
    monkeypatch.setattr(ab, "send_fn", lambda *a: [("email", "o@x.com")])        # set up later → it goes then
    assert ab.check_and_alert(S, edition="solo", now=NOW) == [80]


def test_server_alerts_owners_and_managers(monkeypatch):
    import desk_alerts as da
    monkeypatch.setitem(da._cfg, "team", lambda: [{"role": "owner", "email": "o@x.com", "phone": "+1386"},
                                                  {"role": "manager", "email": "m@x.com", "phone": ""},
                                                  {"role": "tech", "email": "t@x.com", "phone": "+1999"}])
    assert ab.owner_recipients("business") == (["o@x.com", "m@x.com"], ["+1386"])


def test_warn_pct_is_a_setting_shared_with_the_other_agents(tmp_path, monkeypatch):
    import desk_agent_hr_store
    import desk_agent_store
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    monkeypatch.setattr(desk_db, "default_db_path", lambda *a, **k: path)
    monkeypatch.setattr(desk_agent_store, "sync_shared", lambda db: {})
    monkeypatch.setattr(desk_agent_hr_store, "path", lambda: str(tmp_path / "no_hr" / "hr_agent.db"))
    assert desk_db.get_settings(path if desk_db.init_db(path) or True else path)["agent_budget_alert_pct"] == 80
    ok, msg = dga.save_agent_budget("30", "solo", "75")
    assert ok and "75%" in msg
    assert desk_db.get_settings(path)["agent_budget_alert_pct"] == 75
    assert not dga.save_agent_budget("30", "solo", "150")[0]
    assert "agent_budget_alert_pct" in desk_agent_store.SHARED_KEYS and \
        "agent_budget_alert_pct" in desk_agent_hr_store.SHARED_KEYS


def test_a_run_checks_the_budget_alert(monkeypatch, tmp_path):
    import desk_agent as ag
    calls = []
    monkeypatch.setattr(ab, "check_and_alert", lambda s, **kw: calls.append(kw) or [])
    db = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(db)
    for k, v in (("agent_enabled", True), ("agent_shadow", False), ("agent_provider", "claude_api"),
                 ("agent_monthly_budget_usd", 0)):
        desk_db.set_setting(db, k, v, edition="solo")
    monkeypatch.setattr(prov, "_key", lambda p: "k")
    out = ag.run(db, edition="solo", force=True)
    assert out["ran"] is False and "budget" in out["why"] and calls and calls[0]["edition"] == "solo"
