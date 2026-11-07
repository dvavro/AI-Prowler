"""The self-running agent (desk_agent.run + desk_agent_providers): reading the AI's answer,
whether a run should start, one AI call per item through the normal policy, failures and
retries, the lock, the budget, and the scheduler / Run now starting it. No network: the
desk_agent.transport hook stands in for the AI.
Run: run_tests.bat tests\\unit\\test_desk_agent_runner.py
"""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent as ag  # noqa: E402
import desk_agent_providers as prov  # noqa: E402
import desk_db  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_scheduler  # noqa: E402
import desk_tools  # noqa: E402
from db_access import get_connection  # noqa: E402

S = r.SOLO
OWNER = {"user_id": "owner", "role": r.OWNER}


@pytest.fixture
def db(tmp_path, monkeypatch):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    for k, v in (("agent_enabled", True), ("agent_shadow", False), ("agent_provider", "claude_api"),
                 ("agent_batch_seconds", 0)):
        desk_db.set_setting(tickets, k, v, edition=S)
    monkeypatch.setattr(prov, "_key", lambda p: "test-key")
    monkeypatch.setattr(prov, "_cfg", lambda: {})
    ag.enable(lambda: tickets)
    yield tickets
    ag.disable()
    ag.transport = None


def ticket(db, title="Streaks on the front windows"):
    c = desk_db.upsert_contact(db, name="Maria Lopez", phone="+13865550142", contact_type="customer")
    return desk_db.create_ticket(db, title=title, kind=r.EXTERNAL, actor=None, edition=S,
                                 description="Left side is streaky", contact_id=c["contact_id"], priority="P3")


def rows(db, sql, *a):
    ag.ensure_schema(db)
    conn = get_connection(db)
    try:
        return [dict(x) for x in conn.execute(sql, a)]
    finally:
        conn.close()


def fake(answer=None, *, fail=False, calls=None):
    def t(provider, system, user):
        if calls is not None:
            calls.append((provider, system, json.loads(user)))
        if fail:
            raise prov.ProviderError("HTTP 529: overloaded")
        return (answer or json.dumps({"actions": [{"action": "note", "body": "Looked at it.", "why": "first look",
                                                    "confidence": 0.9}], "summary": "noted"}),
                {"input": 2000, "output": 300})
    return t


# ── reading the AI's answer ──────────────────────────────────────────────────

def test_parse_actions_tolerates_fences_and_chatter():
    acts, summ = prov.parse_actions('Sure!\n```json\n{"actions":[{"action":"no_action"}],"summary":"ok"}\n```')
    assert acts == [{"action": "no_action"}] and summ == "ok"


@pytest.mark.parametrize("text", ["no json here", '{"actions": "x"}', '{"actions": [1, }'])
def test_parse_actions_rejects_bad_answers(text):
    with pytest.raises(prov.ProviderError):
        prov.parse_actions(text)


def test_parse_actions_caps_at_eight_and_drops_non_objects():
    acts, _ = prov.parse_actions(json.dumps({"actions": [{"action": "note"}] * 12 + ["x"]}))
    assert len(acts) == 8


def test_cost_uses_prices_and_config_override():
    assert prov.cost("claude-sonnet-5-5", {"input": 1_000_000, "output": 100_000}, {}) == pytest.approx(3.0)
    assert prov.cost("grok-4.3", {"input": 1_000_000, "output": 0}, {}) == pytest.approx(1.25)
    assert prov.cost("x", {"input": 10, "output": 10}, {"agent_prices": {"x": [1, 1]}}) == pytest.approx(0.00002)
    assert prov.cost("unknown", {"input": 10}, {}) == 0.0


def test_ready_says_whats_missing(monkeypatch):
    assert prov.ready("chat_only")[0] is False
    assert prov.ready("claude_code", "solo")[0] is False              # 2026-11-01: no Claude CLI runner
    monkeypatch.setattr(prov, "_key", lambda p: "")
    assert "Claude API key" in prov.ready("claude_api")[1]
    assert "Grok API key" in prov.ready("grok_api")[1]
    monkeypatch.setattr(prov, "_key", lambda p: "k")
    assert prov.ready("grok_api") == (True, "")


# ── whether to start ─────────────────────────────────────────────────────────

def test_why_not_run_reasons(db, monkeypatch):
    now = ag._now()
    s = desk_db.get_settings(db)
    assert ag.why_not_run(db, s, edition=S, now=now) == "nothing waiting"
    ticket(db)
    assert ag.why_not_run(db, s, edition=S, now=now) == ""
    assert ag.why_not_run(db, dict(s, agent_enabled=False), edition=S, now=now) == "the agent is off"
    with monkeypatch.context() as m:
        m.setattr(prov, "_key", lambda p: "")
        assert "no API key" in ag.why_not_run(db, dict(s, agent_provider="chat_only"), edition=S, now=now)
    off_hours = [(now.hour + 1) % 24, (now.hour + 1) % 24 + 1]
    assert "outside" in ag.why_not_run(db, dict(s, agent_hours=off_hours), edition=S, now=now)
    assert ag.why_not_run(db, dict(s, agent_hours=off_hours), edition=S, now=now, force=True) == ""
    assert "budget" in ag.why_not_run(db, dict(s, agent_monthly_budget_usd=0), edition=S, now=now)
    assert "burst" in ag.why_not_run(db, dict(s, agent_batch_seconds=3600), edition=S, now=now)
    assert ag.why_not_run(db, dict(s, agent_batch_seconds=3600, agent_max_items=1), edition=S, now=now) == ""


def test_budget_used_up_stops_runs(db):
    ticket(db)
    conn = get_connection(db)
    conn.execute("INSERT INTO agent_runs (provider, model, started_at, cost_usd) VALUES ('claude_api', 'm', ?, 25)",
                 (desk_db.utcnow_iso(),))
    conn.close()
    assert "used up" in ag.why_not_run(db, desk_db.get_settings(db), edition=S, now=ag._now())


# ── a run ────────────────────────────────────────────────────────────────────

def test_run_works_each_item_through_the_policy_and_records_cost(db):
    t = ticket(db)
    calls = []
    ag.transport = fake(calls=calls)
    out = ag.run(db, edition=S)
    assert out["ran"] and out["items"] == 2 and out["ok"] == 2
    assert [c[0] for c in calls] == ["claude_api", "claude_api"]
    assert "ONLY one JSON object" in calls[0][1]                     # the headless rules ride on the system prompt
    assert "instructions" not in calls[0][2]
    assert {x["status"] for x in rows(db, "SELECT status FROM agent_queue")} == {"done"}
    props = rows(db, "SELECT * FROM agent_proposals")
    assert props and all(p["provider"] == "claude_api" and p["ref"] == t["ticket_id"] for p in props)
    run = rows(db, "SELECT * FROM agent_runs")[-1]
    assert (run["items"], run["ok"], run["input_tokens"], run["output_tokens"]) == (2, 2, 4000, 600)
    assert run["cost_usd"] == pytest.approx(prov.cost("claude-sonnet-5-5", {"input": 4000, "output": 600}, {}))
    st = ag.status(db)
    assert st["runs_on_its_own"] and st["spent_usd"] == round(run["cost_usd"], 2)


def test_a_bad_answer_fails_that_item_only_then_errors_after_three_tries(db):
    ticket(db)
    ag.transport = fake("I think we should reply nicely.")
    first = ag.run(db, edition=S)
    assert first["items"] == 2                                       # each item tried once per run, then held back
    assert ag.why_not_run(db, desk_db.get_settings(db), edition=S, now=ag._now()) == "nothing waiting"
    for _ in range(ag.MAX_ATTEMPTS):
        conn = get_connection(db)
        conn.execute("UPDATE agent_queue SET claimed_until = '2000-01-01T00:00:00' WHERE claimed_by = 'retry'")
        conn.close()
        ag.run(db, edition=S)
    q = rows(db, "SELECT status, attempts, note FROM agent_queue")
    assert {x["status"] for x in q} == {"error"}
    assert all("JSON" in x["note"] for x in q)
    assert ag.status(db)["errors"] == len(q)
    assert ag.retry_errors(db) == len(q)
    ag.transport = fake()
    assert ag.run(db, edition=S)["ok"] == len(q)


def test_provider_error_is_noted_and_the_item_waits_for_next_time(db):
    ticket(db)
    ag.transport = fake(fail=True)
    out = ag.run(db, edition=S)
    assert out["ran"] and out["ok"] == 0 and any("529" in n for n in out["notes"])
    q = rows(db, "SELECT status, claimed_by, attempts FROM agent_queue")
    assert {(x["status"], x["claimed_by"], x["attempts"]) for x in q} == {("claimed", "retry", 1)}
    assert "529" in rows(db, "SELECT summary FROM agent_runs")[-1]["summary"]


def test_lock_keeps_a_second_run_out_and_a_stale_lock_is_ignored(db):
    import os
    ticket(db)
    ag.transport = fake()
    lock = Path(desk_db.root_for(db)) / ag.RUN_LOCK
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("x")
    assert ag.run(db, edition=S) == {"ran": False, "why": "a run is already going"}
    old = ag._now().timestamp() - (ag.LOCK_STALE_MINUTES + 1) * 60
    os.utime(lock, (old, old))
    assert ag.run(db, edition=S)["ran"] and not lock.exists()


def test_run_stops_when_the_budget_runs_out_mid_run(db):
    desk_db.set_setting(db, "agent_monthly_budget_usd", 1, edition=S)
    ticket(db)
    ag.transport = lambda p, s, u: (json.dumps({"actions": [{"action": "no_action"}]}), {"input": 600_000, "output": 0})
    out = ag.run(db, edition=S)
    assert out["items"] == 1 and "stopped: monthly budget reached" in out["notes"]


def _no_runner(db):
    """An old saved chat_only; it can't be saved any more."""
    import json
    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute("UPDATE desk_settings SET value = ? WHERE key = 'agent_provider'", (json.dumps("chat_only"),))
    conn.commit()
    conn.close()


def test_no_key_never_runs(db, monkeypatch):
    monkeypatch.setattr(prov, "_key", lambda p: "")
    _no_runner(db)
    ticket(db)
    ag.transport = fake()
    out = ag.run(db, edition=S, force=True)
    assert out["ran"] is False and "no API key" in out["why"]


# ── who starts it ────────────────────────────────────────────────────────────

def test_scheduler_tick_starts_a_background_run(db, monkeypatch):
    ticket(db)
    started = []
    monkeypatch.setattr(ag, "run_in_background", lambda d, **kw: started.append(kw) or True)
    did = desk_scheduler.run_once(db, edition=S)
    assert started and did.get("agent_run") is True
    monkeypatch.setattr(prov, "_key", lambda p: "")
    _no_runner(db)
    started.clear()
    desk_scheduler.run_once(db, edition=S)
    assert not started


def test_run_now_tool_is_owner_only_and_says_why_not(db, monkeypatch):
    monkeypatch.setattr(ag, "run_in_background", lambda d, **kw: True)
    assert "Only the owner" in desk_tools.desk_agent_run_now(db, {"user_id": "m", "role": r.MANAGER}, S)
    assert "nothing waiting" in desk_tools.desk_agent_run_now(db, OWNER, S)
    ticket(db)
    assert "Started" in desk_tools.desk_agent_run_now(db, OWNER, S)


def test_run_in_background_runs_once_at_a_time(db):
    import threading
    gate = threading.Event()
    ticket(db)

    def slow(p, s, u):
        gate.wait(5)
        return json.dumps({"actions": [{"action": "no_action"}]}), {"input": 1, "output": 1}
    ag.transport = slow
    assert ag.run_in_background(db, edition=S) is True
    assert ag.run_in_background(db, edition=S) is False
    gate.set()
    ag._bg[db].join(10)
    assert {x["status"] for x in rows(db, "SELECT status FROM agent_queue")} == {"done"}
