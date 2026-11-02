"""A stronger model for complex steps and a cheaper one for simple steps, and the 📊 cost analysis popup
(2026-11-01, David).

Run: run_tests.bat tests\\unit\\test_agent_smart_models.py
"""
import datetime as dt
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_agent_budget as ab  # noqa: E402
import desk_agent as ag  # noqa: E402
import desk_agent_providers as prov  # noqa: E402
import desk_db  # noqa: E402
import desk_gui_agent as dga  # noqa: E402
import desk_rules as r  # noqa: E402
import task_queue_automation as tqa  # noqa: E402

NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.timezone.utc)
LIGHT = {"agent_claude_model_light": "claude-haiku-5-5"}


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(tqa, "CONFIG_PATH", tmp_path / "task_automation_config.json")
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path)
    return tmp_path


@pytest.mark.parametrize("kind,stage,complex_", [
    ("route", "sort", True), ("route", "replan", True), ("job", "schedule", True), ("booking", "decide", True),
    ("ticket", "resolution", True), ("hr", "timeoff", True), ("mystery", "x", True),
    ("ticket", "intake", False), ("ticket", "first_reply", False), ("job", "collect", False),
    ("job", "prep", False), ("booking", "reply", False), ("hr", "onboard", False),
])
def test_which_steps_are_complex(kind, stage, complex_):
    assert prov.is_complex(kind, stage) is complex_


@pytest.mark.parametrize("kind,stage,group", [
    ("ticket", "first_reply", "customer"), ("ticket", "follow_through", "customer"), ("booking", "reply", "customer"),
    ("booking", "track", "customer"), ("job", "quotes", "customer"), ("job", "collect", "customer"),
    ("job", "repeat", "customer"), ("route", "send", "complex"), ("booking", "decide", "complex"),
    ("ticket", "intake", "simple"), ("ticket", "learn", "simple"), ("job", "prep", "simple"),
    ("job", "closeout", "simple"), ("job", "onsite", "simple"), ("booking", "check", "simple"),
])
def test_customer_messages_are_their_own_group_on_the_stronger_model(kind, stage, group):
    assert prov.step_group(kind, stage) == group
    want = "claude-haiku-5-5" if group == "simple" else "claude-sonnet-5-5"
    assert prov.model_for_item("claude_api", {"kind": kind, "stage": stage}, LIGHT) == want


def test_model_per_item():
    route, intake = {"kind": "route", "stage": "route"}, {"kind": "ticket", "stage": "intake"}
    assert prov.model_for_item("claude_api", intake, {}) == "claude-sonnet-5-5"            # no simple model chosen
    assert prov.model_for_item("claude_api", intake, LIGHT) == "claude-haiku-5-5"
    assert prov.model_for_item("claude_api", route, LIGHT) == "claude-sonnet-5-5"
    assert prov.model_for_item("claude_api", route, dict(LIGHT, agent_claude_model="claude-opus-5-5")) == \
        "claude-opus-5-5"
    assert prov.model_for_item("grok_api", intake, LIGHT) == prov.model_for("grok_api", LIGHT)
    assert prov.model_for_item("claude_api", intake, {"agent_claude_model_light": "gpt-9"}) == "claude-sonnet-5-5"


def test_light_model_is_saved(cfg):
    prov.set_light_model("claude-haiku-5-5")
    assert json.loads((cfg / "task_automation_config.json").read_text())["agent_claude_model_light"] == \
        "claude-haiku-5-5"
    assert prov.light_model() == "claude-haiku-5-5"
    prov.set_light_model("")
    assert prov.light_model() == ""
    with pytest.raises(ValueError):
        prov.set_light_model("gpt-9")


@pytest.fixture
def desk(tmp_path, monkeypatch):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    for k, v in (("agent_enabled", True), ("agent_shadow", False), ("agent_provider", "claude_api"),
                 ("agent_batch_seconds", 0)):
        desk_db.set_setting(tickets, k, v, edition=r.SOLO)
    monkeypatch.setattr(prov, "_key", lambda p: "test-key")
    monkeypatch.setattr(prov, "_cfg", lambda: dict(LIGHT))
    ag.enable(lambda: tickets)
    yield tickets
    ag.disable()
    ag.transport = None


def test_a_run_uses_the_cheap_model_for_a_simple_step_and_records_it(desk, monkeypatch):
    c = desk_db.upsert_contact(desk, name="Maria Lopez", phone="+13865550142", contact_type="customer")
    desk_db.create_ticket(desk, title="Streaks on the windows", kind=r.EXTERNAL, actor=None, edition=r.SOLO,
                          description="Left side", contact_id=c["contact_id"], priority="P3")
    seen = []

    def fake_ask(provider, system, user, *, model=""):
        seen.append((json.loads(user).get("stage"), model))
        return json.dumps({"actions": [{"action": "no_action", "why": "x", "confidence": 1}]}), \
            {"input": 1_000_000, "output": 0}
    monkeypatch.setattr(prov, "ask", fake_ask)
    out = ag.run(desk, edition=r.SOLO, force=True)
    assert seen and all(m == ("claude-sonnet-5-5" if prov.uses_strong_model("ticket", st) else "claude-haiku-5-5")
                        for st, m in seen)
    # $0.10 per 1M input on Haiku (internal steps), $2 on Sonnet (customer messages / complex)
    assert out["cost_usd"] == pytest.approx(sum(0.10 if m == "claude-haiku-5-5" else 2.0 for _, m in seen))
    con = sqlite3.connect(desk)
    model = con.execute("SELECT model FROM agent_runs ORDER BY run_id DESC").fetchone()[0]
    con.close()
    assert "claude-haiku-5-5" in model


# ── the cost analysis ────────────────────────────────────────────────────────────────

def runs_db(path, runs, queue):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE agent_runs (run_id INTEGER PRIMARY KEY, provider TEXT, model TEXT, started_at TEXT, "
                "ended_at TEXT, items INT, ok INT, input_tokens INT, output_tokens INT, cost_usd REAL, summary TEXT)")
    con.execute("CREATE TABLE agent_queue (item_id INTEGER PRIMARY KEY, kind TEXT, stage TEXT, created_at TEXT)")
    for model, started, items, ti, to, cost in runs:
        con.execute("INSERT INTO agent_runs (model, started_at, items, input_tokens, output_tokens, cost_usd) "
                    "VALUES (?, ?, ?, ?, ?, ?)", (model, started, items, ti, to, cost))
    for kind, stage, created in queue:
        con.execute("INSERT INTO agent_queue (kind, stage, created_at) VALUES (?, ?, ?)", (kind, stage, created))
    con.commit()
    con.close()
    return str(path)


def test_analysis_volume_mix_and_estimates(tmp_path, monkeypatch):
    monkeypatch.setattr(prov, "_cfg", lambda: dict(LIGHT))
    monkeypatch.setattr(ab, "current", lambda *a, **k: {"text": "Spent this month: $1.00 of $20"})
    db = runs_db(tmp_path / "agent.db",
                 [("claude-sonnet-5-5", "2026-11-03T10:00:00Z", 105, 189_000, 57_750, 0.95),
                  ("claude-sonnet-5-5", "2026-10-03T10:00:00Z", 999, 9, 9, 9.0)],
                 [("route", "route", "2026-11-03T09:00:00Z"), ("job", "collect", "2026-11-03T09:00:00Z"),
                  ("ticket", "intake", "2026-11-03T09:00:00Z"), ("job", "prep", "2026-11-03T09:00:00Z")])
    a = ab.analysis("solo", NOW, paths=[db])
    days = (NOW - dt.datetime(2026, 11, 3, 10, 0, tzinfo=dt.timezone.utc)).total_seconds() / 86400
    assert a["items"] == 105 and a["calls_per_day"] == pytest.approx(105 / days)     # Oct 3 is outside 30 days
    assert a["call_tokens"] == (1800, 550) and a["complex_share"] == pytest.approx(0.5)   # route + collect (customer)
    est = {e["model"]: e for e in a["estimates"]}
    assert est["claude-sonnet-5-5"]["per_call"] == pytest.approx(0.0091)         # 1800×$2 + 550×$10 per 1M
    smart = est["claude-sonnet-5-5+claude-haiku-5-5"]
    assert est["claude-haiku-5-5"]["per_month"] < smart["per_month"] < est["claude-sonnet-5-5"]["per_month"]
    assert smart["per_call"] == pytest.approx(0.5 * 0.0091 + 0.5 * 0.000455, rel=1e-2)
    assert a["agents"][0]["items"] == 105 and a["models"][0]["per_call"] == pytest.approx(0.95 / 105, rel=1e-3)


def test_measure_reads_answers_and_never_submits():
    calls = []

    def fake(provider, system, user, *, model=""):
        calls.append(model)
        return json.dumps({"actions": [{"action": "rt_route_day"}]}), {"input": 2000, "output": 400}
    res = ab.measure(["claude-sonnet-5-5", "claude-haiku-5-5"], "sys", [("route / route", "{}", True)], ask_fn=fake)
    assert calls == ["claude-sonnet-5-5", "claude-haiku-5-5"]
    assert res["per_model"]["claude-sonnet-5-5"] == {"tokens": (2000, 400), "per_call": pytest.approx(0.008)}
    assert res["rows"][0]["answer"] == "rt_route_day" and res["cost"] == pytest.approx(0.008 + 0.0004)
    est = ab.estimates(10, (1800, 550), 0.3, cfg={}, measured=res["per_model"])
    assert next(e for e in est if e["model"] == "claude-sonnet-5-5")["measured"] is True


def test_cost_popup_fills_and_runs_a_live_analysis(monkeypatch):
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    monkeypatch.setattr(prov, "has_agent_key", lambda p: True)
    monkeypatch.setattr(prov, "_cfg", lambda: dict(LIGHT))
    seen_measured = []

    def fake_analysis(measured):
        seen_measured.append(measured)
        return {"forecast": {"text": "Spent this month: $0.95 of $20"}, "calls_per_day": 10.0,
                "calls_per_day_used": 10.0, "call_tokens": (1800, 550), "complex_share": 0.25,
                "complex_share_used": 0.25, "main_model": "claude-sonnet-5-5", "light_model": "claude-haiku-5-5",
                "agents": [{"name": "Jobs app", "runs": 3, "items": 105, "input": 1, "output": 1, "cost": 0.95}],
                "estimates": ab.estimates(10, (1800, 550), 0.25, cfg=LIGHT, measured=measured)}
    try:
        ui = dga.open_cost_analysis(root, "solo", analysis_fn=fake_analysis,
                                    sample_fn=lambda: ("sys", [("route / route", "{}", True)]),
                                    measure_fn=lambda models, system, samples: {
                                        "rows": [{"model": m, "item": "route / route", "complex": True, "input": 2000,
                                                  "output": 400, "cost": 0.008, "answer": "rt_route_day"}
                                                 for m in models],
                                        "per_model": {m: {"tokens": (2000, 400), "per_call": 0.008} for m in models},
                                        "cost": 0.016})
        t_agents, t_est, t_live = ui["tables"]
        assert ui["head"].get().startswith("Spent this month") and len(t_agents.get_children()) == 1
        assert any("Smart mix" in str(t_est.item(i)["values"][0]) for i in t_est.get_children())
        ui["run_live"]()
        for _ in range(200):
            root.update()
            if len(t_live.get_children()) == 2:
                break
            __import__("time").sleep(0.01)
        assert len(t_live.get_children()) == 2 and "cost" in ui["status"].get()
        assert seen_measured[-1] and "claude-sonnet-5-5" in seen_measured[-1]
    finally:
        root.destroy()
