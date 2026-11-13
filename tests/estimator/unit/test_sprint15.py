"""Sprint 15 (re-ordered from planned Sprint 10, Coder 1): API-key agents, budgets, the agent task queue, role
prompts (S15-..). A fake provider stands in for Claude and Grok: no real API calls."""
import json
from datetime import date, datetime, timedelta

import pytest

from estimator.agents import providers, queue, roles
from estimator.bids import service as bids
from estimator.context import RequestContext, personal_context
from estimator.director import engine, watch
from estimator.errors import InvalidInput, PermissionDenied
from estimator.estimating import quick, service
from estimator.mcp_tools import est_tools as t
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}
REVIEWER = RequestContext(user_id="rita", role="reviewer")


class FakeProvider:
    """Answers like Claude or Grok would. replies[provider] is a list of texts (or exceptions) used in order."""

    def __init__(self):
        self.keys = {"claude_api": True, "grok_api": True}
        self.replies = {"claude_api": [], "grok_api": []}
        self.calls = []

    def ready(self, provider):
        return (True, "") if self.keys.get(provider) else (False, "no API key saved")

    def model_for(self, provider):
        return {"claude_api": "claude-sonnet-5-5", "grok_api": "grok-4.3"}[provider]

    def ask(self, provider, system, user, model=""):
        self.calls.append({"provider": provider, "system": system, "user": json.loads(user), "model": model})
        r = self.replies[provider].pop(0) if self.replies[provider] else '{"actions": [{"action": "no_action"}]}'
        if isinstance(r, Exception):
            raise r
        return r, {"input": 2000, "output": 500}

    def cost(self, model, usage):           # $2 / $10 per 1M tokens, like Sonnet
        return round((usage["input"] * 2 + usage["output"] * 10) / 1_000_000, 5)


@pytest.fixture
def fake():
    f = FakeProvider()
    providers.set_provider(f)
    yield f
    providers.set_provider(None)


def at(days=0, hour=10):
    d = date.today() + timedelta(days=days)
    return datetime(d.year, d.month, d.day, hour).astimezone()


def _on(db, role, provider="claude_api", **extra):
    return roles.update_role(db, CTX, role, {"provider": provider, **extra}, confirm=True)


def _review_job(db):
    return engine.start(db, CTX, "replace the roof", answers=ROOF, registry=REG)      # $7,817.10 waits for review


def say(*actions, summary="ok"):
    return json.dumps({"actions": list(actions), "summary": summary})


# ---------------------------------------------------------------- roles, keys and budgets

def test_roles_start_off(db):  # S15-R01
    ov = roles.overview(db, "default")
    assert {r["role"] for r in ov["roles"]} == {"reviewer", "bid_writer", "follow_up", "plan_reader", "takeoff",
                                                 "llm_takeoff"}
    assert all(r["provider"] == "off" for r in ov["roles"])
    assert ov["budget"] == {"daily_cents": 200, "monthly_cents": 2000} and ov["spent"]["today"]["calls"] == 0
    assert "Small Business" in ov["where_keys_go"]
    _review_job(db)
    assert queue.run(db, CTX)["queued"] == []                        # nothing runs while roles are off


def test_role_settings(db, fake):  # S15-R02
    out = roles.update_role(db, CTX, "reviewer", {"provider": "claude_api", "fallback_provider": "grok_api"})
    assert out["confirmed"] is False and roles.get_role(db, "default", "reviewer")["provider"] == "off"
    out = _on(db, "reviewer", fallback_provider="grok_api", model="claude-haiku-5-5")
    assert out["role"]["ready"] and out["role"]["model"] == "claude-haiku-5-5" and out["role"]["fallback_ready"]
    with pytest.raises(InvalidInput, match="different"):
        _on(db, "reviewer", fallback_provider="claude_api")
    with pytest.raises(InvalidInput):
        _on(db, "reviewer", provider="claude_code")
    with pytest.raises(InvalidInput):
        _on(db, "reviewer", model="rm -rf /")
    with pytest.raises(PermissionDenied):
        roles.update_role(db, REVIEWER, "reviewer", {"provider": "off"}, confirm=True)
    fake.keys["grok_api"] = False
    out = _on(db, "bid_writer", provider="grok_api")
    assert "isn't ready" in out["warnings"][0]
    assert "Plan Engine" in _on(db, "takeoff")["warnings"][-1]
    assert _on(db, "reviewer", provider="chat_only")["role"]["fallback_provider"] is None


def test_budget_settings(db):  # S15-R03
    assert roles.update_budget(db, CTX, {"monthly_cents": 5000})["confirmed"] is False
    assert roles.update_budget(db, CTX, {"monthly_cents": 5000, "daily_cents": 500}, confirm=True)["budget"] == \
        {"daily_cents": 500, "monthly_cents": 5000}
    for bad in ({"daily_cents": 6000}, {"daily_cents": -1}, {"weekly_cents": 1}, {"daily_cents": 1.5}):
        with pytest.raises(InvalidInput):
            roles.update_budget(db, CTX, bad, confirm=True)
    with pytest.raises(PermissionDenied):
        roles.update_budget(db, REVIEWER, {"daily_cents": 1}, confirm=True)


def test_no_host_providers_means_not_ready(db, monkeypatch):  # S15-R04
    providers.set_provider(None)
    monkeypatch.setattr(providers, "_host", lambda: None)
    ok, why = providers.ready("claude_api")
    assert not ok and "inside AI-Prowler" in why
    with pytest.raises(providers.ProviderError):
        providers.ask("claude_api", "s", "u")


# ---------------------------------------------------------------- the reviewer agent

def test_reviewer_runs_on_the_api_key(db, fake):  # S15-A01
    _on(db, "reviewer")
    r = _review_job(db)
    fake.replies["claude_api"] = [say({"action": "review_note", "body": "Check the pitch on sheet A3."},
                                      {"action": "flag", "message": "Sample prices still in use", "severity": "warning"})]
    out = queue.run(db, CTX)
    assert len(out["queued"]) == 1 and out["ran"][0]["state"] == "done" and out["ran"][0]["provider"] == "claude_api"
    call = fake.calls[0]
    assert "Reviewer" in call["system"] and "Never invent" in call["system"] and "review_note" in call["system"]
    assert call["user"]["estimate"]["total"] == "$7,817.10" and call["user"]["request"] == "replace the roof"
    msgs = [n["message"] for n in watch.inbox(db, CTX)["notices"]]
    assert any("sheet A3" in m for m in msgs) and any("flagged" in m for m in msgs)
    assert queue.run(db, CTX)["queued"] == []                        # once per estimate version
    s = roles.spent(db, "default")
    assert s["today"]["calls"] == 1 and s["today"]["micros"] == 9000       # 2,000 x $2 + 500 x $10 per 1M
    ev = [e for e in service.events(db, CTX, r["estimate"]["id"]) if e["action"] == "agent_task_done"]
    assert ev and json.loads(ev[0]["after_json"])["provider"] == "claude_api"


def test_backup_provider(db, fake):  # S15-A02
    _on(db, "reviewer", fallback_provider="grok_api")
    _review_job(db)
    fake.replies["claude_api"] = [providers.ProviderError("HTTP 529: overloaded")]
    fake.replies["grok_api"] = [say({"action": "review_note", "body": "Looks complete."})]
    out = queue.run(db, CTX)
    assert out["ran"][0]["provider"] == "grok_api" and out["ran"][0]["state"] == "done"
    assert any(n["kind"] == "agent_fallback" and "overloaded" in n["message"] for n in watch.inbox(db, CTX)["notices"])
    usage = db.execute("SELECT provider, ok FROM agent_usage ORDER BY id").fetchall()
    assert [(u["provider"], u["ok"]) for u in usage] == [("claude_api", 0), ("grok_api", 1)]


def test_gives_up_after_three_tries(db, fake):  # S15-A03
    _on(db, "reviewer")
    _review_job(db)
    fake.replies["claude_api"] = ["I think it's fine!", '{"actions": [{"action": "approve"}]}',
                                  providers.ProviderError("HTTP 401: bad key")]
    states = [queue.run(db, CTX)["ran"][0]["state"] for _ in range(3)]
    assert states == ["queued", "queued", "failed"]
    task = queue.list_tasks(db, CTX)["tasks"][0]
    assert "bad key" in task["error"] and task["attempts"] == 3
    assert any(n["kind"] == "agent_failed" for n in watch.inbox(db, CTX)["notices"])


def test_budget_pauses_and_resumes(db, fake):  # S15-A04
    _on(db, "reviewer")
    roles.update_budget(db, CTX, {"daily_cents": 1, "monthly_cents": 2000}, confirm=True)     # 1 cent a day
    _review_job(db)
    _review_job(db)
    _review_job(db)
    out = queue.run(db, CTX)                     # first call costs 0.9 cents, second 1.8 -> over the 1-cent day
    assert len(out["ran"]) == 2 and "today's AI budget" in out["paused"]
    assert queue.list_tasks(db, CTX, state="paused")["tasks"]
    assert any(n["kind"] == "agent_budget" for n in watch.inbox(db, CTX)["notices"])
    roles.update_budget(db, CTX, {"daily_cents": 100}, confirm=True)
    out = queue.run(db, CTX)
    assert out["paused"] is None and len(out["ran"]) == 1 and not queue.list_tasks(db, CTX, state="paused")["tasks"]


def test_agents_never_invent_numbers(db, fake):  # S15-A05
    _on(db, "reviewer")
    _review_job(db)
    fake.replies["claude_api"] = [say({"action": "review_note", "body": "Should be $9,999 not $7,817.10."})]
    out = queue.run(db, CTX)
    assert out["ran"][0]["state"] == "queued" and "$9,999" in out["ran"][0]["error"]
    fake.replies["claude_api"] = [say({"action": "review_note", "body": "Total $7,817.10 is in range."})]
    assert queue.run(db, CTX)["ran"][0]["state"] == "done"


def test_watcher_runs_the_agents(db, fake):  # S15-A06
    _on(db, "reviewer")
    _review_job(db)
    fake.replies["claude_api"] = [say({"action": "review_note", "body": "Fine."})]
    out = watch.tick(db, CTX, at(0, 6))
    assert out["agents"] == {"queued": 1, "ran": 1, "paused": None}


def test_watcher_survives_agent_trouble(db, fake, monkeypatch):  # S15-A07
    monkeypatch.setattr(queue, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    out = watch.tick(db, CTX, at(0, 6))
    assert out["ok"] and "boom" in out["agents"]["error"]


# ---------------------------------------------------------------- chat_only

def test_chat_only_waits_for_an_ai_in_chat(db, fake):  # S15-C01
    _on(db, "reviewer", provider="chat_only")
    r = _review_job(db)
    out = queue.run(db, CTX)
    assert len(out["queued"]) == 1 and out["ran"] == [] and fake.calls == []
    nxt = queue.next_task(db, CTX)
    assert nxt["task"]["state"] == "waiting_for_ai" and "Reviewer" in nxt["prompt"]
    assert nxt["context"]["estimate"]["estimate_id"] == r["estimate"]["id"] and "review_note" in nxt["allowed_actions"]
    with pytest.raises(InvalidInput, match="can only use"):
        queue.submit(db, CTX, nxt["task"]["task_id"], [{"action": "approve"}])
    out = queue.submit(db, REVIEWER, nxt["task"]["task_id"], [{"action": "review_note", "body": "Add drip edge?"}])
    assert out["state"] == "done" and queue.next_task(db, CTX)["task"] is None
    with pytest.raises(InvalidInput):
        queue.submit(db, CTX, nxt["task"]["task_id"], [{"action": "no_action"}])


# ---------------------------------------------------------------- bid writer and follow-up

def _approved_job(db):
    r = _review_job(db)
    return engine.next_step(db, CTX, r["job"]["id"], reviewed=True, registry=REG)       # now at approve


def test_bid_writer_draft_goes_on_the_bid(db, fake):  # S15-B01
    _on(db, "bid_writer")
    r = _approved_job(db)
    assert r["job"]["stage"] == "approve"
    fake.replies["claude_api"] = [say({"action": "draft_bid", "scope_text": "Tear off and re-roof 20 squares with "
                                       "architectural shingles.", "inclusions": "Cleanup and haul-off",
                                       "exclusions": "Rotten decking"})]
    assert queue.run(db, CTX)["ran"][0]["state"] == "done"
    r = engine.next_step(db, CTX, r["job"]["id"], approve=True, confirm_sample_prices=True, registry=REG)
    bid = bids.latest_for_estimate(db, CTX, r["estimate"]["id"])
    assert bid["scope_text"].startswith("Tear off") and bid["exclusions"] == "Rotten decking"
    assert any("Bid Writer" in n for n in r["notes"])
    assert queue.latest_draft(db, CTX, r["estimate"]["id"]) is None            # used once


def test_bid_writer_draft_applied_later(db, fake):  # S15-B02
    r = _approved_job(db)
    r = engine.next_step(db, CTX, r["job"]["id"], approve=True, confirm_sample_prices=True, registry=REG)
    first = bids.latest_for_estimate(db, CTX, r["estimate"]["id"])
    _on(db, "bid_writer")
    fake.replies["claude_api"] = [say({"action": "draft_bid", "scope_text": "Re-roof the house."})]
    tid = queue.run(db, CTX)["ran"][0]["task_id"]
    out = queue.apply_draft(db, CTX, tid)
    assert out["bid"]["version"] == first["version"] + 1
    assert bids.preview(db, CTX, first["id"])["status"] == "void"
    with pytest.raises(InvalidInput, match="already used"):
        queue.apply_draft(db, CTX, tid)


def test_follow_up_draft_and_send(db, fake, fake_host):  # S15-F01
    e = service.create_estimate(db, CTX, "Smith clean")
    e = quick.answer(db, CTX, e["id"], "house_cleaning", {"bedrooms": 3, "bathrooms": 2, "sqft": 1800}, e["rev"], REG)
    e = service.set_status(db, CTX, e["id"], e["rev"], "approved")
    b = bids.generate(db, CTX, e["id"], customer={"name": "Ann Smith", "email": "ann@example.com"}, registry=REG)
    b = bids.send(db, CTX, b["id"], confirm=True)
    _on(db, "follow_up")
    assert queue.run(db, CTX, at(1))["queued"] == []                           # not due yet
    fake.replies["claude_api"] = [say({"action": "draft_message", "subject": f"Your quote {b['number']}",
                                       "body": f"Hi Ann, just checking in on quote {b['number']} ({b['total']})."})]
    out = queue.run(db, CTX, at(6))
    assert out["ran"][0]["state"] == "done"
    pack = fake.calls[0]["user"]
    assert pack["customer_first_name"] == "Ann" and pack["quote"]["number"] == b["number"]
    tid = out["ran"][0]["task_id"]
    preview = queue.apply_draft(db, CTX, tid)
    assert preview["confirmed"] is False and preview["would_send"]["to"] == "ann@example.com"
    assert queue.apply_draft(db, CTX, tid, confirm=True)["sent_to"] == "ann@example.com"
    assert fake_host.named("send_email")[-1]["subject"] == f"Your quote {b['number']}"
    with pytest.raises(PermissionDenied):
        queue.apply_draft(db, REVIEWER, tid, confirm=True)


# ---------------------------------------------------------------- prompts and tools

def test_role_prompts(db):  # S15-P01
    for role in ("director", "intake", "quick_pricer", "plan_reader", "takeoff", "estimate_runner", "pricer",
                 "reviewer", "bid_writer", "follow_up"):
        text = queue.prompt(role)
        assert "Never invent" in text and len(text) > 200
    assert "draft_bid" in queue.headless_rules("bid_writer") and "approve" not in queue.headless_rules("reviewer")


def j(s):
    return json.loads(s)


def test_agent_tools(db, fake):  # S15-T01
    out = j(t.how_to_estimate())
    assert "est_director_start" in out["instructions"] and "reviewer" in out["roles"]
    assert "Takeoff" in j(t.how_to_estimate("takeoff"))["instructions"]
    assert j(t.how_to_estimate("nope"))["error"] == "not_found"
    assert len(j(t.agent_roles_get())["roles"]) == 6
    assert j(t.agent_roles_update("reviewer", '{"provider": "chat_only"}', confirm=True))["role"]["provider"] == \
        "chat_only"
    assert j(t.agent_budget_update({"monthly_cents": 3000}, confirm=True))["budget"]["monthly_cents"] == 3000
    t.est_director_start("replace the roof", answers=json.dumps(ROOF))
    assert len(j(t.est_agent_run_now())["queued"]) == 1
    task = j(t.est_agent_next())["task"]
    out = j(t.est_agent_submit(task["task_id"], '[{"action": "review_note", "body": "Looks right."}]'))
    assert out["state"] == "done" and j(t.est_agent_tasks("done"))["counts"]["done"] == 1
    assert j(t.est_agent_apply(task["task_id"]))["error"] == "invalid_input"     # review notes aren't drafts
