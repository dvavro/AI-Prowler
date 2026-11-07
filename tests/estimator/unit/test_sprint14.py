"""Sprint 14 (re-ordered from planned Sprint 9, Coder 1): Estimate Runner, Agent Manager, Director full takeoff
lane (S14-..)."""
import json

import pytest

from estimator import agent_manager
from estimator.context import RequestContext, personal_context
from estimator.director import engine
from estimator.errors import InvalidInput, NotFound, PermissionDenied
from estimator.estimating import service
from estimator.mcp_tools import est_tools as t
from estimator.modules.registry import ModuleRegistry
from estimator.runner import runner

CTX = personal_context()
REG = ModuleRegistry().load()
REVIEWER = RequestContext(user_id="rita", role="reviewer")
OFFICE = RequestContext(user_id="olga", role="office")
ROOF = {"roof_area_sqft": 2000, "pitch": "5/12", "material": "architectural"}
FRAME = {"wall_lf": 100}
DRY = {"wall_lf": 100, "ceiling_sqft": 400}
PAINT = {"wall_sqft": 1200}


def _est(db):
    return service.create_estimate(db, CTX, "Miller house")


def _start(db, trades, ctx=CTX, reg=REG):
    return runner.start_run(db, ctx, _est(db)["id"], trades, registry=reg)


def _task(out, module):
    return next(x for x in out["tasks"] if x["module_id"] == module)


def _do(db, out, module, answers, ctx=CTX):
    tid = _task(out, module)["task_id"]
    runner.submit_takeoff(db, ctx, tid, answers, registry=REG)
    return runner.review_task(db, ctx, tid, approve=True, registry=REG)


# ---------------------------------------------------------------- runner

def test_tasks_and_dependencies(db):  # S14-R01
    out = _start(db, ["framing", "drywall", "painting", "roofing"])
    states = {x["module_id"]: x["state"] for x in out["tasks"]}
    assert states == {"framing": "running", "drywall": "queued", "painting": "queued", "roofing": "running"}
    assert _task(out, "drywall")["depends_on"] == ["framing"] and out["run"]["state"] == "running"
    assert "waits for framing" in _task(out, "painting")["next"]


def test_framing_approved_unblocks_drywall_and_prices(db):  # S14-R02
    out = _start(db, ["framing", "drywall"])
    tid = _task(out, "framing")["task_id"]
    out = runner.submit_takeoff(db, CTX, tid, FRAME, confidence=90, registry=REG)
    assert out["task"]["state"] == "needs_review" and out["estimate_total_cents"] == 0   # nothing priced yet
    out = runner.review_task(db, CTX, tid, approve=True, registry=REG)
    assert out["task"]["state"] == "completed" and _task(out, "drywall")["state"] == "running"
    assert out["estimate_total_cents"] == 159624                                          # same as S10-D01
    est = service.get_estimate(db, CTX, out["run"]["estimate_id"])
    assert [s["module_id"] for s in est["sections"]] == ["framing"]


def test_one_failed_trade_never_stops_the_others(db):  # S14-R03
    out = _start(db, ["framing", "drywall", "roofing"])
    out = runner.submit_takeoff(db, CTX, _task(out, "framing")["task_id"], cannot_measure="no framing plan in the set",
                                registry=REG)
    assert _task(out, "framing")["state"] == "failed" and _task(out, "drywall")["state"] == "blocked"
    assert "framing" in _task(out, "drywall")["error"] and _task(out, "roofing")["state"] == "running"
    out = _do(db, out, "roofing", ROOF)
    assert out["run"]["state"] == "partial" and out["estimate_total_cents"] == 781710
    out = runner.retry_task(db, CTX, _task(out, "framing")["task_id"], registry=REG)
    assert _task(out, "framing")["state"] == "running" and _task(out, "drywall")["state"] == "queued"
    assert out["run"]["state"] == "running"
    out = _do(db, out, "framing", FRAME)
    out = _do(db, out, "drywall", DRY)
    est = service.get_estimate(db, CTX, out["run"]["estimate_id"])
    assert out["run"]["state"] == "completed" and out["run"]["progress"] == 100
    assert est["totals"]["total_cents"] == sum(s["subtotal_cents"] for s in est["sections"])
    assert {s["module_id"] for s in est["sections"]} == {"framing", "drywall", "roofing"}


def test_all_failed_run(db):  # S14-R04
    out = _start(db, ["roofing"])
    out = runner.submit_takeoff(db, CTX, _task(out, "roofing")["task_id"], cannot_measure="roof plan missing",
                                registry=REG)
    assert out["run"]["state"] == "failed" and "Retry" in _task(out, "roofing")["next"]


def test_submission_checks(db):  # S14-R05
    out = _start(db, ["framing", "drywall", "roofing"])
    f, d, r = (_task(out, m)["task_id"] for m in ("framing", "drywall", "roofing"))
    with pytest.raises(InvalidInput, match="unknown questions"):
        runner.submit_takeoff(db, CTX, f, {"wall_lf": 100, "colour": "red"}, registry=REG)
    with pytest.raises(InvalidInput, match="nothing to price"):
        runner.submit_takeoff(db, CTX, f, {"wall_lf": 0}, registry=REG)
    with pytest.raises(InvalidInput, match="please answer"):
        runner.submit_takeoff(db, CTX, r, {"roof_area_sqft": 2000}, registry=REG)
    with pytest.raises(InvalidInput, match="waiting for framing"):
        runner.submit_takeoff(db, CTX, d, DRY, registry=REG)
    with pytest.raises(InvalidInput, match="confidence"):
        runner.submit_takeoff(db, CTX, f, FRAME, confidence=150, registry=REG)
    with pytest.raises(InvalidInput, match="not waiting for review"):
        runner.review_task(db, CTX, f, approve=True, registry=REG)
    assert _task(runner.run_status(db, CTX, run_id=out["run"]["id"]), "framing")["state"] == "running"


def test_send_back_and_correct(db):  # S14-R06
    out = _start(db, ["framing"])
    tid = _task(out, "framing")["task_id"]
    runner.submit_takeoff(db, CTX, tid, {"wall_lf": 1000}, registry=REG)
    with pytest.raises(InvalidInput, match="note"):
        runner.review_task(db, CTX, tid, approve=False, registry=REG)
    out = runner.review_task(db, CTX, tid, note="1,000 ft is too much; check sheet A2", registry=REG)
    assert out["task"]["state"] == "running" and "sheet A2" in out["task"]["next"]
    runner.submit_takeoff(db, CTX, tid, {"wall_lf": 1000}, registry=REG)
    out = runner.review_task(db, REVIEWER, tid, approve=True, answers={"wall_lf": 100}, registry=REG)
    assert out["task"]["answers"]["wall_lf"] == 100 and out["estimate_total_cents"] == 159624
    assert out["task"]["reviewed_by"] == "rita"


def test_roles_and_scoping(db):  # S14-R07
    with pytest.raises(PermissionDenied):
        _start(db, ["framing"], ctx=REVIEWER)
    out = _start(db, ["framing"])
    tid = _task(out, "framing")["task_id"]
    with pytest.raises(PermissionDenied):
        runner.submit_takeoff(db, REVIEWER, tid, FRAME, registry=REG)
    runner.submit_takeoff(db, CTX, tid, FRAME, registry=REG)
    with pytest.raises(PermissionDenied):
        runner.review_task(db, OFFICE, tid, approve=True, registry=REG)
    other = RequestContext(company_id="acme", user_id="z")
    with pytest.raises(NotFound):
        runner.run_status(db, other, run_id=out["run"]["id"])
    with pytest.raises(NotFound):
        runner.review_task(db, other, tid, approve=True, registry=REG)


def test_one_open_run_and_adding_trades(db):  # S14-R08
    out = _start(db, ["roofing"])
    with pytest.raises(InvalidInput, match="already has run"):
        runner.start_run(db, CTX, out["run"]["estimate_id"], ["framing"], registry=REG)
    out = _do(db, out, "roofing", ROOF)
    assert out["run"]["state"] == "completed"
    out = runner.add_trades(db, CTX, out["run"]["id"], ["roofing", "painting"], registry=REG)
    assert out["added"] == ["painting"] and out["run"]["state"] == "running"
    assert _task(out, "painting")["state"] == "running"          # no framing in this run, so nothing to wait for
    with pytest.raises(InvalidInput, match="isn't a construction trade"):
        runner.add_trades(db, CTX, out["run"]["id"], ["house_cleaning"], registry=REG)


def test_finalized_estimate_cant_take_a_run(db):  # S14-R09
    e = _est(db)
    service.set_status(db, CTX, e["id"], e["rev"], "approved")
    with pytest.raises(Exception, match="revision"):
        runner.start_run(db, CTX, e["id"], ["roofing"], registry=REG)


def test_project_status(db):  # S14-P01
    out = _start(db, ["framing", "drywall", "roofing"])
    out = _do(db, out, "roofing", ROOF)
    ps = runner.project_status(db, CTX, out["run"]["estimate_id"], registry=REG)
    assert ps["estimate"]["total_cents"] == 781710 and ps["trades"][0]["module_id"] == "roofing"
    assert len(ps["trades"][0]["headline"]) == 3 and ps["run"]["counts"]["completed"] == 1
    assert "framing running" in ps["summary"]


def test_audit_trail(db):  # S14-P02
    out = _start(db, ["roofing"])
    out = _do(db, out, "roofing", ROOF)
    acts = [(e["action"], e["actor"]) for e in service.events(db, CTX, out["run"]["estimate_id"])]
    assert ("runner_started", "owner") in acts and ("takeoff_submitted", "owner") in acts
    assert ("takeoff_approved", "owner") in acts
    assert any(a == "agent:estimate_runner" for _, a in acts)       # pricing is done by the Runner itself


# ---------------------------------------------------------------- agent manager

def test_agent_config_defaults_and_confirm(db):  # S14-A01
    cfgs = agent_manager.list_configs(db, "default", REG)
    assert len(cfgs["agents"]) == 15 and cfgs["turned_off"] == []
    roof = agent_manager.get_config(db, "default", "roofing", REG)
    assert roof["enabled"] and roof["confidence_threshold"] == 85 and not roof["auto_advance"]
    assert "roof plan" in roof["sheet_rules"]["titles"]
    out = agent_manager.update_config(db, CTX, "roofing", {"enabled": False}, registry=REG)
    assert out["confirmed"] is False and out["would_change"] == {"enabled": False}
    assert agent_manager.get_config(db, "default", "roofing", REG)["enabled"]
    agent_manager.update_config(db, CTX, "roofing", {"enabled": False}, confirm=True, registry=REG)
    assert agent_manager.list_configs(db, "default", REG)["turned_off"] == ["roofing"]
    with pytest.raises(PermissionDenied):
        agent_manager.update_config(db, REVIEWER, "framing", {"enabled": False}, confirm=True, registry=REG)
    for bad in ({"confidence_threshold": 120}, {"sheet_rules": {"pages": []}}, {"defaults": {"height": "9"}},
                {"defaults": {"colour": 1}}, {"speed": 1}):
        with pytest.raises(InvalidInput):
            agent_manager.update_config(db, CTX, "fencing", bad, confirm=True, registry=REG)
    with pytest.raises(NotFound):
        agent_manager.get_config(db, "default", "house_cleaning", REG)


def test_turned_off_trades_are_skipped(db):  # S14-A02
    agent_manager.update_config(db, CTX, "roofing", {"enabled": False}, confirm=True, registry=REG)
    out = _start(db, ["roofing", "framing"])
    assert [x["module_id"] for x in out["tasks"]] == ["framing"] and "roofing" in out["warnings"][0]
    with pytest.raises(InvalidInput, match="turned off"):
        _start(db, ["roofing"])


def test_company_defaults_fill_in(db):  # S14-A03
    agent_manager.update_config(db, CTX, "fencing", {"defaults": {"height": "8", "material": "vinyl"}}, confirm=True,
                                registry=REG)
    out = _start(db, ["fencing"])
    out = runner.submit_takeoff(db, CTX, _task(out, "fencing")["task_id"], {"length_lf": 100}, registry=REG)
    assert out["task"]["proposed"] == {"height": "8", "material": "vinyl", "length_lf": 100}


def test_auto_advance(db):  # S14-A04
    agent_manager.update_config(db, CTX, "roofing", {"auto_advance": True, "confidence_threshold": 90}, confirm=True,
                                registry=REG)
    out = _start(db, ["roofing"])
    tid = _task(out, "roofing")["task_id"]
    assert runner.submit_takeoff(db, CTX, tid, ROOF, confidence=80, registry=REG)["task"]["state"] == "needs_review"
    assert runner.submit_takeoff(db, CTX, tid, ROOF, registry=REG)["task"]["state"] == "needs_review"
    out = runner.submit_takeoff(db, CTX, tid, ROOF, confidence=95, registry=REG)
    assert out["auto_approved"] and out["task"]["state"] == "completed" and "auto-advance" in out["task"]["reviewed_by"]


# ---------------------------------------------------------------- Director full takeoff lane

def test_director_plan_job_end_to_end(db):  # S14-D01
    r = engine.start(db, CTX, "bid the Miller plans: framing, drywall and a new roof", has_plans=True, registry=REG)
    assert r["job"]["lane"] == "full_takeoff" and r["job"]["stage"] == "takeoff"
    assert r["job"]["waiting_on"] == "takeoff" and "Plan Engine" in " ".join(r["notes"])
    tasks = {x["module_id"]: x["task_id"] for x in r["next_step"]["tasks"]}
    assert set(tasks) == {"framing", "roofing", "drywall"} and "drywall" in r["next_step"]["say"]
    for m, ans in (("framing", FRAME), ("roofing", ROOF)):
        runner.submit_takeoff(db, CTX, tasks[m], ans, registry=REG)
    r = engine.next_step(db, CTX, r["job"]["id"], registry=REG)
    assert r["job"]["stage"] == "takeoff" and "Check and approve" in r["next_step"]["say"]
    assert r["job"]["waiting_on"] == "reviewer"
    for m in ("framing", "roofing"):
        runner.review_task(db, CTX, tasks[m], approve=True, registry=REG)
    out = runner.submit_takeoff(db, CTX, tasks["drywall"], DRY, registry=REG)
    out = runner.review_task(db, CTX, tasks["drywall"], approve=True, registry=REG)
    assert "est_director_next(job_id=" in out["warnings"][-1]
    r = engine.next_step(db, CTX, r["job"]["id"], registry=REG)
    est = service.get_estimate(db, CTX, r["estimate"]["id"])
    assert r["job"]["stage"] == "review" and r["job"]["waiting_on"] == "reviewer"
    assert r["estimate"]["total_cents"] == sum(s["subtotal_cents"] for s in est["sections"]) > 0
    assert r["job"]["module_id"] == "framing" and set(r["job"]["trades"]) == {"roofing", "drywall"}
    r = engine.next_step(db, CTX, r["job"]["id"], reviewed=True, approve=True, confirm_sample_prices=True, registry=REG)
    assert service.get_estimate(db, CTX, r["estimate"]["id"])["status"] == "approved"
    assert r["job"]["stage"] == "write_bid"


def test_director_asks_for_trades(db):  # S14-D02
    r = engine.start(db, CTX, "bid this house", has_plans=True, registry=REG)
    assert r["job"]["open_questions"] == ["trades"] and "roofing" in r["next_step"]["ask"]
    with pytest.raises(InvalidInput, match="not construction trades"):
        engine.next_step(db, CTX, r["job"]["id"], trades=["pool_service"], registry=REG)
    r = engine.next_step(db, CTX, r["job"]["id"], trades="concrete, roofing", registry=REG)
    assert r["job"]["stage"] == "takeoff" and [x["module_id"] for x in r["next_step"]["tasks"]] == ["concrete", "roofing"]
    q = engine.start(db, CTX, "pressure wash my driveway", registry=REG)
    with pytest.raises(InvalidInput, match="plan takeoff"):
        engine.next_step(db, CTX, q["job"]["id"], trades=["roofing"], registry=REG)


def test_director_leaves_out_failed_trades(db):  # S14-D03
    r = engine.start(db, CTX, "bid the plans: framing and roofing", has_plans=True, registry=REG)
    tasks = {x["module_id"]: x["task_id"] for x in r["next_step"]["tasks"]}
    runner.submit_takeoff(db, CTX, tasks["framing"], cannot_measure="structural sheets missing", registry=REG)
    runner.submit_takeoff(db, CTX, tasks["roofing"], ROOF, registry=REG)
    runner.review_task(db, CTX, tasks["roofing"], approve=True, registry=REG)
    r = engine.next_step(db, CTX, r["job"]["id"], registry=REG)
    assert r["job"]["module_id"] == "roofing" and r["job"]["trades"] == {}
    assert "couldn't be measured): framing" in " ".join(r["notes"]) and r["estimate"]["total_cents"] == 781710


def test_director_all_trades_failed(db):  # S14-D04
    r = engine.start(db, CTX, "bid the roofing plans", has_plans=True, registry=REG)
    tid = r["next_step"]["tasks"][0]["task_id"]
    runner.submit_takeoff(db, CTX, tid, cannot_measure="roof plan unreadable", registry=REG)
    r = engine.next_step(db, CTX, r["job"]["id"], registry=REG)
    assert r["next_step"]["error"] == "takeoff_failed" and "unreadable" in r["next_step"]["say"]


def test_director_add_trade_to_plan_job(db):  # S14-D05
    r = engine.start(db, CTX, "bid the roofing plans", has_plans=True, registry=REG)
    r = engine.add_trade(db, CTX, r["job"]["id"], "siding", registry=REG)
    assert [x["module_id"] for x in r["next_step"]["tasks"]] == ["roofing", "siding"]
    assert runner.latest_run(db, CTX, job_id=r["job"]["id"])["id"] == r["next_step"]["run_id"]


def test_turned_off_trade_left_out_of_plan_job(db):  # S14-D06
    agent_manager.update_config(db, CTX, "drywall", {"enabled": False}, confirm=True, registry=REG)
    r = engine.start(db, CTX, "bid the plans: framing and drywall", has_plans=True, registry=REG)
    assert [x["module_id"] for x in r["next_step"]["tasks"]] == ["framing"]
    assert "turned off" in " ".join(r["notes"])


# ---------------------------------------------------------------- MCP tools

def j(s):
    return json.loads(s)


def test_runner_tools(db):  # S14-T01
    e = j(t.est_create_estimate("Tool run"))
    out = j(t.runner_start(e["id"], "framing, drywall"))
    assert out["ok"] and len(out["tasks"]) == 2
    fid = _task(out, "framing")["task_id"]
    assert j(t.runner_submit_takeoff(fid, '{"wall_lf": 100}', confidence=88))["task"]["state"] == "needs_review"
    assert j(t.runner_review_task(fid, approve=True))["task"]["state"] == "completed"
    assert j(t.runner_status(estimate_id=e["id"]))["counts"]["running"] == 1
    assert j(t.est_project_status(e["id"]))["estimate"]["total_cents"] == 159624
    assert j(t.runner_retry_task(fid))["error"] == "invalid_input"
    assert j(t.runner_start(e["id"], "[\"nope\"]"))["error"] == "invalid_input"


def test_agent_config_tools(db):  # S14-T02
    assert len(j(t.agent_config_get())["agents"]) == 15
    assert j(t.agent_config_get("fencing"))["agent"]["sheet_rules"]["prefixes"] == ["C", "L", "A"]
    assert j(t.agent_config_update("fencing", {"auto_advance": True}))["confirmed"] is False
    assert j(t.agent_config_update("fencing", '{"auto_advance": true}', confirm=True))["config"]["auto_advance"]
    out = j(t.est_director_start("bid this house", has_plans=True))
    out = j(t.est_director_next(out["job"]["id"], trades='["fencing"]'))
    assert out["job"]["stage"] == "takeoff"


def test_briefing_and_watcher_see_takeoffs(db):  # S14-W01
    from datetime import date, datetime, timedelta
    from estimator.director import briefing, watch
    r = engine.start(db, CTX, "bid the roofing plans", has_plans=True, registry=REG)
    assert "plan takeoff(s) in progress" in briefing.briefing(db, CTX)["text"]
    d = date.today() + timedelta(days=2)
    out = watch.tick(db, CTX, datetime(d.year, d.month, d.day, 6).astimezone())
    msgs = [n["message"] for n in out["new_notices"] if n["kind"] == "review_reminder"]
    assert msgs and "trade takeoffs" in msgs[0] and str(r["job"]["id"]) in msgs[0]
