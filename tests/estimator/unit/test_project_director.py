"""Every project gets a Director job (2026-11-12, David): the project lane.

The person builds the estimate on the screens; the Director says what to do next and why, then runs the checks, the
approval, the quote and the follow-up. Also: the Bid Writer takes inclusions sent as a list.
"""
import pytest

from estimator.agents import queue
from estimator.context import personal_context
from estimator.director import engine
from estimator.director.playbooks import playbook_for_lane
from estimator.errors import ConfirmationRequired, InvalidInput
from estimator.estimating import quick, service
from estimator.modules.registry import ModuleRegistry

CTX = personal_context()
REG = ModuleRegistry().load()
SLAB = {"area_sqft": 400}


def _project(db, title="NSB Slab"):
    est = service.create_estimate(db, CTX, title, address="1 Main St")
    return est, engine.adopt(db, CTX, est["id"], registry=REG)


def _price(db, eid):
    est = service.get_estimate(db, CTX, eid)
    return quick.answer(db, CTX, eid, "concrete", SLAB, est["rev"], REG)


def test_project_playbook_guides_then_checks_approves_and_quotes():  # PD-01
    pb = playbook_for_lane("project")
    assert [s.action for s in pb.stages] == ["guide_build", "review", "approve", "write_bid", "follow_up"]


def test_a_new_project_gets_a_director_job_that_says_what_to_do_and_why(db):  # PD-02
    est, r = _project(db)
    job, ns = r["job"], r["next_step"]
    assert job["lane"] == "project" and job["stage"] == "build" and job["estimate_id"] == est["id"]
    assert job["state"] == "waiting_on_user" and job["request_text"] == "NSB Slab"
    assert ns["say"].startswith("Add the plans") and ns["why"]
    assert {t["key"] for t in ns["todo"]} >= {"plans", "price", "customer"}
    assert ns["ready_ok"] is False and ns["needs_customer"] is True
    assert r["estimate"]["total_cents"] == 0


def test_asking_again_reuses_the_job_and_writes_nothing(db):  # PD-03
    est, r = _project(db)
    again = engine.adopt(db, CTX, est["id"], registry=REG)
    assert again["job"]["id"] == r["job"]["id"]
    assert again["job"]["rev"] == r["job"]["rev"]          # an unchanged step doesn't bump the job
    n = db.execute("SELECT COUNT(*) FROM director_jobs WHERE estimate_id = ?", (est["id"],)).fetchone()[0]
    assert n == 1


def test_priced_project_goes_through_ready_review_approve_and_quote(db):  # PD-04
    est, r = _project(db)
    jid = r["job"]["id"]
    _price(db, est["id"])
    r = engine.adopt(db, CTX, est["id"], registry=REG)
    ns = r["next_step"]
    assert ns["ready_ok"] is True and "tell me it's ready" in ns["say"]
    assert next(t for t in ns["todo"] if t["key"] == "price")["done"]
    r = engine.next_step(db, CTX, jid, customer={"name": "Pat Lee", "email": "pat@example.com"}, registry=REG)
    assert not r["next_step"]["needs_customer"]
    r = engine.next_step(db, CTX, jid, ready=True, registry=REG)
    assert r["job"]["stage"] in ("review", "approve")
    # The owner approves (and signs off the review over the limit); the concrete prices here are samples.
    r = engine.next_step(db, CTX, jid, reviewed=True, approve=True, confirm_sample_prices=True, registry=REG)
    if r["job"]["stage"] == "approve":
        r = engine.next_step(db, CTX, jid, approve=True, confirm_sample_prices=True, registry=REG)
    assert r["estimate"]["status"] == "approved" and r["job"]["stage"] == "write_bid"
    assert "pat@example.com" in r["next_step"]["say"] and r["next_step"]["bid_id"]
    with pytest.raises(ConfirmationRequired):            # sending reaches the customer: it asks first
        engine.next_step(db, CTX, jid, send=True, registry=REG)


def test_ready_with_nothing_priced_stays_on_build(db):  # PD-05
    est, r = _project(db)
    r = engine.next_step(db, CTX, r["job"]["id"], ready=True, registry=REG)
    assert r["job"]["stage"] == "build" and "nothing on the estimate is priced" in r["notes"][0]


def test_a_project_is_built_on_the_screens_not_with_answers(db):  # PD-06
    est, r = _project(db)
    with pytest.raises(InvalidInput, match="built on the Estimates screen"):
        engine.next_step(db, CTX, r["job"]["id"], answers=SLAB, registry=REG)


def test_a_revision_keeps_the_same_director_job(db):  # PD-07
    est, r = _project(db)
    _price(db, est["id"])
    cur = service.get_estimate(db, CTX, est["id"])
    service.set_status(db, CTX, est["id"], cur["rev"], "approved", roles=service.APPROVE_ROLES)
    new = service.create_revision(db, CTX, est["id"], "customer wants 5 in")
    r2 = engine.adopt(db, CTX, new["id"], registry=REG)
    assert r2["job"]["id"] == r["job"]["id"] and r2["job"]["estimate_id"] == new["id"]
    assert r2["job"]["stage"] == "build"


def test_practice_and_finished_projects_get_no_new_job(db):  # PD-08
    est = service.create_estimate(db, CTX, "Practice")
    db.execute("UPDATE estimates SET is_practice = 1 WHERE id = ?", (est["id"],))
    assert engine.adopt(db, CTX, est["id"], registry=REG) is None
    est = service.create_estimate(db, CTX, "Old job")
    cur = service.get_estimate(db, CTX, est["id"])
    service.set_status(db, CTX, est["id"], cur["rev"], "archived", roles=service.APPROVE_ROLES)
    assert engine.adopt(db, CTX, est["id"], registry=REG) is None


# ---------------------------------------------------------------- Start a new quote or estimate (Dashboard)

def test_intake_preview_reads_the_job_and_changes_nothing(db):  # PD-11
    n = db.execute("SELECT COUNT(*) FROM estimates").fetchone()[0]
    p = engine.intake(db, CTX, "pour a concrete slab for a shed", preview=True, registry=REG)
    assert p["kind"] == "trade" and p["module_id"] == "concrete" and p["ask_plans"] and "plans" in p["say"]
    p = engine.intake(db, CTX, "pressure wash the driveway", preview=True, registry=REG)
    assert p["kind"] == "service" and p["ask_plans"] is False
    assert db.execute("SELECT COUNT(*) FROM estimates").fetchone()[0] == n
    with pytest.raises(InvalidInput):
        engine.intake(db, CTX, "  ", preview=True, registry=REG)


def test_intake_trade_without_plans_goes_to_the_measurements_form(db):  # PD-12
    r = engine.intake(db, CTX, "pour a concrete slab for a shed", has_plans=False,
                      customer={"name": "Pat Lee", "email": "pat@example.com"}, address="1 Main St", registry=REG)
    eid = r["estimate"]["id"]
    assert r["job"]["lane"] == "project" and r["route"] == f"#/quick/{eid}?module=concrete"
    ns = r["next_step"]
    price = next(t for t in ns["todo"] if t["key"] == "price")
    assert "concrete" in price["text"] and price["link"] == f"#/quick/{eid}?module=concrete"
    assert not ns["needs_customer"]
    est = service.get_estimate(db, CTX, eid)
    assert "Pat Lee" in est["title"] and est["address"] == "1 Main St"


def test_intake_with_plans_goes_to_the_project_page(db):  # PD-13
    r = engine.intake(db, CTX, "bid the framing and drywall from the plans", has_plans=True, registry=REG)
    assert r["job"]["lane"] == "project" and r["route"] == f"#/projects/{r['estimate']['id']}"
    assert r["next_step"]["say"].startswith("Add the plans")


def test_intake_service_is_a_quick_quote(db):  # PD-14
    r = engine.intake(db, CTX, "pressure wash the driveway", has_plans=False, customer={"name": "Sam"}, registry=REG)
    assert r["job"]["lane"] == "quick_quote" and r["route"] == f"#/jobs/{r['job']['id']}"


def test_migration_23_keeps_jobs_and_their_steps():  # PD-10
    import sqlite3
    from estimator.database.migrations import migrate
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")              # a cascade from the old table would delete the steps
    migrate(conn, 22)
    conn.execute("INSERT INTO director_jobs (id, company_id, lane, stage, created_at, updated_at, customer_json)"
                 " VALUES (7, 'default', 'quick_quote', 'approve', 'x', 'x', '{\"name\": \"Pat\"}')")
    conn.execute("INSERT INTO director_steps (job_id, stage, agent_role, state, started_at)"
                 " VALUES (7, 'triage', 'director', 'done', 'x')")
    assert migrate(conn) == [23]
    assert conn.execute("SELECT lane, customer_json FROM director_jobs WHERE id = 7").fetchone() == \
        ("quick_quote", '{"name": "Pat"}')
    assert conn.execute("SELECT COUNT(*) FROM director_steps WHERE job_id = 7").fetchone()[0] == 1
    conn.execute("INSERT INTO director_jobs (company_id, lane, stage, created_at, updated_at)"
                 " VALUES ('default', 'project', 'build', 'x', 'x')")
    conn.execute("DELETE FROM director_jobs WHERE id = 7")  # the steps still follow their job
    assert conn.execute("SELECT COUNT(*) FROM director_steps").fetchone()[0] == 0
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_bid_writer_takes_inclusions_as_a_list():  # PD-09
    out = queue._check_actions("bid_writer", [{"action": "draft_bid", "scope_text": "Pour the slab.",
                                               "inclusions": ["Forms", "- Fill dirt"], "exclusions": ["Permits"]}], {})
    assert out[0]["inclusions"] == "- Forms\n- Fill dirt" and out[0]["exclusions"] == "- Permits"
    with pytest.raises(InvalidInput, match="must be text"):
        queue._check_actions("bid_writer", [{"action": "draft_bid", "scope_text": "x", "inclusions": {"a": 1}}], {})
