"""The agent engine shared by the Service Desk Agent and the Booking & scheduling agent
(desk_agent.py): queue, context packs, the policy, applying, review. Fixed booking clock:
Monday 1 Mar 2027, 06:00.
Run: run_tests.bat tests\\unit\\test_desk_agent_core.py
"""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import booking_db as bdb  # noqa: E402
import booking_flow as bf  # noqa: E402
import desk_agent as ag  # noqa: E402
import desk_db  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_scheduler  # noqa: E402
import desk_tools  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

NOW = dt.datetime(2027, 3, 1, 6, 0)
T7, T9, W9 = "2027-03-02T07:00-09:00", "2027-03-02T09:00-11:00", "2027-03-03T09:00-11:00"
S = r.SOLO


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    for k, v in (("agent_enabled", True), ("agent_shadow", False), ("portal_enabled", True),
                 ("booking_paths", ["book", "new", "problem"])):
        desk_db.set_setting(tickets, k, v, edition=S)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES ('WIN-EXT', 'Exterior windows', 150)")
    conn.close()
    bdb.sync_services(jobs)
    bdb.update_service(jobs, "WIN-EXT", online=True, minutes=105, buffer_min=15)
    p.jobs_db_fn = lambda: jobs
    p.channels_fn = lambda: {"email": True, "sms": True}
    p.send_fn = lambda *a: True
    bf.clock = lambda: NOW
    ag.enable(lambda: tickets)
    yield tickets, jobs
    ag.disable()
    p.jobs_db_fn = p.channels_fn = p.send_fn = None
    bf.clock = None


def setv(env, **kw):
    for k, v in kw.items():
        desk_db.set_setting(env[0], k, v, edition=S)


def customer_ticket(env, title="Streaks on the front windows", priority="P3"):
    tickets = env[0]
    c = desk_db.upsert_contact(tickets, name="Maria Lopez", phone="+13865550142", contact_type="customer")
    return desk_db.create_ticket(tickets, title=title, kind=r.EXTERNAL, actor=None, edition=S,
                                 description="Left side is streaky", contact_id=c["contact_id"], priority=priority)


def queue(env):
    ag.ensure_schema(env[0])
    conn = get_connection(env[0])
    try:
        return [dict(x) for x in conn.execute("SELECT * FROM agent_queue ORDER BY item_id")]
    finally:
        conn.close()


def take(env, **kw):
    out = ag.next_items(env[0], edition=S, jobs_db=env[1], **kw)
    return out["items"][0] if out["items"] else None


def submit(env, item, *actions):
    return ag.submit(env[0], item["item_id"], list(actions), edition=S, jobs_db=env[1])


# ── the queue ────────────────────────────────────────────────────────────────

def test_new_customer_ticket_queues_intake_and_first_reply(env):
    t = customer_ticket(env)
    q = queue(env)
    assert [(x["kind"], x["ref"], x["stage"]) for x in q] == [("ticket", t["ticket_id"], "intake"),
                                                               ("ticket", t["ticket_id"], "first_reply")]
    assert ag.enqueue(env[0], "ticket", t["ticket_id"], "intake") == q[0]["item_id"]       # idempotent


def test_nothing_is_queued_when_the_agent_or_stage_is_off(env):
    setv(env, agent_stage_intake="off")
    customer_ticket(env)
    assert [x["stage"] for x in queue(env)] == ["first_reply"]
    setv(env, agent_enabled=False)
    customer_ticket(env, title="Another")
    assert len(queue(env)) == 1


def test_the_agents_own_changes_queue_nothing(env):
    t = customer_ticket(env)
    n = len(queue(env))
    desk_db.add_message(env[0], t["ticket_id"], "hi", actor=ag.actor(desk_db.get_settings(env[0])), edition=S,
                        visibility="public")
    assert len(queue(env)) == n


def test_private_tickets_never_reach_the_ai(env):
    t = desk_db.create_ticket(env[0], title="HR matter", kind=r.INTERNAL, actor=None, edition=S, visibility="private")
    assert all(x["ref"] != t["ticket_id"] for x in queue(env))


# ── packs and the policy ─────────────────────────────────────────────────────

def test_pack_has_the_ticket_and_the_rules(env):
    t = customer_ticket(env)
    item = take(env)
    assert item["ticket"]["ticket_id"] == t["ticket_id"] and item["stage"] == "intake"
    assert "set_priority" in item["allowed_actions"] and "reply" not in item["allowed_actions"]
    assert "<customer_text>" in item["ticket"]["description"] and item["signature"].startswith("— ")
    assert queue(env)[0]["status"] == "claimed"


def test_suggest_holds_auto_applies(env):
    t = customer_ticket(env)
    item = take(env)                                             # intake, on Suggest
    res = submit(env, item, {"action": "set_type", "type": "Quality", "why": "streaks", "confidence": 0.9})
    assert res["results"][0]["status"] == "pending"
    assert desk_db.get_ticket(env[0], t["ticket_id"])["type"] != "Quality"
    setv(env, agent_stage_first_reply="auto")
    item = take(env)                                             # first reply, on Auto
    res = submit(env, item, {"action": "reply", "body": "Thanks Maria — we'll come back and fix the streaks.",
                             "why": "ack", "confidence": 0.9})
    assert res["results"][0]["status"] == "applied"
    msgs = desk_db.get_ticket_detail(env[0], t["ticket_id"], actor=None, edition=S)["messages"]
    m = [x for x in msgs if x["visibility"] == "public"][-1]
    assert m["author"] == "agent" and "virtual assistant" in m["body"].lower()       # signed as the assistant


def test_safety_rules_hold_even_on_auto(env):
    setv(env, agent_stage_first_reply="auto", agent_stage_intake="auto")
    customer_ticket(env)
    intake = take(env)
    res = submit(env, intake, {"action": "set_priority", "priority": "P4", "why": "minor", "confidence": 0.9})
    assert res["results"][0]["status"] == "pending" and "lowers the priority" in res["results"][0]["why"]
    reply = take(env)
    res = submit(env, reply,
                 {"action": "reply", "body": "It's $95 and I'm a real person.", "why": "x", "confidence": 0.95},
                 {"action": "propose_merge", "primary_id": "T-0001", "why": "dup", "confidence": 0.9},
                 {"action": "set_type", "type": "x", "why": "not allowed here", "confidence": 1})
    why = res["results"][0]["why"]
    assert res["results"][0]["status"] == "pending" and "price" in why and "claims to be a person" in why
    assert res["results"][1]["status"] == "rejected"              # merge isn't a first-reply action
    assert res["results"][2]["status"] == "rejected"


def test_low_confidence_and_p1_wait(env):
    setv(env, agent_stage_intake="auto")
    customer_ticket(env, priority="P1")
    item = take(env)
    res = submit(env, item, {"action": "note", "body": "Looks like hard water", "why": "", "confidence": 0.95})
    assert res["results"][0]["status"] == "pending" and "P1" in res["results"][0]["why"]
    customer_ticket(env, title="Gutter")
    item = [x for x in [take(env), take(env)] if x and x["stage"] == "intake"][0]
    res = submit(env, item, {"action": "note", "body": "hmm", "why": "", "confidence": 0.3})
    assert "confidence" in res["results"][0]["why"]


def test_practice_mode_shows_only(env):
    setv(env, agent_shadow=True, agent_stage_intake="auto")
    t = customer_ticket(env)
    res = submit(env, take(env), {"action": "set_type", "type": "Quality", "why": "x", "confidence": 0.9})
    assert res["results"][0]["status"] == "practice"
    assert desk_db.get_ticket(env[0], t["ticket_id"])["type"] != "Quality"
    [pr] = ag.inbox(env[0], status="practice")
    ag.review(env[0], pr["proposal_id"], "up", actor_=None, edition=S)
    assert ag.inbox(env[0], status="practice")[0]["feedback"] == "up"


def test_a_change_after_reading_requeues(env):
    t = customer_ticket(env)
    item = take(env)
    desk_db.update_ticket(env[0], t["ticket_id"], {"title": "Changed by a person"}, actor=None, edition=S)
    res = submit(env, item, {"action": "note", "body": "x", "why": "x", "confidence": 0.9})
    assert res.get("requeued") and queue(env)[0]["status"] == "waiting"


def test_review_approve_edit_reject(env):
    t = customer_ticket(env)
    submit(env, take(env), {"action": "set_type", "type": "Quality", "why": "x", "confidence": 0.9})
    submit(env, take(env), {"action": "reply", "body": "Thanks!", "why": "ack", "confidence": 0.9})
    pend = ag.inbox(env[0])
    assert len(pend) == 2
    with pytest.raises(desk_db.DeskError, match="owner or a manager"):
        ag.review(env[0], pend[0]["proposal_id"], "approve", actor_={"id": "sam", "role": "staff"}, edition=r.BUSINESS)
    reply = next(x for x in pend if x["action"] == "reply")
    out = ag.review(env[0], reply["proposal_id"], "edit", actor_=None, edition=S, edits={"body": "Thanks, Maria!"})
    assert out["status"] == "applied"
    typ = next(x for x in pend if x["action"] == "set_type")
    ag.review(env[0], typ["proposal_id"], "reject", actor_=None, edition=S)
    assert desk_db.get_ticket(env[0], t["ticket_id"])["type"] != "Quality"
    body = [m["body"] for m in desk_db.get_ticket_detail(env[0], t["ticket_id"], actor=None, edition=S)["messages"]
            if m["visibility"] == "public"][-1]
    assert body.startswith("Thanks, Maria!")


def test_agent_off_stops_approvals_but_not_rejects(env):
    """David 2026-11-03: turning the agent off stops its suggestions being approved; reject still clears them,
    and they can be approved again once it's back on."""
    t = customer_ticket(env)
    submit(env, take(env), {"action": "set_type", "type": "Quality", "why": "x", "confidence": 0.9})
    submit(env, take(env), {"action": "reply", "body": "Thanks!", "why": "ack", "confidence": 0.9})
    pend = ag.inbox(env[0])
    typ = next(x for x in pend if x["action"] == "set_type")
    reply = next(x for x in pend if x["action"] == "reply")
    setv(env, agent_enabled=False)
    for how in ("approve", "edit"):
        with pytest.raises(desk_db.DeskError, match="Service Desk agent is off"):
            ag.review(env[0], typ["proposal_id"], how, actor_=None, edition=S, edits={"type": "Quality"})
    assert desk_db.get_ticket(env[0], t["ticket_id"])["type"] != "Quality"
    assert ag.review(env[0], reply["proposal_id"], "reject", actor_=None, edition=S)["status"] == "rejected"
    setv(env, agent_enabled=True)
    assert ag.review(env[0], typ["proposal_id"], "approve", actor_=None, edition=S)["status"] == "applied"


def test_app_keeps_the_agent_tab_while_suggestions_wait_and_marks_them_paused(env):
    """David 2026-11-03: with the agent off, the 🤖 tab stays while suggestions wait; they show as paused."""
    import desk_http
    owner, staff = {"id": "owner", "role": "owner"}, {"id": "sam", "role": "staff"}

    def get(path, actor=owner):
        st, _ct, body = desk_http.route("GET", path, query={}, body=b"", content_type="", actor=actor,
                                        edition=S, db_path=env[0])
        assert st == 200, body
        return json.loads(body)

    customer_ticket(env)
    submit(env, take(env), {"action": "set_type", "type": "Quality", "why": "x", "confidence": 0.9})
    assert get("/desk-api/me")["agent_pending"] == 1
    assert [p["paused"] for p in get("/desk-api/agent/inbox")["pending"]] == [""]
    setv(env, agent_enabled=False)
    me = get("/desk-api/me")
    assert me["agent_pending"] == 1 and not me["settings"]["agent_enabled"]          # tab stays (index.html)
    d = get("/desk-api/agent/inbox")
    assert "Service Desk agent is off" in d["pending"][0]["paused"] and d["status"]["enabled"] is False
    assert get("/desk-api/me", actor=staff)["agent_pending"] == 0                      # staff never see the tab
    page = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
    assert "S.me.agent_pending > 0" in page and "⏸ Paused" in page and "p.paused || p.payload.refused ? ''" in page


def test_agent_off_reason_follows_each_agents_own_switch():
    on = {"agent_enabled": True, "agent_bk_enabled": True, "agent_jb_enabled": True, "agent_jb_rt_enabled": True,
          "agent_hr_enabled": True}
    kinds, scanners, risk, allowed = dict(ag.KINDS), list(ag.SCANNERS), dict(ag.RISK), dict(ag.ALLOWED)
    try:
        import desk_hr_agent  # noqa: F401  (registers the 'hr' kind)
        import desk_jobs_agent  # noqa: F401  (registers 'job' and 'route')
        desk_hr_agent._register()
        desk_jobs_agent._register()
        for kind, stage in (("ticket", "intake"), ("booking", "decide"), ("job", "closeout"), ("route", "send"),
                            ("hr", "timeoff")):
            assert ag.agent_off_reason(on, kind, stage) == "", kind
        assert "Booking & scheduling is off" in ag.agent_off_reason({**on, "agent_bk_enabled": False}, "booking",
                                                                   "decide")
        assert "Booking & scheduling is off" in ag.agent_off_reason({**on, "agent_enabled": False}, "booking", "decide")
        assert "Jobs agent is off" in ag.agent_off_reason({**on, "agent_jb_enabled": False}, "job", "closeout")
        assert ag.agent_off_reason({**on, "agent_jb_enabled": False}, "route", "send") == ""   # routes have their own
        assert "Route flow is off" in ag.agent_off_reason({**on, "agent_jb_rt_enabled": False}, "route", "send")
        assert "HR agent is off" in ag.agent_off_reason({**on, "agent_hr_enabled": False}, "hr", "timeoff")
        assert ag.agent_off_reason({**on, "agent_shadow": True}, "ticket", "intake") == ""     # practice isn't "off"
    finally:                    # leave the engine as this file's other tests expect it
        ag.KINDS.clear(); ag.KINDS.update(kinds)
        ag.SCANNERS[:] = scanners
        ag.RISK.clear(); ag.RISK.update(risk)
        ag.ALLOWED.clear(); ag.ALLOWED.update(allowed)


# ── bookings ─────────────────────────────────────────────────────────────────

def make_booking(env, key=T7, phone="+13865550142", name="Maria Lopez", backups=()):
    tickets, jobs = env
    s = desk_db.get_settings(tickets)
    h = bf.hold_for_checkout(jobs, s, "WIN-EXT", key, who="ip:" + phone, edition=S)
    held = bf.ensure_hold(jobs, s, "WIN-EXT", h["hold_id"], key, edition=S)
    cid, _ = bdb.find_or_create_customer(jobs, name=name, phone=phone)
    out = bf.create_pending(jobs, s, held, customer_id=cid, customer_name=name, service_name="Exterior windows",
                            street="12 Ocean Ave", edition=S, backups=list(backups))
    c = desk_db.upsert_contact(tickets, name=name, phone=phone, contact_type="customer")
    t = desk_db.create_ticket(tickets, title=f"Exterior windows — {bf.label_of(key)}", kind=r.EXTERNAL, actor=None,
                              edition=S, contact_id=c["contact_id"], job_id=out["job_id"], source="portal")
    bf.link_ticket(jobs, out["job_id"], t["ticket_id"])
    return out["job_id"], t["ticket_id"]


def booking_items(env):
    out = []
    while True:
        it = take(env)
        if not it:
            return out
        out.append(it)
        if it["kind"] == "ticket":
            submit(env, it, {"action": "no_action", "why": "test", "confidence": 1})


def test_bookings_are_queued_check_then_decide(env):
    setv(env, agent_bk_enabled=True, agent_bk_shadow=False, agent_stage_intake="off", agent_stage_first_reply="off")
    job, _t = make_booking(env, backups=[T9])
    items = [i for i in booking_items(env) if i["kind"] == "booking"]
    assert [i["stage"] for i in items] == ["check", "decide"]
    decide = items[1]
    assert decide["booking"]["held"] == T7 and decide["booking"]["backups"][0]["key"] == T9
    assert decide["windows"] and all("key" in w for w in decide["windows"])
    assert "bk_approve" in decide["allowed_actions"] and decide["rules"]["agent_may_confirm"] is False
    assert ag.scan_bookings(env[0], env[1]) == 0                  # same version: never queued twice


def test_recommendation_shows_on_the_card(env):
    setv(env, agent_bk_enabled=True, agent_bk_shadow=False, agent_bk_stage_decide="auto",
         agent_stage_intake="off", agent_stage_first_reply="off")
    job, _t = make_booking(env)
    decide = [i for i in booking_items(env) if i["stage"] == "decide"][0]
    res = submit(env, decide, {"action": "bk_recommend", "choice": "approve", "window_key": T7,
                               "why": "fits the morning", "confidence": 0.85},
                 {"action": "bk_approve", "window_key": T7, "why": "x", "confidence": 0.9},
                 {"action": "bk_suggest_time", "window_key": "2027-03-02T05:00-07:00", "why": "x", "confidence": 0.9})
    st = [x["status"] for x in res["results"]]
    assert st[0] == "applied" and st[1] == "pending" and st[2] == "rejected"   # not allowed to confirm; bad time
    card = ag.for_booking(env[0], job)
    assert card["suggests"]["choice"] == "approve" and card["suggests"]["label"] == "Tue 02 Mar, 7–9"
    assert bf.get(env[1], job)["req"]["status"] == "pending"                   # nobody confirmed it


def test_agent_confirms_only_with_the_tick_auto_and_guardrails(env):
    setv(env, agent_bk_enabled=True, agent_bk_shadow=False, agent_bk_stage_decide="auto", agent_bk_can_confirm=True,
         agent_bk_confirm_per_day=1, agent_stage_intake="off", agent_stage_first_reply="off")
    a, _ = make_booking(env)
    b, _ = make_booking(env, key=W9, phone="+13865550199", name="Bo Chen")
    items = {i["booking"]["job_id"]: i for i in booking_items(env) if i["stage"] == "decide"}
    res = submit(env, items[a], {"action": "bk_approve", "window_key": T9, "why": "x", "confidence": 0.95})
    assert res["results"][0]["status"] == "pending" and "own time" in res["results"][0]["why"]   # not their choice
    res = submit(env, items[b], {"action": "bk_approve", "why": "near other jobs", "confidence": 0.95})
    assert res["results"][0]["status"] == "applied"
    assert bf.get(env[1], b)["req"]["decision"] == "agent" and bf.get(env[1], b)["job"]["job_status"] == "Scheduled"
    assert bf.upcoming(env[1])[0]["how"] == "confirmed by the assistant"


def test_offer_times_to_a_request_with_no_date(env):
    tickets, jobs = env
    setv(env, agent_bk_enabled=True, agent_bk_shadow=False, agent_bk_stage_offer="auto", agent_bk_stage_check="off",
         agent_stage_intake="off", agent_stage_first_reply="off")
    cid, _ = bdb.find_or_create_customer(jobs, name="Pat Kim", phone="+13865550177")
    job = bdb.create_request_job(jobs, customer_id=cid, customer_name="Pat Kim", service="Exterior windows",
                                 service_code="WIN-EXT", street="9 Canal St")
    c = desk_db.upsert_contact(tickets, name="Pat Kim", phone="+13865550177", contact_type="customer")
    t = desk_db.create_ticket(tickets, title="New service request — Exterior windows", kind=r.EXTERNAL, actor=None,
                              edition=S, contact_id=c["contact_id"], job_id=job)
    bdb.link_request_ticket(jobs, job, t["ticket_id"])
    offer = [i for i in booking_items(env) if i["stage"] == "offer"][0]
    keys = [w["key"] for w in offer["windows"][:2]]
    res = submit(env, offer, {"action": "bk_offer_times", "window_keys": keys, "why": "soonest", "confidence": 0.9})
    assert res["results"][0]["status"] == "applied"
    v = bf.view(jobs, job, desk_db.get_settings(tickets))
    assert v["state"] == "suggested" and v["can_accept"]
    # F-19 (David, 2026-11-04): the agent's own offer isn't approved by anyone, so accepting holds the time for Decide.
    done = bf.customer_accept(jobs, tickets, job, edition=S, settings=desk_db.get_settings(tickets))
    assert done["status"] == "pending"
    b = bf.get(jobs, job)
    assert b["held_key"] == keys[0] and b["job"]["job_status"] != "Scheduled"


def test_a_customer_message_on_a_booking_goes_to_the_booking_agent(env):
    setv(env, agent_bk_enabled=True, agent_stage_intake="off", agent_stage_first_reply="off",
         agent_stage_resolution="suggest")
    job, tid = make_booking(env)
    desk_db.add_message(env[0], tid, "The gate code is 4411", actor={"id": "c", "role": "customer",
                                                                     "contact_id": desk_db.get_ticket(env[0], tid)["contact_id"]},
                        edition=S, visibility="public")
    assert ("booking", job, "reply") in [(x["kind"], x["ref"], x["stage"]) for x in queue(env)]


# ── tools, digest ────────────────────────────────────────────────────────────

def test_the_tools_that_manage_the_agent(env):
    customer_ticket(env)
    item = take(env)
    res = submit(env, item, {"action": "note", "body": "x", "why": "y", "confidence": 0.9})
    assert res["results"][0]["status"] == "pending"
    assert "1 item(s)" in desk_tools.desk_agent_review(env[0], None, S)
    assert desk_tools.desk_agent_review(env[0], {"id": "sam", "role": "staff"}, r.BUSINESS).startswith("❌")
    assert "Waiting for review: 1" in desk_tools.desk_agent_status(env[0], None, S)
    line = desk_scheduler.agent_digest_line(env[0], desk_db.get_settings(env[0]))
    assert "1 suggestion(s) waiting for your OK" in line
