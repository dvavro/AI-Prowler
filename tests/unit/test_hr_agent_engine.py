"""The HR agent (hr-agent-spec.md H1 + H2): the shared engine working the HR apps — kind 'hr' in
its own database inside the HR data folder. Vicki's decisions: 1 approving time off is
configurable (off by default) with limits; 2 who reviews is configurable; 3 reading incident
reports is configurable (type only by default); 4 its own database; 5 only a runner with a key
you control or the Claude CLI — never a chat. No network: HR's data functions are fakes (ha.hr).
The clock is the next Wednesday after the real today, 10:00.
Run: run_tests.bat tests\\unit\\test_hr_agent_engine.py
"""
import copy
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent as ag  # noqa: E402
import desk_agent_hr_store as store  # noqa: E402
import desk_agent_settings as das  # noqa: E402
import desk_db  # noqa: E402
import desk_hr_agent as ha  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_tools  # noqa: E402
from db_access import get_connection  # noqa: E402

S = r.SOLO
OWNER = {"id": "owner", "role": r.OWNER, "name": "Vicki"}
REAL = dt.date.today()
WED = REAL + dt.timedelta(days=((2 - REAL.weekday()) % 7) or 7)
d = lambda n: (WED + dt.timedelta(days=n)).isoformat()  # noqa: E731

SECRETS = {"ssn": "123-45-6789", "date_of_birth": "1990-01-02", "address": "9 Secret Lane",
           "phone": "386-555-0199", "personal_email": "pat@home.example", "work_email": "pat@work.example",
           "pay_rate": "31.57", "bank_account": "000123456789", "emergency_contact": "Mom Secretname",
           "medical_notes": "asthma-inhaler", "photo": "PHOTODATA", "pin_hash": "PINHASH99"}


def employee(eid="EMP-00001", **kw):
    e = dict(id=eid, first_name="Pat", last_name="Lee", title="Tech", department="Field", manager_name="Sam Boss",
             status="Active", start_date=d(-400), work_state="FL", employment_type="Full-time",
             flsa_classification="Non-exempt", pay_frequency="biweekly", **SECRETS)
    e.update(kw)
    return e


@pytest.fixture
def e(tmp_path):
    store.PATH_OVERRIDE = tmp_path / "agent" / "hr_agent.db"
    adb = store.init()
    clock = {"now": dt.datetime.combine(WED, dt.time(10, 0))}
    data = {"employees": [employee()], "tasks": [], "documents": [], "training": [], "pto_requests": [],
            "schedule_change_requests": [], "time_entries": [], "messages": [], "incidents": [],
            "recruiting": {"candidates": []}, "config": {"pto_days_per_year": 10}}
    calls = []

    def api(method, path, body):
        calls.append(("api", method, path, body))
        if path.startswith("/pto/") and path.endswith("/approve"):
            for x in data["pto_requests"]:
                if x["id"] == path.split("/")[2]:
                    x["status"], x["decided_at"] = "approved", "now"
        if path == "/messages/reply":
            for m in data["messages"]:
                if m["id"] == body["id"]:
                    m["reply"] = body["reply"]
        return 200, {"ok": True}

    def notify(to, subject, body):
        calls.append(("notify", to, subject, body))
        return "✅ sent"
    ha.hr.clear()
    ha.install(load=lambda: copy.deepcopy(data), mutate=lambda fn: fn(data), api=api, notify=notify,
               balance=lambda db, emp: {"pto": {"remaining": 5}, "sick": {"remaining": 3}},
               state_rules=lambda st: {"final_pay": "next regular payday"} if st == "FL" else {})
    ha.clock = lambda: clock["now"]
    for k, v in (("agent_hr_enabled", True), ("agent_hr_shadow", False)):
        store.set_setting(k, v, actor=OWNER, edition=S)
    yield {"a": adb, "data": data, "calls": calls, "clock": clock}
    store.PATH_OVERRIDE = None
    ha.hr.clear()
    ha.clock = None


def seth(**kw):
    for k, v in kw.items():
        store.set_setting(k, v, actor=OWNER, edition=S)


def settings(e):
    return desk_db.get_settings(e["a"])


def act(name, conf=0.9, **kw):
    return {"action": name, "why": "test", "confidence": conf, **kw}


def release(e):
    conn = get_connection(e["a"])
    conn.execute("UPDATE agent_queue SET status = 'waiting', claimed_by = NULL WHERE status = 'claimed'")
    conn.close()


def items(e, stage=None, ref=None):
    release(e)
    out = ag.next_items(e["a"], edition=S, limit=10)["items"]
    return [i for i in out if (stage is None or i["stage"] == stage) and (ref is None or i["ref"] == ref)]


def submit(e, item, *actions):
    return ag.submit(e["a"], item["item_id"], list(actions), edition=S)["results"]


def queued(e):
    conn = get_connection(e["a"])
    try:
        return {(x["ref"], x["stage"]) for x in conn.execute("SELECT ref, stage FROM agent_queue")}
    finally:
        conn.close()


def pto(e, rid="PTOREQ-0001", **kw):
    r_ = dict(id=rid, employee_id="EMP-00001", type="PTO", start_date=d(20), end_date=d(20), half_day=False,
              status="pending", created_at=dt.datetime.combine(WED, dt.time(9, 0)).isoformat())
    r_.update(kw)
    e["data"]["pto_requests"].append(r_)
    return r_


# ── the registry, the database and the policy table ──────────────────────────

def test_registered_in_its_own_database(e):
    assert ag.KINDS["hr"] is ha and ha.scan in ag.SCANNERS
    assert Path(e["a"]).name == "hr_agent.db" and Path(e["a"]).parent.name == "agent"


def test_policy_table(e):
    s = settings(e)
    assert ag.decide("hr", "onboard", act("hr_note", body="x"), s, {}) == ("apply", "")            # records only
    assert ag.decide("hr", "onboard", act("hr_task", title="x"), s, {})[0] == "pending"            # Suggest
    assert ag.decide("hr", "onboard", act("hr_approve_timeoff"), s, {})[0] == "rejected"           # not this stage
    assert ag.decide("hr", "learn", act("hr_suggest_policy", topic="x", body="y"), s, {})[0] == "pending"
    st, why = ag.decide("hr", "timeoff", act("hr_approve_timeoff", conf=0.99), s, {"checks": {}})
    assert st == "pending" and "isn't allowed to approve" in why                                  # decision 1: off
    for bad in ("hire", "terminate", "set_pay", "delete_employee", "edit_time", "verify_document"):
        assert not any(bad in a for a in ha.RISK)                                                  # no such actions
    seth(agent_hr_shadow=True)
    assert ag.decide("hr", "onboard", act("hr_note", body="x"), settings(e), {})[0] == "practice"
    seth(agent_hr_shadow=False, agent_hr_stage_onboard="off")
    assert ag.decide("hr", "onboard", act("hr_note", body="x"), settings(e), {})[0] == "rejected"
    seth(agent_hr_enabled=False)
    assert ag.enqueue(e["a"], "hr", "emp:EMP-00001", "onboard", "x") is None                      # the agent is off


# ── privacy: what the AI is never given ──────────────────────────────────────

def test_packs_never_carry_private_fields(e):
    e["data"]["employees"][0]["status"] = "Onboarding"
    e["data"]["tasks"].append({"id": "TASK-00001", "employee_id": "EMP-00001", "name": "I-9", "due_date": d(1),
                               "status": "Not Started"})
    pto(e)
    e["data"]["messages"].append({"id": "MSG-1", "employee_id": "EMP-00001", "subject": "PTO question",
                                  "body": "How many days do I get?", "sent_at": d(0)})
    e["data"]["documents"].append({"id": "DOC-1", "employee_id": "EMP-00001", "name": "License",
                                   "expiration_date": d(20)})
    got = items(e)
    assert {i["stage"] for i in got} >= {"onboard", "timeoff", "answer", "compliance"}
    blob = json.dumps(got)
    for v in SECRETS.values():
        assert v not in blob, v
    emp = next(i for i in got if i["stage"] == "onboard")["employee"]
    assert set(emp) <= set(ha.SAFE_EMP) | {"hourly"} and emp["hourly"] is True


def test_a_sensitive_message_is_never_shown_or_answered_by_the_ai(e):
    e["data"]["messages"].append({"id": "MSG-2", "employee_id": "EMP-00001", "subject": "problem",
                                  "body": "My supervisor harassed me again today", "sent_at": d(0)})
    it = items(e, "answer", "msg:MSG-2")[0]
    assert it["sensitive"] is True and "harassed" not in json.dumps(it) and "hint" in it
    res = submit(e, it, act("hr_reply", body="Sorry to hear that"))
    assert res[0]["status"] != "applied" and "person answers" in res[0]["why"]
    assert not [c for c in e["calls"] if c[0] == "api"]
    seth(agent_hr_stage_answer="auto")
    ag.retry_errors(e["a"])
    conn = get_connection(e["a"])
    conn.execute("UPDATE agent_queue SET status = 'waiting' WHERE ref = 'msg:MSG-2'")
    conn.close()
    it = items(e, "answer", "msg:MSG-2")[0]
    res = submit(e, it, act("hr_ack_sensitive"))
    assert res[0]["status"] == "applied", res
    (_, _, path, body), = [c for c in e["calls"] if c[0] == "api"]
    assert path == "/messages/reply" and "a person will get back to you" in body["reply"]


def test_a_help_question_is_answered_and_signed_but_never_when_a_person_was_asked_for(e):
    seth(agent_hr_stage_answer="auto")
    e["data"]["config"]["handbook"] = "Employees get 10 PTO days a year."
    e["data"]["messages"] += [
        {"id": "MSG-H", "employee_id": "EMP-00001", "message_type": "help_question", "subject": "Help question",
         "body": "How many PTO days do I get?", "sent_at": d(0)},
        {"id": "MSG-P", "employee_id": "EMP-00001", "subject": "PTO", "body": "carry over?", "sent_at": d(0),
         "needs_person": True}]
    it = items(e, "answer", "msg:MSG-H")[0]
    assert it["message"]["help_question"] is True and "10 PTO days" in json.dumps(it["policies"])
    assert not items(e, "answer", "msg:MSG-P")                                     # a person answers that one
    res = submit(e, it, act("hr_reply", body="You get 10 PTO days a year."))
    assert res[0]["status"] == "applied", res
    (_, _, path, body), = [c for c in e["calls"] if c[0] == "api"]
    assert body["by"] == "assistant" and "Talk to a person" in body["reply"] and "virtual assistant" in body["reply"].lower()
    ctx = ha.context(e["a"], None, {"ref": "msg:MSG-P", "stage": "answer"}, settings(e), S, "")
    st, why = ag.decide("hr", "answer", act("hr_reply", body="x"), settings(e), ctx)
    assert st == "pending" and "asked for a person" in why


def test_incident_text_only_when_the_owner_allows_it(e):
    e["data"]["incidents"].append({"id": "INC-1", "employee_id": "EMP-00001", "incident_type": "injury",
                                   "description": "slipped-on-wet-floor", "submitted_at": d(0)})
    it = items(e, "incidents", "inc:INC-1")[0]
    assert it["incident"]["type"] == "injury" and "slipped-on-wet-floor" not in json.dumps(it)   # decision 3 default
    seth(agent_hr_incidents_access="read")
    release(e)
    pk = ha.pack(e["a"], None, {"ref": "inc:INC-1", "stage": "incidents"}, settings(e), S, "")
    assert pk["incident"]["report"] == "slipped-on-wet-floor"


# ── time off (decision 1) ────────────────────────────────────────────────────

def test_time_off_is_only_recommended_by_default(e):
    pto(e)
    it = items(e, "timeoff", "pto:PTOREQ-0001")[0]
    c = it["checks"]
    assert c["paid_type"] and c["within_max_days"] and c["enough_notice"] and c["balance_covers"]
    res = submit(e, it, act("hr_recommend", choice="approve", why="3 days left, nobody else off"))
    assert res[0]["status"] == "applied"                                           # shown to HR; changes nothing
    assert e["data"]["pto_requests"][0]["status"] == "pending"
    rec = ha.recommendations(e["a"])["pto:PTOREQ-0001"]                             # on HR Admin's request card
    assert rec["choice"] == "approve" and "nobody else off" in rec["why"] and rec["practice"] is False


def test_time_off_approved_only_when_allowed_and_every_check_passes(e):
    seth(agent_hr_stage_timeoff="auto", agent_hr_can_approve_timeoff=True)
    pto(e, "PTOREQ-0001")
    pto(e, "PTOREQ-0002", start_date=d(3), end_date=d(3))                          # short notice
    pto(e, "PTOREQ-0003", type="Unpaid leave")
    got = {i["ref"]: i for i in items(e, "timeoff")}
    ok = submit(e, got["pto:PTOREQ-0001"], act("hr_approve_timeoff", conf=0.97))
    assert ok[0]["status"] == "applied", ok
    assert e["data"]["pto_requests"][0]["status"] == "approved"
    short = submit(e, got["pto:PTOREQ-0002"], act("hr_approve_timeoff", conf=0.97))
    assert short[0]["status"] == "pending" and "notice" in short[0]["why"]
    unpaid = submit(e, got["pto:PTOREQ-0003"], act("hr_approve_timeoff", conf=0.97))
    assert unpaid[0]["status"] == "pending" and "not paid time off" in unpaid[0]["why"]
    assert [p["status"] for p in e["data"]["pto_requests"]] == ["approved", "pending", "pending"]


def test_a_person_approves_a_suggested_time_off(e):
    pto(e)
    it = items(e, "timeoff", "pto:PTOREQ-0001")[0]
    res = submit(e, it, act("hr_approve_timeoff", conf=0.97))
    assert res[0]["status"] == "pending"
    out = ag.review(e["a"], res[0]["proposal_id"], "approve", actor_=OWNER, edition=S)
    assert out["status"] == "applied" and e["data"]["pto_requests"][0]["status"] == "approved"


# ── messages to employees: quiet hours, reminders, former employees ──────────

def test_reminders_wait_for_working_hours_and_never_repeat_within_two_days(e):
    seth(agent_hr_stage_compliance="auto")
    e["data"]["documents"].append({"id": "DOC-1", "employee_id": "EMP-00001", "name": "License",
                                   "expiration_date": d(20)})
    e["clock"]["now"] = dt.datetime.combine(WED, dt.time(20, 0))
    it = items(e, "compliance", "doc:DOC-1")[0]
    res = submit(e, it, act("hr_remind_employee", body="Your license expires soon — please upload the new one."))
    assert res[0]["status"] == "pending" and "outside the hours" in res[0]["why"]
    out = ag.review(e["a"], res[0]["proposal_id"], "approve", actor_=OWNER, edition=S)   # a person may send it now
    assert out["status"] == "applied"
    (_, to, subj, body), = [c for c in e["calls"] if c[0] == "notify"]
    assert to == "pat@work.example" and "license" in body.lower()
    e["clock"]["now"] = dt.datetime.combine(WED + dt.timedelta(days=1), dt.time(10, 0))
    st, why = ag.decide("hr", "compliance", act("hr_remind_employee", body="again"), settings(e),
                        ha.context(e["a"], None, {"ref": "doc:DOC-1", "stage": "compliance"}, settings(e), S, ""))
    assert st == "pending" and "last 2 days" in why


def test_never_messages_a_former_employee(e):
    e["data"]["employees"][0]["status"] = "Terminated"
    ctx = {"_emp": e["data"]["employees"][0]}
    st, why = ag.decide("hr", "timeclock", act("hr_remind_employee", body="hi"), settings(e), ctx)
    assert st == "pending" and "former employee" in why


# ── the timer's scan ─────────────────────────────────────────────────────────

def test_scan_finds_each_kind_of_work(e):
    D = e["data"]
    D["employees"].append(employee("EMP-00002", status="Pre-Start", start_date=d(5)))
    D["employees"].append(employee("EMP-00003", status="Offboarding"))
    D["tasks"].append({"id": "TASK-1", "employee_id": "EMP-00003", "name": "Return keys", "status": "Not Started"})
    pto(e)
    D["schedule_change_requests"].append({"id": "SCR-1", "employee_id": "EMP-00001", "status": "pending"})
    D["time_entries"].append({"id": "TE-1", "employee_id": "EMP-00001", "clock_in": d(-1) + "T08:00:00",
                              "clock_out": None, "date": d(-1)})
    D["time_entries"].append({"id": "TE-2", "employee_id": "EMP-00001", "clock_in": d(0) + "T06:00:00",
                              "clock_out": d(0) + "T06:01:00", "date": d(0), "duration_minutes": 37 * 60})
    D["documents"].append({"id": "DOC-1", "employee_id": "EMP-00001", "expiration_date": d(25)})
    D["training"].append({"id": "TR-1", "employee_id": "EMP-00001", "due_date": d(-2), "status": "assigned"})
    D["messages"].append({"id": "MSG-1", "employee_id": "EMP-00001", "body": "hi", "sent_at": d(0)})
    D["messages"].append({"id": "MSG-9", "employee_id": "EMP-00001", "body": "done", "reply": "ok"})   # answered
    D["incidents"].append({"id": "INC-1", "employee_id": "EMP-00001", "submitted_at": d(0)})
    D["recruiting"]["candidates"].append({"id": "CAND-1", "first_name": "Ann", "status": "new"})
    D["recruiting"]["candidates"].append({"id": "CAND-2", "first_name": "Bo", "status": "hired"})
    ha.scan(e["a"], settings=settings(e))
    q = queued(e)
    for want in (("emp:EMP-00002", "onboard"), ("emp:EMP-00003", "offboard"), ("pto:PTOREQ-0001", "timeoff"),
                 ("sched:SCR-1", "timeoff"), ("time:TE-1", "timeclock"), ("ot:EMP-00001", "timeclock"),
                 ("doc:DOC-1", "compliance"), ("train:TR-1", "compliance"), ("msg:MSG-1", "answer"),
                 ("inc:INC-1", "incidents"), ("cand:CAND-1", "recruit")):
        assert want in q, want
    assert ("msg:MSG-9", "answer") not in q and ("cand:CAND-2", "recruit") not in q
    off = ha.pack(e["a"], None, {"ref": "emp:EMP-00003", "stage": "offboard"}, settings(e), S, "")
    assert off["final_pay_rule"] == "next regular payday"


def test_the_off_switch_scans_nothing(e):
    pto(e)
    seth(agent_hr_enabled=False)
    assert ha.scan(e["a"], settings=settings(e)) == 0 and not queued(e)


# ── who reviews (decision 2) ─────────────────────────────────────────────────

def test_who_may_review(e):
    pto(e)
    mgr = {"id": "m1", "role": r.MANAGER, "name": "Sam Boss"}
    other = {"id": "m2", "role": r.MANAGER, "name": "Someone Else"}
    p_to = {"ref": "pto:PTOREQ-0001", "stage": "timeoff"}
    p_ans = {"ref": "msg:MSG-1", "stage": "answer"}
    s = settings(e)
    assert ha.can_review(OWNER, p_to, s)[0] and ha.can_review({"id": "x", "role": r.OWNER, "hr_admin": True}, p_ans, s)[0]
    assert not ha.can_review(mgr, p_to, s)[0]                                       # default: owner + HR Admin only
    seth(agent_hr_reviewers="hr_admin_managers")
    s = settings(e)
    assert ha.can_review(mgr, p_to, s)[0]                                           # their own team's time off
    assert not ha.can_review(other, p_to, s)[0]                                     # not their team
    assert not ha.can_review(mgr, p_ans, s)[0]                                      # only time off
    pend = submit(e, items(e, "timeoff", "pto:PTOREQ-0001")[0], act("hr_approve_timeoff", conf=0.97))[0]
    with pytest.raises(ag.AgentError):
        ag.review(e["a"], pend["proposal_id"], "approve", actor_=other, edition=S)
    assert e["data"]["pto_requests"][0]["status"] == "pending"


# ── decision 5: never from a chat ────────────────────────────────────────────

def test_runs_only_on_a_key_never_a_chat(e, monkeypatch):
    import desk_agent_providers as prov
    monkeypatch.setattr(prov, "_key", lambda p: "")
    s = dict(settings(e), agent_provider="chat_only")
    why = ag.why_not_run(e["a"], s, edition=S, now=dt.datetime.combine(WED, dt.time(10, 0)), force=True)
    assert "never runs from a chat" in why
    assert das.hr_runner(dict(s, agent_provider="claude_api"), S) == ("claude_api", "")


def test_the_chat_tool_gives_counts_only(e):
    pto(e)
    items(e)
    assert "Only the owner" in desk_tools.hr_agent({"id": "m", "role": r.MANAGER}, S)
    out = desk_tools.hr_agent(OWNER, S)
    assert "HR agent on" in out and "HR Admin" in out
    assert "Pat" not in out and "PTOREQ" not in out                                # no HR details in a chat
    assert "never runs from a chat" in desk_tools.hr_agent(OWNER, S, action="run_now") or \
        "Not started" in desk_tools.hr_agent(OWNER, S, action="run_now")
