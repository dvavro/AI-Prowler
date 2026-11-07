"""AG-MX and AG-X (AGENTS_GUI_E2E_TEST_SPEC.md §5.1, §5.2) — every agent Off / Practice / Suggest / Auto in both editions,
then the named cross-agent combinations. Set up through the sandbox's control port (the settings screens have their own
tests); checked on the queue, the proposals, the outbox and the AI log.

Each section uses one stage and one trigger that really queues an item, with an answer from the stand-in that isn't a
"FREE" note (those are applied even on Suggest, see §12).
"""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START
from test_env import CUST_RE, JOB_RE

REPLY = "ZAG matrix reply: sorry about that, we'll come back."
PREP = "ZAG matrix prep note for the crew."
HR_TEXT = "ZAG matrix: please finish your first-week forms."
_n = itertools.count(1)
_weeks = itertools.count(1)
DB = {"SD": "tickets", "BK": "tickets", "JB": "jobs_agent", "RT": "jobs_agent", "HR": "hr_agent"}
KIND = {"SD": "ticket", "BK": "booking", "JB": "job", "RT": "route", "HR": "hr"}
RULES = {"ticket:first_reply": [{"action": "reply", "body": REPLY, "why": "ZAG", "confidence": 0.9}],
         "job:prep": [{"action": "jb_prep_note", "body": PREP, "why": "ZAG", "confidence": 0.9}],
         "route:sort": [{"action": "rt_propose_week", "moves": [], "why": "ZAG", "confidence": 0.9}],
         "hr:onboard": [{"action": "hr_remind_employee", "body": HR_TEXT, "why": "ZAG", "confidence": 0.9}]}
SD_STAGES = ("intake", "first_reply", "resolution", "follow_through", "learn")
BK_STAGES = ("check", "decide", "offer", "reply", "track", "learn")
JB_STAGES = ("quotes", "schedule", "prep", "onsite", "closeout", "collect", "repeat", "learn")
RT_STAGES = ("sort", "plan", "route", "send", "replan")
HR_STAGES = ("recruit", "onboard", "timeoff", "timeclock", "compliance", "answer", "incidents", "offboard", "learn")
TARGET = {"SD": "first_reply", "BK": "check", "JB": "prep", "RT": "sort", "HR": "onboard"}


def _rows(box, db, table="agent_proposals"):
    return (box.agent_db().get(db) or {}).get(table) or []


def _marks(box):
    return {db: ({p["proposal_id"] for p in _rows(box, db)}, {q["item_id"] for q in _rows(box, db, "agent_queue")})
            for db in ("tickets", "jobs_agent", "hr_agent")}


def _new(box, marks, section):
    """(new queue rows, new proposals) for this section's agent."""
    db, kind = DB[section], KIND[section]
    q = [x for x in _rows(box, db, "agent_queue") if x["item_id"] not in marks[db][1] and x["kind"] == kind]
    p = [x for x in _rows(box, db) if x["proposal_id"] not in marks[db][0] and x["kind"] == kind]
    return q, p


def off_stages(prefix, stages, on=None, mode="suggest"):
    return {f"{prefix}{s}": (mode if s == on else "off") for s in stages}


def all_off(box):
    """Everything off, nothing waiting, the clock back. Waiting items would show in the next test's counts."""
    st, d = box.desk("GET", "/agent/inbox")
    for p in (d.get("pending") or []) if st == 200 else []:
        box.desk("POST", f"/agent/proposals/{p['proposal_id']}/reject", {})
    box.settings(desk={"agent_enabled": False, "agent_bk_enabled": False, "agent_provider": "claude_api",
                       "agent_batch_seconds": 0, "agent_hours": [0, 24], "agent_monthly_budget_usd": 20,
                       "agent_include_service_link": False, **{f"agent_stage_{s}": "suggest" for s in SD_STAGES}},
                 jobs={"agent_jb_enabled": False, "agent_jb_rt_enabled": False, "agent_jb_prep_hour": 16,
                       "agent_jb_weather": False, "agent_jb_sort_weekday": 4, "agent_jb_quote_days": 5,
                       "agent_jb_remind_days": [7, 14, 30], "agent_jb_route_send_hour": 18, "agent_jb_route_scope": "day"},
                 hr={"agent_hr_enabled": False})
    box.clock(START, "09:00")
    box.ai_reset("good", RULES)


def setup(box, section, state, stage=None):
    """Turn on one section in one state: OFF, PRAC, SUG or AUTO. Only its target stage is on."""
    on, practice = state != "OFF", state == "PRAC"
    mode = "auto" if state == "AUTO" else "suggest"
    stage = stage or TARGET[section]
    if section == "SD":
        box.settings(desk={"agent_enabled": on, "agent_shadow": practice,
                           **off_stages("agent_stage_", SD_STAGES, stage, mode)})
    elif section == "BK":
        box.settings(desk={"agent_enabled": True, "agent_shadow": False, "agent_bk_enabled": on,
                           "agent_bk_shadow": practice, "portal_enabled": True, "staff_booking": True,
                           "booking_paths": ["book", "new", "problem"], **off_stages("agent_stage_", SD_STAGES),
                           **off_stages("agent_bk_stage_", BK_STAGES, stage, mode)})
    elif section == "JB":
        box.settings(jobs={"agent_jb_enabled": on, "agent_jb_shadow": practice,
                           **off_stages("agent_jb_stage_", JB_STAGES, stage, mode)})
    elif section == "RT":
        box.settings(jobs={"agent_jb_rt_enabled": on, "agent_jb_rt_shadow": practice,
                           **off_stages("agent_jb_rt_stage_", RT_STAGES, stage, mode)})
    elif section == "HR":
        st, j = box.hr("POST", "/setup/complete", {"company_name": "ZAG Agents Co", "work_states": ["FL"],
                                                   "setup_complete": True, "hr_admin_email": "owner@time-machine.test",
                                                   "owner_email": "owner@time-machine.test"})
        assert st == 200, j
        box.settings(hr={"agent_hr_enabled": on, "agent_hr_shadow": practice,
                         **off_stages("agent_hr_stage_", HR_STAGES, stage, mode)})


def trigger(box, section):
    """The one thing that queues an item for the section. Moves the clock where the stage needs it."""
    n = next(_n)
    if section == "SD":
        st, d = box.desk("POST", "/tickets", {"kind": "external", "title": f"ZAG matrix streaks {n}",
                                              "contact_name": "ZAG Maria", "contact_phone": "386-555-0142",
                                              "contact_email": "maria@time-machine.test"})
        assert st == 201, d
        return d["ticket"]["ticket_id"]
    if section == "BK":
        st, d = box.desk("POST", "/book", {"path": "new", "name": f"ZAG Matrix Booker {n}", "phone": "386-555-0155",
                                           "address": {"street": "300 Flagler Ave", "city": "New Smyrna Beach",
                                                       "state": "FL", "zip": "32169"},
                                           "service": "Gutter cleaning", "preferred": "Tuesday mornings",
                                           "description": "ZAG two-storey", "notify": False, "source": "phone"})
        assert st in (200, 201), d
        return d
    if section == "JB":
        box.clock(START, "16:30")
        name = f"ZAG Matrix Customer {n}"
        r = box.tool("create_customer", updates={"Customer Name / Company": name, "Phone": "386-555-0177"})
        cid = re.search(CUST_RE, r or "")
        assert cid, r
        r = box.tool("create_job", updates={"CustomerID": cid.group(0), "Customer Name / Company": name,
                                             "Service Type": "Window", "Job Status": "Scheduled",
                                             "Service Date": (START + dt.timedelta(days=1)).isoformat()})
        jid = re.search(JOB_RE, r or "")
        assert jid, r
        return jid.group(0)
    if section == "RT":                                         # sorts once a week: each run gets its own week
        friday = START + dt.timedelta(days=4 + 7 * next(_weeks))
        name = f"ZAG Matrix Route {n}"
        r = box.tool("create_customer", updates={"Customer Name / Company": name, "Street Address": "200 Canal St",
                                                  "City": "New Smyrna Beach", "State": "FL", "Zip": "32168"})
        cid = re.search(CUST_RE, r or "").group(0)
        for plus in (3, 4):
            box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": name,
                                            "Street Address": "200 Canal St", "Service Type": "Window",
                                            "Job Status": "Scheduled",
                                            "Service Date": (friday + dt.timedelta(days=plus)).isoformat()})
        box.clock(friday, "09:00")
        return friday.isoformat()
    if section == "HR":
        st, j = box.hr("POST", "/employees", {
            "personal": {"first_name": "ZAG", "last_name": f"Matrix{n}", "personal_email": f"mx{n}@time-machine.test",
                         "phone": "", "address": ""},
            "employment": {"title": "Window tech", "department": "Field", "start_date": "2026-11-12",
                           "work_state": "FL", "employment_type": "full_time", "remote_status": "onsite",
                           "manager_name": ""},
            "compensation": {"pay_type": "hourly", "pay_rate": 22}})
        assert st in (200, 201), j
        return j
    raise ValueError(section)


def _sent(box, since, text=None):
    return [m for m in box.outbox()[since:] if m.get("kind") in ("email", "sms", "whatsapp")
            and (text is None or text in str(m))]


def _agent_sent(box, since):
    """Only what the agent wrote: team notices and the morning digest about a ZAG ticket aren't the agent's."""
    return [m for t in (REPLY, PREP, HR_TEXT) for m in _sent(box, since, t)]


def _api_calls(box, kind):
    return [c for c in box.ai_calls() if c["kind"] == kind and c["api"] != "chat"]


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    yield b
    all_off(b)


@pytest.fixture
def biz(business):
    all_off(business)
    yield business
    all_off(business)


@pytest.fixture
def one(solo):
    all_off(solo)
    yield solo
    all_off(solo)


# ── §5.1 single-agent states ─────────────────────────────────────────────────
def _run(box, section, state):
    setup(box, section, state)
    marks, sent0, blocked0 = _marks(box), len(box.outbox()), len(box.blocked())
    trigger(box, section)
    box.agents_pass()
    q, p = _new(box, marks, section)
    calls = _api_calls(box, KIND[section])
    assert len(box.blocked()) == blocked0, box.blocked()[blocked0:]
    return q, p, calls, sent0


MATRIX = [(s, st, ed) for s in ("SD", "BK", "JB", "RT") for st in ("OFF", "PRAC", "SUG", "AUTO")
          for ed in ("solo", "business")] + [("HR", st, "business") for st in ("OFF", "PRAC", "SUG", "AUTO")]


@pytest.mark.parametrize("section,state,edition", MATRIX, ids=[f"{a}-{b}-{c}" for a, b, c in MATRIX])
def test_mx(request, section, state, edition):
    box = request.getfixturevalue(edition)
    all_off(box)
    try:
        q, p, calls, sent0 = _run(box, section, state)
        kinds = (section, state)
        if state == "OFF":
            assert not q and not p and not calls, (kinds, q, p, calls)
            assert not _agent_sent(box, sent0), box.outbox()[sent0:]
            return
        assert q and calls and p, (kinds, q, p, calls)
        assert all(x["stage"] == TARGET[section] for x in q), q
        statuses = {x["status"] for x in p}
        if state == "PRAC":
            assert statuses == {"practice"}, (kinds, p)
            assert not _agent_sent(box, sent0), box.outbox()[sent0:]
        elif state == "SUG":
            if section == "RT":                                 # saving a week plan is FREE: it changes nothing yet
                assert statuses == {"applied"}, (kinds, p)
            else:
                assert statuses == {"pending"}, (kinds, p)
                assert all("stage is on Suggest" in (x.get("hold_reason") or "") for x in p), p
                assert not _agent_sent(box, sent0), box.outbox()[sent0:]
        else:
            assert statuses <= {"applied", "pending"} and "applied" in statuses or \
                all(x.get("hold_reason") for x in p), (kinds, p)
            if section == "SD":
                assert statuses == {"applied"} and _sent(box, sent0, REPLY), (p, box.outbox()[sent0:])
    finally:
        all_off(box)


# ── §5.2 cross-agent ─────────────────────────────────────────────────────────
def test_x_01_everything_off(box):
    marks, spent0 = _marks(box), box.desk("GET", "/agent/inbox")[1]["status"].get("spent_usd")
    for section in ("SD", "JB", "RT") + (("HR",) if box.mode == "server" else ()):
        if section == "HR":
            setup(box, "HR", "OFF")
        trigger(box, section)
        box.agents_pass()
    for section in ("SD", "BK", "JB", "RT", "HR"):
        assert _new(box, marks, section) == ([], []), section
    assert not box.ai_calls()
    box.clock(START, "09:00")                                   # "this month" follows the clock
    assert box.desk("GET", "/agent/inbox")[1]["status"].get("spent_usd") == spent0


def test_x_02_booking_needs_agent_on(box):
    setup(box, "BK", "SUG")
    box.settings(desk={"agent_enabled": False})
    marks = _marks(box)
    trigger(box, "BK")
    box.agents_pass()
    assert _new(box, marks, "BK") == ([], [])
    assert not _api_calls(box, "booking")


def test_x_03_ticket_practice_with_live_bookings(box):
    setup(box, "BK", "SUG")
    box.settings(desk={"agent_shadow": True, "agent_stage_first_reply": "suggest"})
    marks = _marks(box)
    trigger(box, "SD")
    trigger(box, "BK")
    box.agents_pass()
    assert {x["status"] for x in _new(box, marks, "SD")[1]} == {"practice"}
    assert {x["status"] for x in _new(box, marks, "BK")[1]} == {"pending"}


def test_x_04_jobs_works_with_service_desk_off(box):
    setup(box, "JB", "SUG")
    marks = _marks(box)
    trigger(box, "JB")
    box.agents_pass()
    assert {x["status"] for x in _new(box, marks, "JB")[1]} == {"pending"}
    assert _new(box, marks, "SD") == ([], [])


def test_x_05_jobs_live_routes_practice(box):
    setup(box, "JB", "SUG")
    setup(box, "RT", "PRAC")
    marks, sent0 = _marks(box), len(box.outbox())
    trigger(box, "RT")                                          # Friday
    box.agents_pass()
    assert {x["status"] for x in _new(box, marks, "RT")[1]} == {"practice"}
    box.clock(START, "16:30")
    trigger(box, "JB")
    box.agents_pass()
    assert {x["status"] for x in _new(box, marks, "JB")[1]} == {"pending"}
    assert not _sent(box, sent0, "route"), box.outbox()[sent0:]


def test_x_06_jobs_practice_routes_live(box):
    setup(box, "JB", "PRAC")
    setup(box, "RT", "SUG")
    marks = _marks(box)
    trigger(box, "RT")
    box.agents_pass()
    assert {x["status"] for x in _new(box, marks, "RT")[1]} == {"applied"}     # a saved plan, FREE
    trigger(box, "JB")
    box.agents_pass()
    assert {x["status"] for x in _new(box, marks, "JB")[1]} == {"practice"}


def test_x_07_hr_does_not_run_without_a_key(one):
    box = one
    box.ai_reset()
    box.settings(hr={"agent_hr_enabled": True, "agent_hr_shadow": True})
    box.no_key()
    try:
        box.agents_pass()
        assert not _api_calls(box, "hr")
    finally:
        box.no_key(False)


def test_x_08_chat_can_not_be_chosen_on_a_server(biz):
    biz.settings(desk={"agent_provider": "claude_api"})
    with pytest.raises(AssertionError, match="API key"):
        biz.settings(desk={"agent_provider": "chat_only"})
    assert biz.settings()["desk"]["agent_provider"] == "claude_api"


def test_x_08_or_on_personal(solo):
    solo.settings(desk={"agent_provider": "claude_api"})
    with pytest.raises(AssertionError, match="API key"):
        solo.settings(desk={"agent_provider": "chat_only"})
    assert solo.settings()["desk"]["agent_provider"] == "claude_api"


def test_x_09_old_practice_proposals_are_never_applied(box):
    setup(box, "SD", "PRAC")
    marks, sent0 = _marks(box), len(box.outbox())
    trigger(box, "SD")
    box.agents_pass()
    pid = _new(box, marks, "SD")[1][0]["proposal_id"]
    box.settings(desk={"agent_shadow": False})
    box.agents_pass()
    st, d = box.desk("POST", f"/agent/proposals/{pid}/approve", {})
    assert st >= 400 and "practice" in str(d), (st, d)
    row = next(x for x in _rows(box, "tickets") if x["proposal_id"] == pid)
    assert row["status"] == "practice"
    assert not _sent(box, sent0, REPLY)


@pytest.mark.parametrize("section,switch,prefix", [("SD", "agent_enabled", ""), ("JB", "agent_jb_enabled", "J"),
                                                   ("BK", "agent_bk_enabled", "")])
def test_x_10_agent_off_pauses_its_suggestions(box, section, switch, prefix):
    setup(box, section, "SUG")
    marks = _marks(box)
    trigger(box, section)
    box.agents_pass()
    pid = _new(box, marks, section)[1][0]["proposal_id"]
    box.settings(**({"jobs": {switch: False}} if section == "JB" else {"desk": {switch: False}}))
    st, d = box.desk("POST", f"/agent/proposals/{prefix}{pid}/approve", {})
    assert st >= 400 and "is off" in str(d), (st, d)
    st, d = box.desk("POST", f"/agent/proposals/{prefix}{pid}/edit", {"edits": {"body": "x"}})
    assert st >= 400 and "is off" in str(d), (st, d)
    box.settings(**({"jobs": {switch: True}} if section == "JB" else {"desk": {switch: True}}))
    st, d = box.desk("POST", f"/agent/proposals/{prefix}{pid}/approve", {})
    assert st == 200, (st, d)                                   # back on: approvable again


def test_x_10_rejecting_works_while_off(one):
    box = one
    setup(box, "SD", "SUG")
    marks = _marks(box)
    trigger(box, "SD")
    box.agents_pass()
    pid = _new(box, marks, "SD")[1][0]["proposal_id"]
    box.settings(desk={"agent_enabled": False})
    st, d = box.desk("POST", f"/agent/proposals/{pid}/reject", {})
    assert st == 200 and d["status"] == "rejected", (st, d)


def test_x_11_all_four_live_no_cross_talk(biz):
    box = biz
    for section in ("SD", "JB", "HR"):
        setup(box, section, "SUG")
    marks = _marks(box)
    for section in ("SD", "JB", "HR"):
        trigger(box, section)
    box.agents_pass()
    for section in ("SD", "JB", "HR"):
        assert {x["status"] for x in _new(box, marks, section)[1]} == {"pending"}, section
    for db, kinds in (("tickets", {"ticket", "booking"}), ("jobs_agent", {"job", "route"}), ("hr_agent", {"hr"})):
        new = [p for p in _rows(box, db) if p["proposal_id"] not in marks[db][0]]
        assert new and {p["kind"] for p in new} <= kinds, (db, new)


def test_x_12_one_stage_off_the_rest_suggest(box):
    setup(box, "SD", "SUG")
    box.settings(desk={"agent_stage_intake": "off", "agent_stage_first_reply": "suggest"})
    marks = _marks(box)
    trigger(box, "SD")
    box.agents_pass()
    q, p = _new(box, marks, "SD")
    assert {x["stage"] for x in q} == {"first_reply"} and {x["stage"] for x in p} == {"first_reply"}, (q, p)
    assert {x["status"] for x in p} == {"pending"}


def test_x_13_saving_a_key_starts_the_agent_and_nothing_old_is_worked(one):
    box = one
    setup(box, "SD", "SUG")
    box.no_key()
    marks = _marks(box)
    try:
        trigger(box, "SD")
        box.agents_pass()
        assert not _api_calls(box, "ticket")
        assert _new(box, marks, "SD") == ([], [])
    finally:
        box.no_key(False)
    trigger(box, "SD")
    box.agents_pass()
    q2, p = _new(box, marks, "SD")
    assert len(_api_calls(box, "ticket")) == len(q2) == 1, (box.ai_calls(), q2)
    assert len(p) == 1
    box.agents_pass()
    assert len(_api_calls(box, "ticket")) == 1                  # not worked twice
