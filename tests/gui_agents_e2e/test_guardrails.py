"""AG-GR (AGENTS_GUI_E2E_TEST_SPEC.md §6) — Auto, with one condition broken at a time. Expected: nothing applied or sent,
a pending suggestion with the reason. Written so far: Service Desk (01–05, 07), hours (30), Jobs invoices (20–27), bad AI
answers (60, 61). Booking and HR are in test_guardrails_booking.py and test_guardrails_hr.py; what's left is in the spec, §16.
"""
from __future__ import annotations

import itertools
import re

import pytest

from conftest import START
from test_env import CUST_RE, JOB_RE
from test_matrix import JB_STAGES, REPLY, _new, _marks, _rows, _sent, all_off, off_stages, setup, trigger

_n = itertools.count(1)


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    yield b
    all_off(b)


def _ticket(box, **extra):
    n = next(_n)
    st, d = box.desk("POST", "/tickets", {"kind": "external", "title": f"ZAG guardrail {n}", "contact_name": "ZAG Maria",
                                          "contact_phone": "386-555-0142", "contact_email": "maria@time-machine.test",
                                          **extra})
    assert st == 201, d
    return d["ticket"]["ticket_id"]


def _reply_rule(box, conf=0.9, body=REPLY):
    box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": body, "why": "ZAG", "confidence": conf}]})


def _ticket_props(box, marks, tid):
    return [p for p in _new(box, marks, "SD")[1] if p["ref"] == tid]


# ── Service Desk ─────────────────────────────────────────────────────────────
def test_gr_01_p1_waits_for_a_person(box):
    setup(box, "SD", "AUTO")
    marks, sent0 = _marks(box), len(box.outbox())
    tid = _ticket(box, priority="P1")
    box.agents_pass()
    p = _ticket_props(box, marks, tid)
    assert p and p[0]["status"] == "pending" and "P1" in p[0]["hold_reason"], p
    assert not _sent(box, sent0, REPLY)


def test_gr_02_lowering_the_priority_waits(box):
    setup(box, "SD", "AUTO", stage="intake")
    box.ai_reset("good", {"ticket:intake": [{"action": "set_priority", "priority": "P3", "why": "ZAG", "confidence": 0.9}]})
    marks = _marks(box)
    tid = _ticket(box, priority="P2")
    box.agents_pass()
    p = _ticket_props(box, marks, tid)
    assert p and p[0]["status"] == "pending" and "lowers the priority" in p[0]["hold_reason"], p


@pytest.mark.parametrize("conf,status", [(0.59, "pending"), (0.60, "applied")])
def test_gr_03_confidence(box, conf, status):
    setup(box, "SD", "AUTO")
    _reply_rule(box, conf)
    marks = _marks(box)
    tid = _ticket(box)
    box.agents_pass()
    p = _ticket_props(box, marks, tid)
    assert p and p[0]["status"] == status, p
    if status == "pending":
        assert "confidence 0.59" in p[0]["hold_reason"], p


@pytest.mark.parametrize("body", ["x" * 1201, "See https://not-allowed.example.com/deal for more."], ids=["long", "link"])
def test_gr_04_text_problems_wait(box, body):
    setup(box, "SD", "AUTO")
    _reply_rule(box, 0.9, body)
    marks, sent0 = _marks(box), len(box.outbox())
    tid = _ticket(box)
    box.agents_pass()
    p = _ticket_props(box, marks, tid)
    if p:                                                       # held with its reason …
        assert p[0]["status"] == "pending" and p[0]["hold_reason"], p
    assert not _sent(box, sent0, body[:30]), box.outbox()[sent0:]   # … and never sent


def test_gr_05_private_ticket_never_reaches_the_ai(box):
    setup(box, "SD", "AUTO")
    marks = _marks(box)
    _ticket(box, kind="internal", visibility="private")
    box.agents_pass()
    assert _new(box, marks, "SD") == ([], [])
    assert not box.ai_calls()


def test_gr_07_an_action_the_stage_doesnt_allow(box):
    setup(box, "SD", "AUTO")
    box.ai_reset("good", {"ticket:first_reply": [{"action": "set_type", "type": "ZAG", "why": "x", "confidence": 0.99}]})
    marks = _marks(box)
    tid = _ticket(box)
    box.agents_pass()
    props = _ticket_props(box, marks, tid)
    assert not [p for p in props if p["status"] == "applied"], props
    held = [p for p in props if p["status"] == "pending"]          # F-25: a notice with the reason, which can't be approved
    assert held and all('"refused": true' in p["payload_json"] for p in held), props
    st, d = box.desk("POST", f"/agent/proposals/{held[0]['proposal_id']}/approve", {})
    assert st != 200 and "refused" in str(d), (st, d)
    box.desk("POST", f"/agent/proposals/{held[0]['proposal_id']}/reject", {})
    st, d = box.desk("GET", f"/tickets/{tid}")
    assert st == 200 and "ZAG" != (d.get("ticket") or {}).get("type"), d


def test_gr_30_outside_the_hours_only_run_now_works(box):
    setup(box, "SD", "AUTO")
    box.settings(desk={"agent_hours": [9, 10]})
    box.clock(START, "15:00")
    marks = _marks(box)
    _ticket(box)
    box.agents_pass()
    assert not box.ai_calls(), "an automatic pass ran outside the agent's hours"
    assert _new(box, marks, "SD")[1] == []
    box.agents_pass(force=True)
    assert [c for c in box.ai_calls() if c["kind"] == "ticket"], "Run now didn't run"


# ── Jobs: invoices ───────────────────────────────────────────────────────────
DRAFT_AND_SEND = [{"action": "jb_draft_invoice", "why": "ZAG done", "confidence": 0.9},
                  {"action": "jb_send_invoice", "channel": "email", "why": "ZAG send", "confidence": 0.9}]


def _invoice_setup(box, *, can_send=True, mode="auto", practice=False, per_day=100, max_=1000, rule=None):
    box.ai_reset("good", {"job:closeout": rule or DRAFT_AND_SEND})
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_shadow": practice, "agent_jb_can_send_invoices": can_send,
                       "agent_jb_invoice_max": max_, "agent_jb_invoices_per_day": per_day,
                       **off_stages("agent_jb_stage_", JB_STAGES, "closeout", mode)})


def _done_job(box, amount=200, email=True, timed=True):
    n = next(_n)
    name = f"ZAG Invoice Customer {n}"
    who = {"Customer Name / Company": name, "Phone": "386-555-0177", "Street Address": "100 Flagler Ave",
           "City": "New Smyrna Beach", "State": "FL", "Zip": "32169"}
    if email:
        who["Email"] = f"inv{n}@time-machine.test"
    r = box.tool("create_customer", updates=who)
    cid = re.search(CUST_RE, r or "")
    assert cid, r
    job = {"CustomerID": cid.group(0), "Customer Name / Company": name, "Street Address": "100 Flagler Ave",
           "Service Type": "Window", "Service Date": START.isoformat(), "Job Status": "Complete",
           "Quote Amount ($)": amount}
    if timed:
        job["Actual Duration"] = 2
    r = box.tool("create_job", updates=job)
    jid = re.search(JOB_RE, r or "")
    assert jid, r
    return jid.group(0), who.get("Email", "")


def _invoice_props(box, marks, jid):
    p = [x for x in _new(box, marks, "JB")[1] if x["ref"] == jid]
    return {x["action"]: x for x in p}, p


def _run_invoice(box, **job):
    marks, sent0 = _marks(box), len(box.outbox())
    jid, email = _done_job(box, **job)
    box.agents_pass()
    by, rows = _invoice_props(box, marks, jid)
    return by, rows, sent0, email


def _invoice_sent(box, sent0, email):
    return [m for m in box.outbox()[sent0:] if email and m.get("to") == email]


def test_gr_27_all_conditions_hold_it_sends(box):
    _invoice_setup(box)
    by, rows, sent0, email = _run_invoice(box)
    assert by["jb_draft_invoice"]["status"] == "applied", rows
    assert by["jb_send_invoice"]["status"] == "applied", rows
    assert _invoice_sent(box, sent0, email), box.outbox()[sent0:]


@pytest.mark.parametrize("settings,job,why", [
    ({"can_send": False}, {}, "isn't allowed to send invoices"),
    ({"max_": 1000}, {"amount": 1250}, "limit"),
    ({}, {"timed": False}, "no time was logged"),
    ({}, {"email": False}, "no email"),
], ids=["gr20-not-allowed", "gr22-over-max", "gr26-no-time", "gr25-no-email"])
def test_gr_20_22_25_26_a_person_sends(box, settings, job, why):
    _invoice_setup(box, **settings)
    by, rows, sent0, email = _run_invoice(box, **job)
    send = by.get("jb_send_invoice")
    assert send and send["status"] == "pending" and why in send["hold_reason"], rows
    assert not _invoice_sent(box, sent0, email)


def test_gr_21_suggest_and_practice(box):
    _invoice_setup(box, mode="suggest")
    by, rows, sent0, email = _run_invoice(box)
    assert {x["status"] for x in rows} == {"pending"}, rows
    assert not _invoice_sent(box, sent0, email)
    _invoice_setup(box, practice=True)
    by, rows, sent0, email = _run_invoice(box)
    assert {x["status"] for x in rows} == {"practice"}, rows
    assert not _invoice_sent(box, sent0, email)


def test_gr_23_daily_count(box):
    _invoice_setup(box, per_day=1)
    _run_invoice(box)
    by, rows, sent0, email = _run_invoice(box)
    send = by.get("jb_send_invoice")
    assert send and send["status"] == "pending" and "daily invoice limit" in send["hold_reason"], rows
    assert not _invoice_sent(box, sent0, email)


def test_gr_invoice_confidence_075_waits(box):
    _invoice_setup(box, rule=[DRAFT_AND_SEND[0], {**DRAFT_AND_SEND[1], "confidence": 0.75}])
    by, rows, sent0, email = _run_invoice(box)
    send = by.get("jb_send_invoice")
    assert send and send["status"] == "pending" and "confidence 0.75" in send["hold_reason"], rows


# ── Bad answers from the AI ──────────────────────────────────────────────────
def test_gr_60_messy_answers_apply_nothing_and_the_next_item_runs(box):
    setup(box, "SD", "AUTO")
    box.ai_reset("messy")
    marks, sent0 = _marks(box), len(box.outbox())
    for _ in range(4):                                          # not JSON, no list, unknown action, empty
        _ticket(box)
    box.agents_pass()
    assert len([c for c in box.ai_calls() if c["kind"] == "ticket"]) >= 2, "one bad answer stopped the pass"
    assert not [p for p in _new(box, marks, "SD")[1] if p["status"] == "applied"]
    assert not [m for m in _sent(box, sent0) if "Re: ZAG guardrail" in str(m)], box.outbox()[sent0:]
    # a good answer afterwards still works
    box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": REPLY, "why": "ZAG", "confidence": 0.9}]})
    tid = _ticket(box)
    box.agents_pass(force=True)
    assert _ticket_props(box, marks, tid), box.ai_calls()


@pytest.mark.parametrize("script", ["error", "slow"])
def test_gr_61_api_errors_dont_crash_or_cost(box, script):
    setup(box, "SD", "AUTO")
    box.ai_reset(script)
    marks = _marks(box)
    cost0 = sum(float(r.get("cost_usd") or 0) for r in _rows(box, "tickets", "agent_runs"))
    tid = _ticket(box)
    res = box.agents_pass()
    assert "did" in res
    assert not _ticket_props(box, marks, tid)
    assert sum(float(r.get("cost_usd") or 0) for r in _rows(box, "tickets", "agent_runs")) == pytest.approx(cost0)
