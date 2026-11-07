"""AG-WF-06, 08, 11, 12 (AGENTS_GUI_E2E_TEST_SPEC.md §7), by route. WF-04, 05, 07, 09 and 13 aren't written."""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START
from test_env import CUST_RE, JOB_RE
from test_guardrails_hr import _employee
from test_matrix import HR_STAGES, JB_STAGES, _marks, _new, all_off, off_stages
from test_stage_grid import _sql

_n = itertools.count(1)
FOLLOW = "ZAG just checking if you had any questions about the quote."
REMIND = "ZAG a friendly reminder about your invoice."
SECRET = "ZAGSECRETWORD my manager keeps harassing me"
INJURY = "ZAGINJURYTEXT cut his hand on the ladder"


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.today = START + dt.timedelta(days=10000 + 60 * next(_n))
    b.clock(b.today, "10:00")
    yield b
    all_off(b)


def _jobs_on(box, *stages, **more):
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_shadow": False,
                       **{f"agent_jb_stage_{s}": ("auto" if s in stages else "off") for s in JB_STAGES}, **more})


def _customer(box):
    n = next(_n)
    name = f"ZAG Flow {n}"
    email = f"flow{n}@time-machine.test"
    r = box.tool("create_customer", updates={"Customer Name / Company": name, "Phone": "386-555-0181", "Email": email,
                                             "Street Address": "100 Flagler Ave", "City": "New Smyrna Beach", "State": "FL", "Zip": "32169"})
    return re.search(CUST_RE, r).group(0), name, email


def _quote(box, cid, name, status, date):
    r = box.tool("create_quote", updates={"CustomerID": cid, "Customer Name / Company": name, "Service Type": "Window",
                                          "Quote Amount": 150, "Status": status, "Quote Date": date.isoformat()})
    assert r and "quote" in r.lower(), r
    return _sql(box, "SELECT quote_id FROM quotes ORDER BY rowid DESC LIMIT 1")[0][0]


# ── WF-06: quote to scheduled job ────────────────────────────────────────────
def test_wf_06_approved_quote_becomes_a_job_at_the_quotes_price(box):
    cid, name, _ = _customer(box)
    box.ai_reset("good", {"job:quotes": [{"action": "jb_job_from_quote", "notes": "ZAG", "why": "ZAG", "confidence": 0.9}]})
    _jobs_on(box, "quotes")
    marks = _marks(box)
    qid = _quote(box, cid, name, "Open", box.today)
    _sql(box, "UPDATE quotes SET status = 'Approved', subtotal = 150 WHERE quote_id = ?", (qid,))     # new quotes start Open
    box.agents_pass()
    props = [p for p in _new(box, marks, "JB")[1] if p["ref"] == qid]
    assert props and props[0]["status"] in ("applied", "pending"), ([dict(r) for r in _sql(box, "SELECT quote_id, status, customer_id, service_type, quote_date FROM quotes WHERE quote_id = ?", (qid,))], _new(box, marks, "JB")[0], [dict(r) for r in _sql(box, "SELECT job_id, service_type, job_status, service_date FROM jobs WHERE customer_id = ?", (cid,))], str(box.ai_calls())[:300])
    if props[0]["status"] == "pending":                 # high risk: a person approves
        st, d = box.desk("POST", f"/agent/proposals/{props[0]['proposal_id']}/approve", {})
        assert st == 200 or "jobs" in str(d), (st, d)
        return
    row = _sql(box, "SELECT quote_amount, job_status FROM jobs WHERE customer_id = ?", (cid,))
    assert row and float(row[0]["quote_amount"]) == 150, [dict(r) for r in row]


def test_wf_06_open_quote_gets_one_follow_up(box):
    cid, name, email = _customer(box)
    box.ai_reset("good", {"job:quotes": [{"action": "jb_quote_followup", "body": FOLLOW, "why": "ZAG", "confidence": 0.9}]})
    _jobs_on(box, "quotes")
    qid = _quote(box, cid, name, "Open", box.today)
    marks = _marks(box)
    box.clock(box.today + dt.timedelta(days=2), "10:00")
    sent = len(box.outbox())
    box.agents_pass()
    assert not [m for m in box.outbox()[sent:] if m.get("to") == email], "too soon"
    box.clock(box.today + dt.timedelta(days=6), "10:00")
    did = []
    for _ in range(5):          # other files' open quotes can take the first passes
        did.append(box.agents_pass())
        if [m for m in box.outbox()[sent:] if m.get("to") == email and FOLLOW in str(m)]:
            break
    q, p = _new(box, marks, "JB")
    assert [m for m in box.outbox()[sent:] if m.get("to") == email and FOLLOW in str(m)], (
        qid, str(did)[:900], [{k: i.get(k) for k in ("ref", "stage", "status", "note", "attempts")} for i in q][:12],
        [{k: i.get(k) for k in ("ref", "action", "status", "hold_reason", "result")} for i in p][:12], len(box.ai_calls()), box.now().isoformat())
    box.clock(box.today + dt.timedelta(days=9), "10:00")
    box.agents_pass()
    assert len([m for m in box.outbox()[sent:] if m.get("to") == email and FOLLOW in str(m)]) == 1


# ── WF-08: close out, get paid, repeat ───────────────────────────────────────
def _sent_invoice(box):
    cid, name, email = _customer(box)
    r = box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": name, "Service Type": "Window",
                                        "Job Status": "Complete", "Service Date": box.today.isoformat(), "Quote Amount ($)": 200,
                                        "Actual Duration": 2, "Recurrence": "Monthly"})
    return re.search(JOB_RE, r).group(0), email


def test_wf_08_invoice_reminders_then_paid_then_next_visit(box):
    box.ai_reset("good", {"job:closeout": [{"action": "jb_draft_invoice", "why": "ZAG", "confidence": 0.9},
                                           {"action": "jb_send_invoice", "channel": "email", "why": "ZAG", "confidence": 0.9}],
                          "job:collect": [{"action": "jb_payment_reminder", "body": REMIND, "why": "ZAG", "confidence": 0.9}],
                          "job:repeat": [{"action": "jb_next_visit", "why": "ZAG", "confidence": 0.9}]})
    _jobs_on(box, "closeout", "collect", "repeat", agent_jb_can_send_invoices=True, agent_jb_invoice_max=1000, agent_jb_invoices_per_day=100)
    # Other tests' finished jobs would take the agent's turn, and count below: retire them and let the queue empty.
    _sql(box, "UPDATE jobs SET job_status = 'Cancelled' WHERE LOWER(COALESCE(job_status, '')) NOT IN ('cancelled', 'canceled')")
    _sql(box, "UPDATE invoices SET payment_status = 'Paid'")
    for _ in range(3):
        box.agents_pass()
    marks, sent = _marks(box), len(box.outbox())
    jid, email = _sent_invoice(box)
    box.agents_pass()

    def to_them(text=""):
        return [m for m in box.outbox()[sent:] if m.get("to") == email and text in str(m)]
    for _ in range(50):
        if to_them():
            break
        import time
        time.sleep(0.1)
    assert to_them(), "the invoice wasn't sent: " + str(_new(box, marks, "JB")[1])
    assert not to_them(REMIND)
    box.clock(box.today + dt.timedelta(days=8), "10:00")
    box.agents_pass()
    assert len(to_them(REMIND)) == 1, _new(box, marks, "JB")[1]
    box.clock(box.today + dt.timedelta(days=15), "10:00")
    box.agents_pass()
    assert len(to_them(REMIND)) == 2, _new(box, marks, "JB")[1]
    _sql(box, "UPDATE invoices SET payment_status = 'Paid' WHERE job_id = ?", (jid,))
    box.clock(box.today + dt.timedelta(days=32), "10:00")
    box.agents_pass()
    assert len(to_them(REMIND)) == 2, "reminded after it was paid"
    props = [p for p in _new(box, marks, "JB")[1] if p["action"] == "jb_next_visit" and p["ref"] == jid]
    assert props and props[0]["status"] == "applied", [{k: str(p.get(k))[:220] for k in ("action", "status", "result")} for p in props]
    rows = _sql(box, "SELECT job_id, service_date, job_status FROM jobs WHERE job_id != ? AND customer_id = (SELECT customer_id FROM jobs WHERE job_id = ?)", (jid, jid))
    assert rows and rows[0]["service_date"] > box.today.isoformat(), [dict(r) for r in rows]     # about a month on, not today


# ── WF-11 and 12: HR, Business only ──────────────────────────────────────────
@pytest.fixture
def biz(business):
    all_off(business)
    day = START + dt.timedelta(days=12000 + 28 * next(_n))
    while day.weekday() != 1:
        day += dt.timedelta(days=1)
    business.clock(day, "10:00")
    business.today = day
    st, j = business.hr("POST", "/setup/complete", {"company_name": "ZAG Agents Co", "work_states": ["FL"], "setup_complete": True,
                                                    "hr_admin_email": "owner@time-machine.test", "owner_email": "owner@time-machine.test"})
    assert st == 200, j
    yield business
    all_off(business)


def _hr_on(box, *stages, mode="auto", **more):
    box.settings(hr={"agent_hr_enabled": True, "agent_hr_shadow": False,
                     **{f"agent_hr_stage_{s}": (mode if s in stages else "off") for s in HR_STAGES}, **more})


def _message(box, eid, text):
    st, j = box.hr("POST", "/messages", {"employee_id": eid, "subject": "ZAG", "message": text, "body": text})
    assert st in (200, 201), j
    return (j.get("message") or j).get("id") or j.get("id")


def _ai_saw(box, text):
    return [c for c in box.ai_calls() if text in str(c)]


@pytest.mark.parametrize("ack", [True, False], ids=["acknowledge on", "acknowledge off"])
def test_wf_11_a_sensitive_message_never_gets_an_answer(biz, ack):
    box = biz
    eid = _employee(box)
    box.ai_reset("good", {"hr:answer": [{"action": "hr_reply", "body": "ZAG here is your answer", "why": "ZAG", "confidence": 0.9}]})
    _hr_on(box, "answer", agent_hr_ack_sensitive=ack)
    marks = _marks(box)
    _message(box, eid, SECRET)
    box.agents_pass()
    assert not _ai_saw(box, "ZAGSECRETWORD"), "the AI saw a sensitive message's text"
    applied = [p for p in _new(box, marks, "HR")[1] if p["action"] == "hr_reply" and p["status"] == "applied"]
    assert not applied, applied


def test_wf_11_an_ordinary_question_is_answered(biz):
    box = biz
    eid = _employee(box)
    answer = "ZAG you get five sick days a year."
    box.ai_reset("good", {"hr:answer": [{"action": "hr_reply", "body": answer, "why": "ZAG", "confidence": 0.9}]})
    _hr_on(box, "answer")
    marks = _marks(box)
    _message(box, eid, "ZAG how many sick days do I get?")
    box.agents_pass()
    props = [p for p in _new(box, marks, "HR")[1] if p["action"] == "hr_reply"]
    assert props and props[0]["status"] == "applied", props


def test_wf_11_a_question_is_answered_at_any_hour(biz):
    """F-18, David 4 Nov: the spec said "when the hours open"; he chose 24 hours a day."""
    box = biz
    eid = _employee(box)
    box.ai_reset("good", {"hr:answer": [{"action": "hr_reply", "body": "ZAG you get five sick days a year.", "why": "ZAG", "confidence": 0.9}]})
    _hr_on(box, "answer")
    box.clock(box.today, "21:00")
    marks = _marks(box)
    _message(box, eid, "ZAG a late question about sick days?")
    box.agents_pass()
    props = [p for p in _new(box, marks, "HR")[1] if p["action"] == "hr_reply"]
    assert props and props[0]["status"] == "applied", props


def test_wf_11_a_reminder_still_keeps_to_the_hours(biz):
    box = biz
    box.ai_reset("good", {"hr:onboard": [{"action": "hr_remind_employee", "body": "ZAG please finish your forms.", "why": "ZAG", "confidence": 0.9}]})
    _hr_on(box, "onboard")
    box.clock(box.today, "21:00")
    marks = _marks(box)
    _employee(box)
    box.agents_pass()
    props = [p for p in _new(box, marks, "HR")[1] if p["action"] == "hr_remind_employee"]
    assert props and props[0]["status"] == "pending" and "outside the hours" in props[0]["hold_reason"], props


@pytest.mark.parametrize("access,sees", [("type_only", False), ("read", True)], ids=["type only", "read the report"])
def test_wf_12_incident_text_only_reaches_the_ai_if_allowed(biz, access, sees):
    box = biz
    box.ai_reset("good", {"hr:incidents": [{"action": "hr_note", "body": "ZAG noted", "why": "ZAG", "confidence": 0.9}]})
    from desk_agent_settings import HR_INCIDENTS
    keys = [k for k, _ in HR_INCIDENTS]
    key = access if access in keys else next(k for k in keys if k != "type_only" and k != "off")
    _hr_on(box, "incidents", agent_hr_incidents_access=key)
    st, j = box.hr("POST", "/incidents", {"type": "Injury", "description": INJURY})
    assert st == 200, j
    box.agents_pass()
    assert [c for c in box.ai_calls() if c.get("kind") == "hr"], "the incident wasn't looked at"
    assert bool(_ai_saw(box, "ZAGINJURYTEXT")) is sees


def test_wf_12_an_expiring_licence_warns_at_30_days(biz):
    box = biz
    eid = _employee(box)
    box.ai_reset("good", {"hr:compliance": [{"action": "hr_note", "body": "ZAG renew it", "why": "ZAG", "confidence": 0.9}]})
    _hr_on(box, "compliance", agent_hr_expiry_days=[30])
    st, j = box.hr("POST", "/training", {"employee_id": eid, "title": "ZAG licence renewal",
                                         "due_date": (box.today - dt.timedelta(days=1)).isoformat()})
    assert st in (200, 201), j
    marks = _marks(box)
    box.agents_pass()
    assert [q for q in _new(box, marks, "HR")[0] if q["stage"] == "compliance"]
