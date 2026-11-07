"""AG-GR-19, 24, 28, 29 (AGENTS_GUI_E2E_TEST_SPEC.md §5.4). GR-28 and 29 use the Schedule stage's rule; the same "never today,
never Hard" check on the Route agent's week plan and re-plan is not separately covered here."""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START
from test_env import CUST_RE, JOB_RE
from test_guardrails import _done_job, _invoice_props, _invoice_setup, _invoice_sent
from test_customer_book_quote import _services
from test_guardrails_booking import _book, _windows
from test_matrix import BK_STAGES, JB_STAGES, _marks, _new, all_off, off_stages
from test_stage_grid import _sql

_n = itertools.count(1)
DRAFT = [{"action": "jb_draft_invoice", "why": "ZAG", "confidence": 0.9}]
SEND = [{"action": "jb_send_invoice", "channel": "email", "why": "ZAG", "confidence": 0.9}]


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.today = START + dt.timedelta(days=6000 + 40 * next(_n))
    while b.today.weekday() != 1:                       # a Tuesday: tomorrow and next week are working days
        b.today += dt.timedelta(days=1)
    b.clock(b.today, "10:00")
    yield b
    all_off(b)


# ── GR-24: the draft was changed, or doesn't match the job ──────────────────
@pytest.mark.parametrize("change", ["edited by a person", "amount differs from the job"])
def test_gr_24_changed_draft_waits_for_a_person(box, change):
    _invoice_setup(box, rule=DRAFT, can_send=False)     # sending off for now, or the send is picked up before the edit
    marks, sent0 = _marks(box), len(box.outbox())
    jid, email = _done_job(box)
    _sql(box, "UPDATE jobs SET service_date = ? WHERE job_id = ?", (box.today.isoformat(), jid))
    box.agents_pass()
    by, rows = _invoice_props(box, marks, jid)
    assert by["jb_draft_invoice"]["status"] == "applied", rows
    if change == "edited by a person":
        _sql(box, "UPDATE invoices SET last_edited_by = 'owner' WHERE job_id = ?", (jid,))
        why = "changed after the agent drafted it"
    else:
        _sql(box, "UPDATE invoices SET subtotal = subtotal + 25 WHERE job_id = ?", (jid,))
        why = "doesn't match the job's price"
    _invoice_setup(box, rule=SEND)
    box.clock(box.today, "10:30")                       # past the wait between runs
    box.agents_pass()
    by, rows = _invoice_props(box, marks, jid)
    assert by["jb_send_invoice"]["status"] == "pending" and why in by["jb_send_invoice"]["hold_reason"], rows
    assert not _invoice_sent(box, sent0, email)


# ── GR-28 and 29: a Hard job keeps its time; nothing goes on today ──────────
def _schedule_setup(box, date):
    box.ai_reset("good", {"job:schedule": [{"action": "jb_schedule", "date": date, "why": "ZAG", "confidence": 0.9}]})
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_shadow": False, **off_stages("agent_jb_stage_", JB_STAGES, "schedule", "auto")})


def _unscheduled(box, **more):
    n = next(_n)
    r = box.tool("create_customer", updates={"Customer Name / Company": f"ZAG Sched {n}", "Phone": "386-555-0178",
                                             "Street Address": "100 Flagler Ave", "City": "New Smyrna Beach", "State": "FL", "ZIP": "32169"})
    cid = re.search(CUST_RE, r).group(0)
    r = box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": f"ZAG Sched {n}", "Service Type": "Window",
                                        "Job Status": "Unscheduled", **more})
    return re.search(JOB_RE, r).group(0)


def _job_row(box, jid):
    return dict(_sql(box, "SELECT service_date, job_status, schedule_type FROM jobs WHERE job_id = ?", (jid,))[0])


def test_gr_28_a_hard_job_keeps_its_time(box):
    fixed = (box.today + dt.timedelta(days=7)).isoformat()
    other = (box.today + dt.timedelta(days=8)).isoformat()
    _schedule_setup(box, other)
    marks = _marks(box)
    jid = _unscheduled(box, **{"Service Date": fixed, "Schedule Type": "Hard"})
    assert _job_row(box, jid)["schedule_type"] == "Hard"
    box.agents_pass()
    assert _job_row(box, jid)["service_date"] == fixed
    assert not [p for p in _new(box, marks, "JB")[1] if p["ref"] == jid and p["status"] == "applied"]


def test_gr_29_nothing_is_put_on_today(box):
    _schedule_setup(box, box.today.isoformat())
    marks = _marks(box)
    jid = _unscheduled(box)
    box.agents_pass()
    assert not _job_row(box, jid)["service_date"]
    assert not [p for p in _new(box, marks, "JB")[1] if p["ref"] == jid and p["status"] == "applied"]


def test_gr_29_a_listed_date_works_so_the_refusals_above_mean_something(box):
    jid = _unscheduled(box)
    tomorrow = (box.today + dt.timedelta(days=1)).isoformat()
    _schedule_setup(box, tomorrow)
    box.agents_pass()
    assert _job_row(box, jid)["service_date"] == tomorrow


# ── GR-19: a weather suggestion needs a bad forecast ─────────────────────────
def test_gr_19_weather_suggestion_without_a_bad_forecast_is_held(box):
    box.settings(desk={"agent_enabled": True, "agent_shadow": False, "agent_bk_enabled": True, "agent_bk_shadow": False,
                       "agent_bk_weather": True, "agent_bk_check_hour": 9, "portal_enabled": True,
                       "booking_paths": ["book", "new", "problem"], "booking_approval": "approve_all",
                       **off_stages("agent_bk_stage_", BK_STAGES, "track", "auto")})
    _services(box)
    _book(box, _windows(box)[0])
    jid = _sql(box, "SELECT job_id FROM booking_requests ORDER BY rowid DESC LIMIT 1")[0][0]
    tomorrow = (box.today + dt.timedelta(days=1)).isoformat()
    _sql(box, "UPDATE booking_requests SET status = 'scheduled' WHERE job_id = ?", (jid,))
    _sql(box, "UPDATE jobs SET job_status = 'Scheduled', service_date = ? WHERE job_id = ?", (tomorrow, jid))
    _sql(box, "UPDATE booking_services SET outdoor = 1")
    later = _windows(box)[-1]
    box.ai_reset("good", {"booking:track": [{"action": "bk_suggest_time", "window_key": later, "note": "ZAG rain", "why": "ZAG", "confidence": 0.9}]})
    marks = _marks(box)
    box.agents_pass()
    props = [p for p in _new(box, marks, "BK")[1] if p["action"] == "bk_suggest_time"]
    assert props and props[0]["status"] != "applied" and "isn't bad enough" in props[0]["hold_reason"], props
