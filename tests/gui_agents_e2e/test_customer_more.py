"""AG-CP-18, 23, 24, 25, 26 and the wait list half of AG-WF-05."""
from __future__ import annotations

import datetime as dt
import re

import pytest

from conftest import http
from test_customer_pages import _address, _details, _open, _problem, _send_and_submit, _state, _view, _who, box  # noqa: F401
from test_guardrails_booking import _book as _book_api, _windows
from test_matrix import SD_STAGES, off_stages
from test_stage_grid import _sql

REPLY = "ZAG the agent answers: we can come back on Thursday."


def _go(person, box, token):
    who = person(box, "customer", phone=True)
    who.page.on("dialog", lambda d: d.accept("ZAG not yet") if d.type == "prompt" else d.accept())
    who.page.goto(f"{box.base}/support/t/{token}")
    return who, who.page


# ── CP-18 ────────────────────────────────────────────────────────────────────
def test_cp_18_reopen_a_closed_request(box, person):
    who, p, token = _problem(box, person)
    tid = _view(box, token)["ticket_id"]
    _state(box, tid, "Closed")
    p.reload()
    p.locator("#reopen").click()
    p.locator("#reopen").wait_for(state="detached")
    assert _view(box, token)["state"] != "Closed"


# ── CP-23 and WF-05 ──────────────────────────────────────────────────────────
def _visit_later(box):
    box.settings(desk={"booking_waitlist": True, "booking_approval": "auto"})
    keys = _windows(box)
    assert len(keys) > 6, keys
    _book_api(box, keys[-1])
    token = box.last_token
    t = _view(box, token)
    assert t["booking"]["state"] == "scheduled", t["booking"]
    return token, t["job_id"], keys


def test_cp_23_join_and_stop_waiting(box, person):
    token, jid, keys = _visit_later(box)
    who, p = _go(person, box, token)
    p.locator("#bkWait").click()
    p.locator("#bkWaiting").wait_for()
    p.locator("#bkUnwait").click()
    p.locator("#bkWait").wait_for()


def test_cp_23_wf_05_offered_an_earlier_time_and_takes_it(box, person):
    token, jid, keys = _visit_later(box)
    before = _sql(box, "SELECT service_date FROM jobs WHERE job_id = ?", (jid,))[0][0]
    who, p = _go(person, box, token)
    p.locator("#bkWait").click()
    p.locator("#bkWaiting").wait_for()
    box.agents_pass()
    p.reload()
    p.locator("#bkOffer").wait_for()
    assert _sql(box, "SELECT service_date FROM jobs WHERE job_id = ?", (jid,))[0][0] == before, "moved before they agreed"
    p.locator("#bkTake").click()
    p.locator("#bkOffer").wait_for(state="detached")
    v = _view(box, token)["booking"]               # taking it becomes a change request, then the usual approval decides
    assert v["state"] == "reschedule" and v["reschedule_to"], v
    assert _sql(box, "SELECT service_date FROM jobs WHERE job_id = ?", (jid,))[0][0] == before, "moved with no approval"


# ── CP-24 ────────────────────────────────────────────────────────────────────
def test_cp_24_pay_now_then_paid(box, person):
    box.control("POST", "/pay-stub", {"on": True})
    try:
        who, p = _open(box, person, "buy")
        p.locator("[data-buy='ZAG-PROD']").click()
        c = _who()
        _address(who)
        _details(who, c)
        token = _send_and_submit(who, box, c)
        o = _view(box, token)["order"]
        assert o["can_pay"] and o["pay_online"] and not o["paid"], o
        p.locator("#payNow").click()
        p.wait_for_url(re.compile("zagpaid="))
        assert "zagpaid=" + str(o["invoice_id"]) in p.url, p.url
        _sql(box, "UPDATE invoices SET payment_status = 'Paid', amount_paid = total_due WHERE invoice_id = ?", (o["invoice_id"],))
        assert _view(box, token)["order"]["paid"], _view(box, token)["order"]
        p.goto(f"{box.base}/support/t/{token}")
        p.locator("#order", has_text="Paid").wait_for()
    finally:
        box.control("POST", "/pay-stub", {})


# ── CP-25, 26 ────────────────────────────────────────────────────────────────
def _agent(box, practice):
    box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": REPLY, "why": "ZAG", "confidence": 0.9}]})
    box.settings(desk={"agent_enabled": True, "agent_shadow": practice, "agent_provider": "claude_api", "agent_batch_seconds": 0,
                       "agent_name": "Sunny", **off_stages("agent_stage_", SD_STAGES, "first_reply", "auto")})


def test_cp_25_the_agent_is_named_and_never_a_person(box, person):
    _agent(box, False)
    who, p, token = _problem(box, person)
    box.agents_pass()
    p.reload()
    msg = p.locator(".msg", has_text="ZAG the agent answers")
    msg.wait_for()
    text = msg.inner_text()
    prof = http("GET", box.base + "/support-api/agent")[1]
    assert prof["label"] and prof["label"].lower() in text.lower(), (prof, text)
    assert "Sunny" in text, (prof, text)


def test_cp_25_the_agents_photo_shows_on_its_messages(box, person):
    import desk_agent_settings as das
    from pathlib import Path
    from test_customer_pages import PNG
    db = Path(box.control("GET", "/state")["sandbox"]) / "tickets_database" / "ai_prowler_tickets.db"
    pic = das.photo_path(das._root(str(db)))
    pic.parent.mkdir(parents=True, exist_ok=True)
    pic.write_bytes(PNG)
    _agent(box, False)
    box.settings(desk={"agent_photo": das.PHOTO_REL})
    try:
        who, p, token = _problem(box, person, title="ZAG photo check")
        box.agents_pass()
        p.reload()
        msg = p.locator(".msg", has_text="ZAG the agent answers")
        msg.wait_for()
        img = msg.locator("img.agpic")
        img.wait_for()
        assert img.evaluate("i => i.complete && i.naturalWidth > 0"), "the photo didn't load"
        assert "Sunny" in msg.locator(".h").inner_text(), msg.locator(".h").inner_text()
        assert p.locator(".msg img.agpic").count() == 1, "only the agent's messages carry its photo"
    finally:
        box.settings(desk={"agent_photo": ""})


def test_cp_26_in_practice_the_customer_sees_nothing_from_the_agent(box, person):
    _agent(box, True)
    who, p, token = _problem(box, person)
    sent = len(box.outbox())
    box.agents_pass()
    p.reload()
    p.locator("#reply").wait_for()
    assert "ZAG the agent answers" not in p.content()
    assert "ZAG the agent answers" not in str(_view(box, token)["messages"])
    assert not [m for m in box.outbox()[sent:] if "ZAG the agent answers" in str(m)]
