"""The final gap review, 5 Nov: real screens and signed-in users for what the suite didn't touch yet."""
from __future__ import annotations

import datetime as dt

import pytest

from conftest import USERS, http
from test_customer_pages import _problem, _view, box as cust_box  # noqa: F401 (a fixture)
from test_guardrails_booking import FIRST, _run as _bk_run, _setup as _bk_setup
from test_guardrails_booking import box as bk_box  # noqa: F401 (a fixture)
from test_matrix import SD_STAGES, _api_calls, _marks, _new, all_off, off_stages, setup, trigger
from test_stage_grid import _sql
from test_workflows_2 import _hr_on, biz  # noqa: F401 (a fixture)
from test_workflows_routes import _day, _job, _on, _pass

ANSWER = "ZAG you get five sick days a year."


# ── the HR Portal's assistant, signed in as an employee ──────────────────────
def _portal(person, box):
    who = person(box, "employee")
    p = who.page
    p.goto(box.base + "/hr_portal/")
    who.type("#login-name", USERS["cris"][0])
    who.type("#login-pass", box.tokens["cris"])
    p.locator("#login-btn").click()
    p.wait_for_selector("#app.visible", timeout=20_000)
    return who, p


def _ask(p, text):
    return p.evaluate("""async (q) => {
        const r = await fetch('/hr-api/ai-chat', {method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: q, ask_assistant: true})});
        return await r.json(); }""", text)


def _message_for(box, mid):
    st, d = box.hr("GET", "/messages")
    assert st == 200, d
    return [m for m in d.get("messages", d) if m.get("id") == mid][0]


def test_portal_assistant_answers_an_employee(biz, person):
    box = biz
    box.ai_reset("good", {"hr:answer": [{"action": "hr_reply", "body": ANSWER, "why": "ZAG", "confidence": 0.9}]})
    _hr_on(box, "answer")
    who, p = _portal(person, box)
    assert p.evaluate("async () => (await (await fetch('/hr-api/assistant')).json()).answers_on") is True
    out = _ask(p, "ZAG how many sick days do I get?")
    assert out.get("queued") and not out.get("sensitive"), out
    for _ in range(4):
        box.agents_pass()
        if ANSWER in str(_message_for(box, out["message_id"])):
            break
    assert ANSWER in str(_message_for(box, out["message_id"])), _message_for(box, out["message_id"])
    st = p.evaluate("""async (id) => { const r = await fetch('/hr-api/messages/talk-to-person', {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify({id})}); return r.status; }""", out["message_id"])
    assert st == 200
    assert _message_for(box, out["message_id"]).get("needs_person") is True


def test_portal_a_sensitive_question_goes_to_a_person_and_never_the_ai(biz, person):
    box = biz
    box.ai_reset("good", {"hr:answer": [{"action": "hr_reply", "body": ANSWER, "why": "ZAG", "confidence": 0.9}]})
    _hr_on(box, "answer")
    who, p = _portal(person, box)
    text = "ZAG my supervisor is harassing me"
    out = _ask(p, text)
    assert out.get("sensitive") and "person at HR" in out["reply"], out
    box.agents_pass()
    assert not [c for c in box.ai_calls() if text in str(c)]


def test_portal_says_so_while_hr_is_practicing(biz, person):
    box = biz
    _hr_on(box, "answer")
    box.settings(hr={"agent_hr_shadow": True})
    who, p = _portal(person, box)
    out = _ask(p, "ZAG anything?")
    assert not out.get("queued") and "isn't answering" in out["reply"], out


# ── managers: the real sign-in, chat tool and screen ─────────────────────────
def _rpc(box, token, body, session=""):
    import json
    import urllib.request
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": f"Bearer {token}"}
    if session:
        h["Mcp-Session-Id"] = session
    req = urllib.request.Request(box.base + "/mcp", data=json.dumps(body).encode(), headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read().decode("utf-8", "replace")
        sid = r.headers.get("Mcp-Session-Id") or session
    for line in text.splitlines():
        if line.startswith("data:"):
            text = line[5:]
    return sid, (json.loads(text) if text.strip() else {})


def _chat(box, key, tool, **args):
    """What a person's chat does: the real MCP endpoint, with that person's own token."""
    sid, _ = _rpc(box, box.tokens[key], {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "zag", "version": "1"}}})
    _rpc(box, box.tokens[key], {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    _, out = _rpc(box, box.tokens[key], {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}}, sid)
    assert "result" in out or "error" in out, out
    return str(out)


@pytest.fixture
def two_queues(biz):
    box = biz
    setup(box, "SD", "SUG")
    box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": "ZAG draft", "why": "ZAG", "confidence": 0.9}]})
    marks = _marks(box)
    shared, other = trigger(box, "SD"), trigger(box, "SD")
    import sqlite3
    from pathlib import Path
    conn = sqlite3.connect(Path(box.control("GET", "/state")["sandbox"]) / "tickets_database" / "ai_prowler_tickets.db")
    conn.execute("UPDATE tickets SET queue_id = 'q-not-theirs' WHERE ticket_id = ?", (other,))
    conn.commit()
    conn.close()
    return box, marks, shared, other


def test_a_chat_can_not_do_the_agents_work(biz):
    """David 5 Nov: a chat uses the normal tools; the tools that took the agent's queue are gone."""
    setup(biz, "SD", "SUG")
    trigger(biz, "SD")
    for tool in ("desk_agent_next", "desk_agent_submit"):
        out = _chat(biz, "owner", tool)
        assert "item_id" not in out and "unknown tool" in out.lower(), (tool, out[:300])


def test_manager_chat_review_only_shows_their_scope(two_queues):
    box, marks, shared, other = two_queues
    box.agents_pass()
    box.agents_pass()
    out = _chat(box, "manager", "desk_agent_review")
    assert shared in out and other not in out, out[:600]
    assert other in _chat(box, "owner", "desk_agent_review")


@pytest.mark.parametrize("key", ["staff", "cris"])
def test_other_roles_can_not_use_the_agent_tools(biz, key):
    setup(biz, "SD", "SUG")
    trigger(biz, "SD")
    biz.agents_pass()
    for tool in ("desk_agent_review", "desk_agent_status", "desk_agent_run_now"):
        out = _chat(biz, key, tool)
        assert "only the owner or a manager" in out.lower() or "only the owner" in out.lower() or "unknown tool" in out.lower(), (tool, out[:400])


def test_the_portal_has_no_ai_assistant_with_no_key(biz, person):
    box = biz
    _hr_on(box, "answer")
    box.no_key()
    try:
        who, p = _portal(person, box)
        assert p.evaluate("async () => (await (await fetch('/hr-api/assistant')).json()).answers_on") is False
        out = _ask(p, "ZAG anything?")
        assert not out.get("queued") and "isn't answering" in out["reply"], out
        assert "AI Assistant" not in p.content()
    finally:
        box.no_key(False)


def test_with_no_key_a_customer_gets_no_ai_reply_and_a_person_can_answer(biz):
    box = biz
    setup(box, "SD", "AUTO")
    box.no_key()
    try:
        sent, marks = len(box.outbox()), _marks(box)
        tid = trigger(box, "SD")
        box.agents_pass()
        assert _new(box, marks, "SD") == ([], [])
        out = box.tool("reply_to_customer", ticket_id=tid, message="ZAG a person answers", preview=False)     # the normal tool, as before the agents
        assert "❌" not in str(out), out
        import time
        for _ in range(50):                 # delivery happens in the background
            if [m for m in box.outbox()[sent:] if "ZAG a person answers" in str(m)]:
                break
            time.sleep(0.1)
        assert [m for m in box.outbox()[sent:] if "ZAG a person answers" in str(m)], box.outbox()[sent:]
    finally:
        box.no_key(False)


def test_manager_agent_tab_shows_only_their_scope(two_queues, person):
    box, marks, shared, other = two_queues
    box.agents_pass()
    box.agents_pass()
    props = {p["ref"]: p for p in _new(box, marks, "SD")[1]}
    assert shared in props and other in props, props
    who = person(box, "manager")
    who.desk_sign_in("manager")
    who.page.locator("#tabAgent").click()
    who.page.locator(".agp", has_text=shared).first.wait_for()
    assert not who.page.locator(".agp", has_text=other).count()
    st, d = box.desk("POST", f"/agent/proposals/{props[other]['proposal_id']}/approve", {}, key="manager")
    assert st != 200 and "outside" in str(d), (st, d)
    assert box.desk("POST", f"/agent/proposals/{props[other]['proposal_id']}/approve", {})[0] == 200


# ── how the agents run ───────────────────────────────────────────────────────
@pytest.mark.parametrize("edition", ["solo", "business"])
def test_an_old_cli_setting_runs_on_the_saved_key(request, edition):
    box = request.getfixturevalue(edition)
    all_off(box)
    try:
        setup(box, "SD", "SUG")
        box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": "ZAG", "why": "ZAG", "confidence": 0.9}]})
        box.no_runner("claude_code")
        assert box.desk("GET", "/agent/inbox")[1]["status"]["provider"] == "claude_api"
        marks = _marks(box)
        tid = trigger(box, "SD")
        box.agents_pass()
        assert _api_calls(box, "ticket") and [p for p in _new(box, marks, "SD")[1] if p["ref"] == tid]
    finally:
        box.settings(desk={"agent_provider": "claude_api"})
        all_off(box)


# ── practice totals, for the two agents not yet seen on a screen ─────────────
def test_booking_practice_total_shows_by_agent(bk_box, person):
    box = bk_box
    _bk_setup(box, mode="suggest")
    box.settings(desk={"agent_bk_shadow": True})
    p, *_ = _bk_run(box, FIRST)
    try:
        assert p["status"] == "practice", p
        assert box.desk("POST", f"/agent/proposals/{p['proposal_id']}/up", {})[0] == 200
        who = person(box, "owner")
        who.desk_sign_in("owner")
        who.page.locator("#tabAgent").click()
        who.page.locator("#agRatings [data-rated='booking']", has_text="good").wait_for()
    finally:
        box.settings(desk={"agent_bk_shadow": False})


def test_route_practice_total_shows_by_agent(solo, person):
    box = solo
    all_off(box)
    try:
        tue = _day(1)
        box.clock(tue, "10:00")
        _job(box, tue + dt.timedelta(days=1))
        box.ai_reset("good", {"route:route": [{"action": "rt_route_day", "why": "ZAG", "confidence": 0.9}]})
        _on(box, "route", agent_jb_rt_shadow=True)
        marks = _marks(box)
        got = _pass(box, marks, "rt_route_day")
        assert got and got[0]["status"] == "practice", got
        assert box.tool("jobs_agent", action="down", proposal_id=f"J{got[0]['proposal_id']}")
        who = person(box, "owner")
        who.jobs_sign_in("owner")
        who.page.locator("#navAgent").click()
        who.page.locator("#agRatings [data-rated='route']", has_text="not right").wait_for()
    finally:
        all_off(box)


# ── the customer page ────────────────────────────────────────────────────────
def test_cp_18_a_subcontractor_marks_their_part_done(cust_box, person):
    box = cust_box
    d = box.control("POST", "/sub-link", {"name": "ZAG Dan", "phone": "386-555-0177"})
    who = person(box, "subcontractor", phone=True)
    who.page.goto(f"{box.base}/support/t/{d['token']}")
    who.page.locator("#done").click()
    who.page.locator("#done").wait_for(state="detached")
    assert _view(box, d["token"])["state"] == "Fixed"


def test_cp_25_the_agent_is_named_on_business_too(biz, person):
    from test_customer_business import _services
    box = biz
    box.settings(desk={"portal_enabled": True, "booking_paths": ["book", "new", "problem"], "agent_enabled": True, "agent_shadow": False, "agent_provider": "claude_api",
                       "agent_name": "Sunny", **off_stages("agent_stage_", SD_STAGES, "first_reply", "auto")})
    _services(box)
    box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": "ZAG from the agent", "why": "ZAG", "confidence": 0.9}]})
    tid = trigger(box, "SD")
    box.agents_pass()
    box.agents_pass()
    st, d = box.desk("GET", f"/tickets/{tid}")
    msgs = d.get("messages") or (d.get("ticket") or {}).get("messages") or []
    assert st == 200 and [m for m in msgs if "ZAG from the agent" in m["body"] and "Sunny" in m["body"]], (list(d), msgs)


# ── crew: no agent controls on their screens (WF-07) ─────────────────────────
def test_wf_07_crew_see_no_agent_controls_in_the_app(biz, person):
    owner = person(biz, "owner")
    owner.jobs_sign_in("owner")
    owner.page.locator("#navAgent").wait_for()                       # the check below means something
    who = person(biz, "crew")
    who.jobs_sign_in("cris")
    who.page.locator("nav, #navJobs, .bottom-nav").first.wait_for()
    who.page.wait_for_timeout(1500)
    assert not who.page.locator("#navAgent").is_visible()


# ── AG-SAFE-05: nothing above left a database damaged ────────────────────────
@pytest.mark.parametrize("edition", ["solo", "business"])
def test_safe_05_every_database_is_whole(request, edition):
    out = request.getfixturevalue(edition).control("POST", "/integrity", {})
    assert out and all(v == "ok" for v in out.values()), out
