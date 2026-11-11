"""Service Desk Phase 2 — desk_portal: request form, codes, status links,
customer/subcontractor actions, rating, and the /support-api router."""
import datetime
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402

UTC = datetime.timezone.utc


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    sent = []
    p.send_fn = lambda ch, to, subj, text: sent.append((ch, to, subj, text)) or True
    yield path, sent
    p.send_fn = None


def code_from(sent):
    return re.search(r"\b(\d{6})\b", sent[-1][3]).group(1)


def file_request(db, sent, phone="386-555-0100", title="Streaky windows", ip="1.2.3.4"):
    s = p.start_request(db, name="Mrs. Lopez", phone=phone, ip=ip)
    return p.verify_and_file(db, contact_id=s["contact_id"], code=code_from(sent), title=title,
                             ip=ip, edition=r.SOLO, base_url="https://desk.example")


def test_code_by_text_then_ticket_and_link(db):
    db, sent = db
    out = file_request(db, sent)
    assert sent[0][0] == "sms" and sent[0][1] == "+13865550100" and "code" in sent[0][3]
    assert out["ticket_id"] == "T-0001" and out["url"].startswith("https://desk.example/support/t/")
    t = desk_db.get_ticket(db, "T-0001")
    assert t["source"] == "portal" and t["assignee"] == "owner" and t["filed_by"] == "contact:CT-0001"
    assert desk_db.get_contact(db, "CT-0001")["verified_at"]
    assert "Track it here" in sent[-1][3]
    # the token is stored only as a hash
    con = desk_db.get_connection(db)
    try:
        assert out["token"] not in json.dumps([dict(x) for x in con.execute("SELECT * FROM ticket_links")])
    finally:
        con.close()


def test_email_code_when_chosen_and_phone_always_required(db):
    """2026-10-30 (booking-spec.md §3.1): a phone number is required on every request so the
    team can call back; the code goes by email when the customer chooses email."""
    db, sent = db
    with pytest.raises(p.desk_db.DeskError, match="enter a phone number"):
        p.start_request(db, email="L@Example.com")
    p.start_request(db, phone="386-555-0100", email="L@Example.com", send_by="email")
    assert sent[0][0] == "email" and sent[0][1] == "l@example.com"


def test_wrong_code_attempts_and_expiry(db):
    db, sent = db
    s = p.start_request(db, phone="386-555-0100", ip="1.1.1.1")
    for _ in range(p.CODE_MAX_ATTEMPTS):
        with pytest.raises(desk_db.DeskError, match="not right"):
            p.verify_and_file(db, contact_id=s["contact_id"], code="000000", title="x", edition=r.SOLO)
    with pytest.raises(desk_db.DeskError, match="expired"):
        p.verify_and_file(db, contact_id=s["contact_id"], code=code_from(sent), title="x", edition=r.SOLO)
    s = p.start_request(db, phone="386-555-0100", ip="1.1.1.1")
    later = datetime.datetime.now(UTC) + datetime.timedelta(minutes=p.CODE_TTL_MINUTES + 1)
    with pytest.raises(desk_db.DeskError, match="expired"):
        p.verify_and_file(db, contact_id=s["contact_id"], code=code_from(sent), title="x",
                          edition=r.SOLO, now=later)


def test_honeypot_bots_are_dropped_silently(db):
    db, sent = db
    out = p.start_request(db, phone="386-555-0100", honeypot="http://spam")
    assert out["ok"] and out["contact_id"] == "" and sent == []
    assert desk_db.find_contact(db, phone="386-555-0100") is None


def test_rate_limits(db):
    db, sent = db
    for _ in range(5):
        p.start_request(db, phone="386-555-0100", ip="9.9.9.9")
    with pytest.raises(desk_db.DeskError, match="too many codes"):
        p.start_request(db, phone="386-555-0100", ip="8.8.8.8")


def test_portal_switch(db):
    db, sent = db
    desk_db.set_setting(db, "portal_enabled", False, edition=r.SOLO)
    with pytest.raises(desk_db.DeskError, match="turned off"):
        p.start_request(db, phone="386-555-0100")


def test_link_sees_only_its_ticket_and_public_thread(db):
    db, sent = db
    a = file_request(db, sent, phone="386-555-0100", title="A")
    b = file_request(db, sent, phone="386-555-0111", title="B")
    desk_db.add_message(db, "T-0001", "internal: picky", edition=r.SOLO)
    desk_db.add_message(db, "T-0001", "On our way", edition=r.SOLO, visibility="public")
    v = p.status_view(db, a["token"], edition=r.SOLO)
    assert v["ticket_id"] == "T-0001" and [m["body"] for m in v["messages"]] == ["On our way"]
    assert "events" not in v and v["who"]["role"] == "customer"
    st, ct, body = p.route("GET", f"/support-api/t/{a['token']}/attachments/999", query={},
                           body=b"", content_type="", ip="", db_path=db, edition=r.SOLO)
    assert st == 404
    st, ct, body = p.route("GET", f"/support-api/t/{b['token']}", query={}, body=b"",
                           content_type="", ip="", db_path=db, edition=r.SOLO)
    assert json.loads(body)["ticket"]["ticket_id"] == "T-0002"


def test_bad_or_revoked_link_is_404(db):
    db, sent = db
    a = file_request(db, sent)
    st, ct, body = p.route("GET", "/support-api/t/" + "x" * 43, query={}, body=b"",
                           content_type="", ip="", db_path=db, edition=r.SOLO)
    assert st == 404
    # crew can't see the ticket at all -> refused before the revoke check (both are refusals)
    with pytest.raises(desk_db.DeskError, match="only the owner or a manager|no ticket"):
        p.revoke_links(db, "T-0001", actor={"id": "c", "role": "field_crew"}, edition=r.BUSINESS)
    with pytest.raises(desk_db.DeskError, match="only the owner or a manager"):
        p.revoke_links(db, "T-0001", actor={"id": "owner", "role": "field_crew"},
                       edition=r.BUSINESS)            # assignee, but not a lead
    assert p.revoke_links(db, "T-0001", edition=r.SOLO) == 1
    with pytest.raises(desk_db.NotFoundError):
        p.resolve_link(db, a["token"])


def test_link_expires_30_days_after_close(db):
    db, sent = db
    a = file_request(db, sent)
    desk_db.change_state(db, "T-0001", r.CLOSED, edition=r.SOLO, reason="done")
    p.resolve_link(db, a["token"])
    later = datetime.datetime.now(UTC) + datetime.timedelta(days=31)
    with pytest.raises(desk_db.NotFoundError):
        p.resolve_link(db, a["token"], now=later)


def test_customer_confirm_reject_reopen_and_rate_through_router(db):
    db, sent = db
    a = file_request(db, sent)

    def go(method, rest, body=None):
        st, ct, out = p.route(method, f"/support-api/t/{a['token']}{rest}", query={},
                              body=json.dumps(body).encode() if body else b"", content_type="application/json",
                              ip="", db_path=db, edition=r.SOLO)
        return st, json.loads(out)

    desk_db.change_state(db, "T-0001", r.IN_PROGRESS, edition=r.SOLO)
    desk_db.change_state(db, "T-0001", r.FIXED, edition=r.SOLO)
    assert go("GET", "")[1]["ticket"]["can_confirm"] is True
    st, d = go("POST", "/state", {"to_state": "In Progress", "reason": "still streaky"})
    assert st == 200 and desk_db.get_ticket(db, "T-0001")["state"] == r.IN_PROGRESS
    desk_db.change_state(db, "T-0001", r.FIXED, edition=r.SOLO)
    assert go("POST", "/state", {"to_state": "Closed"})[0] == 200
    v = go("GET", "")[1]["ticket"]
    assert v["can_rate"] and v["can_reopen"] and not v["can_confirm"]
    assert go("POST", "/rating", {"score": 9})[0] == 400
    assert go("POST", "/rating", {"score": 5, "comment": "Great job"})[0] == 200
    assert go("POST", "/rating", {"score": 4})[1]["message"].startswith("thanks")
    assert desk_db.get_ticket(db, "T-0001")["csat_score"] == 5
    assert go("POST", "/state", {"to_state": "Assigned", "reason": "spots came back"})[0] == 200
    assert go("POST", "/reply", {"body": "Photos coming"})[0] == 201
    st, d = go("POST", "/state", {"to_state": "Closed", "reason": "x"})
    assert st == 400


def test_subcontractor_link_marks_part_done(db):
    db, sent = db
    s = desk_db.upsert_contact(db, name="Dan", phone="386-555-0199", contact_type="subcontractor")
    t = desk_db.create_ticket(db, title="Drywall", kind="subcontractor", contact_id=s["contact_id"],
                              edition=r.SOLO)
    token = p.issue_link(db, t["ticket_id"], s["contact_id"])
    v = p.status_view(db, token, edition=r.SOLO)
    assert v["can_mark_done"] and not v["can_rate"] and v["who"]["role"] == "subcontractor"
    st, ct, body = p.route("POST", f"/support-api/t/{token}/state", query={},
                           body=b'{"to_state": "Fixed"}', content_type="application/json", ip="",
                           db_path=db, edition=r.SOLO)
    assert st == 200 and desk_db.get_ticket(db, t["ticket_id"])["state"] == r.FIXED


def test_router_start_verify_and_upload(db):
    db, sent = db

    def go(method, path, body=b"", ctype="application/json"):
        st, ct, out = p.route(method, path, query={}, body=body, content_type=ctype, ip="5.5.5.5",
                              db_path=db, edition=r.SOLO, business="Vavro Field Services")
        return st, (json.loads(out) if ct == b"application/json" else out)

    assert go("GET", "/support-api/info")[1]["business"] == "Vavro Field Services"
    st, d = go("POST", "/support-api/start", json.dumps({"phone": "386-555-0100"}).encode())
    assert st == 200
    st, d = go("POST", "/support-api/verify",
               json.dumps({"contact_id": d["contact_id"], "code": code_from(sent), "title": ""}).encode())
    assert st == 400 and "what you need" in d["message"]
    st, d = go("POST", "/support-api/verify",
               json.dumps({"contact_id": "CT-0001", "code": code_from(sent), "title": "Gutters"}).encode())
    assert st == 201
    boundary = "b0undary"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"q.pdf\"\r\n\r\n"
            f"%PDF-1.4\r\n--{boundary}--\r\n").encode()
    st, d2 = go("POST", f"/support-api/t/{d['token']}/attachments", body,
                f"multipart/form-data; boundary={boundary}")
    assert st == 201 and d2["attachments"][0]["filename"] == "0001_q.pdf"
    st, f = go("GET", f"/support-api/t/{d['token']}/attachments/{d2['attachments'][0]['attachment_id']}")
    assert st == 200 and f.startswith(b"%PDF")
    st, d3 = go("POST", "/support-api/teleport")
    assert st == 404


def test_static_page_is_the_support_app():
    st, ct, body = p.static_page("/support/new")
    assert st == 200 and b"Request service" in body


# ── Ask the AI assistant (2026-11-10) ─────────────────────────────────────────
# The customer-facing chat on the status page: a question goes to the agent,
# answered from this ticket only, and the run is recorded so the monthly budget
# meter counts it. The provider is monkeypatched — no API key, no token cost.


def _enable_agent(db):
    desk_db.set_setting(db, "agent_enabled", True, edition=r.SOLO)
    desk_db.set_setting(db, "agent_provider", "claude_api", edition=r.SOLO)


def _ask(db, token, q):
    st, ct, out = p.route("POST", f"/support-api/t/{token}/ask", query={},
                          body=json.dumps({"question": q}).encode(),
                          content_type="application/json", ip="", db_path=db, edition=r.SOLO)
    return st, json.loads(out)


def test_ask_assistant_answers_and_records_a_run(db, monkeypatch):
    db, sent = db
    a = file_request(db, sent)
    _enable_agent(db)
    import desk_agent_providers as prov
    calls = []
    monkeypatch.setattr(prov, "ready", lambda p: (True, ""))

    def fake_ask(provider, system, user, model=""):
        calls.append((provider, system, user, model))
        return "Your visit is Thursday 9-11.", {"input": 120, "output": 15,
                                                "cache_read": 0, "cache_write": 0}
    monkeypatch.setattr(prov, "ask", fake_ask)
    st, d = _ask(db, a["token"], "When are you coming?")
    assert st == 200
    assert d["ok"] and d["answer"] == "Your visit is Thursday 9-11."
    # the prompt is grounded in this ticket only
    assert "T-0001" in calls[0][2] and "Streaky windows" in calls[0][2]
    # the run is recorded, so the budget meter counts the answer
    con = desk_db.get_connection(db)
    try:
        runs = [dict(x) for x in con.execute("SELECT * FROM agent_runs")]
    finally:
        con.close()
    assert len(runs) == 1 and runs[0]["summary"] == "customer ask" and runs[0]["ok"] == 1


def test_ask_assistant_rejects_empty_and_long(db, monkeypatch):
    db, sent = db
    a = file_request(db, sent)
    _enable_agent(db)
    import desk_agent_providers as prov
    monkeypatch.setattr(prov, "ready", lambda p: (True, ""))
    monkeypatch.setattr(prov, "ask", lambda *a_, **k: ("x", {"input": 1, "output": 1}))
    st, d = _ask(db, a["token"], "")
    assert st == 400 and "write your question" in d["message"]
    st, d = _ask(db, a["token"], "x" * 501)
    assert st == 400 and "under 500" in d["message"]


def test_ask_assistant_off_and_no_key(db, monkeypatch):
    db, sent = db
    a = file_request(db, sent)
    # agent off
    st, d = _ask(db, a["token"], "hi")
    assert st == 400 and "assistant is off" in d["message"]
    # agent on but no key saved
    _enable_agent(db)
    import desk_agent_providers as prov
    monkeypatch.setattr(prov, "ready", lambda p: (False, "no Claude API key saved"))
    st, d = _ask(db, a["token"], "hi")
    assert st == 400 and "no Claude API key saved" in d["message"]


# ── Ask the AI assistant, general (2026-11-10) ───────────────────────────────
# The same chat on the "How can we help?" page, before there is a ticket: the
# visitor asks a general question and the assistant answers from the business's
# public facts only (services/products offered online, welcome text). Same gates
# and budget recording as the ticket ask; the provider is monkeypatched.


def _ask_general(db, q):
    st, ct, out = p.route("POST", "/support-api/ask", query={},
                          body=json.dumps({"question": q}).encode(),
                          content_type="application/json", ip="", db_path=db, edition=r.SOLO)
    return st, json.loads(out)


def test_ask_general_answers_from_public_facts(db, monkeypatch):
    db, sent = db
    _enable_agent(db)
    desk_db.set_setting(db, "booking_welcome", "Welcome to Blue Wave", edition=r.SOLO)
    import desk_agent_providers as prov
    calls = []
    monkeypatch.setattr(prov, "ready", lambda p: (True, ""))

    def fake_ask(provider, system, user, model=""):
        calls.append((provider, system, user, model))
        return "We clean windows and gutters.", {"input": 90, "output": 12,
                                                 "cache_read": 0, "cache_write": 0}
    monkeypatch.setattr(prov, "ask", fake_ask)
    st, d = _ask_general(db, "What do you do?")
    assert st == 200
    assert d["ok"] and d["answer"] == "We clean windows and gutters."
    # the prompt is grounded in the business's public facts and the question
    assert "Welcome to Blue Wave" in calls[0][2] and "What do you do?" in calls[0][2]
    # the run is recorded, so the budget meter counts the answer
    con = desk_db.get_connection(db)
    try:
        runs = [dict(x) for x in con.execute("SELECT * FROM agent_runs")]
    finally:
        con.close()
    assert len(runs) == 1 and runs[0]["summary"] == "visitor ask" and runs[0]["ok"] == 1


def test_ask_general_rejects_empty_and_long(db, monkeypatch):
    db, sent = db
    _enable_agent(db)
    import desk_agent_providers as prov
    monkeypatch.setattr(prov, "ready", lambda p: (True, ""))
    monkeypatch.setattr(prov, "ask", lambda *a_, **k: ("x", {"input": 1, "output": 1}))
    st, d = _ask_general(db, "")
    assert st == 400 and "write your question" in d["message"]
    st, d = _ask_general(db, "x" * 501)
    assert st == 400 and "under 500" in d["message"]


def test_ask_general_off_and_no_key(db, monkeypatch):
    db, sent = db
    # agent off
    st, d = _ask_general(db, "hi")
    assert st == 400 and "assistant is off" in d["message"]
    # agent on but no key saved
    _enable_agent(db)
    import desk_agent_providers as prov
    monkeypatch.setattr(prov, "ready", lambda p: (False, "no Claude API key saved"))
    st, d = _ask_general(db, "hi")
    assert st == 400 and "no Claude API key saved" in d["message"]


# ── the three controls (2026-11-10): who can ask, what it answers, rate limit ──

def _ask_general_full(db, q, page="landing", ask_token="", ip="1.2.3.4"):
    st, ct, out = p.route("POST", "/support-api/ask", query={},
                          body=json.dumps({"question": q, "page": page,
                                           "ask_token": ask_token}).encode(),
                          content_type="application/json", ip=ip, db_path=db, edition=r.SOLO)
    return st, json.loads(out)


def _fake_provider(monkeypatch):
    import desk_agent_providers as prov
    calls = []
    monkeypatch.setattr(prov, "ready", lambda p: (True, ""))

    def fake_ask(provider, system, user, model=""):
        calls.append((provider, system, user, model))
        return "An answer.", {"input": 90, "output": 12, "cache_read": 0, "cache_write": 0}
    monkeypatch.setattr(prov, "ask", fake_ask)
    return calls


def test_ask_who_ticket_refuses_general_ask(db, monkeypatch):
    db, sent = db
    _enable_agent(db)
    _fake_provider(monkeypatch)
    desk_db.set_setting(db, "agent_ask_who", "ticket", edition=r.SOLO)
    st, d = _ask_general_full(db, "What do you do?")
    assert st == 400 and "service request" in d["message"]


def test_ask_who_verified_needs_token_then_asks(db, monkeypatch):
    db, sent = db
    _enable_agent(db)
    _fake_provider(monkeypatch)
    desk_db.set_setting(db, "agent_ask_who", "verified", edition=r.SOLO)
    # no token: refused
    st, d = _ask_general_full(db, "What do you do?")
    assert st == 400 and "verify first" in d["message"]
    # a wrong token: refused the same way
    st, d = _ask_general_full(db, "What do you do?", ask_token="bogus")
    assert st == 400 and "verify first" in d["message"]
    # the verify flow: a code arrives by text, the code verifies, a token comes back
    s = p.start_ask_code(db, phone="386-555-0100", ip="1.2.3.4")
    assert s["ok"] and sent[-1][0] == "sms" and "verification code" in sent[-1][3]
    code = code_from(sent)
    out = p.verify_ask_code(db, contact_id=s["contact_id"], code=code, ip="1.2.3.4")
    assert out["ok"] and out["ask_token"]
    # asking with the token works
    st, d = _ask_general_full(db, "What do you do?", ask_token=out["ask_token"])
    assert st == 200 and d["ok"] and d["answer"] == "An answer."


def test_ask_verify_wrong_code_refused(db):
    db, sent = db
    s = p.start_ask_code(db, phone="386-555-0100", ip="1.2.3.4")
    code = code_from(sent)
    wrong = "000000" if code != "000000" else "111111"
    with pytest.raises(desk_db.DeskError, match="not right"):
        p.verify_ask_code(db, contact_id=s["contact_id"], code=wrong, ip="1.2.3.4")
    # the right code still works after one wrong try
    out = p.verify_ask_code(db, contact_id=s["contact_id"], code=code, ip="1.2.3.4")
    assert out["ok"] and out["ask_token"]
    # the code is single-use: a second verify with it is refused
    with pytest.raises(desk_db.DeskError):
        p.verify_ask_code(db, contact_id=s["contact_id"], code=code, ip="1.2.3.4")


def test_ask_codes_do_not_clash_with_request_codes(db):
    db, sent = db
    # an ask code and a request code for the same phone live side by side
    a = p.start_ask_code(db, phone="386-555-0100", ip="1.2.3.4")
    ask_code = code_from(sent)
    s = p.start_request(db, name="Mrs. Lopez", phone="386-555-0100", ip="1.2.3.4")
    req_code = code_from(sent)
    assert ask_code != req_code
    # each verifies through its own flow
    out = p.verify_ask_code(db, contact_id=a["contact_id"], code=ask_code, ip="1.2.3.4")
    assert out["ok"]
    filed = p.verify_and_file(db, contact_id=s["contact_id"], code=req_code, title="Streaky windows",
                              ip="1.2.3.4", edition=r.SOLO, base_url="https://desk.example")
    assert filed["ticket_id"] == "T-0001"


def test_ask_rate_limit_per_hour(db, monkeypatch):
    db, sent = db
    _enable_agent(db)
    _fake_provider(monkeypatch)
    desk_db.set_setting(db, "agent_ask_per_hour", 1, edition=r.SOLO)
    st, d = _ask_general_full(db, "First question?")
    assert st == 200
    st, d = _ask_general_full(db, "Second question?")
    assert st == 400 and "asked a lot" in d["message"]
    # a different visitor (different IP) is not blocked
    st, d = _ask_general_full(db, "Another visitor?", ip="5.6.7.8")
    assert st == 200
    # 0 = no limit
    desk_db.set_setting(db, "agent_ask_per_hour", 0, edition=r.SOLO)
    st, d = _ask_general_full(db, "Third question?")
    assert st == 200
    st, d = _ask_general_full(db, "Fourth question?")
    assert st == 200


def test_ask_page_scopes_facts_and_toggles(db, monkeypatch):
    db, sent = db
    _enable_agent(db)
    calls = _fake_provider(monkeypatch)
    # the book page is told the visitor is booking; the buy page is told they are shopping
    st, d = _ask_general_full(db, "When can you come?", page="book")
    assert st == 200
    assert "booking a service" in calls[0][2]
    st, d = _ask_general_full(db, "How much is it?", page="buy")
    assert st == 200
    assert "shopping for products" in calls[1][2]
    # turning services off removes them from the facts the model gets
    desk_db.set_setting(db, "agent_ask_services", False, edition=r.SOLO)
    calls.clear()
    st, d = _ask_general_full(db, "What services do you offer?", page="book")
    assert st == 200
    assert "Services offered:\n(none listed)" in calls[0][2]
    # an unknown page falls back to the main page
    st, d = _ask_general_full(db, "Hi", page="nope")
    assert st == 200 and "How can we help?" in calls[1][2]


def test_ask_assistant_rate_limit(db, monkeypatch):
    db, sent = db
    a = file_request(db, sent)
    _enable_agent(db)
    _fake_provider(monkeypatch)
    desk_db.set_setting(db, "agent_ask_per_hour", 1, edition=r.SOLO)
    token = a["url"].rsplit("/t/", 1)[1]
    st, d = _ask(db, token, "First?")
    assert st == 200
    st, d = _ask(db, token, "Second?")
    assert st == 400 and "asked a lot" in d["message"]


def test_ask_general_string_prices_do_not_500(db, monkeypatch):
    # 2026-11-10 live /support/new: the Jobs DB prices services as text
    # ("from $500", "from $120"), not numbers. ask_general formatted them with
    # :,.2f, which raised ValueError, and route() only catches DeskError, so
    # the whole /ask call 500'd and the page showed "Something went wrong".
    # _fmt_price renders text prices as-is and numbers as ($X.XX).
    db, sent = db
    _enable_agent(db)
    calls = _fake_provider(monkeypatch)
    monkeypatch.setattr(
        p, "_public_offerings",
        lambda db_path, s: (
            [{"code": "Prod-001", "name": "AI Prowler Server HW",
              "description": "Mini server", "price": "from $500"},
             {"code": "Serv-0001", "name": "Business Install",
              "description": "", "price": "from $120"}],
            [{"code": "Prod-001", "name": "AI Prowler Server HW",
              "description": "Mini server", "unit_price": 500.0}]))
    st, d = _ask_general_full(db, "What products do you offer?")
    assert st == 200 and d["ok"] and d["answer"] == "An answer."
    user_prompt = calls[0][2]
    assert "from $500" in user_prompt and "from $120" in user_prompt
    assert "$500.00" in user_prompt


def test_ask_general_reads_full_specs_not_just_the_tile(db, monkeypatch):
    # 2026-11-10 live /support/new Buy page: the product tile shows the full
    # specs (16GB DDR5 RAM, Ryzen 7 Pro 8845HS), but the assistant answered
    # "I don't have information on how much RAM it has" — _public_offerings
    # kept only name/description/price and threw the specs away. The specs,
    # shipping and duration now travel with the facts.
    db, sent = db
    _enable_agent(db)
    calls = _fake_provider(monkeypatch)
    monkeypatch.setattr(
        p, "_public_offerings",
        lambda db_path, s: (
            [],
            [{"code": "Prod-001", "name": "AI Prowler Server HW",
              "description": "Mini server", "unit_price": 500.0,
              "specs": "Glorlin AI Mini PC AMD Ryzen 7 Pro 8845HS CPU 16GB DDR5 RAM 500GB SSD",
              "shipping": 0.0}]))
    st, d = _ask_general_full(db, "How much memory does the Server have?", page="buy")
    assert st == 200 and d["ok"] and d["answer"] == "An answer."
    user_prompt = calls[0][2]
    assert "16GB DDR5 RAM" in user_prompt and "Ryzen 7 Pro 8845HS" in user_prompt
    assert "Shipping: free" in user_prompt


def test_ask_assistant_reads_full_ticket_facts(db, monkeypatch):
    # 2026-11-10: the ticket ask only passed title/state/description and the
    # last 5 messages (200 chars each) to the model. It now also passes the
    # ticket's kind, priority, filed/fixed/closed dates, resolution and close
    # reason, and the last 8 messages up to 400 chars each.
    db, sent = db
    a = file_request(db, sent)
    _enable_agent(db)
    calls = _fake_provider(monkeypatch)
    con = desk_db.get_connection(db)
    try:
        con.execute("UPDATE tickets SET resolution = ?, close_reason = ?, fixed_at = ? "
                    "WHERE ticket_id = ?",
                    ("Replaced the window latch.", "Fixed and confirmed by the customer.",
                     "2026-11-10T10:00:00+00:00", a["ticket_id"]))
        con.commit()
    finally:
        con.close()
    st, d = _ask(db, a["token"], "What did you do to fix it?")
    assert st == 200 and d["ok"] and d["answer"] == "An answer."
    user_prompt = calls[0][2]
    assert "Replaced the window latch." in user_prompt
    assert "Fixed and confirmed by the customer." in user_prompt
    assert "Filed:" in user_prompt and "Priority:" in user_prompt
    assert "Fixed:" in user_prompt


# ── Ask the AI assistant, AI context file (2026-11-11) ─────────────────────────
# The owner points the chat at a .txt/.md file (agent_ask_context_file) with extra
# business info — FAQs, policies, service details. Both ask paths read it and
# include it in the facts given to the model; a missing/unreadable file never
# fails the ask. The provider is monkeypatched — no API key, no token cost.


def _fake_ask(calls, answer="An answer."):
    import desk_agent_providers as prov

    def fake_ask(provider, system, user, model=""):
        calls.append((provider, system, user, model))
        return answer, {"input": 90, "output": 12, "cache_read": 0, "cache_write": 0}
    return fake_ask


def test_ask_general_uses_context_file(db, monkeypatch, tmp_path):
    db, sent = db
    _enable_agent(db)
    ctx = tmp_path / "ask-context.txt"
    ctx.write_text("We offer a 10% discount for seniors on Tuesdays.", encoding="utf-8")
    desk_db.set_setting(db, "agent_ask_context_file", str(ctx), edition=r.SOLO)
    import desk_agent_providers as prov
    calls = []
    monkeypatch.setattr(prov, "ready", lambda p: (True, ""))
    monkeypatch.setattr(prov, "ask", _fake_ask(calls))
    st, d = _ask_general(db, "Do seniors get a discount?")
    assert st == 200 and d["ok"]
    assert "Additional business information" in calls[0][2]
    assert "10% discount for seniors on Tuesdays" in calls[0][2]


def test_ask_assistant_uses_context_file(db, monkeypatch, tmp_path):
    db, sent = db
    a = file_request(db, sent)
    _enable_agent(db)
    ctx = tmp_path / "ask-context.md"
    ctx.write_text("# Policy\nWe never charge a call-out fee.", encoding="utf-8")
    desk_db.set_setting(db, "agent_ask_context_file", str(ctx), edition=r.SOLO)
    import desk_agent_providers as prov
    calls = []
    monkeypatch.setattr(prov, "ready", lambda p: (True, ""))
    monkeypatch.setattr(prov, "ask", _fake_ask(calls))
    st, d = _ask(db, a["token"], "Is there a call-out fee?")
    assert st == 200 and d["ok"]
    assert "Additional business information" in calls[0][2]
    assert "never charge a call-out fee" in calls[0][2]


def test_ask_general_missing_context_file_is_skipped(db, monkeypatch, tmp_path):
    db, sent = db
    _enable_agent(db)
    desk_db.set_setting(db, "agent_ask_context_file",
                        str(tmp_path / "no-such-file.txt"), edition=r.SOLO)
    import desk_agent_providers as prov
    calls = []
    monkeypatch.setattr(prov, "ready", lambda p: (True, ""))
    monkeypatch.setattr(prov, "ask", _fake_ask(calls))
    st, d = _ask_general(db, "What do you do?")
    assert st == 200 and d["ok"]
    assert "Additional business information" not in calls[0][2]


def test_ask_context_text_cap_and_extension(db, tmp_path):
    import desk_agent_settings as das
    db, sent = db
    ctx = tmp_path / "long.txt"
    ctx.write_text("x" * 30000, encoding="utf-8")
    desk_db.set_setting(db, "agent_ask_context_file", str(ctx), edition=r.SOLO)
    assert len(das.ask_context_text(db)) == das.ASK_CONTEXT_MAX_CHARS
    assert len(das.ask_context_text(db, max_chars=100)) == 100
    # not a .txt/.md file: skipped
    other = tmp_path / "context.pdf"
    other.write_bytes(b"%PDF-1.4 fake")
    desk_db.set_setting(db, "agent_ask_context_file", str(other), edition=r.SOLO)
    assert das.ask_context_text(db) == ""
    # unset: nothing
    desk_db.set_setting(db, "agent_ask_context_file", "", edition=r.SOLO)
    assert das.ask_context_text(db) == ""
