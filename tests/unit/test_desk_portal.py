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


def test_email_code_when_no_phone(db):
    db, sent = db
    p.start_request(db, email="L@Example.com")
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
