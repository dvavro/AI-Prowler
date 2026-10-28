"""Service Desk - a customer request from first message to rating, both sides.

The customer acts only through the request/status page API (/support-api,
desk_portal.route) and the owner/crew only through the app API (/desk-api,
desk_http.route) - the same calls the two pages make. Texts, emails and
alerts are caught. Checks at every step what EACH side sees:

  file -> messages both ways -> In Progress -> Fixed -> "No, not yet" ->
  Fixed -> "Yes, all good" (Closed) -> rating with a comment -> owner sees
  the rating (ticket, list, Claude, PDF) and is told about it -> reopen ->
  owner closes it himself (not recorded as the customer's confirmation).
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_alerts  # noqa: E402
import desk_data  # noqa: E402
import desk_db  # noqa: E402
import desk_files  # noqa: E402
import desk_http  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_tools  # noqa: E402

OWNER = {"id": "owner", "role": "owner"}
TEAM = [{"id": "dave", "name": "Dave", "role": "owner", "email": "dave@x.com", "phone": "+13865550001"},
        {"id": "sam", "name": "Sam", "role": "staff", "email": "sam@x.com", "phone": "+13865550003"}]
PHONE, E164 = "386-555-0142", "+13865550142"


@pytest.fixture
def desk(tmp_path):
    db = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(db)
    sent = []
    desk_alerts.reset()
    desk_alerts.configure(
        email=lambda to, subj, body: sent.append(("email", to, subj + "\n" + body)) or True,
        sms=lambda to, text: sent.append(("sms", to, text)) or True,
        team=lambda: TEAM, db_path=lambda: db, base_url=lambda: "https://desk.example",
        business=lambda: "Vavro Field Services", background=False)
    p.send_fn = lambda ch, to, subj, text: sent.append((ch, to, text)) or True
    yield db, sent
    p.send_fn = None
    desk_alerts.reset()


# ── the two sides ────────────────────────────────────────────────────────────

class Customer:
    def __init__(self, db, sent, edition):
        self.db, self.sent, self.edition, self.token = db, sent, edition, None

    def call(self, path, payload=None, method="POST"):
        st, _ct, body = p.route(method, "/support-api" + path, query={},
                                body=json.dumps(payload).encode() if payload is not None else b"",
                                content_type="application/json", ip="203.0.113.9", db_path=self.db,
                                edition=self.edition, base_url="https://desk.example")
        return st, json.loads(body)

    def file(self, title, description=""):
        st, d = self.call("/start", {"name": "Mrs Lopez", "phone": PHONE})
        assert st == 200, d
        code = re.search(r"\b(\d{6})\b", self.texts()[-1]).group(1)
        st, d = self.call("/verify", {"contact_id": d["contact_id"], "code": code, "title": title,
                                      "description": description})
        assert st == 201, d
        self.token = d["token"]
        return d["ticket_id"]

    def page(self):
        st, d = self.call(f"/t/{self.token}", method="GET")
        assert st == 200, d
        return d["ticket"]

    def act(self, what, payload):
        return self.call(f"/t/{self.token}/{what}", payload)

    def texts(self):
        return [s[2] for s in self.sent if s[1] == E164]


class Team:
    def __init__(self, db, actor, edition):
        self.db, self.actor, self.edition = db, actor, edition

    def call(self, method, path, payload=None, query=None):
        st, _ct, body = desk_http.route(method, "/desk-api" + path, query=query or {},
                                        body=json.dumps(payload).encode() if payload is not None else b"",
                                        content_type="application/json", actor=self.actor,
                                        edition=self.edition, db_path=self.db)
        return st, (json.loads(body) if body[:1] in (b"{", b"[") else body)

    def ticket(self, tid):
        st, d = self.call("GET", f"/tickets/{tid}")
        assert st == 200, d
        return d["ticket"]

    def move(self, tid, to, reason=""):
        st, d = self.call("POST", f"/tickets/{tid}/state", {"to_state": to, "reason": reason})
        assert st == 200, (to, d)

    def say(self, tid, body, visibility="public"):
        st, d = self.call("POST", f"/tickets/{tid}/messages", {"body": body, "visibility": visibility})
        assert st in (200, 201), d


def _alerts_to(sent, address):
    return [s[2] for s in sent if s[1] == address]


# ── Solo: the owner and one customer, the whole way round ────────────────────

def test_solo_full_cycle_customer_and_owner(desk):
    db, sent = desk
    owner = Team(db, OWNER, r.SOLO)
    st, _ = owner.call("POST", "/settings", {"key": "alert_email", "value": "dave@x.com"})
    assert st == 200
    cust = Customer(db, sent, r.SOLO)

    # 1. the customer files; it lands on the owner, who is told
    tid = cust.file("Streaks on the front windows", "Upstairs ones mostly")
    assert cust.page()["state"] == r.ASSIGNED
    assert any(tid in a for a in _alerts_to(sent, "dave@x.com"))
    assert any(f"We got your request {tid}" in t for t in cust.texts())

    # 2. messages both ways, each side sees the other's
    st, _ = cust.act("reply", {"body": "The two by the garage too"})
    assert st == 201
    assert any("The two by the garage too" in a for a in _alerts_to(sent, "dave@x.com"))
    seen = owner.ticket(tid)["messages"]
    assert [m["body"] for m in seen] == ["The two by the garage too"]
    owner.say(tid, "We'll come back Thursday at 9")
    owner.say(tid, "bring the long pole", visibility="internal")
    assert any("Thursday at 9" in t for t in cust.texts())
    msgs = [m["body"] for m in cust.page()["messages"]]
    assert msgs == ["The two by the garage too", "We'll come back Thursday at 9"]   # no internal note

    # 3. work starts -> the customer is told
    owner.move(tid, r.IN_PROGRESS)
    assert any("is in progress" in t for t in cust.texts())

    # 4. owner says Fixed; the customer says "No, not yet"
    owner.move(tid, r.FIXED)
    pg = cust.page()
    assert pg["can_confirm"] and not pg["can_rate"]
    st, d = cust.act("state", {"to_state": r.IN_PROGRESS, "reason": "Still a streak on the left one"})
    assert st == 200, d
    assert owner.ticket(tid)["state"] == r.IN_PROGRESS
    assert any("NOT fixed" in a and "left one" in a for a in _alerts_to(sent, "dave@x.com"))

    # 5. fixed again; the customer confirms -> Closed, "confirmed by customer"
    owner.call("POST", f"/tickets/{tid}/update", {"fields": {"resolution": "Re-did left pane with fresh squeegee"}})
    owner.move(tid, r.FIXED)
    st, d = cust.act("state", {"to_state": r.CLOSED, "reason": ""})
    assert st == 200, d
    t = owner.ticket(tid)
    assert t["state"] == r.CLOSED and t["close_reason"] == "confirmed by customer"
    pg = cust.page()
    assert pg["can_rate"] and pg["can_reopen"] and pg.get("csat_score") is None

    # 6. the customer rates it, with a comment
    st, d = cust.act("rating", {"score": 5, "comment": "Great job, very clean"})
    assert st == 200, d
    # ... the customer's page now shows the rating back, and asks no more
    pg = cust.page()
    assert pg["csat_score"] == 5 and pg["csat_comment"] == "Great job, very clean" and not pg["can_rate"]
    st, d = cust.act("rating", {"score": 1})
    assert st == 400 and "already rated" in d["message"]
    # ... the owner is told
    assert any("rated it 5/5" in a and "Great job, very clean" in a for a in _alerts_to(sent, "dave@x.com"))
    # ... and it is on the ticket everywhere the owner looks
    t = owner.ticket(tid)
    assert t["csat_score"] == 5 and t["csat_comment"] == "Great job, very clean"
    assert any(e["kind"] == "csat" and e["to_value"] == "5" for e in t["events"])
    st, d = owner.call("GET", "/tickets", query={"state": r.CLOSED})
    assert [x["csat_score"] for x in d["tickets"] if x["ticket_id"] == tid] == [5]
    text = desk_tools.get_ticket(db, OWNER, r.SOLO, ticket_id=tid)
    assert "Customer rating: 5/5" in text and "Great job, very clean" in text
    assert "Closed: confirmed by customer" in text and "Re-did left pane" in text
    pdf = desk_data.ticket_pdf(desk_db.get_ticket_detail(db, tid, actor=OWNER, edition=r.SOLO))
    assert b"Customer rating: 5/5" in pdf and b"Re-did left pane" in pdf
    doc = desk_files.read_ticket_json(desk_db.root_for(db) / t["folder"] / desk_files.TICKET_JSON)
    assert doc["csat_score"] == 5 and doc["csat_comment"] == "Great job, very clean"

    # 7. the customer reopens; the rating is cleared from the ticket (kept in history)
    st, d = cust.act("state", {"to_state": r.ASSIGNED, "reason": "Rain left spots"})
    assert st == 200, d
    t = owner.ticket(tid)
    assert t["state"] == r.ASSIGNED and t["csat_score"] is None and t["close_reason"] is None
    assert any(e["kind"] == "csat" for e in t["events"])
    assert any("reopened" in a for a in _alerts_to(sent, "dave@x.com"))
    pg = cust.page()
    assert pg["csat_score"] is None and not pg["can_rate"]       # open again: nothing to rate yet

    # 8. this time the OWNER closes it from Fixed - not the customer's confirmation
    owner.move(tid, r.IN_PROGRESS)
    owner.move(tid, r.FIXED)
    owner.move(tid, r.CLOSED)
    t = owner.ticket(tid)
    assert t["state"] == r.CLOSED and t["close_reason"] != "confirmed by customer"
    assert any("complete and closed" in x for x in cust.texts())
    pg = cust.page()
    assert pg["can_rate"]                         # asked again for the final outcome
    st, _ = cust.act("rating", {"score": 4, "comment": "Good after the redo"})
    assert st == 200
    assert owner.ticket(tid)["csat_score"] == 4
    assert desk_files.verify(db) == []


# ── Business: the rating reaches the crew member who did the work ────────────

def test_business_rating_goes_to_the_assignee(desk):
    db, sent = desk
    cust = Customer(db, sent, r.BUSINESS)
    tid = cust.file("Gutter overflowing")
    boss = Team(db, {"id": "dave", "role": "owner"}, r.BUSINESS)
    st, d = boss.call("POST", f"/tickets/{tid}/assign", {"assignee": "sam"})
    assert st == 200, d
    sam = Team(db, {"id": "sam", "role": "staff"}, r.BUSINESS)
    sam.say(tid, "Cleared it, downspout was blocked")
    sam.move(tid, r.IN_PROGRESS)
    sam.move(tid, r.FIXED)
    assert cust.act("state", {"to_state": r.CLOSED, "reason": ""})[0] == 200
    assert cust.act("rating", {"score": 2, "comment": "Took three days"})[0] == 200
    sam_alerts = _alerts_to(sent, "sam@x.com")
    assert any("rated it 2/5" in a and "Took three days" in a for a in sam_alerts)
    t = boss.ticket(tid)
    assert t["csat_score"] == 2 and t["close_reason"] == "confirmed by customer"
    st, d = boss.call("GET", "/report")
    assert st == 200
