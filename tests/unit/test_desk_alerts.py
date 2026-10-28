"""Service Desk Phase 1 — desk_alerts: who is told, by which channel, and
delivery of public replies to the outside party."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_alerts  # noqa: E402
import desk_db  # noqa: E402
import desk_rules as r  # noqa: E402

TEAM = [
    {"id": "dave", "name": "Dave", "role": "owner", "email": "dave@x.com", "phone": "+13865550001"},
    {"id": "mgr", "name": "Mia", "role": "manager", "email": "mia@x.com", "phone": "+13865550002"},
    {"id": "cris", "name": "Cris", "role": "field_crew", "email": "cris@x.com", "phone": "+13865550003"},
]
OWNER_S, MANAGER, CREW = ({"id": u["id"], "role": u["role"]} for u in TEAM)


@pytest.fixture
def setup(tmp_path):
    db = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(db)
    sent = []
    desk_alerts.reset()
    desk_alerts.configure(
        email=lambda to, subj, body: sent.append(("email", to, subj, body)) or True,
        sms=lambda to, text: sent.append(("sms", to, text)) or True,
        team=lambda: TEAM, db_path=lambda: db, base_url=lambda: "https://desk.example",
        business=lambda: "Vavro Field Services", background=False)
    yield db, sent
    desk_alerts.reset()


def test_business_new_unassigned_ticket_alerts_owner_and_managers_not_filer(setup):
    db, sent = setup
    desk_db.create_ticket(db, title="Pump leaking", kind="internal", actor=CREW)
    to = sorted(s[1] for s in sent if s[0] == "email")
    assert to == ["dave@x.com", "mia@x.com"]
    assert "https://desk.example/desk/#T-0001" in sent[0][3]
    assert not [s for s in sent if s[0] == "sms"]


def test_assignment_alerts_assignee_but_never_yourself(setup):
    db, sent = setup
    t = desk_db.create_ticket(db, title="Hose", kind="internal", actor=MANAGER)
    sent.clear()
    desk_db.assign_ticket(db, t["ticket_id"], "cris", actor=MANAGER)
    assert [s[1] for s in sent] == ["cris@x.com"]
    sent.clear()
    t2 = desk_db.create_ticket(db, title="Mine", kind="internal", actor=CREW, assignee="cris")
    assert sent == []                                   # filed for yourself: no alert
    assert t2["assignee"] == "cris"


def test_p1_or_sms_fallback_also_texts(setup):
    db, sent = setup
    desk_db.create_ticket(db, title="Truck down", kind="internal", actor=MANAGER, assignee="cris",
                          priority="P1")
    assert ("sms", "+13865550003") in [(s[0], s[1]) for s in sent]


def test_customer_reply_alerts_assignee(setup):
    db, sent = setup
    c = desk_db.upsert_contact(db, name="Lopez", phone="386-555-0100")
    cust = {"id": "cust", "role": "customer", "contact_id": c["contact_id"]}
    t = desk_db.create_ticket(db, title="Streaks", contact_id=c["contact_id"], actor=MANAGER,
                              assignee="cris")
    sent.clear()
    desk_db.add_message(db, t["ticket_id"], "Still streaky by the door", actor=cust,
                        visibility="public")
    assert [s[1] for s in sent] == ["cris@x.com"] and "Still streaky" in sent[0][2]


def test_public_reply_is_delivered_to_customer_and_recorded(setup):
    db, sent = setup
    c = desk_db.upsert_contact(db, name="Lopez", phone="386-555-0100")
    t = desk_db.create_ticket(db, title="Streaks", contact_id=c["contact_id"], actor=MANAGER,
                              assignee="cris")
    sent.clear()
    m = desk_db.add_message(db, t["ticket_id"], "We'll redo it Thursday", actor=CREW,
                            visibility="public")
    assert len(sent) == 1 and sent[0][:2] == ("sms", "+13865550100")
    assert sent[0][2].startswith("Vavro Field Services: We'll redo it Thursday (ref T-0001) Details: "
                                 "https://desk.example/support/t/")
    detail = desk_db.get_ticket_detail(db, t["ticket_id"])
    assert detail["messages"][-1]["delivery_status"] == "sent"
    assert m["message_id"] == detail["messages"][-1]["message_id"]


def test_internal_note_is_never_delivered(setup):
    db, sent = setup
    c = desk_db.upsert_contact(db, name="Lopez", email="l@x.com")
    t = desk_db.create_ticket(db, title="Streaks", contact_id=c["contact_id"], actor=MANAGER,
                              assignee="cris")
    sent.clear()
    desk_db.add_message(db, t["ticket_id"], "customer is picky", actor=CREW)
    assert sent == []


def test_failed_delivery_is_recorded(setup):
    db, sent = setup
    desk_alerts.configure(email=lambda *a: False)
    c = desk_db.upsert_contact(db, name="Lopez", email="l@x.com")
    t = desk_db.create_ticket(db, title="Streaks", contact_id=c["contact_id"], actor=MANAGER,
                              assignee="cris")
    desk_db.add_message(db, t["ticket_id"], "On it", actor=CREW, visibility="public")
    assert desk_db.get_ticket_detail(db, t["ticket_id"])["messages"][-1]["delivery_status"] == "failed"


def test_reopen_alerts_assignee(setup):
    db, sent = setup
    t = desk_db.create_ticket(db, title="Gate", kind="internal", actor=MANAGER, assignee="cris")
    desk_db.change_state(db, t["ticket_id"], r.CLOSED, actor=MANAGER, reason="dup")
    sent.clear()
    desk_db.change_state(db, t["ticket_id"], r.ASSIGNED, actor=MANAGER, reason="not a dup")
    assert [s[1] for s in sent] == ["cris@x.com"] and "reopened" in sent[0][2]


# ── Solo ─────────────────────────────────────────────────────────────────────

def test_solo_owner_alerts_go_to_settings_contacts_and_not_for_own_actions(setup):
    db, sent = setup
    desk_db.set_setting(db, "alert_email", "owner@x.com", edition=r.SOLO)
    desk_db.set_setting(db, "alert_phone", "+13865559999", edition=r.SOLO)
    desk_db.create_ticket(db, title="My own to-do", kind="internal", edition=r.SOLO)
    assert sent == []
    c = desk_db.upsert_contact(db, name="Lopez", phone="386-555-0100")
    cust = {"id": "cust", "role": "customer", "contact_id": c["contact_id"]}
    desk_db.create_ticket(db, title="Streaks", actor=cust, edition=r.SOLO, priority="P1")
    assert ("email", "owner@x.com") in [(s[0], s[1]) for s in sent]
    assert ("sms", "+13865559999") in [(s[0], s[1]) for s in sent]


def test_subcontractor_marking_done_alerts_owner(setup):
    db, sent = setup
    desk_db.set_setting(db, "alert_email", "owner@x.com", edition=r.SOLO)
    s = desk_db.upsert_contact(db, name="Dan", phone="386-555-0199", contact_type="subcontractor")
    sub = {"id": "dan", "role": "subcontractor", "contact_id": s["contact_id"]}
    t = desk_db.create_ticket(db, title="Drywall", kind="subcontractor",
                              contact_id=s["contact_id"], edition=r.SOLO)
    sent.clear()
    desk_db.change_state(db, t["ticket_id"], r.FIXED, actor=sub, edition=r.SOLO)
    assert [x[1] for x in sent if x[0] == "email"] == ["owner@x.com"]
    assert "marked their part done" in sent[0][2]


def test_a_failing_sender_never_breaks_the_change(setup):
    db, sent = setup

    def boom(*a):
        raise RuntimeError("SMTP down")
    desk_alerts.configure(email=boom)
    t = desk_db.create_ticket(db, title="Pump", kind="internal", actor=CREW)
    assert desk_db.get_ticket(db, t["ticket_id"]) is not None
