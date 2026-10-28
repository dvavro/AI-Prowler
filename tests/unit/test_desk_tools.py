"""Service Desk Phase 1 — desk_tools (the logic behind the MCP tools)."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_tools as dt  # noqa: E402

SOLO, BIZ = "solo", "business"
OWNER_S = {"id": "dave", "role": "owner", "name": "David"}
MANAGER = {"id": "mgr", "role": "manager"}
CREW = {"id": "cris", "role": "field_crew"}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    return path


def tid_of(text):
    return text.split("Filed ", 1)[1].split(" ", 1)[0]


def test_voice_customer_call_creates_contact_and_ticket(db):
    out = dt.create_ticket(db, None, SOLO, title="Front windows streaky",
                           contact_name="Mrs. Lopez", contact_phone="386-555-0100")
    assert out.startswith("✅ Filed T-0001") and "customer ticket" in out and "owner" in out
    t = desk_db.get_ticket(db, "T-0001")
    assert t["kind"] == "external" and t["contact_id"] == "CT-0001" and t["source"] == "claude"


def test_own_reminder_defaults_to_internal_with_due_date(db):
    out = dt.create_ticket(db, None, SOLO, title="Renew pesticide license", due="2026-10-30")
    assert "internal ticket" in out and "Due" in out
    t = desk_db.get_ticket(db, tid_of(out))
    assert t["kind"] == "internal" and t["due_resolve_at"].endswith("+00:00")


def test_subcontractor_ticket_creates_sub_contact(db):
    out = dt.create_ticket(db, None, SOLO, title="Drywall sub no-show", kind="subcontractor",
                           contact_name="Dan", contact_phone="386-555-0199")
    t = desk_db.get_ticket(db, tid_of(out))
    assert desk_db.get_contact(db, t["contact_id"])["contact_type"] == "subcontractor"


def test_switch_off_refusal_is_readable_text(db):
    dt.tickets_settings(db, None, SOLO, setting="own_tickets", value="off")
    out = dt.create_ticket(db, None, SOLO, title="Truck tire")
    assert out.startswith("❌") and "switched off" in out


def test_bad_due_date_is_refused(db):
    out = dt.create_ticket(db, None, SOLO, title="x", due="next tuesday-ish")
    assert out.startswith("❌") and "not a date" in out


def test_business_flow_assign_state_note_and_lists(db):
    out = dt.create_ticket(db, CREW, BIZ, title="Pump leaking oil", priority="p2")
    tid = tid_of(out)
    assert "Open" in out and "P2" in out
    assert "assigned to cris" in dt.assign_ticket(db, MANAGER, BIZ, ticket_id=tid, assignee="cris")
    assert "In Progress" in dt.set_ticket_state(db, CREW, BIZ, ticket_id=tid, state="in progress")
    assert dt.set_ticket_state(db, CREW, BIZ, ticket_id=tid, state="Closed",
                               reason="done").startswith("❌")
    assert "Internal note added" in dt.add_ticket_note(db, CREW, BIZ, ticket_id=tid,
                                                       note="Ordered a seal kit")
    mine = dt.my_tickets(db, CREW, BIZ)
    assert tid in mine and "1 open ticket" in mine
    assert "No tickets match" in dt.list_tickets(db, CREW, BIZ, text="ladder")
    detail = dt.get_ticket(db, CREW, BIZ, ticket_id=tid.lower())
    assert "Ordered a seal kit" in detail and "internal note" in detail
    assert "Open → Assigned → In Progress" in detail


def test_stale_update_is_a_warning_not_an_overwrite(db):
    tid = tid_of(dt.create_ticket(db, OWNER_S, BIZ, title="Hose", kind="internal",
                                  assignee="cris"))
    assert dt.update_ticket(db, OWNER_S, BIZ, ticket_id=tid, title="Hose split",
                            expected_version=1).startswith("✅")
    out = dt.update_ticket(db, OWNER_S, BIZ, ticket_id=tid, title="again", expected_version=1)
    assert out.startswith("⚠️") and "Reload" in out
    assert dt.update_ticket(db, OWNER_S, BIZ, ticket_id=tid).startswith("❌ Nothing to change")


def test_hidden_ticket_reads_as_not_found(db):
    tid = tid_of(dt.create_ticket(db, OWNER_S, BIZ, title="Private", kind="internal",
                                  private=True))
    assert dt.get_ticket(db, CREW, BIZ, ticket_id=tid).startswith("❌ no ticket")


def test_updates_json(db):
    dt.create_ticket(db, None, SOLO, title="A", contact_phone="386-555-0100")
    doc = json.loads(dt.ticket_updates_json(db, None, SOLO, since=""))
    assert doc["ok"] and len(doc["tickets"]) == 1 and doc["cursor"]
    again = json.loads(dt.ticket_updates_json(db, None, SOLO, since=doc["cursor"]))
    assert again["tickets"] == []


def test_reply_to_customer_previews_then_sends(db):
    tid = tid_of(dt.create_ticket(db, None, SOLO, title="Streaks", contact_name="Lopez",
                                  contact_phone="386-555-0100"))
    pv = dt.reply_to_customer(db, None, SOLO, ticket_id=tid, message="Thursday at 9?")
    assert "PREVIEW" in pv and "Lopez" in pv and "text (SMS)" in pv
    assert desk_db.get_ticket_detail(db, tid)["messages"] == []
    out = dt.reply_to_customer(db, None, SOLO, ticket_id=tid, message="Thursday at 9?", preview=False)
    assert out.startswith("✅ Sent to Lopez")
    m = desk_db.get_ticket_detail(db, tid)["messages"][0]
    assert m["visibility"] == "public" and m["author_kind"] == "claude"
    own = tid_of(dt.create_ticket(db, None, SOLO, title="Tire"))
    assert "internal ticket" in dt.reply_to_customer(db, None, SOLO, ticket_id=own, message="x")


def test_create_job_from_ticket(db):
    tid = tid_of(dt.create_ticket(db, None, SOLO, title="Streaks", contact_phone="386-555-0100"))
    calls = []

    def fake_create_job(updates):
        calls.append(updates)
        return "✅ Created job\nNEW_JOB_ID=JOB-0107"
    out = dt.create_job_from_ticket(db, None, SOLO, ticket_id=tid, service_date="2026-11-04",
                                    create_job_fn=fake_create_job)
    assert out.startswith("❌") and "customer" in out and calls == []
    out = dt.create_job_from_ticket(db, None, SOLO, ticket_id=tid, service_date="2026-11-04",
                                    customer_id="CUST-0187", service_type="Window",
                                    create_job_fn=fake_create_job)
    assert out.startswith("✅ Created JOB-0107 for 2026-11-04") and "customer was told" in out
    assert calls[0]["CustomerID"] == "CUST-0187" and calls[0]["Service Date"] == "2026-11-04"
    assert tid in calls[0]["Notes"]
    t = desk_db.get_ticket(db, tid)
    assert t["job_id"] == "JOB-0107" and t["customer_id"] == "CUST-0187"
    msgs = desk_db.get_ticket_detail(db, tid)["messages"]
    assert [m["visibility"] for m in msgs] == ["internal", "public"]
    bad = dt.create_job_from_ticket(db, None, SOLO, ticket_id=tid, service_date="2026-11-05",
                                    create_job_fn=lambda u: "❌ CustomerID not found")
    assert bad.startswith("❌ The Jobs app did not create the job")


def test_mode_settings_keep_off_as_a_word(db):
    out = dt.tickets_settings(db, None, SOLO, setting="sms_new_request_mode", value="ask")
    assert "sms_new_request_mode = ask" in out
    out = dt.tickets_settings(db, None, SOLO, setting="sms_new_request_mode", value="off")
    assert "sms_new_request_mode = off" in out
    assert dt.tickets_settings(db, None, SOLO, setting="sms_new_request_mode",
                               value="shout").startswith("❌")


def test_settings_show_and_owner_only(db):
    shown = dt.tickets_settings(db, None, SOLO)
    assert "own_tickets = on" in shown and "Solo" in shown
    assert dt.tickets_settings(db, MANAGER, BIZ, setting="own_tickets",
                               value=False).startswith("❌")
