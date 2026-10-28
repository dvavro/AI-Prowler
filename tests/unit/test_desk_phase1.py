"""Service Desk Phase 1 — data layer: settings, contacts, subcontractor
tickets, messages, field edits, scoped lists, live updates, attachments."""
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_attachments as att  # noqa: E402
import desk_db  # noqa: E402
import desk_files  # noqa: E402
import desk_rules as r  # noqa: E402

OWNER_S = {"id": "dave", "role": "owner"}
MANAGER = {"id": "mgr", "role": "manager", "queues": ["field"]}
CREW = {"id": "cris", "role": "field_crew"}
CREW2 = {"id": "other", "role": "field_crew"}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    desk_db.json_write_failures.clear()
    return path


def customer(db, phone="386-555-0100", name="Mrs. Lopez"):
    c = desk_db.upsert_contact(db, name=name, phone=phone)
    return c, {"id": "cust-" + c["contact_id"], "role": "customer", "contact_id": c["contact_id"]}


def sub(db, phone="386-555-0199", name="Dry Wall Dan"):
    c = desk_db.upsert_contact(db, name=name, phone=phone, contact_type="subcontractor")
    return c, {"id": "sub-" + c["contact_id"], "role": "subcontractor", "contact_id": c["contact_id"]}


# ── settings ─────────────────────────────────────────────────────────────────

def test_settings_default_and_only_owner_changes_them(db):
    assert desk_db.get_settings(db)["own_tickets"] is True
    with pytest.raises(desk_db.DeskError, match="only the owner"):
        desk_db.set_setting(db, "own_tickets", False, actor=MANAGER)
    with pytest.raises(desk_db.DeskError, match="unknown setting"):
        desk_db.set_setting(db, "teleport", True, actor=OWNER_S)
    with pytest.raises(desk_db.DeskError, match="must be bool"):
        desk_db.set_setting(db, "own_tickets", "no", actor=OWNER_S)
    assert desk_db.set_setting(db, "own_tickets", False, actor=OWNER_S)["own_tickets"] is False


# ── contacts ─────────────────────────────────────────────────────────────────

def test_contacts_dedupe_by_phone_and_type(db):
    a = desk_db.upsert_contact(db, name="Lopez", phone="(386) 555-0100")
    b = desk_db.upsert_contact(db, phone="+1 386 555 0100", email="L@Example.com")
    assert a["contact_id"] == b["contact_id"] == "CT-0001"
    assert b["phone"] == "+13865550100" and b["email"] == "l@example.com" and b["name"] == "Lopez"
    s = desk_db.upsert_contact(db, name="Lopez Plumbing", phone="386-555-0100",
                               contact_type="subcontractor")
    assert s["contact_id"] != a["contact_id"]
    assert desk_db.find_contact(db, email="l@example.com")["contact_id"] == "CT-0001"
    with pytest.raises(desk_db.DeskError, match="phone number or an email"):
        desk_db.upsert_contact(db, name="Nobody")


# ── subcontractor tickets ────────────────────────────────────────────────────

def test_subcontractor_ticket_needs_a_subcontractor_contact(db):
    c, _ = customer(db)
    with pytest.raises(desk_db.DeskError, match="subcontractor contact"):
        desk_db.create_ticket(db, title="Sub no-show", kind="subcontractor",
                              contact_id=c["contact_id"], edition=r.SOLO)


def test_subcontractor_thread_end_to_end(db):
    s, sub_actor = sub(db)
    c, cust_actor = customer(db)
    cust_t = desk_db.create_ticket(db, title="Streaks", actor=cust_actor, edition=r.SOLO)
    t = desk_db.create_ticket(db, title="Drywall sub didn't show Tuesday", kind="subcontractor",
                              contact_id=s["contact_id"], edition=r.SOLO)
    tid = t["ticket_id"]
    assert t["assignee"] == "owner"
    desk_db.add_message(db, tid, "Owner note: call Dan's office", edition=r.SOLO)          # internal
    out = desk_db.add_message(db, tid, "Can you come Thursday?", visibility="public", edition=r.SOLO)
    assert out["delivery_status"] == "queued"
    desk_db.add_message(db, tid, "Yes, Thursday 8am", actor=sub_actor, visibility="public",
                        channel="sms", edition=r.SOLO)
    desk_db.change_state(db, tid, r.IN_PROGRESS, edition=r.SOLO)
    desk_db.change_state(db, tid, r.FIXED, actor=sub_actor, edition=r.SOLO)

    seen = desk_db.get_ticket_detail(db, tid, actor=sub_actor, edition=r.SOLO)
    assert [m["body"] for m in seen["messages"]] == ["Can you come Thursday?", "Yes, Thursday 8am"]
    assert "events" not in seen and "filed_by" not in seen
    assert [x["ticket_id"] for x in desk_db.list_tickets(db, actor=sub_actor, edition=r.SOLO)] == [tid]
    with pytest.raises(desk_db.NotFoundError):
        desk_db.get_ticket_detail(db, cust_t["ticket_id"], actor=sub_actor, edition=r.SOLO)
    assert desk_files.verify(db) == []


# ── messages ─────────────────────────────────────────────────────────────────

def test_customer_reply_takes_ticket_off_hold(db):
    c, cust = customer(db)
    t = desk_db.create_ticket(db, title="Gutter", actor=cust, edition=r.SOLO)
    desk_db.change_state(db, t["ticket_id"], r.IN_PROGRESS, edition=r.SOLO)
    desk_db.change_state(db, t["ticket_id"], r.ON_HOLD, reason="waiting on photos", edition=r.SOLO)
    desk_db.add_message(db, t["ticket_id"], "Photos attached", actor=cust, visibility="public",
                        edition=r.SOLO)
    row = desk_db.get_ticket(db, t["ticket_id"])
    assert row["state"] == r.IN_PROGRESS
    last = desk_db.get_ticket_detail(db, t["ticket_id"], edition=r.SOLO)["state_history"][-1]
    assert last["by"] == "system" and last["reason"] == "customer replied"


def test_first_public_staff_reply_sets_first_response(db):
    c, cust = customer(db)
    t = desk_db.create_ticket(db, title="Gutter", actor=cust, edition=r.SOLO)
    desk_db.add_message(db, t["ticket_id"], "internal only", edition=r.SOLO)
    assert desk_db.get_ticket(db, t["ticket_id"])["first_response_at"] is None
    desk_db.add_message(db, t["ticket_id"], "On it", visibility="public", edition=r.SOLO)
    assert desk_db.get_ticket(db, t["ticket_id"])["first_response_at"]


def test_customer_cannot_write_internal_notes_or_see_them(db):
    c, cust = customer(db)
    t = desk_db.create_ticket(db, title="Gutter", actor=cust, edition=r.SOLO)
    with pytest.raises(desk_db.DeskError, match="team only"):
        desk_db.add_message(db, t["ticket_id"], "x", actor=cust, edition=r.SOLO)
    desk_db.add_message(db, t["ticket_id"], "customer is picky", edition=r.SOLO)
    detail = desk_db.get_ticket_detail(db, t["ticket_id"], actor=cust, edition=r.SOLO)
    assert detail["messages"] == []


def test_internal_ticket_has_no_public_messages(db):
    t = desk_db.create_ticket(db, title="Renew license", kind="internal", edition=r.SOLO)
    with pytest.raises(desk_db.DeskError, match="internal ticket"):
        desk_db.add_message(db, t["ticket_id"], "hi", visibility="public", edition=r.SOLO)


def test_delivery_status_update_reaches_ticket_json(db):
    c, cust = customer(db)
    t = desk_db.create_ticket(db, title="Gutter", actor=cust, edition=r.SOLO)
    m = desk_db.add_message(db, t["ticket_id"], "On it", visibility="public", edition=r.SOLO)
    desk_db.set_message_delivery(db, m["message_id"], "sent", "SM123")
    doc = json.loads((desk_files.ticket_folder(desk_db.root_for(db), t) / "ticket.json")
                     .read_text(encoding="utf-8"))
    assert doc["messages"][0]["delivery_status"] == "sent"


# ── field edits ──────────────────────────────────────────────────────────────

def test_update_ticket_rules(db):
    t = desk_db.create_ticket(db, title="Pump", kind="internal", actor=CREW, assignee="cris",
                              queue_id="field")
    tid = t["ticket_id"]
    with pytest.raises(desk_db.DeskError, match="needs a reason"):
        desk_db.update_ticket(db, tid, {"priority": "P1"}, actor=MANAGER)
    t2 = desk_db.update_ticket(db, tid, {"priority": "P1", "title": "Pump leaking oil"},
                               actor=MANAGER, reason="route day tomorrow")
    assert t2["priority"] == "P1" and t2["version"] == t["version"] + 1
    with pytest.raises(desk_db.DeskError, match="only the owner"):
        desk_db.update_ticket(db, tid, {"visibility": "private"}, actor=MANAGER)
    with pytest.raises(desk_db.DeskError, match="cannot edit"):
        desk_db.update_ticket(db, tid, {"state": "Closed"}, actor=OWNER_S)
    with pytest.raises(desk_db.NotFoundError):
        desk_db.update_ticket(db, tid, {"title": "x"}, actor=CREW2)
    with pytest.raises(desk_db.StaleRowError):
        desk_db.update_ticket(db, tid, {"title": "y"}, actor=MANAGER, expected_version=t["version"])
    edits = [e for e in desk_db.get_ticket_detail(db, tid)["events"] if e["kind"] == "field_edit"]
    assert {e["to_value"] for e in edits} == {"priority=P1", "title=Pump leaking oil"}


# ── lists and updates ────────────────────────────────────────────────────────

def test_lists_are_scoped_and_filtered(db):
    a = desk_db.create_ticket(db, title="A pump", kind="internal", actor=CREW, assignee="cris")
    desk_db.create_ticket(db, title="B hose", kind="internal", actor=CREW2, assignee="other")
    desk_db.create_ticket(db, title="C ladder", kind="internal", actor=OWNER_S, assignee="cris",
                          due_resolve_at="2026-10-01T00:00:00+00:00")
    mine = desk_db.list_tickets(db, actor=CREW)
    assert {t["title"] for t in mine} == {"A pump", "C ladder"}
    assert {t["title"] for t in desk_db.list_tickets(db, actor=OWNER_S)} == {"A pump", "B hose", "C ladder"}
    assert [t["title"] for t in desk_db.list_tickets(db, actor=OWNER_S, text="hose")] == ["B hose"]
    assert [t["title"] for t in desk_db.list_tickets(db, actor=CREW, overdue=True,
                                                     now="2026-10-27T00:00:00+00:00")] == ["C ladder"]
    desk_db.change_state(db, a["ticket_id"], r.CLOSED, actor=OWNER_S, reason="dup")
    assert [t["title"] for t in desk_db.my_tickets(db, actor=CREW)] == ["C ladder"]


def test_updates_cursor_returns_only_changes(db):
    a = desk_db.create_ticket(db, title="A", kind="internal", actor=CREW, assignee="cris")
    first = desk_db.get_ticket_updates(db, "", actor=OWNER_S)
    assert [t["ticket_id"] for t in first["tickets"]] == [a["ticket_id"]]
    assert desk_db.get_ticket_updates(db, first["cursor"], actor=OWNER_S)["tickets"] == []
    desk_db.change_state(db, a["ticket_id"], r.IN_PROGRESS, actor=CREW)
    nxt = desk_db.get_ticket_updates(db, first["cursor"], actor=OWNER_S)
    assert [t["state"] for t in nxt["tickets"]] == [r.IN_PROGRESS]
    assert desk_db.get_ticket_updates(db, first["cursor"], actor=CREW2)["tickets"] == []


# ── attachments ──────────────────────────────────────────────────────────────

def _jpeg_with_gps(size=(3000, 2000)):
    from PIL import Image
    img = Image.new("RGB", size, (200, 120, 40))
    ex = Image.Exif()
    ex[0x0132] = "2026:10:27 09:15:00"
    ex[0x9003] = "2026:10:27 09:15:00"
    gps = {1: "N", 2: (29.0, 1.0, 30.0), 3: "W", 4: (80.0, 55.0, 10.0)}
    ex[0x8825] = gps
    buf = io.BytesIO()
    img.save(buf, "JPEG", exif=ex.tobytes())
    return buf.getvalue()


def test_customer_photo_is_resized_thumbed_and_gps_free(db):
    from PIL import Image
    c, cust = customer(db)
    t = desk_db.create_ticket(db, title="Streaks", actor=cust, edition=r.SOLO)
    a = att.store_attachment(db, t["ticket_id"], _jpeg_with_gps(), "IMG 0915.JPG",
                             actor=cust, edition=r.SOLO, keep_gps=True)
    folder = desk_files.ticket_folder(desk_db.root_for(db), t)
    assert a["filename"] == "0001_IMG-0915.jpg" and a["kind"] == "photo"
    assert a["thumb_path"] == "attachments/0001_IMG-0915_thumb.jpg"
    img = Image.open(folder / a["path"])
    assert max(img.size) == att.PHOTO_MAX_SIDE
    assert 0x8825 not in img.getexif()                       # customer: GPS always removed
    assert max(Image.open(folder / a["thumb_path"]).size) == att.THUMB_MAX_SIDE
    assert a["taken_at"] == "2026-10-27T09:15:00"
    assert a["visibility"] == "public" and a["uploaded_by"] == cust["id"]
    assert desk_files.verify(db) == []


def test_owner_can_keep_gps_for_proof_of_service(db):
    from PIL import Image
    c, _ = customer(db)
    t = desk_db.create_ticket(db, title="Done", contact_id=c["contact_id"], edition=r.SOLO)
    a = att.store_attachment(db, t["ticket_id"], _jpeg_with_gps((800, 600)), "after.jpg",
                             edition=r.SOLO, keep_gps=True, visibility="internal")
    img = Image.open(desk_files.ticket_folder(desk_db.root_for(db), t) / a["path"])
    assert 0x8825 in img.getexif() and a["visibility"] == "internal"


def test_documents_stored_as_is_and_sequence_numbers(db):
    c, cust = customer(db)
    t = desk_db.create_ticket(db, title="Quote", actor=cust, edition=r.SOLO)
    a1 = att.store_attachment(db, t["ticket_id"], b"%PDF-1.4 test", "quote.pdf", actor=cust,
                              edition=r.SOLO)
    a2 = att.store_attachment(db, t["ticket_id"], b"a,b\n1,2\n", "list.csv", edition=r.SOLO)
    assert (a1["filename"], a1["mime"]) == ("0001_quote.pdf", "application/pdf")
    assert a2["filename"] == "0002_list.csv" and a2["kind"] == "document"


def test_refused_uploads_leave_no_files(db):
    c, cust = customer(db)
    _, other = customer(db, phone="386-555-0111", name="Someone else")
    t = desk_db.create_ticket(db, title="Quote", actor=cust, edition=r.SOLO)
    folder = desk_files.ticket_folder(desk_db.root_for(db), t) / "attachments"
    with pytest.raises(att.AttachmentError, match="not accepted"):
        att.store_attachment(db, t["ticket_id"], b"MZ...", "tool.exe", actor=cust, edition=r.SOLO)
    with pytest.raises(desk_db.NotFoundError):
        att.store_attachment(db, t["ticket_id"], b"%PDF", "x.pdf", actor=other, edition=r.SOLO)
    with pytest.raises(att.AttachmentError, match="limit"):
        att.store_attachment(db, t["ticket_id"], b"0" * (att.MAX_FILE_BYTES + 1), "big.pdf",
                             actor=cust, edition=r.SOLO)
    with pytest.raises(att.AttachmentError, match="could not be read"):
        att.store_attachment(db, t["ticket_id"], b"not an image", "fake.jpg", actor=cust,
                             edition=r.SOLO)
    assert list(folder.iterdir()) == []


def test_customer_cannot_fetch_internal_attachment(db):
    c, cust = customer(db)
    t = desk_db.create_ticket(db, title="Quote", actor=cust, edition=r.SOLO)
    a = att.store_attachment(db, t["ticket_id"], b"%PDF", "notes.pdf", edition=r.SOLO,
                             visibility="internal")
    rec, path = desk_db.get_attachment(db, a["attachment_id"], edition=r.SOLO)
    assert path.exists()
    with pytest.raises(desk_db.NotFoundError):
        desk_db.get_attachment(db, a["attachment_id"], actor=cust, edition=r.SOLO)


def test_rebuild_keeps_attachment_links(db):
    c, cust = customer(db)
    t = desk_db.create_ticket(db, title="Photo", actor=cust, edition=r.SOLO)
    m = desk_db.add_message(db, t["ticket_id"], "see photo", actor=cust, visibility="public",
                            edition=r.SOLO)
    att.store_attachment(db, t["ticket_id"], _jpeg_with_gps((400, 300)), "p.jpg", actor=cust,
                         edition=r.SOLO, message_id=m["message_id"])
    for suffix in ("", "-wal", "-shm"):
        p = Path(db + suffix)
        if p.exists():
            p.unlink()
    assert desk_files.rebuild_from_files(db, dry_run=False)["restored"] == [t["ticket_id"]]
    detail = desk_db.get_ticket_detail(db, t["ticket_id"], edition=r.SOLO)
    assert detail["messages"][0]["attachments"] == [detail["attachments"][0]["attachment_id"]]
    assert detail["sms_fallback"] == 0
    assert desk_files.verify(db) == []
