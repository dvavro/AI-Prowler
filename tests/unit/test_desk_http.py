"""Service Desk Phase 1 — desk_http: /desk-api routes and /desk/ app files."""
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_http as h  # noqa: E402

OWNER_S = {"id": "dave", "role": "owner", "name": "Dave"}
MANAGER = {"id": "mgr", "role": "manager"}
CREW = {"id": "cris", "role": "field_crew"}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    return path


def call(db, method, path, body=None, *, actor=None, edition="solo", query=None, raw=None,
         ctype="application/json"):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    st, ct, out = h.route(method, path, query=query or {}, body=data, content_type=ctype,
                          actor=actor, edition=edition, db_path=db)
    return st, (json.loads(out) if ct == b"application/json" else out)


def multipart(files, fields=None):
    boundary = "----deskboundary"
    parts = []
    for k, v in (fields or {}).items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for name, data in files:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
                     f'Content-Type: application/octet-stream\r\n\r\n'.encode() + data + b"\r\n")
    return b"".join(parts) + f"--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def test_me_lists_allowed_kinds_moves_and_reasons(db):
    st, d = call(db, "GET", "/desk-api/me")
    assert st == 200 and d["edition"] == "solo" and d["actor"]["role"] == "owner"
    assert d["kinds"] == ["external", "internal", "subcontractor"]
    assert "Fixed" in d["transitions"]["In Progress"] and ["Fixed", "Closed"] not in d["needs_reason"]
    assert ["In Progress", "On Hold"] in d["needs_reason"]
    desk_db.set_setting(db, "own_tickets", False, edition="solo")
    assert call(db, "GET", "/desk-api/me")[1]["kinds"] == ["external", "subcontractor"]


def test_file_list_detail_move_and_message(db):
    st, d = call(db, "POST", "/desk-api/tickets",
                 {"kind": "external", "title": "Streaky windows", "contact_name": "Lopez",
                  "contact_phone": "386-555-0100", "due": "2026-10-31", "priority": "p2"})
    assert st == 201 and d["ticket"]["ticket_id"] == "T-0001" and d["ticket"]["priority"] == "P2"
    st, d = call(db, "GET", "/desk-api/tickets", query={"mine": "1"})
    assert [t["ticket_id"] for t in d["tickets"]] == ["T-0001"] and d["cursor"]
    st, d = call(db, "POST", "/desk-api/tickets/T-0001/state",
                 {"to_state": "In Progress", "expected_version": 1})
    assert st == 200 and d["ticket"]["state"] == "In Progress"
    st, d = call(db, "POST", "/desk-api/tickets/T-0001/messages", {"body": "On my way", "visibility": "public"})
    assert st == 201 and d["message"]["delivery_status"] == "queued"
    st, d = call(db, "GET", "/desk-api/tickets/T-0001")
    assert d["ticket"]["messages"][0]["body"] == "On my way" and d["ticket"]["rev"] == 3


def test_stale_edit_is_409_and_reason_rules_are_400(db):
    call(db, "POST", "/desk-api/tickets", {"kind": "internal", "title": "Tire"})
    call(db, "POST", "/desk-api/tickets/T-0001/state", {"to_state": "In Progress"})
    st, d = call(db, "POST", "/desk-api/tickets/T-0001/state",
                 {"to_state": "Fixed", "expected_version": 1})
    assert st == 409 and d["error"] == "stale"
    st, d = call(db, "POST", "/desk-api/tickets/T-0001/state", {"to_state": "On Hold"})
    assert st == 400 and "needs a reason" in d["message"]


def test_business_scoping_and_refusals(db):
    call(db, "POST", "/desk-api/tickets", {"kind": "internal", "title": "Pump", "assignee": "cris"},
         actor=MANAGER, edition="business")
    call(db, "POST", "/desk-api/tickets", {"kind": "internal", "title": "Private", "private": True},
         actor=OWNER_S, edition="business")
    st, d = call(db, "GET", "/desk-api/tickets", actor=CREW, edition="business")
    assert [t["title"] for t in d["tickets"]] == ["Pump"]
    st, d = call(db, "GET", "/desk-api/tickets/T-0002", actor=CREW, edition="business")
    assert st == 404
    st, d = call(db, "POST", "/desk-api/tickets/T-0001/state",
                 {"to_state": "Closed", "reason": "done"}, actor=CREW, edition="business")
    assert st == 403
    st, d = call(db, "POST", "/desk-api/settings", {"key": "own_tickets", "value": False},
                 actor=MANAGER, edition="business")
    assert st == 403


def test_update_with_due_and_reason(db):
    call(db, "POST", "/desk-api/tickets", {"kind": "internal", "title": "Tire"})
    st, d = call(db, "POST", "/desk-api/tickets/T-0001/update",
                 {"fields": {"priority": "P1", "due": "2026-11-02"}, "reason": "route day"})
    assert st == 200 and d["ticket"]["priority"] == "P1" and d["ticket"]["due_resolve_at"]


def test_upload_photo_and_fetch_it_and_its_thumbnail(db):
    from PIL import Image
    call(db, "POST", "/desk-api/tickets", {"kind": "internal", "title": "Tire"})
    buf = io.BytesIO()
    Image.new("RGB", (1200, 900), (10, 200, 30)).save(buf, "PNG")
    body, ctype = multipart([("tire.png", buf.getvalue()), ("receipt.pdf", b"%PDF-1.4 x")],
                            {"visibility": "public"})
    st, d = call(db, "POST", "/desk-api/tickets/T-0001/attachments", raw=body, ctype=ctype)
    assert st == 201 and [a["kind"] for a in d["attachments"]] == ["photo", "document"]
    aid = d["attachments"][0]["attachment_id"]
    st, img = call(db, "GET", f"/desk-api/attachments/{aid}")
    assert st == 200 and img[:3] == b"\xff\xd8\xff"
    st, thumb = call(db, "GET", f"/desk-api/attachments/{aid}", query={"thumb": "1"})
    assert st == 200 and len(thumb) < len(img)
    st, d = call(db, "POST", "/desk-api/tickets/T-0001/attachments", raw=b"x", ctype="text/plain")
    assert st == 400 and "multipart" in d["message"]


def test_outside_party_gets_trimmed_tickets(db):
    c = desk_db.upsert_contact(db, name="Lopez", phone="386-555-0100")
    cust = {"id": "cust", "role": "customer", "contact_id": c["contact_id"]}
    call(db, "POST", "/desk-api/tickets", {"kind": "external", "title": "Streaks",
                                           "contact_id": c["contact_id"]})
    call(db, "POST", "/desk-api/tickets/T-0001/messages", {"body": "picky customer"})
    st, d = call(db, "GET", "/desk-api/tickets", actor=cust)
    assert "assignee" not in d["tickets"][0] and "filed_by" not in d["tickets"][0]
    st, d = call(db, "GET", "/desk-api/tickets/T-0001", actor=cust)
    assert d["ticket"]["messages"] == [] and "events" not in d["ticket"]
    st, d = call(db, "GET", "/desk-api/contacts", actor=cust)
    assert st == 403


def test_status_link_and_redo_job_routes(db):
    call(db, "POST", "/desk-api/tickets", {"kind": "external", "title": "Streaks",
                                           "contact_phone": "386-555-0100"})
    call(db, "POST", "/desk-api/tickets", {"kind": "internal", "title": "Tire"})
    st, ct, out = h.route("POST", "/desk-api/tickets/T-0001/link", query={}, body=b"{}",
                          content_type="application/json", actor=None, edition="solo", db_path=db,
                          services={"base_url": "https://desk.example"})
    url = json.loads(out)["url"]
    assert st == 200 and url.startswith("https://desk.example/support/t/")
    import desk_portal
    assert desk_portal.resolve_link(db, url.rsplit("/", 1)[1])[0]["ticket_id"] == "T-0001"
    st, d = call(db, "POST", "/desk-api/tickets/T-0002/link", {})
    assert st in (400, 403) and "status links" in d["message"]
    st, d = call(db, "POST", "/desk-api/tickets/T-0001/job", {"service_date": "2026-11-04"})
    assert st == 400 and "Jobs app is not available" in d["message"]
    st, ct, out = h.route("POST", "/desk-api/tickets/T-0001/job", query={},
                          body=json.dumps({"service_date": "2026-11-04", "customer_id": "CUST-0001"}).encode(),
                          content_type="application/json", actor=None, edition="solo", db_path=db,
                          services={"create_job": lambda u: "✅ ok\nNEW_JOB_ID=JOB-0009"})
    assert st == 200 and "JOB-0009" in json.loads(out)["message"]
    assert desk_db.get_ticket(db, "T-0001")["job_id"] == "JOB-0009"


def test_phase3_routes_report_export_import_backups_team(db):
    biz = dict(actor=OWNER_S, edition="business")
    call(db, "POST", "/desk-api/tickets", {"kind": "internal", "title": "Pump", "assignee": "cris"}, **biz)
    st, d = call(db, "GET", "/desk-api/report", query={"group_by": "assignee"}, **biz)
    assert st == 200 and d["report"]["groups"]["cris"]["tickets"] == 1 and "1 ticket(s)" in d["text"]
    assert call(db, "GET", "/desk-api/report", actor=CREW, edition="business")[0] == 403
    st, xlsx = call(db, "GET", "/desk-api/export", query={"format": "xlsx"}, **biz)
    assert st == 200 and xlsx[:2] == b"PK"
    st, pdf = call(db, "GET", "/desk-api/export", query={"format": "pdf", "ticket_id": "T-0001"}, **biz)
    assert pdf.startswith(b"%PDF")
    body, ctype = multipart([("in.csv", b"Title\nGutters\nWindows\n")], {"dry_run": "1"})
    st, d = call(db, "POST", "/desk-api/import", raw=body, ctype=ctype, **biz)
    assert d["result"]["to_add"] == 2 and d["result"]["dry_run"]
    body, ctype = multipart([("in.csv", b"Title\nGutters\nWindows\n")], {"dry_run": "0"})
    st, d = call(db, "POST", "/desk-api/import", raw=body, ctype=ctype, **biz)
    batch = d["result"]["batch_id"]
    st, d = call(db, "POST", "/desk-api/import/undo", {"batch_id": batch}, **biz)
    assert len(d["result"]["removed"]) == 2
    st, d = call(db, "GET", "/desk-api/backups", **biz)
    assert any(b["trigger"] == "pre-import" for b in d["backups"]) and "backup_hour" in d["settings"]
    st, d = call(db, "POST", "/desk-api/backups", {}, **biz)
    name = d["backup"]["name"]
    st, z = call(db, "GET", f"/desk-api/backups/{name}", **biz)
    assert st == 200 and z[:2] == b"PK"
    st, d = call(db, "POST", "/desk-api/backups/restore", {"name": name}, **biz)
    assert d["result"]["needs_confirm"]
    assert call(db, "GET", "/desk-api/backups", actor=MANAGER, edition="business")[0] == 403
    st, d = call(db, "POST", "/desk-api/team/queue", {"queue_id": "field", "members": "ann, bob"}, **biz)
    assert d["queue"]["members"] == ["ann", "bob"]
    st, d = call(db, "POST", "/desk-api/team/rule", {"rule_id": "inv", "match": {"keyword": "invoice"},
                                                     "action": {"user": "dave"}}, **biz)
    st, d = call(db, "GET", "/desk-api/team", **biz)
    assert d["queues"][0]["queue_id"] == "field" and d["rules"][0]["rule_id"] == "inv"
    assert call(db, "POST", "/desk-api/team/queue", {"queue_id": "x"}, actor=MANAGER,
                edition="business")[0] == 403


def test_bad_json_and_unknown_routes(db):
    st, d = call(db, "POST", "/desk-api/tickets", raw=b"{not json")
    assert st == 400 and "not valid JSON" in d["message"]
    st, d = call(db, "GET", "/desk-api/teleport")
    assert st == 404 and d["error"] == "unknown_route"


def test_static_files_and_traversal():
    st, ct, body, rel = h.static_file("/desk/")
    assert st == 200 and rel == "index.html" and b"Service Desk" in body
    st, ct, body, rel = h.static_file("/desk/manifest.json")
    assert st == 200 and json.loads(body)["start_url"] == "/desk/"
    st, ct, body, rel = h.static_file("/desk/../ai_prowler_mcp.py")
    assert st == 403
    st, ct, body, rel = h.static_file("/desk/%2e%2e/VERSION")
    assert st == 403
    st, ct, body, rel = h.static_file("/desk/some/deep/link")
    assert st == 200 and rel == "index.html"
