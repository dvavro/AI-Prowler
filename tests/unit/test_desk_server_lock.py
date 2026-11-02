"""Server lock on Service Desk setup (David 2026-10-30 — security).

On an AI-Prowler SERVER nobody — owner included — can change Service Desk setup
through Claude / Muse / Grok (desk_tools) or the Service Desk app's API (desk_http).
Those changes are made only in AI-Prowler on the server (desk_gui_settings, which
writes straight to the database). Reading, exporting and "back up now" stay allowed.
On a PERSONAL install nothing changes.

Run: run_tests.bat tests\\unit\\test_desk_server_lock.py
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_gui_settings as dgs  # noqa: E402
import desk_http as h  # noqa: E402
import desk_rules as rules  # noqa: E402
import desk_tools as dt  # noqa: E402

OWNER = {"id": "dave", "role": "owner"}
MANAGER = {"id": "mgr", "role": "manager"}
BIZ, SOLO = "business", "solo"
LOCKED = "only be changed in AI-Prowler on the server"


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    return path


def call(db, method, path, body=None, *, actor=OWNER, edition=BIZ, raw=None, ctype="application/json"):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    st, ct, out = h.route(method, path, query={}, body=data, content_type=ctype, actor=actor,
                          edition=edition, db_path=db, services={})
    return st, (json.loads(out) if ct == b"application/json" else out)


def multipart(fields: dict, filename="t.csv", data=b"title\nx\n"):
    b = "----lockboundary"
    parts = [f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in fields.items()]
    parts.append((f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                  f'Content-Type: text/csv\r\n\r\n').encode() + data + b"\r\n")
    return b"".join(parts) + f"--{b}--\r\n".encode(), f"multipart/form-data; boundary={b}"


# ── Claude / Muse / Grok tools ───────────────────────────────────────────────

@pytest.mark.parametrize("actor", [None, OWNER], ids=["no-actor", "owner"])
def test_tools_refuse_every_setup_change_on_a_server(db, actor):
    before = desk_db.get_settings(db)
    outs = [
        dt.tickets_settings(db, actor, BIZ, setting="auto_close_days", value="9"),
        dt.tickets_settings(db, actor, BIZ, setting="agent_enabled", value="on"),
        dt.tickets_settings(db, actor, BIZ, setting="agent_name", value="Sam"),
        dt.manage_ticket_queues(db, actor, BIZ, action="save", queue_id="q1", name="Q", members="a"),
        dt.manage_ticket_queues(db, actor, BIZ, action="delete", queue_id="q1"),
        dt.manage_ticket_rules(db, actor, BIZ, action="save_rule", rule_id="r1", match='{"keyword":"x"}',
                               send_to_queue="q1"),
        dt.manage_ticket_rules(db, actor, BIZ, action="delete_rule", rule_id="r1"),
        dt.manage_ticket_rules(db, actor, BIZ, action="save_type", type_id="t1", type_name="T"),
        dt.tickets_backup_settings(db, actor, BIZ, backup_enabled="off"),
        dt.restore_tickets_database(db, actor, BIZ, backup_name="desk-x.zip", confirm=True),
        dt.import_tickets(db, actor, BIZ, filename="t.csv", dry_run=False),
        dt.import_tickets(db, actor, BIZ, undo_batch_id="IMP-1"),
    ]
    assert all(LOCKED in o for o in outs), [o for o in outs if LOCKED not in o]
    assert desk_db.get_settings(db) == before
    import desk_routing as rt
    assert not rt.list_queues(db) and not rt.list_rules(db)


def test_tools_still_read_on_a_server(db):
    assert "Service Desk settings" in dt.tickets_settings(db, None, BIZ)
    assert LOCKED not in dt.manage_ticket_queues(db, None, BIZ, action="list")
    assert LOCKED not in dt.manage_ticket_rules(db, None, BIZ, action="list")
    assert "Service Desk backups" in dt.tickets_backup_settings(db, None, BIZ)
    assert LOCKED not in dt.tickets_backup_now(db, None, BIZ)
    assert LOCKED not in dt.import_tickets(db, None, BIZ, filename="t.csv", dry_run=True)


def test_personal_install_is_unchanged(db):
    assert "✅ Saved." in dt.tickets_settings(db, None, SOLO, setting="auto_close_days", value="9")
    assert desk_db.get_settings(db)["auto_close_days"] == 9
    assert "Service Desk backups" in dt.tickets_backup_settings(db, None, SOLO, backup_enabled="off")
    assert desk_db.get_settings(db)["backup_enabled"] is False


# ── the Service Desk app's API ───────────────────────────────────────────────

@pytest.mark.parametrize("path,body", [
    ("/desk-api/settings", {"key": "auto_close_days", "value": 9}),
    ("/desk-api/settings", {"key": "agent_enabled", "value": True}),
    ("/desk-api/agent/photo/delete", {}),
    ("/desk-api/import/undo", {"batch_id": "IMP-1"}),
    ("/desk-api/backups/restore", {"name": "desk-x.zip", "confirm": True}),
    ("/desk-api/team/queue", {"queue_id": "q1", "name": "Q", "members": "a"}),
    ("/desk-api/team/queue/delete", {"queue_id": "q1"}),
    ("/desk-api/team/rule", {"rule_id": "r1", "match": {"keyword": "x"}, "action": {"queue": "q1"}}),
    ("/desk-api/team/rule/delete", {"rule_id": "r1"}),
    ("/desk-api/team/type", {"type_id": "t1", "name": "T"}),
])
@pytest.mark.parametrize("actor", [OWNER, MANAGER], ids=["owner", "manager"])
def test_api_refuses_setup_changes_on_a_server(db, path, body, actor):
    st, d = call(db, "POST", path, body, actor=actor)
    assert st == 403 and LOCKED in d["message"]


def test_api_photo_upload_and_real_import_refused_dry_run_allowed(db):
    raw, ct = multipart({}, "me.png", b"\x89PNG")
    assert call(db, "POST", "/desk-api/agent/photo", raw=raw, ctype=ct)[0] == 403
    raw, ct = multipart({"dry_run": "0"})
    st, d = call(db, "POST", "/desk-api/import", raw=raw, ctype=ct)
    assert st == 403 and LOCKED in d["message"]
    raw, ct = multipart({"dry_run": "1"})
    st, d = call(db, "POST", "/desk-api/import", raw=raw, ctype=ct)
    assert st == 200 and d["result"]["dry_run"] is True


def test_api_reads_still_work_on_a_server(db):
    assert call(db, "GET", "/desk-api/settings")[0] == 200
    assert call(db, "GET", "/desk-api/agent")[0] == 200
    assert call(db, "GET", "/desk-api/team")[0] == 200
    assert call(db, "POST", "/desk-api/backups", {})[0] == 200          # "back up now" changes no setup


def test_api_unchanged_on_a_personal_install(db):
    st, d = call(db, "POST", "/desk-api/settings", {"key": "auto_close_days", "value": 9}, actor=None, edition=SOLO)
    assert st == 200 and d["settings"]["auto_close_days"] == 9


# ── …while AI-Prowler on the server can still change everything ─────────────

def test_ai_prowler_on_the_server_still_changes_setup(db):
    assert dgs.set_one(db, "auto_close_days", 9, BIZ) == (True, "Saved.")
    assert dgs.set_one(db, "agent_enabled", True, BIZ)[0]
    dgs.save_queue(db, "q1", "Q", "a", BIZ)
    assert dgs.save_backup_settings(db, {"backup_enabled": False}, BIZ)[0]
    s = desk_db.get_settings(db)
    assert (s["auto_close_days"], s["agent_enabled"], s["backup_enabled"]) == (9, True, False)
    assert dgs.team(db)["queues"][0]["queue_id"] == "q1"


def test_lock_message_says_where_to_go():
    assert rules.server_locked(BIZ) and not rules.server_locked(SOLO)
    assert "Small Business tab" in rules.SERVER_LOCK_MSG and "only" in rules.SERVER_LOCK_MSG
