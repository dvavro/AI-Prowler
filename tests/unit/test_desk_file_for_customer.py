"""Filing a Customer request FOR a customer from the Service Desk app (2026-10-29).

Solo: the owner files for a customer who phoned / texted / walked in.
Business: anyone on the team (owner, manager, staff, field crew) can.
The ticket records how the customer reached us (source) and who filed it.

Run: run_tests.bat tests\\unit\\test_desk_file_for_customer.py
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_http as h  # noqa: E402

TEAM = [{"id": "dave", "role": "owner"}, {"id": "mgr", "role": "manager"},
        {"id": "sam", "role": "staff"}, {"id": "cris", "role": "field_crew"}]
CUSTOMER = {"id": "c1", "role": "customer", "contact_id": "C-0001"}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    return path


def call(db, method, path, body=None, *, actor=None, edition="solo"):
    data = json.dumps(body).encode() if body is not None else b""
    st, ct, out = h.route(method, path, query={}, body=data, content_type="application/json",
                          actor=actor, edition=edition, db_path=db)
    return st, json.loads(out)


def req(**kw):
    return {"kind": "external", "title": "Streaky windows", "contact_name": "Lopez",
            "contact_phone": "386-555-0100", **kw}


def test_solo_owner_files_for_a_caller(db):
    assert "external" in call(db, "GET", "/desk-api/me")[1]["kinds"]
    st, d = call(db, "POST", "/desk-api/tickets", req(source="phone"))
    assert st == 201
    t = call(db, "GET", "/desk-api/tickets/" + d["ticket"]["ticket_id"])[1]["ticket"]
    assert t["source"] == "phone" and t["filed_by"] == "owner" and t["contact_id"]
    assert t["assignee"] == "owner"                     # Solo: always the owner's


def test_solo_owner_can_still_file_his_own_ticket(db):
    st, d = call(db, "POST", "/desk-api/tickets", {"kind": "internal", "title": "Buy squeegees"})
    assert st == 201 and d["ticket"]["kind"] == "internal"


@pytest.mark.parametrize("who", TEAM, ids=lambda a: a["role"])
def test_everyone_on_the_team_can_file_for_a_customer(db, who):
    assert "external" in call(db, "GET", "/desk-api/me", actor=who, edition="business")[1]["kinds"]
    st, d = call(db, "POST", "/desk-api/tickets", req(source="walk_in"), actor=who, edition="business")
    assert st == 201, d
    tid = d["ticket"]["ticket_id"]
    st, t = call(db, "GET", "/desk-api/tickets/" + tid, actor=who, edition="business")
    assert st == 200, "the filer can always open what they filed"
    assert t["ticket"]["source"] == "walk_in" and t["ticket"]["filed_by"] == who["id"]


def test_customer_request_needs_phone_or_email(db):
    st, d = call(db, "POST", "/desk-api/tickets", {"kind": "external", "title": "x", "contact_name": "Lopez"},
                 actor=TEAM[2], edition="business")
    assert st == 400 and "phone or email" in d["message"]


def test_unknown_or_misused_source_falls_back_to_pwa(db):
    _, d = call(db, "POST", "/desk-api/tickets", req(source="portal"))          # can't fake the form
    assert call(db, "GET", "/desk-api/tickets/" + d["ticket"]["ticket_id"])[1]["ticket"]["source"] == "pwa"
    _, d = call(db, "POST", "/desk-api/tickets", {"kind": "internal", "title": "y", "source": "phone"})
    assert call(db, "GET", "/desk-api/tickets/" + d["ticket"]["ticket_id"])[1]["ticket"]["source"] == "pwa"


def test_app_picker_matches_server_list():
    html = (ROOT / "desk" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"const VIA = \{(.*?)\};", html)
    assert m, "VIA list missing from desk/index.html"
    assert set(re.findall(r"(\w+):\s*'", m.group(1))) == set(h.PWA_SOURCES)
    assert 'id="nVia"' in html and 'id="filedBy"' in html
