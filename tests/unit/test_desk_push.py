"""Service Desk Phase 5 — web push (desk_push) and its use by alerts."""
import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_alerts  # noqa: E402
import desk_db  # noqa: E402
import desk_http  # noqa: E402
import desk_push  # noqa: E402

CREW = {"id": "cris", "role": "field_crew"}
MANAGER = {"id": "mgr", "role": "manager"}
SUB = {"endpoint": "https://push.example/abc", "keys": {"p256dh": "BPk", "auth": "au"}}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    yield path
    desk_push.sender = None
    desk_alerts.reset()


def test_keys_are_made_once_and_are_a_p256_point(db):
    pub, pem = desk_push.keys(db)
    raw = base64.urlsafe_b64decode(pub + "=" * (-len(pub) % 4))
    assert len(raw) == 65 and raw[0] == 4 and "PRIVATE KEY" in pem
    assert desk_push.keys(db) == (pub, pem)


def test_subscribe_validation_and_outside_parties(db):
    assert desk_push.subscribe(db, SUB, actor=CREW)["user"] == "cris"
    with pytest.raises(desk_db.DeskError, match="not a valid"):
        desk_push.subscribe(db, {"endpoint": "http://x"}, actor=CREW)
    with pytest.raises(desk_db.DeskError, match="for your team"):
        desk_push.subscribe(db, SUB, actor={"id": "c", "role": "customer", "contact_id": "CT-1"})
    desk_push.subscribe(db, SUB, actor=MANAGER)          # same phone, new owner
    assert desk_push.subscriptions(db, "cris") == [] and len(desk_push.subscriptions(db, "mgr")) == 1


def test_send_counts_and_drops_retired_subscriptions(db):
    desk_push.subscribe(db, SUB, actor=CREW)
    desk_push.subscribe(db, {**SUB, "endpoint": "https://push.example/old"}, actor=CREW)
    seen = []

    def fake(sub, payload, pem):
        seen.append(json.loads(payload))
        return 410 if sub["endpoint"].endswith("old") else 201
    desk_push.sender = fake
    assert desk_push.send(db, "cris", "Service Desk", "T-0001 assigned", "/desk/#T-0001", "T-0001") == 1
    assert seen[0]["ticket_id"] == "T-0001" and seen[0]["url"] == "/desk/#T-0001"
    assert [s["endpoint"] for s in desk_push.subscriptions(db, "cris")] == ["https://push.example/abc"]
    assert desk_push.send(db, "nobody", "x", "y") == 0


def test_alerts_go_by_push_too(db):
    desk_push.subscribe(db, SUB, actor=CREW)
    pushed = []
    desk_push.sender = lambda sub, payload, pem: pushed.append(json.loads(payload)) or 201
    desk_alerts.configure(push=lambda uid, t, b, u, tid: desk_push.send(db, uid, t, b, u, tid) > 0,
                          email=lambda *a: True, team=lambda: [{"id": "cris", "role": "field_crew",
                                                                "email": "c@x.com"}],
                          db_path=lambda: db, background=False)
    desk_db.create_ticket(db, title="Pump", kind="internal", actor=MANAGER, assignee="cris")
    assert len(pushed) == 1 and "T-0001" in pushed[0]["body"] and pushed[0]["url"] == "/desk/#T-0001"


def test_push_routes(db):
    def call(method, path, body=None, actor=CREW):
        st, ct, out = desk_http.route(method, path, query={}, body=json.dumps(body or {}).encode(),
                                      content_type="application/json", actor=actor, edition="business",
                                      db_path=db)
        return st, json.loads(out)
    st, d = call("GET", "/desk-api/push/key")
    assert st == 200 and len(d["key"]) > 80
    assert call("POST", "/desk-api/push/subscribe", {"subscription": SUB})[1]["user"] == "cris"
    assert call("POST", "/desk-api/push/unsubscribe", {"endpoint": SUB["endpoint"]})[0] == 200
    assert desk_push.subscriptions(db, "cris") == []


def test_real_sender_is_importable():
    pytest.importorskip("pywebpush")
    from py_vapid import Vapid01  # noqa: F401
