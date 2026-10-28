"""Service Desk request page follows what AI-Prowler can actually send.

2026-10-28 (David): "can the customer request service page not show the
mobile phone entry box when SMS is not set up or enabled ... and if set up
then show both. The email has to be setup to allow customer service request."

  * no email set up  -> the form takes no requests (/info portal_enabled false,
                        /start refused), whatever the owner's switch says
  * email, no texting -> email only: /info sms false, a stray phone number is
                        ignored (never texted, never saved), phone-only refused
  * both set up       -> mobile or email, as before
The owner's app gets the same answer in /me (portal_channels) for Settings.
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
import desk_http  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402

EMAIL, PHONE = "pat@example.com", "386-555-0177"


@pytest.fixture
def desk(tmp_path):
    db = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(db)
    state = {"ch": {"email": True, "sms": True}, "sent": []}
    p.send_fn = lambda ch, to, subj, text: state["sent"].append((ch, to, text)) or True
    p.channels_fn = lambda: dict(state["ch"])
    yield db, state
    p.send_fn = None
    p.channels_fn = None


def _api(db, method, path, payload=None):
    st, _ct, body = p.route(method, "/support-api" + path, query={},
                            body=json.dumps(payload).encode() if payload is not None else b"",
                            content_type="application/json", ip="9.9.9.9", db_path=db, edition=r.SOLO)
    return st, json.loads(body)


def test_no_email_means_no_online_requests(desk):
    db, state = desk
    state["ch"] = {"email": False, "sms": True}
    st, d = _api(db, "GET", "/info")
    assert st == 200 and d["portal_enabled"] is False
    st, d = _api(db, "POST", "/start", {"phone": PHONE, "email": EMAIL})
    assert st == 400 and "aren't available" in d["message"]
    assert state["sent"] == []


def test_email_only_hides_the_phone_and_never_texts(desk):
    db, state = desk
    state["ch"] = {"email": True, "sms": False}
    st, d = _api(db, "GET", "/info")
    assert d["portal_enabled"] is True and d["sms"] is False
    st, d = _api(db, "POST", "/start", {"name": "Pat", "phone": PHONE})
    assert st == 400 and d["message"] == "enter your email address"
    st, d = _api(db, "POST", "/start", {"name": "Pat", "phone": PHONE, "email": EMAIL})
    assert st == 200 and d["sent_via"] == "email"
    assert [ch for ch, _, _ in state["sent"]] == ["email"]
    assert desk_db.get_contact(db, d["contact_id"])["phone"] is None      # stray number not saved
    code = re.search(r"\b(\d{6})\b", state["sent"][-1][2]).group(1)
    st, out = _api(db, "POST", "/verify", {"contact_id": d["contact_id"], "code": code, "title": "Gutters"})
    assert st == 201
    assert [ch for ch, _, _ in state["sent"]] == ["email", "email"]     # confirmation by email too


def test_both_set_up_shows_both_and_texts(desk):
    db, state = desk
    st, d = _api(db, "GET", "/info")
    assert d["portal_enabled"] is True and d["sms"] is True
    st, d = _api(db, "POST", "/start", {"phone": PHONE})
    assert st == 200 and d["sent_via"] == "sms"


def test_owner_switch_still_wins(desk):
    db, state = desk
    desk_db.set_setting(db, "portal_enabled", False, actor={"id": "owner", "role": "owner"})
    st, d = _api(db, "GET", "/info")
    assert d["portal_enabled"] is False


def test_a_broken_check_fails_closed(desk):
    db, state = desk

    def boom():
        raise RuntimeError("config unreadable")
    p.channels_fn = boom
    st, d = _api(db, "GET", "/info")
    assert d["portal_enabled"] is False and d["sms"] is False


@pytest.mark.parametrize("ch", [{"email": True, "sms": False}, {"email": False, "sms": False},
                                {"email": True, "sms": True}])
def test_owner_app_settings_get_the_same_answer(desk, ch):
    db, state = desk
    state["ch"] = ch
    st, _ct, body = desk_http.route("GET", "/desk-api/me", query={}, body=b"", content_type="",
                                    actor={"id": "owner", "role": "owner"}, edition=r.SOLO, db_path=db)
    assert st == 200 and json.loads(body)["portal_channels"] == ch
