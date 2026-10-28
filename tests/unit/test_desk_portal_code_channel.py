"""Service Desk request page - the code goes where the customer asked.

2026-10-28 (David): "we couldn't send a code right now" on every try. His
contact had a mobile number from an earlier try (texting isn't set up on
his install), so every later EMAIL-only request still tried to text the
number on file - and failed. The code now goes to what the customer typed
this time; with both, text first and email if texting fails. The "we got
your request" message falls back to email the same way.
"""
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

EMAIL, PHONE, E164 = "David.Vavro1@gmail.com", "386-555-0188", "+13865550188"


@pytest.fixture
def desk(tmp_path):
    db = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(db)
    state = {"sms_works": False, "sent": []}

    def send(ch, to, subj, text):
        if ch == "sms" and not state["sms_works"]:
            return False                      # texting not set up
        state["sent"].append((ch, to, text))
        return True
    p.send_fn = send
    yield db, state
    p.send_fn = None


def _code(state, to):
    hits = [t for ch, dest, t in state["sent"] if dest == to and "code is" in t]
    return re.search(r"\b(\d{6})\b", hits[-1]).group(1)


def test_davids_case_email_works_after_a_failed_text_try(desk):
    db, state = desk
    # 1. first request by email - fine
    s = p.start_request(db, name="David Vavro", email=EMAIL, ip="1.1.1.1")
    assert s["sent_via"] == "email"
    p.verify_and_file(db, contact_id=s["contact_id"], code=_code(state, EMAIL.lower()), title="fix window",
                      ip="1.1.1.1", edition=r.SOLO)
    # 2. from the phone, mobile number AND email - texting isn't set up; it used
    #    to fail here, now the code falls back to the email
    s2 = p.start_request(db, name="David Vavro", phone=PHONE, email=EMAIL, ip="2.2.2.2")
    assert s2["sent_via"] == "email" and s2["contact_id"] == s["contact_id"]
    assert desk_db.get_contact(db, s["contact_id"])["phone"] == E164     # number now on the contact
    # 3. back to email only - used to try the number on file and fail
    s3 = p.start_request(db, name="David Vavro", email=EMAIL, ip="3.3.3.3")
    assert s3["sent_via"] == "email" and s3["contact_id"] == s["contact_id"]
    out = p.verify_and_file(db, contact_id=s3["contact_id"], code=_code(state, EMAIL.lower()),
                            title="test web ticket file", description="testing web", ip="3.3.3.3",
                            edition=r.SOLO)
    assert out["ticket_id"] == "T-0002"
    # the "we got your request" message also fell back to email
    assert any(ch == "email" and "We got your request T-0002" in t for ch, _to, t in state["sent"])


def test_both_given_text_fails_falls_back_to_email(desk):
    db, state = desk
    s = p.start_request(db, phone=PHONE, email=EMAIL, ip="4.4.4.4")
    assert s["sent_via"] == "email"


def test_both_given_text_works_uses_text(desk):
    db, state = desk
    state["sms_works"] = True
    s = p.start_request(db, phone=PHONE, email=EMAIL, ip="5.5.5.5")
    assert s["sent_via"] == "sms" and state["sent"][-1][1] == E164


def test_email_only_never_texts_a_number_on_file_even_when_texting_works(desk):
    db, state = desk
    state["sms_works"] = True
    p.start_request(db, phone=PHONE, email=EMAIL, ip="6.6.6.6")
    state["sent"].clear()
    s = p.start_request(db, email=EMAIL, ip="6.6.6.7")
    assert s["sent_via"] == "email" and [ch for ch, _, _ in state["sent"]] == ["email"]


def test_phone_only_and_texting_down_asks_for_email(desk):
    db, state = desk
    with pytest.raises(desk_db.DeskError, match="enter your email address instead"):
        p.start_request(db, phone=PHONE, ip="8.8.8.8")


def test_nothing_works_says_so(desk):
    db, state = desk
    p.send_fn = lambda *a: False
    with pytest.raises(desk_db.DeskError, match="couldn't send a code right now"):
        p.start_request(db, email=EMAIL, ip="7.7.7.7")
