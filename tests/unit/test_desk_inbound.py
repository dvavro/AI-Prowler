"""Service Desk Phase 2 — desk_inbound (texts and emails) and desk_imap (poller)."""
import datetime
import sys
from email.message import EmailMessage
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_imap  # noqa: E402
import desk_inbound as inb  # noqa: E402
import desk_portal  # noqa: E402
import desk_rules as r  # noqa: E402

BASE = "https://desk.example"


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    sent = []
    desk_portal.send_fn = lambda ch, to, subj, text: sent.append((ch, to, subj, text)) or True
    yield path
    desk_portal.send_fn = None


def sms(db, body, frm="+13865550100", **kw):
    return inb.handle_sms(db, frm, body, edition=r.SOLO, base_url=BASE, business="VFS", **kw)


def test_default_mode_off_does_nothing(db):
    assert sms(db, "Hi, can you come clean my gutters?") == ""
    assert desk_db.list_tickets(db) == []


def test_reply_threads_onto_open_ticket(db):
    c = desk_db.upsert_contact(db, name="Lopez", phone="386-555-0100")
    t = desk_db.create_ticket(db, title="Streaks", contact_id=c["contact_id"], edition=r.SOLO)
    desk_db.change_state(db, t["ticket_id"], r.IN_PROGRESS, edition=r.SOLO)
    desk_db.change_state(db, t["ticket_id"], r.ON_HOLD, reason="waiting on customer", edition=r.SOLO)
    assert sms(db, "Thursday works") == ""
    d = desk_db.get_ticket_detail(db, t["ticket_id"], edition=r.SOLO)
    assert d["messages"][-1]["body"] == "Thursday works" and d["messages"][-1]["channel"] == "sms"
    assert d["state"] == r.IN_PROGRESS                   # the wait is over


def test_team_phones_are_ignored(db):
    desk_db.set_setting(db, "sms_new_request_mode", "create", edition=r.SOLO)
    assert sms(db, "running late", team_phones=["(386) 555-0100"]) == ""
    assert desk_db.list_tickets(db) == []


def test_create_mode(db):
    desk_db.set_setting(db, "sms_new_request_mode", "create", edition=r.SOLO)
    out = sms(db, "Can you pressure wash my driveway next week?\nThanks")
    assert out.startswith("VFS: Thanks — we opened request T-0001") and BASE + "/support/t/" in out
    t = desk_db.get_ticket(db, "T-0001")
    assert t["source"] == "sms" and t["title"] == "Can you pressure wash my driveway next week?"
    assert sms(db, "also the back patio") == ""          # now threads onto T-0001
    assert len(desk_db.list_tickets(db)) == 1


def test_link_mode(db):
    desk_db.set_setting(db, "sms_new_request_mode", "link", edition=r.SOLO)
    assert sms(db, "hello") == f"VFS: To open a service request, use this form: {BASE}/support/new"


def test_ask_mode_yes_no_and_expiry(db):
    desk_db.set_setting(db, "sms_new_request_mode", "ask", edition=r.SOLO)
    assert "Reply YES or NO" in sms(db, "Gutters overflowing")
    assert "opened request T-0001" in sms(db, "Yes!")
    assert desk_db.get_ticket(db, "T-0001")["title"] == "Gutters overflowing"
    assert "Reply YES or NO" in sms(db, "Another thing", frm="+13865550111")
    assert "won't open" in sms(db, "no", frm="+13865550111")
    assert "Reply YES or NO" in sms(db, "Windows", frm="+13865550122")
    later = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=25)
    assert "Reply YES or NO" in inb.handle_sms(db, "+13865550122", "yes", edition=r.SOLO,
                                               base_url=BASE, now=later)   # stale question: asks again


def test_email_reply_threads_by_subject_tag_and_strips_quotes(db):
    c = desk_db.upsert_contact(db, name="Lopez", email="l@x.com")
    t = desk_db.create_ticket(db, title="Streaks", contact_id=c["contact_id"], edition=r.SOLO)
    body = "Thursday is fine.\n\nOn Mon, Oct 26, 2026 at 9:00 AM VFS <us@x.com> wrote:\n> We can come Thursday"
    assert inb.handle_email(db, "Mrs Lopez <L@x.com>", f"Re: Streaks [{t['ticket_id']}]", body,
                            edition=r.SOLO) == "threaded"
    assert desk_db.get_ticket_detail(db, t["ticket_id"])["messages"][-1]["body"] == "Thursday is fine."
    # someone else using the tag is ignored
    assert inb.handle_email(db, "evil@x.com", f"Re: [{t['ticket_id']}]", "hi", edition=r.SOLO) == "ignored"


def test_email_new_request_mode(db):
    assert inb.handle_email(db, "a@b.com", "Need a quote", "Windows please", edition=r.SOLO) == "ignored"
    desk_db.set_setting(db, "email_new_request_mode", "create", edition=r.SOLO)
    assert inb.handle_email(db, "Ann <a@b.com>", "Need a quote", "Windows please",
                            edition=r.SOLO, base_url=BASE) == "created"
    t = desk_db.get_ticket(db, "T-0001")
    assert t["title"] == "Need a quote" and t["source"] == "email"
    assert desk_db.get_contact(db, t["contact_id"])["name"] == "Ann"
    assert inb.handle_email(db, "boss@team.com", "x", "y", edition=r.SOLO,
                            team_emails=["boss@team.com"]) == "ignored"


# ── IMAP poller with a fake mailbox ──────────────────────────────────────────

class FakeIMAP:
    def __init__(self, msgs):
        self.msgs, self.flags, self.logged = msgs, {}, False

    def __call__(self, host, port):
        self.host, self.port = host, port
        return self

    def login(self, u, pw):
        self.logged = (u, pw)

    def select(self, box):
        return "OK", [b"1"]

    def search(self, *a):
        return "OK", [b" ".join(str(i + 1).encode() for i in range(len(self.msgs)))]

    def fetch(self, num, what):
        assert "PEEK" in what
        return "OK", [(b"1 (BODY[] {n})", self.msgs[int(num) - 1].as_bytes()), b")"]

    def store(self, num, op, flag):
        self.flags[int(num)] = flag

    def logout(self):
        pass


def mail(frm, subject, body, mid):
    m = EmailMessage()
    m["From"], m["Subject"], m["Message-ID"] = frm, subject, mid
    m.set_content(body)
    return m


def test_imap_settings_from_email_config():
    assert desk_imap.imap_settings({"smtp_host": "smtp.gmail.com", "username": "u", "password": "p"}) == \
        {"host": "imap.gmail.com", "port": 993, "user": "u", "password": "p"}
    assert desk_imap.imap_settings({"backend": "outlook"}) is None


def test_poll_threads_marks_only_used_mail_and_never_twice(db):
    c = desk_db.upsert_contact(db, name="Lopez", email="l@x.com")
    t = desk_db.create_ticket(db, title="Streaks", contact_id=c["contact_id"], edition=r.SOLO)
    fake = FakeIMAP([mail("l@x.com", f"Re: [{t['ticket_id']}]", "Thanks!", "<a@x>"),
                     mail("news@shop.com", "Big sale", "buy", "<b@x>")])
    cfg = {"smtp_host": "smtp.x.com", "username": "u", "password": "p"}
    handle = lambda f, s, b: inb.handle_email(db, f, s, b, edition=r.SOLO)  # noqa: E731
    out = desk_imap.poll_once(db, cfg, handle, imap_factory=fake)
    assert out["threaded"] == 1 and out["ignored"] == 1 and fake.host == "imap.x.com"
    assert fake.flags == {1: "\\Seen"}                    # the newsletter stays unread
    again = desk_imap.poll_once(db, cfg, handle, imap_factory=fake)
    assert again["checked"] == 0
    assert len(desk_db.get_ticket_detail(db, t["ticket_id"])["messages"]) == 1
