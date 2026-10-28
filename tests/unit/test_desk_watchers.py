"""Service Desk — watchers, the address book, and the customer's two
one-line updates (David 2026-10-28: "customers ... just need to be notified
when it's in process and closed, but internal folks need to be watchers when
it changes state")."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_alerts  # noqa: E402
import desk_backup  # noqa: E402
import desk_db  # noqa: E402
import desk_files  # noqa: E402
import desk_http  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_tools  # noqa: E402

TEAM = [
    {"id": "dave", "name": "Dave", "role": "owner", "email": "dave@x.com", "phone": "+15550100001"},
    {"id": "mgr", "name": "Mia", "role": "manager", "email": "mia@x.com", "phone": "+15550100002"},
    {"id": "cris", "name": "Cris", "role": "field_crew", "email": "cris@x.com", "phone": "+15550100003"},
    {"id": "sam", "name": "Sam", "role": "staff", "email": "sam@x.com", "phone": "+15550100004"},
]
OWNER, MANAGER, CREW, STAFF = ({"id": u["id"], "role": u["role"], "name": u["name"], "email": u["email"]}
                               for u in TEAM)


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


def _customer_ticket(db, email="lopez@example.test", phone=None):
    c = desk_db.upsert_contact(db, name="Mrs Lopez", email=email, phone=phone)
    return desk_db.create_ticket(db, title="Streaky windows", kind="external", actor=MANAGER,
                                 contact_id=c["contact_id"], assignee="cris")["ticket_id"]


def test_who_may_change_watchers(setup):
    db, _ = setup
    tid = _customer_ticket(db)
    ws = desk_db.set_watcher(db, tid, "Vicki@Example.test", name="Vicki", actor=MANAGER)
    assert [w["email"] for w in ws] == ["vicki@example.test"]           # stored lower-case
    desk_db.set_watcher(db, tid, "jamie@example.test", actor=CREW)        # crew is the assignee here
    sams = desk_db.create_ticket(db, title="Sam filed it", kind="internal", actor=STAFF)["ticket_id"]
    desk_db.assign_ticket(db, sams, "cris", actor=MANAGER)               # Sam can see it, isn't assignee
    with pytest.raises(desk_db.DeskError, match="yourself"):
        desk_db.set_watcher(db, sams, "other@example.test", actor=STAFF)
    assert desk_db.set_watcher(db, sams, "sam@x.com", actor=STAFF)[0]["email"] == "sam@x.com"  # ...but may add themself
    desk_db.set_watcher(db, tid, "sam@x.com", actor=MANAGER)
    with pytest.raises(desk_db.DeskError, match="not an email"):
        desk_db.set_watcher(db, tid, "vicki", actor=MANAGER)
    with pytest.raises(desk_db.DeskError, match="customer"):
        desk_db.set_watcher(db, tid, "lopez@example.test", actor=MANAGER)  # the ticket's own customer
    cust = {"id": "c", "role": "customer", "contact_id": _t(db, tid)["contact_id"]}
    with pytest.raises(desk_db.DeskError):
        desk_db.set_watcher(db, tid, "x@example.test", actor=cust)
    desk_db.set_watcher(db, tid, "jamie@example.test", remove=True, actor=MANAGER)
    assert {w["email"] for w in desk_db.list_watchers(db, tid)} == {"vicki@example.test", "sam@x.com"}


def _t(db, tid):
    return desk_db.get_ticket(db, tid)


def test_watchers_kept_in_ticket_json_hidden_from_customers_and_restored(setup):
    db, _ = setup
    tid = _customer_ticket(db)
    desk_db.set_watcher(db, tid, "vicki@example.test", name="Vicki", actor=MANAGER)
    root = desk_db.root_for(db)
    doc = json.loads((desk_files.ticket_folder(root, _t(db, tid)) / "ticket.json").read_text(encoding="utf-8"))
    assert doc["watchers"][0]["email"] == "vicki@example.test"
    assert desk_files.verify(db) == []
    cust = {"id": "c", "role": "customer", "contact_id": _t(db, tid)["contact_id"]}
    assert "watchers" not in desk_db.get_ticket_detail(db, tid, actor=cust)
    assert desk_db.get_ticket_detail(db, tid, actor=MANAGER)["watchers"][0]["name"] == "Vicki"
    b = desk_backup.backup_now(db, "manual")
    desk_db.set_watcher(db, tid, "vicki@example.test", remove=True, actor=MANAGER)
    desk_backup.restore(db, b["name"], actor=OWNER, confirm=True, ticket_id=tid)
    assert [w["email"] for w in desk_db.list_watchers(db, tid)] == ["vicki@example.test"]


def test_watchers_emailed_on_every_state_change_but_not_the_one_who_made_it(setup):
    db, sent = setup
    tid = _customer_ticket(db, email=None, phone="555-010-0142")
    for e in ("vicki@example.test", "mia@x.com", "cris@x.com"):
        desk_db.set_watcher(db, tid, e, actor=MANAGER)
    sent.clear()
    desk_db.change_state(db, tid, r.IN_PROGRESS, actor=CREW)
    w = sorted(s[1] for s in sent if s[0] == "email" and "is now In Progress" in s[2])
    assert w == ["mia@x.com", "vicki@example.test"], "Cris made the change — no email to Cris"
    sent.clear()
    desk_db.change_state(db, tid, r.ON_HOLD, actor=CREW, reason="waiting on parts")
    body = next(s[3] for s in sent if s[1] == "vicki@example.test")
    assert "In Progress → On Hold" in body and "waiting on parts" in body and "T-0001" in body


def test_customer_hears_only_in_progress_and_closed(setup):
    db, sent = setup
    tid = _customer_ticket(db)
    sent.clear()
    desk_db.change_state(db, tid, r.IN_PROGRESS, actor=CREW)
    to_cust = [s for s in sent if s[1] == "lopez@example.test"]
    assert len(to_cust) == 1 and "in progress" in to_cust[0][3].lower()
    assert "https://desk.example/support/t/" in to_cust[0][3]
    sent.clear()
    desk_db.change_state(db, tid, r.ON_HOLD, actor=CREW, reason="parts")
    desk_db.change_state(db, tid, r.IN_PROGRESS, actor=CREW)
    desk_db.change_state(db, tid, r.FIXED, actor=CREW)
    assert [s for s in sent if s[1] == "lopez@example.test" and "in progress" not in s[3].lower()] == [], \
        "no On Hold / Fixed details to the customer"
    sent.clear()
    desk_db.change_state(db, tid, r.CLOSED, actor=MANAGER)
    to_cust = [s for s in sent if s[1] == "lopez@example.test"]
    assert len(to_cust) == 1 and "closed" in to_cust[0][3].lower() and "reopen" in to_cust[0][3].lower()
    desk_db.set_setting(db, "customer_status_updates", False, actor=OWNER)
    sent.clear()
    desk_db.change_state(db, tid, r.ASSIGNED, actor=MANAGER, reason="back")
    desk_db.change_state(db, tid, r.IN_PROGRESS, actor=CREW)
    assert not [s for s in sent if s[1] == "lopez@example.test"], "switched off in Settings"


def test_customer_by_text_when_no_email_and_not_for_their_own_moves(setup):
    db, sent = setup
    tid = _customer_ticket(db, email=None, phone="555-010-0142")
    sent.clear()
    desk_db.change_state(db, tid, r.IN_PROGRESS, actor=CREW)
    assert [s for s in sent if s[0] == "sms" and s[1].endswith("5550100142")]
    desk_db.change_state(db, tid, r.FIXED, actor=CREW)
    sent.clear()
    cust = {"id": "c", "role": "customer", "contact_id": _t(db, tid)["contact_id"]}
    desk_db.change_state(db, tid, r.CLOSED, actor=cust)               # she confirmed it herself
    assert not [s for s in sent if s[0] == "sms" and s[1].endswith("5550100142")]


def test_directory_merges_every_source_once_and_hides_from_customers(setup):
    db, _ = setup
    _customer_ticket(db, email="lopez@example.test")
    svc = {"directory": lambda actor: [
        {"name": "Mia", "email": "MIA@x.com", "source": "team · manager", "user_id": "mgr"},
        {"name": "Vicki", "email": "vicki@example.test", "source": "saved contact"},
        {"name": "Mrs Lopez", "email": "lopez@example.test", "source": "customer CUST-0001"},
        {"name": "bad", "email": "not-an-email", "source": "saved contact"}]}
    out = desk_http.directory(db, MANAGER, svc)
    emails = [e["email"] for e in out]
    assert emails.count("lopez@example.test") == 1 and "mia@x.com" in emails and "not-an-email" not in emails
    assert next(e for e in out if e["email"] == "lopez@example.test")["source"] == "customer CUST-0001"
    assert [e["email"] for e in desk_http.directory(db, MANAGER, svc, "vic")] == ["vicki@example.test"]
    with pytest.raises(desk_db.DeskError):
        desk_http.directory(db, {"id": "c", "role": "customer"}, svc)


def test_watchers_tool_by_name_or_email(setup):
    db, _ = setup
    tid = _customer_ticket(db)
    book = lambda actor: [{"name": "Vicki Vavro", "email": "vicki@example.test", "source": "saved contact"},  # noqa: E731
                          {"name": "Jamie Vavro", "email": "jamie@example.test", "source": "saved contact"}]
    out = desk_tools.ticket_watchers(db, MANAGER, r.BUSINESS, ticket_id=tid, add="Vicki", directory_fn=book)
    assert out.startswith("✅ added Vicki Vavro") and "vicki@example.test" in out
    amb = desk_tools.ticket_watchers(db, MANAGER, r.BUSINESS, ticket_id=tid, add="Vavro", directory_fn=book)
    assert amb.startswith("❌") and "which one" in amb
    out = desk_tools.ticket_watchers(db, MANAGER, r.BUSINESS, ticket_id=tid, add="x@y.test, Jamie",
                                     directory_fn=book)
    assert "x@y.test" in out and "jamie@example.test" in out
    out = desk_tools.ticket_watchers(db, MANAGER, r.BUSINESS, ticket_id=tid, remove="Vicki", directory_fn=book)
    assert "removed Vicki Vavro" in out and "vicki@example.test" not in out.split("Watching", 1)[1]
    assert desk_tools.ticket_watchers(db, STAFF, r.BUSINESS, ticket_id=tid, add="z@y.test").startswith("❌")  # can't see it
    assert desk_tools.ticket_watchers(db, CREW, r.BUSINESS, ticket_id=tid, add="z@y.test").startswith("✅")  # assignee


def test_ticket_detail_lists_only_the_moves_this_person_may_make(setup):
    db, _ = setup
    tid = _customer_ticket(db)
    desk_db.change_state(db, tid, r.IN_PROGRESS, actor=CREW)
    desk_db.change_state(db, tid, r.FIXED, actor=CREW)
    for actor, closed in ((CREW, False), (MANAGER, True)):
        st, ct, body = desk_http.route("GET", f"/desk-api/tickets/{tid}", query={}, body=b"", content_type="",
                                       actor=actor, edition=r.BUSINESS, db_path=db)
        moves = json.loads(body)["ticket"]["moves"]
        assert ("Closed" in moves) is closed, (actor["role"], moves)
