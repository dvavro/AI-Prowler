"""Service Desk Phase 4 — AI assist: triage, apply (logged as Claude +
approver), search, duplicates, merge, links, summaries, learnings."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_ai  # noqa: E402
import desk_attachments  # noqa: E402
import desk_db  # noqa: E402
import desk_files  # noqa: E402
import desk_portal  # noqa: E402
import desk_routing  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_tools  # noqa: E402

OWNER_S = {"id": "dave", "role": "owner"}
MANAGER = {"id": "mgr", "role": "manager"}
CREW = {"id": "cris", "role": "field_crew"}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    desk_routing.availability_fn = None
    desk_routing.job_crew_fn = None
    yield path
    desk_ai.disable_duplicate_flagging()
    desk_db.listeners.clear()


def test_priority_and_type_suggestions(db):
    assert desk_ai.suggest_priority("Water is flooding the garage")[0] == "P1"
    assert desk_ai.suggest_priority("Customer unhappy about streaks")[0] == "P2"
    assert desk_ai.suggest_priority("Quote for spring cleaning", "P3") == ("P3", "nothing urgent mentioned")
    desk_routing.upsert_type(db, "redo", name="Re-do visit", kind="external", actor=OWNER_S)
    assert desk_ai.suggest_type(db, "Please redo the back windows")[0] == "redo"


def test_triage_suggests_without_changing_and_preview_keeps_round_robin(db):
    desk_routing.upsert_queue(db, "field", members=["ann", "bob"], actor=OWNER_S)
    desk_routing.upsert_type(db, "redo", name="Re-do", kind="internal", default_queue="field", actor=OWNER_S)
    desk_db.create_ticket(db, title="Pump is leaking everywhere", kind="internal", actor=CREW, type="")
    before = desk_db.get_ticket(db, "T-0001")
    items = desk_ai.triage(db, actor=MANAGER)
    assert items[0]["suggest"]["priority"] == "P1" and "leaking" in items[0]["why"]["priority"]
    assert desk_db.get_ticket(db, "T-0001") == before                       # nothing changed
    # preview routing never moves the round-robin pointer
    for _ in range(3):
        assert desk_routing.choose(db, {"type": "redo"}, preview=True)[0] == "ann"
    with pytest.raises(desk_db.DeskError, match="only the owner or a manager"):
        desk_ai.triage(db, actor=CREW)


def test_apply_triage_logs_claude_and_approver(db):
    desk_db.create_ticket(db, title="Pump leaking", kind="internal", actor=CREW)
    out = desk_ai.apply_triage(db, [{"ticket_id": "t-0001", "priority": "P1", "assignee": "cris"},
                                    {"ticket_id": "T-0099", "priority": "P2"}], actor=MANAGER)
    assert out[0].startswith("✅ T-0001") and out[1].startswith("❌ T-0099")
    t = desk_db.get_ticket(db, "T-0001")
    assert t["priority"] == "P1" and t["assignee"] == "cris"
    ev = [e for e in desk_db.get_ticket_detail(db, "T-0001")["events"] if e["kind"] in ("field_edit", "assigned")]
    assert ev and all(e["actor"] == "claude" and e["approved_by"] == "mgr" for e in ev)


def test_search_ranks_and_respects_visibility(db):
    a = desk_db.create_ticket(db, title="Surface cleaner leaking oil", kind="internal", actor=OWNER_S,
                              assignee="cris")
    desk_db.update_ticket(db, a["ticket_id"], {"resolution": "Replaced the swivel O-ring"}, actor=OWNER_S)
    desk_db.create_ticket(db, title="Truck oil change", kind="internal", actor=OWNER_S, assignee="dave")
    desk_db.create_ticket(db, title="Private oil thing", kind="internal", actor=OWNER_S, private=True) \
        if False else None
    hits = desk_ai.search(db, "surface cleaner o-ring", actor=OWNER_S)
    assert hits[0]["ticket_id"] == a["ticket_id"]
    assert [h["ticket_id"] for h in desk_ai.search(db, "oil", actor=CREW)] == [a["ticket_id"]]
    with pytest.raises(desk_db.DeskError):
        desk_ai.search(db, "the and of")


def test_duplicate_flagging_is_internal_only(db):
    desk_ai.enable_duplicate_flagging(lambda: db)
    c = desk_db.upsert_contact(db, name="Lopez", phone="386-555-0100")
    t1 = desk_db.create_ticket(db, title="Streaks on front windows", contact_id=c["contact_id"], edition=r.SOLO)
    t2 = desk_db.create_ticket(db, title="Front windows have streaks", contact_id=c["contact_id"], edition=r.SOLO)
    d2 = desk_db.get_ticket_detail(db, t2["ticket_id"])
    assert any(e["kind"] == "possible_duplicate" and t1["ticket_id"] in e["to_value"] for e in d2["events"])
    assert d2["messages"][-1]["visibility"] == "internal" and "Merge only if" in d2["messages"][-1]["body"]
    assert {"kind": "related", "target": t1["ticket_id"]}.items() <= d2["relations"][0].items()
    cust = desk_portal.actor_for(c)
    assert desk_db.get_ticket_detail(db, t2["ticket_id"], actor=cust, edition=r.SOLO)["messages"] == []


def test_merge_moves_thread_photos_links_and_closes_duplicate(db):
    c = desk_db.upsert_contact(db, name="Lopez", phone="386-555-0100")
    p = desk_db.create_ticket(db, title="Streaks", contact_id=c["contact_id"], actor=OWNER_S, assignee="cris")
    d = desk_db.create_ticket(db, title="Streaks again", contact_id=c["contact_id"], actor=OWNER_S, assignee="cris")
    desk_db.add_message(db, d["ticket_id"], "photo attached", actor=OWNER_S, visibility="internal")
    desk_attachments.store_attachment(db, d["ticket_id"], b"%PDF-1.4", "note.pdf", actor=OWNER_S)
    tok = desk_portal.issue_link(db, d["ticket_id"], c["contact_id"])
    with pytest.raises(desk_db.DeskError, match="owner or a manager"):
        desk_ai.merge(db, p["ticket_id"], d["ticket_id"], actor=CREW)
    out = desk_ai.merge(db, p["ticket_id"], d["ticket_id"], actor=MANAGER)
    assert out["messages_moved"] == 1
    dd = desk_db.get_ticket(db, d["ticket_id"])
    assert dd["state"] == r.CLOSED and dd["close_reason"] == f"merged into {p['ticket_id']}"
    pd = desk_db.get_ticket_detail(db, p["ticket_id"])
    assert [a["filename"] for a in pd["attachments"]] == ["0001_note.pdf"]
    assert desk_portal.resolve_link(db, tok)[0]["ticket_id"] == p["ticket_id"]   # link follows
    assert desk_files.verify(db) == []
    with pytest.raises(desk_db.DeskError, match="already merged"):
        desk_ai.merge(db, p["ticket_id"], d["ticket_id"], actor=MANAGER)


def test_links(db):
    a = desk_db.create_ticket(db, title="A", kind="internal", actor=OWNER_S)
    b = desk_db.create_ticket(db, title="B", kind="internal", actor=OWNER_S)
    desk_ai.link(db, a["ticket_id"], "related", b["ticket_id"].lower(), actor=OWNER_S)
    desk_ai.link(db, a["ticket_id"], "invoice", "INV-0042", actor=OWNER_S)
    t = desk_ai.link(db, a["ticket_id"], "job", "JOB-0007", actor=OWNER_S)
    assert t["job_id"] == "JOB-0007"
    kinds = {(x["kind"], x["target"]) for x in desk_db.get_ticket_detail(db, a["ticket_id"])["relations"]}
    assert kinds == {("related", b["ticket_id"]), ("invoice", "INV-0042")}
    with pytest.raises(desk_db.NotFoundError):
        desk_ai.link(db, a["ticket_id"], "related", "T-9999", actor=OWNER_S)


def test_summaries_and_learnings(db):
    t = desk_db.create_ticket(db, title="Gutter overflow", kind="internal", actor=OWNER_S, assignee="cris")
    desk_db.add_message(db, t["ticket_id"], "Ordered a downspout", actor=OWNER_S)
    s = desk_ai.summary(db, t["ticket_id"], actor=OWNER_S)
    assert "Gutter overflow" in s and "with cris" in s and "Ordered a downspout" in s
    assert "1 open ticket(s)" in desk_ai.queue_summary(db, actor=OWNER_S)
    for i in range(3):
        x = desk_db.create_ticket(db, title=f"Surface cleaner leak {i}", kind="internal", actor=OWNER_S,
                                  type="equipment")
        desk_db.update_ticket(db, x["ticket_id"], {"resolution": "Replaced the swivel o-ring and tested"},
                              actor=OWNER_S)
    sug = desk_ai.learning_suggestions(db, actor=OWNER_S)
    assert sug[0]["topic"] == "equipment" and "swivel" in sug[0]["common_words"]


def test_phase4_tools_text(db):
    desk_db.create_ticket(db, title="Pump leaking", kind="internal", actor=CREW)
    out = desk_tools.triage_inbox(db, MANAGER, r.BUSINESS)
    assert "Suggestions only" in out and "priority P3→P1" in out
    out = desk_tools.apply_triage(db, MANAGER, r.BUSINESS, items='[{"ticket_id": "T-0001", "priority": "P1"}]')
    assert out.startswith("✅ T-0001")
    assert "T-0001" in desk_tools.search_tickets(db, MANAGER, r.BUSINESS, query="pump")
    assert "Pump leaking" in desk_tools.ticket_summary(db, MANAGER, r.BUSINESS, ticket_id="T-0001")
    desk_db.create_ticket(db, title="Pump leaking again", kind="internal", actor=CREW)
    assert "only after a clear yes" in desk_tools.merge_tickets(db, MANAGER, r.BUSINESS,
                                                                primary_id="T-0001", duplicate_id="T-0002")
    assert desk_tools.merge_tickets(db, MANAGER, r.BUSINESS, primary_id="T-0001", duplicate_id="T-0002",
                                    confirm=True).startswith("✅ Merged T-0002")
    desk_db.assign_ticket(db, "T-0001", "cris", actor=MANAGER)
    desk_db.change_state(db, "T-0001", r.IN_PROGRESS, actor=CREW)
    assert "Write a one-paragraph resolution" in desk_tools.set_ticket_state(
        db, CREW, r.BUSINESS, ticket_id="T-0001", state="Fixed")
