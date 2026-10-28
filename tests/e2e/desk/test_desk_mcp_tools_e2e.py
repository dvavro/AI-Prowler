"""Service Desk E2E — running the ticket system by TEXT or VOICE (MCP tools).

David 2026-10-28: "can you check if the MCP tools work so that a user can use
text or voice commands to operate the ticket system?"

Claude (typed chat or voice) operates Service Desk through AI-Prowler's MCP
tools. These tests are that conversation without the AI: each step is the tool
call Claude makes for a spoken request (the docstring's "Voice examples"), sent
over the real MCP connection (/mcp, the person's own token) to the same
disposable servers the browser tests use — so the server's sign-in, each
person's role and desk_rules.can() apply exactly as when they talk to Claude.

V1  every Service Desk tool is offered to Claude, with spoken examples
V2  Business, by voice, three people: crew files and takes a ticket, works it,
    is refused closing; the manager fixes the priority (reason asked), writes
    nothing over a newer change, closes; the owner reopens and it's done again
V3  a customer ticket by voice: preview-then-send reply, resolution written,
    search finds the past fix, PDF/xlsx export, summary, link, merge
V4  the owner's admin by voice: settings ("auto close after 5 days"), queues,
    rules, backups (restore only explains without a clear yes), report, triage,
    import hints — and staff / crew are refused the owner-only ones
V5  Solo by voice: the owner's own to-do with a due date, a subcontractor
    ticket, "what's on my plate", Business-only tools say so

Run: tests\\run_desk_e2e.py -k V   (no browser; part of the Service Desk E2E run)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from conftest import SOLO_TOKEN, TOKEN_OF  # noqa: E402

pytestmark = pytest.mark.e2e

TID = re.compile(r"T-\d{4,}")


class Voice:
    """One person talking to Claude: every request becomes a tool call over MCP
    with their own token."""

    def __init__(self, server, token, who):
        import task_queue_automation as tqa
        self.who = who
        self.c = tqa._HttpMCPClient(token, url=server.base + "/mcp")
        self.c.initialize(timeout=60)

    def __call__(self, tool, **args) -> str:
        out = self.c.call_tool(tool, args, timeout=120)
        print(f"[{self.who}] {tool}({args}) -> {out[:220]!r}")
        return out

    def ok(self, tool, **args) -> str:
        out = self(tool, **args)
        assert out.startswith(("✅", "📝")) or not out.startswith(("❌", "⚠️")), f"{self.who} {tool}: {out}"
        return out

    def refused(self, tool, **args) -> str:
        out = self(tool, **args)
        assert out.startswith(("❌", "⚠️")), f"{self.who} {tool} should be refused: {out}"
        return out

    def close(self):
        try:
            self.c.close()
        except Exception:
            pass


@pytest.fixture
def voices(business, solo):
    made = []

    def make(server, name=None):
        v = Voice(server, SOLO_TOKEN if server.kind == "solo" else TOKEN_OF[name], name or "solo owner")
        made.append(v)
        return v
    yield make
    for v in made:
        v.close()


def _id(server, name):
    return server.api("GET", "/desk-api/me", name=name)[1]["actor"]["id"]


def _filed(text) -> str:
    assert text.startswith("✅ Filed"), text
    return TID.search(text).group(0)


def _ticket(server, tid, name="Olive Owner"):
    st, d = server.api("GET", f"/desk-api/tickets/{tid}", name=name if server.kind == "business" else None)
    assert st == 200, (st, d)
    return d["ticket"]


# ══════════════════════════════════════════════════════════════════════════════
def test_V1_every_service_desk_tool_is_offered_with_spoken_examples(business, solo, voices):
    import mcp_tool_catalog as tc
    expected = set(tc.tools_in_category("service_desk"))
    assert len(expected) >= 28, expected
    for server, name in ((business, "Olive Owner"), (solo, None)):
        v = voices(server, name)
        tools = {t["name"]: t for t in v.c.list_tools()}
        missing = sorted(expected - set(tools))
        if server.kind == "solo":       # Business-only tools may be absent or answer "Business feature"
            missing = [m for m in missing if m not in ("manage_ticket_queues",)]
        assert not missing, f"{server.kind}: Claude can't see {missing}"
        for n in expected & set(tools):
            desc = tools[n].get("description") or ""
            assert re.search(r"Voice examples?:|Examples?:", desc), f"{n} has no spoken examples"


def test_V2_business_three_people_by_voice_internal_ticket(business, voices):
    crew, mgr, owner = (voices(business, n) for n in ("Cris Crew", "Mia Manager", "Olive Owner"))
    cris = _id(business, "Cris Crew")
    # Cris: "Open a ticket: the pump on truck 3 is leaking oil"
    tid = _filed(crew.ok("create_ticket", title="ZTEST V2 pump on truck 3 leaking oil", kind="internal",
                         priority="P2", description="Puddle under the trailer after every job"))
    # "I'll take it"
    assert cris in crew.ok("assign_ticket", ticket_id=tid, assignee=cris)
    assert tid in crew.ok("my_tickets")                      # "What's on my plate?"
    assert "In Progress" in crew.ok("set_ticket_state", ticket_id=tid, state="in progress")
    crew.ok("add_ticket_note", ticket_id=tid, note="ZTEST seal kit is in the shop")
    assert "reason" in crew.refused("set_ticket_state", ticket_id=tid, state="On Hold").lower()
    crew.ok("set_ticket_state", ticket_id=tid, state="On Hold", reason="waiting on the seal kit")
    crew.ok("set_ticket_state", ticket_id=tid, state="In Progress")
    fixed = crew.ok("set_ticket_state", ticket_id=tid, state="Fixed")
    assert "resolution" in fixed                              # Claude is told to write it up
    crew.ok("update_ticket", ticket_id=tid, resolution="ZTEST replaced the pump shaft seal and the gasket")
    crew.refused("set_ticket_state", ticket_id=tid, state="Closed")   # crew can't close

    # Mia: "What's going on with that pump ticket?" — reads the whole story back
    story = mgr.ok("get_ticket", ticket_id=tid)
    for bit in ("ZTEST seal kit is in the shop", "waiting on the seal kit", "Fixed"):
        assert bit in story, (bit, story)
    version = int(re.search(r"Version: (\d+)", story).group(1))
    assert "reason" in mgr.refused("update_ticket", ticket_id=tid, priority="P1").lower()
    crew.ok("add_ticket_note", ticket_id=tid, note="ZTEST tested it twice, dry")   # someone changes it meanwhile
    assert mgr("update_ticket", ticket_id=tid, title="ZTEST V2 pump seal (truck 3)",
               expected_version=version).startswith("⚠️"), "a stale change must not overwrite"
    mgr.ok("set_ticket_state", ticket_id=tid, state="Closed")

    # Olive: "Reopen 42 — it's leaking again"
    assert "reason" in owner.refused("set_ticket_state", ticket_id=tid, state="Assigned").lower()
    owner.ok("set_ticket_state", ticket_id=tid, state="Assigned", reason="leaking again after a week")
    assert tid in crew.ok("my_tickets"), "a reopen goes back to the person who had it"
    crew.ok("set_ticket_state", ticket_id=tid, state="In Progress")
    crew.ok("set_ticket_state", ticket_id=tid, state="Fixed")
    owner.ok("set_ticket_state", ticket_id=tid, state="Closed")
    t = _ticket(business, tid)
    assert [h["to"] for h in t["state_history"]] == [
        "Open", "Assigned", "In Progress", "On Hold", "In Progress", "Fixed", "Closed",
        "Assigned", "In Progress", "Fixed", "Closed"], t["state_history"]
    assert t["resolution"].startswith("ZTEST replaced the pump shaft seal")


def test_V3_customer_ticket_by_voice_reply_search_export(business, voices):
    staff, mgr = voices(business, "Sam Staff"), voices(business, "Mia Manager")
    dee = _id(business, "Dee Crew")
    # Sam takes a phone call: "File a ticket: Mrs. Lopez says the front windows are streaky"
    tid = _filed(staff.ok("create_ticket", title="ZTEST V3 streaky front windows",
                          contact_name="ZTEST Mrs Lopez", contact_phone="555-010-0301",
                          contact_email="lopez@example.test"))
    assert "ZTEST V3 streaky front windows" in staff.ok("get_ticket", ticket_id=tid)
    mgr.ok("assign_ticket", ticket_id=tid, assignee=dee)                  # "Give it to Dee"
    crew = voices(business, "Dee Crew")
    n = len(business.messages())
    prev = crew.ok("reply_to_customer", ticket_id=tid, message="We'll redo the windows Thursday at 9.")
    assert prev.startswith("📝 PREVIEW") and "Lopez" in prev and "by email" in prev, prev
    assert len(business.messages()) == n, "a preview sends nothing"
    sent = crew.ok("reply_to_customer", ticket_id=tid, message="We'll redo the windows Thursday at 9.",
                   preview=False)
    assert "Sent" in sent
    business.wait_message(lambda m: m["kind"] == "email" and m["to"] == "lopez@example.test"
                          and "Thursday at 9" in m["body"])
    crew.ok("set_ticket_state", ticket_id=tid, state="In Progress")
    crew.ok("set_ticket_state", ticket_id=tid, state="Fixed")
    crew.ok("update_ticket", ticket_id=tid, resolution="ZTEST re-washed with the deionized pole, no streaks")
    # later: "How did we fix the streaky windows last time?"
    found = mgr.ok("search_tickets", query="streaky windows")
    assert tid in found
    summary = mgr.ok("ticket_summary", ticket_id=tid)
    assert summary.strip(), "a summary comes back"
    pdf = mgr.ok("export_tickets", format="pdf", ticket_id=tid)
    assert ".pdf" in pdf, pdf
    assert ".xlsx" in mgr.ok("export_tickets", format="xlsx")
    # a duplicate call about the same job: link, then merge only after a clear yes
    dup = _filed(staff.ok("create_ticket", title="ZTEST V3 Lopez windows streaky again",
                          contact_name="ZTEST Mrs Lopez", contact_phone="555-010-0301"))
    mgr.ok("link_ticket", ticket_id=dup, kind="related", target=tid)
    preview = mgr("merge_tickets", primary_id=tid, duplicate_id=dup)
    assert _ticket(business, dup)["state"] != "Closed", f"merge without confirm changed things: {preview}"
    mgr.ok("merge_tickets", primary_id=tid, duplicate_id=dup, confirm=True)
    assert _ticket(business, dup)["state"] == "Closed"
    upd = json.loads(mgr("get_ticket_updates", since=""))
    assert upd.get("ok") and any(t["ticket_id"] == tid for t in upd["tickets"])


def test_V4_owner_admin_by_voice_and_role_gates(business, voices):
    owner, staff, crew = (voices(business, n) for n in ("Olive Owner", "Sam Staff", "Cris Crew"))
    sam = _id(business, "Sam Staff")
    # "Close fixed customer tickets after 5 days" — numbers arrive as words/strings by voice
    assert "auto_close_days = 5" in owner.ok("tickets_settings", setting="auto_close_days", value="5")
    assert "auto_close_days = 3" in owner.ok("tickets_settings", setting="auto_close_days", value="3")
    assert "own_tickets" in owner.ok("tickets_settings")                    # "Show the settings"
    staff.refused("tickets_settings", setting="auto_close_days", value="9")
    # queues and rules: "Make a Redo queue with Sam" / "Send every billing ticket to Sam"
    assert "ztest_redo" in owner.ok("manage_ticket_queues", action="save", queue_id="ztest_redo",
                                    name="ZTEST Redo", members=sam).lower()
    assert "ztest_redo" in owner.ok("manage_ticket_queues").lower()
    staff.refused("manage_ticket_queues", action="save", queue_id="ztest_x", name="x", members=sam)
    owner.ok("manage_ticket_rules", action="save_rule", rule_id="ztest_billing",
             match='{"keyword": "ztest invoice"}', send_to_user=sam)
    routed = owner.ok("create_ticket", title="ZTEST V4 question about my ztest invoice", kind="internal")
    assert sam in routed, f"the rule should route it to Sam: {routed}"
    owner.ok("manage_ticket_rules", action="delete_rule", rule_id="ztest_billing")
    owner.ok("manage_ticket_queues", action="delete", queue_id="ztest_redo")
    # backups: "Back up the tickets now" / "When was the last backup?" / restore needs a yes
    assert "verified" in owner.ok("tickets_backup_now")
    assert "verified" in owner.ok("backup_tickets_database")
    listing = owner.ok("list_tickets_backups")
    name = re.search(r"desk-\d{8}-\d{6}-[a-z-]+\.zip", listing).group(0)
    explain = owner("restore_tickets_database", backup_name=name)
    assert "confirm" in explain.lower(), f"restore must only explain without a yes: {explain}"
    assert "backup_hour" in owner.ok("tickets_backup_settings")
    crew.refused("tickets_backup_now")
    crew.refused("restore_tickets_database", backup_name=name, confirm=True)
    # report, triage, import, overdue
    assert "ticket(s)" in owner.ok("ticket_report", since="2020-01-01")
    crew.refused("ticket_report")
    tri = owner.ok("triage_inbox")
    assert tri.strip()
    t_new = _filed(staff.ok("create_ticket", title="ZTEST V4 gate latch broken", kind="internal"))
    owner.ok("apply_triage", items=json.dumps([{"ticket_id": t_new, "priority": "P2"}]))
    assert _ticket(business, t_new)["priority"] == "P2"
    assert "imports folder" in owner("import_tickets", filename="ztest_not_there.csv")
    owner.ok("list_tickets", overdue=True)
    # crew only ever sees their own tickets
    seen = crew.ok("list_tickets", open_only=False)
    assert "ZTEST V3" not in seen, "crew must not see other people's customer tickets"


def test_V5_solo_by_voice(solo, voices):
    me = voices(solo)
    # "Remind me to renew my pesticide license by Friday"
    todo = _filed(me.ok("create_ticket", title="ZTEST V5 renew pesticide license", kind="internal",
                        due="2026-12-31"))
    due = (_ticket(solo, todo).get("sla") or {}).get("due_resolve_at") or ""
    assert due[:10] in ("2026-12-31", "2027-01-01"), f"the due date (end of Dec 31, local): {due}"
    # "Open a ticket on Dan the drywall sub — he didn't show Tuesday"
    sub = _filed(me.ok("create_ticket", title="ZTEST V5 Dan didn't show Tuesday", kind="subcontractor",
                       contact_name="ZTEST Dan", contact_phone="555-010-0399"))
    plate = me.ok("my_tickets")
    assert todo in plate and sub in plate, "in Solo everything is the owner's"
    me.ok("set_ticket_state", ticket_id=todo, state="In Progress")
    me.ok("set_ticket_state", ticket_id=todo, state="Fixed")
    me.ok("set_ticket_state", ticket_id=todo, state="Closed")
    out = me("manage_ticket_queues", action="save", queue_id="ztest_q", name="q")
    assert out.startswith("❌") and "Business" in out, out
