"""Service Desk E2E — the address book, watchers and customer updates (human mode).

David 2026-10-28: "Can the user access that email list in the server mode to help
him select the emails on the tickets as he enters emails for assigned or add
multiple emails that get notified on the ticket when it changes state" — the list
is the team, the person's own saved contacts, Jobs customers and past ticket
contacts; owner, managers and the assignee manage a ticket's watchers (anyone
else may add or remove only themselves). "Customers don't need all the details.
They just need to be notified when it's in process and closed … internal folks
need to be watchers when it changes state."

W1  Voice: "Add Vicki to ticket …" finds the owner's own saved contact; Mia
    (manager) can't see the owner's private contacts; crew can't add others;
    "remove Vicki" — and the customer is refused as a watcher
W2  Browser, three people: the owner picks the customer's email from the list
    (name + phone fill in), assigns from the team list, adds Mia by name; Sam
    (staff) watches it himself; each change of state emails the watchers (never
    the person who made it); Mia is removed with ✕ and gets nothing after; the
    customer hears exactly two lines — in progress, and closed

Run: tests\\run_desk_e2e.py -k W
"""
from __future__ import annotations

import json
import re
import time

import pytest

from conftest import TOKEN_OF  # noqa: F401

pytestmark = pytest.mark.e2e

TID = re.compile(r"T-\d{4,}")
MIA, SAM = "mia.manager@example.test", "sam.staff@example.test"
PAT, VICKI = "pat.customer@example.test", "vicki.vendor@example.test"


def _id(server, name):
    return server.api("GET", "/desk-api/me", name=name)[1]["actor"]["id"]


@pytest.fixture(scope="module")
def book(business):
    """Give Mia and Sam an email in users.json, and the owner two private saved contacts."""
    p = business.state / "users.json"
    users = json.loads(p.read_text(encoding="utf-8"))
    for rec in users["users"].values():
        if rec["name"] == "Mia Manager":
            rec["email"] = MIA
        if rec["name"] == "Sam Staff":
            rec["email"] = SAM
    p.write_text(json.dumps(users, indent=2), encoding="utf-8")
    owner = re.sub(r"[^a-z0-9_-]", "_", _id(business, "Olive Owner").lower())
    (business.state / f"contacts_cache_{owner}.json").write_text(json.dumps({"contacts": {
        "ZTEST Vicki Vendor": {"name": "ZTEST Vicki Vendor", "email": VICKI, "phone": "+15555550142"},
        "ZTEST Pat Customer": {"name": "ZTEST Pat Customer", "email": PAT, "phone": "+15555550143"},
    }}), encoding="utf-8")
    return business


def _voice(server, name):
    import task_queue_automation as tqa
    c = tqa._HttpMCPClient(TOKEN_OF[name], url=server.base + "/mcp")
    c.initialize(timeout=60)
    return c


def _say(c, who, tool, **args):
    out = c.call_tool(tool, args, timeout=120)
    print(f"[{who}] {tool}({args}) -> {out[:200]!r}")
    return out


def _go(p, tid):
    """Find the ticket the way a person would: Open tab, then Closed."""
    p.page.goto(f"{p.server.base}/desk/")
    p.page.locator("#tabs").wait_for()
    for tab in ("open", "closed", "mine"):
        p.tab(tab)
        try:
            p.page.locator(f"[data-open='{tid}']").first.wait_for(timeout=4000)
        except Exception:
            continue
        p.open_ticket(tid)
        return
    raise AssertionError(f"{p.label} can't find {tid} on any tab")


def _sent_to(server, addr, tid):
    return [m for m in server.messages() if m["kind"] == "email" and m["to"].lower() == addr and tid in
            (m["subject"] + m["body"])]


# ══════════════════════════════════════════════════════════════════════════════
def test_W1_watchers_by_voice(book):
    owner, mgr, crew = (_voice(book, n) for n in ("Olive Owner", "Mia Manager", "Dee Crew"))
    try:
        out = _say(owner, "owner", "create_ticket", title="ZTEST W1 order more gutter guards", kind="internal")
        tid = TID.search(out).group(0)
        # Olive: "Add Vicki to ticket <tid>" — Vicki is one of HER saved contacts
        out = _say(owner, "owner", "ticket_watchers", ticket_id=tid, add="Vicki")
        assert out.startswith("✅") and VICKI in out, out
        # Mia: "Add Vicki too" — the owner's contacts are private to the owner
        out = _say(mgr, "mia", "ticket_watchers", ticket_id=tid, add="Vicki")
        assert out.startswith("❌") and "no email on file" in out, out
        # Mia: "and add Sam" — the team is everyone's
        out = _say(mgr, "mia", "ticket_watchers", ticket_id=tid, add="Sam Staff")
        assert out.startswith("✅") and SAM in out, out
        # Dee (crew, not the assignee) may not change other people's watching
        _say(owner, "owner", "assign_ticket", ticket_id=tid, assignee=_id(book, "Cris Crew"))
        out = _say(crew, "dee", "ticket_watchers", ticket_id=tid, remove="Sam Staff")
        assert out.startswith("❌"), out
        # Olive: "Who's watching it?" then "remove Vicki"
        out = _say(owner, "owner", "ticket_watchers", ticket_id=tid)
        assert VICKI in out and SAM in out, out
        out = _say(owner, "owner", "ticket_watchers", ticket_id=tid, remove="Vicki")
        assert out.startswith("✅") and VICKI not in out.split("Watching")[1], out
        # A customer's own address can't be a watcher on their ticket
        out = _say(owner, "owner", "create_ticket", title="ZTEST W1 leaking spigot", kind="external",
                   contact_name="ZTEST Pat Customer", contact_email=PAT)
        ext = TID.search(out).group(0)
        out = _say(owner, "owner", "ticket_watchers", ticket_id=ext, add=PAT)
        assert out.startswith("❌"), out
    finally:
        for c in (owner, mgr, crew):
            try:
                c.close()
            except Exception:
                pass


def test_W2_three_people_watchers_and_customer_updates_in_the_app(book, people):
    srv = book
    cris = _id(srv, "Cris Crew")
    o = people(srv, "Olive (owner)")
    o.sign_in("Olive Owner")
    # ── the owner files a customer request, picking the email from the list ──
    o.click("#fab")
    o.page.select_option("#nKind", "external")
    o.type("#nTitle", "ZTEST W2 back gate won't latch")
    assert o.page.locator(f"#dlEmail option[value='{PAT}']").count() == 1, "saved contact not offered"
    assert o.page.locator(f"#dlEmail option[value='{MIA}']").count() == 1, "team member not offered"
    o.type("#nEmail", PAT)
    o.page.locator("#nEmail").press("Tab")                         # picked → the rest fills in
    assert o.page.input_value("#nName") == "ZTEST Pat Customer"
    assert o.page.input_value("#nPhone") == "+15555550143"
    o.click("#nGo")
    o.toast("Filed")
    tid = TID.search(o.page.locator("#toast").inner_text()).group(0)
    o.page.locator("#wCard").wait_for()
    # ── Sam (staff, phone) spots it in the shared inbox and watches it himself —
    #    he gets no box for adding other people ──
    s = people(srv, "Sam (staff)", phone=True)
    s.sign_in("Sam Staff")
    _go(s, tid)
    assert s.page.locator("#wEmail").count() == 0, "staff got the add-anyone box"
    s.click("#wMe")
    s.toast("Added")
    s.page.locator(f"[data-watcher='{SAM}']").wait_for()
    s.page.get_by_role("button", name="Stop watching").wait_for()
    # ── the owner assigns it from the team list ──
    _go(o, tid)
    assert o.page.locator(f"#dlTeam option[value='{cris}']").count() == 1, "Cris not in the team list"
    o.type("#asg", cris)
    o.click("#asgGo")
    o.page.locator(".chip", has_text=f"→ {cris}").wait_for()
    # ── add Mia by NAME (the list turns it into her address) ──
    o.type("#wEmail", "Mia Manager")
    o.click("#wAdd")
    o.toast("Added")
    o.page.locator(f"[data-watcher='{MIA}']").wait_for()
    # ── the customer can't be a watcher ──
    o.type("#wEmail", PAT)
    o.click("#wAdd")
    o.page.locator("#toast", has_text=re.compile("customer", re.I)).wait_for()
    assert o.page.locator(f"[data-watcher='{PAT}']").count() == 0

    def move(to):
        _go(o, tid)
        o.answer(f"ZTEST W2 {to}")                              # a reason, if this move asks
        o.click(f"[data-move='{to}']")
        o.page.locator(".card.muted", has_text=to).wait_for()
        o._dialogs.clear()

    # ── each change of state emails the watchers ──
    move("In Progress")
    for who in (MIA, SAM):
        srv.wait_message(lambda m, w=who: m["to"].lower() == w and f"{tid} is now In Progress" in m["subject"])
    move("Fixed")
    for who in (MIA, SAM):
        srv.wait_message(lambda m, w=who: m["to"].lower() == w and f"{tid} is now Fixed" in m["subject"])
    # ── the owner takes Mia off with ✕ ──
    _go(o, tid)
    o.click(f"[data-wrm='{MIA}']")
    o.toast("Removed")
    o.page.locator(f"[data-watcher='{MIA}']").wait_for(state="detached")
    move("Closed")
    srv.wait_message(lambda m: m["to"].lower() == SAM and f"{tid} is now Closed" in m["subject"])
    time.sleep(2)
    assert not [m for m in _sent_to(srv, MIA, tid) if "is now Closed" in m["subject"]], "Mia was removed"
    # the person who made each change is never told about their own move
    assert not [m for m in srv.messages() if f"{tid} is now" in m["subject"] and
                "olive" in m["to"].lower()]
    # ── the customer heard exactly two short lines ──
    srv.wait_message(lambda m: m["to"].lower() == PAT and f"request {tid} — closed" in m["subject"])
    status = [m for m in _sent_to(srv, PAT, tid) if f"request {tid} — " in m["subject"]]
    assert [m["subject"].split(" — ")[-1] for m in status] == ["in progress", "closed"], status
    for m in status:
        assert "ZTEST W2" not in m["body"].replace("ZTEST W2 back gate won't latch", ""), \
            "a reason / internal detail reached the customer"
        assert "watching" not in m["body"].lower()
