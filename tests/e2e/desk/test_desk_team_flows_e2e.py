"""Service Desk E2E — server mode, several people closing and reopening tickets
(human mode: every person has their own visible browser).

David 2026-10-28: "check in the server mode with three users contributing to
a ticket closure flow and reopen flow for internal and external customers".

T1  INTERNAL ticket — crew Cris (phone) files it; manager Mia assigns it to
    staff Sam; Sam works it (note, On Hold with a reason, resolution, Fixed);
    Cris has no Close button; Mia closes it. REOPEN: Mia reopens it with a
    reason -> back to Sam; Sam fixes it again; owner Olive closes it.
T2  EXTERNAL (customer) ticket — staff Sam files it for a caller; Mia assigns
    crew Dee (phone); Dee replies to the customer and marks it Fixed; the
    customer says "No, not yet" (reason); Dee fixes it again; the customer
    confirms and rates it. REOPEN: the customer reopens it from the status
    link -> back to Dee; Dee fixes it; Mia closes it.
Both end with the full state history, every reason, and who did each step.

Run: tests\\run_desk_e2e.py -k T     (human mode is the default)
"""
from __future__ import annotations

import re
import time

import pytest

pytestmark = pytest.mark.e2e


def _me(server, name):
    return server.api("GET", "/desk-api/me", name=name)[1]["actor"]["id"]


def _t(server, tid):
    st, d = server.api("GET", f"/desk-api/tickets/{tid}", name="Olive Owner")
    assert st == 200, (st, d)
    return d["ticket"]


def _state(server, tid, state, timeout=15):
    end = time.time() + timeout
    while True:
        t = _t(server, tid)
        if t["state"] == state:
            return t
        if time.time() > end:
            raise AssertionError(f"{tid} is {t['state']}, expected {state}")
        time.sleep(0.3)


def _move(person, server, tid, to, reason=None):
    """Press a state button on the open ticket (answering its reason box)."""
    person.page.locator(f"[data-move='{to}']").wait_for()
    if reason is not None:
        person.answer(reason)
    elif to == "Closed":
        person.answer(True)                                  # "Close this ticket?"
    person.click(f"[data-move='{to}']")
    return _state(server, tid, to)


def _filed(p):
    p.toast("Filed")
    return re.search(r"T-\d{4,}", p.page.locator("#toast").inner_text()).group(0)


def test_T1_internal_ticket_three_people_close_and_reopen(business, people):
    sam = _me(business, "Sam Staff")
    cris = people(business, "crew Cris", phone=True)
    cris.sign_in("Cris Crew")
    cris.click("#fab")
    cris.page.select_option("#nKind", "internal")
    cris.type("#nTitle", "ZTEST T1 hydraulic leak on truck 2")
    cris.type("#nDesc", "Drips under the lift when it's raised")
    cris.page.select_option("#nPri", "P2")
    cris.click("#nGo")
    tid = _filed(cris)

    mia = people(business, "manager Mia")
    mia.sign_in("Mia Manager")
    mia.tab("open")
    mia.open_ticket(tid)
    mia.type("#asg", sam)
    mia.click("#asgGo")
    _state(business, tid, "Assigned")

    s = people(business, "staff Sam", phone=True)
    s.sign_in("Sam Staff")
    s.tab("mine")
    s.open_ticket(tid)
    _move(s, business, tid, "In Progress")
    s.page.locator("#msg").wait_for()
    s.type("#msg", "ZTEST T1 hose fitting is cracked")
    s.click("#msgGo")
    _move(s, business, tid, "On Hold", reason="ZTEST T1 waiting on a -8 JIC fitting")
    _move(s, business, tid, "In Progress")
    s.answer("ZTEST T1 replaced the cracked -8 JIC fitting and topped up the fluid")
    s.click("#resEdit")
    end = time.time() + 15
    while not _t(business, tid).get("resolution") and time.time() < end:
        time.sleep(0.3)
    _move(s, business, tid, "Fixed")

    cris.tab("open")                                          # the person who filed it can look...
    cris.open_ticket(tid)
    assert cris.page.locator("[data-move='Closed']").count() == 0, "crew must not see a Close button"
    assert business.api("POST", f"/desk-api/tickets/{tid}/state", {"to_state": "Closed"},
                        name="Cris Crew")[0] == 403

    mia.tab("open")
    mia.open_ticket(tid)
    _move(mia, business, tid, "Closed")

    # REOPEN: the leak is back
    mia.tab("closed")
    mia.open_ticket(tid)
    t = _move(mia, business, tid, "Assigned", reason="ZTEST T1 leaking again after two days")
    assert t["assignee"] == sam, "a reopen goes back to the person who had it"
    s.tab("mine")
    s.open_ticket(tid)
    _move(s, business, tid, "In Progress")
    _move(s, business, tid, "Fixed")

    olive = people(business, "owner Olive")
    olive.sign_in("Olive Owner")
    olive.tab("open")
    olive.open_ticket(tid)
    t = _move(olive, business, tid, "Closed")

    h = t["state_history"]
    assert [x["to"] for x in h] == ["Open", "Assigned", "In Progress", "On Hold", "In Progress", "Fixed",
                                    "Closed", "Assigned", "In Progress", "Fixed", "Closed"], h
    reasons = {x["to"]: x.get("reason") for x in h if x.get("reason")}
    assert reasons.get("On Hold") == "ZTEST T1 waiting on a -8 JIC fitting"
    assert reasons.get("Assigned") == "ZTEST T1 leaking again after two days"
    by = [x["by"] for x in h]
    assert by[5] == sam and by[6] == _me(business, "Mia Manager") and by[-1] == _me(business, "Olive Owner"), by
    assert any(m["body"] == "ZTEST T1 hose fitting is cracked" for m in t["messages"])
    assert t["resolution"].startswith("ZTEST T1 replaced the cracked")


def test_T2_customer_ticket_three_people_and_the_customer_close_and_reopen(business, people):
    dee = _me(business, "Dee Crew")
    s = people(business, "staff Sam")
    s.sign_in("Sam Staff")
    s.click("#fab")                                           # Sam takes a phone call
    s.page.select_option("#nKind", "external")
    s.type("#nTitle", "ZTEST T2 hard-water spots on the sliders")
    s.type("#nName", "ZTEST Mrs Okafor")
    s.type("#nPhone", "555-010-0502")
    s.type("#nEmail", "okafor@example.test")
    s.click("#nGo")
    tid = _filed(s)

    mia = people(business, "manager Mia")
    mia.sign_in("Mia Manager")
    mia.tab("open")
    mia.open_ticket(tid)
    mia.type("#asg", dee)
    mia.click("#asgGo")
    _state(business, tid, "Assigned")
    st, d = business.api("POST", f"/desk-api/tickets/{tid}/link", {}, name="Mia Manager")
    link = business.base + "/support/" + d["url"].split("/support/", 1)[1]

    d_ = people(business, "crew Dee", phone=True)
    d_.sign_in("Dee Crew")
    d_.tab("mine")
    d_.open_ticket(tid)
    _move(d_, business, tid, "In Progress")
    d_.page.locator("#msg").wait_for()
    d_.type("#msg", "ZTEST T2 We'll be there Thursday at 10 with the spot remover.")
    d_.page.select_option("#msgVis", "public")
    d_.click("#msgGo")
    business.wait_message(lambda m: m["kind"] == "email" and m["to"] == "okafor@example.test"
                          and "Thursday at 10" in m["body"])
    _move(d_, business, tid, "Fixed")

    cust = people(business, "customer", phone=True)
    cust.page.goto(link)
    cust.page.get_by_text("Thursday at 10").first.wait_for()  # the reply is on her page
    cust.answer("ZTEST T2 the left slider still has spots")
    cust.click("#no")
    _state(business, tid, "In Progress")

    d_.tab("mine")
    d_.open_ticket(tid)
    _move(d_, business, tid, "Fixed")
    cust.page.reload()
    cust.click("#yes")
    _state(business, tid, "Closed")
    cust.page.locator("[data-star='5']").click()
    cust.click("#rateGo")
    cust.page.locator("#rateGo").wait_for(state="detached")

    # REOPEN by the customer, from her status link
    cust.page.reload()
    cust.answer("ZTEST T2 the spots came back after the sprinklers")
    cust.click("#reopen")
    t = _state(business, tid, "Assigned")
    assert t["assignee"] == dee, "a reopen goes back to the person who had it"
    d_.tab("mine")
    d_.open_ticket(tid)
    _move(d_, business, tid, "In Progress")
    _move(d_, business, tid, "Fixed")
    mia.tab("open")
    mia.open_ticket(tid)
    t = _move(mia, business, tid, "Closed")

    h = t["state_history"]
    assert [x["to"] for x in h] == ["Open", "Assigned", "In Progress", "Fixed", "In Progress", "Fixed",
                                    "Closed", "Assigned", "In Progress", "Fixed", "Closed"], h
    assert h[4].get("reason") == "ZTEST T2 the left slider still has spots"
    assert h[7].get("reason") == "ZTEST T2 the spots came back after the sprinklers"
    assert h[4]["by"].startswith("contact:") and h[7]["by"].startswith("contact:"), "the customer did those"
    assert t["csat_score"] == 5
