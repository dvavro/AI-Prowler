"""Service Desk E2E — several people file new tickets at the same instant.

E20  Four customers on their phones fill in the request page (/support/new)
     while three of the team fill in "New ticket" in the app. Every Send /
     Submit button is pressed by a browser timer set to the same millisecond.
     Each person must end up with their own ticket number; every ticket is in
     the database exactly once with the right title; no number is repeated.
E21  One customer's Submit fires twice at the same instant (double tap):
     one ticket, not two.

Each customer gets their own Cloudflare client address (cf-connecting-ip),
as on the live tunnel, so the per-address hourly limit treats them as the
different people they are.
"""
import json
import os
import re
import sqlite3
import time
import uuid

import pytest

pytestmark = pytest.mark.e2e
HUMAN = os.environ.get("DESK_E2E_FAST", "") != "1"     # same switch as conftest.py

CUSTOMERS = [("Ana Ruiz", "386-555-0301"), ("Ben Cole", "386-555-0302"),
             ("Cara Diaz", "386-555-0303"), ("Dev Shah", "386-555-0304")]
TEAM = ["Cris Crew", "Dee Crew", "Sam Staff"]


def _press_together(people_and_selectors):
    """Arm a timer in each page that clicks its button at one shared moment."""
    lead = (1500 + 500 * len(people_and_selectors)) if HUMAN else 800
    at = int(time.time() * 1000) + lead
    for person, sel in people_and_selectors:
        person.page.evaluate(
            "([s, at]) => setTimeout(() => document.querySelector(s).click(), Math.max(0, at - Date.now()))",
            [sel, at])
    return at


def _code_for(server, phone):
    digits = re.sub(r"\D", "", phone)
    m = server.wait_message(lambda m: m["kind"] == "sms" and "code" in m["body"]
                            and digits in re.sub(r"\D", "", json.dumps(m)))
    return re.search(r"\b(\d{6})\b", m["body"]).group(1)


def _customer(people, server, name, phone, title, ip):
    c = people(server, name, phone=True)
    c.ctx.set_extra_http_headers({"cf-connecting-ip": ip})
    c.page.goto(f"{server.base}/support/new")
    c.type("#fName", name)
    c.type("#fPhone", phone)
    c.type("#fTitle", title)
    return c


def _rows_titled(server, titles):
    con = sqlite3.connect(server.db)
    try:
        q = ",".join("?" * len(titles))
        return con.execute(f"SELECT ticket_id, title FROM tickets WHERE title IN ({q})", titles).fetchall()
    finally:
        con.close()


def test_E20_customers_and_team_file_at_the_same_instant(business, people):
    run = uuid.uuid4().hex[:5]
    cust = []
    for k, (name, phone) in enumerate(CUSTOMERS):
        title = f"{name.split()[0]}'s request {run}"
        cust.append((_customer(people, business, name, phone, title, f"203.0.113.{40 + k}"), phone, title))
    team = []
    for k, name in enumerate(TEAM):
        t = people(business, name, phone=True)
        t.sign_in(name)
        t.click("#fab")
        t.page.select_option("#nKind", "internal")
        title = f"{name.split()[0]}'s crew ticket {run}"
        t.type("#nTitle", title)
        team.append((t, title))

    # Step 1 for the customers: everyone asks for a code at once.
    _press_together([(c, "#fSend") for c, _p, _t in cust])
    for c, phone, _t in cust:
        c.type("#fCode", _code_for(business, phone))

    # Step 2: every customer's Submit and every team member's File, together.
    _press_together([(c, "#fVerify") for c, _p, _t in cust] + [(t, "#nGo") for t, _ in team])

    got = {}
    for c, _phone, title in cust:
        c.page.wait_for_url(re.compile(r"/support/t/"), timeout=30000)
        c.page.get_by_text(title).first.wait_for()
        got[title] = re.search(r"T-\d{4,}", c.page.locator("#h1").inner_text()).group(0)
    for t, title in team:
        t.toast("Filed", timeout=30000)
        got[title] = re.search(r"T-\d{4,}", t.page.locator("#toast").inner_text()).group(0)

    assert len(set(got.values())) == len(got), f"a number was handed out twice: {got}"
    rows = _rows_titled(business, list(got))
    assert sorted(rows) == sorted((tid, title) for title, tid in got.items()), \
        f"database does not match what people were told.\n told: {got}\n db:   {rows}"


def test_E21_double_tapped_submit_files_one_ticket(business, people):
    run = uuid.uuid4().hex[:5]
    title = f"Pool cage screen torn {run}"
    c = _customer(people, business, "Eve Long", "386-555-0310", title, "203.0.113.60")
    c.click("#fSend")
    c.type("#fCode", _code_for(business, "386-555-0310"))
    # two clicks on the same Submit in the same instant
    at = int(time.time() * 1000) + (1500 if HUMAN else 500)
    c.page.evaluate("([at]) => { for (let i = 0; i < 2; i++) setTimeout(() => "
                    "document.querySelector('#fVerify').click(), Math.max(0, at - Date.now())); }", [at])
    c.page.wait_for_url(re.compile(r"/support/t/"), timeout=30000)
    time.sleep(2)            # let the second tap finish either way
    rows = _rows_titled(business, [title])
    assert len(rows) == 1, f"double tap filed {len(rows)} tickets: {rows}"
