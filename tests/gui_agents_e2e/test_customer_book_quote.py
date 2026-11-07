"""David 4 Nov: on the customer page, Book a service and Get a quote said the code couldn't be sent and to ask us to call,
and "ask us to call you" did nothing when clicked. A personal install with email set up and SMS not; real page, real
sending code. Each test runs on its own simulated day because codes are limited per IP address per hour.
"""
from __future__ import annotations

import datetime as dt
import itertools
import re
from pathlib import Path

import pytest

import booking_db
from conftest import START, code_from
from db_access import DEFAULT_DB_FILENAME, DEFAULT_DB_SUBDIR, get_connection, init_db

_n = itertools.count(1)
PATHS = ["book", "new", "problem"]


def _services(box, *, bookable=True):
    state = Path(box.control("GET", "/state")["sandbox"])
    p = state / DEFAULT_DB_SUBDIR / DEFAULT_DB_FILENAME
    p.parent.mkdir(parents=True, exist_ok=True)
    init_db(str(p))
    c = get_connection(str(p))
    c.execute("INSERT OR IGNORE INTO service_pricing (service_code, name, base_price, min_charge) "
              "VALUES ('ZAG-WIN', 'ZAG Exterior windows', 150, 95)")
    c.close()
    booking_db.sync_services(str(p))
    booking_db.update_service(str(p), "ZAG-WIN", online=bool(bookable))
    return str(p)


@pytest.fixture
def box(nosms):
    n = next(_n)
    nosms.clock(START + dt.timedelta(days=40 + n), "10:00")
    nosms.settings(desk={"portal_enabled": True, "booking_paths": PATHS})
    _services(nosms)
    return nosms


def _who():
    n = next(_n)
    return {"name": f"ZAG Book Customer {n}", "phone": f"386556{n:04d}", "email": f"book{n}@time-machine.test"}


def _details(who, c):
    who.type("#fName", c["name"])
    who.type("#fPhone", c["phone"])
    who.type("#fEmail", c["email"])


def _address(who):
    who.type("#fStreet", "300 Flagler Ave")
    who.type("#fCity", "New Smyrna Beach")
    who.type("#fState", "FL")
    who.type("#fZip", "32169")


def _code(box, email):
    got = [m for m in box.outbox() if m.get("to") == email and "request code" in str(m.get("subject"))]
    assert got, box.outbox()[-3:]
    return code_from(got[-1]["body"])


def _finish(who, box, c):
    p = who.page
    p.locator("#fSend").click()
    p.locator("#fErr", has_text="Code sent by email").wait_for(timeout=10_000)
    who.type("#fCode", _code(box, c["email"]))
    p.locator("#fVerify").click()
    p.wait_for_url(re.compile(r"/support/t/"), timeout=15_000)
    assert not who.errors, who.errors


def test_book_a_service_sends_the_code_by_email(box, person):
    who = person(box, "customer", phone=True)
    p, c = who.page, _who()
    p.goto(box.base + "/support/?path=book")
    p.locator("#fSvc").wait_for()
    _address(who)
    p.locator("[data-win]").first.wait_for(timeout=10_000)
    p.locator("[data-win]").first.click()
    _details(who, c)
    _finish(who, box, c)


def test_get_a_quote_sends_the_code_by_email(box, person):
    who = person(box, "customer", phone=True)
    p, c = who.page, _who()
    p.goto(box.base + "/support/?path=new")
    p.locator("#fSvc").wait_for()
    _address(who)
    _details(who, c)
    _finish(who, box, c)


def test_choices_page_reaches_each_form(box, person):
    who = person(box, "customer", phone=True)
    p = who.page
    p.goto(box.base + "/support/")
    for path, sel in (("book", "#wins"), ("new", "#fPref"), ("problem", "#fTitle")):
        p.locator(f"[data-path='{path}']").click()
        p.locator(sel).wait_for()
        p.locator("#back").click()
        p.locator("#choices").wait_for()
    assert not who.errors, who.errors


def test_ask_us_to_call_link_opens_the_quote_form(box, person):
    who = person(box, "customer", phone=True)
    p, c = who.page, _who()
    p.goto(box.base + "/support/?path=book")
    p.locator("#toNew").wait_for()
    p.locator("#toNew").click()
    p.locator("#fPref").wait_for(timeout=5_000)
    assert p.locator("#h1").inner_text() == "Get a quote"
    _address(who)
    _details(who, c)
    _finish(who, box, c)


@pytest.mark.parametrize("why,setup,says", [
    ("no-services", lambda b: _services(b, bookable=False), "no services yet"),
])
def test_every_ask_us_to_call_you_on_book_is_a_working_link(box, person, why, setup, says):
    setup(box)
    who = person(box, "customer", phone=True)
    p = who.page
    p.goto(box.base + "/support/?path=book")
    p.locator("#wins", has_text=says).wait_for(timeout=10_000)
    link = p.locator("#wins a", has_text="ask us to call you")
    assert link.count() == 1, "it says to ask us to call, but nothing there can be clicked"
    link.click()
    p.locator("#fPref").wait_for(timeout=5_000)
    assert not who.errors, who.errors


def test_no_open_times_message_is_a_working_link_too(box, person):
    who = person(box, "customer", phone=True)
    p = who.page
    p.goto(box.base + "/support/?path=book")
    p.locator("[data-win]").first.wait_for(timeout=10_000)
    p.evaluate("P.wins = []; drawWins()")                       # a business with nothing open
    p.locator("#wins", has_text="No open times").wait_for()
    p.locator("#wins a", has_text="ask us to call you").click()
    p.locator("#fPref").wait_for(timeout=5_000)


def test_when_only_book_is_offered_the_page_still_gives_a_way_to_reach_us(box, person):
    box.settings(desk={"booking_paths": ["book"]})
    _services(box, bookable=False)
    who = person(box, "customer", phone=True)
    p = who.page
    p.goto(box.base + "/support/?path=book")
    p.locator("#wins", has_text="no services yet").wait_for(timeout=10_000)
    assert p.locator("#wins a").count() == 0                    # no path to link to, so no link is promised
    p.locator("#wins", has_text="call or text us").wait_for()
    box.settings(desk={"booking_paths": PATHS})
