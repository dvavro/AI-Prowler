"""The customer page on the Business edition: the code, a booking, the status page and a reply on a server install."""
from __future__ import annotations

import datetime as dt
import itertools

import pytest

from conftest import START, http
from test_customer_book_quote import _services
from test_guardrails_booking import _book, _windows
from test_matrix import all_off

_n = itertools.count(1)


@pytest.fixture
def box(business):
    all_off(business)
    business.today = START + dt.timedelta(days=9000 + next(_n))
    business.clock(business.today, "10:00")
    business.settings(desk={"portal_enabled": True, "booking_paths": ["book", "new", "problem"], "booking_approval": "approve_all"})
    _services(business)
    _book(business, _windows(business)[0])
    yield business
    all_off(business)


def _view(box):
    st, d = http("GET", f"{box.base}/support-api/t/{box.last_token}")
    assert st == 200, d
    return d["ticket"]


def test_cp_business_booking_on_the_page_and_for_the_approver(box, person):
    who = person(box, "customer", phone=True)
    who.page.goto(f"{box.base}/support/t/{box.last_token}")
    who.page.locator("#booking", has_text="Waiting for confirmation").wait_for()
    st, d = box.desk("GET", "/bookings")
    assert st == 200 and _view(box)["job_id"] in str(d), d


def test_cp_business_customer_reply_reaches_the_ticket(box):
    st, r = http("POST", f"{box.base}/support-api/t/{box.last_token}/reply", {"body": "ZAG the gate code is 4411"})
    assert st == 201, r
    st, d = box.desk("GET", f"/tickets/{_view(box)['ticket_id']}")
    assert st == 200 and "ZAG the gate code is 4411" in str(d), d
