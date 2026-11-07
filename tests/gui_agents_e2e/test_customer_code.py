"""David 4 Nov: on a personal install with email set up and SMS not, the customer's code must go by email. Runs the real
customer page and the real sending code; only the mail server at the far end is the sandbox's catcher.
Also AG-CP-09, 10, 12, 13: the code by each channel, wrong codes, the resend limit, the honeypot.
"""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START, code_from, http

_n = itertools.count(1)


@pytest.fixture
def page_on(nosms):
    # Codes are limited to 5 an hour per IP address, and every test here comes from 127.0.0.1: a day apart each.
    nosms.clock(START + dt.timedelta(days=200 + next(_n)), "10:00")
    nosms.settings(desk={"portal_enabled": True})
    return nosms


def _who():
    n = next(_n)
    return {"name": f"ZAG Code Customer {n}", "phone": f"386555{n:04d}", "email": f"code{n}@time-machine.test"}


def _fill(who, p, c, title="ZAG the windows are streaky"):
    p.goto(who.box.base + "/support/?path=problem")
    p.locator("#fTitle").wait_for()
    who.type("#fTitle", title)
    who.type("#fName", c["name"])
    who.type("#fPhone", c["phone"])
    who.type("#fEmail", c["email"])


def _codes_to(box, email):
    return [m for m in box.outbox() if m.get("to") == email and "request code" in str(m.get("subject"))]


def test_info_says_no_texting(page_on):
    st, d = http("GET", page_on.base + "/support-api/info")
    assert st == 200 and d["portal_enabled"] is True and d["sms"] is False, d


def test_no_sms_the_page_sends_the_code_by_email_and_it_works(page_on, person):
    who = person(page_on, "customer", phone=True)
    p, c = who.page, _who()
    _fill(who, p, c)
    assert p.locator("#fBy").count() == 0, "the page offers Text with SMS not set up"
    p.locator("#fSend").click()
    p.locator("#fErr", has_text="Code sent by email").wait_for()
    got = _codes_to(page_on, c["email"])
    assert len(got) == 1, page_on.outbox()[-3:]
    who.type("#fCode", code_from(got[0]["body"]))
    p.locator("#fVerify").click()
    p.wait_for_url(re.compile(r"/support/t/"), timeout=15_000)
    assert not who.errors, who.errors
    who.pause(1500)


def test_no_sms_an_old_page_asking_for_text_still_gets_email(page_on):
    c = _who()
    st, d = http("POST", page_on.base + "/support-api/start", {**c, "send_by": "sms"})
    assert st == 200 and d["sent_via"] == "email", (st, d)
    assert len(_codes_to(page_on, c["email"])) == 1


def test_no_sms_blank_email_asks_for_it(page_on, person):
    who = person(page_on, "customer", phone=True)
    p, c = who.page, _who()
    p.goto(page_on.base + "/support/?path=problem")
    p.locator("#fTitle").wait_for()
    who.type("#fTitle", "ZAG no email")
    who.type("#fName", c["name"])
    who.type("#fPhone", c["phone"])
    p.locator("#fSend").click()
    p.locator("#fErr", has_text="email address").wait_for()
    assert p.locator("#codeCard").is_hidden()


def test_no_sms_resend_goes_by_email_too(page_on, person):
    who = person(page_on, "customer", phone=True)
    p, c = who.page, _who()
    _fill(who, p, c)
    p.locator("#fSend").click()
    p.locator("#codeCard").wait_for()
    p.locator("#fResend").click()
    for _ in range(50):
        if len(_codes_to(page_on, c["email"])) >= 2:
            break
        p.wait_for_timeout(100)
    assert len(_codes_to(page_on, c["email"])) == 2
    who.type("#fCode", code_from(_codes_to(page_on, c["email"])[-1]["body"]))     # the newest one works
    p.locator("#fVerify").click()
    p.wait_for_url(re.compile(r"/support/t/"), timeout=15_000)


# ── With SMS set up: the choice on the page ──────────────────────────────────
def test_cp_09_with_sms_each_choice_goes_its_own_way(solo, person):
    solo.settings(desk={"portal_enabled": True})
    for choice, label in (("sms", "text"), ("email", "email")):
        who = person(solo, "customer", phone=True)
        p, c = who.page, _who()
        _fill(who, p, c)
        assert p.locator("#fBy input[value='sms']").is_checked()     # Text is the default when it's set up
        p.locator(f"#fBy input[value='{choice}']").check()
        before = len(solo.outbox())
        p.locator("#fSend").click()
        p.locator("#fErr", has_text=f"Code sent by {label}").wait_for()
        new = [m for m in solo.outbox()[before:] if m.get("kind") in ("sms", "email")]
        assert new and new[0]["kind"] == choice, new


def _start(box, c):
    st, d = http("POST", box.base + "/support-api/start", c)
    assert st == 200 and d.get("contact_id"), (st, d)
    return d["contact_id"]


def test_cp_10_five_wrong_codes_lock_it(page_on):
    c = _who()
    cid = _start(page_on, c)
    right = code_from(_codes_to(page_on, c["email"])[-1]["body"])
    wrong = "000000" if right != "000000" else "111111"
    for _ in range(5):
        st, d = http("POST", page_on.base + "/support-api/verify",
                     {"contact_id": cid, "code": wrong, "title": "ZAG x", "path": "problem"})
        assert st == 400, (st, d)
    st, d = http("POST", page_on.base + "/support-api/verify",
                 {"contact_id": cid, "code": right, "title": "ZAG x", "path": "problem"})
    assert st == 400 and "expired" in str(d), (st, d)


def test_cp_13_honeypot_is_dropped_silently(page_on):
    c = _who()
    st, d = http("POST", page_on.base + "/support-api/start", {**c, "website": "http://spam.example"})
    assert st == 200 and d["ok"] is True and d["contact_id"] == "", (st, d)
    assert not _codes_to(page_on, c["email"])


def test_portal_off_says_so(page_on):
    page_on.settings(desk={"portal_enabled": False})
    st, d = http("POST", page_on.base + "/support-api/start", _who())
    assert st == 400 and "turned off" in str(d), (st, d)
    page_on.settings(desk={"portal_enabled": True})


def test_cp_12_sixth_code_in_an_hour_is_refused(page_on):
    """Last here: the limit is per IP as well as per customer, so it blocks this address for the hour."""
    # Its own address, so other tests' codes from 127.0.0.1 (on other simulated days) don't count against it.
    import json
    import urllib.error
    import urllib.request

    def start(body):
        req = urllib.request.Request(page_on.base + "/support-api/start", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.12"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    c = _who()
    for _ in range(5):
        st, d = start(c)
        assert st == 200, (st, d)
    st, d = start(c)
    assert st == 400 and "too many" in str(d), (st, d)
