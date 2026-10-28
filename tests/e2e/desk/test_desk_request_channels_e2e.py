"""Service Desk E2E — the request page shows only what AI-Prowler can send.

David 2026-10-28: "can the customer request service page not show the mobile
phone entry box when SMS is not set up or enabled in AI-Prowler and if set up
then show both. The email has to be setup to allow customer service request."

C1  texting + email set up  -> mobile box AND email box
C2  email only              -> no mobile box, "We'll email you a code"; a
                               customer files by email end to end; the owner's
                               Settings says customers get codes by email
C3  no email                -> the form is off; the owner's Settings says to
                               set up email first
"""
import re
import uuid

import pytest

pytestmark = pytest.mark.e2e


def _owner_settings_note(people, server):
    owner = people(server, "owner")
    owner.sign_in()
    owner.tab("settings")
    note = owner.page.locator("#portalNote")
    note.wait_for()
    return note.inner_text()


def test_C1_texting_and_email_show_both_boxes(solo, people):
    cust = people(solo, "customer", phone=True)
    cust.page.goto(f"{solo.base}/support/new")
    cust.page.locator("#fEmail").wait_for()
    assert cust.page.locator("#fPhone").count() == 1
    assert "text or email" in cust.page.locator(".card").first.inner_text()


def test_C2_email_only_hides_the_mobile_box_and_files_by_email(solo_email_only, people):
    srv = solo_email_only
    run = uuid.uuid4().hex[:4]
    title = f"Screens torn on the lanai {run}"
    cust = people(srv, "customer", phone=True)
    cust.page.goto(f"{srv.base}/support/new")
    cust.page.locator("#fEmail").wait_for()
    assert cust.page.locator("#fPhone").count() == 0, "mobile box shown with no texting set up"
    assert "We'll email you a code" in cust.page.locator(".card").first.inner_text()
    cust.type("#fName", "Mrs Okafor")
    cust.type("#fEmail", f"okafor.{run}@example.test")
    cust.type("#fTitle", title)
    cust.click("#fSend")
    msg = srv.wait_message(lambda m: m["kind"] == "email" and m["to"] == f"okafor.{run}@example.test"
                           and "code" in m["body"])
    assert not [m for m in srv.messages() if m["kind"] == "sms"], "something was texted"
    cust.type("#fCode", re.search(r"\b(\d{6})\b", msg["body"]).group(1))
    cust.click("#fVerify")
    cust.page.wait_for_url(re.compile(r"/support/t/"))
    cust.page.get_by_text(title).first.wait_for()
    assert "by email" in _owner_settings_note(people, srv)


def test_C3_no_email_means_the_form_is_off(solo_no_email, people):
    srv = solo_no_email
    cust = people(srv, "customer", phone=True)
    cust.page.goto(f"{srv.base}/support/new")
    cust.page.get_by_text("Online requests are turned off").wait_for()
    assert cust.page.locator("#fEmail").count() == 0 and cust.page.locator("#fPhone").count() == 0
    assert "Set up email" in _owner_settings_note(people, srv)
