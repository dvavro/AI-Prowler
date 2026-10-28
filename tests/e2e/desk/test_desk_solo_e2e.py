"""Service Desk E2E — Solo edition (personal mode).

S1  a customer files a request from a phone (6-digit code by text), the owner
    replies by text, the customer reads it on the status page, the owner marks
    it Fixed, the customer confirms and rates it
S4  the owner files a ticket to himself
S5  the owner opens a subcontractor ticket; the sub marks their part done
S6  the owner hides "own tickets" in Settings — the option disappears
"""
import re

import pytest

pytestmark = pytest.mark.e2e


def _filed_id(person):
    person.toast("Filed")
    return re.search(r"T-\d{4,}", person.page.locator("#toast").inner_text()).group(0)


def test_S1_customer_request_reply_confirm_rate(solo, people):
    cust = people(solo, "customer", phone=True)
    cust.page.goto(f"{solo.base}/support/new")
    cust.type("#fName", "Mrs Lopez")
    cust.type("#fPhone", "386-555-0100")
    cust.type("#fTitle", "Streaks on the front windows")
    cust.click("#fSend")
    code_msg = solo.wait_message(lambda m: m["kind"] == "sms" and "code" in m["body"])
    code = re.search(r"\b(\d{6})\b", code_msg["body"]).group(1)
    cust.type("#fCode", code)
    cust.click("#fVerify")
    cust.page.wait_for_url(re.compile(r"/support/t/"))
    cust.page.get_by_text("Streaks on the front windows").first.wait_for()

    owner = people(solo, "owner")
    owner.sign_in()
    owner.tab("mine")
    owner.page.get_by_text("Streaks on the front windows").first.click()
    owner.page.locator("#back").wait_for()
    owner.type("#msg", "We'll come back Thursday at 9")
    owner.page.select_option("#msgVis", "public")
    owner.click("#msgGo")
    solo.wait_message(lambda m: m["kind"] == "sms" and "Thursday at 9" in m["body"])
    cust.page.reload()
    cust.page.get_by_text("We'll come back Thursday at 9").wait_for()

    owner.click("[data-move='In Progress']")
    owner.toast("Saved")
    owner.click("[data-move='Fixed']")
    owner.toast("Saved")
    cust.page.reload()
    cust.click("#yes")
    cust.page.locator("[data-star='5']").click()
    cust.click("#rateGo")
    cust.page.locator("#rateGo").wait_for(state="detached")
    tid = re.search(r"T-\d{4,}", cust.page.locator("#h1").inner_text()).group(0)
    st, d = solo.api("GET", f"/desk-api/tickets/{tid}")
    assert d["ticket"]["state"] == "Closed" and d["ticket"]["csat_score"] == 5


def test_S4_owner_files_own_ticket(solo, people):
    owner = people(solo, "owner", phone=True)
    owner.sign_in()
    owner.click("#fab")
    owner.page.select_option("#nKind", "internal")
    owner.type("#nTitle", "Renew pesticide license")
    owner.click("#nGo")
    tid = _filed_id(owner)
    st, d = solo.api("GET", f"/desk-api/tickets/{tid}")
    assert d["ticket"]["kind"] == "internal" and d["ticket"]["assignee"] == "owner"


def test_S5_subcontractor_marks_part_done(solo, people):
    st, d = solo.api("POST", "/desk-api/tickets", {"kind": "subcontractor", "title": "Drywall patch",
                                                   "contact_name": "Dan", "contact_phone": "386-555-0199"})
    tid = d["ticket"]["ticket_id"]
    st, d = solo.api("POST", f"/desk-api/tickets/{tid}/link", {})
    sub = people(solo, "sub", phone=True)
    # the link carries this PC's real tunnel address; keep only its path, on the sandbox
    sub.page.goto(solo.base + "/support/" + d["url"].split("/support/", 1)[1])
    sub.click("#done")
    sub.page.get_by_text("Fixed").first.wait_for()
    st, d = solo.api("GET", f"/desk-api/tickets/{tid}")
    assert d["ticket"]["state"] == "Fixed"


def test_S6_hide_own_tickets_switch(solo, people):
    owner = people(solo, "owner")
    owner.sign_in()
    owner.tab("settings")
    box = owner.page.locator("[data-set='own_tickets']")
    box.uncheck()
    owner.toast("Saved")
    owner.page.reload()
    owner.page.locator("#tabs").wait_for(state="visible")
    owner.click("#fab")
    kinds = owner.page.locator("#nKind option").evaluate_all("els => els.map(e => e.value)")
    assert "internal" not in kinds and "external" in kinds
    solo.api("POST", "/desk-api/settings", {"key": "own_tickets", "value": True})   # put it back
