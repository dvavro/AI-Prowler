"""Service Desk E2E — a customer request the whole way round, both screens.

S7  Customer (phone) files on /support/new and adds a message; the owner
    (desktop app) reads it and replies; the customer sees the reply. Owner:
    In Progress -> Fixed. Customer: "No, not yet" with a reason. Owner sees
    it back In Progress, fixes again. Customer: "Yes, all good", 5 stars and a
    comment — and their page then SHOWS their rating. The owner sees the
    rating on the Closed list card and on the ticket, with the comment and
    "Closed: confirmed by customer".
S8  The owner closes a Fixed ticket himself: it is not recorded as the
    customer's confirmation, and the customer is asked to rate it.
S9  The customer's status page updates by itself: the owner replies from the
    owner app and it appears without a reload, keeping a half-typed reply.
"""
import re
import uuid

import pytest

pytestmark = pytest.mark.e2e


def _owner_open(owner, tab, title):
    owner.page.goto(f"{owner.server.base}/desk/")
    owner.page.locator("#tabs").wait_for(state="visible")
    owner.tab(tab)
    owner.page.get_by_text(title).first.click()
    owner.page.locator("#back").wait_for()


def test_S7_customer_cycle_reply_reject_confirm_rate_both_sides(solo, people):
    run = uuid.uuid4().hex[:4]
    title = f"Streaks on the upstairs windows {run}"
    cust = people(solo, "customer", phone=True)
    cust.ctx.set_extra_http_headers({"cf-connecting-ip": "198.51.100.71"})
    cust.page.goto(f"{solo.base}/support/new")
    cust.type("#fName", "Mrs Okafor")
    cust.type("#fPhone", "386-555-0471")
    cust.type("#fTitle", title)
    cust.click("#fSend")
    code_msg = solo.wait_message(lambda m: m["kind"] == "sms" and "code" in m["body"] and "5550471" in str(m))
    cust.type("#fCode", re.search(r"\b(\d{6})\b", code_msg["body"]).group(1))
    cust.click("#fVerify")
    cust.page.wait_for_url(re.compile(r"/support/t/"))
    tid = re.search(r"T-\d{4,}", cust.page.locator("#h1").inner_text()).group(0)

    # customer adds a message
    cust.type("#reply", "The two by the garage too")
    cust.click("#send")
    cust.page.get_by_text("The two by the garage too").wait_for()

    # owner reads it and answers the customer
    owner = people(solo, "owner")
    owner.sign_in()
    _owner_open(owner, "mine", title)
    owner.page.get_by_text("The two by the garage too").wait_for()
    owner.type("#msg", "We'll be back Thursday at 9")
    owner.page.select_option("#msgVis", "public")
    owner.click("#msgGo")
    solo.wait_message(lambda m: m["kind"] == "sms" and "Thursday at 9" in m["body"])
    cust.page.reload()
    cust.page.get_by_text("We'll be back Thursday at 9").wait_for()

    # owner: In Progress -> Fixed
    owner.click("[data-move='In Progress']")
    owner.toast("Saved")
    owner.click("[data-move='Fixed']")
    owner.toast("Saved")

    # customer: "No, not yet"
    cust.page.reload()
    cust.answer("Still a streak on the left one")
    cust.click("#no")
    cust.page.locator(".chip.st", has_text="In Progress").wait_for()

    # owner sees it back in progress with the reason, fixes it again
    _owner_open(owner, "mine", title)
    owner.page.locator(".chip.st", has_text="In Progress").first.wait_for()
    owner.page.get_by_text("Still a streak on the left one").first.wait_for()
    owner.click("[data-move='Fixed']")
    owner.toast("Saved")

    # customer: "Yes, all good", 5 stars + a comment
    cust.page.reload()
    cust.click("#yes")
    cust.page.locator("[data-star='5']").click()
    cust.type("#rateNote", "Great job, very clean")
    cust.click("#rateGo")
    rated = cust.page.locator("#rated")
    rated.wait_for()
    assert "★★★★★" in rated.inner_text() and "Great job, very clean" in rated.inner_text()
    assert cust.page.locator("#rateGo").count() == 0

    # owner: rating on the Closed list card and on the ticket
    owner.page.goto(f"{solo.base}/desk/")
    owner.page.locator("#tabs").wait_for(state="visible")
    owner.tab("closed")
    card = owner.page.locator(f"[data-open='{tid}']")
    card.locator(".chip.csat", has_text="★ 5/5").wait_for()
    card.click()
    owner.page.locator("#back").wait_for()
    csat = owner.page.locator("#csat")
    assert "5/5" in csat.inner_text() and "Great job, very clean" in csat.inner_text()
    assert "confirmed by customer" in owner.page.locator("#closeWhy").inner_text()

    st, d = solo.api("GET", f"/desk-api/tickets/{tid}")
    assert d["ticket"]["csat_score"] == 5 and d["ticket"]["csat_comment"] == "Great job, very clean"


def test_S8_owner_closes_fixed_ticket_himself(solo, people):
    run = uuid.uuid4().hex[:4]
    title = f"Pressure wash the driveway {run}"
    st, d = solo.api("POST", "/desk-api/tickets", {"kind": "external", "title": title,
                                                   "contact_name": "Mr Hale", "contact_phone": "386-555-0472"})
    assert st == 201, d
    tid = d["ticket"]["ticket_id"]
    owner = people(solo, "owner")
    owner.sign_in()
    _owner_open(owner, "mine", title)
    owner.click("[data-move='In Progress']")
    owner.toast("Saved")
    owner.click("[data-move='Fixed']")
    owner.toast("Saved")
    owner.answer(True)                       # "Close this ticket?"
    owner.click("[data-move='Closed']")
    owner.toast("Saved")
    _owner_open(owner, "closed", title)
    why = owner.page.locator("#closeWhy")
    assert why.count() == 0 or "confirmed by customer" not in why.inner_text()

    st, d = solo.api("POST", f"/desk-api/tickets/{tid}/link", {})
    cust = people(solo, "customer", phone=True)
    cust.page.goto(solo.base + "/support/" + d["url"].split("/support/", 1)[1])
    cust.page.locator("[data-star='4']").wait_for()     # asked to rate the closed request


def test_S9_customer_page_updates_by_itself(solo, people):
    """The customer's status page is open with a half-typed reply. The owner
    answers from the owner app: the answer appears on the customer's page
    WITHOUT a reload ("Updated just now"), and the draft is untouched. A
    second update while the page stays in front arrives on the 15 s check."""
    run = uuid.uuid4().hex[:4]
    title = f"Clean the lanai screens {run}"
    st, d = solo.api("POST", "/desk-api/tickets", {"kind": "external", "title": title,
                                                   "contact_name": "Ms Duarte", "contact_phone": "386-555-0473"})
    assert st == 201, d
    tid = d["ticket"]["ticket_id"]
    st, d = solo.api("POST", f"/desk-api/tickets/{tid}/link", {})
    assert st in (200, 201), d

    cust = people(solo, "customer", phone=True)
    cust.page.goto(solo.base + "/support/" + d["url"].split("/support/", 1)[1])
    cust.page.locator("#h1", has_text=tid).wait_for()
    cust.page.evaluate("window.__s9 = 'same page'")       # gone if the page ever reloads
    draft = "Could you also do the side gate"
    cust.type("#reply", draft)                           # half-typed, not sent

    # owner answers from the owner app
    owner = people(solo, "owner")
    owner.sign_in()
    _owner_open(owner, "mine", title)
    owner.type("#msg", "Yes - we'll be there Friday at 10")
    owner.page.select_option("#msgVis", "public")
    owner.click("#msgGo")
    owner.page.get_by_text("Yes - we'll be there Friday at 10").first.wait_for()

    # customer: no reload — it just shows up (bringing the window forward also
    # makes a tab that Windows had hidden behind the owner's check at once)
    cust.page.bring_to_front()
    cust.page.get_by_text("Yes - we'll be there Friday at 10").wait_for(timeout=25000)
    cust.page.locator("#live", has_text="Updated just now").wait_for(state="visible", timeout=3000)
    assert cust.page.evaluate("window.__s9") == "same page"
    assert cust.page.locator("#reply").input_value() == draft

    # page stays in front: the next change arrives on the regular 15 s check
    assert cust.page.evaluate("document.visibilityState") == "visible"
    st, _ = solo.api("POST", f"/desk-api/tickets/{tid}/state", {"to_state": "In Progress"})
    assert st == 200
    cust.page.locator(".chip.st", has_text="In Progress").wait_for(timeout=25000)
    assert cust.page.evaluate("window.__s9") == "same page"
    assert cust.page.locator("#reply").input_value() == draft

    # and the draft can still be finished and sent normally
    cust.page.locator("#reply").press("End")
    cust.page.locator("#reply").press_sequentially(" too?", delay=60)
    cust.click("#send")
    cust.page.locator(".msg.me", has_text="side gate too?").wait_for()
    assert cust.page.locator("#reply").input_value() == ""
