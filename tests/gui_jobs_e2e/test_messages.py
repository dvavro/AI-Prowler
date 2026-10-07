"""Messages screen (spec §6.8) — Send a Text + Replies, personal mode.

Nothing is ever texted to anyone:
  • send_sms is an OUTBOUND tool, so the write guard RECORDS the call (with the
    exact To / Message the app sent) and answers "not sent" instead.
  • SMS isn't set up on the test install. To test the sending path the app's
    "is SMS set up?" check (check_sms_configured) is answered in the browser
    with a faked "✅" (page.e2e_fakes — never reaches the server). The
    not-set-up path is tested too.

Run: run_tests_gui_jobs_e2e.bat --human -k test_messages
"""
import re

from playwright.sync_api import expect

from app import type_text

SMS_ON = "✅ SMS is configured (E2E fake)"
SMS_OFF = "⚠️ SMS is not configured (E2E fake)"


def _messages(app, page, configured=True):
    page.e2e_fakes["check_sms_configured"] = SMS_ON if configured else SMS_OFF
    app.goto("messages")


def _send_requests(page):
    sent = []
    page.on("request", lambda r: sent.append(r.post_data) if "/pwa-api" in r.url
            and "send_sms" in (r.post_data or "") else None)
    return sent


# ── MSG-01: the screen ───────────────────────────────────────────────────────
def test_MSG_01_screen_shows_send_and_replies(app, page):
    _messages(app, page)
    expect(page.locator("#smsTo")).to_be_visible()
    expect(page.locator("#smsMessage")).to_be_visible()
    expect(page.locator("#sendSmsBtn")).to_be_enabled()
    expect(page.locator("#smsReplies")).to_contain_text("Tap Check to load recent replies")
    expect(page.get_by_test_id("nav-messages")).to_have_class(re.compile(r"\bactive\b"))


# ── MSG-02: SMS not set up → told so, nothing sent ───────────────────────────
def test_MSG_02_not_configured_says_so_and_sends_nothing(app, page, guard):
    _messages(app, page, configured=False)
    # The guard's record is shared by the whole run (the button sweep records a
    # blocked send earlier) — count only what THIS test adds (2026-10-02).
    before = len(guard.recorded_calls("send_sms"))
    type_text(page, page.locator("#smsTo"), "386-555-0101")
    type_text(page, page.locator("#smsMessage"), "E2E should never go out")
    alerts = []
    page.on("dialog", lambda d: (alerts.append(d.message), d.accept()))
    sent = _send_requests(page)
    app.log("MSG tap 💬 Send (SMS not set up)")
    page.locator("#sendSmsBtn").click()
    page.wait_for_timeout(1500)
    assert alerts and "SMS is not configured yet" in alerts[0], alerts
    assert not sent and len(guard.recorded_calls("send_sms")) == before


# ── MSG-03: empty fields → asked to fill them, nothing sent ──────────────────
def test_MSG_03_missing_recipient_or_message(app, page, guard):
    _messages(app, page)
    before = len(guard.recorded_calls("send_sms"))   # see MSG-02
    sent = _send_requests(page)
    page.locator("#sendSmsBtn").click()
    expect(page.locator("#smsSendStatus")).to_have_text("Enter a recipient and a message.")
    type_text(page, page.locator("#smsTo"), "386-555-0101")
    page.locator("#sendSmsBtn").click()
    expect(page.locator("#smsSendStatus")).to_have_text("Enter a recipient and a message.")
    page.wait_for_timeout(800)
    assert not sent and len(guard.recorded_calls("send_sms")) == before


# ── MSG-04: a send goes out with exactly what was typed (recorded, not sent) ─
def test_MSG_04_send_passes_to_and_message(app, page, guard):
    _messages(app, page)
    before = len(guard.recorded_calls("send_sms"))
    type_text(page, page.locator("#smsTo"), "ZTEST E2E Customer")
    type_text(page, page.locator("#smsMessage"), "On my way, 15 minutes out")
    app.log("MSG tap 💬 Send (recorded by the guard — nothing is texted)")
    with page.expect_response(lambda r: "/pwa-api" in r.url and "send_sms" in (r.request.post_data or "")):
        page.locator("#sendSmsBtn").click()
    expect(page.locator("#smsSendStatus")).to_have_text("✓ Sent")
    expect(page.locator("#toast")).to_contain_text("Text sent!")
    expect(page.locator("#smsMessage")).to_have_value("")               # cleared for the next one
    expect(page.locator("#smsTo")).to_have_value("ZTEST E2E Customer")  # recipient kept
    calls = guard.recorded_calls("send_sms")
    assert len(calls) == before + 1
    assert calls[-1]["args"] == {"to": "ZTEST E2E Customer", "message": "On my way, 15 minutes out"}


# ── MSG-05: a refused send is shown as refused, the message is kept ──────────
def test_MSG_05_failed_send_is_not_shown_as_sent(app, page):
    _messages(app, page)
    page.e2e_fakes["send_sms"] = "❌ Invalid phone number: 555\n   (E2E fake)"
    type_text(page, page.locator("#smsTo"), "555")
    type_text(page, page.locator("#smsMessage"), "E2E failure path")
    page.locator("#sendSmsBtn").click()
    expect(page.locator("#smsSendStatus")).to_have_text("Failed: ❌ Invalid phone number: 555")
    expect(page.locator("#toast")).to_contain_text("Send failed")
    expect(page.locator("#smsMessage")).to_have_value("E2E failure path")
    expect(page.locator("#sendSmsBtn")).to_be_enabled()


# ── MSG-06: 🔄 Check loads replies (real read) ───────────────────────────────
def test_MSG_06_check_replies(app, page):
    _messages(app, page)
    app.log("MSG tap 🔄 Check (real check_sms_inbox — a read)")
    with page.expect_response(lambda r: "/pwa-api" in r.url and "check_sms_inbox" in (r.request.post_data or "")):
        page.locator("#screen-messages").get_by_role("button", name=re.compile("Check")).click()
    box = page.locator("#smsReplies")
    expect(box).not_to_contain_text("Checking…")
    expect(box).not_to_contain_text("Could not check replies")
    assert box.inner_text().strip()


# ── MSG-07: reply text is shown as text ──────────────────────────────────────
def test_MSG_07_reply_text_is_escaped(app, page):
    _messages(app, page)
    page.e2e_fakes["check_sms_inbox"] = 'From 386-555-0101: <img src=x onerror="window.__e2e_sms_xss=1"> ok'
    page.locator("#screen-messages").get_by_role("button", name=re.compile("Check")).click()
    expect(page.locator("#smsReplies")).to_contain_text('<img src=x onerror="window.__e2e_sms_xss=1">')
    assert page.evaluate("() => window.__e2e_sms_xss") is None


# ── MSG-08: 💬 Text Customer from a job — name with an apostrophe ────────────
def test_MSG_08_text_customer_from_job_fills_the_name(clean_slate, app, page, api, data):
    """Completes DET-01 / R-017 + R-019 now that the app can be told SMS is set
    up: the customer name (with an apostrophe) is filled in and the Messages
    tab is the one lit."""
    out = api.call("create_customer", {"updates": {"Company Name": "ZTEST E2E O'Brien's Café",
                                                   "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168",
                                                   "Status Active/Inactive": "Active"}})
    cid = out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    jid = data.job("MSG08", CustomerID=cid)
    page.e2e_fakes["check_sms_configured"] = SMS_ON
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("jobs")
    page.locator(f"[data-testid='job-card'][data-jobid='{jid}']").click()
    expect(page.locator("#jobModal")).to_have_class(re.compile(r"\bopen\b"))
    app.log("DETAIL tap 💬 Text Customer")
    page.locator("#jobModal").get_by_role("button", name=re.compile("Text Customer")).click()
    expect(page.locator("#screen-messages")).to_have_class(re.compile(r"\bactive\b"))
    expect(page.get_by_test_id("nav-messages")).to_have_class(re.compile(r"\bactive\b"))
    expect(page.locator("#smsTo")).to_have_value("ZTEST E2E O'Brien's Café")
