"""Job detail screen (tap a job card) — buttons and content, used the way a
person uses them. Real customer names and notes contain apostrophes and
odd characters; the screen must cope with them.

Run: run_tests_gui_jobs_e2e.bat --human -k job_detail
"""
import re

from playwright.sync_api import expect


def _open_detail(app, page, jid):
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("jobs")
    page.locator(f"[data-testid='job-card'][data-jobid='{jid}']").click()
    expect(page.locator("#jobModal")).to_have_class(re.compile(r"\bopen\b"))


def test_DET_01_text_customer_works_for_a_name_with_an_apostrophe(clean_slate, app, page, data):
    """Found 2026-09-26 (R-017): the 💬 Text Customer button was built as
    onclick="goMessages('<customer name>')" — an apostrophe in the name
    (O'Brien's, Crabby's…) broke that code, so the tap did NOTHING at all.
    After the fix the tap reaches the app's own logic: Messages opens with the
    name filled in (SMS configured) — or, on an install where SMS isn't set
    up, the app's 'SMS is not configured yet' alert appears. Either proves the
    button works; before the fix neither happened."""
    jid = data.job("O'Brien's Café", "city_hall")
    errors, alerts = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))

    def on_dialog(d):
        alerts.append(d.message)
        d.accept()
    page.on("dialog", on_dialog)
    try:
        _open_detail(app, page, jid)
        page.locator("#jobModal").get_by_role("button", name=re.compile("Text Customer")).click()
        page.wait_for_timeout(1500)
    finally:
        page.remove_listener("dialog", on_dialog)
    assert not errors, f"JavaScript error tapping Text Customer: {errors}"
    if any("SMS is not configured" in a for a in alerts):
        return                                      # SMS not set up on this install — correct behaviour
    assert "screen-messages" in app.active_screens(), \
        f"Text Customer did nothing (active: {app.active_screens()}, alerts: {alerts})"
    expect(page.get_by_test_id("nav-messages")).to_have_class(re.compile(r"\bactive\b"))   # R-019
    expect(page.locator("#smsTo")).to_have_value(re.compile("O'Brien's Café"))


def test_DET_02_notes_are_shown_as_text_never_run_as_code(clean_slate, app, page, data):
    """Found by reading the code 2026-09-26: the job detail inserts the notes
    (and customer name) as raw HTML. Notes are typed by people — in server
    mode by any crew member — so markup in them must show as text, and must
    never run as code on whoever opens the job."""
    payload = "Gate code 42 <img src=x onerror=\"window.__e2e_xss=1\"> <b>bold?</b>"
    jid = data.job("DET02 notes", "city_hall", **{"Service Details / Notes": payload})
    _open_detail(app, page, jid)
    page.wait_for_timeout(500)
    ran = page.evaluate("() => window.__e2e_xss === 1")
    assert not ran, "code inside a job's notes RAN when the job was opened"
    body = page.locator("#modalBody")
    expect(body).to_contain_text("Gate code 42")
    expect(body).to_contain_text("<b>bold?</b>")          # shown literally, not turned into bold


def test_DET_03_job_card_in_the_list_never_runs_code_from_a_name(clean_slate, app, page, data):
    """The Jobs LIST card (no tap needed) put the customer, service, city and
    crew in as raw HTML too — worse than the detail view, since it runs as soon
    as the list loads. Same fix (R-018)."""
    jid = data.job("<img src=x onerror=\"window.__e2e_xss_card=1\">Card", "city_hall")
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("jobs")
    card = page.locator(f"[data-testid='job-card'][data-jobid='{jid}']")
    expect(card).to_be_visible()
    page.wait_for_timeout(500)
    assert not page.evaluate("() => window.__e2e_xss_card === 1"), "code in a customer name RAN on the Jobs list"
    assert card.locator("img").count() == 0, "markup in a customer name became a real element on the card"


def test_DET_04_add_photos_lights_up_the_photos_tab(clean_slate, app, page, data):
    """R-019 (found 2026-09-26): 📷 Add Photos opened the Photos screen but lit
    up the ROUTE tab (it picked the tab by position, and the tabs were
    reordered). The button also opens the phone's picker; the test cancels it."""
    jid = data.job("DET04 photos", "city_hall")
    _open_detail(app, page, jid)
    with page.expect_file_chooser(timeout=10_000) as fc:
        page.locator("#jobModal").get_by_role("button", name=re.compile("Add Photos")).click()
    fc.value.set_files([])                                  # dismiss the picker without choosing
    assert "screen-photos" in app.active_screens(), f"active: {app.active_screens()}"
    expect(page.get_by_test_id("nav-photos")).to_have_class(re.compile(r"\bactive\b"))
    expect(page.get_by_test_id("nav-route")).not_to_have_class(re.compile(r"\bactive\b"))
    expect(page.locator("#photoJobSelect")).to_have_value(jid)
