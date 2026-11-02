"""Service Desk E2E — every Service Desk Agent & settings tab, changed the way AI-Prowler's own window
changes it, then checked where it shows (the customer page, the Service Desk app, the outbox).

David 2026-11-02: "I need you to first review the code and verify and test all the configuration
settings for the Service Desk Agent and setting for the web forms, General, agents, and data & backup
with E2E GUI testing because I am finding many features not working."

Each setting is changed through desk_gui_settings / desk_gui_agent — the exact functions the window's
Save buttons call — so a test that passes means the window's change reaches the page.

WEB FORMS
  W1  Choices on the page: one choice goes straight to its form; several ask "How can we help?" with
      the welcome line; every combination shows exactly the choices that are on
  W2  Services offered online: Online on/off, Type = Service vs Product (a product is never offered
      for booking — only in "Request a new service", grouped), price shown none/from/exact; the
      window's "N of M shown" count follows the ticks
  W3  Page look: accent and background colour reach the page
  W4  The page shows the BUSINESS name (Jobs app → Settings → Business Name), not the owner's name
  W5  A request's status page has "Make another request" back to the form
GENERAL
  G1  Customers can request service online: off -> the form says it's turned off; the status page
      still works
  G2  The owner's alert email gets a new customer request
  G3  Customer status updates on/off: a state change texts/emails the customer only when on
  G4  Ask for a rating: the "How did we do?" card only when on
  G5  Auto-close days: 0–60 saves, 61 and "abc" are refused
  G6  A reply to the customer shows "✓ sent" in the app (the bug that hid failed replies)
DATA & BACKUPS
  D1  Back up now -> listed and verified; settings with a bad number are refused, good ones saved;
      export gives a file with the tickets
AGENT
  A1  The assistant's name and label reach the customer page's /agent profile; bad numbers refused

Run:  tests\\run_desk_e2e.py -k settings_effects          (human mode: visible, slowed)
"""
from __future__ import annotations

import re

import pytest

pytestmark = pytest.mark.e2e

ED = "solo"


# ── helpers ───────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _desk_ready(solo):
    """The sandbox server makes its Service Desk database on first use — make sure it exists before a
    test changes a setting the way the window does (straight into that database)."""
    st, d = solo.api("GET", "/desk-api/tickets")
    assert st == 200, d


def _gui():
    import desk_gui_settings as dgs
    return dgs


def _jobs_db(srv):
    """The sandbox server's Jobs database, with two catalogue items for the services tests."""
    from db_access import DEFAULT_DB_FILENAME, DEFAULT_DB_SUBDIR, get_connection, init_db
    p = srv.state / DEFAULT_DB_SUBDIR / DEFAULT_DB_FILENAME
    p.parent.mkdir(parents=True, exist_ok=True)
    init_db(str(p))
    c = get_connection(str(p))
    c.execute("INSERT OR IGNORE INTO service_pricing (service_code, name, base_price, min_charge) "
              "VALUES ('WIN-EXT', 'ZTEST Exterior windows', 150, 95)")
    c.execute("INSERT OR IGNORE INTO service_pricing (service_code, name, base_price, min_charge) "
              "VALUES ('PROD-SSD', 'ZTEST Server 0.5 TB SSD', 500, 500)")
    c.close()
    import booking_db
    booking_db.sync_services(str(p))
    return str(p)


def _customer_ticket(srv, title, phone="386-555-0142", email=None):
    """A customer request filed in the app, and the customer's own status-page path."""
    body = {"kind": "external", "title": title, "contact_name": "ZTEST Pat", "contact_phone": phone}
    if email:
        body["contact_email"] = email
    st, d = srv.api("POST", "/desk-api/tickets", body)
    assert st in (200, 201), d
    tid = d["ticket"]["ticket_id"]
    st, d = srv.api("POST", f"/desk-api/tickets/{tid}/link", {})
    assert st in (200, 201), d
    return tid, "/support/" + d["url"].split("/support/", 1)[1]


def _get(url):
    """GET -> (status, json) without signing in (the customer's side)."""
    import json
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _choices(page):
    """The choices' names (each also has a line saying what it's for, 2026-11-02)."""
    return [b.locator(".lbl").inner_text().strip() for b in page.locator("[data-path]").all()]


# ── WEB FORMS ─────────────────────────────────────────────────────────────────

def test_W1_choices_and_welcome_line(solo, people):
    dgs = _gui()
    cust = people(solo, "customer", phone=True)
    try:
        assert dgs.save_paths(solo.db, [], ED) == (False, "Keep at least one choice on the page.")
        dgs.set_one(solo.db, "booking_welcome", "ZTEST Welcome to Blue Wave", ED)
        combos = [(["problem"], None, "Request service"),
                  (["new"], None, "Request service"),
                  (["new", "problem"], ["Get a quote", "Report a problem"], "How can we help?"),
                  (["book", "new", "problem"], ["Book a service", "Get a quote", "Report a problem"],
                   "How can we help?")]
        for chosen, buttons, h1 in combos:
            assert dgs.save_paths(solo.db, chosen, ED)[0]
            cust.page.goto(f"{solo.base}/support/new")
            cust.page.locator("#h1", has_text=h1).wait_for()
            cust.page.locator("#welcome", has_text="ZTEST Welcome to Blue Wave").wait_for()
            if buttons is None:
                assert cust.page.locator("[data-path]").count() == 0, chosen
            else:
                assert _choices(cust.page) == buttons, (chosen, _choices(cust.page))
                # every choice says what it's for (David: "if I am confused the customer will be confused")
                subs = cust.page.locator("[data-path] small").all_inner_texts()
                assert len(subs) == len(buttons) and all(len(s) > 20 for s in subs), subs
        # /book is the same page
        cust.page.goto(f"{solo.base}/book")
        cust.page.locator("#h1", has_text="How can we help?").wait_for()
        assert len(_choices(cust.page)) == 3
    finally:
        dgs.save_paths(solo.db, ["problem"], ED)
        dgs.set_one(solo.db, "booking_welcome", "", ED)


def test_W2_services_and_products_online(solo, people):
    dgs = _gui()
    jobs = _jobs_db(solo)
    try:
        dgs.save_paths(solo.db, ["book", "new", "problem"], ED)
        rows = {r["code"]: r for r in dgs.service_rows(jobs)[0]}
        assert {"WIN-EXT", "PROD-SSD"} <= set(rows)
        # the window's count follows the ticks (it used to say "0 of 1 shown" after ticking Online)
        online = {c: False for c in rows}
        assert dgs.services_count_text(online).startswith(f"0 of {len(rows)} shown")
        assert dgs.set_service(jobs, "WIN-EXT", online=True, price_display="from")[0]
        assert dgs.set_service(jobs, "PROD-SSD", online=True, price_display="exact")[0]
        online.update({"WIN-EXT": True, "PROD-SSD": True})
        assert dgs.services_count_text(online).startswith(f"2 of {len(rows)} shown")
        assert dgs.set_type(jobs, "PROD-SSD", "Product")[0]
        assert dgs.service_type({"mode": "request"}) == "product"
        # Outdoor is per service, set by each business; a product can't have it
        import booking_db
        assert dgs.set_outdoor(jobs, "WIN-EXT", True)[0]
        assert not dgs.set_outdoor(jobs, "PROD-SSD", True)[0]
        outdoor = {r["code"]: r["outdoor"] for r in booking_db.list_services(jobs)}
        assert outdoor["WIN-EXT"] is True and outdoor["PROD-SSD"] is False

        cust = people(solo, "customer", phone=True)
        cust.page.goto(f"{solo.base}/support/new")
        cust.page.locator("[data-path='book']").click()
        book = cust.page.locator("#fSvc option").all_inner_texts()
        assert book == ["ZTEST Exterior windows — from $95"], book                 # no product to book
        cust.page.locator("#wins .win, #wins button").first.wait_for()              # open times load
        cust.page.locator("#back").click()
        cust.page.locator("[data-path='new']").click()
        cust.page.locator("label", has_text="Which service or product?").wait_for()
        groups = cust.page.locator("#fSvc optgroup").evaluate_all(
            "els => els.map(g => [g.label, [...g.children].map(o => o.textContent)])")
        assert groups == [["Services", ["ZTEST Exterior windows — from $95"]],
                          ["Products", ["ZTEST Server 0.5 TB SSD — $500"]]], groups
        # a product can't be booked even by asking the server directly
        st, d = _get(f"{solo.base}/support-api/windows?service=PROD-SSD")
        assert st == 400 and "can't be booked online" in d["message"], d
        # price "none" hides it; Online off removes it
        assert dgs.set_service(jobs, "PROD-SSD", price_display="none")[0]
        assert dgs.set_service(jobs, "WIN-EXT", online=False)[0]
        cust.page.goto(f"{solo.base}/support/new?path=new")
        opts = cust.page.locator("#fSvc option").all_inner_texts()
        assert opts == ["ZTEST Server 0.5 TB SSD", "Something else"], opts
    finally:
        dgs.set_service(jobs, "WIN-EXT", online=False)
        dgs.set_service(jobs, "PROD-SSD", online=False)
        dgs.save_paths(solo.db, ["problem"], ED)


def test_W3_page_look_colours(solo, people):
    dgs = _gui()
    try:
        assert dgs.save_look(solo.db, ED, bg_mode="picture") == (False, "Choose a background picture first.")
        assert dgs.save_look(solo.db, ED, accent="#c0392b", bg_color="#123456", bg_mode="color")[0]
        cust = people(solo, "customer")
        cust.page.goto(f"{solo.base}/support/new")
        cust.page.locator("#h1").wait_for()
        cust.page.wait_for_function("getComputedStyle(document.documentElement).getPropertyValue('--acc')"
                                    ".trim().toLowerCase() === '#c0392b'")
        bg = cust.page.evaluate("getComputedStyle(document.body).backgroundColor")
        assert bg in ("rgb(18, 52, 86)",), bg
    finally:
        dgs.save_look(solo.db, ED, accent="#0b7fab", bg_mode="plain")


def test_W4_page_shows_the_business_name(solo, people):
    jobs = _jobs_db(solo)
    from db_access import get_connection
    c = get_connection(jobs)
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('Business Name', 'ZTEST Blue Wave LLC')")
    c.close()
    try:
        cust = people(solo, "customer")
        cust.page.goto(f"{solo.base}/support/new")
        cust.page.locator("#biz", has_text="ZTEST Blue Wave LLC").wait_for()
        tid, path = _customer_ticket(solo, "ZTEST W4 name check")
        cust.page.goto(solo.base + path)
        cust.page.locator("#h1", has_text=tid).wait_for()
        assert cust.page.locator("#biz").inner_text() == "ZTEST Blue Wave LLC"
    finally:
        c = get_connection(jobs)
        c.execute("DELETE FROM settings WHERE key = 'Business Name'")
        c.close()


def test_W5_status_page_links_back_to_the_form(solo, people):
    tid, path = _customer_ticket(solo, "ZTEST W5 another request")
    cust = people(solo, "customer", phone=True)
    cust.page.goto(solo.base + path)
    link = cust.page.locator("#another a", has_text="Make another request")
    link.wait_for()
    link.click()
    cust.page.wait_for_url(re.compile(r"/support/new$"))
    cust.page.locator("#fSend, [data-path]").first.wait_for()


def test_W6_buy_a_product_with_shipping_and_pay_now(solo, people):
    """David 2026-11-02: "Allow a product to be purchased ... add the Online Payment Link for each
    product ... shipping and handling needs to be added in." The sandbox's checkout is a fake
    address (pay.example.test) — never Stripe or Square."""
    dgs = _gui()
    jobs = _jobs_db(solo)
    from db_access import get_connection
    c = get_connection(jobs)
    c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('Tax Rate', '0.07')")
    c.close()
    try:
        assert dgs.save_paths(solo.db, ["book", "buy", "new", "problem"], ED)[0]
        assert dgs.set_service(jobs, "PROD-SSD", online=True)[0] and dgs.set_type(jobs, "PROD-SSD", "Product")[0]
        assert dgs.set_service(jobs, "WIN-EXT", online=True)[0]
        assert dgs.set_shipping(jobs, "PROD-SSD", "15")[0]
        assert not dgs.set_shipping(jobs, "WIN-EXT", "15")[0]                      # services aren't shipped

        # the product's Shop card: two photos, a description and specs (Web forms → Details…)
        import io
        from PIL import Image
        for colour in ((20, 120, 200), (200, 80, 20)):
            png = io.BytesIO(); Image.new("RGB", (800, 600), colour).save(png, "PNG")
            f = solo.state / f"ztest_{colour[0]}.png"; f.write_bytes(png.getvalue())
            assert dgs.add_product_photo(solo.db, "PROD-SSD", str(f))[0]
        assert dgs.save_details(jobs, "PROD-SSD", "ZTEST small and quiet", "Storage: 0.5 TB SSD\nWarranty: 1 year")[0]

        cust = people(solo, "customer", phone=True)
        cust.page.goto(f"{solo.base}/support/new")
        cust.page.locator("#h1", has_text="How can we help?").wait_for()
        assert _choices(cust.page) == ["Book a service", "Shop products", "Get a quote",
                                       "Report a problem"], _choices(cust.page)
        # services and products are kept apart: Get a quote lists services only while the Shop is on
        cust.click("[data-path='new']")
        quote = cust.page.locator("#fSvc option").all_inner_texts()
        assert quote == ["ZTEST Exterior windows — from $95", "Something else"], quote
        cust.click("#back")
        cust.click("[data-path='buy']")
        card = cust.page.locator(".prod[data-code='PROD-SSD']")
        card.wait_for()
        assert cust.page.locator(".prod").count() == 1                               # products only
        assert "$500.00" in card.inner_text() and "$15.00 shipping & handling each" in card.inner_text()
        assert "ZTEST small and quiet" in card.inner_text()
        card.locator("summary", has_text="Specs").click()
        card.locator("li", has_text="Warranty").wait_for()
        assert card.locator(".pth button").count() == 2                              # two photos
        big = card.locator(".pimg img")
        first = big.get_attribute("src")
        cust.page.wait_for_function("img => img.complete && img.naturalWidth > 0", arg=big.element_handle())
        card.locator(".pth button").nth(1).click()                                   # tap the 2nd photo
        assert big.get_attribute("src") != first
        assert cust.page.locator("#fSend").is_hidden()                               # no form until one is picked
        cust.click(".prod[data-code='PROD-SSD'] [data-buy]")
        cust.page.locator("#pickedName", has_text="ZTEST Server 0.5 TB SSD").wait_for()
        cust.page.fill("#fQty", "2")
        total = cust.page.locator("#fSum")
        total.locator("text=Shipping & handling").wait_for()
        # 2 × $500 + 2 × $15 shipping = $1,030, + 7% tax $72.10 = $1,102.10
        assert "$1,000.00" in total.inner_text() and "$30.00" in total.inner_text()
        assert "$72.10" in total.inner_text() and "$1,102.10" in total.inner_text(), total.inner_text()
        cust.type("#fStreet", "12 Ocean Ave")
        cust.type("#fCity", "New Smyrna Beach")
        cust.type("#fZip", "32169")
        cust.type("#fName", "ZTEST Buyer")
        cust.type("#fPhone", "386-555-0193")
        cust.click("#fSend")
        msg = solo.wait_message(lambda m: m["kind"] == "sms" and "code" in m["body"] and "5550193" in str(m))
        cust.type("#fCode", re.search(r"\b(\d{6})\b", msg["body"]).group(1))
        assert cust.page.locator("#fVerify").inner_text() == "Place order"
        cust.click("#fVerify")
        cust.page.wait_for_url(re.compile(r"/support/t/"))
        card = cust.page.locator("#order")
        card.wait_for()
        assert "$1,102.10" in card.inner_text() and "Ship to: 12 Ocean Ave" in card.inner_text()
        tid = re.search(r"T-\d{4,}", cust.page.locator("#h1").inner_text()).group(0)
        assert solo.wait_message(lambda m: "Thanks for your order " + tid in m["body"] and "$1,102.10" in m["body"])

        # the Jobs app has the order job (no date) and an unpaid invoice for the total
        c = get_connection(jobs)
        job = c.execute("SELECT * FROM jobs WHERE service_type = 'Order: ZTEST Server 0.5 TB SSD' "
                        "ORDER BY rowid DESC LIMIT 1").fetchone()
        inv = c.execute("SELECT * FROM invoices WHERE invoice_id = ?", (job["invoice_id"],)).fetchone()
        c.close()
        assert job["job_status"] == "Requested" and not job["service_date"]
        assert inv["total_due"] == 1102.10 and inv["payment_status"] == "Unpaid"

        # Pay now opens a fresh checkout for what's owed (caught here — never a real payment page)
        cust.page.route("https://pay.example.test/**", lambda route: route.fulfill(
            status=200, content_type="text/html", body="<h1 id='paid'>ZTEST checkout</h1>"))
        pay = cust.page.locator("#payNow")
        assert "$1,102.10" in pay.inner_text()
        cust.click("#payNow")
        cust.page.wait_for_url(re.compile(r"pay\.example\.test/" + inv["invoice_id"] + r"\?amount=1102\.10"))

        # marked paid in the Jobs app -> the page says so and Pay now is gone
        c = get_connection(jobs)
        c.execute("UPDATE invoices SET amount_paid = total_due, payment_status = 'Paid' WHERE invoice_id = ?",
                  (inv["invoice_id"],))
        c.close()
        cust.page.go_back()
        cust.page.reload()
        cust.page.locator("#order", has_text="Paid — thank you").wait_for()
        assert cust.page.locator("#payNow").count() == 0
    finally:
        dgs.set_service(jobs, "WIN-EXT", online=False)
        dgs.set_service(jobs, "PROD-SSD", online=False, shipping=0, description="", specs="")
        import desk_product_media as media
        for n in reversed(media.photos(solo.db, "PROD-SSD")):
            media.remove_photo(solo.db, "PROD-SSD", n)
        dgs.save_paths(solo.db, ["problem"], ED)


# ── GENERAL ───────────────────────────────────────────────────────────────────

def test_G1_request_form_switch(solo, people):
    dgs = _gui()
    tid, path = _customer_ticket(solo, "ZTEST G1 still visible")
    cust = people(solo, "customer")
    try:
        assert dgs.set_one(solo.db, "portal_enabled", False, ED)[0]
        cust.page.goto(f"{solo.base}/support/new")
        cust.page.get_by_text("Online requests are turned off").wait_for()
        cust.page.goto(solo.base + path)                       # an existing request still works
        cust.page.locator("#h1", has_text=tid).wait_for()
        assert cust.page.locator("#another").count() == 0     # no "make another" while the form is off
    finally:
        dgs.set_one(solo.db, "portal_enabled", True, ED)
    cust.page.goto(f"{solo.base}/support/new")
    cust.page.locator("#fSend").wait_for()


def test_G2_owner_alert_email_gets_new_requests(solo, people):
    dgs = _gui()
    try:
        assert dgs.save_alerts(solo.db, "ztest-owner@example.com", "", ED)[0]
        cust = people(solo, "customer", phone=True)
        cust.page.goto(f"{solo.base}/support/new")
        cust.type("#fName", "ZTEST Lopez")
        cust.type("#fPhone", "386-555-0177")
        cust.type("#fTitle", "ZTEST G2 gutter overflowing")
        cust.click("#fSend")
        code = re.search(r"\b(\d{6})\b", solo.wait_message(
            lambda m: m["kind"] == "sms" and "code" in m["body"] and m["to"].endswith("5550177"))["body"]).group(1)
        cust.type("#fCode", code)
        cust.click("#fVerify")
        cust.page.wait_for_url(re.compile(r"/support/t/"))
        solo.wait_message(lambda m: m["kind"] == "email" and m["to"] == "ztest-owner@example.com"
                          and "ZTEST G2 gutter overflowing" in (m.get("subject", "") + m["body"]))
    finally:
        dgs.save_alerts(solo.db, "", "", ED)


def test_G3_customer_status_updates_switch(solo):
    dgs = _gui()
    for on in (False, True):
        assert dgs.set_one(solo.db, "customer_status_updates", on, ED)[0]
        tid, _path = _customer_ticket(solo, f"ZTEST G3 updates {on}", phone="386-555-01" + ("71" if on else "70"))
        before = len(solo.messages())
        st, d = solo.api("POST", f"/desk-api/tickets/{tid}/state", {"to_state": "In Progress",
                                                                     "expected_version": d_rev(solo, tid)})
        assert st == 200, d
        import time
        time.sleep(2)
        to_cust = [m for m in solo.messages()[before:] if m["to"].endswith("01" + ("71" if on else "70"))]
        assert bool(to_cust) is on, (on, to_cust)


def d_rev(srv, tid):
    return srv.api("GET", f"/desk-api/tickets/{tid}")[1]["ticket"]["rev"]


def test_G4_rating_switch(solo, people):
    dgs = _gui()
    cust = people(solo, "customer", phone=True)
    try:
        for on in (False, True):
            assert dgs.set_one(solo.db, "csat_enabled", on, ED)[0]
            tid, path = _customer_ticket(solo, f"ZTEST G4 rating {on}")
            for to in ("In Progress", "Fixed", "Closed"):
                st, d = solo.api("POST", f"/desk-api/tickets/{tid}/state",
                                 {"to_state": to, "expected_version": d_rev(solo, tid), "reason": "done"})
                assert st == 200, (to, d)
            cust.page.goto(solo.base + path)
            cust.page.locator("#h1", has_text=tid).wait_for()
            assert (cust.page.locator("#rateGo").count() == 1) is on, on
    finally:
        dgs.set_one(solo.db, "csat_enabled", True, ED)


def test_G5_auto_close_days_range(solo):
    dgs = _gui()
    import desk_db
    try:
        assert dgs.save_auto_close(solo.db, "61", ED) == (False, "Enter 0 to 60 days.")
        assert dgs.save_auto_close(solo.db, "abc", ED) == (False, "Enter 0 to 60 days.")
        assert dgs.save_auto_close(solo.db, "7", ED)[0]
        assert desk_db.get_settings(solo.db)["auto_close_days"] == 7
        assert dgs.save_auto_close(solo.db, "0", ED)[0]
        assert desk_db.get_settings(solo.db)["auto_close_days"] == 0
    finally:
        dgs.save_auto_close(solo.db, "3", ED)


def test_G6_reply_shows_delivered_in_the_app(solo, people):
    tid, _path = _customer_ticket(solo, "ZTEST G6 delivery tag", phone="386-555-0166")
    owner = people(solo, "owner")
    owner.sign_in()
    owner.tab("mine")
    owner.open_ticket(tid)
    owner.type("#msg", "ZTEST G6 we'll be there Friday")
    owner.page.select_option("#msgVis", "public")
    owner.click("#msgGo")
    solo.wait_message(lambda m: m["to"].endswith("5550166") and "Friday" in m["body"])
    owner.click("#refreshBtn")
    owner.page.locator(".msg", has_text="ZTEST G6 we'll be there Friday").locator(".dlv.ok",
                                                                                   has_text="✓ sent").wait_for()


# ── DATA & BACKUPS ────────────────────────────────────────────────────────────

def test_D1_backups_and_export(solo, tmp_path):
    dgs = _gui()
    _customer_ticket(solo, "ZTEST D1 in the backup")
    b = dgs.backup_now(solo.db)
    names = [n for n, _ in dgs.backup_rows(solo.db)]
    assert b["name"] in names
    assert "✔ verified" in dict(dgs.backup_rows(solo.db))[b["name"]]
    ok, msg = dgs.save_backup_settings(solo.db, {"backup_hour": "two", "backup_keep_daily": "5"}, ED)
    assert not ok and "hour: enter a whole number" in msg
    import desk_db
    assert dgs.save_backup_settings(solo.db, {"backup_hour": "3", "backup_keep_daily": "9",
                                              "backup_frequency": "daily"}, ED)[0]
    s = desk_db.get_settings(solo.db)
    assert (s["backup_hour"], s["backup_keep_daily"], s["backup_frequency"]) == (3, 9, "daily")
    import zipfile
    assert dgs.export_name(solo.db, "csv", ED).endswith("-csv.zip")
    out = dgs.export_to(solo.db, "csv", str(tmp_path / "t.zip"), ED)
    with zipfile.ZipFile(out) as z:                         # one CSV per table: tickets, messages, events
        assert {"tickets.csv", "messages.csv", "events.csv"} <= set(z.namelist())
        assert "ZTEST D1 in the backup" in z.read("tickets.csv").decode("utf-8-sig")


# ── AGENT ─────────────────────────────────────────────────────────────────────

def test_A1_agent_name_reaches_the_customer_page(solo):
    import desk_gui_agent as dga
    ok, msg = dga.save(solo.db, {"agent_wait_hours": "lots"}, edition=ED)
    assert not ok and "wait hours: enter a whole number" in msg, msg
    # the label is a fixed list on purpose — customers must always be able to tell it's an assistant
    assert not dga.save(solo.db, {"agent_label": "Bob from the office"}, edition=ED)[0]
    try:
        assert dga.save(solo.db, {"agent_name": "ZTEST Robin", "agent_label": "AI assistant"}, edition=ED)[0]
        st, d = _get(f"{solo.base}/support-api/agent")
        assert st == 200 and d["name"] == "ZTEST Robin" and d["display"] == "ZTEST Robin · AI assistant", d
    finally:
        dga.save(solo.db, {"agent_name": "", "agent_label": "Virtual assistant"}, edition=ED)
