"""A typical day, following the Getting-started wizard (spec §6.14, WIZ-10),
done through the real screens the way a person does it:

  1. Add a customer      Database tab → Customers → + Add → Create
  2. Record a quote      Database tab → Quotes → + Add → Create (Approved)
  3. Add the job         Jobs → + Add → pick the customer → Save
  4. Build the route     Route → pick today → Route Selected Date
  5. Clock in & out      job → ▶ Clock In, then ■ Clock Out
  6. Add a photo         job → 📷 Add Photos → pick a file → Upload
  7. Create the invoice  job → 🧾 Create Invoice → Create
  8. Send the receipt    job → 📧 Email Receipt → "Cash" → confirm
                         (the write guard RECORDS the send; nothing is emailed)

Each step is checked on screen AND in the database. Uploaded photo files are
deleted afterwards (job numbers get reused — leftover photos would attach
themselves to a future real job).

Run: run_tests_gui_jobs_e2e.bat --human -k typical_day
"""
import base64
import re
import shutil
import time
from pathlib import Path

import pytest
from playwright.sync_api import expect

from app import RouteScreen, type_text
from app_jobs import JobForm
from safety import SANDBOX_DATE

# a real 1x1 PNG
TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
PHOTOS_ROOT = Path.home() / "Documents" / "AI-Prowler" / "JobPhotos"
# Typed through the UI, so the server has to geocode it: must be an address
# OpenStreetMap knows. ("210 Sams Ave", city hall, is NOT in OSM — a job there
# can never be placed on a route.)
GEO_STREET = "105 S Riverside Dr"


def _ensure_job_located(api, jid: str, log) -> None:
    """Make sure the new job has a map location before it's routed.

    The app looks up a new job's location with the free OpenStreetMap service
    (Nominatim), retrying 3 times (R-023). On 2026-10-02 all 3 tries failed
    for this job during a full run — the service simply didn't answer for a
    few seconds — and step 4 then failed as "the job isn't on today's route",
    which hid the real cause. If the location is missing, look it up again
    (a few seconds apart) and store it; if the service stays down, skip with
    that reason instead of a misleading failure. The app's own handling of a
    job with no location (NOT PLACED + the pre-route warning) is tested elsewhere."""
    import time as _t

    def _located():
        row = next((j for j in api.read("Jobs_Schedule") if j.get("JobID (JOB-####)") == jid), {})
        return (str(row.get("Latitude (AI Geocode)") or "").strip()
                and str(row.get("Longitude (AI Geocode)") or "").strip())

    if _located():
        return
    addr = f"{GEO_STREET}, New Smyrna Beach, FL 32168"
    for attempt in range(1, 4):
        log(f"⚠️ step 3: {jid} has no map location — the free map service didn't answer when the "
            f"job was saved; looking it up again ({attempt}/3)")
        _t.sleep(3)
        out = str(api.call("geocode_address", {"address": addr}, expect_ok=False))
        la = re.search(r"Latitude:\s*(-?\d+(?:\.\d+)?)", out)
        lo = re.search(r"Longitude:\s*(-?\d+(?:\.\d+)?)", out)
        if la and lo:
            api.call("update_job_spreadsheet", {
                "job_identifier": jid, "sheet_name": "Jobs_Schedule", "id_column": "JobID (JOB-####)",
                "updates": {"Latitude (AI Geocode)": float(la.group(1)),
                            "Longitude (AI Geocode)": float(lo.group(1))}})
            if _located():
                log(f"step 3: {jid} located on retry {attempt}")
                return
    pytest.skip(f"the free map service (OpenStreetMap) didn't answer for {addr!r} — "
                f"{jid} has no map location, so it can't be routed; not an AI-Prowler failure")


# ── helpers ──────────────────────────────────────────────────────────────────
def _open_sheet_tab(app, page, tab: str):
    app.goto("sheet")
    page.locator("#sheetTabs").get_by_role("button", name=re.compile(rf"^\W*{tab}", re.I)).first.click()
    page.wait_for_timeout(600)


def _generic_fill(page, col: str, value: str, log):
    el = page.locator(f"#jfGenericInputs [data-col-name='{col}']")
    if el.count() == 0:
        log(f"(no '{col}' field on this form — skipped)")
        return
    el = el.first
    tag = el.evaluate("e => e.tagName")
    if tag != "SELECT" and not el.is_editable():
        # e.g. the Quote form fills in and LOCKS Customer Name once a
        # CustomerID is picked, so the two can't disagree (found 2026-09-26)
        log(f"'{col}' is locked by the app (value {el.input_value()!r}) — not typed")
        return
    log(f"fill {col} = {value!r}")
    if tag == "SELECT":
        el.select_option(value)
    else:
        el.fill("")
        type_text(page, el, value)


def _generic_create(page, tool: str):
    with page.expect_request(lambda r: "/pwa-api" in r.url and tool in (r.post_data or ""), timeout=30_000):
        page.locator("#jobFormSaveBtn").click()
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)


def _find(api, sheet: str, **match):
    for r in api.read(sheet):
        if all(str(r.get(k, "")).strip() == str(v) for k, v in match.items()):
            return r
    return None


def _open_job(app, page, jid):
    # A job detail may still be open from the previous step (after an invoice
    # the app re-opens it on purpose) — tap outside it first, like a person.
    modal = page.locator("#jobModal")
    if "open" in (modal.get_attribute("class") or ""):
        modal.click(position={"x": 5, "y": 5})
        expect(modal).not_to_have_class(re.compile(r"\bopen\b"))
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("jobs")
    page.locator(f"[data-testid='job-card'][data-jobid='{jid}']").click()
    expect(page.locator("#jobModal")).to_have_class(re.compile(r"\bopen\b"))


def _detail_button(page, name_re):
    return page.locator("#jobModal").get_by_role("button", name=re.compile(name_re))


# ── the day ──────────────────────────────────────────────────────────────────
def test_WIZ_10_a_typical_day_following_the_wizard(clean_slate, app, page, api, guard, tmp_path):
    token = str(int(time.time()))[-6:]
    cust_name = f"ZTEST E2E Day {token}"
    log = app.log
    jid = None
    try:
        # 1. customer
        log("DAY 1/8 add a customer (Database → Customers → + Add)")
        _open_sheet_tab(app, page, "Customers")
        page.locator("#sheetAddBtn").click()
        expect(page.locator("#jobFormModal")).to_be_visible()
        for col, val in [("Company Name", cust_name), ("Email", "ztest-e2e@example.invalid"),
                         ("Street Address", GEO_STREET), ("City", "New Smyrna Beach"),
                         ("State", "FL"), ("ZIP", "32168"), ("Status Active/Inactive", "Active")]:
            _generic_fill(page, col, val, log)
        _generic_create(page, "create_customer")
        cust = _find(api, "Customers", **{"Company Name": cust_name})
        assert cust, "step 1: the customer isn't in the database"
        cid = cust["CustomerID (CUST-####)"]

        # 2. quote
        log("DAY 2/8 record a quote (Database → Quotes → + Add)")
        _open_sheet_tab(app, page, "Quotes")
        page.locator("#sheetAddBtn").click()
        expect(page.locator("#jobFormModal")).to_be_visible()
        for col, val in [("CustomerID", cid), ("Customer Name / Company", cust_name),
                         ("Service Type", "Window"), ("Service Description", f"Windows inside and out {token}"),
                         ("QUOTE TOTAL ($)", "150"), ("Status (Open/Approved/Declined)", "Approved")]:
            _generic_fill(page, col, val, log)
        _generic_create(page, "create_quote")
        quote = _find(api, "Quotes", **{"CustomerID": cid})
        assert quote, "step 2: the quote isn't in the database"

        # 3. job
        log("DAY 3/8 add the job (Jobs → + Add)")
        page.evaluate("async () => { await loadJobs(); }")
        app.goto("jobs")
        form = JobForm(page, log).open_new()
        form.customer(cid).text("jfAddress", GEO_STREET).text("jfCity", "New Smyrna Beach")
        form.text("jfState", "FL").text("jfZip", "32168").set("jfDate", SANDBOX_DATE)
        form.choose("jfSchedType", "Soft").set("jfStart", "08:00").set("jfEnd", "17:00").set("jfDuration", "45")
        form.text("jfService", "Window").set("jfQuote", "150").text("jfNotes", f"typical day {token}")
        form.save("create_job")
        expect(form.modal).to_be_hidden()
        # (the Jobs sheet read doesn't list CustomerID — find the job by its unique note)
        job = next((j for j in api.read("Jobs_Schedule")
                    if f"typical day {token}" in (j.get("Service Details / Notes") or "")), None)
        assert job, "step 3: the job isn't in the database"
        jid = job["JobID (JOB-####)"]
        _ensure_job_located(api, jid, log)      # a routed job needs a map location

        # 4. route
        log("DAY 4/8 build the route (Route → today → Route Selected Date)")
        app.goto("route")
        route = RouteScreen(page, log)
        route.pick_date(SANDBOX_DATE)
        route.press_route_selected_date(accept_errors=True)
        route.wait_quiet()
        assert jid in [s.job_id() for s in route.stops()], "step 4: the job isn't on today's route"

        # 5. clock in & out
        log("DAY 5/8 clock in, then clock out (job detail)")
        _open_job(app, page, jid)
        with page.expect_request(lambda r: "log_time_entry" in (r.post_data or "")):
            _detail_button(page, "Clock In").click()
        route.wait_quiet()
        expect(page.locator("#clockResult")).not_to_contain_text("❌")
        _open_job(app, page, jid)
        with page.expect_request(lambda r: "log_time_entry" in (r.post_data or "")):
            _detail_button(page, "Clock Out").click()
        route.wait_quiet()
        expect(page.locator("#clockResult")).not_to_contain_text("❌")

        # 6. photo
        log("DAY 6/8 add a photo (job detail → 📷 Add Photos → Upload)")
        png = tmp_path / f"ztest_{token}.png"
        png.write_bytes(TINY_PNG)
        _open_job(app, page, jid)
        with page.expect_file_chooser(timeout=10_000) as fc:
            _detail_button(page, "Add Photos").click()
        fc.value.set_files(str(png))
        expect(page.locator("#uploadBtn")).to_be_enabled(timeout=10_000)
        type_text(page, page.locator("#photoNotes"), f"before photo {token}")
        page.locator("#uploadBtn").click()
        expect(page.locator("#uploadStatus")).to_contain_text("saved", timeout=30_000)
        assert (PHOTOS_ROOT / jid).exists() and any((PHOTOS_ROOT / jid).iterdir()), \
            f"step 6: no photo saved under {PHOTOS_ROOT / jid}"

        # 7. invoice
        log("DAY 7/8 create the invoice (job detail → 🧾 Create Invoice)")
        _open_job(app, page, jid)
        _detail_button(page, "Create Invoice").click()
        expect(page.locator("#invoiceFormModal")).to_be_visible()
        expect(page.locator("#ifQuote")).to_have_value(re.compile(r"^150"))
        with page.expect_request(lambda r: "create_invoice" in (r.post_data or "")):
            page.locator("#ifSubmitBtn").click()
        expect(page.locator("#invoiceFormModal")).to_be_hidden(timeout=20_000)
        inv = _find(api, "Invoices", **{"JobID (JOB-####)": jid})
        assert inv, "step 7: no invoice for the job in the database"

        # 8. receipt (recorded by the guard, not sent)
        log("DAY 8/8 send the receipt (job detail → 📧 Email Receipt → Cash)")
        n = len(guard.recorded_calls("email_receipt"))
        answers = []

        def on_dialog(d):
            answers.append((d.type, d.message))
            d.accept("Cash") if d.type == "prompt" else d.accept()
        page.on("dialog", on_dialog)
        try:
            _open_job(app, page, jid)
            # Wait for the RESPONSE (the guard's "recorded" answer), not the
            # request — the request fires before the guard records it (2026-10-02).
            with page.expect_response(lambda r: "email_receipt" in (r.request.post_data or ""),
                                      timeout=30_000):
                _detail_button(page, "Email Receipt").first.click()
        finally:
            page.remove_listener("dialog", on_dialog)
        calls = guard.recorded_calls("email_receipt")
        assert len(calls) == n + 1, f"step 8: no receipt send recorded (dialogs: {answers})"
        assert calls[-1]["args"].get("payment_method") == "Cash"
        assert guard.real_emails_sent == 0
        log("DAY done — all 8 wizard steps worked through the real screens")
    finally:
        if jid and (PHOTOS_ROOT / jid).exists():
            shutil.rmtree(PHOTOS_ROOT / jid, ignore_errors=True)        # never leave test photos behind


# ── suspected bugs found while reading the code (2026-09-26) ─────────────────
def test_CLK_01_clock_out_that_the_server_refuses_is_not_shown_as_success(clean_slate, app, page, data):
    """R-020 (found 2026-09-26): clocking OUT of a job you never clocked in to
    is refused by the server ('❌ No open clock-in found…'), but the app still
    said 'Clocked out!' — the crew's payroll hours looked recorded when they
    weren't. The refusal must be shown instead."""
    jid = data.job("CLK01", "city_hall")
    _open_job(app, page, jid)
    with page.expect_request(lambda r: "log_time_entry" in (r.post_data or "")):
        _detail_button(page, "Clock Out").click()
    expect(page.locator("#clockResult")).to_contain_text("No open clock-in", timeout=15_000)
    page.wait_for_timeout(800)
    assert page.get_by_text("Clocked out!", exact=True).count() == 0, \
        "the server refused the clock-out but the app said 'Clocked out!'"


def test_INV_01_after_creating_an_invoice_the_job_reopens(clean_slate, app, page, data):
    """submitInvoiceForm() is meant to re-open the job so the new Email / Text
    Invoice buttons show — but it clears the job id (closeInvoiceForm) BEFORE
    checking it, so the job never re-opens."""
    jid = data.job("INV01", "city_hall", **{"Quote Amount ($)": 120})
    _open_job(app, page, jid)
    _detail_button(page, "Create Invoice").click()
    expect(page.locator("#invoiceFormModal")).to_be_visible()
    page.locator("#ifQuote").fill("120")
    with page.expect_request(lambda r: "create_invoice" in (r.post_data or "")):
        page.locator("#ifSubmitBtn").click()
    expect(page.locator("#invoiceFormModal")).to_be_hidden(timeout=20_000)
    expect(page.locator("#jobModal")).to_have_class(re.compile(r"\bopen\b"), timeout=5_000)
    # R-021: the job detail must be REFRESHED — no more "Create Invoice", the
    # send buttons at full strength (it used to stay stale behind the form)
    expect(_detail_button(page, "Create Invoice")).to_have_count(0, timeout=5_000)
    expect(_detail_button(page, "Email Invoice")).to_be_visible()
