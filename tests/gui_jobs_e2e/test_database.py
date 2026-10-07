"""Database screen (spec §6.16) — the owner's view of every table: 9 tabs,
+ Add / Edit / Delete, and each tab's own filters. Used the way a person
uses it; every change is checked on screen AND read back from the database.
The price-list tab has its own file (test_price_list.py, §6.12).

All data is ZTEST: the one 'ZTEST E2E Customer' (its delete cascades its jobs,
quotes, invoices, time entries), jobs inside the sandbox window, ZTEST- price
codes. Settings are only OPENED here, never saved (the write guard would block
a save to a real setting anyway).

Run: run_tests_gui_jobs_e2e.bat --human -k test_database
"""
import re

import pytest
from playwright.sync_api import expect

from app import type_text
from api import iso_date
from data import CUSTOMER_NAME
from safety import SANDBOX_DATE, sandbox_day

CUST_ID_COL = "CustomerID (CUST-####)"
SHEETS = {  # name: (addable, the tab's own controls row / button that must show ONLY on it)
    "Jobs_Schedule": (True, "#jobsExtraControlsRow"),
    "Customers": (True, "#showInactiveBtn"),
    "Invoices": (True, "#invoicesControlsRow"),
    "Quotes": (True, "#quotesControlsRow"),
    "TimeLog": (False, "#timeLogControlsRow"),
    "Route_Planner": (False, None),
    "Services_Pricing": (True, None),
    "Settings": (False, None),
    "AI-Prowler-Commands": (False, None),
}
OWN_CONTROLS = [c for _, c in SHEETS.values() if c] + ["#showDeclinedBtn"]


# ── helpers ──────────────────────────────────────────────────────────────────
@pytest.fixture
def db(clean_slate, app, page):
    """The Database screen, open."""
    app.goto("sheet")
    _wait(page)
    return page


def _wait(page):
    expect(page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    page.wait_for_timeout(400)


def _tab(app, page, sheet):
    app.log(f"DATABASE open the {sheet} tab")
    page.locator(f"#sheetTabs .sheet-tab-btn[data-sheet='{sheet}']").click()
    _wait(page)


def _refresh(app, page):
    app.log("DATABASE tap ↻")
    page.locator("#refreshSheetBtn").click()
    _wait(page)


def _edit_btn(page, row_id):
    return page.locator(f".sheet-row-edit-btn[data-rowid='{row_id}']")


def _row(page, row_id):
    return page.locator("#sheetContent tr", has=_edit_btn(page, row_id))


def _field(page, col):
    return page.locator(f"#jfGenericInputs [data-col-name='{col}']").first


def _fill(app, page, col, value):
    el = _field(page, col)
    app.log(f"fill {col} = {value!r}")
    tag, typ = el.evaluate("e => [e.tagName, e.type]")
    if tag == "SELECT":
        el.select_option(value)
    elif typ in ("date", "time"):
        el.fill(value)
    else:
        el.fill("")
        type_text(page, el, value)


def _save(app, page, tool):
    app.log(f"DATABASE tap Save / Create ({tool})")
    with page.expect_response(lambda r: "/pwa-api" in r.url and tool in (r.request.post_data or ""),
                              timeout=30_000):
        page.locator("#jobFormSaveBtn").click()


def _open_edit(app, page, row_id):
    app.log(f"DATABASE tap Edit on {row_id}")
    btn = _edit_btn(page, row_id)
    btn.scroll_into_view_if_needed()
    btn.click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jfGenericInputs .spinner")).to_have_count(0, timeout=20_000)


def _close_form(page):
    page.keyboard.press("Escape")
    if page.locator("#jobFormModal").is_visible():
        page.locator("#jobFormModal").click(position={"x": 5, "y": 5})
    if page.locator("#jobFormModal").is_visible():
        page.evaluate("closeJobFormModal()")


def _tap_answering(app, page, locator, accept: bool, what: str) -> list[str]:
    """Tap a button that asks 'are you sure' (confirm) and then pops up the
    server's answer (alert). Returns every dialog text seen."""
    said = []

    def answer(d):
        said.append(d.message)
        if d.type == "confirm":
            app.log(f"DIALOG {'OK' if accept else 'Cancel'}: {d.message[:90]}")
            d.accept() if accept else d.dismiss()
        else:
            app.log(f"DIALOG message: {d.message[:140]}")
            d.accept()

    page.on("dialog", answer)
    try:
        app.log(f"DATABASE tap {what}")
        locator.scroll_into_view_if_needed()
        locator.click()
        page.wait_for_timeout(3000 if accept else 800)
        _wait(page)
    finally:
        page.remove_listener("dialog", answer)
    return said


def _rec(api, sheet, col, value):
    return next((r for r in api.read(sheet) if r.get(col, "") == value), None)


def _write_calls(page):
    """Start recording every write the page sends (to prove a form was only looked at)."""
    seen = []
    page.on("request", lambda r: seen.append(r.post_data or "") if "/pwa-api" in r.url else None)
    return lambda: [p for p in seen if re.search(r'"tool":\s*"(update_|create_|delete_)', p)]


def _quote(api, cust, **fields):
    f = {"CustomerID": cust, "Customer Name / Company": CUSTOMER_NAME, "Quote Date": SANDBOX_DATE,
         "Service Type": "Window", "Subtotal ($)": 200, "Status (Open/Approved/Declined)": "Open"}
    f.update(fields)
    out = api.call("create_quote", {"updates": f})
    return re.search(r"QTE-\d+", out).group(0)


# ── tabs ─────────────────────────────────────────────────────────────────────
def test_DB_01_every_tab_opens_with_its_own_controls(db, app):
    page = db
    for sheet, (addable, own) in SHEETS.items():
        _tab(app, page, sheet)
        assert page.evaluate("_activeSheet") == sheet
        txt = page.locator("#sheetContent").inner_text()
        assert "Error loading" not in txt and "Could not load" not in txt, f"{sheet}: {txt[:200]}"
        add = page.locator("#sheetAddBtn")
        (expect(add).to_be_visible() if addable else expect(add).to_be_hidden())
        mine = set([own] if own else []) | ({"#showDeclinedBtn"} if sheet == "Quotes" else set())
        for c in OWN_CONTROLS:
            loc = page.locator(c)
            (expect(loc).to_be_visible() if c in mine else expect(loc).to_be_hidden())
    _tab(app, page, "Settings")
    expect(page.locator("#sheetContent")).to_contain_text("Business Settings")
    expect(page.locator("#sheetContent")).to_contain_text("Required For Invoicing")
    _tab(app, page, "AI-Prowler-Commands")
    expect(page.locator("#sheetContent")).to_contain_text("Add a service price")


def test_DB_02_refresh_shows_a_change_made_elsewhere(db, app, data):
    page = db
    _tab(app, page, "Customers")
    app.log("SOMEONE ELSE adds a customer while the tab is open")
    cid = data.customer_id()
    expect(_edit_btn(page, cid)).to_have_count(0)
    _refresh(app, page)
    expect(_edit_btn(page, cid)).to_be_visible()


# ── customers ────────────────────────────────────────────────────────────────
def test_DB_03_add_customer(db, app, api):
    page = db
    name = "ZTEST E2E DB03 O'Brien & Sons <b>bold</b>"
    _tab(app, page, "Customers")
    page.locator("#sheetAddBtn").click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jfGenericInputs .spinner")).to_have_count(0, timeout=20_000)
    expect(page.locator("#jobFormTitle")).to_contain_text("Add New")
    expect(_field(page, CUST_ID_COL)).to_have_count(0)   # auto-assigned, not typed
    _fill(app, page, "Company Name", name)
    _fill(app, page, "Phone", "386-555-0199")
    _fill(app, page, "City", "New Smyrna Beach")
    _fill(app, page, "Status Active/Inactive", "Active")
    _save(app, page, "create_customer")
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    r = _rec(api, "Customers", "Company Name", name)
    assert r, "not in the database"
    cid = r[CUST_ID_COL]
    assert re.fullmatch(r"CUST-\d+", cid), cid
    assert r["Phone"] == "386-555-0199" and r["City"] == "New Smyrna Beach"
    row = _row(page, cid)
    expect(row).to_be_visible(timeout=15_000)
    expect(row).to_contain_text(name)                    # shown as text, not as HTML
    expect(row.locator("b")).to_have_count(0)
    _open_edit(app, page, cid)                            # the odd name survives into the form
    expect(_field(page, "Company Name")).to_have_value(name)
    _close_form(page)


def test_DB_04_edit_customer(db, app, api, data):
    page = db
    cid = data.customer_id()
    _tab(app, page, "Customers")
    before = _rec(api, "Customers", CUST_ID_COL, cid)
    _open_edit(app, page, cid)
    expect(_field(page, "Company Name")).to_have_value(CUSTOMER_NAME)
    _fill(app, page, "Phone", "386-555-0142")
    _fill(app, page, "Gate Code / Access Notes", "Gate 4321, dog in yard")
    _save(app, page, "update_job_spreadsheet")
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    after = _rec(api, "Customers", CUST_ID_COL, cid)
    assert after["Phone"] == "386-555-0142", after
    assert after["Gate Code / Access Notes"] == "Gate 4321, dog in yard", after
    for col in ("Company Name", "City", "State", "ZIP", "Status Active/Inactive"):
        assert after.get(col, "") == before.get(col, ""), f"{col}: {before.get(col)!r} → {after.get(col)!r}"
    expect(_row(page, cid)).to_contain_text("386-555-0142")


@pytest.mark.parametrize("sheet,id_col", [("Customers", CUST_ID_COL), ("Services_Pricing", "Service Code")],
                         ids=["customer", "price"])
def test_DB_05_edit_form_does_not_offer_to_change_the_id(db, app, api, data, sheet, id_col):
    """The row's own ID (CustomerID, Service Code) can't be changed by an edit —
    the server ignores it — so the Edit form must show it read-only, not as a
    box that looks editable and then silently does nothing."""
    page = db
    if sheet == "Customers":
        rid = data.customer_id()
    else:
        rid = "ZTEST-IDRO"
        api.call("create_service_pricing", {"updates": {"Service Code": rid, "Name": "id test",
                                                        "Base Price ($)": 10}})
    _tab(app, page, sheet)
    _open_edit(app, page, rid)
    el = _field(page, id_col)
    expect(el).to_have_count(1)
    expect(el).to_have_value(rid)
    locked = el.evaluate("e => e.readOnly || e.disabled || !['INPUT','SELECT','TEXTAREA'].includes(e.tagName)")
    _close_form(page)
    assert locked, f"{id_col} is an editable box on Edit — a changed value would be silently ignored"


def test_DB_06_stale_customer_edit_is_refused_not_overwritten(db, app, api, data):
    """Same as PR-06 (R-032), on the Customers tab: someone else saves while this
    Edit form is open; this person's save must not wipe out their change."""
    page = db
    cid = data.customer_id()
    _tab(app, page, "Customers")
    _open_edit(app, page, cid)
    app.log("SOMEONE ELSE (another device) changes On-Site Contact while this form is open")
    api.call("update_job_spreadsheet", {"sheet_name": "Customers", "job_identifier": cid,
                                        "id_column": CUST_ID_COL,
                                        "updates": {"On-Site Contact": "Pat (changed elsewhere)"}})
    _fill(app, page, "Phone", "386-555-0106")
    _save(app, page, "update_job_spreadsheet")
    page.wait_for_timeout(1500)
    r = _rec(api, "Customers", CUST_ID_COL, cid)
    _close_form(page)
    assert r.get("On-Site Contact", "") == "Pat (changed elsewhere)", \
        f"the other person's change was silently overwritten: On-Site Contact={r.get('On-Site Contact')!r}"


def test_DB_07_inactive_customer_hide_show_delete(db, app, api, data):
    page = db
    cid = data.customer_id()
    _tab(app, page, "Customers")
    expect(_row(page, cid)).to_be_visible()
    expect(page.locator(f".sheet-row-delete-customer-btn[data-custid='{cid}']")).to_have_count(0)  # Active: no Delete
    _open_edit(app, page, cid)
    _fill(app, page, "Status Active/Inactive", "Inactive")
    _save(app, page, "update_job_spreadsheet")
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    _wait(page)
    expect(_row(page, cid)).to_have_count(0)            # hidden by default
    app.log("DATABASE tap Show Inactive")
    page.locator("#showInactiveBtn").click()
    _wait(page)
    expect(page.locator("#showInactiveBtn")).to_have_text("Hide Inactive")
    expect(_row(page, cid)).to_be_visible()
    delete = page.locator(f".sheet-row-delete-customer-btn[data-custid='{cid}']")
    expect(delete).to_be_visible()
    _tap_answering(app, page, delete, accept=False, what=f"Delete on {cid} (then Cancel)")
    assert _rec(api, "Customers", CUST_ID_COL, cid), "deleted even though Cancel was tapped"
    said = _tap_answering(app, page, delete, accept=True, what=f"Delete on {cid} (then OK)")
    data._cust_id = None
    assert len(said) >= 2 and said[1].lstrip().startswith("✅"), f"dialogs: {said}"
    expect(_row(page, cid)).to_have_count(0)
    assert _rec(api, "Customers", CUST_ID_COL, cid) is None


# ── quotes ───────────────────────────────────────────────────────────────────
def test_DB_08_add_quote_with_customer_picker_then_delete(db, app, api, data):
    page = db
    cid = data.customer_id()
    _tab(app, page, "Quotes")
    page.locator("#sheetAddBtn").click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    sel = page.locator("#jfGenericCustomerSelect")
    expect(sel.locator(f"option[value='{cid}']")).to_have_count(1, timeout=20_000)
    app.log(f"pick customer {cid}")
    sel.select_option(cid)
    expect(page.locator("#jfGenericCustomerNameDisplay")).to_have_value(CUSTOMER_NAME)
    _fill(app, page, "Quote Date", SANDBOX_DATE)
    _fill(app, page, "Service Type", "Window")
    _fill(app, page, "Subtotal ($)", "250")
    _fill(app, page, "Status (Open/Approved/Declined)", "Open")
    _save(app, page, "create_quote")
    expect(page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    q = next((r for r in api.read("Quotes") if r.get("CustomerID") == cid), None)
    assert q, "quote not in the database"
    assert q["Customer Name / Company"] == CUSTOMER_NAME, q
    qid = q["QuoteID (QTE-####)"]
    expect(_row(page, qid)).to_be_visible(timeout=15_000)
    delete = page.locator(f".sheet-row-delete-quote-btn[data-quoteid='{qid}']")
    said = _tap_answering(app, page, delete, accept=True, what=f"Delete on {qid} (then OK)")
    assert len(said) >= 2 and said[1].lstrip().startswith("✅"), f"dialogs: {said}"
    expect(_row(page, qid)).to_have_count(0)
    assert _rec(api, "Quotes", "QuoteID (QTE-####)", qid) is None


def test_DB_09_quote_filters(db, app, api, data):
    page = db
    cid = data.customer_id()
    q_open = _quote(api, cid)
    q_declined = _quote(api, cid, **{"Status (Open/Approved/Declined)": "Declined"})
    q_old = _quote(api, cid, **{"Quote Date": (__import__("datetime").date.fromisoformat(SANDBOX_DATE)
                                               - __import__("datetime").timedelta(days=40)).isoformat()})
    _tab(app, page, "Quotes")
    expect(_row(page, q_open)).to_be_visible()
    expect(_row(page, q_declined)).to_have_count(0)      # Declined hidden by default
    expect(_row(page, q_old)).to_have_count(0)           # older than the 7-day default
    app.log("DATABASE tap Show Declined")
    page.locator("#showDeclinedBtn").click()
    _wait(page)
    expect(_row(page, q_declined)).to_be_visible()
    app.log("DATABASE range → All time")
    page.locator("#quotesRangeSelect").select_option("0")
    _wait(page)
    expect(_row(page, q_old)).to_be_visible()
    app.log("DATABASE search for a customer that doesn't exist")
    type_text(page, page.locator("#quotesNameSearch"), "zz-nobody")
    page.wait_for_timeout(900)
    _wait(page)
    expect(_row(page, q_open)).to_have_count(0)
    expect(page.locator("#sheetContent")).to_contain_text('matching "zz-nobody"')
    page.locator("#quotesNameSearch").fill("")
    type_text(page, page.locator("#quotesNameSearch"), "ztest e2e")
    page.wait_for_timeout(900)
    _wait(page)
    for q in (q_open, q_declined, q_old):
        expect(_row(page, q)).to_be_visible()


# ── jobs ─────────────────────────────────────────────────────────────────────
def test_DB_10_jobs_tab_completed_sort_and_delete(db, app, api, data):
    page = db
    j_done = data.job("DB10 done", date=sandbox_day(0), **{"Job Status": "Complete"})
    j_late = data.job("DB10 later", date=sandbox_day(2))
    j_soon = data.job("DB10 sooner", date=sandbox_day(1))
    j_cancel = data.job("DB10 cancelled", date=sandbox_day(1), **{"Job Status": "Cancelled"})
    _tab(app, page, "Jobs_Schedule")
    expect(page.locator("#hideCompletedBtn")).to_have_text("Show Completed")   # completed hidden by default
    expect(_row(page, j_done)).to_have_count(0)

    def order():
        ids = page.eval_on_selector_all("#sheetContent .sheet-row-edit-btn", "bs => bs.map(b => b.dataset.rowid)")
        return [i for i in ids if i in (j_soon, j_late)]
    assert order() == [j_soon, j_late], f"Soonest first: {order()}"
    app.log("DATABASE sort → Soonest last")
    page.locator("#jobsSortSelect").select_option("desc")
    _wait(page)
    assert order() == [j_late, j_soon], f"Soonest last: {order()}"
    app.log("DATABASE tap Show Completed")
    page.locator("#hideCompletedBtn").click()
    _wait(page)
    expect(_row(page, j_done)).to_be_visible()
    # Delete is offered only on the cancelled job
    for j in (j_done, j_soon, j_late):
        expect(page.locator(f".sheet-row-delete-job-btn[data-jobid='{j}']")).to_have_count(0)
    delete = page.locator(f".sheet-row-delete-job-btn[data-jobid='{j_cancel}']")
    said = _tap_answering(app, page, delete, accept=True, what=f"Delete on {j_cancel} (then OK)")
    assert len(said) >= 2 and said[1].lstrip().startswith("✅"), f"dialogs: {said}"
    expect(_row(page, j_cancel)).to_have_count(0)
    ids = [r.get("JobID (JOB-####)") for r in api.read("Jobs_Schedule")]
    assert j_cancel not in ids and j_soon in ids and j_late in ids and j_done in ids


# ── time log ─────────────────────────────────────────────────────────────────
def test_DB_11_timelog_view_and_filters(db, app, api, data):
    page = db
    jid = data.job("DB11")
    api.call("log_time_entry", {"job_identifier": jid, "action": "start", "gps_coords": ""})
    page.wait_for_timeout(1200)
    api.call("log_time_entry", {"job_identifier": jid, "action": "stop", "gps_coords": ""})
    _tab(app, page, "TimeLog")
    expect(page.locator("#sheetAddBtn")).to_be_hidden()
    mine = page.locator("#sheetContent tr", has_text=jid)
    expect(mine).to_have_count(1)
    app.log("DATABASE search for a crew name that doesn't exist")
    type_text(page, page.locator("#timeLogNameSearch"), "zz-nobody")
    page.wait_for_timeout(900)
    _wait(page)
    expect(mine).to_have_count(0)
    expect(page.locator("#sheetContent")).to_contain_text('matching "zz-nobody"')
    page.locator("#timeLogNameSearch").fill("")
    page.locator("#timeLogNameSearch").dispatch_event("input")
    page.wait_for_timeout(900)
    _wait(page)
    expect(mine).to_have_count(1)


# ── route ────────────────────────────────────────────────────────────────────
def test_DB_12_route_tab_delete_stop_then_route(clean_slate, app, page, route, api, data):
    j1, j2 = data.job("DB12 a", "city_hall"), data.job("DB12 b", "library")
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date(accept_errors=True)

    def stops():
        return [s for s in api.read("Route_Planner") if iso_date(s.get("Route Date", "")) == SANDBOX_DATE]
    got = stops()
    assert len(got) >= 2, f"route not built: {got}"
    app.goto("sheet")
    _wait(page)
    _tab(app, page, "Route_Planner")
    first = str(got[0]["ID"])
    stop_btn = page.locator(f".sheet-row-delete-route-stop-btn[data-stopid='{first}']")
    said = _tap_answering(app, page, stop_btn, accept=True, what=f"Delete Stop {first} (then OK)")
    assert len(said) >= 2 and said[1].lstrip().startswith("✅"), f"dialogs: {said}"
    left = stops()
    assert first not in [str(s["ID"]) for s in left] and len(left) == len(got) - 1, left
    # "Delete Route" sits right before "Delete Stop" on the same row
    route_btn = page.locator(f".sheet-row-delete-route-stop-btn[data-stopid='{left[0]['ID']}']") \
        .locator("xpath=preceding-sibling::button[contains(@class,'sheet-row-delete-route-btn')]")
    said = _tap_answering(app, page, route_btn, accept=True, what="Delete Route (then OK)")
    assert len(said) >= 2 and said[1].lstrip().startswith("✅"), f"dialogs: {said}"
    assert stops() == [], "stops left after Delete Route"
    ids = [r.get("JobID (JOB-####)") for r in api.read("Jobs_Schedule")]
    assert j1 in ids and j2 in ids, "deleting the route deleted the jobs"


# ── invoices ─────────────────────────────────────────────────────────────────
def test_DB_13_invoices_add_picker_and_unpaid_filter(db, app, api, data):
    page = db
    j_done = data.job("DB13 done, not invoiced", **{"Job Status": "Complete", "Quote Amount ($)": 120})
    j_sched = data.job("DB13 scheduled", **{"Quote Amount ($)": 90})
    j_inv = data.job("DB13 invoiced", **{"Job Status": "Complete", "Quote Amount ($)": 100})
    j_cancel = data.job("DB13 cancelled", **{"Job Status": "Cancelled", "Quote Amount ($)": 80})
    out = api.call("create_invoice", {"job_identifier": j_inv, "quote_amount": 100, "discount": 0, "tax_rate": 0})
    inv = re.search(r"INV-\d+", out).group(0)
    _tab(app, page, "Invoices")
    expect(_row(page, inv)).to_be_visible()
    app.log("DATABASE tap Show Unpaid Only")
    page.locator("#showUnpaidOnlyBtn").click()
    _wait(page)
    expect(_row(page, inv)).to_be_visible()                 # $100 owed
    page.locator("#showUnpaidOnlyBtn").click()
    _wait(page)
    app.log(f"DATABASE search {j_inv}")
    type_text(page, page.locator("#invoicesSearch"), j_inv)
    page.wait_for_timeout(900)
    _wait(page)
    expect(_row(page, inv)).to_be_visible()
    page.locator("#invoicesSearch").fill("")
    page.locator("#invoicesSearch").dispatch_event("input")
    page.wait_for_timeout(900)
    _wait(page)
    app.log("DATABASE tap + Add (invoice: pick a job)")
    page.locator("#sheetAddBtn").click()
    picker = page.locator("#invoicePickerModal")
    expect(picker).to_have_class(re.compile(r"\bopen\b"), timeout=20_000)
    row = lambda j: picker.locator(f".invoice-picker-row[data-jobid='{j}']")
    expect(row(j_sched)).to_have_count(1)
    expect(row(j_inv)).to_have_count(0)                     # already invoiced
    expect(row(j_cancel)).to_have_count(0)                  # cancelled work isn't invoiced
    has_done = row(j_done).count()
    picker.click(position={"x": 5, "y": 5})
    expect(picker).not_to_have_class(re.compile(r"\bopen\b"))
    assert has_done == 1, "a Complete job that hasn't been invoiced yet is missing from the invoice picker"


# ── settings ─────────────────────────────────────────────────────────────────
def test_DB_14_settings_open_edit_form_without_saving(db, app, page):
    writes = _write_calls(page)
    _tab(app, page, "Settings")
    items = page.locator("#sheetContent div[onclick^='_settingsItemClicked']")
    assert items.count() >= 1
    label = items.first.inner_text().splitlines()[0]
    app.log(f"SETTINGS tap {label!r}")
    items.first.click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jfGenericInputs .spinner")).to_have_count(0, timeout=20_000)
    expect(_field(page, "Value")).to_have_count(1)
    _close_form(page)
    expect(page.locator("#jobFormModal")).to_be_hidden()
    assert writes() == [], f"opening/closing a setting wrote something: {writes()}"
