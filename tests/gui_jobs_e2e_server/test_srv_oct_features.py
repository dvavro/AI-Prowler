"""Server mode — Jobs-app features added 2026-10-02 .. 10-08 (spec §6.11, SRV-OCT).

Users: U1 David (owner), U2 Vicki (manager), U3 Samual (field_crew).
All data is ZTEST (one 'ZTEST E2E Customer' + jobs on the sandbox date; extra
customers are named 'ZTEST E2E …' so the sweep removes them too).

  SRV-PAUSE-01  owner: ⏸️ on a Jobs card → reason dialog (chip) → Save; job
                stashes its date, shows under Unscheduled with the reason;
                ⏸️ again resumes and restores the date
  SRV-PAUSE-02  field crew can't pause another crew's job (R-075)
  SRV-PAUSE-03  field crew pauses/resumes their OWN job from the Jobs page
  SRV-VIEW-01   Jobs page By Status / Billing per role (crew: own jobs only)
  SRV-CUST-01   owner renumbers a customer in Database → Customers → Edit
                (year fixed, number editable); jobs follow; other edits save
  SRV-CUST-02   a number that's already taken is refused in the popup
  SRV-CUST-03   field crew can't renumber a customer
  SRV-TAX-01    Weekly Tax Collected: owner only (manager no, crew no Reports)
  SRV-TAX-02    No Sales Tax job → invoice tax $0; a taxed job → 7%
  SRV-TAX-03    owner's Reports: a 7% invoice moves Weekly Tax Collected (R-084)
  SRV-PDAY-01   + Add job inherits the customer's Preferred Day(s); a date on
                another weekday warns
  SRV-SCHED-10  Soft start-after-end is blocked; end-only ("before X") saves

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_oct_features
"""
import datetime as dt
import re

import pytest
from playwright.sync_api import expect

from api import iso_date
from app import type_text
from app_jobs import JobForm
from safety import SANDBOX_DATE, ZTEST_PREFIX

OWNER, MANAGER, CREW = "David Vavro", "Vicki Vavro", "Samual Cronin"
CUST_ID_COL = "CustomerID (CUST-####)"
JOB_ID_COL = "JobID (JOB-####)"


# ── helpers ──────────────────────────────────────────────────────────────────
def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


def _refused(res) -> bool:
    return isinstance(res, str) and res.lstrip().startswith("❌")


def _job(api, jid):
    return next((r for r in api.read("Jobs_Schedule") if r.get(JOB_ID_COL) == jid), None)


def _cust(api, cid):
    return next((r for r in api.read("Customers") if r.get(CUST_ID_COL) == cid), None)


def _is_paused(row) -> bool:
    return str((row or {}).get("Paused", "")).strip().lower() in ("1", "true", "yes")


def _tool_response(page, tool):
    return page.expect_response(lambda r: "/pwa-api" in r.url and tool in (r.request.post_data or ""),
                                timeout=30_000)


def _open_jobs(w):
    w.app.goto("jobs")
    w.page.evaluate("async () => { await loadJobs(); }")
    w.page.wait_for_timeout(600)


def _card(page, jid):
    return page.locator(f"[data-testid='job-card'][data-jobid='{jid}']")


def _view(w, mode):
    btn = {"date": "#jobsViewDateBtn", "status": "#jobsViewStatusBtn", "billing": "#jobsViewBillingBtn"}[mode]
    w.app.step(f"Jobs view → {mode}")
    w.page.locator(btn).click()
    expect(w.page.locator(btn)).to_have_attribute("aria-pressed", "true")


def _section_of(page, jid) -> str:
    """Which jobs-section-label the card sits under (By Status / Billing views)."""
    return page.evaluate("""id => {
        const card = document.querySelector(`[data-testid='job-card'][data-jobid='${id}']`);
        if (!card) return '';
        let n = card.previousElementSibling;
        while (n && !n.classList.contains('jobs-section-label')) n = n.previousElementSibling;
        return n ? n.textContent.trim() : '';
    }""", jid)


def _new_ztest_customer(owner_api, label, **fields) -> str:
    f = {"Company Name": f"{ZTEST_PREFIX} {label}", "City": "New Smyrna Beach", "State": "FL",
         "ZIP": "32168", "Status Active/Inactive": "Active"}
    f.update(fields)
    out = owner_api.call("create_customer", {"updates": f})
    return re.search(r"NEW_CUST_ID=(\S+)", out).group(1)


# Database screen (same actions as the personal suite's test_database.py)
def _db_tab(w, sheet):
    w.app.goto("sheet")
    expect(w.page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    w.app.step(f"DATABASE open the {sheet} tab")
    w.page.locator(f"#sheetTabs .sheet-tab-btn[data-sheet='{sheet}']").click()
    expect(w.page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    w.page.wait_for_timeout(400)


def _db_open_edit(w, row_id):
    w.app.step(f"DATABASE tap Edit on {row_id}")
    btn = w.page.locator(f".sheet-row-edit-btn[data-rowid='{row_id}']")
    btn.scroll_into_view_if_needed()
    btn.click()
    expect(w.page.locator("#jobFormModal")).to_be_visible()
    expect(w.page.locator("#jfGenericInputs .spinner")).to_have_count(0, timeout=20_000)


def _close_form(page):
    if page.locator("#jobFormModal").is_visible():
        page.evaluate("closeJobFormModal()")


@pytest.fixture
def crew_jobs(clean_slate, data):
    """{'mine': Samual's job, 'theirs': Vicki's job} — both on the sandbox date."""
    return {"mine": data.job("OCT crew mine", **{"Crew / Technician": CREW}),
            "theirs": data.job("OCT crew theirs", "brannon", **{"Crew / Technician": MANAGER})}


# ── SRV-PAUSE-01 ─────────────────────────────────────────────────────────────
def test_SRV_PAUSE_01_owner_pauses_with_reason_then_resumes(windows, clean_slate, data, owner_api):
    jid = data.job("PAUSE01", **{"Crew / Technician": OWNER})
    (david,) = windows("U1")
    david.log_in()
    _signed_in(david)
    p = david.page
    _open_jobs(david)
    card = _card(p, jid)
    expect(card).to_be_visible(timeout=20_000)

    david.app.step(f"tap ⏸️ on {jid}")
    with _tool_response(p, "pause_job"):
        card.locator("[data-testid='job-pause']").click()
    modal = p.locator("#pauseReasonModal")
    expect(modal).to_be_visible()
    expect(p.locator("#pauseReasonJobLine")).to_contain_text(jid)
    david.app.step("pick the 'Equipment' reason chip, then Save")
    modal.get_by_role("button", name="Equipment").click()
    expect(p.locator("#pauseReasonInput")).to_have_value("Equipment")
    with _tool_response(p, "pause_job"):
        modal.get_by_role("button", name="Save", exact=True).click()
    expect(modal).to_be_hidden()

    r = _job(owner_api, jid)
    david.app.log(f"after pause: Paused={r.get('Paused')!r} Service Date={r.get('Service Date')!r} "
                  f"Paused Service Date={r.get('Paused Service Date')!r} Pause Comment={r.get('Pause Comment')!r}")
    assert _is_paused(r), r
    assert r.get("Pause Comment", "") == "Equipment", r
    assert not r.get("Service Date"), "a paused job keeps its live date"
    assert iso_date(r.get("Paused Service Date", "")) == SANDBOX_DATE, "date not stashed"

    _view(david, "status")
    expect(card).to_contain_text("Paused — Equipment")
    assert _section_of(p, jid).startswith("Unscheduled"), _section_of(p, jid)

    david.app.step(f"tap ⏸️ again on {jid} to resume")
    with _tool_response(p, "pause_job"):
        card.locator("[data-testid='job-pause']").click()
    expect(p.locator("#pauseReasonModal")).to_be_hidden()      # no dialog on resume
    r = _job(owner_api, jid)
    assert not _is_paused(r), r
    assert iso_date(r.get("Service Date", "")) == SANDBOX_DATE, "resume didn't restore the date"
    assert not r.get("Pause Comment"), "reason left behind after resume"


# ── SRV-PAUSE-02 (R-075) ─────────────────────────────────────────────────────
def test_SRV_PAUSE_02_crew_cannot_pause_another_crews_job(windows, crew_jobs, owner_api):
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    res = sam.app.mcp("pause_job", {"job_id": crew_jobs["theirs"], "paused": True, "reason": "crew test"})
    after = _job(owner_api, crew_jobs["theirs"])
    if _is_paused(after):          # put Vicki's (test) job back before asserting
        owner_api.call("pause_job", {"job_id": crew_jobs["theirs"], "paused": False})
    sam.app.log(f"Samual pausing Vicki's job → {str(res)[:160]!r}")
    assert _refused(res), f"field crew paused another crew's job: {res!r}"
    assert not _is_paused(after)


# ── SRV-PAUSE-03 ─────────────────────────────────────────────────────────────
def test_SRV_PAUSE_03_crew_pauses_and_resumes_own_job(windows, crew_jobs, owner_api):
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    p = sam.page
    _open_jobs(sam)
    card = _card(p, crew_jobs["mine"])
    expect(card).to_be_visible(timeout=20_000)
    expect(_card(p, crew_jobs["theirs"])).to_have_count(0)
    with _tool_response(p, "pause_job"):
        card.locator("[data-testid='job-pause']").click()
    expect(p.locator("#pauseReasonModal")).to_be_visible()
    sam.app.step("Skip the reason")
    p.locator("#pauseReasonModal").get_by_role("button", name="Skip").click()
    assert _is_paused(_job(owner_api, crew_jobs["mine"]))
    _view(sam, "status")
    with _tool_response(p, "pause_job"):
        card.locator("[data-testid='job-pause']").click()
    r = _job(owner_api, crew_jobs["mine"])
    assert not _is_paused(r) and iso_date(r.get("Service Date", "")) == SANDBOX_DATE, r


# ── SRV-VIEW-01 ──────────────────────────────────────────────────────────────
def test_SRV_VIEW_01_by_status_and_billing_per_role(windows, clean_slate, data):
    done = {"Job Status": "Complete", "Payment Status": "Unpaid", "Quote Amount ($)": 90}
    mine = data.job("VIEW crew done", **{"Crew / Technician": CREW}, **done)
    theirs = data.job("VIEW mgr done", "brannon", **{"Crew / Technician": MANAGER}, **done)
    sam, vicki = windows("U3", "U2")
    for w in (sam, vicki):
        w.log_in()
        _signed_in(w)
        _open_jobs(w)

    for w in (sam, vicki):
        _view(w, "status")
        expect(w.page.locator("#jobsPageTitle")).to_have_text("All Jobs")
    assert _section_of(sam.page, mine).startswith("Complete"), _section_of(sam.page, mine)
    expect(_card(sam.page, theirs)).to_have_count(0)
    assert _section_of(vicki.page, mine).startswith("Complete")
    assert _section_of(vicki.page, theirs).startswith("Complete")

    for w in (sam, vicki):
        _view(w, "billing")
        expect(w.page.locator("#billingChips")).to_be_visible()
        w.page.locator("#billingChips [data-bchip='unpaid']").click()
    expect(_card(sam.page, mine)).to_be_visible()
    expect(_card(sam.page, theirs)).to_have_count(0)
    expect(_card(vicki.page, mine)).to_be_visible()
    expect(_card(vicki.page, theirs)).to_be_visible()
    assert _section_of(sam.page, mine).startswith("Unpaid")


# ── SRV-CUST-01 (CUST-YEAR-N editor) ─────────────────────────────────────────
def test_SRV_CUST_01_owner_renumbers_customer_in_edit_popup(windows, clean_slate, data, owner_api):
    cid = data.customer_id()
    m = re.fullmatch(r"CUST-(\d{4})-(\d+)", cid)
    assert m, f"new customers should get CUST-<year>-<n>, got {cid!r}"
    year, num = m.group(1), int(m.group(2))
    jid = data.job("CUST01")
    taken = {int(c.rsplit("-", 1)[1]) for c in (r.get(CUST_ID_COL, "") for r in owner_api.read("Customers"))
             if c.startswith(f"CUST-{year}-")}
    free = next((n for n in range(1, num) if n not in taken), None)
    if free is None:
        pytest.skip(f"no free customer number below {num} in {year} — renumbering upward would "
                    "raise the year's counter for real customers")
    new_id = f"CUST-{year}-{free}"

    (david,) = windows("U1")
    david.log_in()
    _signed_in(david)
    _db_tab(david, "Customers")
    _db_open_edit(david, cid)
    p = david.page
    num_box = p.locator("#jfCustNum")
    expect(num_box).to_have_value(str(num))
    assert p.evaluate("y => [...document.querySelectorAll('#jfGenericInputs input[readonly]')]"
                      ".some(e => e.value === y)", year), "the year isn't shown read-only"
    david.app.step(f"change the number {num} → {free} and the gate code")
    num_box.fill("")
    type_text(p, num_box, str(free))
    expect(p.locator("#jfCustNumWarn")).to_be_hidden()
    gate = p.locator("#jfGenericInputs [data-col-name='Gate Code / Access Notes']").first
    gate.fill("")
    type_text(p, gate, "gate 77")
    with _tool_response(p, "update_job_spreadsheet"):
        p.locator("#jobFormSaveBtn").click()
    p.wait_for_timeout(800)
    err = p.locator("#jobFormError")
    err_text = err.inner_text() if err.is_visible() else ""
    david.app.log(f"after Save: form open={p.locator('#jobFormModal').is_visible()} error={err_text!r}")
    renamed = _cust(owner_api, new_id)
    data._cust_id = new_id if renamed else cid
    assert renamed, f"{new_id} not in the database (error shown: {err_text!r})"
    assert _cust(owner_api, cid) is None, f"{cid} still exists next to {new_id}"
    assert _job(owner_api, jid).get("CustomerID (Customers!A)") == new_id, "the job didn't follow the rename"
    assert not err_text, f"Save showed an error after renumbering: {err_text!r}"
    expect(p.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    assert renamed.get("Gate Code / Access Notes") == "gate 77", "the other edit in the same Save was lost"


# ── SRV-CUST-02 ──────────────────────────────────────────────────────────────
def test_SRV_CUST_02_taken_number_is_refused_in_popup(windows, clean_slate, data, owner_api):
    cid = data.customer_id()
    other = _new_ztest_customer(owner_api, "CUST02 other")
    taken_num = other.rsplit("-", 1)[1]
    (david,) = windows("U1")
    david.log_in()
    _signed_in(david)
    _db_tab(david, "Customers")
    _db_open_edit(david, cid)
    p = david.page
    sent = []
    p.on("request", lambda r: sent.append(r.post_data or "") if "/pwa-api" in r.url else None)
    num_box = p.locator("#jfCustNum")
    num_box.fill("")
    type_text(p, num_box, taken_num)
    expect(p.locator("#jfCustNumWarn")).to_contain_text("already exists")
    david.app.step("tap Save with a taken number")
    p.locator("#jobFormSaveBtn").click()
    expect(p.locator("#jobFormError")).to_contain_text("Fix the customer number")
    p.wait_for_timeout(800)
    _close_form(p)
    assert not any("rename_customer" in s for s in sent), "a rename was sent anyway"
    assert _cust(owner_api, cid) and _cust(owner_api, other), "a customer id changed"


# ── SRV-CUST-03 ──────────────────────────────────────────────────────────────
def test_SRV_CUST_03_crew_cannot_renumber_a_customer(windows, crew_jobs, data, owner_api):
    cid = data.customer_id()
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    res = sam.app.mcp("rename_customer", {"customer_id": cid, "new_number": 9999})
    sam.app.log(f"Samual rename_customer → {str(res)[:160]!r}")
    assert _refused(res), f"field crew renumbered a customer: {res!r}"
    assert _cust(owner_api, cid), f"{cid} is gone"


# ── SRV-TAX-01 ───────────────────────────────────────────────────────────────
def test_SRV_TAX_01_weekly_tax_card_owner_only(windows):
    david, vicki, sam = windows("U1", "U2", "U3")
    for w in (david, vicki, sam):
        w.log_in()
        _signed_in(w)
    expect(sam.app.nav_button("reports")).to_be_hidden()
    for w in (david, vicki):
        w.app.goto("reports")
    expect(david.page.locator("#reportsContent")).to_contain_text("Weekly Tax Collected", timeout=30_000)
    expect(vicki.page.locator("#arAgingCard")).to_be_visible(timeout=20_000)
    vicki.page.wait_for_timeout(1500)
    expect(vicki.page.locator("#reportsOwnerOnly")).to_be_hidden()
    assert "Weekly Tax Collected" not in vicki.page.locator("#screen-reports").inner_text(), \
        "the manager sees the owner-only Weekly Tax card"


# ── SRV-TAX-02 ───────────────────────────────────────────────────────────────
def test_SRV_TAX_02_no_sales_tax_job_invoices_zero_tax(clean_slate, data, owner_api):
    done = {"Job Status": "Complete", "Quote Amount ($)": 100}
    exempt = data.job("TAX exempt", **{"No Sales Tax": 1}, **done)
    taxed = data.job("TAX taxed", "brannon", **done)
    assert str(_job(owner_api, exempt).get("No Sales Tax", "")).strip() in ("1", "True", "true", "Yes"), \
        _job(owner_api, exempt)
    inv_ex = owner_api.call("create_invoice", {"job_identifier": exempt, "quote_amount": 100, "tax_rate": 0.07})
    inv_tx = owner_api.call("create_invoice", {"job_identifier": taxed, "quote_amount": 100, "tax_rate": 0.07})
    assert re.search(r"Tax \(exempt\):\s*\$0\.00", inv_ex) and "$100.00" in inv_ex.split("TOTAL DUE:")[1][:20], inv_ex
    assert re.search(r"TOTAL DUE:\s*\$107\.00", inv_tx), inv_tx


# ── SRV-TAX-03 (R-084) ───────────────────────────────────────────────────────
def _reports_sandbox_week(w) -> dict:
    """The owner's Reports, 26 weeks each way: the Weekly Detail row of the
    sandbox date's week (Week of = its Monday, 'M/D')."""
    d = dt.date.fromisoformat(SANDBOX_DATE)
    mon = d - dt.timedelta(days=d.weekday())
    label = f"{mon.month}/{mon.day}"
    rows = w.page.locator("#reportsContent table tbody tr")
    expect(rows.first).to_be_visible(timeout=30_000)
    if rows.count() != 53:
        w.page.locator("#reportsWeeksSelect").select_option("26")
        expect(rows).to_have_count(53, timeout=30_000)
    row = rows.filter(has_text=re.compile(rf"^\s*{re.escape(label)}(?!\d)"))
    expect(row).to_have_count(1)
    cells = [c.strip() for c in row.locator("td").all_inner_texts()]
    num = lambda s: float(re.search(r"-?[\d,]*\.?\d+", s).group(0).replace(",", ""))
    keys = ["actual_rev", "proj_rev", "total_rev", "actual_tax", "proj_tax", "total_tax",
            "actual_hrs", "proj_hrs", "total_hrs"]
    return {k: num(v) for k, v in zip(keys, cells[1:10])}


def _reports_refresh(w):
    with w.page.expect_response(lambda r: "/pwa-api" in r.url and "read_job_spreadsheet" in (r.request.post_data or "")):
        w.page.locator("#refreshReportsBtn").click()
    expect(w.page.locator("#reportsContent table tbody tr")).to_have_count(53, timeout=30_000)


def test_SRV_TAX_03_invoice_tax_reaches_weekly_tax_collected(windows, clean_slate, data, owner_api):
    """R-084: Reports read the invoice tax under the wrong column name, so every
    invoice counted $0 tax. Owner's Reports: a Complete $100 job invoiced at 7% —
    unpaid → +$107 projected revenue / +$7 projected tax; paid → actual."""
    (david,) = windows("U1")
    david.log_in()
    _signed_in(david)
    david.app.goto("reports")
    before = _reports_sandbox_week(david)
    jid = data.job("TAX03 taxed", **{"Job Status": "Complete", "Quote Amount ($)": 100,
                                     "Est. Duration": 60, "Est. Duration Unit": "min",
                                     "Actual Duration": 60, "Actual Duration Unit": "min"})
    out = owner_api.call("create_invoice", {"job_identifier": jid, "quote_amount": 100, "tax_rate": 0.07})
    inv = re.search(r"INV-[\d-]*\d", out).group(0)
    david.app.log(f"REPORTS invoiced {jid} as {inv} at 7% — unpaid")
    _reports_refresh(david)
    mid = _reports_sandbox_week(david)
    d1 = {k: round(mid[k] - before[k], 2) for k in before}
    david.app.log(f"REPORTS sandbox-week change (unpaid): {d1}")
    assert (d1["actual_rev"], d1["proj_rev"], d1["actual_tax"], d1["proj_tax"]) == (0, 107, 0, 7), d1
    owner_api.call("update_job_spreadsheet", {"sheet_name": "Invoices", "id_column": "InvoiceID (INV-####)",
                                              "job_identifier": inv, "updates": {"Payment Status": "Paid"}})
    david.app.log(f"REPORTS {inv} recorded as Paid")
    _reports_refresh(david)
    after = _reports_sandbox_week(david)
    d2 = {k: round(after[k] - before[k], 2) for k in before}
    david.app.log(f"REPORTS sandbox-week change (paid): {d2}")
    assert (d2["actual_rev"], d2["proj_rev"], d2["actual_tax"], d2["proj_tax"], d2["actual_hrs"]) \
        == (107, 0, 7, 0, 1.0), d2


# ── SRV-PDAY-01 ──────────────────────────────────────────────────────────────
def test_SRV_PDAY_01_new_job_inherits_preferred_days(windows, clean_slate, data, owner_api):
    cid = data.customer_id()
    owner_api.call("update_job_spreadsheet", {"sheet_name": "Customers", "id_column": CUST_ID_COL,
                                              "job_identifier": cid,
                                              "updates": {"Preferred Day(s)": "Tuesday/Thursday"}})
    (david,) = windows("U1")
    david.log_in()
    _signed_in(david)
    _open_jobs(david)
    form = JobForm(david.page, david.app.log)
    form.open_new()
    expect(david.page.locator(f"#jfCustomer option[value='{cid}']")).to_have_count(1, timeout=15_000)
    form.customer(cid)
    david.page.locator("#jfCustomer").dispatch_event("change")
    checked = david.page.evaluate("() => [0,1,2,3,4,5,6].filter(i => document.getElementById('jfJobPrefDay_' + i).checked)")
    david.app.log(f"Preferred Day checkboxes ticked (0=Mon): {checked}")
    assert checked == [1, 3], f"expected Tuesday + Thursday ticked, got {checked}"
    d = dt.date.today()
    monday = d + dt.timedelta(days=(7 - d.weekday()) % 7 or 7)
    form.set("jfDate", monday.isoformat())
    david.page.locator("#jfDate").dispatch_event("change")
    expect(david.page.locator("#jfPrefDayMsg")).to_contain_text("Preferred day not met")
    expect(david.page.locator("#jfPrefDayMsg")).to_contain_text("Monday")
    _close_form(david.page)


# ── SRV-SCHED-10 (2026-10-07 Hard/Soft validation) ──────────────────────────
def test_SRV_SCHED_10_start_after_end_blocked_end_only_saves(windows, clean_slate, data, owner_api):
    cid = data.customer_id()
    (david,) = windows("U1")
    david.log_in()
    _signed_in(david)
    _open_jobs(david)
    p = david.page
    form = JobForm(p, david.app.log)
    form.open_new()
    expect(p.locator(f"#jfCustomer option[value='{cid}']")).to_have_count(1, timeout=15_000)
    form.customer(cid)
    p.locator("#jfCustomer").dispatch_event("change")
    form.set("jfDate", SANDBOX_DATE).choose("jfSchedType", "Soft")
    form.set("jfStart", "10:00").set("jfEnd", "09:00")
    form.save()
    expect(form.error()).to_contain_text("start time is after the end time")
    assert form.is_open(), "the form closed on an invalid window"
    before = {r.get(JOB_ID_COL) for r in owner_api.read("Jobs_Schedule")}
    david.app.step("clear the start — 'before 9:00' is valid")
    form.set("jfStart", "")
    form.save("create_job")
    expect(form.modal).to_be_hidden(timeout=20_000)
    new = [r for r in owner_api.read("Jobs_Schedule") if r.get(JOB_ID_COL) not in before]
    assert len(new) == 1, f"expected exactly one new job, got {[r.get(JOB_ID_COL) for r in new]}"
    assert not new[0].get("Start Time") and new[0].get("End Time"), new[0]
