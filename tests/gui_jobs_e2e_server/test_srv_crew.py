"""Server mode — field crew restrictions (spec §6.11.5 SRV-SCOPE / G-gaps).
U3 = Samual Cronin (field_crew); U1 = David (owner) for comparison.
Test jobs are created by the owner: one assigned to Samual, one to Vicki.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_crew
"""
import pytest
from playwright.sync_api import expect

CREW = "Samual Cronin"
OTHER = "Vicki Vavro"
LOCKED_SHEETS = ["Invoices", "Quotes", "Services_Pricing", "Settings"]


def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


def _refused(res) -> bool:
    return isinstance(res, str) and res.lstrip().startswith("❌")


def _job(owner_api, jid):
    return next(r for r in owner_api.read("Jobs_Schedule") if r.get("JobID (JOB-####)") == jid)


@pytest.fixture
def two_jobs(clean_slate, data, owner_api):
    """{'mine': JOB id assigned to Samual, 'theirs': JOB id assigned to Vicki}."""
    mine = data.job("CREW mine", **{"Crew / Technician": CREW, "Quote Amount ($)": 120})
    theirs = data.job("CREW theirs", "brannon", **{"Crew / Technician": OTHER, "Quote Amount ($)": 150})
    return {"mine": mine, "theirs": theirs,
            "mine_name": _job(owner_api, mine)["Customer Name / Company"],
            "theirs_name": _job(owner_api, theirs)["Customer Name / Company"]}


# ── SRV-CREW-01: only my own jobs ─────────────────────────────────────────────
def test_SRV_CREW_01_crew_sees_only_own_jobs(windows, two_jobs):
    sam, david = windows("U3", "U1")
    sam.log_in()
    david.log_in()
    _signed_in(sam)
    _signed_in(david)
    for w in (sam, david):
        w.app.goto("jobs")
        w.page.evaluate("async () => { await loadJobs(); }")
        w.page.wait_for_timeout(800)
    # Both test jobs belong to the same test customer, so compare the JOB IDs
    # the Jobs screen actually loaded (what its cards are drawn from).
    ids = lambda w: w.page.evaluate("() => (state.jobs || []).map(j => String(j.id))")   # app's own job objects: id, customer, custId, type…
    sam_ids, david_ids = ids(sam), ids(david)
    sam.app.log(f"Samual's Jobs screen: {sam_ids} | David's: {david_ids}")
    assert two_jobs["mine"] in sam_ids, f"Samual doesn't see his own job: {sam_ids}"
    assert two_jobs["theirs"] not in sam_ids, f"Samual sees Vicki's job: {sam_ids}"
    assert two_jobs["mine"] in david_ids and two_jobs["theirs"] in david_ids, f"owner missing a job: {david_ids}"
    expect(sam.page.locator("#screen-jobs")).to_contain_text(two_jobs["mine_name"])
    # the data behind the screen, as Samual's own session
    res = sam.app.mcp("read_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "max_rows": 200})
    assert two_jobs["mine"] in res and two_jobs["theirs"] not in res, f"crew read leaked: {res[:200]!r}"


# ── SRV-CREW-02: can change my job, not someone else's ────────────────────────
def test_SRV_CREW_02_crew_can_edit_own_job_not_others(windows, two_jobs, owner_api):
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    ok = sam.app.mcp("update_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "id_column": "JobID (JOB-####)",
                                                "job_identifier": two_jobs["mine"],
                                                "updates": {"Service Details / Notes": "crew note on my job"}})
    assert not _refused(ok), f"crew couldn't update their own job: {ok!r}"
    assert _job(owner_api, two_jobs["mine"])["Service Details / Notes"] == "crew note on my job"
    no = sam.app.mcp("update_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "id_column": "JobID (JOB-####)",
                                                "job_identifier": two_jobs["theirs"],
                                                "updates": {"Service Details / Notes": "crew was here"}})
    assert _refused(no), f"crew changed another crew's job: {no!r}"
    assert _job(owner_api, two_jobs["theirs"]).get("Service Details / Notes", "") != "crew was here"


# ── SRV-CREW-03: no Reports ───────────────────────────────────────────────────
def test_SRV_CREW_03_no_reports_for_crew(windows):
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    expect(sam.page.get_by_test_id("nav-reports")).to_be_hidden()
    sam.app.goto("profile")
    expect(sam.page.locator("#profileRole")).to_have_text("field_crew")
    assert _refused(sam.app.mcp("find_stale_customers", {"days_threshold": 0})), "crew got Reports data"


# ── SRV-CREW-04: Invoices / Quotes / Pricing / Settings refused ───────────────
def test_SRV_CREW_04_locked_sheets_refused_for_crew(windows):
    sam, david = windows("U3", "U1")
    sam.log_in()
    david.log_in()
    _signed_in(sam)
    _signed_in(david)
    for sheet in LOCKED_SHEETS:
        theirs = sam.app.mcp("read_job_spreadsheet", {"sheet_name": sheet, "max_rows": 5})
        mine = david.app.mcp("read_job_spreadsheet", {"sheet_name": sheet, "max_rows": 5})
        assert _refused(theirs), f"crew could read {sheet}: {str(theirs)[:120]!r}"
        assert not _refused(mine), f"owner was refused {sheet}: {str(mine)[:120]!r}"
    # the Database screen shouldn't offer tabs the crew can't open
    sam.app.goto("sheet")
    sam.page.wait_for_timeout(1200)
    tabs = sam.page.locator("#sheetTabs").inner_text()
    offered = [s for s in ("Invoices", "Quotes", "Pricing", "Settings") if s.lower() in tabs.lower()]
    assert not offered, f"Database screen offers the crew tabs they're refused: {offered} (tabs: {tabs!r})"


# ── SRV-CREW-05: my customer — gate code yes, pricing / status no ─────────────
def test_SRV_CREW_05_crew_customer_fields(windows, two_jobs, owner_api):
    cust = _job(owner_api, two_jobs["mine"])["CustomerID (Customers!A)"]
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    upd = lambda fields: sam.app.mcp("update_job_spreadsheet", {
        "sheet_name": "Customers", "id_column": "CustomerID (CUST-####)", "job_identifier": cust, "updates": fields})
    ok = upd({"Gate Code / Access Notes": "gate 4321"})
    assert not _refused(ok), f"crew couldn't set the gate code on their own customer: {ok!r}"
    for field, value in (("Standard Quote ($)", "1"), ("Status Active/Inactive", "Inactive")):
        res = upd({field: value})
        assert _refused(res), f"crew changed {field!r} on a customer: {res!r}"
    row = next(r for r in owner_api.read("Customers") if r.get("CustomerID (CUST-####)") == cust)
    assert row["Gate Code / Access Notes"] == "gate 4321"
    assert row.get("Status Active/Inactive", "") != "Inactive"


# ── SRV-CREW-06: no invoicing someone else's job ─────────────────────────────
def test_SRV_CREW_06_crew_cannot_invoice_others_job(windows, two_jobs, owner_api):
    (sam,) = windows("U3")
    sam.log_in()
    _signed_in(sam)
    res = sam.app.mcp("create_invoice", {"job_identifier": two_jobs["theirs"], "quote_amount": 150, "tax_rate": 0})
    assert _refused(res), f"crew invoiced another crew's job: {res!r}"
    assert not _job(owner_api, two_jobs["theirs"]).get("InvoiceID (INV-####)"), "an invoice was attached anyway"
