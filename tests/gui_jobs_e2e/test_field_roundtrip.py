"""Personal mode (owner) — every editable Job and Customer field really
changes, is stored, and shows in the Jobs app (2026-10-09).

  FR-01  Job form: every field → value set A → Save → database has A →
         reopened form shows A; then every field → B (changing set values).
  FR-02  Customer editor (Database → Customers → Edit): every editable field
         A then B, checked in the database and the reopened editor.
  FR-03  AI path: Claude's MCP tools (update_job_spreadsheet, create_job,
         pause_job) over the local /mcp with the owner's token change a job
         and a customer → the Jobs app shows exactly those values.

The server-mode twin (3 users) is gui_jobs_e2e_server/test_srv_field_roundtrip.py.
Run: run_tests_gui_jobs_e2e.bat --human -k test_field_roundtrip
"""
import pytest
from playwright.sync_api import expect

from ai_client import AiClient
from api import local_api_origin
from app_jobs import JobForm
from fields import (CUST_KIND, CUST_SET_A, CUST_SET_AI, CUST_SET_B, JOB_KIND, JOB_SET_A,
                    JOB_SET_AI, JOB_SET_B, compare, fill_customer_form, fill_job_form,
                    read_customer_form, read_job_form, set_job_crew)

CUST_ID_COL = "CustomerID (CUST-####)"
JOB_ID_COL = "JobID (JOB-####)"
CREW_A, CREW_B = "ZTEST Crew A", "ZTEST Crew B"


def _job(api, jid):
    return next((r for r in api.read("Jobs_Schedule") if r.get(JOB_ID_COL) == jid), None)


def _cust(api, cid):
    return next((r for r in api.read("Customers") if r.get(CUST_ID_COL) == cid), None)


def _open_jobs(app, page):
    app.goto("jobs")
    page.evaluate("async () => { await loadJobs(); }")
    page.wait_for_timeout(600)


def _close_form(page):
    if page.locator("#jobFormModal").is_visible():
        page.evaluate("closeJobFormModal()")


def _db_tab_customers(app, page):
    app.goto("sheet")
    expect(page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    page.locator("#sheetTabs .sheet-tab-btn[data-sheet='Customers']").click()
    expect(page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    page.wait_for_timeout(400)


def _open_customer_edit(app, page, cid):
    btn = page.locator(f".sheet-row-edit-btn[data-rowid='{cid}']")
    if not btn.count() and page.locator("#showInactiveBtn").is_visible():
        app.step("tap Show Inactive (the customer was set Inactive)")
        page.locator("#showInactiveBtn").click()
        expect(page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    btn.scroll_into_view_if_needed()
    btn.click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jfGenericInputs .spinner")).to_have_count(0, timeout=20_000)


def _save_customer_form(page) -> str:
    with page.expect_response(lambda r: "/pwa-api" in r.url and "update_job_spreadsheet" in (r.request.post_data or ""),
                              timeout=30_000):
        page.locator("#jobFormSaveBtn").click()
    page.wait_for_timeout(800)
    err = page.locator("#jobFormError")
    return err.inner_text() if err.is_visible() else ""


# ── FR-01 job form, every field, A then B ────────────────────────────────────
def test_FR_01_job_form_every_field_changes_and_is_stored(clean_slate, app, page, api, data):
    jid = data.job("FR01 owner")
    form = JobForm(page, app.log)
    for label, values, crew in (("A", JOB_SET_A, CREW_A), ("B", JOB_SET_B, CREW_B)):
        _open_jobs(app, page)
        form.open_edit(jid)
        app.step(f"set every job field to value set {label}")
        fill_job_form(page, values, app.log)
        set_job_crew(page, crew, server=False, log=app.log)
        form.save("update_job_spreadsheet")
        err = form.error()
        if err.is_visible():
            pytest.fail(f"set {label}: the job form refused the save: {err.inner_text()!r}")
        expect(form.modal).to_be_hidden(timeout=20_000)
        want = dict(values, **{"Crew / Technician": crew})
        bad = compare(want, _job(api, jid), JOB_KIND)
        assert not bad, f"set {label} — stored values wrong:\n  " + "\n  ".join(bad)
        _open_jobs(app, page)
        form.open_edit(jid)
        shown = read_job_form(page)
        _close_form(page)
        # Preferred Day(s) on the reopened form = R-083, checked alone by FR-06
        bad = compare({c: v for c, v in want.items() if c != "Preferred Day(s)"}, shown, JOB_KIND)
        app.log(f"set {label}: reopened-form differences {bad or 'none'}")
        assert not bad, f"set {label} — the reopened form shows:\n  " + "\n  ".join(bad)


# ── FR-02 customer editor, every field, A then B ─────────────────────────────
def test_FR_02_customer_editor_every_field_changes_and_is_stored(clean_slate, app, page, api, data):
    cid = data.customer_id()
    data.job("FR02 owner")
    for label, values in (("A", CUST_SET_A), ("B", CUST_SET_B)):
        _db_tab_customers(app, page)
        _open_customer_edit(app, page, cid)
        app.step(f"set every customer field to value set {label}")
        fill_customer_form(page, values, app.log)
        err = _save_customer_form(page)
        _close_form(page)
        assert not err, f"set {label} — the customer editor refused the save: {err!r}"
        bad = compare(values, _cust(api, cid), CUST_KIND)
        assert not bad, f"set {label} — stored customer values wrong:\n  " + "\n  ".join(bad)
        _db_tab_customers(app, page)
        _open_customer_edit(app, page, cid)
        shown = read_customer_form(page)
        _close_form(page)
        bad = compare(values, shown, CUST_KIND)
        assert not bad, f"set {label} — the reopened editor shows:\n  " + "\n  ".join(bad)


# ── FR-04 nothing LOOKS editable that can't be saved (R-081 / R-082) ─────────
def test_FR_04_read_only_fields_look_read_only(clean_slate, app, page, api, data):
    jid = data.job("FR04 owner")
    cid = data.customer_id()
    api.call("update_job_spreadsheet", {"sheet_name": "Customers", "id_column": CUST_ID_COL,
                                        "job_identifier": cid, "updates": {"Customer Type Comm/Res": "Commercial"}})
    _open_jobs(app, page)
    JobForm(page, app.log).open_edit(jid)
    ct = page.locator("#jfCustomerType")
    expect(ct).to_be_disabled()                     # a job's type is its customer's
    expect(ct).to_have_value("Commercial")
    _close_form(page)
    _db_tab_customers(app, page)
    _open_customer_edit(app, page, cid)
    expect(page.locator("#jfGenericInputs [data-col-name='Last Service Date']")).to_have_count(0)
    expect(page.locator("#jfGenericInputs")).to_contain_text("Last Service Date")
    _close_form(page)


# ── FR-06 an unrelated edit must not wipe Preferred Day(s) (R-083) ───────────
def test_FR_06_edit_keeps_preferred_days(clean_slate, app, page, api, data):
    jid = data.job("FR06 owner", **{"Preferred Day(s)": "Tuesday/Friday"})
    _open_jobs(app, page)
    form = JobForm(page, app.log)
    form.open_edit(jid)
    shown = read_job_form(page)
    form.text("jfNotes", "FR06 only the notes changed")
    form.save("update_job_spreadsheet")
    expect(form.modal).to_be_hidden(timeout=20_000)
    stored = _job(api, jid)
    app.log(f"FR06 form showed {shown.get('Preferred Day(s)')!r}; stored after Save {stored.get('Preferred Day(s)')!r}")
    assert stored.get("Service Details / Notes") == "FR06 only the notes changed"
    assert compare({"Preferred Day(s)": "Tuesday/Friday"}, shown, JOB_KIND) == [], "Edit form opened without the days"
    assert compare({"Preferred Day(s)": "Tuesday/Friday"}, stored, JOB_KIND) == [], "a notes-only Save wiped the days"


# ── FR-03 the AI path, then the app ──────────────────────────────────────────
def test_FR_03_ai_changes_show_in_the_app(clean_slate, app, page, api, data, guard, token):
    ai = AiClient(local_api_origin(), token, guard, "owner")
    jid = data.job("FR03 owner")
    cid = data.customer_id()

    ai.call("update_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "id_column": JOB_ID_COL,
                                       "job_identifier": jid, "updates": JOB_SET_AI})
    bad = compare(JOB_SET_AI, _job(api, jid), JOB_KIND)
    assert not bad, "AI: stored job values wrong:\n  " + "\n  ".join(bad)

    ai.call("update_job_spreadsheet", {"sheet_name": "Customers", "id_column": CUST_ID_COL,
                                       "job_identifier": cid, "updates": CUST_SET_AI})
    bad = compare(CUST_SET_AI, _cust(api, cid), CUST_KIND)
    assert not bad, "AI: stored customer values wrong:\n  " + "\n  ".join(bad)

    out = ai.call("create_job", {"updates": {"CustomerID": cid, "Customer Name / Company": "ZTEST E2E FR03 AI new",
                                             "Service Date": JOB_SET_AI["Service Date"], "Service Type": "Window"}})
    new_jid = out.split("NEW_JOB_ID=")[1].split()[0]
    ai.call("pause_job", {"job_id": new_jid, "paused": True, "reason": "AI pause"})

    _open_jobs(app, page)
    form = JobForm(page, app.log)
    form.open_edit(jid)
    shown = read_job_form(page)
    _close_form(page)
    bad = compare({c: v for c, v in JOB_SET_AI.items() if c != "Preferred Day(s)"}, shown, JOB_KIND)   # R-083: FR-06
    assert not bad, "the job form doesn't show what Claude set:\n  " + "\n  ".join(bad)
    page.locator("#jobsViewStatusBtn").click()
    card = page.locator(f"[data-testid='job-card'][data-jobid='{new_jid}']")
    expect(card).to_be_visible(timeout=20_000)
    expect(card).to_contain_text("Paused — AI pause")
    _db_tab_customers(app, page)
    _open_customer_edit(app, page, cid)
    shown = read_customer_form(page)
    _close_form(page)
    bad = compare(CUST_SET_AI, shown, CUST_KIND)
    assert not bad, "the customer editor doesn't show what Claude set:\n  " + "\n  ".join(bad)
