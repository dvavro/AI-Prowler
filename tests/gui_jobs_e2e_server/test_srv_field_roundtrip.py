"""Server mode — every editable Job and Customer field really changes, is
stored, and shows in the Jobs app — for EACH of the 3 users (2026-10-09).

  SRV-FR-01  Job form: every field → value A → Save → database has A → form
             shows A; then every field → B (changing a set value) → same.
             Samual (field crew) does it on his own job, billing fields and
             No Sales Tax included (David: billing fields are NOT locked for
             crew).
  SRV-FR-02  Customer editor (Database → Customers → Edit): every editable
             field A then B. Samual may change everything except the four
             business fields (Frequency, Standard Quote, Discount, Status) —
             an unchanged one in the same Save must not block his edit, a
             changed one must be refused with nothing written.
  SRV-FR-03  AI path: Claude's MCP tools (update_job_spreadsheet,
             create_job, pause_job), called over /mcp with the user's own
             token, change a job and a customer → the Jobs app shows exactly
             those values. Samual's AI is refused on someone else's job.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_field_roundtrip
"""
import pytest
from playwright.sync_api import expect

from ai_client import AiClient, AiError
from app_jobs import JobForm
from fields import (CREW_LOCKED_CUSTOMER, CUST_KIND, CUST_SET_A, CUST_SET_AI, CUST_SET_B,
                    JOB_KIND, JOB_SET_A, JOB_SET_AI, JOB_SET_B, compare, fill_customer_form,
                    fill_job_form, read_customer_form, read_job_form, set_job_crew)

OWNER, MANAGER, CREW = "David Vavro", "Vicki Vavro", "Samual Cronin"
NAME = {"U1": OWNER, "U2": MANAGER, "U3": CREW}
CUST_ID_COL = "CustomerID (CUST-####)"
JOB_ID_COL = "JobID (JOB-####)"
USERS = ["U1", "U2", "U3"]


# ── helpers ──────────────────────────────────────────────────────────────────
def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


def _job(api, jid):
    return next((r for r in api.read("Jobs_Schedule") if r.get(JOB_ID_COL) == jid), None)


def _cust(api, cid):
    return next((r for r in api.read("Customers") if r.get(CUST_ID_COL) == cid), None)


def _crew_sets(key):
    """(crew A, crew B). Field crew must stay on their own job."""
    if key == "U3":
        return [CREW], [CREW]
    return [MANAGER], [CREW, MANAGER]


def _open_jobs(w):
    w.app.goto("jobs")
    w.page.evaluate("async () => { await loadJobs(); }")
    w.page.wait_for_timeout(600)


def _save_job_form(w, form):
    form.save("update_job_spreadsheet")
    err = form.error()
    if err.is_visible():
        pytest.fail(f"{w.user.name}: the job form refused the save: {err.inner_text()!r}")
    expect(form.modal).to_be_hidden(timeout=20_000)


def _db_tab_customers(w):
    w.app.goto("sheet")
    expect(w.page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    w.page.locator("#sheetTabs .sheet-tab-btn[data-sheet='Customers']").click()
    expect(w.page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    w.page.wait_for_timeout(400)


def _open_customer_edit(w, cid):
    btn = w.page.locator(f".sheet-row-edit-btn[data-rowid='{cid}']")
    if not btn.count() and w.page.locator("#showInactiveBtn").is_visible():
        w.app.step("tap Show Inactive (the customer was set Inactive)")
        w.page.locator("#showInactiveBtn").click()
        expect(w.page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    btn.scroll_into_view_if_needed()
    btn.click()
    expect(w.page.locator("#jobFormModal")).to_be_visible()
    expect(w.page.locator("#jfGenericInputs .spinner")).to_have_count(0, timeout=20_000)


def _save_customer_form(w) -> str:
    """Tap Save; return the error text shown ('' when it saved)."""
    p = w.page
    with p.expect_response(lambda r: "/pwa-api" in r.url and "update_job_spreadsheet" in (r.request.post_data or ""),
                           timeout=30_000):
        p.locator("#jobFormSaveBtn").click()
    p.wait_for_timeout(800)
    err = p.locator("#jobFormError")
    return err.inner_text() if err.is_visible() else ""


def _close_form(page):
    if page.locator("#jobFormModal").is_visible():
        page.evaluate("closeJobFormModal()")


# ── SRV-FR-01 job form, every field, A then B ────────────────────────────────
@pytest.mark.parametrize("key", USERS)
def test_SRV_FR_01_job_form_every_field_changes_and_is_stored(windows, clean_slate, data, owner_api, key):
    crew_a, crew_b = _crew_sets(key)
    jid = data.job(f"FR01 {key}", **{"Crew / Technician": CREW if key == "U3" else OWNER})
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    form = JobForm(w.page, w.app.log)
    for label, values, crew in (("A", JOB_SET_A, crew_a), ("B", JOB_SET_B, crew_b)):
        _open_jobs(w)
        form.open_edit(jid)
        w.app.step(f"set every job field to value set {label}")
        fill_job_form(w.page, values, w.app.log)
        set_job_crew(w.page, crew, server=True, log=w.app.log)
        _save_job_form(w, form)
        want = dict(values, **{"Crew / Technician": ", ".join(crew)})
        stored = _job(owner_api, jid)
        bad = compare(want, stored, JOB_KIND)
        w.app.log(f"set {label}: database differences {bad or 'none'}")
        assert not bad, f"{w.user.name} set {label} — stored values wrong:\n  " + "\n  ".join(bad)
        _open_jobs(w)
        form.open_edit(jid)
        shown = read_job_form(w.page)
        _close_form(w.page)
        # Preferred Day(s) on the REOPENED form is R-083 (open until deployed) —
        # checked on its own by SRV-FR-06 so it can't hide other regressions here.
        bad = compare({c: v for c, v in want.items() if c != "Preferred Day(s)"}, shown, JOB_KIND)
        w.app.log(f"set {label}: reopened-form differences {bad or 'none'}")
        assert not bad, f"{w.user.name} set {label} — the reopened form shows:\n  " + "\n  ".join(bad)


# ── SRV-FR-02 customer editor, every field, A then B ─────────────────────────
# R-078 (found here 2026-10-09): the editor sends every column, and the server
# refused ANY crew save that merely included a business field — so Samual
# could not even fix a phone number. Fixed in db_write_ops (unchanged locked
# values are allowed); deployed to the server 2026-10-09.


@pytest.mark.parametrize("key", USERS)
def test_SRV_FR_02_customer_editor_every_field_changes_and_is_stored(windows, clean_slate, data, owner_api, key):
    cid = data.customer_id()
    data.job(f"FR02 {key}", **{"Crew / Technician": CREW})       # puts the customer in Samual's scope
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    crew = key == "U3"
    for label, values in (("A", CUST_SET_A), ("B", CUST_SET_B)):
        if crew:
            values = {c: v for c, v in values.items() if c not in CREW_LOCKED_CUSTOMER}
        _db_tab_customers(w)
        _open_customer_edit(w, cid)
        w.app.step(f"set every customer field to value set {label}")
        fill_customer_form(w.page, values, w.app.log)
        err = _save_customer_form(w)
        _close_form(w.page)
        assert not err, f"{w.user.name} set {label} — the customer editor refused the save: {err!r}"
        stored = _cust(owner_api, cid)
        bad = compare(values, stored, CUST_KIND)
        assert not bad, f"{w.user.name} set {label} — stored customer values wrong:\n  " + "\n  ".join(bad)
        _db_tab_customers(w)
        _open_customer_edit(w, cid)
        shown = read_customer_form(w.page)
        _close_form(w.page)
        bad = compare(values, shown, CUST_KIND)
        assert not bad, f"{w.user.name} set {label} — the reopened editor shows:\n  " + "\n  ".join(bad)
    if crew:
        before = _cust(owner_api, cid)
        _db_tab_customers(w)
        _open_customer_edit(w, cid)
        w.app.step("crew tries to change a business field (Standard Quote)")
        fill_customer_form(w.page, {"Standard Quote ($)": "999"}, w.app.log)
        err = _save_customer_form(w)
        _close_form(w.page)
        assert err, "field crew changed Standard Quote ($) on a customer"
        assert _cust(owner_api, cid).get("Standard Quote ($)") == before.get("Standard Quote ($)")


# ── SRV-FR-04 nothing LOOKS editable that can't be saved ─────────────────────
# Found 2026-10-09 by FR-01/FR-02: two controls looked editable but the server
# always threw the value away — a job's Customer Type (owned by the customer,
# spec §13 Case B → R-081) and a customer's Last Service Date (computed from
# the last completed job → R-082). Both now show read-only (deployed 2026-10-09).


@pytest.mark.parametrize("key", USERS)
def test_SRV_FR_04_read_only_fields_look_read_only(windows, clean_slate, data, owner_api, key):
    jid = data.job(f"FR04 {key}", **{"Crew / Technician": CREW})
    cid = data.customer_id()
    owner_api.call("update_job_spreadsheet", {"sheet_name": "Customers", "id_column": CUST_ID_COL,
                                              "job_identifier": cid, "updates": {"Customer Type Comm/Res": "Commercial"}})
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    _open_jobs(w)
    form = JobForm(w.page, w.app.log)
    form.open_edit(jid)
    ct = w.page.locator("#jfCustomerType")
    expect(ct).to_be_disabled()
    expect(ct).to_have_value("Commercial")          # the customer's own type
    _close_form(w.page)
    _db_tab_customers(w)
    _open_customer_edit(w, cid)
    # read-only columns render as plain text, not as an input
    expect(w.page.locator("#jfGenericInputs [data-col-name='Last Service Date']")).to_have_count(0)
    expect(w.page.locator("#jfGenericInputs")).to_contain_text("Last Service Date")
    _close_form(w.page)


# ── SRV-FR-05 moving a job to another customer ───────────────────────────────
@pytest.mark.parametrize("key", ["U1", "U2"])
def test_SRV_FR_05_change_a_jobs_customer(windows, clean_slate, data, owner_api, key):
    jid = data.job(f"FR05 {key}", **{"Crew / Technician": OWNER})
    out = owner_api.call("create_customer", {"updates": {
        "Company Name": "ZTEST E2E FR05 Other", "Customer Type Comm/Res": "Commercial",
        "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168", "Status Active/Inactive": "Active"}})
    other = out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    _open_jobs(w)
    form = JobForm(w.page, w.app.log)
    form.open_edit(jid)
    form.customer(other)
    w.page.locator("#jfCustomer").dispatch_event("change")
    _save_job_form(w, form)
    row = _job(owner_api, jid)
    got = (row.get("CustomerID (Customers!A)") or row.get("CustomerID") or "", row.get("Customer Name / Company"))
    assert got == (other, "ZTEST E2E FR05 Other"), f"{w.user.name}: after changing the customer the job has {got}"
    _open_jobs(w)
    form.open_edit(jid)
    expect(w.page.locator("#jfCustomer")).to_have_value(other)
    _close_form(w.page)


# ── SRV-FR-06 an unrelated edit must not wipe Preferred Day(s) (R-083) ─────────
# Found 2026-10-09 by FR-01/FR-03 (all 3 users): the Edit form opened with no
# Preferred Day(s) ticked, so saving ANY change cleared the job's stored days.
# Fix deployed to the server 2026-10-09.
@pytest.mark.parametrize("key", USERS)
def test_SRV_FR_06_edit_keeps_preferred_days(windows, clean_slate, data, owner_api, key):
    jid = data.job(f"FR06 {key}", **{"Crew / Technician": CREW if key == "U3" else OWNER,
                                      "Preferred Day(s)": "Tuesday/Friday"})
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    _open_jobs(w)
    form = JobForm(w.page, w.app.log)
    form.open_edit(jid)
    shown = read_job_form(w.page)
    w.app.log(f"FR06 form opens with Preferred Day(s) = {shown.get('Preferred Day(s)')!r}")
    form.text("jfNotes", "FR06 only the notes changed")
    _save_job_form(w, form)
    stored = _job(owner_api, jid)
    w.app.log(f"FR06 after a notes-only Save, stored Preferred Day(s) = {stored.get('Preferred Day(s)')!r}")
    assert stored.get("Service Details / Notes") == "FR06 only the notes changed"
    assert compare({"Preferred Day(s)": "Tuesday/Friday"}, shown, JOB_KIND) == [], \
        f"{w.user.name}: the Edit form opened without the job's Preferred Day(s): {shown.get('Preferred Day(s)')!r}"
    assert compare({"Preferred Day(s)": "Tuesday/Friday"}, stored, JOB_KIND) == [], \
        f"{w.user.name}: changing only the notes wiped Preferred Day(s): now {stored.get('Preferred Day(s)')!r}"


# ── SRV-FR-03 the AI path, then the app ──────────────────────────────────────
@pytest.mark.parametrize("key", USERS)
def test_SRV_FR_03_ai_changes_show_in_the_app(windows, clean_slate, data, owner_api, srv, guard, key):
    u = srv["users"][key]
    ai = AiClient(srv["origin"], u.token, guard, key)
    crew_job = CREW if key == "U3" else OWNER
    jid = data.job(f"FR03 {key}", **{"Crew / Technician": crew_job})
    cid = data.customer_id()
    w_crew = [crew_job]

    # 1. Claude updates every job field in one call (what "update this job" does)
    ai.call("update_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "id_column": JOB_ID_COL,
                                       "job_identifier": jid, "updates": JOB_SET_AI})
    want_job = dict(JOB_SET_AI, **{"Crew / Technician": ", ".join(w_crew)})
    bad = compare(want_job, _job(owner_api, jid), JOB_KIND)
    assert not bad, f"AI as {u.name}: stored job values wrong:\n  " + "\n  ".join(bad)

    # 2. Claude updates the customer (crew: everything but the business fields)
    cust_vals = {c: v for c, v in CUST_SET_AI.items() if key != "U3" or c not in CREW_LOCKED_CUSTOMER}
    ai.call("update_job_spreadsheet", {"sheet_name": "Customers", "id_column": CUST_ID_COL,
                                       "job_identifier": cid, "updates": cust_vals})
    bad = compare(cust_vals, _cust(owner_api, cid), CUST_KIND)
    assert not bad, f"AI as {u.name}: stored customer values wrong:\n  " + "\n  ".join(bad)

    # 3. Claude creates a job and pauses it
    out = ai.call("create_job", {"updates": {"CustomerID": cid, "Customer Name / Company": "ZTEST E2E FR03 AI new",
                                             "Service Date": JOB_SET_AI["Service Date"],
                                             "Crew / Technician": crew_job, "Service Type": "Window"}})
    new_jid = out.split("NEW_JOB_ID=")[1].split()[0]
    ai.call("pause_job", {"job_id": new_jid, "paused": True, "reason": "AI pause"})

    # 4. the Jobs app shows all of it
    (w,) = windows(key)
    w.log_in()
    _signed_in(w)
    _open_jobs(w)
    form = JobForm(w.page, w.app.log)
    form.open_edit(jid)
    shown = read_job_form(w.page)
    _close_form(w.page)
    bad = compare({c: v for c, v in want_job.items() if c != "Preferred Day(s)"}, shown, JOB_KIND)   # R-083: FR-06
    assert not bad, f"{u.name}: the job form doesn't show what Claude set:\n  " + "\n  ".join(bad)
    w.page.locator("#jobsViewStatusBtn").click()
    card = w.page.locator(f"[data-testid='job-card'][data-jobid='{new_jid}']")
    expect(card).to_be_visible(timeout=20_000)
    expect(card).to_contain_text("Paused — AI pause")
    _db_tab_customers(w)
    _open_customer_edit(w, cid)
    shown = read_customer_form(w.page)
    _close_form(w.page)
    bad = compare(cust_vals, shown, CUST_KIND)
    assert not bad, f"{u.name}: the customer editor doesn't show what Claude set:\n  " + "\n  ".join(bad)

    # 5. field crew's AI can't touch someone else's job
    if key == "U3":
        other = data.job("FR03 other crew", "brannon", **{"Crew / Technician": MANAGER})
        with pytest.raises(AiError):
            ai.call("update_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "id_column": JOB_ID_COL,
                                               "job_identifier": other, "updates": {"No Sales Tax": "1"}})
        assert _job(owner_api, other).get("No Sales Tax", "0") in ("", "0", "0.0", "False", "false")
