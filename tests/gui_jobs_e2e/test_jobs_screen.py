"""Jobs screen (spec §6.3) — the Add / Edit Job form used the way a person
uses it: tap + Add, pick the customer, type the address and details, pick
Hard/Soft and times, Save; open a job, ✏️ Edit Job, change it, Save.
Every change is checked on screen AND in the database.

Run: run_tests_gui_jobs_e2e.bat --human -k jobs_screen
"""
import re
import time

import pytest
from playwright.sync_api import expect

from api import iso_date
from app_jobs import JobForm
from safety import SANDBOX_DATE, sandbox_day

JOB_ID = "JobID (JOB-####)"


def _job_with_note(api, token):
    for j in api.read("Jobs_Schedule"):
        if token in (j.get("Service Details / Notes") or j.get("Notes") or ""):
            return j
    return None


def _job(api, jid):
    for j in api.read("Jobs_Schedule"):
        if j.get(JOB_ID) == jid:
            return j
    return None


@pytest.fixture
def form(clean_slate, app, page, data):
    data.customer_id()                     # the ZTEST customer must exist before the form lists customers
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("jobs")
    return JobForm(page, app.log)


def _fill_new(form, data, token, *, sched="Soft", start="08:00", end="17:00", dur="45"):
    form.open_new()
    form.customer(data.customer_id())
    form.text("jfAddress", "210 Sams Ave").text("jfCity", "New Smyrna Beach")
    form.text("jfState", "FL").text("jfZip", "32168")
    form.set("jfDate", SANDBOX_DATE)
    form.choose("jfSchedType", sched)
    form.set("jfStart", start)
    if sched == "Soft":
        form.set("jfEnd", end)
    form.set("jfDuration", dur)
    form.text("jfService", "Window")
    form.text("jfNotes", f"E2E {token}")
    return form


# ── JOBS-01: cards ───────────────────────────────────────────────────────────
def test_JOBS_01_todays_jobs_show_as_cards(clean_slate, app, page, data):
    ids = [data.job("JOBS01 A", "city_hall"), data.job("JOBS01 B", "brannon")]
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("jobs")
    for jid in ids:
        card = page.locator(f"[data-testid='job-card'][data-jobid='{jid}']")
        expect(card).to_be_visible()
        expect(card).to_contain_text(jid)
        expect(card).to_contain_text("Scheduled")


# JOBS-02 (tap a card -> the job opens) is test_BTN_JOBS_job_card_opens_the_job.


# ── JOBS-03: create a job through the form ───────────────────────────────────
def test_JOBS_03_create_a_job_through_the_form(form, api, data, page):
    token = f"J03-{int(time.time())}"
    _fill_new(form, data, token).save("create_job")
    expect(form.modal).to_be_hidden()
    j = _job_with_note(api, token)
    assert j, "the new job isn't in the database"
    jid = j[JOB_ID]
    form.guard_note = jid
    assert j.get("Street Address") == "210 Sams Ave"
    assert iso_date(j.get("Service Date", "")) == SANDBOX_DATE
    assert j.get("Schedule Type (Hard/Soft)") == "Soft"
    assert j.get("Job Status") == "Scheduled"
    expect(page.locator(f"[data-testid='job-card'][data-jobid='{jid}']")).to_be_visible(timeout=15_000)


# ── validation (nothing may be saved) ────────────────────────────────────────
def test_JOBS_V1_no_customer_is_refused(form):
    form.open_new()
    form.set("jfDate", SANDBOX_DATE).save()
    expect(form.error()).to_contain_text("Select a customer")
    assert form.is_open()


def test_JOBS_V2_hard_job_without_start_time_is_refused(form, data):
    form.open_new()
    form.customer(data.customer_id()).text("jfAddress", "210 Sams Ave").set("jfDate", SANDBOX_DATE)
    form.choose("jfSchedType", "Hard").set("jfStart", "").set("jfDuration", "30").save()
    expect(form.error()).to_contain_text("hard schedule needs a Start Time")
    assert form.is_open()


def test_JOBS_V3_soft_window_shorter_than_the_job_is_refused(form, data):
    token = f"JV3-{int(time.time())}"
    _fill_new(form, data, token, start="09:00", end="09:30", dur="60").save()
    expect(form.error()).to_contain_text("shorter than the Est. Duration")
    assert form.is_open()


# ── JOBS-04/05/06: edit, cancel, move ────────────────────────────────────────
def test_JOBS_04_edit_changes_the_job(form, api, data, page):
    jid = data.job("JOBS04", "city_hall")
    page.evaluate("async () => { await loadJobs(); }")
    form.open_edit(jid)
    form.text("jfNotes", "edited by E2E").set("jfDuration", "90")
    form.save("update_job_spreadsheet")
    expect(form.modal).to_be_hidden()
    j = _job(api, jid)
    assert "edited by E2E" in (j.get("Service Details / Notes") or "")


def test_JOBS_05_cancel_through_the_form_takes_it_off_the_route(clean_slate, app, page, api, data):
    from app import RouteScreen
    ids = [data.job("JOBS05 keep", "city_hall"), data.job("JOBS05 cancel", "brannon")]
    app.goto("route")
    route = RouteScreen(page, app.log)
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date(accept_errors=True)
    route.wait_quiet()
    app.goto("jobs")
    page.evaluate("async () => { await loadJobs(); }")
    f = JobForm(page, app.log).open_edit(ids[1])
    f.choose("jfStatus", "Cancelled").save("update_job_spreadsheet")
    assert _job(api, ids[1]).get("Job Status") == "Cancelled"
    app.goto("route")
    route.pick_date(SANDBOX_DATE)
    route.wait_quiet()
    stops = [s.job_id() for s in route.stops()]
    assert ids[1] not in stops and ids[0] in stops, f"stops after cancelling {ids[1]}: {stops}"


def test_JOBS_06_move_to_another_day_through_the_form(form, api, data, page):
    jid = data.job("JOBS06", "city_hall")
    page.evaluate("async () => { await loadJobs(); }")
    form.open_edit(jid)
    form.set("jfDate", sandbox_day(1)).save("update_job_spreadsheet")
    assert iso_date(_job(api, jid).get("Service Date", "")) == sandbox_day(1)


# ── a refused save must not look like a successful one ───────────────────────
def test_JOBS_07_a_save_the_server_refuses_is_shown_not_hidden(form, api, data, guard):
    """If the server refuses the save (here: the customer was deleted after the
    form was opened — e.g. by someone else), the person must SEE that. Found
    by reading the code 2026-09-26: saveJobForm() closes the form after
    create_job / update_job_spreadsheet without checking the reply, so a
    refusal ('❌ …') looked exactly like a successful save."""
    token = f"J07-{int(time.time())}"
    cid = data.customer_id()
    _fill_new(form, data, token)
    # the customer disappears while the form is open
    api.call("update_job_spreadsheet", {"job_identifier": cid, "sheet_name": "Customers",
                                        "id_column": "CustomerID (CUST-####)",
                                        "updates": {"Status Active/Inactive": "Inactive"}})
    api.call("delete_customer", {"customer_identifier": cid, "confirm": True})
    data._cust_id = None
    form.save("create_job")
    assert _job_with_note(api, token) is None, "the server should have refused this job"
    assert form.is_open(), "the form closed as if the job had been saved — the refusal was hidden"
    expect(form.error()).to_be_visible()
