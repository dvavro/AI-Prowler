"""Server mode — what field crew may create / delete (spec §6.11.5
SRV-SCOPE-09/10, gap G-04). David's decision 2026-09-27:

  • field crew MAY create a job for someone else (any Crew)
  • field crew MAY add a new customer, including the normally-locked
    fields (Frequency, Standard Quote, Discount, …)
  • field crew may NOT delete customers — owner / manager / staff only

Samual (U3) works through his own session; every record is ZTEST and swept.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_crew_create
"""
import logging

from api import parse_records
from safety import SANDBOX_DATE, ZTEST_PREFIX

log = logging.getLogger("e2e_srv")

OTHER = "Vicki Vavro"


def _refused(text) -> bool:
    return str(text).lstrip().startswith(("❌", "⛔"))


def _new_id(out, key):
    return str(out).split(f"{key}=")[1].splitlines()[0].strip()


def _customer(owner_api, cid):
    return next((r for r in owner_api.read("Customers") if cid in r.values()), None)


# ── SRV-SCOPE-09: crew creates a job for another crew ────────────────────────
def test_SRV_SCOPE_09_crew_may_create_a_job_for_someone_else(clean_slate, data, api_as, owner_api):
    cust = data.customer_id()
    out = api_as("U3").call("create_job", {"updates": {
        "CustomerID": cust, "Customer Name / Company": f"{ZTEST_PREFIX} SCOPE09",
        "Service Date": SANDBOX_DATE, "Crew / Technician": OTHER}}, expect_ok=False)
    log.info(f"[SRV-SCOPE-09] Samual create_job for Vicki -> {str(out).splitlines()[0][:160]}")
    assert not _refused(out), f"G-04 (allowed by David): crew couldn't create a job for Vicki: {out[:200]!r}"
    jid = _new_id(out, "NEW_JOB_ID")
    job = next(r for r in owner_api.read("Jobs_Schedule") if r.get("JobID (JOB-####)") == jid)
    assert job.get("Crew / Technician") == OTHER, f"{jid} isn't on Vicki's crew: {job}"


# ── SRV-SCOPE-10: crew adds a customer with the locked fields filled in ─────
def test_SRV_SCOPE_10_crew_may_add_a_customer_with_locked_fields(clean_slate, api_as, owner_api):
    fields = {"Company Name": f"{ZTEST_PREFIX} SCOPE10 Customer", "Frequency": "Monthly",
              "Standard Quote ($)": 150, "Discount (%)": 10}
    out = api_as("U3").call("create_customer", {"updates": fields}, expect_ok=False)
    log.info(f"[SRV-SCOPE-10] Samual create_customer -> {str(out).splitlines()[0][:160]}")
    assert not _refused(out), f"G-04 (allowed by David): crew couldn't add a customer: {out[:200]!r}"
    cid = _new_id(out, "NEW_CUST_ID")
    row = _customer(owner_api, cid)
    assert row, f"{cid} not found"
    assert row.get("Frequency") == "Monthly", f"Frequency not saved: {row}"
    assert str(row.get("Standard Quote ($)", "")).startswith("150"), f"Standard Quote not saved: {row}"

    # David 2026-09-27: "only when creating a new customer and after that it's
    # locked" — even on the customer Samual just created himself. Crew can only
    # edit a customer linked to one of their own jobs, so give him one first —
    # otherwise the edit is refused for THAT reason and the lock is never tested.
    api_as("U3").call("create_job", {"updates": {
        "CustomerID": cid, "Customer Name / Company": f"{ZTEST_PREFIX} SCOPE10 job",
        "Service Date": SANDBOX_DATE, "Crew / Technician": "Samual Cronin"}})
    ok = api_as("U3").call("update_job_spreadsheet", {
        "sheet_name": "Customers", "id_column": "CustomerID (CUST-####)", "job_identifier": cid,
        "updates": {"Gate Code / Access Notes": "gate 1234"}}, expect_ok=False)
    assert not _refused(ok), f"control: Samual can't edit a normal field on his own customer: {ok[:200]!r}"
    res = api_as("U3").call("update_job_spreadsheet", {
        "sheet_name": "Customers", "id_column": "CustomerID (CUST-####)", "job_identifier": cid,
        "updates": {"Frequency": "Weekly"}}, expect_ok=False)
    log.info(f"[SRV-SCOPE-10] Samual edits Frequency after creating -> {str(res).splitlines()[0][:160]}")
    assert _refused(res) and "Frequency" in res, \
        f"crew changed a locked field after the customer was created (or refused for another reason): {res[:200]!r}"
    assert _customer(owner_api, cid).get("Frequency") == "Monthly", "Frequency changed after creation"


# ── G-04: crew may NOT delete a customer ─────────────────────────────────────
def test_SRV_G04_crew_cannot_delete_a_customer(clean_slate, api_as, owner_api):
    out = owner_api.call("create_customer", {"updates": {"Company Name": f"{ZTEST_PREFIX} G04 keep"}})
    cid = _new_id(out, "NEW_CUST_ID")
    res = api_as("U3").call("delete_customer", {"customer_identifier": cid, "confirm": True}, expect_ok=False)
    log.info(f"[SRV-G04] Samual delete_customer -> {str(res).splitlines()[0][:160]}")
    assert _refused(res), f"field crew deleted a customer: {res[:200]!r}"
    assert _customer(owner_api, cid), f"{cid} is gone after a refused delete"
