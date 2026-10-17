"""
HR release gaps closed (David, 2026-10-17):
  * onboarding forms: Done marks on the server; record forms save into the
    employee record (bank numbers: last 4 digits only, whatever is sent);
    signed forms need an attached signed copy of THIS employee or "paper copy
    on file"; no SSN fields anywhere; no false "Saved locally"
  * HR clocks an employee in/out (forgot to) -> a real time entry, entered_by
    HR, following "Who clocks in"; HR Admin's dead browser-only clock is gone
  * Training alert dot reads server completions; old browser-only incidents /
    training / About Me code removed
pytest tmp_path + ZTEST data only. Run:
  run_tests.bat tests\\mcp_tests\\test_hr_release_gaps.py -v
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
ADMIN = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")
PORTAL = (ROOT / "hr_portal" / "index.html").read_text(encoding="utf-8")
HR = {"role": "admin", "user_id": "ztest-admin"}
EMP = {"role": "employee", "employee_id": "EMP-00001"}


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    live = tmp_path / "hr"
    live.mkdir()
    monkeypatch.setattr(m, "_HR_DB_PATH", str(live / "hr_db.json"))
    monkeypatch.setattr(m, "_load_users", lambda: None)
    m._hr_save_db({"config": {"company_name": "ZTEST Co", "setup_complete": True, "work_states": ["FL"]},
                   "employees": [{"id": "EMP-00001", "first_name": "ZTEST", "last_name": "Hire", "status": "Active",
                                  "pay_type": "hourly", "routing_last4": "9999"},
                                 {"id": "EMP-00002", "first_name": "ZTEST", "last_name": "Other", "status": "Active",
                                  "pay_type": "salary", "flsa_classification": "Exempt"}],
                   "documents": [{"id": "DOC-1", "employee_id": "EMP-00001", "name": "w4-signed.pdf", "category": "onboarding"},
                                 {"id": "DOC-2", "employee_id": "EMP-00002", "name": "other.pdf", "category": "onboarding"}],
                   "tasks": [], "audit_log": []})
    m.ztest_live = live
    return m


def call(ap, method, path, body=None, auth=HR):
    st, _ct, b = ap._hr_api_route(method, path, {}, body or {}, auth)
    return st, json.loads(b)


def emp(ap, i="EMP-00001"):
    return next(e for e in ap._hr_load_db()["employees"] if e["id"] == i)


def done(ap):
    return call(ap, "GET", "/onboarding-forms")[1]["done"]


# ── onboarding forms ────────────────────────────────────────────────────────
def test_record_forms_save_into_the_record(ap):
    st, j = call(ap, "POST", "/onboarding-forms/EMP-00001/personal_info_form", {"data": {
        "preferred_name": "Z", "date_of_birth": "1990-01-02", "phone": "5551112222",
        "ec_name": "ZTEST Contact", "ec_relationship": "Sibling", "ec_phone": "5553334444"}})
    assert st == 200 and j["method"] == "record"
    e = emp(ap)
    assert (e["nickname"], e["date_of_birth"], e["phone"]) == ("Z", "1990-01-02", "5551112222")
    assert e["emergency_contact"] == {"name": "ZTEST Contact", "relationship": "Sibling", "phone": "5553334444"}
    call(ap, "POST", "/onboarding-forms/EMP-00001/benefits_enrollment",
         {"data": {"health": "Employee only", "k401": "5", "beneficiary": "ZTEST Ben"}})
    assert emp(ap)["benefits"]["health"] == "Employee only" and emp(ap)["benefits"]["k401"] == "5"
    assert {r["form"] for r in done(ap)["EMP-00001"]} == {"personal_info_form", "benefits_enrollment"}


def test_direct_deposit_keeps_last_4_only(ap):
    call(ap, "POST", "/onboarding-forms/EMP-00001/direct_deposit", {"data": {
        "bank_name": "ZTEST Bank", "account_type": "Checking",
        "routing": "021000021", "account": "123456789012"}})                   # full numbers sent anyway
    e = emp(ap)
    assert (e["routing_last4"], e["account_last4"], e["bank_name"]) == ("0021", "9012", "ZTEST Bank")
    raw = "".join(p.read_text(encoding="utf-8") for p in ap.ztest_live.rglob("*.json"))
    assert "021000021" not in raw and "123456789012" not in raw
    # nothing typed -> what's on file stays
    call(ap, "POST", "/onboarding-forms/EMP-00001/direct_deposit", {"data": {"bank_name": "ZTEST Bank 2"}})
    assert emp(ap)["routing_last4"] == "0021"


def test_signed_forms_need_a_copy_or_paper(ap):
    st, j = call(ap, "POST", "/onboarding-forms/EMP-00001/w4", {})
    assert st == 400 and j["error"] == "signed_copy_required"
    st, j = call(ap, "POST", "/onboarding-forms/EMP-00001/w4", {"doc_id": "DOC-2"})     # someone else's file
    assert st == 400 and j["error"] == "bad_document"
    st, j = call(ap, "POST", "/onboarding-forms/EMP-00001/w4", {"doc_id": "DOC-1"})
    assert st == 200 and j["method"] == "signed_copy"
    st, j = call(ap, "POST", "/onboarding-forms/EMP-00001/i9", {"paper_copy": True})
    assert st == 200 and j["method"] == "paper_copy"
    rows = {r["form"]: r for r in done(ap)["EMP-00001"]}
    assert rows["w4"]["doc_id"] == "DOC-1" and rows["i9"]["method"] == "paper_copy"
    # undo
    assert call(ap, "DELETE", "/onboarding-forms/EMP-00001/w4")[0] == 200
    assert "w4" not in {r["form"] for r in done(ap)["EMP-00001"]}


def test_step_8_unknown_forms_and_admin_only(ap):
    assert call(ap, "POST", "/onboarding-forms/EMP-00001/step_completed", {})[1]["method"] == "completed"
    assert call(ap, "POST", "/onboarding-forms/EMP-00001/ssn_card", {})[0] == 400
    assert call(ap, "POST", "/onboarding-forms/EMP-09999/w4", {"paper_copy": True})[0] == 404
    assert call(ap, "GET", "/onboarding-forms", auth=EMP)[0] == 403
    assert call(ap, "POST", "/onboarding-forms/EMP-00001/i9", {"paper_copy": True}, auth=EMP)[0] == 403


def test_marks_live_in_the_employee_folder(ap):
    call(ap, "POST", "/onboarding-forms/EMP-00001/i9", {"paper_copy": True})
    files = [p for p in ap.ztest_live.rglob("*.json") if "onboarding_forms" in p.name]
    mine = [p for p in files if "EMP-00001" in str(p)]
    assert mine and '"i9"' in mine[0].read_text(encoding="utf-8")
    for p in files:                                   # nothing about this employee kept company-wide
        if "EMP-00001" not in str(p):
            assert '"i9"' not in p.read_text(encoding="utf-8")


# ── HR clocks someone in / out ──────────────────────────────────────────────
def test_hr_clock_in_and_out_creates_a_real_entry(ap):
    st, j = call(ap, "POST", "/timeclock/admin", {"employee_id": "EMP-00001", "action": "in"})
    assert st == 201 and j["entry"]["entered_by"] == "HR Admin"
    assert call(ap, "POST", "/timeclock/admin", {"employee_id": "EMP-00001", "action": "in"})[1]["error"] == "already_clocked_in"
    st, j = call(ap, "POST", "/timeclock/admin", {"employee_id": "EMP-00001", "action": "out"})
    assert st == 200 and j["entry"]["clock_out"] and j["entry"]["clock_out_entered_by"] == "HR Admin"
    entries = call(ap, "GET", "/timeclock/entries?period=all")[1].get("entries")
    assert entries is None or any(en["employee_id"] == "EMP-00001" for en in entries)
    assert call(ap, "GET", "/timeclock/mine", auth=EMP)[1]["entries"][0]["entered_by"] == "HR Admin"
    assert call(ap, "POST", "/timeclock/admin", {"employee_id": "EMP-00001", "action": "out"})[1]["error"] == "not_clocked_in"


def test_hr_clock_follows_who_clocks_in(ap):
    call(ap, "POST", "/settings", {"time_clock_mode": "non_exempt"})
    st, j = call(ap, "POST", "/timeclock/admin", {"employee_id": "EMP-00002", "action": "in"})   # exempt
    assert st == 409 and j["error"] == "time_clock_off"
    assert call(ap, "POST", "/timeclock/admin", {"employee_id": "EMP-00001", "action": "dance"})[0] == 400
    assert call(ap, "POST", "/timeclock/admin", {"employee_id": "EMP-00001", "action": "in"}, auth=EMP)[0] == 403


# ── pages ───────────────────────────────────────────────────────────────────
def test_admin_has_no_ssn_fields_or_browser_only_hr_data():
    for gone in ("w4_ssn", "i9_ssn", "Social Security Number", "ob_forms_", "clock_${", "function clockIn(",
                 "hr_training_completions", "'hr_incidents'", "Saved locally", "coming in Week"):
        assert gone not in ADMIN, gone
    for there in ("function openSignedFormUpload", "async function saveSignedForm", "/onboarding-forms/",
                  "apiGet('/onboarding-forms')", "async function hrClockFor", "apiPost('/timeclock/admin'",
                  "hr_training_seen_at", "d.source === 'training_complete'",
                  "label:'Routing Number \u2014 last 4 digits only'"):
        assert there in ADMIN, there


def test_portal_old_about_me_code_removed():
    for gone in ("function saveAbout(", "function saveEmergencyContact(", "function loadAboutMe(",
                 "localStorage.setItem('hr_about_"):
        assert gone not in PORTAL, gone
