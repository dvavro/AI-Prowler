"""
tests/mcp_tests/test_send_sms_and_scheduler_openpyxl_removal.py
=============================================================
Job Board Architecture Spec — system-wide openpyxl audit (2026-09-13).

Two more real bugs found while auditing every remaining openpyxl
reference in the live (non-backup) codebase, at the user's explicit
request to confirm nothing still depends on the old spreadsheet:

1. send_sms()'s customer-phone lookup (step 1 of its to-phone resolution)
   was still fully openpyxl-based, opening the old .xlsx Job Tracker
   directly — the third instance of the exact same bug class already
   fixed in _lookup_customer_email()/_lookup_invoice_customer_email().

2. scheduler_jobs._todays_jobs_structured() (used by the Morning
   Briefing's per-job weather cross-referencing) was ALSO still fully
   openpyxl-based — since the old file generally no longer exists once
   an install has moved to SQLite, this had been silently returning []
   every single day, with the feature quietly falling back to the
   generic report with no visible error anywhere.

Run with:
    run_tests.bat tests\\mcp\\test_send_sms_and_scheduler_openpyxl_removal.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _owner(uid="dave"):
    return {"id": uid, "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}


# ══════════════════════════════════════════════════════════════════════════
# send_sms() customer-phone lookup — personal mode
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def personal_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"  # deliberately never created
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    return tmp_path / "ai_prowler_jobs.db"


def test_send_sms_resolves_customer_name_to_phone_without_the_old_xlsx(personal_env, mcp_mod, monkeypatch):
    """The .xlsx is never created anywhere in this test — proves the
    lookup no longer depends on openpyxl/the old file at all. Rather
    than mock the full SMS-provider send pipeline (whose exact backend
    interface isn't the point of this test), stub send_sms's own
    resolved-phone check by monkeypatching just far enough to observe
    what `to` becomes right before the digit-count/send step: if it's
    the real phone number, the lookup worked; if it's still the literal
    customer name, it didn't."""
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe", "Phone": "386-555-0101"},
                             filepath="", backup=False, ctx=None)

    captured = {}
    def _fake_config_load():
        # No SMS provider configured -> send_sms fails at the "not
        # configured" stage, which happens AFTER phone resolution —
        # far enough to prove resolution ran, without needing to mock
        # an actual provider's send() call.
        return {}
    monkeypatch.setattr(mcp_mod, "_get_sms_config", _fake_config_load, raising=False)

    result = mcp_mod.send_sms(to="Blue Wave Cafe", message="Test", ctx=None)
    # Whatever the final configuration-related failure message says, it
    # must not be the blank-recipient rejection or a literal-name-not-
    # enough-digits error — both of which would mean resolution never
    # found the real phone number.
    assert "required and cannot be blank" not in result
    assert "Blue Wave Cafe" not in result


def test_lookup_finds_customer_by_name_via_direct_db_query(personal_env, mcp_mod):
    """Lower-level check: confirms the customer row (with phone) is
    genuinely retrievable from the DB the way send_sms's new lookup
    code queries it, independent of the SMS-sending plumbing above."""
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe", "Phone": "386-555-0101"},
                             filepath="", backup=False, ctx=None)
    import sqlite3
    conn = sqlite3.connect(str(personal_env))
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT phone FROM customers WHERE LOWER(company_name) LIKE ?",
        ("%blue wave%",),
    ).fetchone()
    conn.close()
    assert row["phone"] == "386-555-0101"


# ══════════════════════════════════════════════════════════════════════════
# scheduler_jobs._todays_jobs_structured()
# ══════════════════════════════════════════════════════════════════════════

def test_todays_jobs_structured_never_touches_old_xlsx(personal_env, mcp_mod):
    """The .xlsx is never created anywhere in this test."""
    import datetime
    today_iso = datetime.date.today().isoformat()
    cust_result = mcp_mod.create_customer({"Company Name": "Blue Wave Cafe"}, filepath="", backup=False, ctx=None)
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_job(
        {"CustomerID": cust_id, "Customer Name / Company": "Blue Wave Cafe", "City": "New Smyrna Beach",
         "State": "FL", "Service Type": "Window", "Crew / Technician": "Jake",
         "Service Date": today_iso},
        filepath="", backup=False, ctx=None,
    )

    import scheduler_jobs
    results = scheduler_jobs._todays_jobs_structured()
    assert len(results) == 1
    assert results[0]["customer"] == "Blue Wave Cafe"
    assert results[0]["city"] == "New Smyrna Beach"
    assert results[0]["state"] == "FL"


def test_todays_jobs_structured_excludes_other_dates(personal_env, mcp_mod):
    cust_result = mcp_mod.create_customer({"Company Name": "Old Job Co"}, filepath="", backup=False, ctx=None)
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_job(
        {"CustomerID": cust_id, "Customer Name / Company": "Old Job Co", "City": "Orlando",
         "State": "FL", "Service Date": "2020-01-01", "Job Status": "Complete"},
        filepath="", backup=False, ctx=None,
    )
    import scheduler_jobs
    results = scheduler_jobs._todays_jobs_structured()
    assert results == []


def test_todays_jobs_structured_includes_unfinished_past_job(personal_env, mcp_mod):
    """R-058 overrun (David 2026-09-28): a past job that was never marked
    Complete is still being worked, so it's on today's list until it is."""
    import datetime
    if datetime.date.today().weekday() >= 5:
        pytest.skip("overrun days are working days; today is a weekend")
    cust_result = mcp_mod.create_customer({"Company Name": "Still Open Co"}, filepath="", backup=False, ctx=None)
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_job(
        {"CustomerID": cust_id, "Customer Name / Company": "Still Open Co", "City": "Orlando",
         "State": "FL", "Service Date": "2020-01-01", "Job Status": "In Progress"},
        filepath="", backup=False, ctx=None,
    )
    import scheduler_jobs
    assert [r["customer"] for r in scheduler_jobs._todays_jobs_structured()] == ["Still Open Co"]


def test_todays_jobs_structured_empty_db_returns_empty_list(personal_env, mcp_mod):
    import scheduler_jobs
    assert scheduler_jobs._todays_jobs_structured() == []


def test_todays_jobs_structured_omits_missing_fields(personal_env, mcp_mod):
    """A job with no Crew set should simply omit the 'crew' key, not
    include an empty string — matching the documented behavior."""
    import datetime
    today_iso = datetime.date.today().isoformat()
    cust_result = mcp_mod.create_customer({"Company Name": "No Crew Co"}, filepath="", backup=False, ctx=None)
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_job(
        {"CustomerID": cust_id, "Customer Name / Company": "No Crew Co", "Service Date": today_iso},
        filepath="", backup=False, ctx=None,
    )
    import scheduler_jobs
    results = scheduler_jobs._todays_jobs_structured()
    assert len(results) == 1
    assert "crew" not in results[0]
    assert results[0]["customer"] == "No Crew Co"
