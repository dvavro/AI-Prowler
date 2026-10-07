"""Harness self-tests (spec §11 Phase 1 'done when'): the guard really blocks
writes to real data, outbound calls are recorded not sent, and test data is
created and fully cleaned up."""
import pytest

from safety import SANDBOX_DATE


@pytest.mark.expect_guard_block
def test_HARNESS_guard_blocks_a_write_to_real_data_from_the_browser(app, api, guard):
    before = {r.get("Setting"): r.get("Value") for r in api.read("Settings")}
    with pytest.raises(Exception):
        # a real setting — NOT test data — so the guard must abort this before it leaves the browser
        app.mcp("update_job_spreadsheet", {"job_identifier": "Business Name", "sheet_name": "Settings",
                                           "id_column": "Setting", "updates": {"Value": "HACKED BY E2E"}})
    assert any(v["tool"] == "update_job_spreadsheet" for v in guard.violations), "guard did not record the block"
    after = {r.get("Setting"): r.get("Value") for r in api.read("Settings")}
    assert after == before, "a real setting changed — the guard let a write through"


def test_HARNESS_guard_blocks_a_write_to_real_data_from_test_code(api, guard):
    from safety import GuardViolation
    # NOT a low number like JOB-0001: IDs are "highest + 1", so on an empty
    # database this run's own first job IS JOB-0001 (legitimately test data) —
    # which made this test fail on 2026-09-25. Use an ID no run will create.
    real_id = "JOB-99990"
    assert real_id not in guard.created
    with pytest.raises(GuardViolation):
        api.call("delete_job", {"job_identifier": real_id, "confirm": True})
    guard.take_violations()     # expected block — don't let it fail teardown


def test_HARNESS_outbound_is_recorded_not_sent(app, guard):
    n = len(guard.recorded_calls("email_route_now"))
    result = app.mcp("email_route_now", {"route_date": SANDBOX_DATE})
    assert "[E2E guard" in result
    calls = guard.recorded_calls("email_route_now")
    assert len(calls) == n + 1 and calls[-1]["args"]["route_date"] == SANDBOX_DATE
    assert guard.real_emails_sent == 0


def test_HARNESS_test_data_is_created_and_fully_cleaned_up(api, data):
    jid = data.job("Harness check", "brannon")
    assert any(j.get("JobID (JOB-####)") == jid for j in api.read("Jobs_Schedule"))
    data.sweep("harness self-test")
    assert data.leftovers() == []
