"""The Jobs-app E2E write guard (tests/gui_jobs_e2e/safety.py) must classify
every tool the Jobs app can call, and its mileage rules must allow test data
only (2026-10-25).

Why: the mileage tracker added 13 tools to the Jobs app and the guard knew
none of them. The app calls mileage_settings on every page load, so every
E2E test ended "GUARD BLOCKED … UNCLASSIFIED tool" — and nothing in the
normal test run noticed. This runs in the normal suite (no browser, no server).
"""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load_safety():
    spec = importlib.util.spec_from_file_location("_e2e_safety_for_unit_test",
                                                  ROOT / "tests" / "gui_jobs_e2e" / "safety.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


S = _load_safety()


def test_every_jobs_app_tool_is_classified_by_the_e2e_guard():
    import mcp_tool_catalog as cat
    known = (S.READ | S.CREATE | S.SCOPED | S.OUTBOUND | set(S.CREDITS) | S.MARKS_READ | S.NEVER
             | S.MILEAGE_TOOLS)
    missing = sorted(set(cat.JOBS_APP_TOOLS) - known)
    assert not missing, ("Jobs app tools the E2E guard doesn't classify (every E2E test that triggers one "
                         f"fails with 'UNCLASSIFIED tool'): {missing} — add them to tests/gui_jobs_e2e/safety.py")


@pytest.fixture
def g():
    guard = S.Guard()
    trips = {"TRIP-0901": {"trip_date": S.SANDBOX_DATE, "job_id": "JOB-9001", "crew": ""},
             "TRIP-0902": {"trip_date": S.SANDBOX_DATE, "job_id": "", "crew": "Samual"},
             "TRIP-0903": {"trip_date": S.SANDBOX_DATE, "job_id": "", "crew": f"{S.ZTEST_PREFIX} Driver"},
             "TRIP-0904": {"trip_date": "2020-01-02", "job_id": "JOB-9001", "crew": ""}}
    guard.trip_resolver = trips.get
    guard.entry_resolver = {"TE-1": "JOB-9001", "TE-2": "JOB-4444"}.get
    guard.reimb_resolver = {"REIM-0001": f"{S.ZTEST_PREFIX} Driver", "REIM-0002": "Samual"}.get
    guard.created.add("JOB-9001")
    return guard


def _d(g, tool, **a):
    return g.check(tool, a)[0]


def test_mileage_reads_and_downloads_allowed_files_and_email_not_sent(g):
    for t in ("get_mileage_log", "get_mileage_report", "review_mileage_log"):
        assert _d(g, t) == "allow"
    assert _d(g, "mileage_settings", action="get") == "allow"
    assert _d(g, "manage_vehicles", action="list") == "allow"
    assert _d(g, "update_mileage_trip", trip_id="TRIP-0001", action="history", reason="view") == "allow"
    assert _d(g, "export_mileage_log", format="csv", deliver="download") == "allow"
    assert _d(g, "export_mileage_log", format="pdf") == "record"               # default deliver=file
    assert _d(g, "export_mileage_log", deliver="email", email_to="cpa@example.com") == "record"
    assert _d(g, "mileage_reimbursement", action="statement", deliver="download") == "allow"
    assert _d(g, "mileage_reimbursement", action="statement", deliver="email") == "record"


def test_new_trips_only_in_the_sandbox_window_for_test_people_and_vehicles(g):
    assert _d(g, "add_mileage_trip", to_place="Home Depot", purpose="Supplies – x", miles="3") == "allow"
    assert _d(g, "add_mileage_trip", text="Bank deposit at Chase, 6 miles") == "allow"
    assert _d(g, "add_mileage_trip", date="2020-01-02", to_place="x") == "block"
    assert _d(g, "add_mileage_trip", for_crew="Samual", to_place="x") == "block"
    assert _d(g, "add_mileage_trip", for_crew=f"{S.ZTEST_PREFIX} Driver", to_place="x") == "allow"
    assert _d(g, "add_mileage_trip", vehicle_id="VEH-0001", to_place="x") == "block"     # a real vehicle
    g.note_result("manage_vehicles", "✅ Added VEH-0042 (business-owned), VIN 1GCWGAFP0CB123456.")
    assert _d(g, "add_mileage_trip", vehicle_id="VEH-0042", to_place="x") == "allow"


def test_trip_changes_only_on_test_trips(g):
    assert _d(g, "update_mileage_trip", trip_id="TRIP-0901", miles="5", reason="r") == "allow"   # test job's leg
    assert _d(g, "update_mileage_trip", trip_id="TRIP-0903", action="void", reason="r") == "allow"
    assert _d(g, "update_mileage_trip", trip_id="TRIP-0902", miles="5", reason="r") == "block"   # Samual's
    assert _d(g, "update_mileage_trip", trip_id="TRIP-0904", miles="5", reason="r") == "block"   # 2020
    assert _d(g, "update_mileage_trip", trip_id="TRIP-0999", miles="5", reason="r") == "block"   # unknown
    assert _d(g, "update_mileage_trip", trip_id="TRIP-0901", date="2020-01-02", reason="r") == "block"
    g.note_result("add_mileage_trip", "✅ Saved TRIP-0950, TRIP-0951 — 2026-10-25, 5.2 mi to Chase (Bank).")
    assert _d(g, "update_mileage_trip", trip_id="TRIP-0951", action="split", via_place="Ace", reason="r") == "allow"
    assert _d(g, "apply_mileage_review_fix", finding_id=f"duplicate:{S.SANDBOX_DATE}:TRIP-0950") == "allow"
    assert _d(g, "apply_mileage_review_fix", finding_id=f"duplicate:{S.SANDBOX_DATE}:TRIP-0902") == "block"
    assert _d(g, "apply_mileage_review_fix", finding_id=f"route_mismatch:{S.SANDBOX_DATE}:owner") == "block"
    # a failed reply registers nothing
    g.note_result("add_mileage_trip", "❌ A specific business purpose is required (TRIP-0960)")
    assert "TRIP-0960" not in g.created


def test_rebuilds_gaps_cancellations_vehicles_settings_reimbursements(g):
    assert _d(g, "build_mileage_log", date=S.SANDBOX_DATE) == "allow"
    assert _d(g, "build_mileage_log") == "allow"
    assert _d(g, "build_mileage_log", date="2020-01-02") == "block"
    assert _d(g, "build_mileage_log", start_date=S.SANDBOX_DATE, end_date=S.SANDBOX_DATE, preview=False) == "block"
    assert _d(g, "fix_mileage_gap", entry_id="TE-1", clock_out_time="15:30", reason="r") == "allow"
    assert _d(g, "fix_mileage_gap", entry_id="TE-2", clock_out_time="15:30", reason="r") == "block"
    assert _d(g, "job_cancelled_on_arrival", job_id="JOB-9001") == "allow"
    assert _d(g, "job_cancelled_on_arrival", job_id="JOB-4444") == "block"
    assert _d(g, "manage_vehicles", action="add", vin="x", nickname=f"{S.ZTEST_PREFIX} Van") == "allow"
    assert _d(g, "manage_vehicles", action="add", vin="x", nickname="White F-150") == "block"
    assert _d(g, "manage_vehicles", action="odometer", vehicle_id="VEH-0001", odometer="5") == "block"
    assert _d(g, "manage_vehicles", action="set_default", vehicle_id="VEH-0001") == "block"
    g.created.add("VEH-0042")
    assert _d(g, "manage_vehicles", action="retire", vehicle_id="VEH-0042") == "allow"
    assert _d(g, "manage_vehicles", action="set_default", vehicle_id="VEH-0042") == "block"
    assert _d(g, "manage_vehicles", action="set_day", vehicle_id="VEH-0042", date=S.SANDBOX_DATE) == "allow"
    # settings: never tracking/rates/locks; period + reminders only once the originals are saved
    for act in ("set_enabled", "set_rate", "lock", "unlock"):
        assert _d(g, "mileage_settings", action=act) == "block"
    assert _d(g, "mileage_settings", action="set_period", pay_period="weekly") == "block"
    g.mileage_settings_saved = {"period": "biweekly", "reminders": {}}
    assert _d(g, "mileage_settings", action="set_period", pay_period="weekly") == "allow"
    assert _d(g, "mileage_settings", action="set_reminder", reminder="weekly", enabled=False) == "allow"
    # reimbursements: submit for a ZTEST driver; approve/return/paid only on theirs
    assert _d(g, "mileage_reimbursement", action="submit") == "block"                 # the owner's own
    assert _d(g, "mileage_reimbursement", action="submit", crew="Samual") == "block"
    assert _d(g, "mileage_reimbursement", action="submit", crew=f"{S.ZTEST_PREFIX} Driver") == "allow"
    assert _d(g, "mileage_reimbursement", action="approve", reimbursement_id="REIM-0001") == "allow"
    assert _d(g, "mileage_reimbursement", action="paid", reimbursement_id="REIM-0002", method="check") == "block"
    assert _d(g, "mileage_reimbursement", action="return", reimbursement_id="REIM-0009", note="x") == "block"
    assert _d(g, "mileage_reimbursement", action="status") == "allow"
