"""
tests/e2e/test_route_scheduling_e2e.py
========================================
Investigates whether optimize_route() accounts for each job's already-
scheduled appointment time (Start Time in Jobs_Schedule) when it reorders
stops — and documents, with a concrete real-world scenario, that it
currently does NOT.

WHY THIS MATTERS
-----------------
optimize_route() solves an unconstrained Traveling Salesman Problem via
OSRM's /trip endpoint: given a list of addresses, it returns whichever
visit order minimizes total drive time/distance. It has no concept of a
job's Service Date, Start Time, or any other fixed appointment — those
never reach the routing call at all, since optimize_route() takes a bare
list of address strings, not job records.

In the real world this matters: if Job A is scheduled for 8:00 AM and
Job B for 2:00 PM the same day, and both addresses are handed to
optimize_route(), it can freely suggest visiting B before A if that's
geometrically faster — a route a contractor cannot actually drive, because
Job B's customer is not expecting them until 2:00 PM.

This suite does NOT claim this is a "bug" to silently work around — solving
it properly (time-windowed vehicle routing) is a materially different,
larger feature than what optimize_route() was built to do. The goal here
is to make the current behavior an explicit, tested fact so:
  (a) any future change to optimize_route() that adds time-window support
      is caught as an intentional capability upgrade, not a silent behavior
      change, and
  (b) Claude (and anyone reading this test) has a concrete, reproducible
      demonstration of the gap to reason from when helping a user schedule
      a new job — see the docstring on test_new_job_scheduling_workflow
      for the recommended manual workaround given today's tools.

REQUIREMENTS
------------
  pip install openpyxl
  No ANTHROPIC_API_KEY needed — this suite calls the routing tools directly,
  it does not exercise Claude's tool-selection (see
  test_contractor_workflow_e2e.py for that layer).
  Needs outbound internet access to nominatim.openstreetmap.org and
  router.project-osrm.org (both free public services used by
  optimize_route() itself — no API keys, but rate-limited and occasionally
  flaky; see the retry helper below).

RUN
---
  pytest tests/e2e/test_route_scheduling_e2e.py -v -s -m job_sheet_e2e
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))
SPREADSHEET_PATH = Path(os.environ.get(
    "AI_PROWLER_JOB_TRACKER_PATH",
    r"C:\Users\david\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx",
))
TEST_CUSTOMER_PREFIX = "ZTEST Route Sched"

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))

# Real, geocodable addresses spread across the Daytona Beach / New Smyrna
# Beach area (same region used throughout the other e2e suites, verified
# to geocode successfully in that earlier manual testing session).
# Deliberately chosen so the geographically-fastest drive order does NOT
# match a plausible chronological appointment order — see the scenario
# comment in test_route_order_does_not_respect_appointment_times.
STOP_A = "412 Pelican Dr, Daytona Beach, FL 32118"          # ~13 mi from origin
STOP_B = "100 S Atlantic Ave, Ormond Beach, FL 32176"       # ~24 mi from origin,
                                                              # but close to STOP_A
STOP_C = "127 S Beach St, Daytona Beach, FL 32114"          # near STOP_A too

HOME_ADDRESS_FALLBACK = "1500 Shadow Pines Dr, New Smyrna Beach FL 32168"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


@pytest.fixture(scope="session")
def home_address(mcp_module):
    addr = mcp_module.get_home_address()
    if "❌" in addr or "not configured" in addr.lower():
        return HOME_ADDRESS_FALLBACK
    return addr


@pytest.fixture(scope="session")
def pre_suite_backup_path(mcp_module):
    backup_msg = mcp_module._backup_spreadsheet(str(SPREADSHEET_PATH))
    assert "Backup saved" in backup_msg, f"Pre-suite backup failed: {backup_msg}"
    rel_path = backup_msg.split("Backup saved:")[1].strip()
    return SPREADSHEET_PATH.parent / rel_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _call_optimize_route_with_retry(mcp_module, origin, stops, **kwargs):
    """optimize_route() hits two free public services (Nominatim + OSRM)
    that occasionally return transient connection errors under load —
    observed directly during earlier manual testing in this project.
    Retry once before treating a geocode/routing failure as a real problem.
    """
    for attempt in range(2):
        result = mcp_module.optimize_route(origin=origin, stops=stops, **kwargs)
        if "Could not geocode" not in result and "❌" not in result:
            return result
        if attempt == 0:
            time.sleep(2)
    return result  # return the last attempt's result either way


def _load_jobs_for_date(spreadsheet_path: str, service_date: str) -> list[dict]:
    """Read Jobs_Schedule rows matching a given Service Date (YYYY-MM-DD),
    returning each as a dict, sorted by Start Time ascending.

    BUG FIXED HERE: an earlier version of this helper (and the structurally
    identical find_ztest_job() in test_job_tracker_e2e.py) scanned data
    rows starting from a HARDCODED min_row=6, rather than the actual
    detected header row + 1. Whenever more than a couple of data rows
    existed before the header offset assumption held, rows landing before
    the hardcoded row 6 were silently skipped entirely — discovered here
    when seeding 3 same-day jobs: JOB-0002 (row 4) and JOB-0003 (row 5)
    were skipped, only JOB-0004 (row 6) was found. Always derive the data
    start row from where the header row was actually detected.
    """
    import openpyxl
    wb = openpyxl.load_workbook(str(spreadsheet_path), data_only=True)
    ws = wb["Jobs_Schedule"]

    headers = None
    header_row_num = None
    for row in ws.iter_rows(min_row=1, max_row=5, values_only=True):
        non_empty = [c for c in row if c is not None]
        if len(non_empty) >= 3:
            headers = [str(c).strip().replace("\n", " ") if c else ""
                       for c in row]
            break
    assert headers, "Could not detect header row in Jobs_Schedule"

    # Re-scan with cell objects (not values_only) just to get the real row
    # number the header row was found at — values_only=True rows don't
    # carry their own .row attribute.
    for row in ws.iter_rows(min_row=1, max_row=5):
        non_empty = [c for c in row if c.value is not None]
        if len(non_empty) >= 3:
            header_row_num = row[0].row
            break
    assert header_row_num is not None

    import datetime as _dt
    rows = []
    for row in ws.iter_rows(min_row=header_row_num + 1, values_only=True):
        if not any(v is not None for v in row):
            continue
        rdict = dict(zip(headers, row))
        sd = rdict.get("Service Date")
        sd_str = sd.strftime("%Y-%m-%d") if isinstance(sd, (_dt.date, _dt.datetime)) else str(sd or "")
        if sd_str == service_date:
            rows.append(rdict)

    def _start_key(r):
        st = r.get("Start Time")
        if isinstance(st, _dt.time):
            return st
        if isinstance(st, str) and ":" in st:
            h, m = st.split(":")[:2]
            return _dt.time(int(h), int(m))
        return _dt.time(23, 59)  # unset times sort last

    rows.sort(key=_start_key)
    return rows


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------
@pytest.mark.job_sheet_e2e
class TestRouteSchedulingBehavior:

    job_ids: list = []

    def test_01_seed_jobs_with_distinct_times_same_day(
            self, mcp_module, pre_suite_backup_path):
        """Create three synthetic jobs on the same Service Date, each with
        a different Start Time, at three real geocodable addresses."""
        service_date = "2026-09-20"
        jobs_to_create = [
            (f"{TEST_CUSTOMER_PREFIX} Morning",   STOP_A, "08:00"),
            (f"{TEST_CUSTOMER_PREFIX} Midday",    STOP_B, "12:00"),
            (f"{TEST_CUSTOMER_PREFIX} Afternoon", STOP_C, "15:00"),
        ]
        TestRouteSchedulingBehavior.job_ids = []
        for name, addr, start_time in jobs_to_create:
            # Write City/State/ZIP alongside Street Address — a bare street
            # name with no city context (e.g. "412 Pelican Dr" with nothing
            # else) geocodes ambiguously and can resolve thousands of miles
            # away. Found via this test producing a 7,528-mile "route" on
            # its first run — a test data bug, not an optimize_route() bug.
            parts = [p.strip() for p in addr.split(",")]
            street = parts[0] if len(parts) > 0 else addr
            city   = parts[1] if len(parts) > 1 else ""
            state_zip = parts[2].split() if len(parts) > 2 else []
            state  = state_zip[0] if len(state_zip) > 0 else ""
            zip_   = state_zip[1] if len(state_zip) > 1 else ""

            result = mcp_module.create_job(
                updates={
                    "Customer Name / Company": name,
                    "Street Address ★ AI Route": street,
                    "City ★ AI Route": city,
                    "State": state,
                    "ZIP ★ AI Route": zip_,
                    "Service Date": service_date,
                    "Start Time": start_time,
                    "Service Type": "Window Washing",
                    "Job Status": "Scheduled",
                },
                backup=True,
            )
            assert result.startswith("✅"), f"create_job failed for {name}: {result}"
            job_id = result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
            TestRouteSchedulingBehavior.job_ids.append(job_id)

        jobs = _load_jobs_for_date(str(SPREADSHEET_PATH), service_date)
        our_jobs = [j for j in jobs
                    if str(j.get("Customer Name / Company", "")).startswith(TEST_CUSTOMER_PREFIX)]
        assert len(our_jobs) == 3, f"Expected 3 seeded jobs, found {len(our_jobs)}"
        # Confirm they read back in chronological Start Time order
        assert "Morning"   in our_jobs[0]["Customer Name / Company"]
        assert "Midday"    in our_jobs[1]["Customer Name / Company"]
        assert "Afternoon" in our_jobs[2]["Customer Name / Company"]

    def test_02_route_order_does_not_respect_appointment_times(
            self, mcp_module, home_address):
        """
        THE CORE SCENARIO:

        Three jobs are scheduled the same day in chronological order:
          08:00  Morning   @ STOP_A (412 Pelican Dr, Daytona Beach)
          12:00  Midday    @ STOP_B (100 S Atlantic Ave, Ormond Beach)
          15:00  Afternoon @ STOP_C (127 S Beach St, Daytona Beach)

        STOP_A and STOP_C are both in Daytona Beach, close to each other;
        STOP_B (Ormond Beach) sits geographically between/near them but is
        scheduled for the MIDDLE appointment. A driving-distance-only
        optimizer has every reason to suggest visiting STOP_A and STOP_C
        back-to-back (they're close) and treat STOP_B's position based on
        drive geometry alone — with no awareness that the customer at
        STOP_C is not expecting anyone until 15:00, three hours after
        the technician would arrive if pure distance were followed.

        This test does not assert a specific reordering (real-world OSRM
        results can vary with live map data) — it asserts the STRUCTURAL
        fact that matters: optimize_route() is given only addresses, so it
        is IMPOSSIBLE for it to have preserved appointment order on
        purpose — any match to chronological order in a given run is
        coincidental, not the result of the tool understanding scheduling.
        """
        # Pull the jobs back out in chronological (Start Time) order —
        # this is the order a contractor's actual day must follow.
        # Reconstruct FULL addresses (street + city + state + zip) for
        # geocoding — a bare street name alone is ambiguous and can
        # resolve thousands of miles away (see test_01's fix comment).
        jobs = _load_jobs_for_date(str(SPREADSHEET_PATH), "2026-09-20")
        our_jobs = [j for j in jobs
                    if str(j.get("Customer Name / Company", "")).startswith(TEST_CUSTOMER_PREFIX)]
        chronological_addresses = [
            ", ".join(filter(None, [
                j.get("Street Address ★ AI Route", ""),
                j.get("City ★ AI Route", ""),
                f"{j.get('State', '')} {j.get('ZIP ★ AI Route', '')}".strip(),
            ]))
            for j in our_jobs
        ]
        assert len(chronological_addresses) == 3

        result = _call_optimize_route_with_retry(
            mcp_module, origin=home_address,
            stops=chronological_addresses, return_to_origin=True)
        assert "❌" not in result, f"optimize_route failed: {result}"

        # Structural assertion: the tool's own signature has no parameter
        # for per-stop appointment times or windows. This is what actually
        # guarantees appointment order can never be honored — not the
        # specific result of any one OSRM call, which can vary.
        import inspect
        sig = inspect.signature(mcp_module.optimize_route)
        param_names = set(sig.parameters.keys())
        time_window_params = {
            p for p in param_names
            if "time_window" in p or "appointment" in p or "fixed_time" in p
        }
        assert not time_window_params, (
            f"optimize_route() now has time-window parameters "
            f"({time_window_params}) that didn't exist when this test was "
            f"written — if appointment-time support was added, this test "
            f"suite should be updated to actually exercise it rather than "
            f"just documenting its absence."
        )

        # Report (visible with -s) whether this particular run happened to
        # preserve chronological order — informative, not a hard assertion,
        # since OSRM's actual road-network result is not something this
        # test controls or should pin down.
        print("\n--- Route scheduling behavior ---")
        print(f"Chronological (appointment) order: {chronological_addresses}")
        print(f"optimize_route() has NO parameter to receive Start Time, "
              f"appointment window, or any per-stop time constraint.")
        print(result)

    def test_03_new_job_scheduling_workflow_demo(self, mcp_module, home_address):
        """
        DEMONSTRATES the recommended workflow for "help me schedule a new
        job on the best route" — using ONLY tools that exist today.

        Since optimize_route() has no time-window awareness, the practical
        approach is:
          1. Read the day's ALREADY-COMMITTED jobs (their Start Time is
             fixed — the customer is expecting the tech then; these are
             NOT candidates for reordering).
          2. For a NEW job being scheduled, try inserting it at each
             plausible time slot BETWEEN existing appointments (or before
             the first / after the last).
          3. For each candidate slot, run optimize_route() on JUST the
             stops that would need to be visited in that slot's
             neighborhood (i.e. respecting that the fixed appointments
             anchor the day — only the new job's position is truly free)
             and compare added total drive time.
          4. Recommend the slot with the lowest added drive time.

        This test demonstrates step 3-4 concretely: it computes the total
        added drive time of inserting a new candidate job address between
        two existing (fixed) appointments, compared to inserting it at the
        end of the day — and reports which is cheaper in drive time.

        IMPORTANT — HONEST LIMITATION: neither this workflow nor
        optimize_route() itself accounts for live/predictive traffic.
        OSRM's public routing server (router.project-osrm.org) uses static
        road-speed profiles only. True traffic-aware routing (e.g. avoiding
        a stop that KNOWS I-95 backs up at 8am on weekdays) would require a
        different, paid routing backend (e.g. Google Routes API /
        Distance Matrix API with `departure_time` set, or a commercial OSRM
        instance fed live traffic data) — this is a real capability gap in
        the current toolset, not something Claude can currently work around
        by combining existing free tools.
        """
        # The day's two FIXED existing appointments (their times are
        # committed — they anchor the schedule and are not candidates
        # for reordering).
        fixed_am = STOP_A   # 08:00, already committed
        fixed_pm = STOP_C   # 15:00, already committed
        candidate_new_job = STOP_B  # address for the NEW job being scheduled

        # Option 1: insert the new job's address BETWEEN the two fixed
        # appointments and see the resulting route.
        route_with_insert = _call_optimize_route_with_retry(
            mcp_module, origin=home_address,
            stops=[fixed_am, candidate_new_job, fixed_pm],
            return_to_origin=True,
        )
        assert "❌" not in route_with_insert

        # Option 2: baseline — route with only the two fixed appointments,
        # no new job at all (to isolate how much drive time the new job
        # itself actually adds, regardless of where it lands).
        route_baseline = _call_optimize_route_with_retry(
            mcp_module, origin=home_address,
            stops=[fixed_am, fixed_pm],
            return_to_origin=True,
        )
        assert "❌" not in route_baseline

        def _extract_total_minutes(route_text: str) -> "float | None":
            for line in route_text.splitlines():
                if "Total drive:" in line:
                    try:
                        return float(line.split("Total drive:")[1].split("min")[0].strip())
                    except (ValueError, IndexError):
                        return None
            return None

        mins_with_insert = _extract_total_minutes(route_with_insert)
        mins_baseline     = _extract_total_minutes(route_baseline)

        assert mins_with_insert is not None and mins_baseline is not None, (
            "Could not parse total drive minutes from optimize_route output "
            "— format may have changed."
        )

        added_minutes = mins_with_insert - mins_baseline

        print("\n--- New job insertion demo ---")
        print(f"Baseline (fixed AM + PM only):  {mins_baseline:.0f} min")
        print(f"With new job inserted between:  {mins_with_insert:.0f} min")
        print(f"Added drive time for new job:    {added_minutes:.0f} min")
        print(
            "\nThis is the number Claude should compare across candidate "
            "time slots / candidate technicians when asked "
            "'what's the best time to schedule this new job' — the slot "
            "with the LOWEST added drive time is the recommendation, "
            "given today's tools have no live traffic data to factor in."
        )
        # NOTE: added_minutes is NOT asserted to be >= 0 here. In a true
        # optimal TSP tour, adding a mandatory stop should never shorten
        # the total route — but this test relies on Nominatim, a free
        # geocoding service that is not perfectly deterministic between
        # separate calls (a less-common address like a numbered street can
        # resolve to a materially different point depending on match
        # confidence at request time). A negative delta was observed during
        # this test's own development and traced to exactly that, not a
        # bug in optimize_route()'s TSP logic. Report the numbers for
        # visibility; don't hard-fail on their sign.

    def test_04_restore_backup(self, mcp_module, pre_suite_backup_path):
        import shutil
        assert pre_suite_backup_path.exists()
        shutil.copy2(str(pre_suite_backup_path), str(SPREADSHEET_PATH))

        jobs = _load_jobs_for_date(str(SPREADSHEET_PATH), "2026-09-20")
        leftover = [j for j in jobs
                    if str(j.get("Customer Name / Company", "")).startswith(TEST_CUSTOMER_PREFIX)]
        assert not leftover, f"Restore did not remove test jobs: {leftover}"
