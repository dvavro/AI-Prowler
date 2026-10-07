"""Phone tap-to-navigate link built after BOTH route engines (2026-09-21).

_publish_route_links() reads the stored route_stops for a date and builds the
Google Maps link the phone opens:
  * NO origin  -> Google starts from the phone's live GPS location (not a stop);
  * stops = the jobs in order (+ the Start/End Address at both ends in Company
    Location mode); the day's "Home" bookend rows are mileage markers, skipped;
  * destination = the user's/owner's home address (unless the last stop is
    already that same place); with no home on file it ends at the last stop;
  * the link is saved on every job in the route and on its route_stops rows.
"""
import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

DATE = "2026-09-21"
HOME = {"street": "1500 Shadow Pines Dr", "city": "New Smyrna Beach", "state": "FL", "zip": "32168"}
JOB1_ADDR = "300 Riverside Dr, New Smyrna Beach, FL 32168"
JOB2_ADDR = "421 Faulkner St, New Smyrna Beach, FL 32168"
COMPANY_ADDR = "1500 Shadow Pines Dr, New Smyrna Beach, Florida 32168"


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(tmp_path / "x.xlsx"))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address", lambda: dict(HOME))
    return tmp_path / "ai_prowler_jobs.db"


def _make_job(mcp_mod, customer, street, lat, lon):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_result = mcp_mod.create_customer({"Company Name": customer}, filepath="", backup=False, ctx=None)
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    out = mcp_mod.create_job({
        "CustomerID": cust_id, "Customer Name / Company": customer, "Service Date": DATE,
        "Street Address": street, "City": "New Smyrna Beach", "State": "FL",
        "Latitude (AI Geocode)": lat, "Longitude (AI Geocode)": lon,
    }, filepath="", backup=False, ctx=None)
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _stop(job_id, address, lat=29.0, lon=-80.9):
    return {"crew": "", "job_id": job_id, "cust_id": None, "address": address,
            "lat": lat, "lon": lon, "arrival": "08:00",
            "leg_drive_min": 5, "leg_drive_miles": 1.0, "map_url": None}


def _write_route(db_path, stops):
    from db_route_ops import db_write_route_stops
    db_write_route_stops(str(db_path), DATE, stops, "test", single_crew=True)


def _link_parts(note):
    url = next(ln.strip() for ln in note.splitlines() if ln.strip().startswith("http"))
    q = parse_qs(urlparse(url).query)
    waypoints = q.get("waypoints", [""])[0].split("|") if q.get("waypoints") else []
    return url, q, waypoints


def test_jobs_only_link_has_no_origin_jobs_in_order_and_ends_at_home(env, mcp_mod):
    j1 = _make_job(mcp_mod, "Riverside", "300 Riverside Dr", 29.02, -80.92)
    j2 = _make_job(mcp_mod, "Coastal", "421 Faulkner St", 29.03, -80.93)
    _write_route(env, [
        _stop(j1, JOB1_ADDR), _stop(j2, JOB2_ADDR),
        # trailing return-to-home bookend row (Jobs Only): a mileage marker, not a stop
        {**_stop(None, "Home"), "job_id": None},
    ])
    note = mcp_mod._publish_route_links(str(env), DATE, "", None, "test")
    assert note.startswith("📍")
    url, q, waypoints = _link_parts(note)
    assert "origin" not in q                      # open start -> phone GPS
    assert waypoints == [JOB1_ADDR, JOB2_ADDR]    # jobs in order; first job = first waypoint
    assert q["destination"][0].startswith("1500 Shadow Pines Dr")   # ends at home
    assert "Home" not in url.replace("Shadow", "")  # bookend row never becomes a stop
    assert "dir_action=navigate" in url


def test_link_saved_on_jobs_and_route_stops(env, mcp_mod):
    j1 = _make_job(mcp_mod, "Riverside", "300 Riverside Dr", 29.02, -80.92)
    _write_route(env, [_stop(j1, JOB1_ADDR)])
    note = mcp_mod._publish_route_links(str(env), DATE, "", None, "test")
    url, _, _ = _link_parts(note)
    conn = sqlite3.connect(env)
    assert conn.execute("SELECT route_map_url FROM jobs WHERE job_id = ?", (j1,)).fetchone()[0] == url
    assert conn.execute("SELECT map_url FROM route_stops WHERE route_date = ?", (DATE,)).fetchone()[0] == url
    conn.close()


def test_two_jobs_at_same_address_are_both_kept(env, mcp_mod):
    # 2026-09-25: both JOBS are kept (each gets the link), but the address is
    # no longer repeated back-to-back in the link — "same address twice" is
    # exactly what made Google Maps open a stop list instead of a route (9/24).
    j1 = _make_job(mcp_mod, "A", "1755 State Road 44", 29.01, -80.94)
    j2 = _make_job(mcp_mod, "B", "1755 State Road 44", 29.01, -80.94)
    addr = "1755 State Road 44, New Smyrna Beach, FL 32168"
    _write_route(env, [_stop(j1, addr), _stop(j2, addr)])
    note = mcp_mod._publish_route_links(str(env), DATE, "", None, "test")
    _, q, waypoints = _link_parts(note)
    assert waypoints == [addr]                    # once, not twice
    assert "saved on 2 job(s)" in note            # both jobs still kept


def test_company_location_start_end_are_stops_then_home(env, mcp_mod, monkeypatch):
    # Different home than the Start/End Address -> link continues on to home.
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                        lambda: {"street": "77 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"})
    j1 = _make_job(mcp_mod, "Riverside", "300 Riverside Dr", 29.02, -80.92)
    _write_route(env, [
        _stop(None, COMPANY_ADDR),                # Start/End Address = real first stop
        _stop(j1, JOB1_ADDR),
        _stop(None, COMPANY_ADDR),                # ... and real last stop
    ])
    note = mcp_mod._publish_route_links(str(env), DATE, "", None, "test")
    _, q, waypoints = _link_parts(note)
    assert "origin" not in q
    assert waypoints == [COMPANY_ADDR, JOB1_ADDR, COMPANY_ADDR]
    assert q["destination"][0].startswith("77 Ocean Ave")


def test_company_location_home_same_as_start_end_is_not_repeated(env, mcp_mod):
    j1 = _make_job(mcp_mod, "Riverside", "300 Riverside Dr", 29.02, -80.92)
    _write_route(env, [_stop(None, COMPANY_ADDR), _stop(j1, JOB1_ADDR), _stop(None, COMPANY_ADDR)])
    note = mcp_mod._publish_route_links(str(env), DATE, "", None, "test")
    _, q, waypoints = _link_parts(note)
    assert waypoints == [COMPANY_ADDR, JOB1_ADDR]
    assert q["destination"][0].startswith("1500 Shadow Pines Dr")   # the return stop IS home


def test_no_home_on_file_ends_at_last_stop(env, mcp_mod, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address", lambda: {})
    j1 = _make_job(mcp_mod, "Riverside", "300 Riverside Dr", 29.02, -80.92)
    j2 = _make_job(mcp_mod, "Coastal", "421 Faulkner St", 29.03, -80.93)
    _write_route(env, [_stop(j1, JOB1_ADDR), _stop(j2, JOB2_ADDR)])
    note = mcp_mod._publish_route_links(str(env), DATE, "", None, "test")
    _, q, waypoints = _link_parts(note)
    assert waypoints == [JOB1_ADDR]
    assert q["destination"][0] == JOB2_ADDR
    assert "no home address on file" in note


def test_with_route_link_passes_failures_through_untouched(env, mcp_mod):
    assert mcp_mod._with_route_link("❌ nope", str(env), DATE, "", None, "test") == "❌ nope"
    assert mcp_mod._with_route_link("✅ nothing to suggest", str(env), DATE, "", None, "test") == "✅ nothing to suggest"


# ── 2026-09-25: back-to-back stops at one address (the 9/24 live bug) ──────────
SR44_ADDR = "1755 State Road 44, New Smyrna Beach, FL 32168"


def test_back_to_back_same_address_appears_once_but_both_jobs_get_link(env, mcp_mod):
    j1 = _make_job(mcp_mod, "Riverside", "300 Riverside Dr", 29.02, -80.92)
    j2 = _make_job(mcp_mod, "SR44 A", "1755 State Road 44", 29.03, -80.95)
    j3 = _make_job(mcp_mod, "SR44 B", "1755 State Road 44", 29.03, -80.95)
    j4 = _make_job(mcp_mod, "Coastal", "421 Faulkner St", 29.03, -80.93)
    _write_route(env, [_stop(j1, JOB1_ADDR), _stop(j2, SR44_ADDR),
                       _stop(j3, SR44_ADDR), _stop(j4, JOB2_ADDR)])
    note = mcp_mod._publish_route_links(str(env), DATE, "", None, "test")
    url, q, waypoints = _link_parts(note)
    assert waypoints == [JOB1_ADDR, SR44_ADDR, JOB2_ADDR]     # SR44 once, not twice
    assert "saved on 4 job(s)" in note                          # every job still gets the link
    import sqlite3 as _sq
    con = _sq.connect(str(env))
    try:
        urls = {r[0] for r in con.execute(
            "SELECT route_map_url FROM jobs WHERE job_id IN (?,?,?,?)", (j1, j2, j3, j4))}
    finally:
        con.close()
    assert urls == {url}


def test_same_stop_matching_is_strict():
    import ai_prowler_mcp as ap
    same = ap._route_same_stop
    assert same(SR44_ADDR, "1755 SR 44, New Smyrna Beach, FL 32168")
    assert same(SR44_ADDR, "1755 State Rd. 44, New Smyrna Beach, Florida 32168")
    assert not same(SR44_ADDR, "1755 State Road 46, New Smyrna Beach, FL 32168")   # different road
    assert not same(SR44_ADDR, "1755 State Road 44, Deland, FL 32720")             # different ZIP
    assert not same("29.03,-80.95", "29.03,-80.99")                                 # coords: exact only
    assert same("29.03,-80.95", "29.03,-80.95")
