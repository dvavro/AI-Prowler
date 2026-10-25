"""Mileage tracker — db_mileage_ops unit tests (spec test plan MI-01..MI-53).

Every test builds its own scratch SQLite database with the real
db_schema.apply_schema under tmp_path — never the live Jobs app database —
and replaces the network hooks (OSRM, geocoder, home address) with fakes,
so no test consumes real TRIP-/VEH- numbers or touches the internet.

Run: py -m pytest tests\\mcp_tests\\test_mileage_ops.py -v
"""
import datetime as dt
import sys
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SRC_ROOT))

import db_mileage_ops as mo  # noqa: E402
from db_access import get_connection  # noqa: E402
from db_schema import apply_schema  # noqa: E402

# Places on a simple grid; 1 unit of lat/lon distance = 10 miles (fake router).
PLACES = {
    "HOME ADDR": (0.0, 0.0),
    "COMPANY ADDR": (0.0, 1.0),
    "Home Depot": (0.5, 0.0),
    "Bank": (0.0, 0.3),
}
VIN_OK = "1HGCM82633A004352"      # valid check digit
VIN_OK2 = "1M8GDM9AXKP042788"     # valid check digit (X)


def fake_router(a, b):
    if not a or not b:
        return None
    return round((abs(a[0] - b[0]) + abs(a[1] - b[1])) * 10, 1)


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "jobs.db")
    conn = get_connection(path)
    apply_schema(conn)
    conn.close()
    monkeypatch.setattr(mo, "ROUTER", fake_router)
    monkeypatch.setattr(mo, "GEOCODER", lambda addr: PLACES.get(addr))
    monkeypatch.setattr(mo, "HOME_RESOLVER", lambda crew: "HOME ADDR")
    mo._ROUTE_CACHE.clear()
    return path


def _setting(path, key, value):
    conn = get_connection(path)
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.close()


def _company_mode(path):
    _setting(path, "Route Origin Mode", "Company Location")
    _setting(path, "Start/End Street Address", "COMPANY ADDR")
    # db_read_route_address joins components; make the geocoder accept the join.
    PLACES["COMPANY ADDR"] = (0.0, 1.0)


def _job(path, job_id, lat, lon, customer, status="Scheduled", service="Window"):
    conn = get_connection(path)
    conn.execute("INSERT INTO jobs (job_id, customer_name, latitude, longitude, service_type, job_status) "
                 "VALUES (?,?,?,?,?,?)", (job_id, customer, lat, lon, service, status))
    conn.close()


def _entry(path, eid, job_id, day, t_in, t_out, crew="Sam", gps_in="", gps_out=""):
    conn = get_connection(path)
    conn.execute("INSERT INTO time_entries (entry_id, job_id, customer_name, entry_date, clock_in, clock_out, "
                 "crew, clock_in_gps, clock_out_gps) VALUES (?,?,?,?,?,?,?,?,?)",
                 (eid, job_id, job_id, day, f"{day} {t_in}:00", f"{day} {t_out}:00" if t_out else None,
                  crew, gps_in, gps_out))
    conn.close()


def _three_job_day(path, day="2026-10-20"):
    _job(path, "JOB-0001", 1.0, 0.0, "Norwoods")
    _job(path, "JOB-0002", 1.0, 1.0, "Bamboo")
    _job(path, "JOB-0003", 0.0, 2.0, "Copperline")
    _entry(path, "TE-0001", "JOB-0001", day, "08:00", "09:00")
    _entry(path, "TE-0002", "JOB-0002", day, "09:30", "10:30")
    _entry(path, "TE-0003", "JOB-0003", day, "11:00", "12:00")
    return day


def _active(path, day=None):
    conn = get_connection(path)
    q = "SELECT * FROM mileage_trips WHERE status = 'active'"
    rows = conn.execute(q + (" AND trip_date = ?" if day else "") + " ORDER BY seq, trip_id",
                        (day,) if day else ()).fetchall()
    conn.close()
    return rows


# ── Daily build & commuting rule ───────────────────────────────────────────

def test_mi01_jobs_only_all_business(db):
    day = _three_job_day(db)
    s = mo.build_trips_for_day(db, day, "tester")
    rows = _active(db, day)
    assert s["created"] == 4 and len(rows) == 4
    assert [r["classification"] for r in rows] == ["business"] * 4
    assert rows[0]["from_label"] == "Home" and rows[-1]["to_label"] == "Home"
    assert rows[0]["purpose"] == "Window – Norwoods"
    assert sum(r["miles"] for r in rows) == pytest.approx(10 + 10 + 20 + 20)


def test_mi02_company_location_commute_legs(db):
    _company_mode(db)
    day = _three_job_day(db)
    mo.build_trips_for_day(db, day, "tester")
    rows = _active(db, day)
    labels = [(r["from_label"], r["to_label"], r["classification"]) for r in rows]
    assert labels[0] == ("Home", "Company location", "commute")
    assert labels[-1] == ("Company location", "Home", "commute")
    assert all(c == "business" for _, _, c in labels[1:-1])
    assert all(r["origin_mode"] == "Company Location" for r in rows)


def test_mi03_mode_change_keeps_stored_origin_mode(db):
    day = _three_job_day(db)
    mo.build_trips_for_day(db, day, "tester")
    _company_mode(db)
    rows = _active(db, day)
    assert all(r["origin_mode"] == "Jobs Only" for r in rows)
    mo.build_trips_for_day(db, day, "tester")        # explicit rebuild reclassifies
    assert any(r["classification"] == "commute" for r in _active(db, day))


def test_mi04_gps_preferred_address_fallback(db):
    day = "2026-10-21"
    _job(db, "JOB-0001", 1.0, 0.0, "A")
    _job(db, "JOB-0002", 1.0, 1.0, "B")
    _entry(db, "TE-0001", "JOB-0001", day, "08:00", "09:00", gps_in="1.0,0.0", gps_out="1.0,0.0")
    _entry(db, "TE-0002", "JOB-0002", day, "10:00", "11:00", gps_in="", gps_out="")
    mo.build_trips_for_day(db, day, "tester")
    mid = [r for r in _active(db, day) if r["from_label"] == "A"][0]
    assert mid["distance_source"] == "address"


def test_mi05_route_fallback_then_flag(db, monkeypatch):
    day = "2026-10-22"
    _job(db, "JOB-0001", None, None, "Nowhere")
    _entry(db, "TE-0001", "JOB-0001", day, "08:00", "09:00")
    s = mo.build_trips_for_day(db, day, "tester")
    rows = _active(db, day)
    assert rows and all(r["needs_fix"] for r in rows) and all(r["miles"] == 0 for r in rows)
    assert s["gaps"]
    conn = get_connection(db)
    conn.execute("INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, leg_drive_miles) "
                 "VALUES (?,?,?,?,?)", (day, "sam", 1, "JOB-0001", 7.5))
    conn.close()
    mo.build_trips_for_day(db, day, "tester")
    first = _active(db, day)[0]
    assert first["miles"] == 7.5 and first["distance_source"] == "route"


# ── Rates & reports ────────────────────────────────────────────────────────

def test_mi06_mi07_rate_split_at_july_1(db):
    rates = mo.get_rates(db)
    assert mo.rate_cents_for(rates, "2026-06-30") == 72.5
    assert mo.rate_cents_for(rates, "2026-07-01") == 76.0
    mo.add_trip(db, "t", trip_date="2026-06-30", to_label="Bank", purpose="Bank – deposit", miles=10)
    mo.add_trip(db, "t", trip_date="2026-07-01", to_label="Bank", purpose="Bank – deposit", miles=10)
    rep = mo.mileage_report(db, "2026-06-01", "2026-07-31")
    amounts = sorted(round(p["amount"], 2) for p in rep["deduction"].values())
    assert amounts == [7.25, 7.6]
    text = mo.format_report(rep)
    assert "72.5¢" in text and "76¢" in text


def test_mi08_rebuild_is_idempotent(db):
    day = _three_job_day(db)
    mo.build_trips_for_day(db, day, "t")
    ids = [r["trip_id"] for r in _active(db, day)]
    s = mo.build_trips_for_day(db, day, "t")
    assert s["created"] == 0 and s["updated"] == 0
    assert [r["trip_id"] for r in _active(db, day)] == ids


def test_mi09_mi32_edited_trip_survives_rebuild(db):
    day = _three_job_day(db)
    mo.build_trips_for_day(db, day, "t")
    tid = _active(db, day)[1]["trip_id"]
    assert mo.update_trip(db, tid, {"miles": 13}, "detour for fuel", "t").startswith("✅")
    s = mo.build_trips_for_day(db, day, "t")
    assert tid in s["kept_edited"]
    assert [r for r in _active(db, day) if r["trip_id"] == tid][0]["miles"] == 13


def test_mi10_edit_audit_trail(db):
    mo.add_trip(db, "t", trip_date="2026-10-01", to_label="Bank", purpose="Bank – deposit", miles=5)
    tid = _active(db)[0]["trip_id"]
    mo.update_trip(db, tid, {"miles": 6}, "odometer showed 6", "Vicki")
    h = mo.trip_history(db, tid)
    assert h[-1]["field"] == "miles" and h[-1]["old_value"] == "5.0" and h[-1]["new_value"] == "6.0"
    assert h[-1]["edited_by"] == "Vicki" and h[-1]["reason"] == "odometer showed 6"


def test_mi11_void_excluded_but_kept(db):
    mo.add_trip(db, "t", trip_date="2026-10-01", to_label="Bank", purpose="Bank – deposit", miles=5)
    tid = _active(db)[0]["trip_id"]
    assert mo.void_trip(db, tid, "", "t").startswith("❌")
    mo.void_trip(db, tid, "duplicate entry", "t")
    assert mo.mileage_report(db, "2026-10-01", "2026-10-31")["trip_count"] == 0
    rows = mo.export_rows(db, "2026-10-01", "2026-10-31")
    assert rows[0]["Status"] == "void" and rows[0]["Void reason"] == "duplicate entry"


def test_mi12_locked_month(db):
    mo.add_trip(db, "t", trip_date="2026-09-10", to_label="Bank", purpose="Bank – deposit", miles=5)
    tid = _active(db)[0]["trip_id"]
    mo.lock_period(db, "2026-09", "owner")
    assert "locked" in mo.update_trip(db, tid, {"miles": 9}, "fix", "t")
    assert "locked" in mo.add_trip(db, "t", trip_date="2026-09-11", to_label="Bank",
                                   purpose="Bank – deposit", miles=5)
    mo.lock_period(db, "2026-09", "owner", unlock=True)
    assert mo.update_trip(db, tid, {"miles": 9}, "fix", "t").startswith("✅")


def test_mi13_crew_cannot_edit_others(db):
    mo.add_trip(db, "t", trip_date="2026-10-01", to_label="Bank", purpose="Bank – deposit", miles=5, crew="Sam")
    tid = _active(db)[0]["trip_id"]
    assert "own trips" in mo.update_trip(db, tid, {"miles": 6}, "x", "Pat", restrict=True, ukey="pat")
    assert mo.update_trip(db, tid, {"miles": 6}, "x", "Sam", restrict=True, ukey="sam").startswith("✅")


# ── Vehicles ───────────────────────────────────────────────────────────────

def test_mi17_vin_validation():
    assert mo.validate_vin(VIN_OK) == ""
    assert mo.validate_vin(VIN_OK2) == ""
    assert "17" in mo.validate_vin("123")
    assert "I, O, or Q" in mo.validate_vin("1HGCM82633A00435O")
    assert "check digit" in mo.validate_vin("1HGCM82643A004352")


def test_mi18_duplicate_vin(db):
    assert mo.add_vehicle(db, VIN_OK, "t", make="Ford").startswith("✅")
    assert "already exists" in mo.add_vehicle(db, VIN_OK.lower(), "t")


def test_mi14_mi15_five_business_vehicles_warning(db):
    vins = ["1HGCM82633A004352", "1M8GDM9AXKP042788", "JH4KA7650MC012345",
            "1FTFW1ET5DFC10312", "2T1BURHE0JC034552", "5YJ3E1EA7KF317000"]
    good = [v for v in vins if mo.validate_vin(v) == ""]
    if len(good) < 6:
        good = good + []  # fall back to skipping the check digit for the extra test VINs
    vids = []
    for i, v in enumerate(vins):
        own = "crew" if i == 5 else "business"
        r = mo.add_vehicle(db, v, "t", ownership=own, owner_name="Sam" if own == "crew" else "",
                           skip_check_digit=True)
        assert r.startswith("✅"), r
        vids.append(r.split()[2])
    for vid in vids[:4] + vids[5:]:
        mo.add_trip(db, "t", trip_date="2026-10-02", to_label="Bank", purpose="Bank – deposit", miles=3,
                    vehicle_id=vid)
    assert not any("business vehicles" in c for c in mo.mileage_report(db, "2026-10-01", "2026-10-31")["compliance"])
    mo.add_trip(db, "t", trip_date="2026-10-02", to_label="Bank", purpose="Bank – deposit", miles=3,
                vehicle_id=vids[4])
    assert any("5 business vehicles" in c for c in mo.mileage_report(db, "2026-10-01", "2026-10-31")["compliance"])


def test_mi16_crew_owned_is_reimbursable(db):
    vid = mo.add_vehicle(db, VIN_OK, "t", ownership="crew", owner_name="Sam").split()[2]
    mo.add_trip(db, "t", trip_date="2026-10-03", to_label="Bank", purpose="Bank – deposit", miles=10,
                crew="Sam", vehicle_id=vid)
    rep = mo.mileage_report(db, "2026-10-01", "2026-10-31")
    assert rep["deduction"] == {}
    assert rep["reimbursement"]["Sam"]["76¢"]["amount"] == pytest.approx(7.6)


def test_mi19_mi20_form_4562_odometer(db):
    vid = mo.add_vehicle(db, VIN_OK, "t", placed_in_service="2025-03-01").split()[2]
    for i in range(12):
        mo.add_trip(db, "t", trip_date=f"2026-{i + 1:02d}-10", to_label="Bank", purpose="Bank – deposit",
                    miles=1000, vehicle_id=vid)
    mo.add_trip(db, "t", trip_date="2026-05-05", to_label="Company", purpose="Commute to yard",
                miles=1500, vehicle_id=vid, classification="commute")
    rep = mo.mileage_report(db, "2026-01-01", "2026-12-31")
    v = [x for x in rep["vehicles_4562"] if x["year"] == 2026][0]
    assert v["total"] is None and v["personal"] is None
    assert any("odometer" in c for c in rep["compliance"])
    mo.add_odometer(db, vid, 40000, "t", "2026-01-01", "year_start")
    mo.add_odometer(db, vid, 58000, "t", "2026-12-31", "year_end")
    v = [x for x in mo.mileage_report(db, "2026-01-01", "2026-12-31")["vehicles_4562"] if x["year"] == 2026][0]
    assert (v["total"], v["business"], v["commute"], v["personal"]) == (18000, 12000, 1500, 4500)


def test_day_vehicle_applies_to_auto_trips(db):
    vid = mo.add_vehicle(db, VIN_OK, "t").split()[2]
    vid2 = mo.add_vehicle(db, VIN_OK2, "t").split()[2]
    day = _three_job_day(db)
    mo.build_trips_for_day(db, day, "t")
    assert all(r["vehicle_id"] is None for r in _active(db, day))   # 2 vehicles, none chosen
    mo.set_day_vehicle(db, day, "owner", vid2, "t")     # personal mode: the owner drives
    assert all(r["vehicle_id"] == vid2 for r in _active(db, day))


def test_personal_mode_mixed_job_crews_are_one_driver(db):
    """Personal mode: a time entry's crew is the JOB's crew text, which can
    differ per job — the day must still be one continuous chain for the owner."""
    day = "2026-10-23"
    _job(db, "JOB-0001", 1.0, 0.0, "A")
    _job(db, "JOB-0002", 1.0, 1.0, "B")
    _entry(db, "TE-0001", "JOB-0001", day, "08:00", "09:00", crew="David")
    _entry(db, "TE-0002", "JOB-0002", day, "10:00", "11:00", crew="David, Jamie")
    s = mo.build_trips_for_day(db, day, "t")
    rows = _active(db, day)
    assert s["drivers"] == 1 and len(rows) == 3
    assert ("A", "B") in [(r["from_label"], r["to_label"]) for r in rows]
    assert all(mo.user_key(r["crew_user_id"], r["crew"]) == "owner" for r in rows)


def test_server_mode_drivers_kept_apart(db):
    day = "2026-10-24"
    conn = get_connection(db)
    conn.execute("INSERT OR IGNORE INTO users (id) VALUES ('u_sam')")
    conn.execute("INSERT OR IGNORE INTO users (id) VALUES ('u_pat')")
    conn.close()
    _job(db, "JOB-0001", 1.0, 0.0, "A")
    _job(db, "JOB-0002", 1.0, 1.0, "B")
    for eid, job, uid, crew in (("TE-0001", "JOB-0001", "u_sam", "Sam"), ("TE-0002", "JOB-0002", "u_pat", "Pat")):
        conn = get_connection(db)
        conn.execute("INSERT INTO time_entries (entry_id, job_id, entry_date, clock_in, clock_out, crew, "
                     "crew_user_id) VALUES (?,?,?,?,?,?,?)",
                     (eid, job, day, f"{day} 08:00:00", f"{day} 09:00:00", crew, uid))
        conn.close()
    s = mo.build_trips_for_day(db, day, "t")
    assert s["drivers"] == 2
    sam = mo.list_trips(db, day, day, restrict=True, ukey="u_sam")
    assert sam and all(t["crew_user_id"] == "u_sam" for t in sam)
    s2 = mo.build_trips_for_day(db, day, "t", crew_user_id="u_pat", crew="Pat")
    assert s2["drivers"] == 1


# ── Gaps, schedule changes, backfill ──────────────────────────────────────

def test_mi21_missing_clock_out_fix(db):
    day = "2026-10-15"
    _job(db, "JOB-0001", 1.0, 0.0, "A")
    _job(db, "JOB-0002", 1.0, 1.0, "B")
    _entry(db, "TE-0001", "JOB-0001", day, "08:00", None)
    _entry(db, "TE-0002", "JOB-0002", day, "10:00", "11:00")
    mo.build_trips_for_day(db, day, "t")
    gaps = mo.day_gaps(db, day, day)
    assert any(g["type"] == "missing_clock_out" and g["entry_id"] == "TE-0001" for g in gaps)
    assert "reason" in mo.fix_missing_clock_out(db, "TE-0001", "09:15", "", "t")
    res = mo.fix_missing_clock_out(db, "TE-0001", "09:15", "phone died", "Sam")
    assert res.startswith("✅")
    assert not [g for g in mo.day_gaps(db, day, day) if g["type"] == "missing_clock_out"]
    assert not any(r["needs_fix"] for r in _active(db, day))
    conn = get_connection(db)
    note = conn.execute("SELECT notes FROM time_entries WHERE entry_id = 'TE-0001'").fetchone()[0]
    conn.close()
    assert "phone died" in note


def test_mi28_job_dropped_from_day_reconnects(db):
    day = _three_job_day(db)
    mo.build_trips_for_day(db, day, "t")
    conn = get_connection(db)
    conn.execute("DELETE FROM time_entries WHERE entry_id = 'TE-0002'")
    conn.close()
    s = mo.build_trips_for_day(db, day, "t")
    rows = _active(db, day)
    assert s["voided"] >= 1
    assert ("Norwoods", "Copperline") in [(r["from_label"], r["to_label"]) for r in rows]
    assert "Bamboo" not in [r["to_label"] for r in rows]


def test_mi29_cancelled_on_site_kept(db):
    day = "2026-10-16"
    _job(db, "JOB-0001", 1.0, 0.0, "Norwoods", status="Cancelled")
    _entry(db, "TE-0001", "JOB-0001", day, "08:00", "08:05")
    mo.build_trips_for_day(db, day, "t")
    rows = _active(db, day)
    assert rows[0]["classification"] == "business"
    assert rows[0]["purpose"] == "Norwoods – cancelled on site"


def test_mi23_mi24_backfill_preview_then_once(db):
    _three_job_day(db, "2026-03-03")
    pv = mo.backfill(db, "2026-01-01", "2026-10-31", "owner", preview=True)
    assert "Days to build: 1" in pv and not _active(db)
    mo.backfill(db, "2026-01-01", "2026-10-31", "owner", preview=False)
    rows = _active(db)
    assert len(rows) == 4 and all(r["origin"] == "backfill" for r in rows)
    mo.backfill(db, "2026-01-01", "2026-10-31", "owner", preview=False)
    assert len(_active(db)) == 4


def test_locked_day_not_rebuilt(db):
    day = _three_job_day(db)
    mo.lock_period(db, "2026", "owner")
    assert mo.build_trips_for_day(db, day, "t")["skipped_locked"]


# ── Manual / non-job trips ─────────────────────────────────────────────────

def test_mi50_vague_purpose_refused(db):
    r = mo.add_trip(db, "t", trip_date="2026-10-01", to_label="Bank", purpose="business", miles=5)
    assert r.startswith("❌") and "specific" in r


def test_destination_required(db):
    assert "Destination" in mo.add_trip(db, "t", trip_date="2026-10-01", to_label=" ",
                                        purpose="Bank – deposit", miles=5)


def test_mi47_round_trip_two_legs(db):
    r = mo.add_trip(db, "t", trip_date="2026-10-04", from_label="HOME ADDR", to_label="Home Depot",
                    purpose="Supplies – ladders", round_trip=True, category="Supplies")
    rows = _active(db)
    assert r.startswith("✅") and len(rows) == 2
    assert [x["miles"] for x in rows] == [5.0, 5.0]
    assert rows[1]["from_label"] == "Home Depot"


def test_odometer_entry_and_errors(db):
    assert mo.add_trip(db, "t", trip_date="2026-10-04", to_label="Bank", purpose="Bank – deposit",
                       odometer_start=1000, odometer_end=1012).startswith("✅")
    assert _active(db)[0]["miles"] == 12 and _active(db)[0]["distance_source"] == "odometer"
    assert "higher" in mo.add_trip(db, "t", trip_date="2026-10-04", to_label="Bank",
                                   purpose="Bank – deposit", odometer_start=10, odometer_end=5)
    assert "couldn't work out" in mo.add_trip(db, "t", trip_date="2026-10-04", to_label="Unknown St",
                                              purpose="Bank – deposit")


def test_mi33_split_leg(db):
    day = _three_job_day(db)
    mo.build_trips_for_day(db, day, "t")
    leg = [r for r in _active(db, day) if r["from_label"] == "Norwoods"][0]
    r = mo.split_trip(db, leg["trip_id"], "Home Depot", "Supplies – caulk", "stopped for caulk", "Sam")
    assert r.startswith("✅"), r
    labels = [(x["from_label"], x["to_label"]) for x in _active(db, day)]
    assert ("Norwoods", "Home Depot") in labels and ("Home Depot", "Bamboo") in labels
    assert ("Norwoods", "Bamboo") not in labels
    mo.build_trips_for_day(db, day, "t")    # rebuild must not resurrect the original leg
    assert ("Norwoods", "Bamboo") not in [(x["from_label"], x["to_label"]) for x in _active(db, day)]


def test_mi34_edit_needs_reason(db):
    mo.add_trip(db, "t", trip_date="2026-10-01", to_label="Bank", purpose="Bank – deposit", miles=5)
    assert "reason" in mo.update_trip(db, _active(db)[0]["trip_id"], {"miles": 7}, "", "t")


def test_mi52_late_entry_flag(db):
    old = (dt.date.today() - dt.timedelta(days=10)).isoformat()
    r = mo.add_trip(db, "t", trip_date=old, to_label="Bank", purpose="Bank – deposit", miles=5)
    assert "late entry" in r
    trips = mo.list_trips(db, old, old)
    assert trips[0]["late_entry"] is True       # recorded today, 10 days after the trip
    today = dt.date.today().isoformat()
    mo.add_trip(db, "t", trip_date=today, to_label="Bank", purpose="Bank – deposit", miles=5)
    assert mo.list_trips(db, today, today)[0]["late_entry"] is False


def test_mi27_trip_numbers_never_reused(db):
    mo.add_trip(db, "t", trip_date="2026-10-01", to_label="Bank", purpose="Bank – deposit", miles=5)
    first = _active(db)[0]["trip_id"]
    mo.void_trip(db, first, "mistake", "t")
    mo.add_trip(db, "t", trip_date="2026-10-01", to_label="Bank", purpose="Bank – deposit", miles=5)
    second = _active(db)[0]["trip_id"]
    assert first == "TRIP-0001" and second == "TRIP-0002"


def test_mi26_parking_tolls_in_deduction(db):
    mo.add_trip(db, "t", trip_date="2026-10-01", to_label="Bank", purpose="Bank – deposit", miles=10,
                parking_usd=4, tolls_usd=2.5)
    rep = mo.mileage_report(db, "2026-10-01", "2026-10-31")
    assert rep["parking_tolls"] == pytest.approx(6.5)
    assert "$14.10" in mo.format_report(rep)     # 10 × 76¢ = 7.60 + 6.50


@pytest.mark.parametrize("text,miles,dest,cat,rt", [
    ("Home Depot for ladders, 12 miles, round trip", 12, "Home Depot", "Supplies", True),
    ("bank deposit at Chase this afternoon, about 6 miles", 6, "Chase", "Bank", False),
    ("Drove to the Post Office for stamps 4 mi", 4, "Post Office", "Office errand", False),
])
def test_mi47_mi48_parse_text(text, miles, dest, cat, rt):
    p = mo.parse_trip_text(text)
    assert p["miles"] == miles and p["category"] == cat and p["round_trip"] is rt
    assert dest in p["to_label"]
    assert not p["missing"]


def test_mi53_ambiguous_text_asks():
    p = mo.parse_trip_text("drove to the store")
    assert any("miles" in m for m in p["missing"])


def test_tracking_toggle(db):
    assert mo.tracking_enabled(db) is True
    mo.set_tracking_enabled(db, False, "owner")
    assert mo.tracking_enabled(db) is False


def test_schema_migration_is_idempotent(db):
    conn = get_connection(db)
    apply_schema(conn)
    apply_schema(conn)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert {"vehicles", "odometer_readings", "mileage_trips", "mileage_trip_edits",
            "mileage_locks", "mileage_day_vehicles"} <= names
