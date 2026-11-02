"""booking_db + schema + job states — service booking Phase 0 (booking-spec.md §5, §8, §11).

A real temporary Jobs database. Dates are in March 2027 so the Jobs app's overrun
rule (which looks at the real today) can never touch them.
Run: run_tests.bat tests\\unit\\test_booking_db.py
"""
import datetime as dt
import pathlib
import sqlite3
import sys
import threading

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import booking_db as bdb  # noqa: E402
import booking_slots as bs  # noqa: E402
import db_write_ops  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

NOW = dt.datetime(2027, 3, 1, 6, 0)            # Monday
TUE = dt.date(2027, 3, 2)
ALL = ["07:00", "09:00", "11:00", "13:00", "15:00"]


@pytest.fixture
def jobs_db(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    conn = get_connection(path)
    conn.executemany("INSERT INTO service_pricing (service_code, category, name, base_price, min_charge) "
                     "VALUES (?, ?, ?, ?, ?)",
                     [("WIN-EXT", "Windows", "Exterior windows", 150.0, 95.0),
                      ("GUT", "Gutters", "Gutter clean", 120.0, None),
                      ("PRESS", "Pressure", "Driveway wash", 200.0, 180.0)])
    conn.close()
    bdb.sync_services(path)
    bdb.update_service(path, "WIN-EXT", online=True, minutes=60, buffer_min=15)
    return path


def add_job(db, job_id, date, *, start="", hard=False, est=1, unit="hour", status="Scheduled", end_date="",
            created_by="tester"):
    conn = get_connection(db)
    conn.execute("INSERT INTO jobs (job_id, customer_name, service_date, end_date, start_time, est_duration, "
                 "est_duration_unit, schedule_type, job_status, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                 (job_id, "Test", date, end_date, start, est, unit, "Hard" if hard else "Soft", status, created_by))
    conn.close()


def starts(db, **kw):
    kw.setdefault("now", NOW)
    return [bs.fmt(w.start) for w in bdb.windows_for(db, "WIN-EXT", from_date=TUE, to_date=TUE, **kw)]


# ── schema and job states ────────────────────────────────────────────────────

def test_booking_tables_exist_and_schema_reapplies_cleanly(jobs_db):
    init_db(jobs_db)                                              # idempotent
    conn = sqlite3.connect(jobs_db)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert {"booking_services", "booking_holds", "booking_requests", "booking_openings", "booking_waitlist",
            "calendar_busy", "calendar_sync_queue", "calendar_sync_log"} <= names


def test_new_job_states_have_their_own_words_and_pending_still_means_scheduled():
    canon = lambda v: db_write_ops._canon_choice("jobs", "job_status", "Job Status", v)[0]  # noqa: E731
    assert canon("pending approval") == "Pending Approval" and canon("to approve") == "Pending Approval"
    assert canon("suggested") == "Suggested" and canon("requested") == "Requested"
    assert canon("declined") == "Declined"
    assert canon("pending") == "Scheduled" and canon("booked") == "Scheduled"   # unchanged
    assert db_write_ops.job_is_open("Declined") is False and db_write_ops.job_is_open("declined") is False
    for s in ("Pending Approval", "Suggested", "Requested", "Scheduled"):
        assert db_write_ops.job_is_open(s) is True


def test_jobs_app_form_keeps_booking_states_instead_of_turning_them_into_scheduled():
    """A booking waiting for approval has no date. The Jobs form used to open any dateless job
    as "Unscheduled" and save it as "Scheduled" — that would skip the owner's approval."""
    html = (ROOT / "jobs" / "index.html").read_text(encoding="utf-8")
    sel = html[html.index('<select id="jfStatus"'):html.index("</select>", html.index('<select id="jfStatus"'))]
    for s in ("Pending Approval", "Suggested", "Requested", "Declined"):
        assert f"<option>{s}</option>" in sel
    opener = html[html.index("var _keep = ["):html.index("var _keep = [") + 200]
    assert all(s in opener for s in ("Pending Approval", "Suggested", "Requested", "Declined"))
    assert "/^(complete|cancelled|canceled|declined)$/i.test(_jfStatusVal)" in html


# ── services from Services & Pricing ─────────────────────────────────────────

def test_services_follow_services_and_pricing(jobs_db):
    rows = {s["code"]: s for s in bdb.list_services(jobs_db)}
    assert set(rows) == {"WIN-EXT", "GUT", "PRESS"}
    assert [s["code"] for s in bdb.list_services(jobs_db, online_only=True)] == ["WIN-EXT"]
    assert rows["WIN-EXT"]["price"] == "from $95" and rows["GUT"]["price"] == "from $120"
    bdb.update_service(jobs_db, "PRESS", price_display="exact", label="Driveway pressure wash", mode="request")
    p = next(s for s in bdb.list_services(jobs_db) if s["code"] == "PRESS")
    assert p["price"] == "$200" and p["name"] == "Driveway pressure wash" and p["mode"] == "request"
    bdb.update_service(jobs_db, "GUT", price_display="none")
    assert next(s for s in bdb.list_services(jobs_db) if s["code"] == "GUT")["price"] == ""
    conn = get_connection(jobs_db)
    conn.execute("DELETE FROM service_pricing WHERE service_code = 'GUT'")
    conn.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES ('SOLAR', 'Solar panels', 99)")
    conn.close()
    assert bdb.sync_services(jobs_db) == {"added": 1, "removed": 1}
    rows = {s["code"]: s for s in bdb.list_services(jobs_db)}
    assert "GUT" not in rows and rows["SOLAR"]["online"] is False          # new ones start hidden


@pytest.mark.parametrize("field,value,msg", [("minutes", 5, "minutes must be 15–600"),
                                             ("people", 0, "people needed must be 1–20"),
                                             ("price_display", "free", "price display must be one of"),
                                             ("mode", "maybe", "bookable must be one of"),
                                             ("colour", "red", "unknown service setting")])
def test_service_settings_are_checked(jobs_db, field, value, msg):
    with pytest.raises(bdb.BookingError, match=msg):
        bdb.update_service(jobs_db, "WIN-EXT", **{field: value})
    with pytest.raises(bdb.BookingError, match="no service NOPE"):
        bdb.update_service(jobs_db, "NOPE", online=True)


# ── rules come from the Jobs app + Service Desk settings ─────────────────────

def test_rules_follow_jobs_settings_and_booking_settings(jobs_db):
    r = bdb.rules_for(jobs_db)
    assert (r.day_start, r.day_end, r.lunch_start, r.lunch_minutes) == (420, 1020, 720, 60)
    assert r.working_days == frozenset(range(5))
    conn = get_connection(jobs_db)
    conn.executemany("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                     [("Workday Start Time", "8:00 AM"), ("Workday End Time", "16:00"),
                      ("Lunch Break Duration (min)", "0"), ("Working Days", "Mon-Sat")])
    conn.close()
    r = bdb.rules_for(jobs_db, {"booking_window_minutes": 90, "booking_lead_hours": 2, "booking_full_pct": 100})
    assert (r.day_start, r.day_end, r.lunch_start) == (480, 960, None) and 5 in r.working_days
    assert (r.window_minutes, r.lead_hours, r.full_pct) == (90, 2.0, 100)


# ── what's booked → open windows ─────────────────────────────────────────────

def test_jobs_on_the_day_shape_the_windows(jobs_db):
    assert starts(jobs_db) == ALL
    add_job(jobs_db, "JOB-1", TUE.isoformat(), start="09:00", hard=True, est=2)       # blocks 9–11
    assert starts(jobs_db) == ["07:00", "11:00", "13:00", "15:00"]
    add_job(jobs_db, "JOB-2", TUE.isoformat(), est=6)                                  # soft 6 h: 480 of 540 used
    assert starts(jobs_db) == []                                                       # ≥ 85 % full
    conn = get_connection(jobs_db)
    conn.execute("UPDATE jobs SET job_status = 'Cancelled' WHERE job_id = 'JOB-2'")
    conn.close()
    assert starts(jobs_db) == ["07:00", "11:00", "13:00", "15:00"]                     # cancelled frees it at once


def test_multi_day_jobs_fill_each_working_day_they_cover(jobs_db):
    add_job(jobs_db, "JOB-M", "2027-03-01", est=3, unit="day", end_date="2027-03-03")
    assert starts(jobs_db) == []                                                       # Tue is mid-job


def test_web_bookings_count_towards_the_daily_limit(jobs_db):
    add_job(jobs_db, "JOB-W", TUE.isoformat(), est=1, created_by=bdb.WEB_BOOKING)
    assert starts(jobs_db, booking={"booking_max_per_day": 1}) == []
    assert starts(jobs_db, booking={"booking_max_per_day": 2}) == ALL


def test_openings_and_closed_days(jobs_db):
    sat = dt.date(2027, 3, 6)
    assert bdb.windows_for(jobs_db, "WIN-EXT", now=NOW, from_date=sat, to_date=sat) == []
    bdb.add_opening(jobs_db, "open", sat.isoformat(), "08:00", "12:00", note="catch-up Saturday")
    assert [bs.fmt(w.start) for w in bdb.windows_for(jobs_db, "WIN-EXT", now=NOW, from_date=sat,
                                                       to_date=sat)] == ["08:00", "10:00"]
    oid = bdb.add_opening(jobs_db, "closed", TUE.isoformat(), note="holiday")
    assert starts(jobs_db) == []
    assert bdb.delete_opening(jobs_db, oid) and starts(jobs_db) == ALL
    for args, msg in [(("open", TUE.isoformat()), "needs a start and end"),
                      (("shut", TUE.isoformat()), "kind must be one of"),
                      (("closed", "03/02/2027"), "YYYY-MM-DD"),
                      (("open", TUE.isoformat(), "10:00", "09:00"), "end time must be after"),
                      (("closed", TUE.isoformat(), "nine"), "look like 08:00")]:
        with pytest.raises(bdb.BookingError, match=msg):
            bdb.add_opening(jobs_db, *args)


def test_only_online_services_can_be_booked_from_the_page(jobs_db):
    with pytest.raises(bdb.BookingError, match="isn't a service offered online"):
        bdb.windows_for(jobs_db, "GUT", now=NOW)
    assert bdb.windows_for(jobs_db, "GUT", now=NOW, online_only=False, from_date=TUE, to_date=TUE)   # staff can


# ── holds: the re-check stops double-booking ─────────────────────────────────

def test_hold_rechecks_and_blocks_and_expires(jobs_db):
    bdb.update_service(jobs_db, "WIN-EXT", minutes=420, buffer_min=0)   # one per day (7 h of 9 h)
    key = "2027-03-02T07:00-09:00"
    first = bdb.hold_window(jobs_db, "WIN-EXT", key, now=NOW)
    assert first and first["crew"] == "owner" and first["minutes"] == 420 and first["kind"] == "checkout"
    assert bdb.hold_window(jobs_db, "WIN-EXT", key, now=NOW) is None             # already taken
    assert starts(jobs_db) == []                                                  # the whole day is now held
    assert bdb.extend_hold(jobs_db, first["hold_id"], kind="pending", minutes_to_live=48 * 60, job_id="JOB-9",
                           now=NOW)
    h = bdb.get_hold(jobs_db, first["hold_id"])
    assert h["kind"] == "pending" and h["job_id"] == "JOB-9"
    assert bdb.expire_holds(jobs_db, now=NOW + dt.timedelta(hours=47)) == []      # still held
    gone = bdb.expire_holds(jobs_db, now=NOW + dt.timedelta(hours=49))
    seven_hours = ["07:00", "09:00"]               # a 7-hour job (+ lunch) can only start in these windows
    assert [g["hold_id"] for g in gone] == [first["hold_id"]] and starts(jobs_db) == seven_hours
    second = bdb.hold_window(jobs_db, "WIN-EXT", key, now=NOW)
    assert second and bdb.release_hold(jobs_db, second["hold_id"]) and starts(jobs_db) == seven_hours
    assert bdb.hold_window(jobs_db, "WIN-EXT", "2027-03-02T08:00-10:00", now=NOW) is None   # not a real window


def test_two_people_racing_for_the_last_window_only_one_gets_it(jobs_db):
    bdb.update_service(jobs_db, "WIN-EXT", minutes=420, buffer_min=0)
    key = "2027-03-02T07:00-09:00"
    got, start = [], threading.Barrier(4)

    def book():
        start.wait()
        got.append(bdb.hold_window(jobs_db, "WIN-EXT", key, now=NOW))

    threads = [threading.Thread(target=book) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for g in got if g) == 1 and got.count(None) == 3


# ── business calendar busy times: personal only ──────────────────────────────

def test_business_calendar_blocks_on_a_personal_install_only(jobs_db):
    blocks = [{"start": "2027-03-02T13:00", "end": "2027-03-02T17:00"}]
    assert bdb.replace_busy(jobs_db, "2027-03-01", "2027-03-07", blocks) == 1
    assert starts(jobs_db, edition="solo") == ["07:00", "09:00"]
    assert starts(jobs_db, edition="business") == ALL                            # server: Jobs app only
    with pytest.raises(bdb.BookingError, match="Jobs app calendar only"):
        bdb.replace_busy(jobs_db, "2027-03-01", "2027-03-07", blocks, edition="business")
    assert bdb.replace_busy(jobs_db, "2027-03-01", "2027-03-07", []) == 0          # deleted on Google → freed
    assert starts(jobs_db) == ALL
    bdb.replace_busy(jobs_db, "2027-03-01", "2027-03-07",
                     [{"start": "2027-03-02T00:00", "end": "2027-03-03T00:00", "all_day": True}])
    assert starts(jobs_db) == []
    assert bdb.last_busy_sync(jobs_db)
    with pytest.raises(bdb.BookingError, match="end after it starts"):
        bdb.replace_busy(jobs_db, "2027-03-01", "2027-03-07", [{"start": "2027-03-02T10:00", "end": "2027-03-02T09:00"}])


def test_page_json_never_shows_the_crew(jobs_db):
    out = bdb.to_json(bdb.windows_for(jobs_db, "WIN-EXT", now=NOW, from_date=TUE, to_date=TUE))
    assert out[0] == {"key": "2027-03-02T07:00-09:00", "date": "2027-03-02", "start": "07:00", "end": "09:00",
                      "label": "Tue 02 Mar, 7–9"}
    assert all("crew" not in w and "free_minutes" not in w for w in out)


# ── shipped: the installer and both update scripts carry the booking files ──

@pytest.mark.parametrize("ship", ["AI-Prowler-Setup.iss", "update_install.bat", "update_install_server.bat",
                                  "scripts/release.py"])
def test_booking_files_are_installed_and_updated(ship):
    text = (ROOT / ship).read_text(encoding="utf-8", errors="replace")
    for f in ("booking_slots.py", "booking_db.py", "booking_flow.py"):
        assert f in text, f"{f} missing from {ship} — it would never reach users"


# ── booking rules in Service Desk settings ───────────────────────────────────

def test_booking_rule_settings_are_range_checked(tmp_path):
    import desk_db
    db = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(db)
    s = desk_db.get_settings(db)
    assert (s["booking_window_minutes"], s["booking_lead_hours"], s["booking_horizon_days"],
            s["booking_max_per_day"], s["booking_full_pct"]) == (120, 24, 21, 0, 85)
    desk_db.set_setting(db, "booking_window_minutes", 90, edition="solo")
    for key, bad in [("booking_window_minutes", 10), ("booking_horizon_days", 400), ("booking_full_pct", 5),
                     ("booking_lead_hours", -1)]:
        with pytest.raises(desk_db.DeskError, match=f"{key} must be"):
            desk_db.set_setting(db, key, bad, edition="solo")
    import desk_tools
    assert all(k in desk_tools.SETTING_HELP for k in desk_db.BOOKING_RANGES)


# ── services vs products (2026-11-02, David: "2 types ... services and ... products") ──────────────────

def test_a_product_is_never_booked_online(jobs_db):
    import desk_gui_settings as dgs
    bdb.update_service(jobs_db, "GUT", online=True)
    assert dgs.set_type(jobs_db, "GUT", "Product") == (True, "Saved — customers can ask for it; it isn't offered "
                                                              "for booking.")
    row = next(r for r in bdb.list_services(jobs_db) if r["code"] == "GUT")
    assert row["mode"] == "request" and dgs.service_type(row) == "product"
    with pytest.raises(bdb.BookingError, match="can't be booked online"):
        bdb.windows_for(jobs_db, "GUT", now=NOW, from_date=TUE, to_date=TUE)
    # the office can still put it on the schedule by hand
    assert bdb.service(jobs_db, "GUT", online_only=False).code == "GUT"
    assert dgs.set_type(jobs_db, "GUT", "Service")[0]
    assert bdb.windows_for(jobs_db, "GUT", now=NOW, from_date=TUE, to_date=TUE)


def test_outdoor_is_set_per_service_and_never_on_a_product(jobs_db):
    """David 2026-11-02: "make that configurable so different services companies can turn it on or off"."""
    import desk_gui_settings as dgs
    out = lambda code: next(r for r in bdb.list_services(jobs_db) if r["code"] == code)["outdoor"]  # noqa: E731
    assert out("WIN-EXT") is False and out("GUT") is False                   # off until the business ticks it
    assert dgs.set_outdoor(jobs_db, "WIN-EXT", True)[0] and out("WIN-EXT") is True
    assert out("GUT") is False                                               # one service at a time
    assert dgs.set_outdoor(jobs_db, "WIN-EXT", False)[0] and out("WIN-EXT") is False
    assert dgs.set_outdoor(jobs_db, "GUT", True)[0]
    assert dgs.set_type(jobs_db, "GUT", "Product")[0] and out("GUT") is False  # a product loses the tick
    ok, msg = dgs.set_outdoor(jobs_db, "GUT", True)
    assert not ok and "set its Type to Service first" in msg and out("GUT") is False


def test_services_count_follows_the_ticks():
    import desk_gui_settings as dgs
    assert dgs.services_count_text({"A": False}).startswith("0 of 1 shown on the page.")
    assert dgs.services_count_text({"A": True, "B": False}).startswith("1 of 2 shown on the page.")
