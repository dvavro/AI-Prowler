"""The one business Google Calendar, synced through an AI (booking-spec.md §6, §13.6; Phase 5):
busy times in (replace the range, AI-Prowler's own events left out), confirmed bookings out
(new / update / cancel, mark synced, retry on error), the stale-calendar fallback to approval,
clash tickets, the four tools, and a server refusing all of it.
Fixed booking clock: Monday 1 Mar 2027, 06:00.
Run: run_tests.bat tests\\unit\\test_booking_calendar.py
"""
import datetime as dt
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import booking_calendar as bc  # noqa: E402
import booking_db as bdb  # noqa: E402
import booking_flow as bf  # noqa: E402
import desk_db  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_tools  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

NOW = dt.datetime(2027, 3, 1, 6, 0)
T7, T9 = "2027-03-02T07:00-09:00", "2027-03-02T09:00-11:00"
ADDR = {"street": "12 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"}
OWNER = {"user_id": "owner", "role": r.OWNER}
S = r.SOLO


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    for k, v in (("portal_enabled", True), ("booking_paths", ["book", "problem"]), ("booking_approval", "auto"),
                 ("calendar_sync", "ai"), ("calendar_name", "Blue Wave Jobs")):
        desk_db.set_setting(tickets, k, v, edition=S)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES ('WIN-EXT', 'Exterior windows', 150)")
    conn.close()
    bdb.sync_services(jobs)
    bdb.update_service(jobs, "WIN-EXT", online=True, minutes=105, buffer_min=15)
    sent = []
    p.send_fn = lambda ch, to, subj, text: sent.append((ch, to, text)) or True
    p.channels_fn = lambda: {"email": True, "sms": True}
    p.jobs_db_fn = lambda: jobs
    bf.clock = lambda: NOW
    yield tickets, jobs, sent
    p.send_fn = p.channels_fn = p.jobs_db_fn = None
    bf.clock = None


def api(db, method, path, body=None, ip="1.2.3.4"):
    st, ct, out = p.route(method, "/support-api" + path, query={}, body=json.dumps(body or {}).encode(),
                          content_type="application/json", ip=ip, db_path=db, edition=S,
                          base_url="https://x.example", business="Blue Wave")
    return st, (json.loads(out) if ct.startswith(b"application/json") else out)


def book(env, key=T9, phone="386-555-0142", ip="1.2.3.4"):
    tickets, _jobs, sent = env
    st, h = api(tickets, "POST", "/hold", {"service_code": "WIN-EXT", "window_key": key}, ip=ip)
    assert st == 200, h
    st, d = api(tickets, "POST", "/start", {"name": "Maria Lopez", "phone": phone}, ip=ip)
    code = re.search(r"\b(\d{6})\b", [t for _c, _to, t in sent if "code is" in t][-1]).group(1)
    st, out = api(tickets, "POST", "/verify", {"contact_id": d["contact_id"], "code": code, "path": "book",
                                                "service_code": "WIN-EXT", "address": ADDR, "hold_id": h["hold_id"],
                                                "window_key": key}, ip=ip)
    assert st == 201, out
    return out


def fresh(env, blocks=()):
    return bc.sync_busy(env[1], "2027-03-01", "2027-03-21", list(blocks), edition=S, tickets_db=env[0])


def keys(env):
    return {w["key"] for w in bf.windows(env[1], desk_db.get_settings(env[0]), "WIN-EXT", S)}


# ── stale picture → approval (§6.4) ──────────────────────────────────────────

def test_never_synced_means_every_booking_waits_for_approval(env):
    st, why = bc.stale(env[1], desk_db.get_settings(env[0]), S)
    assert st and "hasn't been synced" in why
    out = book(env)
    assert out["booking"]["status"] == "pending"


def test_a_fresh_sync_lets_automatic_booking_confirm(env):
    fresh(env)
    assert bc.stale(env[1], desk_db.get_settings(env[0]), S) == (False, "")
    assert book(env)["booking"]["status"] == "scheduled"


def test_an_old_sync_is_stale_again(env):
    fresh(env)
    conn = get_connection(env[1])
    conn.execute("UPDATE calendar_sync_log SET ran_at = '2000-01-01T00:00:00Z'")
    conn.close()
    st, why = bc.stale(env[1], desk_db.get_settings(env[0]), S)
    assert st and "hasn't synced for" in why


def test_sync_off_or_a_server_never_counts_as_stale(env):
    s = desk_db.get_settings(env[0])
    assert bc.stale(env[1], dict(s, calendar_sync="off"), S) == (False, "")
    assert bc.stale(env[1], s, r.BUSINESS) == (False, "")


# ── busy times in ────────────────────────────────────────────────────────────

def test_busy_blocks_close_windows_and_a_new_sync_replaces_them(env):
    assert T7 in keys(env)
    fresh(env, [{"start": "2027-03-02T07:00", "end": "2027-03-02T11:00"}])   # no room to start inside 7–9
    assert T7 not in keys(env)
    fresh(env)                                           # deleted on Google → open again
    assert T7 in keys(env)


def test_own_events_are_left_out(env):
    out = fresh(env, [{"start": "2027-03-02T07:30", "end": "2027-03-02T08:30", "title": "Job: Exterior windows — Ann"}])
    assert out["skipped_own"] == 1 and T7 in keys(env)


def test_a_busy_block_on_a_booked_visit_opens_one_clash_ticket(env):
    fresh(env)
    b = book(env)
    block = {"start": "2027-03-02T10:00", "end": "2027-03-02T11:00"}
    out = fresh(env, [block])
    assert len(out["tickets"]) == 1
    t = desk_db.get_ticket(env[0], out["tickets"][0], actor=None, edition=S)
    assert t["kind"] == r.INTERNAL and b["job_id"] in t["title"] and t["title"].startswith("Calendar clash")
    assert fresh(env, [block])["tickets"] == []          # once per clash
    assert desk_db.get_ticket(env[0], b["ticket_id"], actor=None, edition=S)   # the booking itself untouched
    assert bf.get(env[1], b["job_id"])["req"]["status"] == "scheduled"


def test_bad_blocks_are_refused(env):
    with pytest.raises(bc.CalendarError):
        fresh(env, [{"start": "2027-03-02T10:00", "end": "2027-03-02T09:00"}])
    with pytest.raises(bc.CalendarError):
        fresh(env, [{"start": "soon"}])


# ── bookings out ─────────────────────────────────────────────────────────────

def test_only_confirmed_bookings_are_pushed_then_updated_then_deleted(env):
    pend = book(env)                                     # stale → pending: not pushed
    assert bc.pending(env[1], edition=S) == []
    fresh(env)
    bf.approve(env[1], env[0], pend["job_id"], actor=OWNER, edition=S, settings=desk_db.get_settings(env[0]))
    items = bc.pending(env[1], edition=S)
    assert [(i["action"], i["date"], i["start"], i["end"]) for i in items] == [("new", "2027-03-02", "09:00", "11:00")]
    assert items[0]["title"] == "Job: Exterior windows — Maria" and "Ocean Ave" in items[0]["address"]
    assert bc.mark_synced(env[1], [{"job_id": pend["job_id"], "action": "new", "event_id": "g1"}], edition=S)["done"] == 1
    assert bc.pending(env[1], edition=S) == []
    assert fresh(env, [{"start": "2027-03-02T09:00", "end": "2027-03-02T11:00", "event_id": "g1"}])["skipped_own"] == 1
    conn = get_connection(env[1])                        # moved in the Jobs app → update the same event
    conn.execute("UPDATE jobs SET original_start_time = '13:00', original_end_time = '15:00', start_time = '13:00', "
                 "end_time = '15:00' WHERE job_id = ?", (pend["job_id"],))
    conn.close()
    up = bc.pending(env[1], edition=S)
    assert [(i["action"], i["event_id"], i["start"]) for i in up] == [("update", "g1", "13:00")]
    bc.mark_synced(env[1], [{"job_id": pend["job_id"], "action": "update", "event_id": "g1"}], edition=S)
    bf.customer_cancel(env[1], env[0], pend["job_id"], edition=S, settings=desk_db.get_settings(env[0]))
    gone = bc.pending(env[1], edition=S)
    assert [(i["action"], i["event_id"]) for i in gone] == [("cancel", "g1")]
    bc.mark_synced(env[1], [{"job_id": pend["job_id"], "action": "cancel"}], edition=S)
    assert bc.pending(env[1], edition=S) == []


def test_a_failed_write_is_offered_again_and_listed(env):
    fresh(env)
    b = book(env)
    out = bc.mark_synced(env[1], [{"job_id": b["job_id"], "error": "calendar not found"}], edition=S)
    assert out["errors"] == 1
    again = bc.pending(env[1], edition=S)
    assert again[0]["action"] == "new" and again[0]["retry_of_error"] == "calendar not found"
    st = bc.status(env[1], desk_db.get_settings(env[0]), edition=S)
    assert st["errors"][0]["error"] == "calendar not found" and "couldn't be written" in bc.status_line(st)


def test_a_new_event_must_come_back_with_its_id(env):
    fresh(env)
    b = book(env)
    out = bc.mark_synced(env[1], [{"job_id": b["job_id"], "action": "new"}], edition=S)
    assert out["done"] == 0 and out["errors"] == 1
    assert bc.mark_synced(env[1], [{"job_id": "JOB-NOPE", "event_id": "x"}], edition=S)["unknown"] == ["JOB-NOPE"]


# ── the tools, the prompt, the task ──────────────────────────────────────────

def test_tools_walk_through_a_sync(env):
    fresh(env)
    b = book(env)
    assert "Busy times saved: 1 block" in desk_tools.calendar_sync_busy(
        env[0], OWNER, S, date_from="2027-03-01", date_to="2027-03-21",
        blocks=[{"start": "2027-03-04T13:00", "end": "2027-03-04T14:00"}], jobs_db=env[1])
    got = json.loads(desk_tools.calendar_pending_events(env[0], OWNER, S, jobs_db=env[1]))
    assert got["calendar"] == "Blue Wave Jobs" and got["items"][0]["job_id"] == b["job_id"]
    assert "1 calendar item" in desk_tools.calendar_mark_synced(
        env[0], OWNER, S, items=json.dumps([{"job_id": b["job_id"], "action": "new", "event_id": "g9"}]), jobs_db=env[1])
    st = desk_tools.calendar_sync_status(env[0], OWNER, S, jobs_db=env[1])
    assert "Blue Wave Jobs" in st and "calendar_sync_busy" in st
    assert "Only the owner" in desk_tools.calendar_pending_events(env[0], {"user_id": "s", "role": r.STAFF}, S,
                                                                   jobs_db=env[1])


def test_tools_say_when_sync_is_off(env):
    desk_db.set_setting(env[0], "calendar_sync", "off", edition=S)
    assert "Calendar sync is off" in desk_tools.calendar_pending_events(env[0], OWNER, S, jobs_db=env[1])
    assert "off" in desk_tools.calendar_sync_status(env[0], OWNER, S, jobs_db=env[1]).lower()


def test_server_refuses_everything_calendar(env):
    for fn in (desk_tools.calendar_pending_events, desk_tools.calendar_sync_status):
        assert "Jobs app calendar only" in fn(env[0], OWNER, r.BUSINESS, jobs_db=env[1])
    assert "Jobs app calendar only" in desk_tools.calendar_sync_busy(env[0], OWNER, r.BUSINESS, date_from="2027-03-01",
                                                                      date_to="2027-03-02", jobs_db=env[1])
    with pytest.raises(bc.CalendarError):
        bc.pending(env[1], edition=r.BUSINESS)
    with pytest.raises(desk_db.DeskError):
        desk_db.set_setting(env[0], "calendar_sync", "ai", edition=r.BUSINESS)


def test_sync_prompt_names_the_calendar_and_the_steps():
    t = bc.sync_prompt({"calendar_name": "Blue Wave Jobs", "calendar_days": 0, "booking_horizon_days": 14})
    assert "\"Blue Wave Jobs\"" in t and "next 14 days" in t
    for step in ("calendar_sync_busy", "calendar_pending_events", "calendar_mark_synced", "\"Job:\""):
        assert step in t


def test_create_scheduled_sync_adds_one_task(tmp_path, monkeypatch):
    import custom_tasks_manager as ctm
    monkeypatch.setattr(ctm, "CUSTOM_TASKS_PATH", tmp_path / "tasks.json")
    s = {"calendar_name": "Blue Wave Jobs", "calendar_days": 0, "booking_horizon_days": 21}
    assert "Created" in bc.create_scheduled_sync(s, edition=S, today=dt.date(2027, 3, 1))
    assert "Updated" in bc.create_scheduled_sync(dict(s, calendar_name="Jobs 2"), edition=S)
    tasks = ctm.load_custom_tasks()
    assert len(tasks) == 1 and "Jobs 2" in tasks[0]["prompt"] and tasks[0]["daily_times_per_day"] == 13
    assert tasks[0]["output_learnings"] is False
    with pytest.raises(bc.CalendarError):
        bc.create_scheduled_sync(s, edition=r.BUSINESS)


def test_gui_helpers_save_and_report(env):
    import desk_gui_settings as g
    ok, msg = g.save_calendar(env[0], {"calendar_sync": True, "calendar_name": "", "calendar_days": "0",
                                       "calendar_fresh_hours": "4"}, S)
    assert not ok and "name" in msg
    ok, _ = g.save_calendar(env[0], {"calendar_sync": True, "calendar_name": " Jobs ", "calendar_days": "10",
                                     "calendar_fresh_hours": "6"}, S)
    s = desk_db.get_settings(env[0])
    assert ok and (s["calendar_name"], s["calendar_days"], s["calendar_fresh_hours"]) == ("Jobs", 10, 6)
    assert g.save_calendar(env[0], {}, r.BUSINESS)[0] is False
    ok, _ = g.add_opening(env[1], "Closed day", "2027-03-03", "", "", "Holiday")
    rows = g.opening_rows(env[1])
    assert ok and "Closed day" in rows[0]["text"] and "all day" in rows[0]["text"] and "Holiday" in rows[0]["text"]
    assert g.add_opening(env[1], "Extra opening", "2027-03-06", "", "", "")[0] is False   # needs hours
