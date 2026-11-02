"""The time-machine story (booking-spec.md §13.9, personal install): a week of one small
business, end to end, with the booking clock moved along.

  Mon 06:00  Ann books Tue 9–11 from the website. The owner suggests Wed 7–9 instead; Ann
             accepts → Scheduled, with the .ics, and the event goes to the business calendar.
             A dentist appointment syncs in over Ann's visit → a clash ticket.
             The owner closes Tuesday. Cara books Thu, Ben books Fri and asks for earlier.
  Mon 12:00  Cara cancels Thursday → Ben is offered it, takes it, the owner approves.
             The calendar gets Ben's event; Cara's event is deleted.
  Tue 17:05  Ann's day-before reminder goes by email.
Run: run_tests.bat tests\\unit\\test_booking_story.py
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
import booking_followup as fu  # noqa: E402
import desk_db  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

S = r.SOLO
OWNER = {"user_id": "owner", "role": r.OWNER}
ADDR = {"street": "12 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"}
TUE9, WED7 = "2027-03-02T09:00-11:00", "2027-03-03T07:00-09:00"
THU7, FRI7 = "2027-03-04T07:00-09:00", "2027-03-05T07:00-09:00"


@pytest.fixture
def world(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    for k, v in (("portal_enabled", True), ("booking_paths", ["book", "problem"]), ("booking_max_per_day", 1),
                 ("calendar_sync", "ai"), ("calendar_name", "Blue Wave Jobs"), ("booking_waitlist", True)):
        desk_db.set_setting(tickets, k, v, edition=S)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES ('WIN-EXT', 'Exterior windows', 150)")
    conn.close()
    bdb.sync_services(jobs)
    bdb.update_service(jobs, "WIN-EXT", online=True, minutes=105, buffer_min=15)
    sent = []
    clock = {"now": dt.datetime(2027, 3, 1, 6, 0)}
    p.send_fn = lambda ch, to, subj, text: sent.append((ch, to, text)) or True
    p.channels_fn = lambda: {"email": True, "sms": True}
    p.jobs_db_fn = lambda: jobs
    bf.clock = lambda: clock["now"]
    yield {"t": tickets, "j": jobs, "sent": sent, "clock": clock}
    p.send_fn = p.channels_fn = p.jobs_db_fn = None
    bf.clock = None


def api(w, method, path, body=None, ip="1.2.3.4"):
    st, ct, out = p.route(method, "/support-api" + path, query={}, body=json.dumps(body or {}).encode(),
                          content_type="application/json", ip=ip, db_path=w["t"], edition=S,
                          base_url="https://x.example", business="Blue Wave")
    return st, (json.loads(out) if ct.startswith(b"application/json") else out)


def book(w, name, key, phone, email, ip):
    st, h = api(w, "POST", "/hold", {"service_code": "WIN-EXT", "window_key": key}, ip=ip)
    assert st == 200, h
    st, d = api(w, "POST", "/start", {"name": name, "phone": phone, "email": email, "send_by": "email"}, ip=ip)
    code = re.search(r"\b(\d{6})\b", [t for _c, to, t in w["sent"] if to == email and "code is" in t][-1]).group(1)
    st, out = api(w, "POST", "/verify", {"contact_id": d["contact_id"], "code": code, "path": "book",
                                          "service_code": "WIN-EXT", "address": ADDR, "hold_id": h["hold_id"],
                                          "window_key": key}, ip=ip)
    assert st == 201, out
    return out


def s(w):
    return desk_db.get_settings(w["t"])


def push_all(w):
    items = bc.pending(w["j"], edition=S)
    bc.mark_synced(w["j"], [{"job_id": i["job_id"], "action": i["action"], "event_id": i.get("event_id") or
                             "g-" + i["job_id"]} for i in items], edition=S)
    return [(i["action"], i["job_id"]) for i in items]


def test_a_week_of_bookings(world):
    w = world
    bc.sync_busy(w["j"], "2027-03-01", "2027-03-21", [], edition=S, tickets_db=w["t"])

    # Ann books Tuesday; the owner suggests Wednesday; Ann accepts
    ann = book(w, "Ann Reyes", TUE9, "386-555-0101", "ann@example.com", "1.1.1.1")
    assert ann["booking"]["status"] == "pending"                      # every booking waits for approval (default)
    assert bc.pending(w["j"], edition=S) == []                        # nothing pushed while it waits
    bf.suggest(w["j"], w["t"], ann["job_id"], WED7, actor=OWNER, edition=S, settings=s(w),
               note="We're nearby that morning")
    assert api(w, "POST", f"/t/{ann['token']}/booking/accept")[0] == 200
    assert bf.get(w["j"], ann["job_id"])["scheduled_key"] == WED7
    st, ics = api(w, "GET", f"/t/{ann['token']}/visit.ics")
    assert st == 200 and b"DTSTART:20270303T070000" in ics
    assert push_all(w) == [("new", ann["job_id"])]

    # a dentist appointment lands on Ann's visit → one clash ticket, nothing moved
    out = bc.sync_busy(w["j"], "2027-03-01", "2027-03-21", [{"start": "2027-03-03T08:00", "end": "2027-03-03T09:00"}],
                       edition=S, tickets_db=w["t"])
    assert len(out["tickets"]) == 1 and ann["job_id"] in out["clashes"][0]["job_id"]
    assert bf.get(w["j"], ann["job_id"])["scheduled_key"] == WED7

    # the owner closes Tuesday; Cara books Thursday, Ben books Friday and wants earlier
    bdb.add_opening(w["j"], "closed", "2027-03-02", note="Day off", by="owner")
    cara = book(w, "Cara Diaz", THU7, "386-555-0102", "cara@example.com", "2.2.2.2")
    ben = book(w, "Ben Ito", FRI7, "386-555-0103", "ben@example.com", "3.3.3.3")
    for x in (cara, ben):
        bf.approve(w["j"], w["t"], x["job_id"], actor=OWNER, edition=S, settings=s(w))
    assert sorted(push_all(w)) == sorted([("new", cara["job_id"]), ("new", ben["job_id"])])
    assert api(w, "POST", f"/t/{ben['token']}/booking/wait")[0] == 200
    got = fu.sweep_waitlist(w["j"], w["t"], s(w), edition=S, now=w["clock"]["now"])
    assert got["offered"] == []                                       # Tue closed, Wed and Thu full

    # Cara cancels Thursday → Ben is offered it, takes it, the owner approves
    w["clock"]["now"] = dt.datetime(2027, 3, 1, 12, 0)
    assert api(w, "POST", f"/t/{cara['token']}/booking/cancel")[0] == 200
    got = fu.sweep_waitlist(w["j"], w["t"], s(w), edition=S, now=w["clock"]["now"])
    assert [(x["job_id"], x["key"][:10]) for x in got["offered"]] == [(ben["job_id"], "2027-03-04")]
    st, res = api(w, "POST", f"/t/{ben['token']}/booking/take")
    assert res["status"] == "reschedule"                              # through approval
    bf.approve(w["j"], w["t"], ben["job_id"], actor=OWNER, edition=S, settings=s(w))
    assert bf.get(w["j"], ben["job_id"])["scheduled_key"][:10] == "2027-03-04"
    assert sorted(push_all(w)) == sorted([("update", ben["job_id"]), ("cancel", cara["job_id"])])

    # Tuesday evening: Ann's day-before reminder goes by email
    w["sent"].clear()
    sent = fu.send_reminders(w["j"], w["t"], s(w), edition=S, business="Blue Wave",
                             now=dt.datetime(2027, 3, 2, 17, 5))
    assert [(x["job_id"], x["channels"]) for x in sent] == [(ann["job_id"], ["email"])]
    assert w["sent"][0][1] == "ann@example.com" and "Wed 03 Mar" in w["sent"][0][2]
