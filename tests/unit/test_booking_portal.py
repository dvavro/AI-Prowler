"""Booking through the customer page's routes (booking-spec.md §3, §7a; Phase 2).

/support-api/windows → /hold → /start → /verify (path=book) → the status page's
booking: waiting / suggested (Accept / Pick another / Call me) / confirmed (.ics,
Reschedule, Cancel). The approver's side is booking_flow (tested in test_booking_flow).
Fixed booking clock: Monday 1 Mar 2027, 06:00.
Run: run_tests.bat tests\\unit\\test_booking_portal.py
"""
import datetime as dt
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import booking_db as bdb  # noqa: E402
import booking_flow as bf  # noqa: E402
import desk_db  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

NOW = dt.datetime(2027, 3, 1, 6, 0)
T7, T9, W9 = "2027-03-02T07:00-09:00", "2027-03-02T09:00-11:00", "2027-03-03T09:00-11:00"
PHONE, E164 = "386-555-0142", "+13865550142"
ADDR = {"street": "12 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"}


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    desk_db.set_setting(tickets, "portal_enabled", True, edition=r.SOLO)
    desk_db.set_setting(tickets, "booking_paths", ["book", "new", "problem"], edition=r.SOLO)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.executemany("INSERT INTO service_pricing (service_code, name, base_price, min_charge) VALUES (?, ?, ?, ?)",
                     [("WIN-EXT", "Exterior windows", 150, 95), ("GUT", "Gutter clean", 120, None)])
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


def api(db, method, path, body=None, q=None, ip="1.2.3.4"):
    st, ct, out = p.route(method, "/support-api" + path, query=q or {}, body=json.dumps(body or {}).encode(),
                          content_type="application/json", ip=ip, db_path=db, edition=r.SOLO,
                          base_url="https://x.example", business="Blue Wave")
    return st, (json.loads(out) if ct.startswith(b"application/json") else out)


def book(env, key=T7, backups=(), ip="1.2.3.4", phone=PHONE, **extra):
    tickets, _jobs, sent = env
    st, h = api(tickets, "POST", "/hold", {"service_code": "WIN-EXT", "window_key": key}, ip=ip)
    assert st == 200, h
    st, d = api(tickets, "POST", "/start", {"name": "Maria Lopez", "phone": phone}, ip=ip)
    assert st == 200, d
    code = re.search(r"\b(\d{6})\b", [t for _c, _to, t in sent if "code is" in t][-1]).group(1)
    body = {"contact_id": d["contact_id"], "code": code, "path": "book", "service_code": "WIN-EXT",
            "service": "Exterior windows", "address": ADDR, "hold_id": h["hold_id"], "window_key": key,
            "backups": list(backups), **extra}
    return api(tickets, "POST", "/verify", body, ip=ip)


def status(env, token):
    return api(env[0], "GET", f"/t/{token}")[1]["ticket"]


# ── windows and holding ──────────────────────────────────────────────────────

def test_windows_are_offered_only_when_booking_is_on(env):
    tickets, _jobs, _sent = env
    st, d = api(tickets, "GET", "/windows", q={"service": "WIN-EXT", "from": "2027-03-02"})
    assert st == 200 and d["windows"][0] == {"key": T7, "date": "2027-03-02", "start": "07:00", "end": "09:00",
                                             "label": "Tue 02 Mar, 7–9"}
    assert all(w["date"] <= "2027-03-15" for w in d["windows"])          # two weeks from "from"
    assert "crew" not in json.dumps(d)
    st, d = api(tickets, "GET", "/windows", q={"service": "GUT"})
    assert st == 400 and "isn't a service offered online" in d["message"]
    desk_db.set_setting(tickets, "booking_paths", ["new", "problem"], edition=r.SOLO)
    st, d = api(tickets, "GET", "/windows", q={"service": "WIN-EXT"})
    assert st == 400 and "isn't available" in d["message"]


def test_a_held_window_disappears_for_everyone_else(env):
    tickets, _jobs, _sent = env
    st, h = api(tickets, "POST", "/hold", {"service_code": "WIN-EXT", "window_key": T7}, ip="9.9.9.9")
    assert st == 200 and h["label"] == "Tue 02 Mar, 7–9"
    st, d = api(tickets, "GET", "/windows", q={"service": "WIN-EXT", "from": "2027-03-02"})
    assert T7 not in [w["key"] for w in d["windows"]]
    st, d = api(tickets, "POST", "/hold", {"service_code": "WIN-EXT", "window_key": T7}, ip="8.8.8.8")
    assert st == 400 and "just taken" in d["message"]


# ── booking ──────────────────────────────────────────────────────────────────

def test_booking_waits_for_approval_and_the_customer_is_told_it_is_held(env):
    tickets, jobs, sent = env
    st, d = book(env, backups=[T9])
    assert st == 201 and d["booking"] == {"status": "pending", "label": "Tue 02 Mar, 7–9"} and d["job_id"]
    t = desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None, edition=r.SOLO)
    assert t["title"] == "Exterior windows — Tue 02 Mar, 7–9" and "approve" not in t["title"]
    assert "Or: Tue 02 Mar, 9–11" in t["description"] and E164 in t["description"]
    assert any("We're holding Tue 02 Mar, 7–9 for you" in text for _c, _to, text in sent)
    v = status(env, d["token"])["booking"]
    assert v["state"] == "pending" and v["waiting_for"] == "Tue 02 Mar, 7–9" and v["can_cancel"]
    assert bf.get(jobs, d["job_id"])["req"]["ticket_id"] == d["ticket_id"]


def test_if_the_window_went_while_entering_the_code_the_code_still_works(env):
    tickets, jobs, sent = env
    bdb.update_service(jobs, "WIN-EXT", minutes=420, buffer_min=0)    # one per day
    st, h = api(tickets, "POST", "/hold", {"service_code": "WIN-EXT", "window_key": T7})
    st, d = api(tickets, "POST", "/start", {"name": "Maria Lopez", "phone": PHONE})
    code = re.search(r"\b(\d{6})\b", sent[-1][2]).group(1)
    bf.clock = lambda: NOW + dt.timedelta(minutes=15)                 # her hold lapsed…
    st2, _ = api(tickets, "POST", "/hold", {"service_code": "WIN-EXT", "window_key": T7}, ip="7.7.7.7")
    assert st2 == 200                                                 # …and someone else took Tuesday
    body = {"contact_id": d["contact_id"], "code": code, "path": "book", "service_code": "WIN-EXT",
            "address": ADDR, "hold_id": h["hold_id"], "window_key": T7}
    st, out = api(tickets, "POST", "/verify", body)
    assert st == 400 and "just taken" in out["message"]
    st, h2 = api(tickets, "POST", "/hold", {"service_code": "WIN-EXT", "window_key": W9})
    st, out = api(tickets, "POST", "/verify", dict(body, hold_id=h2["hold_id"], window_key=W9))
    assert st == 201 and out["booking"]["label"] == "Wed 03 Mar, 9–11"   # same code, new time


def test_automatic_approval_books_at_once(env):
    tickets, jobs, sent = env
    desk_db.set_setting(tickets, "booking_approval", "auto", edition=r.SOLO)
    st, d = book(env)
    assert st == 201 and d["booking"] == {"status": "scheduled", "label": "Tue 02 Mar, 7–9"}
    conn = get_connection(jobs)
    j = dict(conn.execute("SELECT * FROM jobs WHERE job_id = ?", (d["job_id"],)).fetchone())
    conn.close()
    assert (j["job_status"], j["service_date"]) == ("Scheduled", "2027-03-02")
    assert any(text.startswith("Booked: Tue 02 Mar, 7–9") for _c, _to, text in sent)


def test_outside_the_service_area_a_booking_becomes_a_call_back_request(env):
    tickets, jobs, _sent = env
    desk_db.set_setting(tickets, "booking_area_zips", ["32168"], edition=r.SOLO)
    st, d = book(env)
    assert st == 201 and d["out_of_area"] is True and d["booking"] is None
    conn = get_connection(jobs)
    j = dict(conn.execute("SELECT * FROM jobs WHERE job_id = ?", (d["job_id"],)).fetchone())
    holds = conn.execute("SELECT COUNT(*) FROM booking_holds").fetchone()[0]
    conn.close()
    assert j["job_status"] == "Requested" and holds == 0               # no time held


def test_booking_needs_a_phone_a_service_and_an_address(env):
    tickets, _jobs, sent = env
    st, d = api(tickets, "POST", "/start", {"name": "Maria Lopez", "email": "m@example.com"})
    assert st == 400 and "phone number" in d["message"]                 # phone first, always
    st, d = api(tickets, "POST", "/start", {"name": "Maria Lopez", "phone": PHONE})
    code = re.search(r"\b(\d{6})\b", sent[-1][2]).group(1)
    base = {"contact_id": d["contact_id"], "code": code, "path": "book", "window_key": T7}
    st, out = api(tickets, "POST", "/verify", dict(base, address=ADDR))
    assert st == 400 and "pick a service" in out["message"]
    st, out = api(tickets, "POST", "/verify", dict(base, service_code="WIN-EXT", address={"street": "12 Ocean"}))
    assert st == 400 and "address" in out["message"]
    st, out = api(tickets, "POST", "/verify", dict(base, service_code="WIN-EXT", address=ADDR))
    assert st == 201                                                  # the code wasn't used up above


# ── the customer's page after a decision ─────────────────────────────────────

def test_suggestion_on_the_status_page_accept(env):
    tickets, jobs, _sent = env
    st, d = book(env)
    bf.suggest(jobs, tickets, d["job_id"], W9, actor=None, edition=r.SOLO, settings=desk_db.get_settings(tickets))
    v = status(env, d["token"])["booking"]
    assert v["state"] == "suggested" and v["suggested"] == "Wed 03 Mar, 9–11" and v["can_accept"] and v["can_pick"]
    st, out = api(tickets, "POST", f"/t/{d['token']}/booking/accept")
    assert st == 200 and out["status"] == "scheduled" and out["label"] == "Wed 03 Mar, 9–11"
    v = status(env, d["token"])["booking"]
    assert v["state"] == "scheduled" and v["confirmed"] == "Wed 03 Mar, 9–11" and v["ics"]
    st, cal = api(tickets, "GET", f"/t/{d['token']}/visit.ics")
    assert st == 200 and b"DTSTART:20270303T090000" in cal and b"SUMMARY:Blue Wave: Exterior windows" in cal
    msgs = [m["body"] for m in desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None, edition=r.SOLO)["messages"]]
    assert "I accept Wed 03 Mar, 9–11." in msgs                        # the team sees it (and is alerted)


def test_pick_another_time_and_call_me(env):
    tickets, jobs, _sent = env
    st, d = book(env)
    bf.suggest(jobs, tickets, d["job_id"], W9, actor=None, edition=r.SOLO, settings=desk_db.get_settings(tickets))
    st, w = api(tickets, "GET", f"/t/{d['token']}/booking/windows", q={"from": "2027-03-02"})
    assert st == 200 and T9 in [x["key"] for x in w["windows"]]
    st, out = api(tickets, "POST", f"/t/{d['token']}/booking/pick", {"window_key": T9})
    assert st == 200 and out["status"] == "pending"
    assert status(env, d["token"])["booking"]["waiting_for"] == "Tue 02 Mar, 9–11"
    st, out = api(tickets, "POST", f"/t/{d['token']}/booking/call")
    msgs = [m["body"] for m in desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None, edition=r.SOLO)["messages"]]
    assert st == 200 and "Please call me about the time." in msgs


def test_reschedule_and_cancel_from_the_status_page(env):
    tickets, jobs, _sent = env
    st, d = book(env)
    s = desk_db.get_settings(tickets)
    bf.approve(jobs, tickets, d["job_id"], actor=None, edition=r.SOLO, settings=s)
    v = status(env, d["token"])["booking"]
    assert v["can_reschedule"] and v["can_cancel"]
    st, out = api(tickets, "POST", f"/t/{d['token']}/booking/reschedule", {"window_key": W9})
    assert st == 200 and out["status"] == "reschedule"
    v = status(env, d["token"])["booking"]
    assert v["confirmed"] == "Tue 02 Mar, 7–9" and v["reschedule_to"] == "Wed 03 Mar, 9–11"
    st, out = api(tickets, "POST", f"/t/{d['token']}/booking/cancel")
    assert st == 200 and out["status"] == "cancelled"
    st, out = api(tickets, "POST", f"/t/{d['token']}/booking/accept")
    assert st == 400 and "no suggested time" in out["message"]


def test_a_problem_report_is_not_a_booking(env):
    tickets, _jobs, sent = env
    st, d = api(tickets, "POST", "/start", {"name": "Pat", "phone": PHONE})
    code = re.search(r"\b(\d{6})\b", sent[-1][2]).group(1)
    st, d = api(tickets, "POST", "/verify", {"contact_id": d["contact_id"], "code": code, "path": "problem",
                                             "title": "Streaks"})
    assert st == 201 and d["booking"] is None and status(env, d["token"])["booking"] is None
    st, out = api(tickets, "POST", f"/t/{d['token']}/booking/cancel")
    assert st == 400 and "isn't a booking" in out["message"]
    st, out = api(tickets, "GET", f"/t/{d['token']}/visit.ics")
    assert st == 404


# ── service area by distance (booking-spec.md §5) ───────────────────────────

START = "100 Flagler Ave, New Smyrna Beach, FL 32169"
MAP = {START.lower(): (29.026, -80.918),
       "12 ocean ave, new smyrna beach, fl 32169": (29.040, -80.905),       # about 1 mile
       "5 main st, orlando, fl 32801": (28.541, -81.379)}                   # about 45 miles
FAR = {"street": "5 Main St", "city": "Orlando", "state": "FL", "zip": "32801"}


@pytest.fixture
def geo():
    looked = []

    def fake(address):
        looked.append(address)
        return MAP.get(" ".join(address.lower().split()))
    bdb.GEOCODE = fake
    yield looked
    bdb.GEOCODE = None


def _start_address(jobs, street="100 Flagler Ave", city="New Smyrna Beach", state="FL", zip_="32169"):
    conn = get_connection(jobs)
    for k, v in (("Start/End Street Address", street), ("Start/End City", city),
                 ("Start/End State", state), ("Start/End ZIP", zip_)):
        conn.execute("DELETE FROM settings WHERE key = ?", (k,))
        conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (k, v))
    conn.commit()
    conn.close()


def test_area_check_zip_list_and_radius(env, geo):
    _tickets, jobs, _sent = env
    assert bdb.area_check(jobs, {}, FAR) == (True, "no service area set")
    ok, why = bdb.area_check(jobs, {"booking_area_zips": ["32801"], "booking_area_miles": 10}, FAR)
    assert ok and "ZIP 32801" in why and geo == []                   # a listed ZIP needs no map lookup
    ok, why = bdb.area_check(jobs, {"booking_area_miles": 10}, ADDR)
    assert not ok and "no Start/End Address" in why                 # nothing to measure from
    _start_address(jobs)
    ok, why = bdb.area_check(jobs, {"booking_area_miles": 10}, ADDR)
    assert ok and "miles away" in why
    ok, why = bdb.area_check(jobs, {"booking_area_miles": 10}, FAR)
    assert not ok and "outside the 10-mile area" in why
    assert bdb.area_check(jobs, {"booking_area_miles": 60}, FAR)[0]
    ok, why = bdb.area_check(jobs, {"booking_area_miles": 10},
                             {"street": "1 Nowhere Rd", "city": "Atlantis", "zip": "00000"})
    assert not ok and "couldn't find that address" in why


def test_area_check_falls_back_to_the_business_address(env, geo):
    _tickets, jobs, _sent = env
    conn = get_connection(jobs)
    conn.execute("DELETE FROM settings WHERE key = 'Business Address'")
    conn.execute("INSERT INTO settings (key, value) VALUES ('Business Address', ?)", (START,))
    conn.commit()
    conn.close()
    assert bdb.area_check(jobs, {"booking_area_miles": 10}, ADDR)[0]


def test_a_booking_outside_the_radius_becomes_a_call_back_request(env, geo):
    tickets, jobs, _sent = env
    _start_address(jobs)
    desk_db.set_setting(tickets, "booking_area_miles", 10, edition=r.SOLO)
    st, d = book(env, address=FAR)
    assert st == 201 and d["out_of_area"] and d["booking"] is None
    t = desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None, edition=r.SOLO)
    assert "(outside service area)" in t["title"]
    assert any("outside the 10-mile area" in m["body"] for m in t["messages"])
    st, w = api(tickets, "GET", "/windows", q={"service": "WIN-EXT", "from": "2027-03-02"})
    assert T7 in [x["key"] for x in w["windows"]]                    # the hold was let go
    st, d = book(env, key=T9, ip="5.5.5.5")                            # 1 mile away: books as normal
    assert st == 201 and not d["out_of_area"] and d["booking"]["status"] == "pending"


def test_area_miles_setting_is_checked():
    import desk_gui_settings as g
    assert desk_db.SETTING_DEFAULTS["booking_area_miles"] == 0
    assert desk_db.BOOKING_RANGES["booking_area_miles"] == (0, 250)
    assert (g.parse_miles(" 25 mi"), g.parse_miles(""), g.parse_miles("abc")) == (25, 0, 0)
    assert "booking_area_miles" in __import__("desk_tools").SETTING_HELP
