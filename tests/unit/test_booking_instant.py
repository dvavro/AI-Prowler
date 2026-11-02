"""Instant booking (booking-spec.md §7a.1; Phase 4): the pre-approval limits, the reschedule
switch, the FYI digest line and "suggest a change" on a booked visit.
Fixed booking clock: Monday 1 Mar 2027, 06:00.
Run: run_tests.bat tests\\unit\\test_booking_instant.py
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
import desk_scheduler  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

NOW = dt.datetime(2027, 3, 1, 6, 0)
T7, T9 = "2027-03-02T07:00-09:00", "2027-03-02T09:00-11:00"
W9, F7 = "2027-03-03T09:00-11:00", "2027-03-05T07:00-09:00"
ADDR = {"street": "12 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"}


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    for k, v in (("portal_enabled", True), ("booking_paths", ["book", "problem"]), ("booking_approval", "preapprove")):
        desk_db.set_setting(tickets, k, v, edition=r.SOLO)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.executemany("INSERT INTO service_pricing (service_code, name, base_price) VALUES (?, ?, ?)",
                     [("WIN-EXT", "Exterior windows", 150), ("GUT", "Gutter clean", 120)])
    conn.close()
    bdb.sync_services(jobs)
    for code in ("WIN-EXT", "GUT"):
        bdb.update_service(jobs, code, online=True, minutes=105, buffer_min=15)
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


def book(env, key=T7, phone="386-555-0142", service="WIN-EXT", ip="1.2.3.4"):
    tickets, _jobs, sent = env
    st, h = api(tickets, "POST", "/hold", {"service_code": service, "window_key": key}, ip=ip)
    assert st == 200, h
    st, d = api(tickets, "POST", "/start", {"name": "Maria Lopez", "phone": phone}, ip=ip)
    code = re.search(r"\b(\d{6})\b", [t for _c, _to, t in sent if "code is" in t][-1]).group(1)
    st, out = api(tickets, "POST", "/verify", {"contact_id": d["contact_id"], "code": code, "path": "book",
                                                "service_code": service, "address": ADDR, "hold_id": h["hold_id"],
                                                "window_key": key}, ip=ip)
    assert st == 201, out
    return out


def notes(env, ticket_id):
    t = desk_db.get_ticket_detail(env[0], ticket_id, actor=None, edition=r.SOLO)
    return [m["body"] for m in t["messages"] if m["visibility"] == "internal"]


def setv(env, k, v):
    desk_db.set_setting(env[0], k, v, edition=r.SOLO)


def test_instant_booking_with_no_limits_books_any_open_time(env):
    out = book(env)
    assert out["booking"]["status"] == "scheduled"
    assert bf.get(env[1], out["job_id"])["req"]["decision"] == bf.PRE_APPROVED
    assert any("FYI — booked on its own" in n for n in notes(env, out["ticket_id"]))


def test_days_ahead_limit(env):
    setv(env, "booking_pre_min_days", 3)
    out = book(env)                                        # Tuesday is 1 day away
    assert out["booking"]["status"] == "pending"
    assert any("less than 3 days away" in n for n in notes(env, out["ticket_id"]))
    assert book(env, key=F7, phone="386-555-0199", ip="5.5.5.5")["booking"]["status"] == "scheduled"


def test_services_limit(env):
    setv(env, "booking_pre_services", ["GUT"])
    assert book(env)["booking"]["status"] == "pending"
    assert book(env, key=T9, service="GUT", phone="386-555-0199", ip="5.5.5.5")["booking"]["status"] == "scheduled"


def test_returning_customers_only(env):
    tickets, jobs, _sent = env
    setv(env, "booking_pre_returning", True)
    first = book(env)
    assert first["booking"]["status"] == "pending"                  # new customer
    bf.approve(jobs, tickets, first["job_id"], actor=None, edition=r.SOLO, settings=desk_db.get_settings(tickets))
    again = book(env, key=W9, ip="6.6.6.6")                          # same phone → same customer, now returning
    assert again["booking"]["status"] == "scheduled"


def test_per_day_limit(env):
    setv(env, "booking_pre_per_day", 1)
    assert book(env)["booking"]["status"] == "scheduled"
    out = book(env, key=T9, phone="386-555-0199", ip="5.5.5.5")
    assert out["booking"]["status"] == "pending"
    assert any("already has 1 instant booking" in n for n in notes(env, out["ticket_id"]))


def test_reschedules_wait_unless_switched_off(env):
    tickets, jobs, _sent = env
    out = book(env)
    s = desk_db.get_settings(tickets)
    res = bf.customer_reschedule(jobs, tickets, out["job_id"], W9, edition=r.SOLO, settings=s)
    assert res["status"] == "reschedule"                               # default: waits
    bf.decline(jobs, tickets, out["job_id"], actor=None, edition=r.SOLO, settings=s)
    setv(env, "booking_reschedule_approval", False)
    s = desk_db.get_settings(tickets)
    res = bf.customer_reschedule(jobs, tickets, out["job_id"], F7, edition=r.SOLO, settings=s)
    assert res["status"] == "scheduled" and res["window"] == F7
    setv(env, "booking_approval", "approve_all")                       # approve-all always asks
    res = bf.customer_reschedule(jobs, tickets, out["job_id"], W9, edition=r.SOLO,
                                 settings=desk_db.get_settings(tickets))
    assert res["status"] == "reschedule"


def test_suggest_a_change_on_a_booked_visit(env):
    tickets, jobs, _sent = env
    out = book(env)
    s = desk_db.get_settings(tickets)
    [u] = bf.upcoming(jobs)
    assert u["job_id"] == out["job_id"] and u["how"] == "instant booking" and u["key"] == T7
    with pytest.raises(bf.BookingError, match="already have"):
        bf.suggest(jobs, tickets, out["job_id"], T7, actor=None, edition=r.SOLO, settings=s)
    bf.suggest(jobs, tickets, out["job_id"], W9, actor=None, edition=r.SOLO, settings=s, note="We're nearby.")
    v = bf.view(jobs, out["job_id"], s)
    assert v["state"] == "suggested" and v["confirmed"] == "Tue 02 Mar, 7–9" and v["suggested"] == "Wed 03 Mar, 9–11"
    msgs = desk_db.get_ticket_detail(tickets, out["ticket_id"], actor=None, edition=r.SOLO)["messages"]
    assert any("Your visit stays Tue 02 Mar, 7–9 unless you accept" in m["body"] for m in msgs)
    done = bf.customer_accept(jobs, tickets, out["job_id"], edition=r.SOLO, settings=s)
    assert done["window"] == W9


def test_the_digest_has_the_fyi_line(env):
    out = book(env)
    line = desk_scheduler.booking_digest_line(env[0], desk_db.get_settings(env[0]))
    assert "Booked on their own since yesterday (FYI): 1" in line and "Tue 02 Mar, 7–9" in line
    assert out["job_id"]


def test_settings_are_checked(env):
    tickets = env[0]
    with pytest.raises(desk_db.DeskError):
        desk_db.set_setting(tickets, "booking_pre_min_days", 99, edition=r.SOLO)
    desk_db.set_setting(tickets, "booking_pre_services", [" GUT", "GUT", ""], edition=r.SOLO)
    assert desk_db.get_settings(tickets)["booking_pre_services"] == ["GUT"]
    import desk_gui_settings as g
    assert g.parse_codes("win-ext, gut  GUT") == ["WIN-EXT", "GUT"]
    form = {"booking_approval": "preapprove", "booking_customer_changes": True, "booking_backups": "2",
            "booking_hold_hours": "48", "booking_release_hours": "72", "booking_suggest_hours": "48",
            "booking_change_hours": "24", "booking_pre_returning": True, "booking_reschedule_approval": False,
            "booking_pre_services": "gut", "booking_pre_min_days": "2", "booking_pre_per_day": "4"}
    ok, msg = g.save_approval(tickets, form, "solo")
    s = desk_db.get_settings(tickets)
    assert ok and s["booking_pre_services"] == ["GUT"] and s["booking_pre_min_days"] == 2
    assert s["booking_pre_per_day"] == 4 and not s["booking_reschedule_approval"] and s["booking_pre_returning"]
