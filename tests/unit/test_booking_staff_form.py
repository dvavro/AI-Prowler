"""Booking for a customer from the app's + (booking-spec.md §9.2; Phase 3): desk_staff_booking
and its /desk-api/book routes. Fixed booking clock: Monday 1 Mar 2027, 06:00.
Run: run_tests.bat tests\\unit\\test_booking_staff_form.py
"""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import booking_db as bdb  # noqa: E402
import booking_flow as bf  # noqa: E402
import desk_db  # noqa: E402
import desk_http as h  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_staff_booking as dsb  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

NOW = dt.datetime(2027, 3, 1, 6, 0)
T7, T9 = "2027-03-02T07:00-09:00", "2027-03-02T09:00-11:00"
ADDR = {"street": "12 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"}
MANAGER = {"id": "mgr", "role": "manager", "name": "Mia"}
STAFF = {"id": "sam", "role": "staff", "name": "Sam"}
CREW = {"id": "u-ann", "role": "field_crew", "name": "Ann"}
B = r.BUSINESS


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    desk_db.set_setting(tickets, "staff_booking", True, edition=r.SOLO)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.executemany("INSERT INTO service_pricing (service_code, name, base_price) VALUES (?, ?, ?)",
                     [("WIN-EXT", "Exterior windows", 150), ("PRESS", "Pressure washing", 200)])
    conn.executemany("INSERT INTO users (id, display_name, role) VALUES (?, ?, 'field_crew')",
                     [("u-ann", "Ann"), ("u-bo", "Bo")])
    conn.commit()
    conn.close()
    bdb.sync_services(jobs)
    bdb.update_service(jobs, "WIN-EXT", online=True, minutes=105, buffer_min=15)
    bdb.update_service(jobs, "PRESS", minutes=105, buffer_min=15)          # not offered online
    sent = []
    p.send_fn = lambda ch, to, subj, text: sent.append((ch, to, text)) or True
    p.channels_fn = lambda: {"email": True, "sms": True}
    p.jobs_db_fn = lambda: jobs
    bf.clock = lambda: NOW
    yield tickets, jobs, sent
    p.send_fn = p.channels_fn = p.jobs_db_fn = None
    bf.clock = None


def book(env, actor=None, edition=r.SOLO, **kw):
    tickets, jobs, _sent = env
    args = dict(path="book", name="Maria Lopez", phone="386-555-0142", address=ADDR, service_code="WIN-EXT",
                window_key=T7, base_url="https://x.example")
    args.update(kw)
    return dsb.book(tickets, actor=actor, edition=edition, jobs_db=jobs, **args)


def api(env, method, path, body=None, q=None, actor=None, edition=r.SOLO):
    tickets, _jobs, _sent = env
    st, ct, out = h.route(method, "/desk-api" + path, query=q or {}, body=json.dumps(body or {}).encode(),
                          content_type="application/json", actor=actor, edition=edition, db_path=tickets,
                          services={"team": lambda: [{"id": "u-ann", "name": "Ann"}, {"id": "u-bo", "name": "Bo"}],
                                    "base_url": "https://x.example"})
    return st, json.loads(out)


def ticket(env, tid):
    return desk_db.get_ticket_detail(env[0], tid, actor=None, edition=r.SOLO)


# ── who can ─────────────────────────────────────────────────────────────────

def test_off_by_default_and_who_can_book(env):
    tickets, _jobs, _sent = env
    assert desk_db.SETTING_DEFAULTS["staff_booking"] is False
    s = desk_db.get_settings(tickets)
    assert dsb.can_book(None, r.SOLO, s) and dsb.can_book(STAFF, B, s) and dsb.can_book(MANAGER, B, s)
    assert not dsb.can_book(CREW, B, s)                                   # field crew: not by default
    assert not dsb.can_book({"id": "c", "role": "customer"}, B, s)
    assert dsb.can_override(MANAGER, B, s) and not dsb.can_override(STAFF, B, s)     # approvers only
    desk_db.set_setting(tickets, "staff_booking", False, edition=r.SOLO)
    with pytest.raises(desk_db.DeskError, match="switched off"):
        book(env)
    st, d = api(env, "GET", "/me")
    assert d["can_book_for_customers"] is False


def test_staff_booking_roles_are_checked():
    with pytest.raises(desk_db.DeskError, match="staff_booking_roles can list"):
        desk_db.set_setting("unused", "staff_booking_roles", ["owner"], edition=r.SOLO)


# ── booking ─────────────────────────────────────────────────────────────────

def test_the_owner_books_and_it_is_confirmed_at_once(env):
    tickets, jobs, sent = env
    out = book(env)
    assert out["booking"] == {"status": "scheduled", "label": "Tue 02 Mar, 7–9"} and out["sent_via"] == "sms"
    j = bf.get(jobs, out["job_id"])["job"]
    assert j["job_status"] == "Scheduled" and j["service_date"] == "2027-03-02" and j["created_by"] == "owner"
    t = ticket(env, out["ticket_id"])
    assert t["title"] == "Exterior windows — Tue 02 Mar, 7–9" and t["source"] == "phone"
    assert not [m for m in t["messages"] if m["visibility"] == "public"]        # one confirmation, by text
    assert sent[-1][1] == "+13865550142" and sent[-1][2].startswith("Booked: Tue 02 Mar, 7–9")
    assert T7 not in [w["key"] for w in bf.windows(jobs, desk_db.get_settings(tickets), "WIN-EXT", r.SOLO)]


def test_staff_bookings_wait_for_approval_and_show_who_booked(env):
    tickets, jobs, sent = env
    out = book(env, actor=STAFF, edition=B)
    assert out["booking"]["status"] == "pending"
    [b] = bf.to_approve(jobs)
    assert b["job_id"] == out["job_id"] and b["booked_by"] == "Sam" and b["held"] == T7
    assert "We're holding Tue 02 Mar, 7–9" in sent[-1][2]
    desk_db.set_setting(tickets, "staff_booking_approval", False, edition=r.SOLO)
    out2 = book(env, actor=STAFF, edition=B, window_key=T9, phone="386-555-0199", name="Bo Chen")
    assert out2["booking"]["status"] == "scheduled"                     # approval off for staff


def test_phone_name_and_address_are_required(env):
    with pytest.raises(desk_db.DeskError, match="phone"):
        book(env, phone="")
    with pytest.raises(desk_db.DeskError, match="name"):
        book(env, name="")
    with pytest.raises(desk_db.DeskError, match="address"):
        book(env, address={"street": "", "city": "X"})
    with pytest.raises(desk_db.DeskError, match="pick a time"):
        book(env, window_key="")


def test_any_service_unless_the_owner_limits_it_to_online_ones(env):
    tickets, _jobs, _sent = env
    out = book(env, service_code="PRESS")
    assert out["booking"]["status"] == "scheduled"
    desk_db.set_setting(tickets, "staff_booking_all_services", False, edition=r.SOLO)
    with pytest.raises(desk_db.DeskError, match="isn't a service offered online"):
        book(env, service_code="PRESS", window_key=T9)
    opts = dsb.options(tickets, actor=None, edition=r.SOLO, jobs_db=env[1])
    assert [s["code"] for s in opts["services"]] == ["WIN-EXT"]


def test_a_quiet_booking_sends_nothing(env):
    tickets, _jobs, sent = env
    before = len(sent)
    out = book(env, notify=False)
    assert out["sent_via"] == "" and len(sent) == before
    assert any("Confirmed" in m["body"] and m["visibility"] == "internal"
               for m in ticket(env, out["ticket_id"])["messages"])


def test_new_service_request_from_the_app(env):
    tickets, jobs, _sent = env
    out = book(env, path="new", service_code="", service="Gutter guards", preferred="mornings", window_key="")
    assert out["booking"] is None
    conn = get_connection(jobs)
    j = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (out["job_id"],)).fetchone()
    conn.close()
    assert j["job_status"] == "Requested" and not j["service_date"]
    assert ticket(env, out["ticket_id"])["title"] == "New service request — Gutter guards"


# ── overrides and crews (server) ────────────────────────────────────────────

def test_only_approvers_book_outside_the_open_times_by_default(env):
    tickets, jobs, _sent = env
    sat = {"date": "2027-03-06", "start": "08:00", "end": "10:00"}           # a Saturday
    with pytest.raises(desk_db.DeskError, match="only approvers"):
        book(env, actor=STAFF, edition=B, custom=sat)
    out = book(env, actor=MANAGER, edition=B, custom=sat, crew="u-ann")
    assert out["booking"] == {"status": "scheduled", "label": "Sat 06 Mar, 8–10"}
    assert any("override" in w for w in out["warnings"])
    j = bf.get(jobs, out["job_id"])["job"]
    assert j["crew_user_id"] == "u-ann" and j["service_date"] == "2027-03-06"
    desk_db.set_setting(tickets, "staff_booking_override", "everyone", edition=r.SOLO)
    assert book(env, actor=STAFF, edition=B, custom=dict(sat, start="13:00", end="15:00"),
                phone="386-555-0199")["booking"]["status"] == "pending"


def test_double_booking_a_crew_is_refused_unless_allowed(env):
    tickets, _jobs, _sent = env
    sat = {"date": "2027-03-06", "start": "08:00", "end": "10:00"}
    book(env, actor=MANAGER, edition=B, custom=sat, crew="u-ann")
    with pytest.raises(desk_db.DeskError, match="u-ann already has"):
        book(env, actor=MANAGER, edition=B, custom=dict(sat, start="09:00", end="11:00"), crew="u-ann",
             phone="386-555-0199")
    out = book(env, actor=MANAGER, edition=B, custom=dict(sat, start="09:00", end="11:00"), crew="u-bo",
               phone="386-555-0199")
    assert out["booking"]["status"] == "scheduled"                      # another crew is fine
    desk_db.set_setting(tickets, "staff_booking_double_book", True, edition=r.SOLO)
    out = book(env, actor=MANAGER, edition=B, custom=dict(sat, start="09:00", end="11:00"), crew="u-ann",
               phone="386-555-0177")
    assert any(w.startswith("Double-booked: u-ann") for w in out["warnings"])


# ── AI-Prowler's settings ───────────────────────────────────────────────────

def test_ai_prowler_saves_the_employee_form_settings(env):
    import desk_gui_settings as g
    tickets = env[0]
    form = {"staff_booking": True, "staff_booking_approval": False, "staff_booking_override": "Everyone who can book",
            "staff_booking_double_book": True, "staff_booking_all_services": False, "staff_booking_notify": False,
            "role_manager": True, "role_staff": False, "role_field_crew": True}
    ok, msg = g.save_staff(tickets, form, "business")
    s = desk_db.get_settings(tickets)
    assert ok and s["staff_booking_override"] == "everyone" and s["staff_booking_roles"] == ["manager", "field_crew"]
    assert not s["staff_booking_approval"] and s["staff_booking_double_book"] and not s["staff_booking_notify"]
    assert set(g.STAFF_HELP) <= set(desk_db.SETTING_DEFAULTS)
    src = Path(g.__file__).read_text(encoding="utf-8")
    assert "_build_staff(app, f, db, edition)" in src


# ── the app's routes ────────────────────────────────────────────────────────

def test_app_routes_for_booking(env):
    tickets, _jobs, _sent = env
    st, me = api(env, "GET", "/me", actor=STAFF, edition=B)
    assert me["can_book_for_customers"] is True and me["can_approve_bookings"] is False
    st, o = api(env, "GET", "/book", actor=STAFF, edition=B)
    assert st == 200 and {c["name"] for c in o["crews"]} == {"Ann", "Bo"} and not o["can_override"]
    assert o["confirms_at_once"] is False and o["notify"] is True
    st, w = api(env, "GET", "/book/windows", q={"service": "WIN-EXT", "from": "2027-03-02"}, actor=STAFF, edition=B)
    assert st == 200 and w["windows"][0]["key"] == T7
    st, d = api(env, "POST", "/book", {"name": "Maria Lopez", "phone": "386-555-0142", "address": ADDR,
                                        "service_code": "WIN-EXT", "window_key": T7, "source": "walk_in"},
                actor=STAFF, edition=B)
    assert st == 201 and d["booking"]["status"] == "pending" and d["url"].startswith("https://x.example")
    st, me = api(env, "GET", "/me", actor=MANAGER, edition=B)
    assert me["can_approve_bookings"] is True                           # staff booking alone turns 📅 on
    st, d = api(env, "POST", "/book", {"name": "X", "phone": "1"}, actor=STAFF, edition=B)
    assert st == 400 and "phone number" in d["message"]
    st, d = api(env, "GET", "/book", actor=CREW, edition=B)
    assert st in (400, 403) and "can't book" in d["message"]
