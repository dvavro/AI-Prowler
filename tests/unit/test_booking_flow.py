"""booking_flow — a booking's life (booking-spec.md §7, §7a; test plan §13.3).

Fixed clock: Monday 1 Mar 2027, 06:00 (dates far enough ahead that the Jobs app's
overrun rule, which looks at the real today, can't touch them). Service WIN-EXT:
60 min + 15 buffer, offered online. Windows are 2 h, lead time 24 h, so Tuesday
2 Mar is the first bookable day: 07:00-09:00 … 15:00-17:00.
Run: run_tests.bat tests\\unit\\test_booking_flow.py
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
import desk_rules as r  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

NOW = dt.datetime(2027, 3, 1, 6, 0)
T7, T9, T11, W9 = "2027-03-02T07:00-09:00", "2027-03-02T09:00-11:00", "2027-03-02T11:00-13:00", "2027-03-03T09:00-11:00"
OWNER, MANAGER, STAFF = None, {"id": "mgr", "role": "manager"}, {"id": "sam", "role": "staff"}


@pytest.fixture
def env(tmp_path):
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES ('WIN-EXT', 'Exterior windows', 150)")
    conn.close()
    bdb.sync_services(jobs)
    # 105 min + 15 buffer = a full 2-hour window, so one booking fills one window
    # (a shorter service can fit two visits in one window — that's correct, and tested below).
    bdb.update_service(jobs, "WIN-EXT", online=True, minutes=105, buffer_min=15)
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    bf.clock = lambda: NOW
    yield jobs, tickets, dict(desk_db.get_settings(tickets))
    bf.clock = None


def book(env, key=T7, backups=(), edition=r.SOLO, settings=None, who="ip:1"):
    jobs, tickets, s = env
    s = settings or s
    h = bf.hold_for_checkout(jobs, s, "WIN-EXT", key, who=who, edition=edition)
    held = bf.ensure_hold(jobs, s, "WIN-EXT", h["hold_id"], key, edition=edition)
    cid, _ = bdb.find_or_create_customer(jobs, name="Maria Lopez", phone="+13865550142")
    c = desk_db.upsert_contact(tickets, name="Maria Lopez", phone="+13865550142", contact_type="customer",
                               actor={"id": "portal", "role": "customer"})
    out = bf.create_pending(jobs, s, held, backups=backups, customer_id=cid, customer_name="Maria Lopez",
                            service_name="Exterior windows", street="12 Ocean Ave", city="New Smyrna Beach",
                            zip_code="32169", edition=edition)
    t = desk_db.create_ticket(tickets, title=f"Exterior windows — {out['label']}", kind=r.EXTERNAL,
                              actor={"id": c["contact_id"], "role": "customer", "contact_id": c["contact_id"]},
                              edition=edition, source="portal", contact_id=c["contact_id"], customer_id=cid,
                              job_id=out["job_id"])
    bf.link_ticket(jobs, out["job_id"], t["ticket_id"])
    return out["job_id"], t["ticket_id"]


def job(jobs, jid):
    conn = get_connection(jobs)
    try:
        return dict(conn.execute("SELECT * FROM jobs WHERE job_id = ?", (jid,)).fetchone())
    finally:
        conn.close()


def keys(env, day=dt.date(2027, 3, 2), edition=r.SOLO):
    jobs, _t, s = env
    return [w["key"] for w in bf.windows(jobs, s, "WIN-EXT", edition, from_date=day, to_date=day)]


def public(tickets, tid):
    return [m["body"] for m in desk_db.get_ticket_detail(tickets, tid, actor=None, edition=r.SOLO)["messages"]
            if m["visibility"] == "public"]


# ── who approves (§7a.1) ─────────────────────────────────────────────────────

def test_who_can_approve():
    s = {"booking_approve_managers": True}
    assert bf.can_approve(OWNER, r.SOLO, s) and bf.can_approve(OWNER, r.BUSINESS, s)
    assert bf.can_approve(MANAGER, r.BUSINESS, s)                      # default on (David 2026-10-30)
    assert not bf.can_approve(MANAGER, r.BUSINESS, {"booking_approve_managers": False})
    for nobody in (STAFF, {"id": "fc", "role": "field_crew"}, {"id": "c", "role": "customer"},
                   {"id": "agent", "role": "agent"}):
        assert not bf.can_approve(nobody, r.BUSINESS, s), nobody


def test_settings_defaults_and_checks(env):
    _jobs, tickets, s = env
    assert (s["booking_approval"], s["booking_approve_managers"], s["booking_crew_mode"]) == ("approve_all", True, "approver")
    assert (s["booking_backups"], s["booking_hold_hours"], s["booking_release_hours"]) == (2, 48, 72)
    with pytest.raises(desk_db.DeskError, match="booking_approval must be one of"):
        desk_db.set_setting(tickets, "booking_approval", "yolo", edition=r.SOLO)
    with pytest.raises(desk_db.DeskError, match="booking_backups must be 0–3"):
        desk_db.set_setting(tickets, "booking_backups", 5, edition=r.SOLO)
    import desk_tools
    for k in ("booking_approval", "booking_approve_managers", "booking_crew_mode", "booking_backups",
              "booking_hold_hours", "booking_release_hours", "booking_suggest_hours", "booking_customer_changes",
              "booking_change_hours"):
        assert k in desk_tools.SETTING_HELP, k


# ── a booking waits for approval with NO date ────────────────────────────────

def test_a_new_booking_holds_its_window_and_has_no_date(env):
    jobs, tickets, s = env
    jid, tid = book(env, backups=[T9, T9, "2027-03-02T08:00-10:00", W9, T11])
    j = job(jobs, jid)
    assert j["job_status"] == "Pending Approval" and not j["service_date"]       # never routed while waiting
    assert j["created_by"] == bdb.WEB_BOOKING and j["est_duration"] == 105 and j["est_duration_unit"] == "min"
    b = bf.get(jobs, jid)
    assert b["held_key"] == T7 and b["req"]["status"] == "pending" and b["req"]["ticket_id"] == tid
    assert [x["key"] for x in b["choices"]["backups"]] == [T9, W9]     # real, distinct, at most 2
    assert T7 not in keys(env)                                         # held: nobody else can take it
    assert bf.needs_approval(s) is True


def test_checkout_hold_is_one_per_visitor_and_lost_windows_are_reported(env):
    jobs, _t, s = env
    a = bf.hold_for_checkout(jobs, s, "WIN-EXT", T7, who="ip:9", edition=r.SOLO)
    b = bf.hold_for_checkout(jobs, s, "WIN-EXT", T9, who="ip:9", edition=r.SOLO)
    assert bdb.get_hold(jobs, a["hold_id"]) is None and b["label"] == "Tue 02 Mar, 9–11"
    bdb.release_hold(jobs, b["hold_id"])
    bdb.update_service(jobs, "WIN-EXT", minutes=420, buffer_min=0)     # one per day
    bf.hold_for_checkout(jobs, s, "WIN-EXT", T7, who="ip:1", edition=r.SOLO)
    with pytest.raises(bdb.BookingError, match="just taken"):
        bf.hold_for_checkout(jobs, s, "WIN-EXT", T7, who="ip:2", edition=r.SOLO)


def test_an_expired_checkout_hold_is_taken_again_if_still_open(env):
    jobs, _t, s = env
    h = bf.hold_for_checkout(jobs, s, "WIN-EXT", T7, who="ip:1", edition=r.SOLO)
    bf.clock = lambda: NOW + dt.timedelta(minutes=15)                  # past the 10 minutes
    again = bf.ensure_hold(jobs, s, "WIN-EXT", h["hold_id"], T7, edition=r.SOLO)
    assert again["hold_id"] != h["hold_id"] and bf.key_of(again) == T7


def test_a_short_service_can_fit_two_visits_in_one_window(env):
    jobs, _t, s = env
    bdb.update_service(jobs, "WIN-EXT", minutes=45, buffer_min=15)     # 1 h: 7:00 and 8:00 both fit 7–9
    book(env, key=T7, who="ip:1")                                      # placed at 7:00
    assert T7 in keys(env)                                             # an 8:00 start still fits
    book(env, key=T7, who="ip:2")                                      # placed at 8:00
    assert T7 not in keys(env) and T9 in keys(env)                     # 7–9 is full; 9–11 is open


# ── ✅ approve ───────────────────────────────────────────────────────────────

def test_approve_sets_the_date_tells_the_customer_and_frees_nothing_else(env):
    jobs, tickets, s = env
    jid, tid = book(env)
    out = bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s)
    assert out["status"] == "scheduled" and out["label"] == "Tue 02 Mar, 7–9"
    j = job(jobs, jid)
    assert (j["job_status"], j["service_date"], j["start_time"], j["end_time"]) == ("Scheduled", "2027-03-02",
                                                                                     "07:00", "09:00")
    assert (j["original_start_time"], j["original_end_time"]) == ("07:00", "09:00")
    assert j["crew_user_id"] is None                                   # personal: the owner, not a users row
    assert bf.get(jobs, jid)["holds"] == []
    assert any(m.startswith("Confirmed: Tue 02 Mar, 7–9") for m in public(tickets, tid))
    assert T7 not in keys(env)                                         # the job itself now blocks it
    with pytest.raises(bdb.BookingError, match="isn't waiting"):
        bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s)


def test_approve_a_backup_or_any_open_time_instead(env):
    jobs, tickets, s = env
    jid, _ = book(env, backups=[T9])
    out = bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s, window_key=T9)
    assert out["window"] == T9 and job(jobs, jid)["start_time"] == "09:00"
    assert T7 in keys(env)                                             # the first choice was freed


def test_staff_and_managers_without_the_setting_cannot_approve(env):
    jobs, tickets, s = env
    jid, _ = book(env, edition=r.BUSINESS)
    with pytest.raises(bdb.BookingError, match="only the owner or a manager"):
        bf.approve(jobs, tickets, jid, actor=STAFF, edition=r.BUSINESS, settings=s)
    off = dict(s, booking_approve_managers=False)
    with pytest.raises(bdb.BookingError, match="only the owner can approve"):
        bf.approve(jobs, tickets, jid, actor=MANAGER, edition=r.BUSINESS, settings=off)
    assert bf.approve(jobs, tickets, jid, actor=MANAGER, edition=r.BUSINESS, settings=s)["status"] == "scheduled"


def test_crew_assignment_follows_the_setting_on_a_server(env):
    jobs, tickets, s = env
    conn = get_connection(jobs)
    conn.executemany("INSERT INTO users (id, display_name, role) VALUES (?, ?, ?)",
                     [("u-ann", "Ann", "field_crew"), ("u-bob", "Bob", "Field Crew"), ("u-own", "Dave", "owner")])
    conn.close()
    assert [c.crew_id for c in bf.crews_for(jobs, r.BUSINESS)] == ["u-ann", "u-bob"]
    assert [c.crew_id for c in bf.crews_for(jobs, r.SOLO)] == ["owner"]
    jid, _ = book(env, edition=r.BUSINESS)
    out = bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.BUSINESS, settings=s, crew="u-bob")
    assert job(jobs, jid)["crew_user_id"] == "u-bob" and out["crew"] == "u-bob"
    jid2, _ = book(env, key=T9, edition=r.BUSINESS, who="ip:2")
    bf.approve(jobs, tickets, jid2, actor=OWNER, edition=r.BUSINESS, settings=dict(s, booking_crew_mode="suggested"))
    assert job(jobs, jid2)["crew_user_id"] in ("u-ann", "u-bob")       # the suggested crew
    jid3, _ = book(env, key=T11, edition=r.BUSINESS, who="ip:3")
    bf.approve(jobs, tickets, jid3, actor=OWNER, edition=r.BUSINESS, settings=dict(s, booking_crew_mode="office"))
    assert job(jobs, jid3)["crew_user_id"] is None                     # left for the office


def test_no_field_crew_users_yet_still_books_on_a_server(env):
    jobs, tickets, s = env
    assert [c.crew_id for c in bf.crews_for(jobs, r.BUSINESS)] == ["team"]
    jid, _ = book(env, edition=r.BUSINESS)
    assert bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.BUSINESS, settings=s)["status"] == "scheduled"


# ── ↔ suggest, and the customer's answer ─────────────────────────────────────

def test_suggest_then_customer_accepts_without_a_second_approval(env):
    jobs, tickets, s = env
    jid, tid = book(env)
    out = bf.suggest(jobs, tickets, jid, W9, actor=OWNER, edition=r.SOLO, settings=s, note="We're nearby then.")
    assert out["status"] == "suggested" and job(jobs, jid)["job_status"] == "Suggested"
    assert T7 in keys(env) and W9 not in keys(env, day=dt.date(2027, 3, 3))   # old freed, new held
    assert any("We'd like to come Wed 03 Mar, 9–11 instead" in m and "nearby" in m for m in public(tickets, tid))
    v = bf.view(jobs, jid, s)
    assert v["state"] == "suggested" and v["suggested"] == "Wed 03 Mar, 9–11" and v["can_accept"]
    done = bf.customer_accept(jobs, tickets, jid, edition=r.SOLO, settings=s)
    assert done["status"] == "scheduled" and job(jobs, jid)["service_date"] == "2027-03-03"


def test_customer_picks_another_time_and_it_goes_back_for_approval(env):
    jobs, tickets, s = env
    jid, _ = book(env)
    bf.suggest(jobs, tickets, jid, W9, actor=OWNER, edition=r.SOLO, settings=s)
    out = bf.customer_pick(jobs, tickets, jid, T11, edition=r.SOLO, settings=s)
    assert out["status"] == "pending" and job(jobs, jid)["job_status"] == "Pending Approval"
    b = bf.get(jobs, jid)
    assert b["held_key"] == T11 and b["suggested"] is None
    assert W9 in keys(env, day=dt.date(2027, 3, 3))                    # the suggestion was freed
    auto = dict(s, booking_approval="auto")
    jid2, _ = book(env, key=T9, who="ip:2")
    bf.suggest(jobs, tickets, jid2, "2027-03-03T13:00-15:00", actor=OWNER, edition=r.SOLO, settings=s)
    assert bf.customer_pick(jobs, tickets, jid2, "2027-03-03T15:00-17:00", edition=r.SOLO,
                            settings=auto)["status"] == "scheduled"


def test_suggesting_a_time_that_is_gone_keeps_the_customers_hold(env):
    jobs, tickets, s = env
    bdb.update_service(jobs, "WIN-EXT", minutes=420, buffer_min=0)
    a, _ = book(env, key=T7, who="ip:1")
    book(env, key="2027-03-03T07:00-09:00", who="ip:2")
    with pytest.raises(bdb.BookingError, match="isn't open any more"):
        bf.suggest(jobs, tickets, a, "2027-03-03T07:00-09:00", actor=OWNER, edition=r.SOLO, settings=s)
    assert bf.get(jobs, a)["held_key"] == T7                           # still holding Tuesday


# ── ✖ decline ────────────────────────────────────────────────────────────────

def test_decline_frees_the_window_and_can_keep_a_request(env):
    jobs, tickets, s = env
    jid, tid = book(env)
    bf.decline(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s, message="Fully booked that week.")
    assert job(jobs, jid)["job_status"] == "Declined" and T7 in keys(env)
    assert "Fully booked that week." in public(tickets, tid)
    jid2, _ = book(env, key=T9, who="ip:2")
    bf.decline(jobs, tickets, jid2, actor=OWNER, edition=r.SOLO, settings=s, keep_request=True)
    assert job(jobs, jid2)["job_status"] == "Requested"


# ── the customer reschedules / cancels ───────────────────────────────────────

def test_reschedule_keeps_the_old_visit_until_decided(env):
    jobs, tickets, s = env
    jid, tid = book(env)
    bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s)
    out = bf.customer_reschedule(jobs, tickets, jid, W9, edition=r.SOLO, settings=s)
    assert out["status"] == "reschedule"
    j = job(jobs, jid)
    assert (j["job_status"], j["service_date"]) == ("Scheduled", "2027-03-02")   # old visit stays
    v = bf.view(jobs, jid, s)
    assert v["confirmed"] == "Tue 02 Mar, 7–9" and v["reschedule_to"] == "Wed 03 Mar, 9–11"
    bf.decline(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s)
    assert job(jobs, jid)["service_date"] == "2027-03-02" and bf.get(jobs, jid)["req"]["status"] == "scheduled"
    assert any("Your visit stays Tue 02 Mar, 7–9" in m for m in public(tickets, tid))
    bf.customer_reschedule(jobs, tickets, jid, W9, edition=r.SOLO, settings=s)
    bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s)
    j = job(jobs, jid)
    assert (j["service_date"], j["start_time"]) == ("2027-03-03", "09:00")
    assert T7 in keys(env)                                             # the old time is free again
    assert any(m.startswith("Your visit is now Wed 03 Mar, 9–11") for m in public(tickets, tid))


def test_customers_cannot_change_too_close_to_the_visit_or_when_switched_off(env):
    jobs, tickets, s = env
    jid, _ = book(env)
    bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s)
    bf.clock = lambda: dt.datetime(2027, 3, 1, 12, 0)                  # 19 h before 07:00 Tue
    with pytest.raises(bdb.BookingError, match="too close"):
        bf.customer_cancel(jobs, tickets, jid, edition=r.SOLO, settings=s)
    assert bf.view(jobs, jid, s)["can_cancel"] is False
    bf.clock = lambda: NOW
    with pytest.raises(bdb.BookingError, match="please call us"):
        bf.customer_cancel(jobs, tickets, jid, edition=r.SOLO, settings=dict(s, booking_customer_changes=False))
    assert bf.customer_cancel(jobs, tickets, jid, edition=r.SOLO, settings=s)["status"] == "cancelled"
    assert job(jobs, jid)["job_status"] == "Cancelled" and T7 in keys(env)


# ── approval modes ───────────────────────────────────────────────────────────

def test_approval_modes():
    assert bf.needs_approval({"booking_approval": "approve_all"})
    assert not bf.needs_approval({"booking_approval": "preapprove"})
    assert not bf.needs_approval({"booking_approval": "auto"})
    assert bf.needs_approval({"booking_approval": "auto"}, calendar_stale=True)   # stale calendar → approval


# ── nothing waits forever (§7a.5) ────────────────────────────────────────────

def test_reminder_once_then_release_and_tell_the_customer(env):
    jobs, tickets, s = env
    jid, tid = book(env)
    assert bf.sweep(jobs, tickets, s, edition=r.SOLO, now=NOW + dt.timedelta(hours=47))["remind"] == []
    out = bf.sweep(jobs, tickets, s, edition=r.SOLO, now=NOW + dt.timedelta(hours=49))
    assert [x["job_id"] for x in out["remind"]] == [jid]
    assert bf.sweep(jobs, tickets, s, edition=r.SOLO, now=NOW + dt.timedelta(hours=50))["remind"] == []  # once
    out = bf.sweep(jobs, tickets, s, edition=r.SOLO, now=NOW + dt.timedelta(hours=73))
    assert out["released"] == [{"job_id": jid, "was": "pending"}]
    assert job(jobs, jid)["job_status"] == "Requested" and bf.get(jobs, jid)["holds"] == []
    assert any("We'll call you" in m for m in public(tickets, tid))


def test_an_unanswered_suggestion_is_freed_and_the_team_asked_to_call(env):
    jobs, tickets, s = env
    jid, tid = book(env)
    bf.suggest(jobs, tickets, jid, W9, actor=OWNER, edition=r.SOLO, settings=s)
    out = bf.sweep(jobs, tickets, s, edition=r.SOLO, now=NOW + dt.timedelta(hours=49))
    assert out["released"] == [{"job_id": jid, "was": "suggested"}] and job(jobs, jid)["job_status"] == "Requested"
    notes = [m["body"] for m in desk_db.get_ticket_detail(tickets, tid, actor=None, edition=r.SOLO)["messages"]
             if m["visibility"] == "internal"]
    assert any("Please call them" in n for n in notes)


def test_a_lapsed_reschedule_keeps_the_visit(env):
    jobs, tickets, s = env
    jid, _ = book(env)
    bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s)
    bf.customer_reschedule(jobs, tickets, jid, W9, edition=r.SOLO, settings=s)
    bf.sweep(jobs, tickets, s, edition=r.SOLO, now=NOW + dt.timedelta(hours=73))
    assert bf.get(jobs, jid)["req"]["status"] == "scheduled" and job(jobs, jid)["service_date"] == "2027-03-02"


# ── the approver's list, the customer's page, the calendar file ──────────────

def test_to_approve_list_shows_what_the_approver_needs(env):
    jobs, tickets, s = env
    jid, tid = book(env, backups=[T9])
    rows = bf.to_approve(jobs)
    assert len(rows) == 1
    x = rows[0]
    assert (x["job_id"], x["ticket_id"], x["status"], x["held_label"]) == (jid, tid, "pending", "Tue 02 Mar, 7–9")
    assert x["phone"] == "+13865550142" and x["address"].startswith("12 Ocean Ave")
    assert [b["label"] for b in x["backups"]] == ["Tue 02 Mar, 9–11"]
    bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s)
    assert bf.to_approve(jobs) == []


def test_customer_view_never_shows_crews_and_ics_needs_a_confirmed_visit(env):
    jobs, tickets, s = env
    jid, _ = book(env)
    v = bf.view(jobs, jid, s)
    assert v["state"] == "pending" and v["waiting_for"] == "Tue 02 Mar, 7–9" and not v["ics"]
    assert "crew" not in json.dumps(v)
    with pytest.raises(bdb.BookingError, match="isn't confirmed"):
        bf.ics(jobs, jid)
    bf.approve(jobs, tickets, jid, actor=OWNER, edition=r.SOLO, settings=s)
    cal = bf.ics(jobs, jid, business="Blue Wave")
    assert "DTSTART:20270302T070000" in cal and "DTEND:20270302T090000" in cal
    assert "SUMMARY:Blue Wave: Exterior windows" in cal and "LOCATION:12 Ocean Ave\\, New Smyrna Beach" in cal
    assert cal.startswith("BEGIN:VCALENDAR\r\n") and bf.view(jobs, jid, s)["ics"] is True
