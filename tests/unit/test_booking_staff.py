"""The approver's side of booking (booking-spec.md §7a.3; Phase 2): the app's
/desk-api/bookings routes, the review_booking tool, and the timer (reminders, releases,
the digest line). Fixed booking clock: Monday 1 Mar 2027, 06:00.
Run: run_tests.bat tests\\unit\\test_booking_staff.py
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
import desk_scheduler  # noqa: E402
import desk_tools  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

NOW = dt.datetime(2027, 3, 1, 6, 0)
T7, W9 = "2027-03-02T07:00-09:00", "2027-03-03T09:00-11:00"
MANAGER, STAFF = {"id": "mgr", "role": "manager", "name": "Mia"}, {"id": "sam", "role": "staff"}


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    desk_db.set_setting(tickets, "portal_enabled", True, edition=r.SOLO)
    desk_db.set_setting(tickets, "booking_paths", ["book", "problem"], edition=r.SOLO)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES ('WIN-EXT', 'Exterior windows', 150)")
    conn.close()
    bdb.sync_services(jobs)
    bdb.update_service(jobs, "WIN-EXT", online=True, minutes=105, buffer_min=15)
    p.jobs_db_fn = lambda: jobs
    bf.clock = lambda: NOW
    yield tickets, jobs
    p.jobs_db_fn = None
    bf.clock = None


def make_booking(env, key=T7, who="ip:1", name="Maria Lopez", edition=r.SOLO):
    tickets, jobs = env
    s = desk_db.get_settings(tickets)
    held = bf.ensure_hold(jobs, s, "WIN-EXT", bf.hold_for_checkout(jobs, s, "WIN-EXT", key, who=who,
                                                                   edition=edition)["hold_id"], key, edition=edition)
    cid, _ = bdb.find_or_create_customer(jobs, name=name, phone="+13865550142" if who == "ip:1" else "+13865550199")
    out = bf.create_pending(jobs, s, held, customer_id=cid, customer_name=name, service_name="Exterior windows",
                            street="12 Ocean Ave", edition=edition)
    return out["job_id"]


def api(env, method, path, body=None, q=None, actor=None, edition=r.SOLO):
    tickets, _jobs = env
    st, ct, out = h.route(method, "/desk-api" + path, query=q or {}, body=json.dumps(body or {}).encode(),
                          content_type="application/json", actor=actor, edition=edition, db_path=tickets,
                          services={"team": lambda: [{"id": "u-ann", "name": "Ann"}]})
    return st, json.loads(out)


# ── the app's 📅 To approve ──────────────────────────────────────────────────

def test_owner_sees_and_approves_bookings_in_the_app(env):
    tickets, jobs = env
    jid = make_booking(env)
    st, d = api(env, "GET", "/me")
    assert d["can_approve_bookings"] is True
    st, d = api(env, "GET", "/bookings")
    assert st == 200 and [b["job_id"] for b in d["bookings"]] == [jid] and d["approval"] == "approve_all"
    st, w = api(env, "GET", "/bookings/windows", q={"service": "WIN-EXT", "from": "2027-03-03"})
    assert st == 200 and W9 in [x["key"] for x in w["windows"]]
    st, d = api(env, "POST", f"/bookings/{jid}/approve", {})
    assert st == 200 and d["status"] == "scheduled" and d["label"] == "Tue 02 Mar, 7–9"
    st, d = api(env, "POST", f"/bookings/{jid}/approve", {})
    assert st == 400 and "isn't waiting" in d["message"]


def test_suggest_and_decline_through_the_app(env):
    tickets, jobs = env
    a, b = make_booking(env), make_booking(env, key="2027-03-02T09:00-11:00", who="ip:2", name="Bo Chen")
    st, d = api(env, "POST", f"/bookings/{a}/suggest", {"window_key": W9, "note": "We're nearby."})
    assert st == 200 and d["status"] == "suggested"
    st, d = api(env, "POST", f"/bookings/{b}/decline", {"message": "Sorry, full.", "keep_request": True})
    assert st == 200 and d["status"] == "requested"
    st, d = api(env, "POST", f"/bookings/{a}/suggest", {"window_key": "2027-03-02T08:00-10:00"})
    assert st == 400 and "isn't open" in d["message"]


def test_only_approvers_get_in_and_managers_follow_the_setting(env):
    tickets, jobs = env
    desk_db.set_setting(tickets, "booking_paths", ["book", "problem"], edition=r.BUSINESS)
    jid = make_booking(env, edition=r.BUSINESS)
    st, d = api(env, "GET", "/bookings", actor=STAFF, edition=r.BUSINESS)
    assert st == 403 and "only the owner or a manager" in d["message"]
    st, d = api(env, "POST", f"/bookings/{jid}/approve", {}, actor=STAFF, edition=r.BUSINESS)
    assert st == 403
    st, d = api(env, "GET", "/me", actor=STAFF, edition=r.BUSINESS)
    assert d["can_approve_bookings"] is False
    st, d = api(env, "GET", "/bookings", actor=MANAGER, edition=r.BUSINESS)
    assert st == 200 and d["crew_mode"] == "approver"                      # managers: on by default
    desk_db.set_setting(tickets, "booking_approve_managers", False, edition=r.SOLO)
    st, d = api(env, "GET", "/bookings", actor=MANAGER, edition=r.BUSINESS)
    assert st == 403 and "only the owner can" in d["message"]


def test_approving_is_not_setup_so_the_server_lock_does_not_stop_it(env):
    tickets, jobs = env
    jid = make_booking(env, edition=r.BUSINESS)
    st, d = api(env, "POST", f"/bookings/{jid}/approve", {}, actor=None, edition=r.BUSINESS)
    assert st == 200 and d["status"] == "scheduled"


def test_bookings_list_is_hidden_when_booking_is_off(env):
    tickets, _jobs = env
    desk_db.set_setting(tickets, "booking_paths", ["problem"], edition=r.SOLO)
    st, d = api(env, "GET", "/me")
    assert d["can_approve_bookings"] is False


# ── the review_booking tool (Claude, Muse, Grok) ─────────────────────────────

def test_review_booking_tool_lists_approves_suggests_and_declines(env):
    tickets, jobs = env
    run = lambda actor=None, edition=r.SOLO, **kw: desk_tools.review_booking(tickets, actor, edition, **kw)  # noqa: E731
    assert run() == "📅 No bookings are waiting for approval."
    a = make_booking(env)
    b = make_booking(env, key="2027-03-02T09:00-11:00", who="ip:2", name="Bo Chen")
    out = run()
    assert "📅 2 booking(s):" in out and "Maria Lopez" in out and "wants Tue 02 Mar, 7–9" in out
    assert run(action="approve", booking="lopez").startswith(f"✅ {a} confirmed for Tue 02 Mar, 7–9")
    ws = run(action="windows", booking="Chen")
    assert W9 in ws
    assert "Which time?" in run(action="suggest", booking="chen")
    assert run(action="suggest", booking="chen", window_key=W9).startswith("✅ Suggested Wed 03 Mar, 9–11")
    assert "you suggested Wed 03 Mar, 9–11" in run()
    assert run(action="decline", booking=b).startswith(f"✅ {b} declined")
    assert "No waiting booking matches" in run(action="approve", booking="nobody")
    assert run(actor=STAFF, edition=r.BUSINESS).startswith("❌ Only the owner")
    assert run(actor={"id": "agent", "role": "agent"}, edition=r.BUSINESS).startswith("❌ Only the owner")


def test_review_booking_is_a_registered_tool():
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert "def review_booking(" in src and '_desk_call("review_booking"' in src
    import mcp_tool_catalog
    assert any(row[0] == "review_booking" for row in mcp_tool_catalog.TOOLS) if hasattr(mcp_tool_catalog, "TOOLS") \
        else "'review_booking'" in (ROOT / "mcp_tool_catalog.py").read_text(encoding="utf-8")


# ── AI-Prowler → Web forms → Approving bookings ──────────────────────────────

def test_approval_settings_save_from_ai_prowler(env):
    tickets, _jobs = env
    import desk_gui_settings as dgs
    form = {"booking_approval": "Instant booking — book windows that meet the rules at once",
            "booking_approve_managers": False, "booking_crew_mode": "Use the suggested crew",
            "booking_backups": "1", "booking_hold_hours": "24", "booking_release_hours": "48",
            "booking_suggest_hours": "12", "booking_customer_changes": True, "booking_change_hours": "6"}
    assert dgs.save_approval(tickets, form, "business") == (True, "Approval settings saved.")
    s = desk_db.get_settings(tickets)
    assert (s["booking_approval"], s["booking_approve_managers"], s["booking_crew_mode"]) == ("preapprove", False, "suggested")
    assert (s["booking_backups"], s["booking_hold_hours"], s["booking_release_hours"], s["booking_change_hours"]) == (1, 24, 48, 6)
    ok, msg = dgs.save_approval(tickets, dict(form, booking_release_hours="10"), "business")
    assert not ok and "more than the reminder" in msg
    ok, msg = dgs.save_approval(tickets, dict(form, booking_backups="lots"), "business")
    assert not ok and "whole numbers" in msg
    ok, msg = dgs.save_approval(tickets, dict(form, booking_backups="9"), "business")
    assert not ok and "booking_backups must be 0–3" in msg
    # personal installs: no managers / crews to set — those stay as they were
    assert dgs.save_approval(tickets, dict(form, booking_approve_managers=True), "solo")[0]
    assert desk_db.get_settings(tickets)["booking_approve_managers"] is False
    assert dict(dgs.APPROVAL_CHOICES)["approve_all"].endswith("(recommended)")


def test_book_a_service_is_no_longer_greyed_out_in_settings():
    src = (ROOT / "desk_gui_settings.py").read_text(encoding="utf-8")
    assert "(next update)" not in src and "Arrives in the next update" not in src
    assert "_build_approval(app, f, db, edition)" in src


# ── the timer ────────────────────────────────────────────────────────────────

def test_scheduler_reminds_the_owner_and_releases_undecided_bookings(env):
    tickets, jobs = env
    jid = make_booking(env)
    told = []
    did = desk_scheduler.run_once(tickets, edition=r.SOLO, now=NOW + dt.timedelta(hours=49),
                                  alert_owner=told.append)
    assert did["bookings"]["remind"][0]["job_id"] == jid
    assert told and "Bookings still waiting for your OK" in told[0] and "Tue 02 Mar, 7–9" in told[0]
    did = desk_scheduler.run_once(tickets, edition=r.SOLO, now=NOW + dt.timedelta(hours=73),
                                  alert_owner=told.append)
    assert did["bookings"]["released"] == [{"job_id": jid, "was": "pending"}]


def test_digest_line_lists_bookings_to_approve(env):
    tickets, jobs = env
    s = desk_db.get_settings(tickets)
    assert desk_scheduler.booking_digest_line(tickets, s) == ""
    make_booking(env)
    line = desk_scheduler.booking_digest_line(tickets, s)
    assert line.startswith("📅 Bookings to approve: 1 — Maria Lopez Tue 02 Mar, 7–9") and "To approve" in line
    assert desk_scheduler.booking_digest_line(tickets, dict(s, booking_paths=["problem"])) == ""
