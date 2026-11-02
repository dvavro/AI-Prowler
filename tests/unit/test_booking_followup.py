"""Phase 6 (booking-spec.md §4, §9.4, §13.4, §13.5): the waitlist for earlier times (through
approval), visit reminders by email / text / both, and Share & embed (snippets, Allowed
websites → frame-ancestors, local-only).
Fixed booking clock: Monday 1 Mar 2027, 06:00.
Run: run_tests.bat tests\\unit\\test_booking_followup.py
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
import booking_followup as fu  # noqa: E402
import desk_db  # noqa: E402
import desk_embed  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
import desk_tools  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

NOW = dt.datetime(2027, 3, 1, 6, 0)
F7 = "2027-03-05T07:00-09:00"
ADDR = {"street": "12 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"}
OWNER = {"user_id": "owner", "role": r.OWNER}
S = r.SOLO


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    for k, v in (("portal_enabled", True), ("booking_paths", ["book", "problem"]), ("booking_waitlist", True)):
        desk_db.set_setting(tickets, k, v, edition=S)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES ('WIN-EXT', 'Exterior windows', 150)")
    conn.close()
    bdb.sync_services(jobs)
    bdb.update_service(jobs, "WIN-EXT", online=True, minutes=105, buffer_min=15)
    sent = []
    have = {"email": True, "sms": True}
    p.send_fn = lambda ch, to, subj, text: sent.append((ch, to, text)) or True
    p.channels_fn = lambda: dict(have)
    p.jobs_db_fn = lambda: jobs
    bf.clock = lambda: NOW
    yield {"t": tickets, "j": jobs, "sent": sent, "have": have}
    p.send_fn = p.channels_fn = p.jobs_db_fn = None
    bf.clock = None


def api(db, method, path, body=None, ip="1.2.3.4"):
    st, ct, out = p.route(method, "/support-api" + path, query={}, body=json.dumps(body or {}).encode(),
                          content_type="application/json", ip=ip, db_path=db, edition=S,
                          base_url="https://x.example", business="Blue Wave")
    return st, (json.loads(out) if ct.startswith(b"application/json") else out)


def book(env, key=F7, phone="386-555-0142", email="maria@example.com", ip="1.2.3.4", approve=True):
    st, h = api(env["t"], "POST", "/hold", {"service_code": "WIN-EXT", "window_key": key}, ip=ip)
    assert st == 200, h
    st, d = api(env["t"], "POST", "/start", {"name": "Maria Lopez", "phone": phone, "email": email, "send_by": "email"},
                ip=ip)
    assert st == 200, d
    code = re.search(r"\b(\d{6})\b", [t for _c, _to, t in env["sent"] if "code is" in t][-1]).group(1)
    st, out = api(env["t"], "POST", "/verify", {"contact_id": d["contact_id"], "code": code, "path": "book",
                                                 "service_code": "WIN-EXT", "address": ADDR, "hold_id": h["hold_id"],
                                                 "window_key": key}, ip=ip)
    assert st == 201, out
    if approve:
        bf.approve(env["j"], env["t"], out["job_id"], actor=OWNER, edition=S, settings=desk_db.get_settings(env["t"]))
    return out


def page(env, out):
    st, v = api(env["t"], "GET", f"/t/{out['token']}")
    assert st == 200, v
    return v["ticket"]["booking"]


def act(env, out, what, body=None):
    return api(env["t"], "POST", f"/t/{out['token']}/booking/{what}", body)


def sweep(env, now=NOW):
    return fu.sweep_waitlist(env["j"], env["t"], desk_db.get_settings(env["t"]), edition=S, now=now)


# ── the waitlist ─────────────────────────────────────────────────────────────

def test_customer_joins_and_is_offered_the_earliest_open_time(env):
    out = book(env)
    assert page(env, out)["waitlist"]["can_join"] is True
    assert act(env, out, "wait")[0] == 200
    assert page(env, out)["waitlist"]["waiting"] is True
    got = sweep(env)
    assert len(got["offered"]) == 1
    offer = got["offered"][0]["key"]
    assert offer < F7 and offer[:10] >= "2027-03-02"
    v = page(env, out)["waitlist"]
    assert v["offer"] and v["offer_key"] == offer
    # the offered window is held: nobody else is shown it
    assert offer not in {w["key"] for w in bf.windows(env["j"], desk_db.get_settings(env["t"]), "WIN-EXT", S)}


def test_taking_an_opening_waits_for_approval_then_moves_the_visit(env):
    out = book(env)
    act(env, out, "wait")
    offer = sweep(env)["offered"][0]["key"]
    st, res = act(env, out, "take")
    assert st == 200 and res["status"] == "reschedule"
    b = bf.get(env["j"], out["job_id"])
    assert b["req"]["status"] == "reschedule" and b["held_key"] == offer
    assert b["scheduled_key"] == F7                                  # the visit stays until approved
    bf.approve(env["j"], env["t"], out["job_id"], actor=OWNER, edition=S, settings=desk_db.get_settings(env["t"]))
    assert bf.get(env["j"], out["job_id"])["scheduled_key"] == offer
    assert fu.entry_for(env["j"], out["job_id"]) is None             # booked → off the list


def test_with_waitlist_approval_off_the_approval_setting_decides(env):
    desk_db.set_setting(env["t"], "booking_waitlist_approval", False, edition=S)
    desk_db.set_setting(env["t"], "booking_approval", "auto", edition=S)
    out = book(env, approve=False)                    # confirmed automatically
    assert bf.get(env["j"], out["job_id"])["req"]["status"] == "scheduled"
    act(env, out, "wait")
    offer = sweep(env)["offered"][0]["key"]
    st, res = act(env, out, "take")
    assert res["status"] == "scheduled" and bf.get(env["j"], out["job_id"])["scheduled_key"] == offer


def test_an_offer_not_taken_passes_on_and_isnt_offered_again(env):
    out = book(env)
    act(env, out, "wait")
    first = sweep(env)["offered"][0]["key"]
    later = NOW + dt.timedelta(hours=3)
    got = sweep(env, later)
    assert got["passed"] == [{"job_id": out["job_id"], "key": first}]
    assert got["offered"] and got["offered"][0]["key"] != first
    with pytest.raises(bdb.BookingError):
        fu.take(env["j"], env["t"], out["job_id"], settings=desk_db.get_settings(env["t"]), edition=S,
                now=later + dt.timedelta(hours=3))


def test_first_come_first_served_and_leaving(env):
    a = book(env)
    b = book(env, key="2027-03-05T09:00-11:00", phone="386-555-0199", email="b@example.com", ip="5.5.5.5")
    act(env, a, "wait")
    act(env, b, "wait")
    got = sweep(env)
    assert [x["job_id"] for x in got["offered"]] == [a["job_id"], b["job_id"]]
    assert got["offered"][0]["key"] != got["offered"][1]["key"]       # never the same window twice
    act(env, a, "unwait")
    assert fu.entry_for(env["j"], a["job_id"]) is None
    assert got["offered"][0]["key"] in {w["key"] for w in bf.windows(env["j"], desk_db.get_settings(env["t"]),
                                                                      "WIN-EXT", S)}   # its hold freed


def test_a_cancelled_booking_leaves_the_waitlist(env):
    out = book(env)
    act(env, out, "wait")
    bf.customer_cancel(env["j"], env["t"], out["job_id"], edition=S, settings=desk_db.get_settings(env["t"]))
    assert sweep(env)["closed"] == [out["job_id"]]


def test_waitlist_off_means_no_option_and_no_joining(env):
    desk_db.set_setting(env["t"], "booking_waitlist", False, edition=S)
    out = book(env)
    assert "waitlist" not in page(env, out)
    st, res = act(env, out, "wait")
    assert st == 400


def test_the_booking_sweep_never_releases_a_booking_over_a_waitlist_hold(env):
    out = book(env)
    act(env, out, "wait")
    sweep(env)
    later = NOW + dt.timedelta(hours=5)
    bf.sweep(env["j"], env["t"], desk_db.get_settings(env["t"]), edition=S, now=later)
    assert bf.get(env["j"], out["job_id"])["req"]["status"] == "scheduled"


# ── reminders ────────────────────────────────────────────────────────────────

EVE = dt.datetime(2027, 3, 4, 17, 5)            # the evening before Friday 5 Mar


def test_day_before_reminder_by_email_goes_once(env):
    book(env)
    env["sent"].clear()
    s = desk_db.get_settings(env["t"])
    assert fu.due_reminders(env["j"], s, now=EVE - dt.timedelta(hours=2)) == []      # before the hour
    out = fu.send_reminders(env["j"], env["t"], s, edition=S, business="Blue Wave", now=EVE)
    assert [x["channels"] for x in out] == [["email"]]
    assert env["sent"][0][:2] == ("email", "maria@example.com") and "tomorrow" in env["sent"][0][2]
    assert "Blue Wave" in env["sent"][0][2] and "Fri 05 Mar" in env["sent"][0][2]
    assert fu.send_reminders(env["j"], env["t"], s, edition=S, now=EVE) == []


def test_text_and_both_and_the_fallback(env):
    assert fu.channels_for("text", {"email": True, "sms": True}) == ["sms"]
    assert fu.channels_for("text", {"email": True, "sms": False}) == ["email"]
    assert fu.channels_for("both", {"email": True, "sms": True}) == ["email", "sms"]
    assert fu.channels_for("both", {"email": True, "sms": False}) == ["email"]
    assert fu.channels_for("off", {"email": True, "sms": True}) == []
    desk_db.set_setting(env["t"], "booking_reminders", "both", edition=S)
    book(env)
    env["sent"].clear()
    fu.send_reminders(env["j"], env["t"], desk_db.get_settings(env["t"]), edition=S, now=EVE)
    assert sorted(c for c, _to, _t in env["sent"]) == ["email", "sms"]


def test_off_sends_nothing_and_a_moved_visit_is_reminded_again(env):
    desk_db.set_setting(env["t"], "booking_reminders", "off", edition=S)
    out = book(env)
    assert fu.due_reminders(env["j"], desk_db.get_settings(env["t"]), now=EVE) == []
    desk_db.set_setting(env["t"], "booking_reminders", "email", edition=S)
    s = desk_db.get_settings(env["t"])
    fu.send_reminders(env["j"], env["t"], s, edition=S, now=EVE)
    conn = get_connection(env["j"])
    conn.execute("UPDATE jobs SET original_start_time = '13:00', original_end_time = '15:00' WHERE job_id = ?",
                 (out["job_id"],))
    conn.close()
    assert len(fu.due_reminders(env["j"], s, now=EVE)) == 1


def test_morning_reminder(env):
    desk_db.set_setting(env["t"], "booking_reminder_morning", True, edition=S)
    book(env)
    s = desk_db.get_settings(env["t"])
    got = fu.due_reminders(env["j"], s, now=dt.datetime(2027, 3, 5, 6, 30))
    assert [x["kind"] for x in got] == ["morning"]
    assert fu.due_reminders(env["j"], s, now=dt.datetime(2027, 3, 5, 9, 30)) == []   # window already started


def test_no_way_to_reach_them_is_noted_not_retried(env):
    out = book(env)
    env["have"].update(email=False, sms=False)
    got = fu.send_reminders(env["j"], env["t"], desk_db.get_settings(env["t"]), edition=S, now=EVE)
    assert got[0]["channels"] == []
    t = desk_db.get_ticket_detail(env["t"], out["ticket_id"], actor=None, edition=S)
    assert any("couldn't be sent" in m["body"] for m in t["messages"] if m["visibility"] == "internal")
    assert fu.due_reminders(env["j"], desk_db.get_settings(env["t"]), now=EVE) == []


def test_pending_bookings_get_no_reminder(env):
    book(env, approve=False)
    assert fu.due_reminders(env["j"], desk_db.get_settings(env["t"]), now=EVE) == []


# ── Share & embed ────────────────────────────────────────────────────────────

def test_snippets():
    sn = desk_embed.snippets("https://bw.ai-prowler.com/", service_code="GUT", accent="#123456")
    assert sn["link"] == "https://bw.ai-prowler.com/book?service=GUT"
    assert 'href="https://bw.ai-prowler.com/book?service=GUT"' in sn["button"] and "#123456" in sn["button"]
    assert "embed=1" in sn["embed"] and "aiprowlerHeight" in sn["embed"] and "<iframe" in sn["embed"]
    assert "<script>alert" not in desk_embed.snippets("x", label="<script>alert(1)</script>")["button"]


def test_allowed_websites_set_the_frame_policy_and_are_local_only(env):
    assert p.frame_policy(env["t"]) == b"frame-ancestors 'self'"
    desk_db.set_setting(env["t"], "booking_allowed_sites", ["https://www.BlueWave.com/book", "*.bw.com"], edition=S)
    assert desk_db.get_settings(env["t"])["booking_allowed_sites"] == ["www.bluewave.com", "*.bw.com"]
    assert p.frame_policy(env["t"]) == b"frame-ancestors 'self' https://www.bluewave.com https://*.bw.com"
    with pytest.raises(desk_db.DeskError):
        desk_db.set_setting(env["t"], "booking_allowed_sites", ["not a site; script-src *"], edition=S)
    msg = desk_tools.tickets_settings(env["t"], OWNER, S, setting="booking_allowed_sites", value=["evil.com"])
    assert "only be changed in AI-Prowler" in msg
    assert desk_db.get_settings(env["t"])["booking_allowed_sites"] == ["www.bluewave.com", "*.bw.com"]


def test_gui_save_followup(env):
    import desk_gui_settings as g
    ok, msg = g.save_followup(env["t"], {"sites": "bluewave.com, https://shop.bluewave.com/x", "booking_waitlist": True,
                                         "booking_waitlist_hold_hours": "3", "booking_waitlist_approval": False,
                                         "booking_reminders": "Email and text", "booking_reminder_hour": "18",
                                         "booking_reminder_morning": True}, S)
    s = desk_db.get_settings(env["t"])
    assert ok, msg
    assert s["booking_allowed_sites"] == ["bluewave.com", "shop.bluewave.com"]
    assert (s["booking_waitlist_hold_hours"], s["booking_reminders"], s["booking_reminder_hour"]) == (3, "both", 18)
    assert g.save_followup(env["t"], {"sites": "nope"}, S)[0] is False
