"""The booking agent's last three jobs (booking-agent-spec §4–§6): the weather check for
outdoor services, offering openings to the waitlist (Keep on track decides — David's
decision 4), and Learn from real time on site. No network: desk_agent_evidence.fetch stands
in for the forecast. Fixed booking clock: Monday 1 Mar 2027.
Run: run_tests.bat tests\\unit\\test_booking_agent_triggers.py
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
import desk_agent as ag  # noqa: E402
import desk_agent_evidence as ev  # noqa: E402
import desk_db  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

S = r.SOLO
OWNER = {"id": "owner", "role": r.OWNER}
ADDR = {"street": "12 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"}
TUE9, FRI7 = "2027-03-02T09:00-11:00", "2027-03-05T07:00-09:00"


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    for k, v in (("portal_enabled", True), ("booking_paths", ["book", "problem"]), ("agent_enabled", True),
                 ("agent_shadow", False), ("agent_bk_enabled", True), ("agent_bk_shadow", False),
                 ("agent_bk_stage_track", "auto"), ("agent_bk_stage_learn", "suggest")):
        desk_db.set_setting(tickets, k, v, edition=S)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.execute("INSERT INTO service_pricing (service_code, name, base_price) VALUES ('WIN-EXT', 'Exterior windows', 150)")
    conn.close()
    bdb.sync_services(jobs)
    bdb.update_service(jobs, "WIN-EXT", online=True, minutes=105, buffer_min=15, outdoor=True)
    sent = []
    clock = {"now": dt.datetime(2027, 3, 1, 6, 0)}
    p.send_fn = lambda ch, to, subj, text: sent.append((ch, to, text)) or True
    p.channels_fn = lambda: {"email": True, "sms": True}
    p.jobs_db_fn = lambda: jobs
    bf.clock = lambda: clock["now"]
    ag.enable(lambda: tickets)
    ev._CACHE.clear()
    yield {"t": tickets, "j": jobs, "sent": sent, "clock": clock}
    ag.disable()
    ev.fetch = None
    p.send_fn = p.channels_fn = p.jobs_db_fn = None
    bf.clock = None


def api(e, method, path, body=None, ip="1.2.3.4"):
    st, ct, out = p.route(method, "/support-api" + path, query={}, body=json.dumps(body or {}).encode(),
                          content_type="application/json", ip=ip, db_path=e["t"], edition=S,
                          base_url="https://x.example", business="Blue Wave")
    return st, (json.loads(out) if ct.startswith(b"application/json") else out)


def book(e, key, phone="386-555-0142", email="maria@example.com", ip="1.2.3.4"):
    st, h = api(e, "POST", "/hold", {"service_code": "WIN-EXT", "window_key": key}, ip=ip)
    assert st == 200, h
    st, d = api(e, "POST", "/start", {"name": "Maria Lopez", "phone": phone, "email": email, "send_by": "email"}, ip=ip)
    code = re.search(r"\b(\d{6})\b", [t for _c, to, t in e["sent"] if to == email and "code is" in t][-1]).group(1)
    st, out = api(e, "POST", "/verify", {"contact_id": d["contact_id"], "code": code, "path": "book",
                                          "service_code": "WIN-EXT", "address": ADDR, "hold_id": h["hold_id"],
                                          "window_key": key}, ip=ip)
    assert st == 201, out
    bf.approve(e["j"], e["t"], out["job_id"], actor=OWNER, edition=S, settings=desk_db.get_settings(e["t"]))
    conn = get_connection(e["j"])
    conn.execute("UPDATE jobs SET latitude = 29.03, longitude = -80.93 WHERE job_id = ?", (out["job_id"],))
    conn.close()
    return out


def setv(e, **kw):
    for k, v in kw.items():
        desk_db.set_setting(e["t"], k, v, edition=S)


def clear_queue(e):
    ag.ensure_schema(e["t"])
    conn = get_connection(e["t"])
    conn.execute("UPDATE agent_queue SET status = 'done' WHERE status IN ('waiting', 'claimed')")
    conn.close()


def take(e, stage):
    for it in ag.next_items(e["t"], edition=S, jobs_db=e["j"], limit=10)["items"]:
        if it["stage"] == stage:
            return it
    conn = get_connection(e["t"])
    rows = [dict(x) for x in conn.execute("SELECT stage, reason, status, note FROM agent_queue")]
    conn.close()
    raise AssertionError(f"no {stage} item: {rows}")


def forecast(rain, wind=5):
    def f(lat, lon, date):
        return {"hourly": {"time": [f"{date}T{h:02d}:00" for h in range(24)],
                           "precipitation_probability": [rain] * 24, "wind_speed_10m": [wind] * 24}}
    return f


def queued(e, stage, reason_like="%"):
    conn = get_connection(e["t"])
    try:
        return [dict(x) for x in conn.execute("SELECT * FROM agent_queue WHERE stage = ? AND reason LIKE ?",
                                              (stage, reason_like))]
    finally:
        conn.close()


# ── the weather check ────────────────────────────────────────────────────────

def test_rain_tomorrow_queues_once_and_the_agent_offers_another_day(env):
    b = book(env, TUE9)
    clear_queue(env)
    ev.fetch = forecast(80, 12)
    assert ag.scan_bookings(env["t"], env["j"], now=dt.datetime(2027, 3, 1, 15, 0)) == 0      # before 16:00
    assert ag.scan_bookings(env["t"], env["j"], now=dt.datetime(2027, 3, 1, 16, 30)) == 1
    assert ag.scan_bookings(env["t"], env["j"], now=dt.datetime(2027, 3, 1, 17, 30)) == 0     # once a day
    item = take(env, "track")
    assert item["trigger"] == "weather" and item["weather"]["bad"] is True and item["weather"]["rain_pct"] == 80
    assert "bk_suggest_time" in item["allowed_actions"] and "hint" in item
    assert all(w["date"] != "2027-03-02" for w in item["windows"])                          # never the same day
    key = item["windows"][0]["key"]
    out = ag.submit(env["t"], item["item_id"], [{"action": "bk_suggest_time", "window_key": key, "confidence": 0.9,
                                                 "note": "Rain is likely tomorrow (80%).", "why": "rain"}],
                    edition=S, jobs_db=env["j"])
    assert out["results"][0]["status"] == "applied", out
    got = bf.get(env["j"], b["job_id"])
    assert got["req"]["status"] == "suggested" and got["scheduled_key"] == TUE9          # the visit stays


def test_a_fine_forecast_holds_the_offer(env):
    book(env, TUE9)
    clear_queue(env)
    ev.fetch = forecast(20, 8)
    ag.scan_bookings(env["t"], env["j"], now=dt.datetime(2027, 3, 1, 16, 30))
    item = take(env, "track")
    assert item["weather"]["bad"] is False
    out = ag.submit(env["t"], item["item_id"], [{"action": "bk_suggest_time", "window_key": item["windows"][0]["key"],
                                                 "confidence": 0.9, "note": "Maybe rain", "why": "?"}],
                    edition=S, jobs_db=env["j"])
    res = out["results"][0]
    assert res["status"] == "pending" and "isn't bad enough" in res["why"]


def test_wind_alone_counts_and_errors_never_count():
    ev._CACHE.clear()
    ev.fetch = forecast(10, 30)
    assert ev.weather(29.0, -80.9, "2027-03-02", "09:00", "13:00")["bad"] is True
    ev._CACHE.clear()
    ev.fetch = lambda *a: (_ for _ in ()).throw(OSError("offline"))
    w = ev.weather(29.0, -80.9, "2027-03-02")
    assert w["bad"] is False and "unavailable" in w["error"]
    assert ev.weather(None, None, "2027-03-02")["error"].startswith("no map location")
    ev.fetch = None


def test_no_weather_check_for_indoor_services_or_when_switched_off(env):
    book(env, TUE9)
    clear_queue(env)
    ev.fetch = forecast(90)
    setv(env, agent_bk_weather=False)
    assert ag.scan_bookings(env["t"], env["j"], now=dt.datetime(2027, 3, 1, 16, 30)) == 0
    setv(env, agent_bk_weather=True)
    bdb.update_service(env["j"], "WIN-EXT", outdoor=False)
    assert ag.scan_bookings(env["t"], env["j"], now=dt.datetime(2027, 3, 1, 16, 30)) == 0


# ── waitlist offers through Keep on track ────────────────────────────────────

def waitlisted(env):
    setv(env, booking_waitlist=True)
    b = book(env, FRI7)
    api(env, "POST", f"/t/{b['token']}/booking/wait")
    clear_queue(env)
    return b


def sweep(env):
    return fu.sweep_waitlist(env["j"], env["t"], desk_db.get_settings(env["t"]), edition=S)


def test_on_suggest_the_owner_oks_each_offer(env):
    setv(env, agent_bk_stage_track="suggest")
    b = waitlisted(env)
    got = sweep(env)
    assert got["offered"] == [] and len(got["queued"]) == 1
    assert sweep(env).get("queued") is None                                   # one at a time
    item = take(env, "track")
    assert item["trigger"] == "waitlist" and item["opening"]["key"] == got["queued"][0]["key"]
    out = ag.submit(env["t"], item["item_id"], [{"action": "bk_offer_opening", "window_key": item["opening"]["key"],
                                                 "confidence": 0.9, "why": "earlier"}], edition=S, jobs_db=env["j"])
    res = out["results"][0]
    assert res["status"] == "pending"
    assert fu.entry_for(env["j"], b["job_id"])["status"] == "waiting"           # nothing offered yet
    assert sweep(env).get("queued") is None                                   # still deciding
    ag.review(env["t"], res["proposal_id"], "approve", actor_=OWNER, edition=S, jobs_db=env["j"])
    e = fu.entry_for(env["j"], b["job_id"])
    assert e["status"] == "offered" and e["offered_key"] == item["opening"]["key"]
    t = desk_db.get_ticket_detail(env["t"], b["ticket_id"], actor=None, edition=S)
    assert any("earlier time opened" in m["body"] for m in t["messages"] if m["visibility"] == "public")


def test_on_auto_the_offer_goes_at_once(env):
    b = waitlisted(env)
    sweep(env)
    item = take(env, "track")
    out = ag.submit(env["t"], item["item_id"], [{"action": "bk_offer_opening", "window_key": item["opening"]["key"],
                                                 "confidence": 0.9, "why": "earlier"}], edition=S, jobs_db=env["j"])
    assert out["results"][0]["status"] == "applied", out
    assert fu.entry_for(env["j"], b["job_id"])["status"] == "offered"


def test_the_agent_can_only_offer_the_opening_and_passing_moves_on(env):
    waitlisted(env)
    first = sweep(env)["queued"][0]["key"]
    item = take(env, "track")
    other = next(w["key"] for w in item["windows"] if w["key"] != first)
    out = ag.submit(env["t"], item["item_id"], [{"action": "bk_offer_opening", "window_key": other,
                                                 "confidence": 0.9, "why": "x"}], edition=S, jobs_db=env["j"])
    assert out["results"][0]["status"] == "rejected"
    nxt = sweep(env)["queued"][0]["key"]                                      # it passed on `first`
    assert nxt != first


def test_with_keep_on_track_off_the_waitlist_offers_by_itself(env):
    setv(env, agent_bk_stage_track="off")
    b = waitlisted(env)
    got = sweep(env)
    assert len(got["offered"]) == 1 and not got.get("queued")
    assert fu.entry_for(env["j"], b["job_id"])["status"] == "offered"


# ── Learn: real time on site ─────────────────────────────────────────────────

def done_jobs(env, minutes, *, timer=True):
    conn = get_connection(env["j"])
    try:
        for i, m in enumerate(minutes):
            jid = f"JOB-L{i:03d}"
            conn.execute("INSERT INTO jobs (job_id, customer_name, service_type, service_date, job_status, "
                         "actual_duration, actual_duration_unit) VALUES (?, 'Old customer', 'Exterior windows', ?, "
                         "'Completed', ?, 'min')", (jid, f"2027-02-{i + 1:02d}", None if timer else m))
            if timer:
                conn.execute("INSERT INTO time_entries (entry_id, job_id, entry_date, clock_in, clock_out) "
                             "VALUES (?, ?, ?, ?, ?)", (f"TE-{i}", jid, f"2027-02-{i + 1:02d}",
                                                        f"2027-02-{i + 1:02d} 09:00:00",
                                                        (dt.datetime(2027, 2, i + 1, 9) + dt.timedelta(minutes=m))
                                                        .strftime("%Y-%m-%d %H:%M:%S")))
    finally:
        conn.close()


def finish(env, b):
    conn = get_connection(env["j"])
    conn.execute("UPDATE jobs SET job_status = 'Completed' WHERE job_id = ?", (b["job_id"],))
    conn.close()


def test_time_on_site_finds_a_pattern_from_the_job_timer(env):
    done_jobs(env, [140, 150, 145, 160, 150])
    t = ev.time_on_site(env["j"], "WIN-EXT", 105, name="Exterior windows")
    assert t["n"] == 5 and t["median_minutes"] == 150 and t["pattern"] and t["suggested_minutes"] == 150
    assert {j["from"] for j in t["jobs"]} == {"job timer"}


def test_actual_duration_counts_too_and_a_small_difference_isnt_a_pattern(env):
    done_jobs(env, [110, 100, 115, 105, 110], timer=False)
    t = ev.time_on_site(env["j"], "WIN-EXT", 105, name="Exterior windows")
    assert t["n"] == 5 and not t["pattern"] and t["suggested_minutes"] is None


def test_learn_proposes_new_minutes_and_a_person_approves(env):
    done_jobs(env, [140, 150, 145, 160, 150])
    b = book(env, TUE9)
    clear_queue(env)
    finish(env, b)
    ag.scan_bookings(env["t"], env["j"])
    item = take(env, "learn")
    assert item["trigger"] == "learn" and item["time_on_site"]["suggested_minutes"] == 150
    out = ag.submit(env["t"], item["item_id"], [{"action": "bk_set_minutes", "service_code": "WIN-EXT", "minutes": 150,
                                                 "confidence": 0.9, "why": "jobs run long"}], edition=S, jobs_db=env["j"])
    res = out["results"][0]
    assert res["status"] == "pending" and "evidence" not in (res.get("why") or "")
    ag.review(env["t"], res["proposal_id"], "approve", actor_=OWNER, edition=S, jobs_db=env["j"])
    assert next(x for x in bdb.list_services(env["j"]) if x["code"] == "WIN-EXT")["minutes"] == 150


def test_learn_without_a_pattern_says_so(env):
    done_jobs(env, [140, 150])
    b = book(env, TUE9)
    clear_queue(env)
    finish(env, b)
    ag.scan_bookings(env["t"], env["j"])
    item = take(env, "learn")
    out = ag.submit(env["t"], item["item_id"], [{"action": "bk_set_minutes", "service_code": "WIN-EXT", "minutes": 150,
                                                 "confidence": 0.9, "why": "?"}], edition=S, jobs_db=env["j"])
    assert "not enough evidence" in out["results"][0]["why"]
