"""
HR Portal pages on real data — server side (David, 2026-10-16, Phase 3).

  * holidays computed for any year (nth-weekday rules, weekend -> observed day),
    paid list set by HR
  * PTO: yearly allowance, first-year proration, carryover cap, sick days apart,
    paid holidays / weekends / pending / bereavement not deducted, HR adjustments
  * weekly hours, per-person allowance and gender validated on the employee
  * announcements (HR writes, employees acknowledge / RSVP) and the feed's
    automatic items
  * company resources (handbook, policies) as real files
  * an employee's own to-dos / reminders / goals, photo, one-time browser upload
  * every route: signed-in only; HR-only actions refuse employees; employees
    only ever see their own things

All in pytest's tmp_path with ZTEST data; never the real HR data or config.json.

Run: run_tests.bat tests\\mcp_tests\\test_hr_portal_phase3.py -v
"""
import base64
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TODAY = dt.date.today()
PDF = b"%PDF-1.4 ZTEST handbook"
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
durl = lambda raw, mime="application/pdf": f"data:{mime};base64," + base64.b64encode(raw).decode()  # noqa: E731


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    live = tmp_path / "hr"
    live.mkdir()
    monkeypatch.setattr(m, "_HR_DB_PATH", str(live / "hr_db.json"))
    m._hr_save_db({"config": {"company_name": "ZTEST Co", "setup_complete": True},
                   "employees": [
                       {"id": "EMP-00001", "first_name": "ZTEST", "last_name": "One", "status": "Active",
                        "start_date": "2025-01-01", "pay_frequency": "Bi-weekly"},
                       {"id": "EMP-00002", "first_name": "ZTEST", "last_name": "Two", "status": "Active",
                        "start_date": "2026-04-15"}],
                   "tasks": [], "documents": [], "audit_log": [], "pto_requests": []})
    m.ztest_live = live
    return m


def call(ap, method, path, body=None, role="admin", emp="EMP-00001", query=None):
    auth = {"role": "admin", "user_id": "ztest-admin"} if role == "admin" else \
           ({"role": "employee", "employee_id": emp} if role == "employee" else {"role": None})
    st, ct, b = ap._hr_api_route(method, path, query or {}, body or {}, auth)
    return st, json.loads(b)


def add_pto(ap, emp, start, end, typ="PTO (Vacation)", status="approved", half=False):
    db = ap._hr_load_db()
    db["pto_requests"].append({"id": f"PTOREQ-{len(db['pto_requests']) + 1:05d}", "employee_id": emp,
                               "type": typ, "start_date": start, "end_date": end, "half_day": half,
                               "status": status})
    ap._hr_save_db(db)


# ── holidays ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("year", [2024, 2025, 2026, 2027, 2031])
def test_holiday_rules_hold_every_year(ap, year):
    h = {x["key"]: x for x in ap._hr_holidays(year)}
    d = lambda k: dt.date.fromisoformat(h[k]["date"])                       # noqa: E731
    assert d("mlk").weekday() == 0 and 15 <= d("mlk").day <= 21 and d("mlk").month == 1
    assert d("presidents").weekday() == 0 and 15 <= d("presidents").day <= 21
    assert d("memorial").weekday() == 0 and d("memorial").day >= 25 and d("memorial").month == 5
    assert d("labor").weekday() == 0 and d("labor").day <= 7 and d("labor").month == 9
    assert d("columbus").weekday() == 0 and 8 <= d("columbus").day <= 14
    assert d("thanksgiving").weekday() == 3 and 22 <= d("thanksgiving").day <= 28
    assert d("day_after_thanksgiving") == d("thanksgiving") + dt.timedelta(days=1)
    for k in ("new_year", "juneteenth", "independence", "veterans", "christmas"):
        obs = dt.date.fromisoformat(h[k]["observed"])
        assert obs.weekday() < 5, (k, year)
        assert abs((obs - d(k)).days) <= 1


def test_holiday_known_dates(ap):
    h26 = {x["key"]: x for x in ap._hr_holidays(2026)}
    assert h26["mlk"]["date"] == "2026-01-19" and h26["thanksgiving"]["date"] == "2026-11-26"
    assert h26["independence"]["date"] == "2026-07-04" and h26["independence"]["observed"] == "2026-07-03"
    h27 = {x["key"]: x for x in ap._hr_holidays(2027)}
    assert h27["christmas"]["observed"] == "2027-12-24"
    assert "2027-12-31" in ap._hr_paid_holiday_dates(2027, {}), "New Year's Day 2028 (a Saturday) is observed in 2027"
    assert h26["christmas_eve"]["observed"] == "2026-12-24", "eves are not moved"


def test_holidays_routes_and_paid_policy(ap):
    st, r = call(ap, "GET", "/holidays", role="employee", query={"year": "2027"})
    assert st == 200 and r["year"] == 2027 and len(r["holidays"]) == 14
    assert {x["key"] for x in r["holidays"] if x["paid"]} >= {"new_year", "christmas", "thanksgiving"}
    assert call(ap, "POST", "/holidays/policy", {"paid": ["christmas"]}, role="employee")[0] == 403
    st, r = call(ap, "POST", "/holidays/policy", {"paid": ["christmas", "day_after_thanksgiving", "bogus"]})
    assert st == 200 and {x["key"] for x in r["holidays"] if x["paid"]} == {"christmas", "day_after_thanksgiving"}
    assert call(ap, "GET", "/holidays", role=None)[0] == 401


# ── PTO ─────────────────────────────────────────────────────────────────────
def test_first_year_is_prorated_and_policy_editable(ap):
    st, r = call(ap, "GET", "/pto/balance", role="employee", emp="EMP-00002", query={"year": "2026"})
    assert st == 200 and r["pto"]["allowance"] == 11.5, "15 days x 9/12 months = 11.25 -> 11.5"
    assert r["sick"]["allowance"] == 4.0, "5 x 9/12 = 3.75 -> 4"
    assert call(ap, "POST", "/pto/policy", {"days_per_year": 20}, role="employee")[0] == 403
    assert call(ap, "POST", "/pto/policy", {"days_per_year": 999})[0] == 400
    st, r = call(ap, "POST", "/pto/policy", {"days_per_year": 12, "prorate_first_year": False, "carryover_max": 3})
    assert st == 200 and r["policy"]["days_per_year"] == 12
    r = call(ap, "GET", "/pto/balance", role="employee", emp="EMP-00002", query={"year": "2026"})[1]
    assert r["pto"]["allowance"] == 12.0


def test_usage_counts_workdays_only(ap):
    # Mon 2026-11-23 .. Fri 2026-11-27: Thanksgiving (paid) not deducted, day after (unpaid by default) is
    add_pto(ap, "EMP-00001", "2026-11-23", "2026-11-27")
    add_pto(ap, "EMP-00001", "2026-03-06", "2026-03-09")              # Fri..Mon -> 2 workdays
    add_pto(ap, "EMP-00001", "2026-02-02", "2026-02-02", half=True)    # half day
    add_pto(ap, "EMP-00001", "2026-05-04", "2026-05-05", typ="Sick Day")
    add_pto(ap, "EMP-00001", "2026-06-01", "2026-06-03", typ="bereavement")   # not deducted
    add_pto(ap, "EMP-00001", "2026-08-03", "2026-08-04", status="pending")
    r = call(ap, "GET", "/pto/balance", role="employee", query={"year": "2026"})[1]
    assert r["pto"]["used"] == 4 + 2 + 0.5
    assert r["pto"]["pending"] == 2
    assert r["sick"]["used"] == 2
    assert r["pto"]["remaining"] == r["pto"]["allowance"] + r["pto"]["carried_over"] - 6.5


def test_carryover_is_capped(ap):
    add_pto(ap, "EMP-00001", "2025-03-03", "2025-03-07")               # 5 days used in 2025
    r = call(ap, "GET", "/pto/balance", role="employee", query={"year": "2026"})[1]
    assert r["pto"]["carried_over"] == 5.0, "10 unused, capped at 5"
    assert r["pto"]["remaining"] == 20.0


def test_hr_adjustments_and_per_person_allowance(ap):
    assert call(ap, "POST", "/pto/adjust", {"employee_id": "EMP-00001", "days": 2}, role="employee")[0] == 403
    st, r = call(ap, "POST", "/pto/adjust", {"employee_id": "EMP-00001", "days": 2.5, "note": "ZTEST opening",
                                             "date": "2026-01-01"})
    assert st == 200 and r["pto"]["adjusted"] == 2.5
    assert call(ap, "POST", "/pto/adjust", {"employee_id": "EMP-00001", "days": 0})[0] == 400
    assert call(ap, "PATCH", "/employees/EMP-00001", {"pto_days_per_year": "20"})[0] == 200
    r = call(ap, "GET", "/pto/balance", query={"employee_id": "EMP-00001", "year": "2026"})[1]
    assert r["pto"]["allowance"] == 20.0 and r["days_per_year"] == 20.0
    assert any(a.get("action") == "pto_adjusted" for a in ap._hr_load_db()["audit_log"])


def test_balance_scoping(ap):
    st, r = call(ap, "GET", "/pto/balance", role="employee", emp="EMP-00002", query={"employee_id": "EMP-00001"})
    assert r["employee_id"] == "EMP-00002", "employees only ever get their own balance"
    st, r = call(ap, "GET", "/pto/balance")
    assert {b["employee_id"] for b in r["balances"]} == {"EMP-00001", "EMP-00002"}


# ── employee fields ─────────────────────────────────────────────────────────
def test_work_schedule_and_gender_validation(ap):
    week = {"mon": {"start": "08:00", "end": "16:00"}, "tue": {"start": "08:00", "end": "16:00"},
            "sat": None, "location": "ZTEST Shop"}
    st, r = call(ap, "PATCH", "/employees/EMP-00001", {"work_schedule": week, "gender": "f"})
    assert st == 200 and r["employee"]["work_schedule"]["mon"]["start"] == "08:00"
    assert r["employee"]["work_schedule"]["wed"] is None and r["employee"]["gender"] == "F"
    assert call(ap, "PATCH", "/employees/EMP-00001", {"work_schedule": {"mon": {"start": "8am", "end": "4"}}})[0] == 400
    assert call(ap, "PATCH", "/employees/EMP-00001", {"gender": "X"})[0] == 400
    me = call(ap, "GET", "/portal/me", role="employee")[1]["employee"]
    assert me["work_schedule"]["location"] == "ZTEST Shop"


# ── announcements + feed ────────────────────────────────────────────────────
def test_announcements_flow(ap):
    assert call(ap, "POST", "/announcements", {"title": "x"}, role="employee")[0] == 403
    assert call(ap, "POST", "/announcements", {"title": ""})[0] == 400
    st, r = call(ap, "POST", "/announcements", {"title": "ZTEST enrollment closes", "body": "Review plans",
                                               "tag": "urgent", "ack_required": True})
    a1 = r["announcement"]["id"]
    st, r = call(ap, "POST", "/announcements", {"title": "ZTEST all-hands", "tag": "event", "rsvp": True,
                                               "event_date": "2026-12-01"})
    a2 = r["announcement"]["id"]
    call(ap, "POST", "/announcements", {"title": "ZTEST old news", "expires": "2020-01-01"})
    feed = call(ap, "GET", "/feed", role="employee")[1]
    assert [a["title"] for a in feed["announcements"]] == ["ZTEST all-hands", "ZTEST enrollment closes"], \
        "newest first, expired hidden from employees"
    assert call(ap, "POST", f"/announcements/{a1}/respond", {"ack": True}, role="employee")[0] == 200
    assert call(ap, "POST", f"/announcements/{a2}/respond", {"rsvp": "going"}, role="employee")[0] == 200
    assert call(ap, "POST", f"/announcements/{a2}/respond", {"rsvp": "cant"}, role="employee", emp="EMP-00002")[0] == 200
    mine = {a["id"]: a for a in call(ap, "GET", "/announcements", role="employee")[1]["announcements"]}
    assert mine[a1]["my_ack"] is True and mine[a2]["my_rsvp"] == "going"
    other = {a["id"]: a for a in call(ap, "GET", "/announcements", role="employee", emp="EMP-00002")[1]["announcements"]}
    assert other[a1]["my_ack"] is False, "responses are per employee"
    hr = {a["id"]: a for a in call(ap, "GET", "/announcements")[1]["announcements"]}
    assert hr[a1]["acks"] == 1 and hr[a2]["going"] == 1 and hr[a2]["cant"] == 1 and len(hr) == 3
    assert (ap.ztest_live / "employees" / "EMP-00001_One_ZTEST" / "announcement_responses.json").exists()
    assert call(ap, "POST", f"/announcements/{a1}/respond", {"ack": True})[0] == 403
    assert call(ap, "PATCH", f"/announcements/{a1}", {"pinned": True})[0] == 200
    assert call(ap, "GET", "/feed", role="employee")[1]["announcements"][0]["id"] == a1, "pinned first"
    assert call(ap, "DELETE", f"/announcements/{a2}")[0] == 200
    assert not [r for r in ap._hr_load_db().get("announcement_responses", []) if r["announcement_id"] == a2]


def test_feed_automatic_items(ap):
    db = ap._hr_load_db()
    db["employees"].append({"id": "EMP-00003", "first_name": "ZTEST", "last_name": "New", "status": "Active",
                            "start_date": (TODAY - dt.timedelta(days=3)).isoformat(),
                            "date_of_birth": f"1990-{TODAY.month:02d}-{TODAY.day:02d}"})
    db["employees"].append({"id": "EMP-00004", "first_name": "ZTEST", "last_name": "Gone", "status": "Terminated",
                            "start_date": (TODAY - dt.timedelta(days=3)).isoformat()})
    db["employees"][0]["start_date"] = TODAY.replace(year=TODAY.year - 2).isoformat()
    ap._hr_save_db(db)
    feed = call(ap, "GET", "/feed", role="employee")[1]
    assert [h["name"] for h in feed["new_hires"]] == ["ZTEST New"]
    assert [b["name"] for b in feed["birthdays"]] == ["ZTEST New"] and "1990" not in json.dumps(feed["birthdays"])
    assert {"name": "ZTEST One", "years": 2, "day": TODAY.day} in feed["anniversaries"]
    assert feed["company"]["name"] == "ZTEST Co"
    for h in feed["holidays"]:
        assert 0 <= (dt.date.fromisoformat(h["observed"]) - TODAY).days <= 45


# ── resources ───────────────────────────────────────────────────────────────
def test_company_resources(ap):
    assert call(ap, "POST", "/resources", {"title": "x", "data": durl(PDF)}, role="employee")[0] == 403
    st, r = call(ap, "POST", "/resources", {"title": "ZTEST Handbook 2026", "category": "handbook",
                                           "name": "handbook.pdf", "data": durl(PDF), "description": "Read me"})
    assert st == 200
    res = r["resource"]
    assert list((ap.ztest_live / "company" / "files" / "resources" / "handbook").glob("*_handbook.pdf"))
    lst = call(ap, "GET", "/resources", role="employee")[1]["resources"]
    assert [x["title"] for x in lst] == ["ZTEST Handbook 2026"] and "rel_path" not in json.dumps(lst)
    st, r = call(ap, "GET", f"/resources/{res['id']}/download", role="employee")
    assert st == 200 and base64.b64decode(r["data_b64"]) == PDF
    assert call(ap, "DELETE", f"/resources/{res['id']}", role="employee")[0] == 403
    assert call(ap, "DELETE", f"/resources/{res['id']}")[0] == 200
    assert call(ap, "GET", "/resources", role="employee")[1]["resources"] == []
    assert list((ap.ztest_live / "company" / "files" / "_deleted_files").glob("*_handbook.pdf"))


# ── an employee's own things ────────────────────────────────────────────────
def test_personal_lists_are_private(ap):
    todos = [{"id": 1, "text": "ZTEST call vendor", "done": False}]
    assert call(ap, "POST", "/portal/items/todos", {"items": todos}, role="employee")[0] == 200
    assert call(ap, "GET", "/portal/items/todos", role="employee")[1]["items"] == todos
    assert call(ap, "GET", "/portal/items/todos", role="employee", emp="EMP-00002")[1]["items"] == []
    assert call(ap, "GET", "/portal/items/todos")[0] == 403, "not even HR reads someone's to-do list"
    assert call(ap, "GET", "/portal/items/bogus", role="employee")[0] == 404
    assert call(ap, "POST", "/portal/items/todos", {"items": [{"x": "y" * 300_000}]}, role="employee")[0] == 400
    assert (ap.ztest_live / "employees" / "EMP-00001_One_ZTEST" / "personal_todos.json").exists()


def test_portal_photo_is_the_same_photo_hr_sees(ap):
    assert call(ap, "POST", "/portal/photo", {"data": durl(PNG, "image/png")}, role="employee")[0] == 200
    assert call(ap, "GET", "/portal/photo", role="employee")[1]["photo"].startswith("data:image/png")
    assert "EMP-00001" in call(ap, "GET", "/admin-photos")[1]["photos"]
    assert call(ap, "POST", "/portal/photo", {"data": durl(PDF)}, role="employee")[0] == 400


def test_portal_import_once_and_merge(ap):
    body = {"photo": durl(PNG, "image/png"), "todos": [{"id": 7, "text": "ZTEST mine"}],
            "reminders": [{"id": "r1", "text": "ZTEST stretch", "time": "09:00"}]}
    st, r = call(ap, "POST", "/portal/import", body, role="employee")
    assert st == 200 and r["summary"] == {"photo": True, "todos": 1, "reminders": 1}
    st, r = call(ap, "POST", "/portal/import", body, role="employee")
    assert r["summary"] == {"photo": False, "todos": 0, "reminders": 0}, "running it again changes nothing"
    assert len(call(ap, "GET", "/portal/items/todos", role="employee")[1]["items"]) == 1
    assert call(ap, "POST", "/portal/import", body)[0] == 403


def test_portal_goals_show_hr_goals(ap):
    call(ap, "POST", "/admin-store/hr_perf_v1", {"value": {"EMP-00001": {"goals": [
        {"id": "G1", "title": "ZTEST finish certification", "status": "In Progress"}]}}})
    call(ap, "POST", "/portal/items/goals", {"items": [{"id": "m1", "title": "ZTEST read a book", "done": True}]},
         role="employee")
    r = call(ap, "GET", "/portal/goals", role="employee")[1]
    assert r["hr_goals"][0]["title"] == "ZTEST finish certification" and r["my_goals"][0]["done"] is True
    assert call(ap, "GET", "/portal/goals", role="employee", emp="EMP-00002")[1]["hr_goals"] == []


def test_ai_chat_uses_the_settings(ap):
    call(ap, "POST", "/pto/policy", {"days_per_year": 12, "sick_days_per_year": 6})
    r = call(ap, "POST", "/ai-chat", {"message": "how much vacation do I get"}, role="employee")[1]
    assert "12 PTO days" in r["reply"] and "6 sick days" in r["reply"] and "1.25" not in r["reply"]
    r = call(ap, "POST", "/ai-chat", {"message": "when do I get paid"}, role="employee")[1]
    assert "bi-weekly" in r["reply"] and "every Friday" not in r["reply"]


def test_all_new_routes_need_sign_in(ap):
    for method, path in (("GET", "/holidays"), ("POST", "/holidays/policy"), ("GET", "/pto/policy"),
                         ("POST", "/pto/policy"), ("GET", "/pto/balance"), ("POST", "/pto/adjust"),
                         ("GET", "/feed"), ("GET", "/announcements"), ("POST", "/announcements"),
                         ("GET", "/resources"), ("POST", "/resources"), ("GET", "/portal/items/todos"),
                         ("GET", "/portal/goals"), ("GET", "/portal/photo"), ("POST", "/portal/import")):
        assert call(ap, method, path, role=None)[0] == 401, (method, path)
