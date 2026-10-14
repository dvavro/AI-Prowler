"""
HR apps — every feature and data entry, live on the AI-Prowler server, three
real users (David 2026-10-12: "make sure all the features and data entries work").

Users (users.local.json): David (owner) and Vicki (manager) are HR admins; for the
HR Portal, Samual's AI-Prowler account is linked to ZTEST employee #1 and Vicki's
to ZTEST employee #2 (so shift swaps run between two real portal users). Every
write is read back by a DIFFERENT user and checked field by field.

  HF-01 employee record + edit             HF-11 directory
  HF-02 onboarding tasks (complete/waive/   HF-12 attendance (admin + self-report
        reassign/custom), employee sees           with location consent)
        only their own                     HF-13 documents (upload/download/delete)
  HF-03 time off (request/approve/deny)    HF-14 portal profile (own fields only)
  HF-04 time clock (in/out/double/delete)  HF-15 recruiting (round trip, restored)
  HF-05 messages (send/reply/read/delete;  HF-16 incidents (sign-in required,
        sender identity from the session)         filed under the caller)
  HF-06 schedule-change requests           HF-17 role isolation (employees can't
  HF-07 shift swaps between two employees         see/approve others' data)
  HF-08 training                           HF-18 termination in HR Admin -> portal
  HF-09 calendar events/notes/reminders           access ends + offboarding tasks
  HF-10 work locations                            (R-091, fixed 2026-10-12)
  HF-19 every HR Admin screen and every HR Portal page opens with no script
        errors and shows the ZTEST data (browser, human mode)

All test data is ZTEST-named or tied to the two +hrtest@ employees and is
removed at the end (POST /hr-api/test/cleanup with all_linked +
include_ztest_named + include_employees) — then the server is checked for
leftovers. Needs the 2026-10-12 server code (cleanup options, incident fix).

Run (human mode): run_tests_gui_jobs_e2e.bat --server --human -k test_srv_hr_features
"""
import base64
import datetime as dt
import json
import uuid

import pytest
from playwright.sync_api import expect

from test_srv_hr_apps import (_admin_sign_in, _crew_user_id, _http, _json,  # noqa: F401
                              _portal_sign_in, hr, page_for)

TODAY = dt.date.today()
D = lambda n: (TODAY + dt.timedelta(days=n)).isoformat()          # noqa: E731
RUN = uuid.uuid4().hex[:6].upper()                                 # tags this run's records


# ── module fixture: two ZTEST employees, linked logins, sessions, cleanup ────
@pytest.fixture(scope="module")
def team(hr):
    o = hr["origin"]

    def admin_api(user):
        st, _, b = hr["admin_login"](user)
        assert st == 200, f"{user.name} HR Admin sign-in: {st} {b[:160]}"
        tok = _json(b)["access_token"]

        def api(method, path, body=None):
            st, _, txt = _http(method, o + "/hr-api" + path, body, {"Authorization": f"Bearer {tok}"})
            return st, _json(txt)
        api.user = user
        return api

    david, vicki_admin = admin_api(hr["owner"]), admin_api(hr["manager"])
    emps = []
    for n, (who, email) in enumerate(((hr["crew"], f"ztest.hf1.{RUN.lower()}+hrtest@example.com"),
                                      (hr["manager"], f"ztest.hf2.{RUN.lower()}+hrtest@example.com")), 1):
        st, r = david("POST", "/employees", {
            "personal": {"first_name": f"ZTEST HF{n}", "last_name": RUN, "personal_email": email,
                         "phone": "555-0100"},
            "employment": {"title": "ZTEST Tech", "department": "ZTEST", "work_state": "FL",
                           "start_date": D(-40), "manager_name": hr["owner"].name},
            "compensation": {"pay_type": "hourly", "pay_rate": 21.5, "pay_frequency": "Bi-weekly"}})
        assert st == 200 and r.get("id"), f"create ZTEST HF{n}: {st} {r}"
        emps.append(r["id"])
    users = {u["name"].lower(): u["id"] for u in david("GET", "/aiprowler-users")[1]["users"]}
    for emp_id, who in zip(emps, (hr["crew"], hr["manager"])):
        st, r = david("PATCH", f"/employees/{emp_id}",
                      {"aiprowler_user_id": users[who.name.lower()], "aiprowler_user_name": who.name})
        assert st == 200, f"link {who.name}: {st} {r}"

    def portal_api(user, emp_id):
        st, _, b = _http("POST", o + "/hr-api/auth/aiprowler", {"name": user.name, "token": user.token})
        assert st == 200, f"{user.name} portal sign-in: {st} {b[:200]}"
        sess = json.dumps(_json(b)["session"])
        assert _json(sess)["employee_id"] == emp_id

        def api(method, path, body=None):
            st, _, txt = _http(method, o + "/hr-api" + path, body, {"X-Employee-Session": sess})
            return st, _json(txt)
        api.user, api.emp_id, api.session = user, emp_id, sess
        return api

    t = {"o": o, "david": david, "vicki_admin": vicki_admin, "emp1": emps[0], "emp2": emps[1],
         "samual": portal_api(hr["crew"], emps[0]), "vicki": portal_api(hr["manager"], emps[1]), "hr": hr}
    yield t
    # cleanup — even after failures
    st, r = david("POST", "/test/cleanup", {"all_linked": True, "include_ztest_named": True,
                                            "include_employees": True})
    assert st == 200, f"cleanup: {st} {r}"
    st, r = david("GET", "/employees")
    left = [e for e in r.get("employees", []) if "+hrtest@" in (e.get("personal_email") or "")
            and RUN in (e.get("last_name") or "")]
    assert not left, f"ZTEST employees left on the server: {[e['id'] for e in left]}"


def _ok(res, what):
    st, r = res
    assert 200 <= st < 300, f"{what}: HTTP {st} {str(r)[:300]}"
    return r


# ── HF-01 employee record ────────────────────────────────────────────────────
def test_HF_01_employee_record_and_edit(team):
    e = _ok(team["vicki_admin"]("GET", f"/employees/{team['emp1']}"), "Vicki reads HF1")
    e = e.get("employee", e)
    assert (e["first_name"], e["last_name"], e["title"], e["work_state"]) == ("ZTEST HF1", RUN, "ZTEST Tech", "FL")
    assert float(e["pay_rate"]) == 21.5 and e["start_date"] == D(-40)
    _ok(team["vicki_admin"]("PATCH", f"/employees/{team['emp1']}",
                            {"title": "ZTEST Senior Tech", "phone": "555-0199", "department": "ZTEST Ops"}), "edit")
    e = _ok(team["david"]("GET", f"/employees/{team['emp1']}"), "David reads back")
    e = e.get("employee", e)
    assert (e["title"], e["phone"], e["department"]) == ("ZTEST Senior Tech", "555-0199", "ZTEST Ops")
    emps = _ok(team["david"]("GET", "/employees"), "list")["employees"]
    assert {team["emp1"], team["emp2"]} <= {x["id"] for x in emps}


# ── HF-02 onboarding tasks ───────────────────────────────────────────────────
def test_HF_02_onboarding_tasks(team):
    mine = _ok(team["samual"]("GET", "/tasks"), "Samual's tasks")["tasks"]
    assert mine, ("Samual has no onboarding tasks — the server isn't generating them "
                  "(is hr_task_templates.json in the install folder?)")
    assert all(t["employee_id"] == team["emp1"] for t in mine), "Samual sees someone else's tasks"
    emp_task = next(t for t in mine if t.get("assigned_to_role") == "Employee"
                    and t["status"] not in ("Completed", "Waived"))
    _ok(team["samual"]("POST", f"/tasks/{emp_task['id']}/complete", {"notes": f"ZTEST done {RUN}"}), "complete")
    all_t = _ok(team["david"]("GET", f"/tasks?employee_id={team['emp1']}"), "David's view")["tasks"]
    got = next(t for t in all_t if t["id"] == emp_task["id"])
    assert got["status"] == "Completed" and RUN in (got.get("completion_notes") or "")
    hr_task = next(t for t in all_t if t.get("assigned_to_role") == "HR" and t["status"] not in ("Completed", "Waived"))
    _ok(team["david"]("POST", f"/tasks/{hr_task['id']}/waive", {"reason": f"ZTEST waive {RUN}"}), "waive")
    other = next(t for t in all_t if t["id"] not in (emp_task["id"], hr_task["id"])
                 and t["status"] not in ("Completed", "Waived"))
    _ok(team["vicki_admin"]("POST", f"/tasks/{other['id']}/reassign",
                            {"new_assignee": "Manager", "reason": "ZTEST"}), "reassign")
    r = _ok(team["david"]("POST", "/tasks", {"employee_id": team["emp1"], "name": f"ZTEST custom {RUN}",
                                             "priority": "LOW", "due_date": D(7), "assigned_to_role": "Employee",
                                             "phase": "Custom", "notes": "ZTEST"}), "custom task")
    cid = (r.get("task") or {}).get("id") or r.get("id")
    _ok(team["david"]("PATCH", f"/tasks/{cid}", {"due_date": D(9)}), "edit custom task")
    mine = {t["id"]: t for t in _ok(team["samual"]("GET", "/tasks"), "re-read")["tasks"]}
    assert mine[cid]["due_date"] == D(9) and mine[hr_task["id"]]["status"] == "Waived"


# ── HF-03 time off ───────────────────────────────────────────────────────────
def test_HF_03_time_off(team):
    s, d, v = team["samual"], team["david"], team["vicki_admin"]
    r1 = _ok(s("POST", "/pto/request", {"type": "Vacation", "start_date": D(20), "end_date": D(22),
                                         "notes": f"ZTEST trip {RUN}"}), "request 1")
    r2 = _ok(s("POST", "/pto/request", {"type": "Personal", "start_date": D(30), "end_date": D(30),
                                         "half_day": True, "half_day_period": "AM", "notes": f"ZTEST {RUN}"}), "request 2")
    id1 = (r1.get("request") or r1).get("id")
    id2 = (r2.get("request") or r2).get("id")
    pend = {x["id"]: x for x in _ok(d("GET", "/pto"), "HR list")["requests"]}
    assert pend[id1]["status"] == "pending" and pend[id1]["start_date"] == D(20) and pend[id1]["end_date"] == D(22)
    _ok(v("POST", f"/pto/{id1}/approve", {}), "Vicki approves")
    _ok(d("POST", f"/pto/{id2}/deny", {"reason": "ZTEST"}), "David denies")
    mine = {x["id"]: x for x in _ok(s("GET", "/pto/mine"), "Samual's view")["requests"]}
    assert (mine[id1]["status"], mine[id2]["status"]) == ("approved", "denied")
    company = _ok(s("GET", "/pto/company"), "company calendar")["requests"]   # shared view: no ids
    assert any(x.get("start_date") == D(20) and x.get("end_date") == D(22) for x in company), company[:3]


# ── HF-04 time clock ─────────────────────────────────────────────────────────
def test_HF_04_time_clock(team):
    s, d = team["samual"], team["david"]
    _ok(s("POST", "/timeclock/in", {"lat": 29.03, "lng": -80.93, "accuracy": 12}), "clock in")
    assert _ok(s("GET", "/timeclock/status"), "status")["clocked_in"] is True
    st, r = s("POST", "/timeclock/in", {})
    assert st == 400 and r.get("error") == "already_clocked_in", "double clock-in must be refused"
    today = _ok(d("GET", "/timeclock/today"), "HR today")["entries"]
    e = next(x for x in today if x["employee_id"] == team["emp1"] and x.get("clock_out") is None)
    assert e["clock_in_maps_url"] and "29.03" in e["clock_in_maps_url"]
    _ok(s("POST", "/timeclock/out", {}), "clock out")
    mine = _ok(s("GET", "/timeclock/mine"), "mine")["entries"]
    assert mine and mine[0]["id"] == e["id"] and mine[0]["clock_out"] and mine[0]["duration_minutes"] is not None
    _ok(d("DELETE", f"/timeclock/entries/{e['id']}"), "HR deletes the entry")
    assert e["id"] not in {x["id"] for x in _ok(d("GET", "/timeclock/entries"), "entries")["entries"]}


# ── HF-05 messages ───────────────────────────────────────────────────────────
def test_HF_05_messages(team):
    s, d = team["samual"], team["david"]
    _ok(s("POST", "/messages", {"subject": f"ZTEST question {RUN}", "body": "ZTEST body",
                                 "message_type": "general", "sender_name": "Someone Else"}), "send")
    m = next(x for x in _ok(d("GET", "/messages"), "HR inbox")["messages"] if RUN in (x.get("subject") or ""))
    assert m["employee_id"] == team["emp1"], "sender must come from the session"
    assert "Someone Else" not in json.dumps(m), "a forged sender name was stored"
    _ok(d("POST", "/messages/read", {"id": m["id"]}), "mark read")
    _ok(d("POST", "/messages/reply", {"id": m["id"], "reply": f"ZTEST reply {RUN}"}), "reply")
    mine = next(x for x in _ok(s("GET", "/messages/mine"), "Samual's view")["messages"] if x["id"] == m["id"])
    assert RUN in json.dumps(mine.get("reply")), "Samual doesn't see the reply"
    _ok(d("POST", "/messages/delete", {"id": m["id"], "box": "inbox"}), "delete")
    assert m["id"] not in {x["id"] for x in _ok(d("GET", "/messages"), "after delete")["messages"]}


# ── HF-06 schedule changes ───────────────────────────────────────────────────
def test_HF_06_schedule_change(team):
    s = team["samual"]
    ids = []
    for kind in ("swap_day", "different_hours"):
        r = _ok(s("POST", "/schedule-change/request", {"request_type": kind, "current_shift": "Mon 8-4",
                                                        "requested_change": f"ZTEST {RUN}", "reason": "ZTEST"}), kind)
        ids.append((r.get("request") or r).get("id"))
    _ok(team["vicki_admin"]("POST", f"/schedule-change/{ids[0]}/approve", {}), "approve")
    _ok(team["david"]("POST", f"/schedule-change/{ids[1]}/deny", {"reason": "ZTEST"}), "deny")
    mine = {x["id"]: x["status"] for x in _ok(s("GET", "/schedule-change/mine"), "mine")["requests"]}
    assert (mine[ids[0]], mine[ids[1]]) == ("approved", "denied")


# ── HF-07 shift swaps between two employees ──────────────────────────────────
def test_HF_07_shift_swap(team):
    s, v = team["samual"], team["vicki"]
    co = _ok(s("GET", "/swaps/coworkers"), "coworkers")["coworkers"]
    assert team["emp2"] in {c["id"] for c in co}
    r = _ok(s("POST", "/swaps", {"to_employee_id": team["emp2"], "message": f"ZTEST swap {RUN}"}), "ask")
    sw_id = (r.get("swap") or r).get("id")
    st, _ = s("POST", f"/swaps/{sw_id}/respond", {"decision": "approved"})
    assert st == 403, "the sender must not be able to answer their own swap"
    _ok(v("POST", f"/swaps/{sw_id}/respond", {"decision": "approved"}), "Vicki (employee) accepts")
    sw = next(x for x in _ok(team["david"]("GET", "/swaps"), "HR view")["swaps"] if x["id"] == sw_id)
    assert sw["status"] == "approved"
    assert any(m.get("swap_id") == sw_id for m in _ok(team["david"]("GET", "/messages"), "HR notice")["messages"])


# ── HF-08 training ───────────────────────────────────────────────────────────
def test_HF_08_training(team):
    d = team["david"]
    _ok(d("POST", "/training", {"employee_id": team["emp1"], "title": f"ZTEST Ladder safety {RUN}",
                                "provider": "ZTEST", "due_date": D(14), "notes": "ZTEST"}), "assign")
    recs = _ok(d("GET", "/training"), "HR list")["records"]
    rec = next(x for x in recs if RUN in (x.get("title") or ""))
    assert rec["employee_id"] == team["emp1"] and rec["due_date"] == D(14)
    _ok(team["vicki_admin"]("PATCH", f"/training/{rec['id']}", {"due_date": D(21)}), "edit")
    rec = next(x for x in _ok(d("GET", "/training"), "re-read")["records"] if x["id"] == rec["id"])
    assert rec["due_date"] == D(21)
    _ok(team["samual"]("POST", "/training/complete", {"title": rec["title"], "category": "safety",
                                                      "completed_date": TODAY.isoformat()}), "Samual completes")
    _ok(d("DELETE", f"/training/{rec['id']}"), "delete")


# ── HF-09 calendar ───────────────────────────────────────────────────────────
def test_HF_09_calendar(team):
    d, s = team["david"], team["samual"]
    _ok(d("POST", "/calendar/events", {"date": D(5), "end_date": D(6), "title": f"ZTEST Event {RUN}",
                                       "type": "company", "notes": "ZTEST"}), "event")
    ev = next(x for x in _ok(d("GET", "/calendar/events"), "events")["events"] if RUN in (x.get("title") or ""))
    assert (ev["date"], ev["end_date"]) == (D(5), D(6))
    _ok(d("POST", f"/calendar/events/{ev['id']}/delete", {}), "delete event")
    _ok(d("POST", "/reminders", {"date": D(3), "title": f"ZTEST Reminder {RUN}", "note": "ZTEST"}), "reminder")
    rem = next(x for x in _ok(d("GET", "/reminders"), "reminders")["reminders"] if RUN in (x.get("title") or ""))
    _ok(team["vicki_admin"]("PATCH", f"/reminders/{rem['id']}", {"date": D(4)}), "move reminder")
    rem = next(x for x in _ok(d("GET", "/reminders"), "re-read")["reminders"] if x["id"] == rem["id"])
    assert rem["date"] == D(4) and not rem.get("email_sent"), "moving a reminder must re-arm its email"
    _ok(d("DELETE", f"/reminders/{rem['id']}"), "delete reminder")
    _ok(s("POST", "/calendar/notes", {"notes": {D(2): f"ZTEST note {RUN}"}}), "Samual's note")
    assert RUN in json.dumps(_ok(s("GET", "/calendar/notes"), "notes"))
    _ok(s("POST", "/calendar/reminders", {"reminders": [{"date": D(2), "text": f"ZTEST {RUN}"}]}), "Samual reminder")
    assert RUN in json.dumps(_ok(s("GET", "/calendar/reminders"), "his reminders"))


# ── HF-10 work locations ─────────────────────────────────────────────────────
def test_HF_10_locations(team):
    d = team["david"]
    _ok(d("POST", "/locations", {"name": f"ZTEST Site {RUN}", "address": "1 ZTEST Way", "lat": 29.03,
                                 "lng": -80.93, "radius_m": 150, "notes": "ZTEST"}), "create")
    loc = next(x for x in _ok(d("GET", "/locations"), "list")["locations"] if RUN in (x.get("name") or ""))
    _ok(d("POST", f"/locations/{loc['id']}/assign", {"employee_ids": [team["emp1"]]}), "assign")
    my = _ok(team["samual"]("GET", "/locations/my"), "Samual's site")["location"]
    assert my and my["id"] == loc["id"]
    _ok(team["vicki_admin"]("PATCH", f"/locations/{loc['id']}", {"radius_m": 300}), "edit")
    loc = next(x for x in _ok(d("GET", "/locations"), "re-read")["locations"] if x["id"] == loc["id"])
    assert int(loc["radius_m"]) == 300
    _ok(d("DELETE", f"/locations/{loc['id']}"), "delete")


# ── HF-11 directory ──────────────────────────────────────────────────────────
def test_HF_11_directory(team):
    v = team["vicki_admin"]
    _ok(v("POST", "/directory", {"name": f"ZTEST Contact {RUN}", "role": "ZTEST", "email": "ztest@example.com",
                                 "ext": "101"}), "add")
    c = next(x for x in _ok(team["samual"]("GET", "/directory"), "Samual sees")["contacts"]
             if RUN in (x.get("name") or ""))
    _ok(v("PATCH", f"/directory/{c['id']}", {"ext": "202"}), "edit")
    c = next(x for x in _ok(team["david"]("GET", "/directory"), "re-read")["contacts"] if x["id"] == c["id"])
    assert c["ext"] == "202"
    _ok(v("DELETE", f"/directory/{c['id']}"), "delete")


# ── HF-12 attendance ─────────────────────────────────────────────────────────
def test_HF_12_attendance(team):
    d = team["david"]
    _ok(d("POST", "/attendance", {"employee_id": team["emp1"], "date": D(-1), "status": "late",
                                  "note": f"ZTEST {RUN}"}), "record")
    rec = next(x for x in _ok(d("GET", f"/attendance?period=all&employee_id={team['emp1']}"), "list")["records"]
               if RUN in (x.get("note") or "") and x.get("date") == D(-1) and x.get("status") == "late")
    assert (rec["employee_id"], rec["date"], rec["status"]) == (team["emp1"], D(-1), "late")
    _ok(team["vicki_admin"]("PATCH", f"/attendance/{rec['id']}", {"status": "excused"}), "edit")
    rec = next(x for x in _ok(d("GET", f"/attendance?period=all&employee_id={team['emp1']}"), "re-read")["records"] if x["id"] == rec["id"])
    assert rec["status"] == "excused"
    _ok(d("DELETE", f"/attendance/{rec['id']}"), "delete")
    s = team["samual"]
    _ok(s("POST", "/consent/location", {"signature_name": f"ZTEST HF1 {RUN}"}), "location consent")
    assert _ok(s("GET", "/consent/location/status"), "consent status")["signed"] is True
    _ok(s("POST", "/attendance/self-report", {"status": "absent", "note": f"ZTEST self {RUN}",
                                               "lat": 29.03, "lng": -80.93}), "self-report")
    assert any(RUN in (x.get("note") or "") and x["employee_id"] == team["emp1"]
               for x in _ok(d("GET", f"/attendance?period=all&employee_id={team['emp1']}"), "HR sees")["records"])


# ── HF-13 documents ──────────────────────────────────────────────────────────
def test_HF_13_documents(team):
    o, pdf = team["o"], b"%PDF-1.4\nZTEST " + RUN.encode() + b"\n%%EOF\n"
    bnd = "----ZTEST" + RUN
    parts = []
    for k, v in (("employee_id", team["emp1"]), ("name", f"ZTEST Doc {RUN}"), ("category", "general"),
                 ("expiration_date", D(400))):
        parts.append(f'--{bnd}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{bnd}\r\nContent-Disposition: form-data; name="file"; filename="ztest.pdf"\r\n'
                 f'Content-Type: application/pdf\r\n\r\n'.encode() + pdf + f"\r\n--{bnd}--\r\n".encode())
    import urllib.request
    from api import USER_AGENT
    st, _, b = team["hr"]["admin_login"](team["hr"]["owner"])
    tok = _json(b)["access_token"]
    req = urllib.request.Request(o + "/hr-api/documents/upload", data=b"".join(parts), method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={bnd}",
                                          "Authorization": f"Bearer {tok}", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as r:
        assert r.status in (200, 201)
    docs = _ok(team["david"]("GET", f"/documents?employee_id={team['emp1']}"), "list")["documents"]
    doc = next(x for x in docs if x.get("name") == f"ZTEST Doc {RUN}")
    assert doc["expiration_date"] == D(400)
    req = urllib.request.Request(o + f"/hr-api/documents/{doc['id']}/download",
                                 headers={"Authorization": f"Bearer {tok}", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as r:
        got = r.read()
    if got[:1] == b"{":                                   # JSON {filename, data(base64)}
        got = base64.b64decode(_json(got.decode()).get("data_b64", ""))
    assert got == pdf, "the downloaded file differs from what was uploaded"
    _ok(team["david"]("DELETE", f"/documents/{doc['id']}"), "delete")


# ── HF-14 portal profile ─────────────────────────────────────────────────────
def test_HF_14_portal_profile(team):
    s = team["samual"]
    r = _ok(s("PATCH", "/portal/me", {"nickname": f"ZT{RUN}", "phone": "555-0142",
                                       "emergency_contact": {"name": "ZTEST Contact", "phone": "555-0143"},
                                       "account_last4": "000012345678", "pay_rate": 999, "title": "CEO"}), "edit")
    assert set(r["changed"]) == {"nickname", "phone", "emergency_contact", "account_last4"}
    e = _ok(team["david"]("GET", f"/employees/{team['emp1']}"), "HR reads")
    e = e.get("employee", e)
    assert (e["nickname"], e["phone"], e["account_last4"]) == (f"ZT{RUN}", "555-0142", "5678")
    assert float(e["pay_rate"]) == 21.5 and e["title"] != "CEO", "an employee changed their own pay/title"
    me = _ok(s("GET", "/portal/me"), "me")
    assert "pin_hash" not in json.dumps(me)


# ── HF-15 recruiting (round trip; the real data is restored) ─────────────────
def test_HF_15_recruiting(team):
    d = team["david"]
    before = _ok(d("GET", "/recruiting"), "read")
    rec = before.get("recruiting") or {}
    ver = before.get("version") or before.get("recruiting_version")
    pos = {"id": f"ZTEST-{RUN}", "title": f"ZTEST Position {RUN}", "status": "open"}
    new = {**rec, "positions": list(rec.get("positions") or []) + [pos]}
    _ok(d("POST", "/recruiting", {**new, "version": ver}), "save with a ZTEST position")
    after = _ok(team["vicki_admin"]("GET", "/recruiting"), "Vicki reads")
    assert any(p.get("id") == pos["id"] for p in (after.get("recruiting") or {}).get("positions", []))
    restore = {**(after.get("recruiting") or {})}
    restore["positions"] = [p for p in restore.get("positions", []) if p.get("id") != pos["id"]]
    _ok(d("POST", "/recruiting", {**restore, "version": after.get("version") or after.get("recruiting_version")}),
        "restore")
    final = (_ok(d("GET", "/recruiting"), "final").get("recruiting") or {}).get("positions", [])
    assert final == list(rec.get("positions") or []), "recruiting data was not restored exactly"


# ── HF-16 incidents ──────────────────────────────────────────────────────────
def test_HF_16_incidents(team):
    st, _, _ = _http("POST", team["o"] + "/hr-api/incidents", {"summary": "ZTEST anon"})
    assert st == 401, f"signed-out incident report accepted (HTTP {st})"
    _ok(team["samual"]("POST", "/incidents", {"summary": f"ZTEST incident {RUN}", "employee_id": team["emp2"]}),
        "file")
    inc = next(x for x in _ok(team["david"]("GET", "/incidents"), "HR list")["incidents"]
               if RUN in (x.get("summary") or ""))
    assert inc["employee_id"] == team["emp1"], "the report was filed under someone else"


# ── HF-17 role isolation ─────────────────────────────────────────────────────
def test_HF_17_employees_only_see_their_own(team):
    s = team["samual"]
    assert s("GET", f"/employees/{team['emp2']}")[0] in (403, 404), "Samual read Vicki's employee record"
    assert s("GET", "/employees")[0] == 403, "Samual listed all employees"
    assert s("GET", "/pto")[0] == 403, "Samual opened the HR time-off queue"
    assert s("GET", "/incidents")[0] == 403
    assert s("GET", "/timeclock/entries")[0] == 403
    assert not any(t["employee_id"] != team["emp1"] for t in _ok(s("GET", "/tasks"), "tasks")["tasks"])
    pend = _ok(team["vicki"]("POST", "/pto/request", {"type": "Vacation", "start_date": D(40),
                                                       "end_date": D(40), "notes": f"ZTEST {RUN}"}), "Vicki asks")
    pid = (pend.get("request") or pend).get("id")
    assert s("POST", f"/pto/{pid}/approve", {})[0] == 403, "an employee approved time off"


# ── HF-18 termination in HR Admin (R-091) ────────────────────────────────────
def test_HF_18_termination_ends_portal_access_and_starts_offboarding(team):
    """R-091 (fixed 2026-10-12). Last day already passed -> Terminated at once."""
    d = team["david"]
    sess_before = team["vicki"].session
    # exactly what HR Admin's Terminations screen sends (hr_admin/index.html)
    r = _ok(d("PATCH", f"/employees/{team['emp2']}", {"status": "terminated", "termination_type": "voluntary",
                                                      "end_date": D(-1), "termination_notes": "ZTEST"}),
            "terminate")
    assert r.get("offboarding_tasks_created", 0) >= 5, r
    e = _ok(d("GET", f"/employees/{team['emp2']}"), "re-read")
    assert (e.get("employee", e))["status"] == "Terminated"
    tasks = _ok(d("GET", f"/tasks?employee_id={team['emp2']}"), "tasks")["tasks"]
    assert any((t.get("template_id") or "").startswith("TMPL-TERM") for t in tasks)
    st, _, _ = _http("GET", team["o"] + f"/hr-api/employees/{team['emp2']}",
                     headers={"X-Employee-Session": sess_before})
    assert st in (401, 403), f"the terminated employee's open portal session still works (HTTP {st})"
    hr = team["hr"]
    st, _, _ = _http("POST", team["o"] + "/hr-api/auth/aiprowler", {"name": hr["manager"].name,
                                                                      "token": hr["manager"].token})
    assert st != 200, "the terminated employee can still sign in to the HR Portal"


# ── HF-19 every screen opens (browser, human mode) ───────────────────────────
ADMIN_TABS = ("employees", "onboarding", "tasks", "timeoff", "attendance", "clocklog", "schedule",
              "messages", "incidents", "documents", "training", "locations", "recruiting", "performance",
              "benefits", "payroll", "compliance", "reports", "offboarding", "terminations", "settings")
PORTAL_PAGES = ("welcome", "feed", "tasks", "pto", "timeclock", "schedule", "calendar", "companycalendar",
                "messages", "docs", "trainings", "directory", "payroll", "pay", "deposits", "details",
                "emergency", "about", "handbook", "help", "news", "portfolio", "my-team",
                "incident-reports", "writeup")


def _js_errors(pg):
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)[:200]))
    return errs


def test_HF_19_every_screen_opens(team, page_for):
    hr = team["hr"]
    admin = page_for()
    a_errs = _js_errors(admin)
    _admin_sign_in(admin, team["o"], hr["owner"])
    expect(admin.locator("#auth-screen")).to_be_hidden(timeout=30_000)
    admin.evaluate("() => { const w = document.getElementById('setup-wizard'); "
                   "if (w) { w.classList.add('hidden'); w.style.display = 'none'; } }")
    bad = []
    for tab in ADMIN_TABS:
        admin.evaluate(f"() => navTo('{tab}')")
        admin.wait_for_timeout(600)
        shown = admin.evaluate(f"""() => {{ const p = document.getElementById('tab-{tab}');
            return !!p && getComputedStyle(p).display !== 'none' && state.currentTab === '{tab}'; }}""")
        if not shown:
            bad.append(f"HR Admin '{tab}' did not open")
    admin.evaluate("() => navTo('employees')")
    admin.wait_for_function("() => Array.isArray(state.employees) && "
                            "state.employees.some(e => String(e.first_name||'').startsWith('ZTEST HF1'))",
                            timeout=15_000)

    portal = page_for()
    p_errs = _js_errors(portal)
    _portal_sign_in(portal, team["o"], hr["crew"])
    expect(portal.locator("#login-screen")).to_be_hidden(timeout=30_000)
    for page in PORTAL_PAGES:
        ok = portal.evaluate(f"""() => {{
            const el = document.getElementById('page-{page}'); if (!el) return 'missing';
            if (typeof showPage === 'function') showPage('{page}');
            else if (typeof goTo === 'function') goTo('{page}');
            return 'ok'; }}""")
        portal.wait_for_timeout(400)
        if ok != "ok":
            bad.append(f"HR Portal page '{page}' {ok}")
    assert not bad, "\n".join(bad)
    assert not a_errs, "HR Admin script errors:\n" + "\n".join(a_errs[:10])
    assert not p_errs, "HR Portal script errors:\n" + "\n".join(p_errs[:10])
