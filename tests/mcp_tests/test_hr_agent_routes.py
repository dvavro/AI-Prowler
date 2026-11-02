"""
The HR agent's routes in HR Admin (/hr-api/agent…, hr-agent-spec.md H3) and its wiring into the
real HR data (2026-10-31): HR Admin only; approving a suggestion goes through HR's own routes;
the HR agent's database sits in the HR data folder and is part of the HR backup.

Run: run_tests.bat tests\\mcp_tests\\test_hr_agent_routes.py -v
"""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    import desk_agent_hr_store as store
    import desk_hr_agent as ha
    monkeypatch.setattr(m, "_HR_DB_PATH", str(tmp_path / "hr" / "hr_db.json"))
    (tmp_path / "hr").mkdir()
    start = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    m._hr_save_db({
        "config": {"company_name": "ZTEST Co", "setup_complete": True, "doc_root": str(tmp_path / "hr" / "docs")},
        "employees": [{"id": "EMP-00001", "first_name": "ZTEST", "last_name": "Person", "status": "Active",
                       "work_email": "ztest@example.com", "ssn": "123-45-6789", "department": "Field"}],
        "pto_requests": [{"id": "PTOREQ-0001", "employee_id": "EMP-00001", "type": "PTO", "start_date": start,
                          "end_date": start, "status": "pending",
                          "created_at": dt.datetime.now().isoformat(timespec="seconds")}],
        "tasks": [], "documents": [], "messages": [], "audit_log": [], "attendance": []})
    monkeypatch.setattr(store, "PATH_OVERRIDE", None)
    m._JOBS_AGENT_WIRED.pop("hr", None)
    m._hr_agent_wire()
    yield m
    ha.hr.clear()
    m._JOBS_AGENT_WIRED.pop("hr", None)


def call(m, method, path, body=None, role="admin"):
    st, _ct, b = m._hr_api_route(method, path, {}, body or {}, {"role": role})
    return st, json.loads(b or b"{}")


def test_the_agent_database_lives_in_the_hr_data_folder(ap):
    import desk_agent_hr_store as store
    assert Path(store.path()) == Path(ap._hr_data_root()) / "agent" / "hr_agent.db"


def test_only_hr_admin(ap):
    for role in (None, "employee"):
        for me, path in (("GET", "/agent/status"), ("GET", "/agent/pending"), ("POST", "/agent/run-now"),
                         ("GET", "/agent/recommendations"),
                         ("POST", "/agent/settings"), ("POST", "/agent/proposals/H1/approve")):
            assert call(ap, me, path, role=role)[0] == 403, (role, me, path)


def test_status_settings_and_diagram(ap):
    st, out = call(ap, "GET", "/agent/status")
    assert st == 200 and out["enabled"] is False and "pending" in out
    st, out = call(ap, "GET", "/agent/settings")
    assert st == 200 and out["flow"]["states"] and len(out["options"]["stages"]) == 9
    if out["can_change_settings"]:
        st, out = call(ap, "POST", "/agent/settings", {"settings": {"agent_hr_enabled": True}})
        assert st == 200 and out["settings"]["agent_hr_enabled"] is True
        st, out = call(ap, "POST", "/agent/settings", {"settings": {"agent_hr_bogus": 1}})
        assert st == 400


def test_run_now_refuses_a_chat_runner(ap):
    import desk_agent_hr_store as store
    store.set_setting("agent_hr_enabled", True, actor={"id": "o", "role": "owner"}, edition="solo")
    st, out = call(ap, "POST", "/agent/run-now")
    assert st == 200 and out["started"] is False and out["why"]


def test_approving_a_suggestion_goes_through_hr(ap):
    import desk_agent as ag
    import desk_agent_hr_store as store
    import desk_hr_agent as ha
    owner = {"id": "o", "role": "owner"}
    for k, v in (("agent_hr_enabled", True), ("agent_hr_shadow", False)):
        store.set_setting(k, v, actor=owner, edition="solo")
    adb = store.init()
    ha.scan(adb, settings=ag.desk_db.get_settings(adb))
    got = [i for i in ag.next_items(adb, edition="solo", limit=10)["items"] if i["ref"] == "pto:PTOREQ-0001"]
    assert got and "123-45-6789" not in json.dumps(got)                          # the AI never sees the SSN
    res = ag.submit(adb, got[0]["item_id"], [{"action": "hr_approve_timeoff", "why": "t", "confidence": 0.97}],
                    edition="solo")["results"]
    assert res[0]["status"] == "pending"                                          # off by default: a person decides
    st, out = call(ap, "GET", "/agent/pending")
    pid = next(x["proposal_id"] for x in out["items"] if x["ref"] == "pto:PTOREQ-0001")
    assert pid.startswith("H")
    st, out = call(ap, "POST", f"/agent/proposals/{pid}/approve")
    assert st == 200 and out["status"] == "applied", out
    db = ap._hr_load_db()
    assert db["pto_requests"][0]["status"] == "approved"


def test_time_off_sees_the_persons_booked_jobs(ap, tmp_path, monkeypatch):
    import desk_hr_agent as ha
    from db_access import get_connection, init_db
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    monkeypatch.setattr(ap, "_resolve_job_db_path", lambda *_a, **_k: jobs)
    db = ap._hr_load_db()
    emp, req = db["employees"][0], db["pto_requests"][0]
    assert ha.hr["booked_jobs"](emp, [req["start_date"]]) == 0
    conn = get_connection(jobs)
    conn.execute("INSERT INTO jobs (job_id, customer_name, service_date, job_status, crew) VALUES "
                 "('JOB-0001', 'Ann', ?, 'Scheduled', 'ZTEST Person')", (req["start_date"],))
    conn.close()
    assert ha.hr["booked_jobs"](emp, [req["start_date"]]) == 1
    c = ha.timeoff_checks(db, req, emp, {"agent_hr_timeoff_max_days": 2})
    assert c["booked_jobs"] == 1 and c["no_booked_jobs"] is False


EMP = {"role": "employee", "employee_id": "EMP-00001"}


def emp_call(m, method, path, body=None, auth=EMP):
    st, _ct, b = m._hr_api_route(method, path, {}, body or {}, auth)
    return st, json.loads(b or b"{}")


def answers_on(stage="suggest"):
    import desk_agent_hr_store as store
    import desk_db
    owner = {"id": "o", "role": "owner"}
    adb = store.init()
    for k, v in (("agent_hr_enabled", True), ("agent_hr_shadow", False), ("agent_hr_stage_answer", stage)):
        store.set_setting(k, v, actor=owner, edition="solo")
    desk_db.set_setting(adb, "agent_provider", "claude_api", actor=owner, edition="solo")
    return adb


def test_the_portal_asks_the_assistant_only_when_it_answers(ap, monkeypatch):
    import desk_agent as ag
    started = []
    monkeypatch.setattr(ag, "run_in_background", lambda *a, **k: started.append(a) or True)   # no real AI here
    monkeypatch.setattr(ap, "_desk_app_turned_off", lambda: True)
    st, out = emp_call(ap, "GET", "/assistant")
    assert st == 200 and out["answers_on"] is False                                 # agent off
    st, out = emp_call(ap, "POST", "/ai-chat", {"message": "How many PTO days do I get?", "ask_assistant": True})
    assert st == 200 and out["queued"] is False and "Messages" in out["reply"]
    assert not [m for m in ap._hr_load_db()["messages"] if m.get("message_type") == "help_question"]
    adb = answers_on()
    st, out = emp_call(ap, "GET", "/assistant")
    assert out["answers_on"] is True and out["checked_first"] is True
    assert emp_call(ap, "GET", "/assistant", auth={"role": None})[0] == 401
    st, out = emp_call(ap, "POST", "/ai-chat", {"message": "How many PTO days do I get?", "ask_assistant": True})
    assert out["queued"] is True and out["sensitive"] is False and "once HR has checked it" in out["reply"]
    msg = next(m for m in ap._hr_load_db()["messages"] if m["id"] == out["message_id"])
    assert msg["message_type"] == "help_question" and msg["employee_id"] == "EMP-00001" and not msg.get("needs_person")
    conn = ag._conn(adb)
    try:
        assert conn.execute("SELECT stage FROM agent_queue WHERE ref = ?", (f"msg:{msg['id']}",)).fetchone()[0] == "answer"
    finally:
        conn.close()
    # a sensitive question goes straight to a person, never to the AI
    st, out = emp_call(ap, "POST", "/ai-chat", {"message": "My supervisor harassed me", "ask_assistant": True})
    assert out["sensitive"] is True and "person at HR" in out["reply"]
    msg = next(m for m in ap._hr_load_db()["messages"] if m["id"] == out["message_id"])
    assert msg["needs_person"] is True
    conn = ag._conn(adb)
    try:
        assert not conn.execute("SELECT 1 FROM agent_queue WHERE ref = ?", (f"msg:{msg['id']}",)).fetchone()
    finally:
        conn.close()
    # practice mode: the assistant isn't answering anyone
    import desk_agent_hr_store as store
    store.set_setting("agent_hr_shadow", True, actor={"id": "o", "role": "owner"}, edition="solo")
    assert emp_call(ap, "GET", "/assistant")[1]["answers_on"] is False


def test_talk_to_a_person(ap):
    db = ap._hr_load_db()
    db["employees"].append({"id": "EMP-00002", "first_name": "Other", "last_name": "Person", "status": "Active"})
    db["messages"] += [{"id": "MSG-A", "employee_id": "EMP-00001", "subject": "PTO", "body": "how many?"},
                       {"id": "MSG-B", "employee_id": "EMP-00002", "subject": "x", "body": "y"}]
    ap._hr_save_db(db)
    assert call(ap, "POST", "/messages/reply", {"id": "MSG-A", "reply": "10 days. — Sam", "by": "assistant"})[0] == 200
    mine = {m["id"]: m for m in emp_call(ap, "GET", "/messages/mine")[1]["messages"]}
    assert mine["MSG-A"]["reply_by"] == "assistant"
    assert emp_call(ap, "POST", "/messages/talk-to-person", {"id": "MSG-B"})[0] == 404     # not theirs
    assert call(ap, "POST", "/messages/talk-to-person", {"id": "MSG-A"})[0] == 403        # employees only
    assert emp_call(ap, "POST", "/messages/talk-to-person", {"id": "MSG-A"})[1]["ok"] is True
    m = next(x for x in ap._hr_load_db()["messages"] if x["id"] == "MSG-A")
    assert m["needs_person"] is True and m["read"] is False
    st, out = call(ap, "POST", "/messages/reply", {"id": "MSG-A", "reply": "again", "by": "assistant"})
    assert st == 409                                                                     # the assistant stays out
    assert call(ap, "POST", "/messages/reply", {"id": "MSG-A", "reply": "Hi, it's Dana from HR."})[0] == 200
    m = next(x for x in ap._hr_load_db()["messages"] if x["id"] == "MSG-A")
    assert m["reply_by"] == "hr" and m["needs_person"] is False and m["assistant_reply"].startswith("10 days")


def test_the_hr_backup_includes_the_agent_database(ap, tmp_path):
    import desk_agent_hr_store as store
    store.init()
    db = ap._hr_load_db()
    db["config"]["employee_backup"] = {"backup_dir": str(tmp_path / "bk"), "retention_count": 2}
    ap._hr_save_db(db)
    out = ap._hr_run_employee_backup()
    assert out["snapshot"], out
    assert (tmp_path / "bk" / out["snapshot"] / "agent" / "hr_agent.db").is_file()
