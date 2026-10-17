"""
Every AI-Prowler server user is an employee -- except contractors HR marks
"not an employee" (David, 2026-10-16).

  * HR Admin's employee list creates / links a record for every ACTIVE user in
    the server's Admin tab: name, email, cell phone; no onboarding tasks
  * an existing record with the same name is linked, never duplicated; a name
    matching two records is reported, never guessed
  * "Not an employee": record leaves HR (folder set aside), the login keeps
    working, sync never re-adds them, the HR Portal says it's for employees;
    deleting a server user's record does the same; "Make an employee" reverses it
  * a rename in the Admin tab (login id follows the name) re-links by email and
    never turns a contractor back into an employee
  * the list is its own company file: survives reloads and re-running setup
  * HR Admin page: all 50 states + DC; the new screens are present

pytest tmp_path, ZTEST names, users.json faked in memory -- never real HR data,
never the real users.json, never config.json.

Run: run_tests.bat tests\\mcp_tests\\test_hr_server_users_employees.py -v
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

USERS = {
    "tok-a": {"name": "ZTEST Alpha", "email": "alpha+hrtest@example.com", "cell_phone": "5550000001",
              "role": "staff", "status": "active"},
    "tok-b": {"name": "ZTEST Bravo", "email": "bravo+hrtest@example.com", "cell_phone": "5550000002",
              "role": "manager", "status": "active"},
    "tok-c": {"name": "ZTEST Contractor", "email": "contractor+hrtest@example.com", "cell_phone": "",
              "role": "field crew", "status": "active"},
    "tok-x": {"name": "ZTEST Gone", "email": "gone+hrtest@example.com", "status": "inactive"},
}


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    live = tmp_path / "hr"
    live.mkdir()
    monkeypatch.setattr(m, "_HR_DB_PATH", str(live / "hr_db.json"))
    users = {"users": json.loads(json.dumps(USERS))}
    monkeypatch.setattr(m, "_load_users", lambda: users)
    m._hr_save_db({"config": {"company_name": "ZTEST Co", "setup_complete": True},
                   "employees": [
                       # already in HR with the same name, not linked yet
                       {"id": "EMP-00001", "first_name": "ZTEST", "last_name": "Bravo", "status": "Active",
                        "title": "Lead"}],
                   "tasks": [], "documents": [], "audit_log": []})
    m.ztest_users = users
    m.ztest_live = live
    return m


def call(ap, method, path, body=None, role="admin"):
    auth = {"role": "admin", "user_id": "ztest-admin"} if role == "admin" else \
           ({"role": "employee", "employee_id": "EMP-00001"} if role == "employee" else {"role": None})
    st, _ct, b = ap._hr_api_route(method, path, {}, body or {}, auth)
    return st, json.loads(b)


def emps(ap):
    return {e.get("aiprowler_user_id"): e for e in ap._hr_load_db()["employees"]}


def test_every_active_server_user_becomes_an_employee(ap):
    st, j = call(ap, "GET", "/employees")
    assert st == 200
    by = emps(ap)
    assert set(by) == {"ztest-alpha", "ztest-bravo", "ztest-contractor"}      # inactive user skipped
    a = by["ztest-alpha"]
    assert (a["first_name"], a["last_name"], a["status"]) == ("ZTEST", "Alpha", "Active")
    assert a["personal_email"] == "alpha+hrtest@example.com" and a["phone"] == "5550000001"
    assert a["address"] == "" and a["created_by"] == "server_user_sync"
    assert not ap._hr_load_db()["tasks"]                                       # no onboarding tasks
    # the existing record was linked, not duplicated, and kept its details
    assert by["ztest-bravo"]["id"] == "EMP-00001" and by["ztest-bravo"]["title"] == "Lead"
    assert len(ap._hr_load_db()["employees"]) == 3
    assert sorted(j["server_user_sync"]["linked"]) == ["EMP-00001"]
    assert len(j["server_user_sync"]["created"]) == 2
    # second load changes nothing
    st, j2 = call(ap, "GET", "/employees")
    assert j2["server_user_sync"] == {"created": [], "linked": [], "needs_link": []}
    assert len(ap._hr_load_db()["employees"]) == 3
    # no token ever leaves the server
    assert "tok-" not in json.dumps(j) and "tok-" not in json.dumps(ap._hr_load_db())


def test_duplicate_names_are_reported_not_guessed(ap):
    db = ap._hr_load_db()
    db["employees"].append({"id": "EMP-00002", "first_name": "ZTEST", "last_name": "Alpha", "status": "Active"})
    db["employees"].append({"id": "EMP-00003", "first_name": "ZTEST", "last_name": "Alpha", "status": "Active"})
    ap._hr_save_db(db)
    st, j = call(ap, "GET", "/employees")
    assert j["server_user_sync"]["needs_link"] == ["ZTEST Alpha"]
    assert "ztest-alpha" not in emps(ap)
    assert len([e for e in ap._hr_load_db()["employees"] if e["last_name"] == "Alpha"]) == 2


def test_not_an_employee_removes_record_and_sync_skips_them(ap):
    call(ap, "GET", "/employees")
    c = emps(ap)["ztest-contractor"]
    st, j = call(ap, "POST", f"/employees/{c['id']}/not-employee")
    assert st == 200 and j["user_id"] == "ztest-contractor"
    assert "ztest-contractor" not in emps(ap)
    # folder set aside, not erased
    deleted = [p for p in ap.ztest_live.rglob("*") if p.is_dir() and "Contractor" in p.name]
    assert deleted and all("_deleted" in str(p) or "deleted" in str(p).lower() for p in deleted)
    # never re-added
    for _ in range(2):
        call(ap, "GET", "/employees")
    assert "ztest-contractor" not in emps(ap)
    st, j = call(ap, "GET", "/non-employees")
    assert [(u["user_id"], u["name"], u["still_server_user"]) for u in j["users"]] == \
           [("ztest-contractor", "ZTEST Contractor", True)]
    assert ap._hr_load_db()["non_employee_users"][0]["email"] == "contractor+hrtest@example.com"
    # Portal sign-in path refuses without creating a record
    db = ap._hr_load_db()
    assert ap._hr_is_non_employee(db, "ztest-contractor")
    emp, changed = ap._hr_portal_employee_for_user({"id": "ztest-contractor", "name": "ZTEST Contractor"}, db)
    assert emp is None and changed is False
    # a record with no server login can't be marked (use Delete)
    db = ap._hr_load_db()
    db["employees"].append({"id": "EMP-00009", "first_name": "ZTEST", "last_name": "Paper", "status": "Active"})
    ap._hr_save_db(db)
    st, j = call(ap, "POST", "/employees/EMP-00009/not-employee")
    assert st == 400 and j["error"] == "no_server_login"


def test_make_an_employee_again(ap):
    call(ap, "GET", "/employees")
    c = emps(ap)["ztest-contractor"]
    call(ap, "POST", f"/employees/{c['id']}/not-employee")
    st, j = call(ap, "POST", "/non-employees/ztest-contractor/restore")
    assert st == 200 and j["employee_id"]
    assert emps(ap)["ztest-contractor"]["id"] == j["employee_id"]
    assert call(ap, "GET", "/non-employees")[1]["users"] == []
    assert call(ap, "POST", "/non-employees/ztest-contractor/restore")[0] == 404


def test_deleting_a_server_users_record_marks_not_employee(ap):
    call(ap, "GET", "/employees")
    a = emps(ap)["ztest-alpha"]
    st, j = call(ap, "DELETE", f"/employees/{a['id']}")
    assert st == 200 and j["marked_not_employee"] is True
    call(ap, "GET", "/employees")
    assert "ztest-alpha" not in emps(ap)
    # deleting a record with no server login is a plain delete
    db = ap._hr_load_db()
    db["employees"].append({"id": "EMP-00009", "first_name": "ZTEST", "last_name": "Paper", "status": "Active"})
    ap._hr_save_db(db)
    st, j = call(ap, "DELETE", "/employees/EMP-00009")
    assert st == 200 and j["marked_not_employee"] is False


def test_rename_in_admin_tab_relinks_by_email(ap):
    call(ap, "GET", "/employees")
    a = emps(ap)["ztest-alpha"]
    ap.ztest_users["users"]["tok-a"]["name"] = "ZTEST Alphamarried"      # id becomes ztest-alphamarried
    st, j = call(ap, "GET", "/employees")
    by = emps(ap)
    assert "ztest-alpha" not in by and by["ztest-alphamarried"]["id"] == a["id"]
    assert j["server_user_sync"]["linked"] == [a["id"]] and not j["server_user_sync"]["created"]
    assert len(ap._hr_load_db()["employees"]) == 3


def test_renamed_contractor_stays_out(ap):
    call(ap, "GET", "/employees")
    call(ap, "POST", f"/employees/{emps(ap)['ztest-contractor']['id']}/not-employee")
    ap.ztest_users["users"]["tok-c"]["name"] = "ZTEST Contractorrenamed"
    call(ap, "GET", "/employees")
    assert not any("contractor" in (k or "") for k in emps(ap))


def test_list_survives_reload_and_setup_rerun(ap):
    call(ap, "GET", "/employees")
    call(ap, "POST", f"/employees/{emps(ap)['ztest-contractor']['id']}/not-employee")
    assert (ap.ztest_live / "company" / "non_employee_users.json").exists() or \
        any(p.name == "non_employee_users.json" for p in ap.ztest_live.rglob("*.json"))
    call(ap, "POST", "/setup/complete", {"company_name": "ZTEST Co", "work_states": ["FL", "GA"]})
    db = ap._hr_load_db()
    assert ap._hr_is_non_employee(db, "ztest-contractor")
    assert db["config"]["work_states"] == ["FL", "GA"]


@pytest.mark.parametrize("method,path", [
    ("GET", "/non-employees"), ("POST", "/non-employees/ztest-alpha/restore"),
    ("POST", "/employees/EMP-00001/not-employee")])
def test_routes_are_hr_admin_only(ap, method, path):
    assert call(ap, method, path, role="employee")[0] == 403
    assert call(ap, method, path, role=None)[0] in (401, 403)      # not signed in


def test_personal_mode_has_no_server_users(ap, monkeypatch):
    monkeypatch.setattr(ap, "_load_users", lambda: None)
    st, j = call(ap, "GET", "/employees")
    assert st == 200 and len(ap._hr_load_db()["employees"]) == 1


def test_hiring_someone_already_in_the_admin_tab_onboards_them(ap):
    # 2026-10-17: the owner added the new hire in the Admin tab first -> sync made
    # a bare placeholder; HR's + New Employee must turn it into a real hire.
    call(ap, "GET", "/employees")
    ph = emps(ap)["ztest-alpha"]
    st, j = call(ap, "POST", "/employees", {
        "personal": {"first_name": "ZTEST", "last_name": "Alpha", "personal_email": ""},
        "employment": {"title": "Tech", "start_date": "2030-01-07", "work_state": "FL"},
        "compensation": {"pay_type": "hourly", "pay_rate": 20}})
    assert st in (200, 201), j
    db = ap._hr_load_db()
    alphas = [e for e in db["employees"] if e["last_name"] == "Alpha"]
    assert len(alphas) == 1, alphas                                   # no duplicate
    new = alphas[0]
    assert new["aiprowler_user_id"] == "ztest-alpha"                   # login link kept
    assert new["personal_email"] == "alpha+hrtest@example.com"         # email carried over
    assert new["start_date"] == "2030-01-07" and new["title"] == "Tech"
    assert any(t["employee_id"] == new["id"] for t in db["tasks"])      # onboarding tasks generated
    assert any(a.get("action") == "placeholder_became_hire" and a.get("replaced_id") == ph["id"]
               for a in db["audit_log"])
    # a later sync doesn't make another one
    call(ap, "GET", "/employees")
    assert len([e for e in ap._hr_load_db()["employees"] if e["last_name"] == "Alpha"]) == 1


def test_a_record_with_real_hr_data_still_blocks_a_duplicate_hire(ap):
    call(ap, "GET", "/employees")
    db = ap._hr_load_db()
    b = next(e for e in db["employees"] if e.get("aiprowler_user_id") == "ztest-bravo")
    db["tasks"].append({"id": "TASK-99999", "employee_id": b["id"], "name": "ZTEST task", "status": "Not Started"})
    ap._hr_save_db(db)
    st, j = call(ap, "POST", "/employees", {"personal": {"first_name": "ZTEST", "last_name": "Bravo"},
                                            "employment": {"start_date": "2030-01-07", "work_state": "FL"},
                                            "compensation": {}})
    assert st == 409 and j["error"] == "name_exists"


def test_portal_sign_in_refuses_not_an_employee():
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index('"error": "not_an_employee"')
    block = src[i - 1500:i]
    assert "_hr_is_non_employee(_hrl_db" in block and "_hr_portal_employee_for_user(_hrl_user" in block


# ── HR Admin page ───────────────────────────────────────────────────────────
ADMIN = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")


def test_admin_lists_all_states_and_dc():
    m = re.search(r"const US_STATES = (\[.*?\]);", ADMIN)
    codes = re.findall(r"\['([A-Z]{2})',", m.group(1))
    assert len(codes) == 51 and len(set(codes)) == 51 and "DC" in codes and "FL" in codes and "WY" in codes
    wiz = re.search(r"options:\[([^\]]*)\], key:'work_states'", ADMIN).group(1)
    assert re.findall(r"'([A-Z]{2})'", wiz) == codes          # wizard lists every state + DC
    sel = re.search(r'<select class="form-select" id="nef-work-state".*?</select>', ADMIN, re.S).group(0)
    assert len(re.findall(r'<option value="[A-Z]{2}">', sel)) == 51
    assert 'value="OTHER"' not in sel


def test_admin_has_not_an_employee_screens():
    for s in ("renderNonEmployeeSettings", "restoreNonEmployee", "confirmNotEmployee", "markNotEmployee",
              "/non-employees", "/not-employee", 'id="nonemp-body"', "server_user_sync",
              "_dj.marked_not_employee"):
        assert s in ADMIN, s
    assert "renderResourcesSettings(); renderNonEmployeeSettings(); }" in ADMIN
