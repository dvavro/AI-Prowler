"""
HR sign-in + duplicate-email fixes (David, 2026-10-15).

  1. HR Portal / HR Admin sign in with the AI-Prowler name + bearer token from
     the server's Admin tab (users.json) — new employees are auto-linked to the
     AI-Prowler user with the same name; HR Admin no longer hands out a
     separate HR token / PIN.
  2. Onboarding emails arrived 3x — every server-mode process ran its own
     hr_scheduler. A cross-process runner lock now lets only one of them run.
  3. "missing bearer token" when opening the installed HR Portal — its
     manifest started at /employee/, which the server didn't serve. Manifest
     now starts at /hr_portal/ (the temporary /employee* redirect was
     removed 2026-10-16).

Run: run_tests.bat tests\\mcp_tests\\test_hr_signin_and_scheduler_fixes.py -v
"""
import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ── 3. HR Portal start URL ───────────────────────────────────────────────────
def test_employee_manifest_starts_at_hr_portal():
    m = json.loads((ROOT / "hr_portal" / "employee_manifest.json").read_text(encoding="utf-8"))
    assert m["start_url"] == "/hr_portal/"
    assert m["scope"] == "/hr_portal/"


def test_router_has_no_legacy_redirects():
    # 2026-10-16 (David): the /employee/ (and /hr/) redirects are gone — the
    # apps live only at /hr_admin/ and /hr_portal/.
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert 'path == "/employee"' not in src and '"/employee/"' not in src
    assert 'b"location", b"/hr_portal/"' not in src and 'b"location", b"/hr_admin/"' not in src


# ── 1. auto-link to the AI-Prowler Admin-tab user ────────────────────────────
@pytest.fixture()
def ap(monkeypatch):
    import ai_prowler_mcp as ap
    users = {"users": {
        "ztest-tok-A": {"name": "ZTEST Person", "role": "user", "status": "active"},
        "ztest-tok-B": {"name": "ZTEST Other", "role": "user", "status": "active"},
    }}
    monkeypatch.setattr(ap, "_load_users", lambda *a, **k: users)
    ap._ztest_users = users
    return ap


def _db(*emps):
    return {"employees": list(emps), "audit_log": []}


def test_autolink_links_unique_name_match(ap):
    emp = {"id": "E1", "first_name": "ztest", "last_name": "  PERSON "}
    db = _db(emp)
    u = ap._hr_autolink_aiprowler_user(emp, db)
    assert u is not None
    assert emp["aiprowler_user_id"] == ap._make_user_id("ZTEST Person")
    assert emp["aiprowler_user_name"] == "ZTEST Person"
    assert db["audit_log"][-1]["action"] == "aiprowler_login_linked"


def test_autolink_no_match(ap):
    emp = {"id": "E1", "first_name": "ZTEST", "last_name": "Nobody"}
    assert ap._hr_autolink_aiprowler_user(emp, _db(emp)) is None
    assert "aiprowler_user_id" not in emp


def test_autolink_ambiguous_name_not_linked(ap):
    ap._ztest_users["users"]["ztest-tok-C"] = {"name": "ZTEST Person", "role": "user", "status": "active"}
    emp = {"id": "E1", "first_name": "ZTEST", "last_name": "Person"}
    # Two Admin-tab entries with this name -> don't guess; HR links it by hand.
    assert ap._hr_autolink_aiprowler_user(emp, _db(emp)) is None
    assert "aiprowler_user_id" not in emp


def test_autolink_skips_login_already_used_by_another_employee(ap):
    other = {"id": "E0", "first_name": "x", "last_name": "y",
             "aiprowler_user_id": ap._make_user_id("ZTEST Person")}
    emp = {"id": "E1", "first_name": "ZTEST", "last_name": "Person"}
    assert ap._hr_autolink_aiprowler_user(emp, _db(other, emp)) is None


def test_autolink_leaves_existing_link_alone(ap):
    emp = {"id": "E1", "first_name": "ZTEST", "last_name": "Person", "aiprowler_user_id": "someone-else"}
    assert ap._hr_autolink_aiprowler_user(emp, _db(emp)) is None
    assert emp["aiprowler_user_id"] == "someone-else"


def test_public_employee_strips_legacy_credentials():
    import ai_prowler_mcp as ap
    emp = {"id": "E1", "first_name": "ZTEST", "temp_pin": "1234", "portal_token": "t",
           "pin_hash": "h", "portal_token_hash": "h2"}
    out = ap._hr_public_employee(emp)
    assert out == {"id": "E1", "first_name": "ZTEST"}


def test_hr_admin_ui_uses_aiprowler_login_not_hr_token():
    html = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")
    assert 'id="dr-signin-box"' in html
    assert "editEmpAiProwlerLogin()" in html
    # The old HR-only token / PIN buttons are gone (helper functions may linger, unused).
    assert 'onclick="makeNewPortalToken' not in html
    assert 'onclick="setEmployeePortalPin' not in html
    assert "showPortalToken(emp.portal_token)" not in html
    assert "Email (used to sign in to the Portal)" not in html


# ── 1b. (2026-10-16) any active Admin-tab user can sign in to the HR Portal ──
@pytest.fixture()
def portal_db(tmp_path):
    return {"config": {"doc_root": str(tmp_path / "hr_documents")},
            "employees": [], "tasks": [], "audit_log": []}


def test_portal_signin_creates_employee_for_unlisted_user(portal_db):
    import ai_prowler_mcp as ap
    user = {"id": "ztest-person", "name": "ZTEST Person"}
    emp, changed = ap._hr_portal_employee_for_user(user, portal_db)
    assert changed and emp in portal_db["employees"]
    assert emp["aiprowler_user_id"] == "ztest-person"
    assert (emp["first_name"], emp["last_name"], emp["status"]) == ("ZTEST", "Person", "Active")
    assert portal_db["tasks"] == [], "no onboarding tasks / emails for an existing server user"
    assert emp["start_date"] == "", "no start date -> no welcome / benefits emails"
    # signing in again reuses the same record
    again, changed2 = ap._hr_portal_employee_for_user(user, portal_db)
    assert again is emp and not changed2 and len(portal_db["employees"]) == 1


def test_portal_signin_links_existing_same_name_employee(portal_db):
    import ai_prowler_mcp as ap
    existing = {"id": "EMP-0001", "first_name": "ztest", "last_name": "Person", "status": "Onboarding"}
    portal_db["employees"].append(existing)
    emp, changed = ap._hr_portal_employee_for_user({"id": "ztest-person", "name": "ZTEST Person"}, portal_db)
    assert emp is existing and changed
    assert existing["aiprowler_user_id"] == "ztest-person"
    assert len(portal_db["employees"]) == 1


def test_portal_signin_terminated_record_is_returned_not_replaced(portal_db):
    import ai_prowler_mcp as ap
    gone = {"id": "EMP-0001", "first_name": "ZTEST", "last_name": "Person",
            "status": "Terminated", "aiprowler_user_id": "ztest-person"}
    portal_db["employees"].append(gone)
    emp, changed = ap._hr_portal_employee_for_user({"id": "ztest-person", "name": "ZTEST Person"}, portal_db)
    assert emp is gone and not changed and ap._hr_is_terminated(emp)
    assert len(portal_db["employees"]) == 1


def test_portal_signin_never_makes_a_second_record_for_a_name(portal_db):
    import ai_prowler_mcp as ap
    # Same-name record that's Terminated and unlinked -> linked + returned (caller refuses it)
    gone = {"id": "EMP-0001", "first_name": "ZTEST", "last_name": "Person", "status": "Terminated"}
    portal_db["employees"].append(gone)
    emp, _ = ap._hr_portal_employee_for_user({"id": "ztest-person", "name": "ZTEST Person"}, portal_db)
    assert emp is gone and len(portal_db["employees"]) == 1
    # Older duplicate data (two unlinked same-name records) -> don't guess
    portal_db["employees"] = [{"id": "EMP-0001", "first_name": "ZTEST", "last_name": "Twin"},
                              {"id": "EMP-0002", "first_name": "ZTEST", "last_name": "Twin"}]
    emp, changed = ap._hr_portal_employee_for_user({"id": "ztest-twin", "name": "ZTEST Twin"}, portal_db)
    assert emp is None and not changed and len(portal_db["employees"]) == 2


# ── 1c. (2026-10-16) one employee record per name ───────────────────────────
@pytest.fixture()
def hrapi(tmp_path, monkeypatch):
    import ai_prowler_mcp as ap
    monkeypatch.setattr(ap, "_HR_DB_PATH", str(tmp_path / "hr_db.json"))
    monkeypatch.setattr(ap, "_load_users", lambda *a, **k: {"users": {}})
    ap._hr_save_db({       # 2026-10-16: seed through the real per-folder storage
        "config": {"company_name": "ZTEST Co", "setup_complete": True, "work_states": ["FL"],
                   "doc_root": str(tmp_path / "hr_documents")},
        "employees": [], "tasks": [], "documents": [], "audit_log": []})

    def call(method, path, body=None):
        st, _ct, b = ap._hr_api_route(method, path, {}, body or {}, {"role": "admin"})
        return st, json.loads(b)
    return ap, call


def _new(first, last):
    return {"personal": {"first_name": first, "last_name": last},
            "employment": {"start_date": "2099-01-01", "work_state": "FL"}, "compensation": {}}


def test_add_employee_rejects_existing_name(hrapi):
    ap, call = hrapi
    st, first = call("POST", "/employees", _new("ZTEST", "Dupe"))
    assert st == 200
    st, err = call("POST", "/employees", _new("  ztest ", "DUPE"))   # case / spaces don't matter
    assert st == 409 and err["error"] == "name_exists"
    assert "Name already exists" in err["message"] and first["id"] in err["message"]
    assert len(ap._hr_load_db()["employees"]) == 1
    # a different name is fine
    assert call("POST", "/employees", _new("ZTEST", "Other"))[0] == 200


def test_add_employee_rejects_name_of_terminated_record(hrapi):
    ap, call = hrapi
    st, emp = call("POST", "/employees", _new("ZTEST", "Former"))
    db = ap._hr_load_db()
    db["employees"][0]["status"] = "Terminated"
    ap._hr_save_db(db)
    st, err = call("POST", "/employees", _new("ZTEST", "Former"))
    assert st == 409 and "Terminated" in err["message"]


def test_rename_cannot_take_another_employees_name(hrapi):
    ap, call = hrapi
    a = call("POST", "/employees", _new("ZTEST", "Alpha"))[1]
    b = call("POST", "/employees", _new("ZTEST", "Bravo"))[1]
    st, err = call("PATCH", f"/employees/{b['id']}", {"last_name": "alpha"})
    assert st == 409 and err["error"] == "name_exists" and a["id"] in err["message"]
    # renaming to a fresh name, or saving your own name again, is fine
    assert call("PATCH", f"/employees/{b['id']}", {"last_name": "Charlie"})[0] == 200
    assert call("PATCH", f"/employees/{a['id']}", {"first_name": "ZTEST", "last_name": "Alpha"})[0] == 200


def test_mcp_tools_reject_duplicate_names(hrapi):
    ap, call = hrapi
    call("POST", "/employees", _new("ZTEST", "Tool"))
    out = ap.hr_create_employee({"first_name": "ZTEST", "last_name": "Tool"},
                                {"start_date": "2099-01-01", "work_state": "FL"}, {})
    assert out.startswith("❌") and "Name already exists" in out
    other = call("POST", "/employees", _new("ZTEST", "Tool2"))[1]
    out = ap.hr_update_employee(other["id"], {"last_name": "Tool"})
    assert out.startswith("❌") and len(ap._hr_load_db()["employees"]) == 2


def test_hr_admin_shows_the_server_error_message():
    html = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")
    assert "async function _apiError(res, path)" in html
    assert html.count("e.serverError === 'name_exists'") >= 3


# ── 1d. (2026-10-16) Gender replaces Pronouns; portal shows only real data ──
def _employee_call(ap, emp_id):
    def call(method, path, body=None):
        st, _ct, b = ap._hr_api_route(method, path, {}, body or {}, {"role": "employee", "employee_id": emp_id})
        return st, json.loads(b)
    return call


def test_portal_gender_saves_m_or_f_only(hrapi):
    ap, call = hrapi
    emp = call("POST", "/employees", _new("ZTEST", "Gender"))[1]
    me = _employee_call(ap, emp["id"])
    assert me("PATCH", "/portal/me", {"gender": "f"})[1]["employee"]["gender"] == "F"
    assert me("PATCH", "/portal/me", {"gender": "Male"})[1]["employee"]["gender"] == "M"
    st, err = me("PATCH", "/portal/me", {"gender": "X"})
    assert st == 400 and err["error"] == "bad_gender"
    st, out = me("PATCH", "/portal/me", {"pronouns": "they/them"})
    assert "pronouns" not in out["changed"], "pronouns is no longer a portal field"


def test_portal_me_never_returns_login_hashes(hrapi):
    ap, call = hrapi
    emp = call("POST", "/employees", _new("ZTEST", "Hashes"))[1]
    st, out = _employee_call(ap, emp["id"])("GET", "/portal/me")
    assert st == 200
    for k in ("pin_hash", "portal_token_hash", "_session_secret"):
        assert k not in out["employee"]


def test_benefits_saved_on_employee_record_and_visible_to_portal(hrapi):
    ap, call = hrapi
    emp = call("POST", "/employees", _new("ZTEST", "Benefits"))[1]
    ben = {"health": "Employee Only", "dental": "Waive", "vision": "Employee Only", "k401": "3"}
    assert call("PATCH", f"/employees/{emp['id']}", {"benefits": ben})[0] == 200
    out = _employee_call(ap, emp["id"])("GET", "/portal/me")[1]
    assert out["employee"]["benefits"]["health"] == "Employee Only"


def test_hr_admin_benefits_go_to_the_database():
    html = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")
    a = html.index("async function saveBenefitsForm(empId)")
    body = html[a:a + 1500]
    assert "apiPatch(`/employees/${empId}`, { benefits })" in body
    assert "localStorage.setItem('hr_benefits_enrollment', JSON.stringify(saved))" not in html


PORTAL_SAMPLE_DATA = ("#EMP-0042", "Blue Cross PPO", "$842.50", "Operations Lead</div>", "Chandler, AZ</div>",
                      "MST (AZ)", "$62,400", "$47,580", "$38,400", "$29,700", "+$1,980.00", "Jamie Vavro | Employer",
                      ">8.5d<", ">4/6<", "Accruing 1.25d/mo", "label: 'Clean Record'",
                      'id="sidebar-role">Staff<', '<div class="profile-badge">Active</div>')


def test_portal_has_no_hardcoded_sample_employee_data():
    html = (ROOT / "hr_portal" / "index.html").read_text(encoding="utf-8")
    left = [s for s in PORTAL_SAMPLE_DATA if s in html]
    assert not left, f"sample data still in the HR Portal: {left}"


def test_portal_pages_render_from_the_employee_record():
    html = (ROOT / "hr_portal" / "index.html").read_text(encoding="utf-8")
    assert "{ k:'gender', label:'Gender', type:'select', opts:['M','F'] }" in html
    assert "k:'pronouns'" not in html
    for marker in ("id=\"pdt-employment\"", "id=\"pdt-benefits\"", "id=\"pyb-benefits\"", "id=\"prl-rate\"",
                   "window.loadPtoStats", "id=\"sidebar-status\""):
        assert marker in html, marker


# ── 2. one hr_scheduler runner across processes ─────────────────────────────
_HOLDER = textwrap.dedent("""
    import sys, time
    sys.path.insert(0, sys.argv[1])
    import hr_scheduler as hs
    hs._RUNNER_LOCK_PATH = sys.argv[2]
    hs._runner_lock_fh = None
    print("GOT" if hs._acquire_runner_lock() else "NO", flush=True)
    time.sleep(float(sys.argv[3]))
""")


def _try_in_subprocess(lock_path, hold=0.0):
    return subprocess.Popen([sys.executable, "-c", _HOLDER, str(ROOT), str(lock_path), str(hold)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_scheduler_runner_lock_is_exclusive_across_processes(tmp_path):
    lock = tmp_path / "hr_scheduler.lock"
    holder = _try_in_subprocess(lock, hold=20)
    try:
        first = holder.stdout.readline().strip()
        assert first == "GOT", holder.stderr.read() if first != "GOT" else ""
        second = _try_in_subprocess(lock)
        out, err = second.communicate(timeout=60)
        assert out.strip() == "NO", err
    finally:
        holder.kill()
        holder.wait(timeout=30)
    time.sleep(0.5)
    third = _try_in_subprocess(lock)
    out, err = third.communicate(timeout=60)
    assert out.strip() == "GOT", err


def test_tick_does_nothing_without_runner_lock(monkeypatch):
    import hr_scheduler as hs
    monkeypatch.setattr(hs, "_acquire_runner_lock", lambda: False)
    called = []
    monkeypatch.setattr(hs, "_scheduler_enabled", lambda: called.append(1) or True)
    hs._tick()
    assert called == []
