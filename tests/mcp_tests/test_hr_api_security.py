"""
HR API security guards (David, 2026-10-12).

  * every HR API route refuses a SIGNED-OUT caller (no admin token, no
    employee session) — the API has no global sign-in gate, each route guards
    itself, so this probes all of them. Found: POST /incidents (anyone could
    file reports under any employee's name) and POST /ai-chat — both fixed.
  * an employee's incident report is filed under THEIR OWN record
  * /test/cleanup's opt-in extras (all_linked / include_ztest_named /
    include_employees) never touch a real employee or their records

Run: run_tests.bat tests\\mcp_tests\\test_hr_api_security.py -v
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PUBLIC = {("POST", "/auth/employee")}          # signs employees in — must be reachable signed out


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    monkeypatch.setattr(m, "_HR_DB_PATH", str(tmp_path / "hr_db.json"))
    (tmp_path / "hr_db.json").write_text(json.dumps({
        "config": {"company_name": "ZTEST Co", "setup_complete": True, "doc_root": str(tmp_path / "docs")},
        "employees": [
            {"id": "EMP-00001", "first_name": "Real", "last_name": "Person", "status": "Active",
             "personal_email": "real.person@example.com"},
            {"id": "EMP-00002", "first_name": "ZTEST", "last_name": "QA", "status": "Active",
             "personal_email": "qa+hrtest@example.com"}],
        "tasks": [{"id": "TASK-00001", "employee_id": "EMP-00001", "name": "I-9", "status": "Not Started"},
                  {"id": "TASK-00002", "employee_id": "EMP-00002", "name": "I-9", "status": "Not Started"}],
        "pto_requests": [{"id": "PTO-1", "employee_id": "EMP-00001"}, {"id": "PTO-2", "employee_id": "EMP-00002"}],
        "messages": [{"id": "M1", "employee_id": "EMP-00001"}, {"id": "M2", "employee_id": "EMP-00002"}],
        "directory_contacts": [{"id": "C1", "name": "Real Vendor"}, {"id": "C2", "name": "ZTEST Contact"}],
        "locations": [{"id": "L1", "name": "Shop", "employee_ids": ["EMP-00001", "EMP-00002"]}],
        "documents": [], "audit_log": [], "attendance": []}), encoding="utf-8")
    return m


def _routes():
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    body = src[src.index("def _hr_api_route("):]
    body = body[:body.index("\ndef ", 10)]
    out = set()
    # action sub-paths: if subpath.startswith("/x/") and subpath.endswith("/act") and method == "M"
    # (2026-10-12: the first version missed /documents/<id>/download)
    for m in re.finditer(r'subpath\.startswith\(["\'](/[\w-]+/)["\']\)\s+and\s+subpath\.endswith\(["\'](/[\w-]+)["\']\)'
                         r'[^\n]*?method\s*==\s*["\'](\w+)["\']', body):
        out.add((m.group(3), m.group(1) + "DOC-00001" + m.group(2)))
    for m in re.finditer(r'subpath\s*(==|\.startswith\()\s*["\']([^"\']+)["\'][^\n]*?method\s*'
                         r'(?:==\s*["\'](\w+)["\']|in\s*\(([^)]*)\))', body):
        path = m.group(2) if m.group(1) == "==" else m.group(2).rstrip("/") + "/EMP-00001"
        for me in ([m.group(3)] if m.group(3) else re.findall(r"\w+", m.group(4) or "")):
            out.add((me, path))
    return sorted(out)


def test_routes_were_found():
    assert len(_routes()) >= 90, "the route scan stopped working"


def test_every_route_refuses_a_signed_out_caller(ap):
    open_ = []
    for me, path in _routes():
        if (me, path) in PUBLIC:
            continue
        st, _ct, b = ap._hr_api_route(me, path, {}, {"message": "hi", "employee_id": "EMP-00001",
                                                     "summary": "x"}, {"role": None})
        if 200 <= st < 300:
            open_.append(f"{me} {path} -> {st} {b[:80]!r}")
    assert not open_, "answered a signed-out caller:\n" + "\n".join(open_)


def test_incident_filed_under_the_callers_own_record(ap):
    st, _ct, b = ap._hr_api_route("POST", "/incidents", {}, {"summary": "x", "employee_id": "EMP-00001"},
                                  {"role": "employee", "employee_id": "EMP-00002"})
    assert st == 200
    inc = next(i for i in ap._hr_load_db()["incidents"] if i["id"] == json.loads(b)["id"])
    assert inc["employee_id"] == "EMP-00002" and inc["submitted_by"] == "employee"


def test_cleanup_extras_never_touch_real_people(ap):
    st, _ct, _b = ap._hr_api_route("POST", "/test/cleanup", {},
                                   {"all_linked": True, "include_ztest_named": True, "include_employees": True},
                                   {"role": "admin"})
    assert st == 200
    db = ap._hr_load_db()
    assert [e["id"] for e in db["employees"]] == ["EMP-00001"]
    assert [t["id"] for t in db["tasks"]] == ["TASK-00001"]
    assert [p["id"] for p in db["pto_requests"]] == ["PTO-1"]
    assert [m["id"] for m in db["messages"]] == ["M1"]
    assert [c["id"] for c in db["directory_contacts"]] == ["C1"]
    assert db["locations"][0]["employee_ids"] == ["EMP-00001"], "a shared location lost a real employee"


def test_cleanup_defaults_unchanged_for_jamies_flow(ap):
    st, _ct, _b = ap._hr_api_route("POST", "/test/cleanup", {}, {}, {"role": "admin"})
    assert st == 200
    db = ap._hr_load_db()
    assert len(db["employees"]) == 2 and len(db["pto_requests"]) == 2, "default cleanup removed more than before"


def test_cleanup_is_admin_only(ap):
    st, _ct, _b = ap._hr_api_route("POST", "/test/cleanup", {}, {"include_employees": True},
                                   {"role": "employee", "employee_id": "EMP-00002"})
    assert st == 403


def test_document_download_only_for_hr_or_the_owner(ap, tmp_path):
    f = tmp_path / "id.pdf"
    f.write_bytes(b"%PDF-1.4 ZTEST")
    with ap._hr_db_lock:
        db = ap._hr_load_db()
        db["documents"] = [{"id": "DOC-00001", "employee_id": "EMP-00001", "name": "ID",
                            "file_path": str(f)}]
        ap._hr_save_db(db)
    route = lambda auth: ap._hr_api_route("GET", "/documents/DOC-00001/download", {}, {}, auth)[0]
    assert route({"role": None}) == 401
    assert route({"role": "employee", "employee_id": "EMP-00002"}) == 404, "another employee downloaded it"
    assert route({"role": "employee", "employee_id": "EMP-00001"}) == 200
    assert route({"role": "admin"}) == 200
