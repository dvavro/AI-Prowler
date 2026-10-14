"""2026-10-12, second live run:
  HF-12 attendance list defaults to THIS WEEK (Monday on) — ask for the
        employee's full history (employee_id + period=all)
  HF-13 the download returns base64 under "data_b64"
  HF-19 setEmpFilter needs a click event — check the employee is in HR Admin's
        loaded data instead of driving the filter buttons
  test_hr_api_security.py: probe every ACTION sub-path too (/x/<id>/<action>)
        — the signed-out probe missed /documents/<id>/download; plus a
        document-download ownership test
ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def edit(rel, pairs):
    p = ROOT / rel
    s = p.read_text(encoding="utf-8")
    for old, new in pairs:
        n = s.count(old)
        assert n >= 1, f"{rel}: not found: {old[:70]!r}"
        s = s.replace(old, new)
    compile(s, rel, "exec")
    p.write_text(s, encoding="utf-8")
    print(f"{rel}: ok")


edit("tests/gui_jobs_e2e_server/test_srv_hr_features.py", [
    ('d("GET", "/attendance")', 'd("GET", f"/attendance?period=all&employee_id={team[\'emp1\']}")'),
    ('''        got = base64.b64decode(_json(got.decode()).get("data", ""))''',
     '''        got = base64.b64decode(_json(got.decode()).get("data_b64", ""))'''),
    ('''    admin.evaluate("() => { if (typeof setEmpFilter === 'function') setEmpFilter('all'); }")
    admin.wait_for_timeout(500)
    expect(admin.locator("#tab-employees").get_by_text("ZTEST HF1").first).to_be_visible(timeout=15_000)''',
     '''    admin.wait_for_function("() => Array.isArray(state.employees) && "
                            "state.employees.some(e => String(e.first_name||'').startsWith('ZTEST HF1'))",
                            timeout=15_000)'''),
])

edit("tests/mcp_tests/test_hr_api_security.py", [
    ('''def _routes():
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    body = src[src.index("def _hr_api_route("):]
    body = body[:body.index("\\ndef ", 10)]
    out = set()''',
     '''def _routes():
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    body = src[src.index("def _hr_api_route("):]
    body = body[:body.index("\\ndef ", 10)]
    out = set()
    # action sub-paths: if subpath.startswith("/x/") and subpath.endswith("/act") and method == "M"
    # (2026-10-12: the first version missed /documents/<id>/download)
    for m in re.finditer(r'subpath\\.startswith\\(["\\'](/[\\w-]+/)["\\']\\)\\s+and\\s+subpath\\.endswith\\(["\\'](/[\\w-]+)["\\']\\)'
                         r'[^\\n]*?method\\s*==\\s*["\\'](\\w+)["\\']', body):
        out.add((m.group(3), m.group(1) + "DOC-00001" + m.group(2)))'''),
])

p = ROOT / "tests/mcp_tests/test_hr_api_security.py"
s = p.read_text(encoding="utf-8")
s += '''

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
'''
compile(s, str(p), "exec")
p.write_text(s, encoding="utf-8")
print("test_hr_api_security.py: download test added")
