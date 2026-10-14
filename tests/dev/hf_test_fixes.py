"""2026-10-12: test-side fixes from the first live run of test_srv_hr_features.py
  HF-02  clear message when the employee's task list is empty
  HF-03  /pto/company is a shared calendar view (no request ids) — match dates
  HF-12  match the attendance record by date + status (HF-03's approval adds
         a 'pto' day with the same run tag)
  HF-13  match the uploaded document by its exact name (HF-08's training
         completion adds a certificate document with the run tag)
  HF-19  the Employees screen filters by phase — show 'all' before looking
ASCII output."""
from pathlib import Path

p = Path(__file__).resolve().parents[2] / "tests/gui_jobs_e2e_server/test_srv_hr_features.py"
s = p.read_text(encoding="utf-8")
pairs = [
    ('''    assert mine and all(t["employee_id"] == team["emp1"] for t in mine), "Samual sees someone else's tasks"''',
     '''    assert mine, ("Samual has no onboarding tasks — the server isn't generating them "
                  "(is hr_task_templates.json in the install folder?)")
    assert all(t["employee_id"] == team["emp1"] for t in mine), "Samual sees someone else's tasks"'''),
    ('''    assert id1 in {x["id"] for x in _ok(s("GET", "/pto/company"), "company calendar")["requests"]}''',
     '''    company = _ok(s("GET", "/pto/company"), "company calendar")["requests"]   # shared view: no ids
    assert any(x.get("start_date") == D(20) and x.get("end_date") == D(22) for x in company), company[:3]'''),
    ('''    rec = next(x for x in _ok(d("GET", "/attendance"), "list")["records"] if RUN in (x.get("note") or ""))''',
     '''    rec = next(x for x in _ok(d("GET", "/attendance"), "list")["records"]
               if RUN in (x.get("note") or "") and x.get("date") == D(-1) and x.get("status") == "late")'''),
    ('''    doc = next(x for x in docs if RUN in (x.get("name") or ""))''',
     '''    doc = next(x for x in docs if x.get("name") == f"ZTEST Doc {RUN}")'''),
    ('''    admin.evaluate("() => navTo('employees')")
    expect(admin.get_by_text(f"ZTEST HF1").first).to_be_visible(timeout=15_000)''',
     '''    admin.evaluate("() => navTo('employees')")
    admin.evaluate("() => { if (typeof setEmpFilter === 'function') setEmpFilter('all'); }")
    admin.wait_for_timeout(500)
    expect(admin.locator("#tab-employees").get_by_text("ZTEST HF1").first).to_be_visible(timeout=15_000)'''),
]
for old, new in pairs:
    assert s.count(old) == 1, f"not found once: {old[:70]!r}"
    s = s.replace(old, new)
compile(s, str(p), "exec")
p.write_text(s, encoding="utf-8")
print(f"{len(pairs)} fixes applied")
