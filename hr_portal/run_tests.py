import json, pathlib, sys

results = []
PASS = 0
FAIL = 0

def test(name, ok, detail=""):
    global PASS, FAIL
    symbol = "PASS" if ok else "FAIL"
    line = f"  {'✅' if ok else '❌'} {symbol} — {name}" + (f": {detail}" if detail else "")
    results.append(line)
    if ok: PASS += 1
    else: FAIL += 1

DEPLOY = pathlib.Path(r"C:\Program Files\AI-Prowler")

results.append("\n=== AI-Prowler HR Portal — Test Results ===\n")

results.append("📄 Deployed File Checks")
for name, path in [
    ("Employee portal",   DEPLOY / "hr_portal/index.html"),
    ("HR Admin",          DEPLOY / "hr_admin/index.html"),
    ("Backend MCP",       DEPLOY / "ai_prowler_mcp.py"),
    ("Incident PDF",      DEPLOY / "hr_portal/docs/AI-Prowler_Incident_Report_Form.pdf"),
    ("Handbook PDF",      DEPLOY / "hr_portal/docs/AI-Prowler_Employee_Handbook_2026.pdf"),
    ("Safety PDF",        DEPLOY / "hr_portal/docs/AI-Prowler_Safety_Guidelines_2026.pdf"),
]:
    test(name, path.exists())

results.append("\n📋 Policy Documents")
for name, path in [
    ("Attendance",       DEPLOY / "hr_portal/docs/policy_attendance.html"),
    ("Compensation",     DEPLOY / "hr_portal/docs/policy_compensation.html"),
    ("Time Off",         DEPLOY / "hr_portal/docs/policy_timeoff.html"),
    ("Code of Conduct",  DEPLOY / "hr_portal/docs/policy_conduct.html"),
    ("Privacy",          DEPLOY / "hr_portal/docs/policy_privacy.html"),
    ("Health & Safety",  DEPLOY / "hr_portal/docs/policy_health_safety.html"),
]:
    e = path.exists()
    test(f"{name} exists", e)
    if e: test(f"{name} has content", path.stat().st_size > 2000, f"{path.stat().st_size} bytes")

results.append("\n🔍 Employee Portal HTML")
p = DEPLOY / "hr_portal/index.html"
if p.exists():
    html = p.read_text(encoding="utf-8-sig", errors="replace")
    for name, check in [
        ("Messages nav", 'data-page="messages"' in html),
        ("Incident Reports nav", "incident-reports" in html),
        ("Write-Ups page", "page-writeup" in html),
        ("My Team page", "page-my-team" in html),
        ("Back button", "header-back-btn" in html),
        ("Incident modal", "incidentModal" in html),
        ("Messages page", "page-messages" in html),
        ("loadSentReports fn", "loadSentReports" in html),
        ("openPolicy fn", "openPolicy" in html),
        ("Policy viewer modal", "policy-modal" in html),
        ("Welcome page", "page-welcome" in html),
        ("Attendance policy linked", "policy_attendance.html" in html),
        ("Compensation policy linked", "policy_compensation.html" in html),
        ("Time Off policy linked", "policy_timeoff.html" in html),
        ("Code of Conduct linked", "policy_conduct.html" in html),
        ("Privacy policy linked", "policy_privacy.html" in html),
        ("Health Safety linked", "policy_health_safety.html" in html),
    ]:
        test(name, check)

results.append("\n🔌 Backend API")
b = DEPLOY / "ai_prowler_mcp.py"
if b.exists():
    code = b.read_text(encoding="utf-8-sig", errors="replace")
    for name, check in [
        ("messages/outbox endpoint", "messages/outbox" in code),
        ("messages/my-reports endpoint", "messages/my-reports" in code),
        ("messages/delete endpoint", "messages/delete" in code),
        ("messages/hr-outbox endpoint", "messages/hr-outbox" in code),
        ("incident_report type", "incident_report" in code),
    ]:
        test(name, check)

results.append("\n💾 Database")
db_path = pathlib.Path.home() / ".ai-prowler" / "hr" / "hr_db.json"
test("hr_db.json exists", db_path.exists())
if db_path.exists():
    try:
        db = json.loads(db_path.read_text(encoding="utf-8"))
        test("DB valid JSON", True)
        for key in ["messages","outbox","employees"]:
            test(f'DB has "{key}" array', key in db, f"{len(db.get(key,[]))} items")
    except Exception as e:
        test("DB valid JSON", False, str(e))

results.append(f"\n{'='*45}")
results.append(f"  TOTAL: {PASS} passed  |  {FAIL} failed  |  {PASS+FAIL} total")
results.append("  🎉 All tests passed!" if FAIL == 0 else f"  ⚠️  {FAIL} item(s) need attention")
results.append(f"{'='*45}\n")

out = "\n".join(results)
out_path = pathlib.Path(r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\test_results.txt")
out_path.write_text(out, encoding="utf-8")
print("Done — results written to test_results.txt")
