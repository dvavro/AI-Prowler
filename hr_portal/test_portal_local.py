import json, pathlib, os, sys

PASS = 0
FAIL = 0

def test(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ✅ PASS — {name}")
    else:
        FAIL += 1
        print(f"  ❌ FAIL — {name}" + (f": {detail}" if detail else ""))

DEPLOY = pathlib.Path(r"C:\Program Files\AI-Prowler")
DEV    = pathlib.Path(r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler")

print("\n=== AI-Prowler HR Portal — File & Config Tests ===\n")

# ── 1. Key files exist ───────────────────────────────────
print("📄 Deployed File Checks")
files = [
    ("Employee portal (index.html)",   DEPLOY / "hr_portal/index.html"),
    ("HR Admin (index.html)",          DEPLOY / "hr_admin/index.html"),
    ("Backend (ai_prowler_mcp.py)",    DEPLOY / "ai_prowler_mcp.py"),
    ("Incident Report PDF",            DEPLOY / "hr_portal/docs/AI-Prowler_Incident_Report_Form.pdf"),
    ("Employee Handbook PDF",          DEPLOY / "hr_portal/docs/AI-Prowler_Employee_Handbook_2026.pdf"),
    ("Safety Guidelines PDF",         DEPLOY / "hr_portal/docs/AI-Prowler_Safety_Guidelines_2026.pdf"),
]
for name, path in files:
    test(name, path.exists(), str(path))

# ── 2. Policy documents ──────────────────────────────────
print("\n📋 Policy Document Checks")
policies = [
    ("Attendance policy",      DEPLOY / "hr_portal/docs/policy_attendance.html"),
    ("Compensation policy",    DEPLOY / "hr_portal/docs/policy_compensation.html"),
    ("Time Off policy",        DEPLOY / "hr_portal/docs/policy_timeoff.html"),
    ("Code of Conduct",        DEPLOY / "hr_portal/docs/policy_conduct.html"),
    ("Privacy policy",         DEPLOY / "hr_portal/docs/policy_privacy.html"),
    ("Health & Safety policy", DEPLOY / "hr_portal/docs/policy_health_safety.html"),
]
for name, path in policies:
    exists = path.exists()
    test(f"{name} exists", exists)
    if exists:
        size = path.stat().st_size
        test(f"{name} has content (>2KB)", size > 2000, f"{size} bytes")

# ── 3. Portal HTML content checks ───────────────────────
print("\n🔍 Employee Portal Content Checks")
portal = DEPLOY / "hr_portal/index.html"
if portal.exists():
    html = portal.read_text(encoding="utf-8-sig", errors="replace")
    test("Has Messages nav item",          'data-page="messages"' in html or 'data-page=\'messages\'' in html)
    test("Has Incident Reports nav item",  "incident-reports" in html)
    test("Has Write-Ups page",             "page-writeup" in html)
    test("Has My Team page",               "page-my-team" in html)
    test("Has Back button",                "header-back-btn" in html)
    test("Has Incident modal",             "incidentModal" in html)
    test("Has Messages page",              "page-messages" in html)
    test("Has loadSentReports function",   "loadSentReports" in html)
    test("Has openPolicy function",        "openPolicy" in html)
    test("Has policy viewer modal",        "policy-modal" in html)
    test("Has Welcome page",               "page-welcome" in html)
    test("Attendance policy linked",       "policy_attendance.html" in html)
    test("Compensation policy linked",     "policy_compensation.html" in html)
    test("Time Off policy linked",         "policy_timeoff.html" in html)
    test("Code of Conduct linked",         "policy_conduct.html" in html)
    test("Privacy policy linked",          "policy_privacy.html" in html)
    test("Health Safety policy linked",    "policy_health_safety.html" in html)
    size_kb = portal.stat().st_size // 1024
    test(f"Portal file size reasonable ({size_kb}KB)", size_kb > 100)

# ── 4. Backend API checks ────────────────────────────────
print("\n🔌 Backend (ai_prowler_mcp.py) Checks")
backend = DEPLOY / "ai_prowler_mcp.py"
if backend.exists():
    code = backend.read_text(encoding="utf-8-sig", errors="replace")
    test("Has /messages POST endpoint",       '"/messages"' in code or "'/messages'" in code)
    test("Has /messages/outbox GET",          "messages/outbox" in code)
    test("Has /messages/my-reports POST",     "messages/my-reports" in code)
    test("Has /messages/delete POST",         "messages/delete" in code)
    test("Has /messages/hr-outbox POST",      "messages/hr-outbox" in code)
    test("Has incident_report handling",      "incident_report" in code)

# ── 5. Database check ────────────────────────────────────
print("\n💾 Database Checks")
db_path = pathlib.Path.home() / ".ai-prowler" / "hr" / "hr_db.json"
test("hr_db.json exists", db_path.exists(), str(db_path))
if db_path.exists():
    try:
        db = json.loads(db_path.read_text(encoding="utf-8"))
        test("Database is valid JSON", True)
        msgs = db.get("messages", [])
        outbox = db.get("outbox", [])
        employees = db.get("employees", [])
        test(f"Messages array exists ({len(msgs)} messages)", "messages" in db)
        test(f"Outbox array exists ({len(outbox)} items)", "outbox" in db)
        test(f"Employees array exists ({len(employees)} employees)", "employees" in db)
    except Exception as e:
        test("Database is valid JSON", False, str(e))

# ── Summary ──────────────────────────────────────────────
print(f"\n{'='*50}")
print(f"  Results: {PASS} passed  |  {FAIL} failed  |  {PASS+FAIL} total")
if FAIL == 0:
    print("  🎉 All tests passed! Portal is fully deployed.")
else:
    print(f"  ⚠️  {FAIL} item(s) need attention — see above.")
print(f"{'='*50}\n")
