import json, pathlib, requests, sys, time

BASE = "https://ap-jamievavroaiprowler-f68efeed.ai-prowler.com"
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

print("\n=== AI-Prowler HR Portal — Full Test Run ===\n")

# ── 1. Portal loads ──────────────────────────────────────
print("📄 Page Load Tests")
try:
    r = requests.get(f"{BASE}/hr_portal/", timeout=8)
    test("Employee portal loads (200)", r.status_code == 200)
    test("Portal contains AI-Prowler branding", "AI-Prowler" in r.text)
    test("Portal has login screen", "login-screen" in r.text)
    test("Portal has Messages nav item", "messages" in r.text.lower())
    test("Portal has Incident Reports nav", "incident" in r.text.lower())
except Exception as e:
    test("Employee portal loads", False, str(e))

# ── 2. HR Admin loads ────────────────────────────────────
print("\n📄 HR Admin Tests")
try:
    r = requests.get(f"{BASE}/hr_admin/", timeout=8)
    test("HR Admin loads (200)", r.status_code == 200)
    test("HR Admin has Messages tab", "messages" in r.text.lower())
    test("HR Admin has Employees tab", "employees" in r.text.lower())
except Exception as e:
    test("HR Admin loads", False, str(e))

# ── 3. API Endpoints ─────────────────────────────────────
print("\n🔌 API Endpoint Tests")

# Send a message
try:
    r = requests.post(f"{BASE}/hr-api/messages", json={
        "sender_name": "Test Employee",
        "subject": "Test Message from Portal Test",
        "body": "This is an automated test message.",
        "message_type": "employee_message"
    }, timeout=8)
    data = r.json()
    test("POST /hr-api/messages (send message)", data.get("ok") == True)
    msg_id = data.get("id", "")
    test("Message has ID returned", bool(msg_id), msg_id)
except Exception as e:
    test("POST /hr-api/messages", False, str(e))
    msg_id = ""

# Submit incident report
try:
    r = requests.post(f"{BASE}/hr-api/messages", json={
        "sender_name": "jamie vavro",
        "subject": "🚨 Incident Report — Injury · 2026-09-13",
        "body": "TEST INCIDENT REPORT\nType: Injury\nLocation: Home Office\nDescription: Test submission.",
        "message_type": "incident_report"
    }, timeout=8)
    data = r.json()
    test("POST /hr-api/messages (incident report)", data.get("ok") == True)
    inc_id = data.get("id", "")
except Exception as e:
    test("POST /hr-api/messages (incident)", False, str(e))
    inc_id = ""

# Fetch outbox (employee reads HR messages)
try:
    r = requests.get(f"{BASE}/hr-api/messages/outbox", timeout=8)
    data = r.json()
    test("GET /hr-api/messages/outbox (public)", "messages" in data)
except Exception as e:
    test("GET /hr-api/messages/outbox", False, str(e))

# Fetch my-reports
try:
    r = requests.post(f"{BASE}/hr-api/messages/my-reports", json={
        "sender_name": "jamie vavro"
    }, timeout=8)
    data = r.json()
    test("POST /hr-api/messages/my-reports", "reports" in data)
    test("Incident report appears in my-reports", len(data.get("reports", [])) > 0)
except Exception as e:
    test("POST /hr-api/messages/my-reports", False, str(e))

# ── 4. Policy Documents ──────────────────────────────────
print("\n📋 Policy Document Tests")
policies = [
    ("Attendance", "/hr_portal/docs/policy_attendance.html"),
    ("Compensation", "/hr_portal/docs/policy_compensation.html"),
    ("Time Off", "/hr_portal/docs/policy_timeoff.html"),
    ("Code of Conduct", "/hr_portal/docs/policy_conduct.html"),
    ("Privacy", "/hr_portal/docs/policy_privacy.html"),
    ("Health & Safety", "/hr_portal/docs/policy_health_safety.html"),
]
for name, path in policies:
    try:
        r = requests.get(f"{BASE}{path}", timeout=8)
        test(f"{name} policy loads (200)", r.status_code == 200)
        test(f"{name} policy has content", len(r.text) > 2000)
    except Exception as e:
        test(f"{name} policy loads", False, str(e))

# ── 5. PDF Documents ─────────────────────────────────────
print("\n📄 PDF Document Tests")
pdfs = [
    ("Employee Handbook", "/hr_portal/docs/AI-Prowler_Employee_Handbook_2026.pdf"),
    ("Safety Guidelines", "/hr_portal/docs/AI-Prowler_Safety_Guidelines_2026.pdf"),
    ("Incident Report PDF", "/hr_portal/docs/AI-Prowler_Incident_Report_Form.pdf"),
]
for name, path in pdfs:
    try:
        r = requests.get(f"{BASE}{path}", timeout=8)
        test(f"{name} PDF accessible", r.status_code == 200)
    except Exception as e:
        test(f"{name} PDF accessible", False, str(e))

# ── 6. Delete test message ───────────────────────────────
print("\n🧹 Cleanup")
if msg_id:
    try:
        # Need admin auth for delete - just verify endpoint exists
        r = requests.post(f"{BASE}/hr-api/messages/delete", json={"id": msg_id, "box": "inbox"}, timeout=8)
        data = r.json()
        # Expect 403 (no admin auth) or 200 — either means endpoint exists
        test("DELETE endpoint reachable", r.status_code in [200, 403, 401])
    except Exception as e:
        test("DELETE endpoint reachable", False, str(e))

# ── Summary ──────────────────────────────────────────────
print(f"\n{'='*45}")
print(f"  Results: {PASS} passed  |  {FAIL} failed  |  {PASS+FAIL} total")
if FAIL == 0:
    print("  🎉 All tests passed!")
else:
    print(f"  ⚠️  {FAIL} test(s) need attention")
print(f"{'='*45}\n")
