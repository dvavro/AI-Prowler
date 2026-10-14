"""Dev helper (2026-10-12): inventory of the HR apps for test-coverage review.
  1. every /hr-api route in _hr_api_route (method + path + role guard nearby)
  2. hr_scheduler.py jobs (name, when they run)
  3. which routes the existing tests touch (unit + live E2E)
ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8", errors="replace")
start = MCP.index("def _hr_api_route(")
end = MCP.index("\ndef ", start + 10)
body = MCP[start:end].splitlines()
routes = []
for i, l in enumerate(body):
    m = re.search(r'(?:if|elif)\s+.*?subpath\s*(==|\.startswith\()\s*["\']([^"\']+)["\'].*?(?:method\s*==\s*["\'](\w+)["\'])?', l)
    if not m:
        continue
    meth = m.group(3) or ""
    if not meth:
        mm = re.search(r'method\s*==\s*["\'](\w+)["\']', l) or re.search(r'method\s+in\s+\(([^)]*)\)', l)
        meth = mm.group(1) if mm else "?"
    guard = ""
    for j in range(i + 1, min(i + 8, len(body))):
        g = re.search(r'role["\']?\)?\s*(!=|==|not in|in)\s*([^:]+):', body[j])
        if g:
            guard = (g.group(1) + " " + g.group(2).strip())[:40]
            break
    routes.append((meth, m.group(2) + ("*" if m.group(1) != "==" else ""), guard))
print(f"== {len(routes)} HR API routes")
for meth, path, guard in routes:
    print(f"  {meth:7} {path:42} {guard}")

sched = (ROOT / "hr_scheduler.py").read_text(encoding="utf-8", errors="replace")
print("\n== hr_scheduler.py jobs")
for l in sched.splitlines():
    if re.search(r'add_job\(|def _job_|def job_|"id":|CronTrigger|IntervalTrigger|hour=', l):
        print("  " + l.strip()[:150].encode("ascii", "backslashreplace").decode("ascii"))

tests = list((ROOT / "tests").rglob("*hr*.py")) + [ROOT / "tests" / "gui_jobs_e2e_server" / "test_srv_hr_apps.py"]
blob = "\n".join(t.read_text(encoding="utf-8", errors="replace") for t in set(tests) if t.exists())
print("\n== routes NOT mentioned in any HR test")
for meth, path, _ in routes:
    key = path.rstrip("*").rstrip("/")
    if key and key not in blob:
        print(f"  {meth:7} {path}")
