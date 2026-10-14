"""Dev helper (2026-10-12): call every HR API route as a SIGNED-OUT caller
(auth role None) against a THROWAWAY hr_db.json, and list the ones that answer
2xx instead of 401/403. Never touches the real HR database. ASCII output."""
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
tmp = Path(tempfile.mkdtemp(prefix="hr_probe_"))
os.environ["AIPROWLER_TEST_STATE_DIR"] = str(tmp)
sys.path.insert(0, str(ROOT))
import ai_prowler_mcp as ap  # noqa: E402

ap._HR_DB_PATH = str(tmp / "hr_db.json")
seed = {"config": {"company_name": "ZTEST Co", "setup_complete": True},
        "employees": [{"id": "EMP-00001", "first_name": "ZTEST", "last_name": "One",
                       "status": "Active", "personal_email": "z1+hrtest@example.com",
                       "date_of_birth": "1990-01-02"}],
        "tasks": [{"id": "TASK-00001", "employee_id": "EMP-00001", "name": "I-9", "status": "Not Started"}],
        "documents": [], "audit_log": [], "attendance": [{"id": "ATT-1", "employee_id": "EMP-00001"}],
        "pto_requests": [], "messages": [], "incidents": [], "training": [], "reminders": [],
        "locations": [], "timeclock": [], "directory": [], "swaps": [], "schedule_changes": []}
Path(ap._HR_DB_PATH).write_text(json.dumps(seed), encoding="utf-8")

src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
body = src[src.index("def _hr_api_route("):]
body = body[:body.index("\ndef ", 10)]
routes = set()
for m in re.finditer(r'subpath\s*(==|\.startswith\()\s*["\']([^"\']+)["\'][^\n]*?method\s*(?:==\s*["\'](\w+)["\']|in\s*\(([^)]*)\))', body):
    path, meths = m.group(2), [m.group(3)] if m.group(3) else re.findall(r"\w+", m.group(4) or "")
    if m.group(1) != "==":
        path = path.rstrip("/") + "/EMP-00001"
    for me in meths:
        routes.add((me, path))
open_routes = []
for me, path in sorted(routes, key=lambda r: (r[1], r[0])):
    if path in ("/auth/employee",):
        continue
    try:
        st, _ct, b = ap._hr_api_route(me, path, {}, {"message": "hi", "employee_id": "EMP-00001"},
                                      {"role": None})
    except Exception as e:
        st, b = 500, str(e).encode()
    if 200 <= st < 300:
        open_routes.append((me, path, st, b[:90]))
print(f"probed {len(routes)} route/method pairs as a signed-out caller")
print(f"answered 2xx (NO sign-in required): {len(open_routes)}")
for me, path, st, b in open_routes:
    print(f"  {me:6} {path:38} {st}  {b!r}"[:170])
