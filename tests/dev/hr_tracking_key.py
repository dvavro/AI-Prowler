"""2026-10-12: register job_lifecycle_advance's tracking key in the
hr_task_tracking.json template and update Jamie's job-count tests (12 -> 13)."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
p = ROOT / "hr_task_tracking.json"
raw = p.read_text(encoding="utf-8-sig")
data = json.loads(raw)
data.setdefault("scheduler", {})["last_lifecycle_advance"] = None
p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print("hr_task_tracking.json: scheduler.last_lifecycle_advance added")

t = ROOT / "tests" / "analysis" / "test_hr_scheduler.py"
s = t.read_text(encoding="utf-8")
s2, n = re.subn(r"(len\((?:set\()?(?:keys|tracking_keys)\)?\)) == 12",
                r"\1 == 13   # 13th: lifecycle_advance (R-090, 2026-10-12)", s)
compile(s2, str(t), "exec")
t.write_text(s2, encoding="utf-8")
print(f"test_hr_scheduler.py: {n} count(s) 12 -> 13")
