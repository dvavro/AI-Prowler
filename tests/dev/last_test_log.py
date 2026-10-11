"""Dev helper: print the summary of the newest test_logs\\test_run_*.log —
FAILED/ERROR lines, assertion lines (E ...) and the final counts. ASCII-only output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
logs = sorted((ROOT / "test_logs").glob("test_run_*.log"), key=lambda p: p.stat().st_mtime)
if not logs:
    raise SystemExit("no logs")
log = logs[-1]
text = log.read_text(encoding="utf-8", errors="replace")
text = re.sub(r"\x1b\[[0-9;]*m", "", text)
keep = [l for l in text.splitlines()
        if re.match(r"^(FAILED|ERROR) ", l) or l.startswith("E   ")
        or re.search(r"\d+ (passed|failed)", l) or l.startswith("____")]
print(log.name)
for l in keep[-80:]:
    print(l[:220].encode("ascii", "backslashreplace").decode("ascii"))
