"""Dev helper: FAILED/ERROR lines of a test_logs run, grouped by test file, with
the first reason. Usage: failure_summary.py [log name substring]. ASCII output."""
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
logs = sorted((ROOT / "test_logs").glob("test_run_*.log"), key=lambda p: p.stat().st_mtime)
if len(sys.argv) > 1:
    logs = [l for l in logs if sys.argv[1] in l.name]
log = logs[-1]
text = re.sub(r"\x1b\[[0-9;]*m", "", log.read_text(encoding="utf-8", errors="replace"))
groups = defaultdict(list)
for l in text.splitlines():
    m = re.match(r"^(FAILED|ERROR) (\S+?)::(\S+)(?: - (.*))?$", l)
    if m:
        groups[m.group(2)].append((m.group(1), m.group(3), (m.group(4) or "")[:150]))
print(log.name)
for f in sorted(groups):
    rows = groups[f]
    print(f"\n{f}  ({len(rows)})")
    for kind, name, why in rows[:4]:
        print(f"  {kind} {name}: {why}".encode("ascii", "backslashreplace").decode("ascii"))
    if len(rows) > 4:
        print(f"  ... {len(rows) - 4} more")
