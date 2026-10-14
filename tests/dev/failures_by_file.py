"""Dev helper: group the FAILED/ERROR lines of a test_logs log by test file, with
the first reason for each file. Usage: failures_by_file.py [log name]. ASCII."""
import re
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
logs = sorted((ROOT / "test_logs").glob("test_run_*.log"), key=lambda p: p.stat().st_mtime)
log = ROOT / "test_logs" / sys.argv[1] if len(sys.argv) > 1 else logs[-1]
text = re.sub(r"\x1b\[[0-9;]*m", "", log.read_text(encoding="utf-8", errors="replace"))
groups = OrderedDict()
for l in text.splitlines():
    m = re.match(r"^(FAILED|ERROR) (\S+?)::(\S+)(?: - (.*))?$", l)
    if m:
        kind, f, test, why = m.groups()
        g = groups.setdefault(f, {"n": 0, "kind": set(), "why": why or ""})
        g["n"] += 1
        g["kind"].add(kind)
print(log.name)
for f, g in groups.items():
    print(f"{g['n']:3} {'/'.join(sorted(g['kind'])):12} {f}".encode("ascii", "backslashreplace").decode("ascii"))
    print(f"      {g['why'][:200]}".encode("ascii", "backslashreplace").decode("ascii"))
