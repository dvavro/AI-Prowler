"""Dev helper (2026-10-11): group a pytest log's FAILED/ERROR lines by test file,
with the first reason per file. Usage: failure_groups.py <log name in test_logs>
ASCII output."""
import re
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
log = ROOT / "test_logs" / sys.argv[1]
text = re.sub(r"\x1b\[[0-9;]*m", "", log.read_text(encoding="utf-8", errors="replace"))
groups = OrderedDict()
for line in text.splitlines():
    m = re.match(r"^(FAILED|ERROR) (\S+?)::(\S+)(?: - (.*))?$", line)
    if m:
        kind, f, test, why = m.groups()
        g = groups.setdefault(f, {"FAILED": 0, "ERROR": 0, "why": why or "", "tests": []})
        g[kind] += 1
        g["tests"].append(test)
for f, g in groups.items():
    print(f"{f}: {g['FAILED']} failed, {g['ERROR']} errors".encode("ascii", "backslashreplace").decode())
    print(f"    e.g. {g['tests'][0]}: {g['why'][:200]}".encode("ascii", "backslashreplace").decode())
