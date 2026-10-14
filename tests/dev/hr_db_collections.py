"""Dev helper (2026-10-12): every collection (top-level key) of hr_db.json the
code reads or writes, and which employee-link field each uses — for a cleanup
that removes ALL records of the +hrtest@ QA employees. ASCII output."""
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8") + \
      (ROOT / "hr_scheduler.py").read_text(encoding="utf-8")
keys = defaultdict(int)
for m in re.finditer(r'\bdb(?:\d*|_\w+)?(?:\.get|\.setdefault)?\(?\[?["\'](\w+)["\']', src):
    keys[m.group(1)] += 1
links = defaultdict(set)
for k in keys:
    for m in re.finditer(r'db\w*(?:\.get|\.setdefault)?\(?\[?["\']' + k + r'["\'][^\n]{0,160}?\.get\(["\'](\w*(?:employee|emp|user|from|to)\w*)["\']', src):
        links[k].add(m.group(1))
for k, n in sorted(keys.items(), key=lambda kv: -kv[1]):
    print(f"  {k:28} {n:4}x   links: {sorted(links[k]) or '-'}")
