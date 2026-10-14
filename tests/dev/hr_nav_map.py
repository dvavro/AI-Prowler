"""Dev helper (2026-10-12): how HR Admin and HR Portal switch screens — the nav
function(s) and every page/section id they accept. ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for app in ("hr_admin/index.html", "hr_portal/index.html"):
    s = (ROOT / app).read_text(encoding="utf-8", errors="replace")
    fns = Counter = {}
    for m in re.finditer(r"onclick=\"(\w+)\(\s*'([\w-]+)'", s):
        fns.setdefault(m.group(1), set()).add(m.group(2))
    print(f"\n== {app}")
    for fn, args in sorted(fns.items(), key=lambda kv: -len(kv[1])):
        if len(args) >= 4:
            print(f"  {fn}(): {len(args)} targets: {', '.join(sorted(args))[:900]}")
    ids = sorted(set(re.findall(r'id="((?:page|section|view|tab)-[\w-]+)"', s)))
    print(f"  page/section ids ({len(ids)}): {', '.join(ids)[:900]}")
