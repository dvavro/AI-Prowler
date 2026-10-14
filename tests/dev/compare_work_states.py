"""Dev helper (2026-10-11): how the setup wizard captures work_states in the old
hr/index.html (git HEAD, before retirement) vs hr_admin/index.html. Prints every
line mentioning work_states / workStates with 2 lines of context. ASCII output."""
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
old = subprocess.run(["git", "-C", str(REPO), "show", "HEAD:hr/index.html"], capture_output=True,
                     text=True, encoding="utf-8", errors="replace").stdout
new = (REPO / "hr_admin" / "index.html").read_text(encoding="utf-8", errors="replace")
for label, text in (("OLD hr/index.html", old), ("NEW hr_admin/index.html", new)):
    lines = text.splitlines()
    hits = [i for i, l in enumerate(lines) if re.search(r"work_states|workStates|wizard-states|wz-states", l)]
    print(f"\n===== {label}: {len(hits)} line(s)")
    for i in hits[:20]:
        print(f"  {i + 1:6}: {lines[i].strip()[:180]}".encode("ascii", "backslashreplace").decode())
