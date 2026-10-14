"""Dev helper (2026-10-11): every difference between the retired hr/index.html
and hr_admin/index.html AS THEY WERE IN GIT (HEAD, before today's edits) — to
find fixes that only ever reached the old app. Prints each hunk. ASCII output."""
import difflib
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def show(p):
    return subprocess.run(["git", "-C", str(REPO), "show", f"HEAD:{p}"], capture_output=True,
                          text=True, encoding="utf-8", errors="replace").stdout.splitlines()


old, adm = show("hr/index.html"), show("hr_admin/index.html")
diff = list(difflib.unified_diff(old, adm, "hr/index.html", "hr_admin/index.html", lineterm="", n=1))
hunks = sum(1 for l in diff if l.startswith("@@"))
print(f"{hunks} hunk(s); lines only in hr/: {sum(1 for l in diff if l.startswith('-') and not l.startswith('---'))}, "
      f"only in hr_admin/: {sum(1 for l in diff if l.startswith('+') and not l.startswith('+++'))}")
for l in diff[:260]:
    print(l[:190].encode("ascii", "backslashreplace").decode())
