"""Dev helper (2026-10-11): diff hr/sw.js vs hr_admin/sw.js and hr/manifest.json
vs hr_admin/manifest.json as they were in git (HEAD). ASCII output."""
import difflib
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def show(p):
    return subprocess.run(["git", "-C", str(REPO), "show", f"HEAD:{p}"], capture_output=True,
                          text=True, encoding="utf-8", errors="replace").stdout.splitlines()


for name in ("sw.js", "manifest.json"):
    d = list(difflib.unified_diff(show(f"hr/{name}"), show(f"hr_admin/{name}"),
                                  f"hr/{name}", f"hr_admin/{name}", lineterm="", n=0))
    print(f"===== {name}: {'identical' if not d else ''}")
    for l in d:
        print(l[:190].encode("ascii", "backslashreplace").decode())
