"""Dev helper (2026-10-11, David: the original /hr/ app is bogus — can it be
removed?). Every reference to the hr/ folder or the /hr/ URL in tracked files,
excluding hr_admin / hr_portal / hr-api / hr_* names. Read-only. ASCII output."""
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
files = subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True,
                       encoding="utf-8").stdout.splitlines()
# /hr  or /hr/  or hr\  or "hr" folder — but not /hr_admin, /hr_portal, /hr-api, hr_db, hr_scheduler ...
RX = re.compile(r"""(?:["'/\\(=\s]|^)hr(?:[/\\]|["'](?!\w)|$)|/hr(?![\w-])""")
SKIP_PREFIX = ("hr/",)                 # the folder's own files
by_file = {}
for f in files:
    if f.startswith(SKIP_PREFIX) or not f.endswith((".py", ".html", ".js", ".json", ".bat", ".iss",
                                                    ".md", ".txt", ".ini", ".ps1")):
        continue
    try:
        lines = (REPO / f).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        continue
    hits = [(i + 1, l.strip()) for i, l in enumerate(lines) if RX.search(l)]
    if hits:
        by_file[f] = hits
for f in sorted(by_file):
    print(f"\n== {f} ({len(by_file[f])})")
    for n, l in by_file[f][:12]:
        print(f"  {n:6}: {l[:170]}".encode("ascii", "backslashreplace").decode("ascii"))
    if len(by_file[f]) > 12:
        print(f"  ... {len(by_file[f]) - 12} more")
print("\nfiles in hr/:", sorted(p.name for p in (REPO / "hr").iterdir()) if (REPO / "hr").is_dir() else "none")
