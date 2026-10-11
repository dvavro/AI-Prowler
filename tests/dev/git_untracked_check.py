"""Dev helper (2026-10-11): list what `git add -A` would ADD (untracked, not
ignored) and flag anything that looks secret or bulky before a commit. Read-only."""
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def git(*a):
    return subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout


untracked = [l for l in git("ls-files", "--others", "--exclude-standard").splitlines() if l]
SUSPECT = ("token", "secret", "password", "users.local", ".env", "credential", "license",
           "config.json", "remote_access", "email_config", ".pem", ".key")
print(f"{len(untracked)} untracked file(s) would be added:")
for f in untracked:
    p = REPO / f
    size = p.stat().st_size if p.exists() else 0
    flag = []
    if any(s in f.lower() for s in SUSPECT):
        flag.append("NAME LOOKS SENSITIVE")
    if size > 2_000_000:
        flag.append(f"LARGE {size / 1_048_576:.1f} MB")
    line = f"  {f}  ({size:,} B)" + (("   <<< " + ", ".join(flag)) if flag else "")
    print(line.encode("ascii", "backslashreplace").decode("ascii"))
print("\nIgnored check for known secret files:")
for f in ("tests/gui_jobs_e2e_server/users.local.json", "tests/gui_jobs_e2e/users.local.json"):
    if (REPO / f).exists():
        r = subprocess.run(["git", "-C", str(REPO), "check-ignore", "-q", f])
        tracked = bool(git("ls-files", f).strip())
        print(f"  {f}: exists, {'IGNORED' if r.returncode == 0 else 'NOT ignored'}, "
              f"{'TRACKED' if tracked else 'not tracked'}")
    else:
        print(f"  {f}: not present")
