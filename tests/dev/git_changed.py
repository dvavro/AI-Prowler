"""Dev helper: tracked files changed since the last commit (M/A/D/R), plus
untracked non-generated files. Skips */artifacts/*, tmp_r056proto/, backups.
ASCII output."""
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def git(*a):
    return subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout


print("branch:", git("branch", "--show-current").strip(), "| last commit:",
      git("log", "-1", "--format=%h %s").strip())
print("\nTRACKED changes:")
for l in git("status", "--porcelain", "--untracked-files=no").splitlines():
    print("  " + l)
print("\nNEW files (untracked, not generated):")
for l in git("ls-files", "--others", "--exclude-standard").splitlines():
    if "/artifacts/" in "/" + l or l.startswith(("tmp_r056proto/", "backup/")) or ".bak" in l:
        continue
    print("  " + l)
