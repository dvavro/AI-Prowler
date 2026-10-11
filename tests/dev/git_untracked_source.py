"""Dev helper (2026-10-11): untracked, not-ignored files OUTSIDE generated test
output (any '/artifacts/' folder, tmp_r056proto/) — i.e. what would really be new
source in a commit. Read-only. ASCII output."""
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
EXCLUDE = ("/artifacts/", "tmp_r056proto/")
out = subprocess.run(["git", "-C", str(REPO), "ls-files", "--others", "--exclude-standard"],
                     capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
files = [f for f in out.splitlines() if f and not any(e in "/" + f for e in EXCLUDE)]
skipped = [f for f in out.splitlines() if f and any(e in "/" + f for e in EXCLUDE)]
print(f"{len(files)} untracked source file(s); {len(skipped)} generated file(s) left out")
for f in files:
    size = (REPO / f).stat().st_size if (REPO / f).exists() else 0
    print(f"  {f}  ({size:,} B)".encode("ascii", "backslashreplace").decode("ascii"))
