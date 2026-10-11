"""Dev helper (2026-10-11): remove the edit tool's numbered backups — files whose
name ends in .bak<N> (e.g. ai_prowler_mcp.py.bak27) — under the work folder
C:\\Users\\david\\AI-Prowler-V910_to_V920_work. Skips .git. Nothing else is touched.

    clean_bak_files.py            dry run: counts per folder, total size
    clean_bak_files.py --apply    delete them
"""
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]          # ...\AI-Prowler-V910_to_V920_work
PAT = re.compile(r"\.bak\d+$", re.I)
apply = "--apply" in sys.argv

found = [p for p in ROOT.rglob("*")
         if p.is_file() and PAT.search(p.name) and ".git" not in p.relative_to(ROOT).parts]
size = sum(p.stat().st_size for p in found)
per_dir = Counter(str(p.parent.relative_to(ROOT)) or "." for p in found)
print(f"root: {ROOT}")
print(f"{len(found)} .bakN file(s), {size / 1_048_576:.1f} MB")
for d, n in sorted(per_dir.items(), key=lambda x: -x[1]):
    print(f"  {n:4}  {d}".encode("ascii", "backslashreplace").decode("ascii"))
if not apply:
    print("dry run — nothing deleted (run with --apply to delete)")
    sys.exit(0)
failed = []
for p in found:
    try:
        p.unlink()
    except OSError as e:
        failed.append(f"{p}: {e}")
print(f"deleted {len(found) - len(failed)} file(s)")
for f in failed[:20]:
    print("  FAILED " + f.encode("ascii", "backslashreplace").decode("ascii"))
left = [p for p in ROOT.rglob("*") if p.is_file() and PAT.search(p.name)
        and ".git" not in p.relative_to(ROOT).parts]
print(f"left: {len(left)}")
