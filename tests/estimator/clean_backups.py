"""Delete the .bakN backup files left by edits to the Estimator files.

    python tests\\estimator\\clean_backups.py           (dry run: lists what would be deleted)
    python tests\\estimator\\clean_backups.py --apply   (deletes them)

Only touches: estimator\\, tests\\estimator\\, install_estimator.py, and the Estimator Plan and Design Spec docs.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # ...\AI-Prowler
WORK = ROOT.parent                                  # ...\AI-Prowler_V970_to_V1000
BAK = re.compile(r"\.bak\d+$")

found = []
for folder in (ROOT / "estimator", ROOT / "tests" / "estimator"):
    found += [p for p in folder.rglob("*") if p.is_file() and BAK.search(p.name)]
for base in (ROOT / "install_estimator.py", WORK / "AI-Prowler Estimator Implementation Plan.md",
             WORK / "AI-Prowler Estimator Design Spec.md"):
    found += [p for p in base.parent.glob(base.name + ".bak*") if p.is_file() and BAK.search(p.name)]

found = sorted(set(found))
size = sum(p.stat().st_size for p in found)
apply = "--apply" in sys.argv
by_folder = {}
for p in found:
    by_folder.setdefault(str(p.parent), 0)
    by_folder[str(p.parent)] += 1
for folder, n in sorted(by_folder.items()):
    print(f"{n:4d}  {folder}")
print(f"{len(found)} backup files, {size / 1024:.0f} KB")
if apply:
    failed = 0
    for p in found:
        try:
            p.unlink()
        except OSError as exc:
            failed += 1
            print(f"couldn't delete {p}: {exc}")
    print(f"Deleted {len(found) - failed} files." + (f" {failed} couldn't be deleted." if failed else ""))
else:
    print("Dry run: nothing deleted. Run with --apply to delete.")
