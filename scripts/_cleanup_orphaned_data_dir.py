"""One-off cleanup: remove the empty, orphaned AI-Prowler/data/ folder left
over from the 2026-08-27 HR session (confirmed empty before running this)."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
target = os.path.join(ROOT, "data")

if not os.path.isdir(target):
    print("NOT_A_DIR_OR_MISSING")
elif os.listdir(target):
    print("NOT_EMPTY_ABORTING")
else:
    os.rmdir(target)
    print("REMOVED:", target)
