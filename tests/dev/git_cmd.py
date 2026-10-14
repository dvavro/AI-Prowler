"""Dev helper: run a read-only git command in the work copy. Usage: git_cmd.py status --short"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALLOWED = {"status", "diff", "log", "branch", "show", "ls-files"}
if not sys.argv[1:] or sys.argv[1] not in ALLOWED:
    sys.exit(f"only read-only git commands: {sorted(ALLOWED)}")
out = subprocess.run(["git", *sys.argv[1:]], cwd=ROOT, capture_output=True, text=True,
                     encoding="utf-8", errors="replace")
print((out.stdout + out.stderr).encode("ascii", "backslashreplace").decode("ascii"))
