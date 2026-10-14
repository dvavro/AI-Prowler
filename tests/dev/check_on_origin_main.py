"""Dev helper (2026-10-11): run given tests on a CLEAN checkout of origin/main
(a temporary git worktree next to the work copy, removed afterwards) — to tell
"broken on GitHub already" from "broken by the merge". ASCII output.
Usage: check_on_origin_main.py <pytest node or path> [...]"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WT = REPO.parent / "_origin_main_check"
PY = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "Python" / "Python311" / "python.exe"


def run(*a, cwd=None, env=None):
    r = subprocess.run(list(a), capture_output=True, text=True, encoding="utf-8", errors="replace",
                       cwd=cwd, env=env)
    return r.returncode, (r.stdout + r.stderr)


if WT.exists():
    run("git", "-C", str(REPO), "worktree", "remove", "--force", str(WT))
code, out = run("git", "-C", str(REPO), "worktree", "add", "--detach", str(WT), "origin/main")
print(out.strip()[-300:])
try:
    env = dict(os.environ)
    env["AIPROWLER_TEST_STATE_DIR"] = tempfile.mkdtemp(prefix="ai_prowler_origin_check_")
    code, out = run(str(PY), "-m", "pytest", "-q", "-p", "no:randomly", "-p", "no:cacheprovider",
                    *sys.argv[1:], cwd=str(WT), env=env)
    tail = [l for l in out.splitlines() if l.strip()][-12:]
    for l in tail:
        print(l[:220].encode("ascii", "backslashreplace").decode("ascii"))
    print(f"pytest exit code on origin/main: {code}")
finally:
    run("git", "-C", str(REPO), "worktree", "remove", "--force", str(WT))
    if WT.exists():
        shutil.rmtree(WT, ignore_errors=True)
    print("temporary worktree removed:", not WT.exists())
