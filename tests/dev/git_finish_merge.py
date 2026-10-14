"""Dev helper (2026-10-11): commit the resolved merge of origin/main into
david-work-2026-10-11 (LOCAL only — nothing is pushed) and print the result."""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def git(*a):
    r = subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = (r.stdout + r.stderr).strip()
    if r.returncode:
        print(f"!! git {' '.join(a)}: {out}".encode("ascii", "backslashreplace").decode("ascii"))
        sys.exit(1)
    return out


def p(s):
    print(str(s).encode("ascii", "backslashreplace").decode("ascii"))


if git("diff", "--name-only", "--diff-filter=U"):
    p("unresolved conflicts remain — stopping")
    sys.exit(1)
git("commit", "-q", "--no-edit", "-m",
    "Merge GitHub main (Jamie: HR Admin / HR Portal apps) into David's work\n\n"
    "Conflicts resolved (keep both sides):\n"
    "  ai_prowler_mcp.py  - Jamie's HR module MCP tools + David's _ACCESS_ONLY_GUIDE\n"
    "  run_tests.bat      - David's playwright + pytest-playwright auto-install\n"
    "  tests/mcp_tests/test_pwa_api_route.py, test_pwa_static_route.py - Jamie's\n"
    "                       fresh-event-loop helper (same fix as David's)\n"
    "  time-machine latest/RUN_FOLDER.txt, SUMMARY.txt - untracked (generated)\n\n"
    "Unit/MCP/GUI suites: 5056 passed, 2 failed - both also fail on origin/main\n"
    "itself (HR state-dir source check expects 2 uses, finds 4; hr_* tools marked\n"
    "personal-only in the catalog but registered on a server).")
p("branch: " + git("branch", "--show-current"))
p(git("log", "--oneline", "-4", "--graph"))
p("ahead of origin/main by: " + git("rev-list", "--count", "origin/main..HEAD") + " commit(s); behind: "
  + git("rev-list", "--count", "HEAD..origin/main"))
p("local main still at: " + git("log", "-1", "--format=%h %s", "main"))
st = git("status", "--porcelain", "--untracked-files=no")
p("tracked files with uncommitted changes: " + (str(len(st.splitlines())) if st else "0"))
