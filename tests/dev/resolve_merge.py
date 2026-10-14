"""Dev helper (2026-10-11): resolve the 6 conflicts of merging origin/main (Jamie,
HR apps) into david-work-2026-10-11. Decisions (agreed with David: keep both
sides' changes):

  ai_prowler_mcp.py        1 block — both inserted new code at one spot:
                           THEIRS (HR module MCP tools, 720 lines) + OURS
                           (_ACCESS_ONLY_GUIDE, 31 lines, kept next to
                           how_to_use_ai_prowler which uses it)
  run_tests.bat            OURS — same playwright auto-install, ours also
                           installs pytest-playwright
  tests/mcp_tests/test_pwa_api_route.py     THEIRS — same fix (fresh event
  tests/mcp_tests/test_pwa_static_route.py  loop); theirs uses their helper
  tests/gui_jobs_timemachine/artifacts/personal/latest/{RUN_FOLDER,SUMMARY}.txt
                           generated run pointers Jamie removed from git —
                           untracked (git rm --cached), files kept on disk
Stages the result; does NOT commit (that waits for the tests). ASCII output."""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def git(*a):
    r = subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode:
        print(f"!! git {' '.join(a)}: {(r.stdout + r.stderr).strip()}")
        sys.exit(1)
    return r.stdout


def resolve(rel, pick):
    """pick(ours_lines, theirs_lines) -> lines. Keeps the file's own newline style."""
    path = REPO / rel
    raw = path.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.split(nl)
    out, i, blocks = [], 0, 0
    while i < len(lines):
        if lines[i].startswith("<<<<<<< "):
            m = next(j for j in range(i, len(lines)) if lines[j].startswith("======="))
            e = next(j for j in range(m, len(lines)) if lines[j].startswith(">>>>>>> "))
            out.extend(pick(lines[i + 1:m], lines[m + 1:e]))
            blocks += 1
            i = e + 1
        else:
            out.append(lines[i])
            i += 1
    text = nl.join(out)
    assert "<<<<<<< " not in text and "\n=======\n" not in text.replace("\r", "") \
        and ">>>>>>> " not in text, f"markers left in {rel}"
    path.write_bytes(text.encode("utf-8"))
    git("add", "--", rel)
    print(f"resolved {rel}: {blocks} block(s)")


resolve("ai_prowler_mcp.py", lambda ours, theirs: theirs + ["", ""] + ours)
resolve("run_tests.bat", lambda ours, theirs: ours)
resolve("tests/mcp_tests/test_pwa_api_route.py", lambda ours, theirs: theirs)
resolve("tests/mcp_tests/test_pwa_static_route.py", lambda ours, theirs: theirs)
for rel in ("tests/gui_jobs_timemachine/artifacts/personal/latest/RUN_FOLDER.txt",
            "tests/gui_jobs_timemachine/artifacts/personal/latest/SUMMARY.txt"):
    git("rm", "--cached", "-q", "--", rel)
    print(f"untracked (kept on disk): {rel}")

left = git("diff", "--name-only", "--diff-filter=U").strip()
print("\nunresolved:", left or "none")
api = (REPO / "tests/mcp_tests/test_pwa_api_route.py").read_text(encoding="utf-8")
print("test_pwa_api_route defines _fresh_loop_run:", "def _fresh_loop_run" in api)
