"""Step 1 (local only, nothing is pushed): put the Estimator work on its own branch and merge David's latest main.

1. Remove today's one-off helper scripts; copy the Estimator Plan and Design Spec into docs/estimator/.
2. Create branch `estimator` from the current commit (local changes come along).
3. Commit the Estimator files and the ai_prowler_mcp.py hook on that branch.
4. Merge origin/main (v9.7.1) into the branch. If ai_prowler_mcp.py conflicts, take David's version and add the
   Estimator hook back in the same place.
5. Move local main up to origin/main (fast-forward only; main has no local commits).
Stops at the first problem and says what happened. main on GitHub and the tags are never touched.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT.parent
ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0")
HOOK = '''# Estimator tools (AI-Prowler Estimator, Sprint 2). Registered after the
# mcp.tool monkeypatch above so they are counted and audited like every tool.
try:
    from estimator.mcp_tools.est_tools import register as _register_estimator
    _log.info("Estimator tools registered: %s", _register_estimator(mcp))
except Exception as _exc:  # the Estimator must never stop AI-Prowler starting
    _log.warning("Estimator tools not loaded: %s", _exc)

'''
ANCHOR = "# Module-level event set by the background prewarm thread"
TRAILER = ("\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n"
           "Claude-Session: https://claude.ai/code/session_01MEHLPC43kzQCxk4FPVtKa7\n")


def git(*args, check=True):
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=ENV)
    out = (r.stdout + r.stderr).strip()
    print(f"$ git {' '.join(args)}  (rc={r.returncode})")
    if out:
        print("  " + "\n  ".join(out.splitlines()[:25]))
    if check and r.returncode != 0:
        raise SystemExit(f"STOPPED at: git {' '.join(args)}")
    return r


def readd_hook():
    f = ROOT / "ai_prowler_mcp.py"
    text = f.read_text(encoding="utf-8")
    if "_register_estimator" in text:
        return
    if ANCHOR not in text:
        raise SystemExit("STOPPED: couldn't find where the Estimator hook goes in David's ai_prowler_mcp.py")
    f.write_text(text.replace(ANCHOR, HOOK + ANCHOR, 1), encoding="utf-8")
    print("Estimator hook added back into David's ai_prowler_mcp.py")


# 1. tidy and docs
for name in ("pdf_probe.py", "git_status_check.py", "git_preflight.py"):
    p = ROOT / "tests" / "estimator" / name
    if p.exists():
        p.unlink()
        print("removed", p.name)
docs = ROOT / "docs" / "estimator"
docs.mkdir(parents=True, exist_ok=True)
for name in ("AI-Prowler Estimator Design Spec.md", "AI-Prowler Estimator Implementation Plan.md"):
    shutil.copy2(WORK / name, docs / name)
    print("copied", name, "-> docs/estimator/")

# 2-3. branch and commit
if git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip() != "estimator":
    git("switch", "-c", "estimator")
git("add", "estimator", "tests/estimator", "install_estimator.bat", "install_estimator.py", "docs/estimator",
    "ai_prowler_mcp.py")
staged = git("diff", "--cached", "--name-only").stdout.split()
print(f"{len(staged)} files staged")
if staged:
    git("commit", "-m", "Estimator: Coder 1 Sprints 1-15 (Director, 23 modules, Runner, API-key agents)\n\n"
        "Adds the AI-Prowler Estimator package (estimator/), its tests (tests/estimator/, 563 passing), the\n"
        "installer (install_estimator.bat/.py), the Estimator tool hook in ai_prowler_mcp.py, and the design\n"
        "spec and implementation plan (docs/estimator/)." + TRAILER)

# 4. merge David's latest main
git("fetch", "--tags", "origin")
r = git("merge", "--no-ff", "origin/main", "-m", "Merge origin/main (v9.7.1) into estimator" + TRAILER, check=False)
if r.returncode != 0:
    conflicts = git("diff", "--name-only", "--diff-filter=U", check=False).stdout.split()
    print("conflicts:", conflicts)
    if conflicts != ["ai_prowler_mcp.py"]:
        git("merge", "--abort", check=False)
        raise SystemExit("STOPPED: merge conflicts outside ai_prowler_mcp.py; merge undone, nothing changed")
    git("checkout", "--theirs", "ai_prowler_mcp.py")
    readd_hook()
    git("add", "ai_prowler_mcp.py")
    git("commit", "--no-edit")
readd_hook()
if git("status", "--porcelain", "ai_prowler_mcp.py").stdout.strip():
    git("add", "ai_prowler_mcp.py")
    git("commit", "-m", "Keep the Estimator hook in ai_prowler_mcp.py" + TRAILER)

# 5. local main follows GitHub's main (fast-forward only)
git("fetch", "origin", "main:main")
git("log", "--oneline", "--graph", "-6")
git("status", "--short", "--branch")
print("\nLOCAL STEP DONE. Nothing pushed yet.")
