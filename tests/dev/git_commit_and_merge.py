"""Dev helper (2026-10-11, David: merge GitHub main into the local work copy).

  1. new LOCAL branch david-work-2026-10-11 from the current commit (main stays put)
  2. commit the uncommitted work there — tracked changes + new source files; NOT
     generated test output (*/artifacts/*), tmp_r056proto/, the backup/*.db job
     database copy, or the cleanup scratch files
  3. git merge origin/main (Jamie's 12 commits) — conflicts are left for review
Nothing is pushed. ASCII output."""
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BRANCH = "david-work-2026-10-11"
SKIP_PREFIX = ("backup/", "tmp_r056proto/")
SKIP_FILES = {"cleanup_out.txt", "cleanup_tmp.py", "wrap_cleanup.py"}


def git(*a, ok=(0,)):
    r = subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = (r.stdout + r.stderr).strip()
    if r.returncode not in ok:
        print(f"!! git {' '.join(a)} -> {r.returncode}\n{out}".encode("ascii", "backslashreplace").decode("ascii"))
        sys.exit(1)
    return r.returncode, out


def p(s):
    print(str(s).encode("ascii", "backslashreplace").decode("ascii"))


if git("branch", "--show-current")[1] != "main":
    p("not on main — stopping")
    sys.exit(1)
if git("rev-parse", "--verify", "--quiet", BRANCH, ok=(0, 1))[0] == 0:
    p(f"branch {BRANCH} already exists — stopping")
    sys.exit(1)

git("switch", "-c", BRANCH)
p(f"created branch {BRANCH}")
git("add", "-u")                                        # tracked edits + deletions
_, untracked = git("ls-files", "--others", "--exclude-standard")
add = [f for f in untracked.splitlines()
       if f and "/artifacts/" not in "/" + f and not f.startswith(SKIP_PREFIX) and f not in SKIP_FILES]
for i in range(0, len(add), 50):
    git("add", "--", *add[i:i + 50])
_, staged = git("diff", "--cached", "--name-only")
p(f"staged {len(staged.splitlines())} file(s) ({len(add)} new)")
git("commit", "-q", "-m",
    "David's work 2026-10-03..10-11 (pre-merge snapshot)\n\n"
    "Jobs app Reports (R-084/R-085), access-only folders personal-only + Remote PWA\n"
    "section + add rules, R-086..R-089, Remote PWA learning edit + get_learning,\n"
    "new E2E/unit tests. Generated test output, the backup/*.db job database copy\n"
    "and scratch files are deliberately not committed.")
p("committed: " + git("log", "-1", "--format=%h %s")[1])

code, out = git("merge", "--no-ff", "--no-edit", "origin/main", ok=(0, 1))
p(f"\nmerge exit code {code}")
for line in out.splitlines()[-40:]:
    p("  " + line)
_, conflicts = git("diff", "--name-only", "--diff-filter=U")
p(f"\nCONFLICTED files ({len(conflicts.splitlines())}):")
for f in conflicts.splitlines():
    p("  " + f)
