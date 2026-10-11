"""Dev helper (2026-10-11): read-only survey before merging GitHub into the work
copy. Runs `git fetch` (downloads only — changes no files) and reports branch,
remote, uncommitted changes, ahead/behind, and what each side changed since
they split. ASCII output."""
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def git(*args, check=False):
    r = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = (r.stdout + (("\n" + r.stderr) if r.returncode else "")).strip()
    return out


def show(title, text, limit=60):
    print(f"\n== {title}")
    lines = text.splitlines()
    for l in lines[:limit]:
        print("  " + l.encode("ascii", "backslashreplace").decode("ascii"))
    if len(lines) > limit:
        print(f"  ... ({len(lines) - limit} more)")


show("git version", git("--version"))
show("remotes", git("remote", "-v"))
show("current branch", git("branch", "--show-current"))
show("HEAD", git("log", "-1", "--format=%h %ad %an  %s", "--date=iso"))
show("fetch origin", git("fetch", "origin", "--prune") or "(ok)")
show("remote branches", git("branch", "-r"))
default = git("symbolic-ref", "refs/remotes/origin/HEAD").replace("refs/remotes/", "") or "origin/main"
show("origin default branch", default)
show("origin tip", git("log", "-1", default, "--format=%h %ad %an  %s", "--date=iso"))
base = git("merge-base", "HEAD", default)
show("merge-base", git("log", "-1", base, "--format=%h %ad %an  %s", "--date=iso"))
show("ahead/behind (HEAD...origin)", git("rev-list", "--left-right", "--count", f"HEAD...{default}"))
st = git("status", "--porcelain")
show(f"uncommitted changes ({len(st.splitlines())} paths)", st, 40)
show("their commits since the split", git("log", "--format=%h %ad %an  %s", "--date=short", f"{base}..{default}"), 40)
show("our commits since the split", git("log", "--format=%h %ad %an  %s", "--date=short", f"{base}..HEAD"), 20)
theirs = git("diff", "--name-status", base, default)
show(f"files THEY changed ({len(theirs.splitlines())})", theirs, 80)
ours_committed = set(git("diff", "--name-only", base, "HEAD").splitlines())
ours_wt = set(git("diff", "--name-only", base).splitlines()) | {l[3:] for l in st.splitlines() if l.startswith("??")}
ours = ours_committed | ours_wt
both = sorted(set(l.split("\t")[-1] for l in theirs.splitlines()) & ours)
show(f"files changed on BOTH sides ({len(both)}) — possible conflicts", "\n".join(both), 80)
