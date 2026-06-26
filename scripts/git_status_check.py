"""
git_status_check.py  —  Show git status for all AI-Prowler repos
"""
import subprocess
import sys
from pathlib import Path

REPOS = [
    ("AI-Prowler (main)",        Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")),
    ("AI-Prowler-ADMIN-V8/subs", Path(r"C:\Users\david\AI-Prowler-ADMIN-V8\ai-prowler-subs")),
    ("ai-prowler-subscription",  Path(r"C:\Users\david\AI-Prowler-ADMIN-V8\ai-prowler-subscription")),
]

SEP = "=" * 60

def run(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, shell=True)
    return r.stdout.strip(), r.stderr.strip()

for name, path in REPOS:
    print(f"\n{SEP}")
    print(f"  {name}")
    print(f"  {path}")
    print(SEP)

    if not path.exists():
        print("  ❌ Directory not found")
        continue

    # Branch
    branch, _ = run("git branch --show-current", path)
    print(f"  Branch  : {branch or '(detached)'}")

    # Remote
    remote, _ = run("git remote -v", path)
    if remote:
        # just show first fetch line
        first = [l for l in remote.splitlines() if "(fetch)" in l]
        print(f"  Remote  : {first[0] if first else remote.splitlines()[0]}")
    else:
        print("  Remote  : ⚠️  none configured")

    # Last commit
    log, _ = run('git log -1 --format="%h %s (%ci)"', path)
    print(f"  Last    : {log}")

    # Status
    status, _ = run("git status --short", path)
    if status:
        print(f"\n  Uncommitted changes:")
        for line in status.splitlines():
            print(f"    {line}")
    else:
        print(f"  Status  : ✅ clean")

    # Ahead/behind
    ahead_behind, _ = run('git rev-list --left-right --count HEAD...@{upstream}', path)
    if ahead_behind and "no upstream" not in ahead_behind.lower():
        parts = ahead_behind.split()
        if len(parts) == 2:
            ahead, behind = parts
            print(f"  Ahead   : {ahead} commit(s)  |  Behind: {behind} commit(s)")
    elif "fatal" not in ahead_behind.lower():
        print(f"  Upstream: ⚠️  no upstream set")

print(f"\n{SEP}")
print("  Done")
print(SEP)
