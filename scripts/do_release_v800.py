"""
do_release_v800.py  —  Commit remaining changes and tag v8.0.0 on main repo
============================================================================
What this does:
  1. Main repo — stage specific files, commit, tag v8.0.0, push
  2. Print instructions for subscription repo (already committed, just needs push)
"""
import subprocess, sys
from pathlib import Path

MAIN_REPO = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")
SEP = "=" * 60

def run(cmd, cwd, check=False):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, shell=True)
    out = (r.stdout + r.stderr).strip()
    ok = r.returncode == 0
    return ok, out

def step(label, cmd, cwd, fatal=True):
    print(f"\n  >> {label}")
    print(f"     {cmd}")
    ok, out = run(cmd, cwd)
    if out:
        for line in out.splitlines():
            print(f"     {line}")
    if not ok and fatal:
        print(f"\n  ❌ FAILED (rc={subprocess.run(cmd, cwd=cwd, shell=True).returncode})")
        sys.exit(1)
    status = "✅" if ok else "⚠️ "
    print(f"     {status}")
    return ok

print(SEP)
print("  AI-Prowler v8.0.0 — Git commit & tag")
print(SEP)

# ── Files to stage in main repo ──────────────────────────────────────────────
# Deliberately selective — exclude check_and_fix_dirs.py (one-off diagnostic)
# Include the new scripts, updated ISS, updated release_gate.bat, installer exe
FILES_TO_ADD = [
    "AI-Prowler-Setup.iss",
    "release_gate.bat",
    "Output/AI-Prowler_INSTALL.exe",
    "scripts/fix_v800_paths.py",
    "scripts/git_status_check.py",
    "scripts/do_release_v800.py",
]

print(f"\n── Main repo: {MAIN_REPO}")

# Stage selected files
for f in FILES_TO_ADD:
    step(f"git add {f}", f'git add "{f}"', MAIN_REPO, fatal=False)

# Show what's staged
print(f"\n  >> Staged files:")
ok, out = run("git diff --cached --name-status", MAIN_REPO)
for line in out.splitlines():
    print(f"     {line}")

# Commit
step(
    "git commit",
    'git commit -m "v8.0.0 release: ISS fixes, path cleanup scripts, updated release gate"',
    MAIN_REPO,
    fatal=False  # may be nothing new if already committed
)

# Tag — delete existing local tag if present, then recreate
print(f"\n  >> Checking for existing v8.0.0 tag ...")
ok, out = run("git tag -l v8.0.0", MAIN_REPO)
if "v8.0.0" in out:
    print(f"     Tag v8.0.0 already exists locally — deleting and recreating")
    run("git tag -d v8.0.0", MAIN_REPO)
    run("git push origin :refs/tags/v8.0.0", MAIN_REPO)

step(
    "git tag v8.0.0",
    'git tag -a v8.0.0 -m "AI-Prowler v8.0.0 — Proactive Alerts, Job Images, Common Business AI Analysis, SMS/WhatsApp, Bilingual OCR"',
    MAIN_REPO
)

# Push commits
step("git push origin main", "git push origin main", MAIN_REPO)

# Push tag
step("git push origin v8.0.0", "git push origin v8.0.0", MAIN_REPO)

# ── Final status ─────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  ✅ Main repo committed, tagged v8.0.0, and pushed")
print(SEP)

print("""
── Next manual steps ───────────────────────────────────────────────

  1. CREATE GITHUB RELEASE (manual):
     → https://github.com/dvavro/AI-Prowler/releases/new
     → Tag: v8.0.0
     → Title: AI-Prowler v8.0.0
     → Attach: Output/AI-Prowler_INSTALL.exe
     → Paste release notes (see scripts/RELEASE_NOTES_v6.0.2.md for format)

  2. ai-prowler-subscription repo — needs GitHub repo created then push:
     cd C:\\Users\\david\\AI-Prowler-ADMIN-V8\\ai-prowler-subscription
     git remote set-url origin https://github.com/dvavro/ai-prowler-subscription.git
     git push -u origin main

  3. ai-prowler-subs — already clean ✅ nothing to do

  4. Compile the installer (if not already done):
     → Open AI-Prowler-Setup.iss in Inno Setup Compiler
     → Build → Compile
     → Output: Output/AI-Prowler_INSTALL.exe

  5. Update AI-Prowler Index Documents tab:
     → Add C:\\Users\\david\\Documents\\AI-Prowler
     → Click Update All
""")
