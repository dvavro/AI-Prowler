"""Pre-commit cleanup of the work copy. DRY RUN by default; --apply MOVES files
(never deletes) into ..\_cleanup_<date>\ beside the repo, keeping relative paths,
so anything can be put back. Only UNTRACKED files are ever candidates."""
import datetime, re, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APPLY = "--apply" in sys.argv
DEST = ROOT.parent / f"_cleanup_{datetime.date.today():%Y-%m-%d}"

def git(*a):
    return subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout

untracked = [l for l in git("ls-files", "--others", "--exclude-standard").splitlines() if l]
untracked += [l for l in git("ls-files", "--others", "--ignored", "--exclude-standard").splitlines() if l]
untracked = sorted(set(untracked))
tracked = set(git("ls-files").splitlines())

BAK = re.compile(r"\.bak\d+$", re.I)
# one-off scratch scripts at repo root / tmp dirs (verified below: untracked + unreferenced)
SCRATCH_NAMES = {"cleanup_tmp.py", "clear_att.py", "clr.py", "fhr.py", "find_attendance.py",
                 "wrap_cleanup.py", "cleanup_out.txt", "tests/dev/check_install_coverage.py"}
SCRATCH_DIRS = ("tmp_r056proto/", "tests/dev/_tmp_")
NEVER = ("tests/dev/git_commit_work.py", ".git/")

def referenced(name):
    """Tracked files that mention this file's name (excluding itself)."""
    stem = Path(name).name
    out = git("grep", "-l", "-F", stem, "--", ".")
    # References from tests/dev helpers are their "skip this scratch file" lists,
    # not real uses, so they don't count. Generic names like chroma.sqlite3 are
    # checked by their folder instead (tmp_r056proto is excluded by the commit tooling).
    if name.startswith(SCRATCH_DIRS):
        stem = name.split("/")[0]
    return [f for f in out.splitlines()
            if f and f != name and not f.startswith("tests/dev/")] if not name.startswith(SCRATCH_DIRS) else \
           [f for f in git("grep", "-l", "-F", stem, "--", ".").splitlines()
            if f and not f.startswith("tests/dev/")]

bak, scratch, held = [], [], []
for rel in untracked:
    r = rel.replace("\\", "/")
    if r.startswith(NEVER) or "/.git/" in r or "node_modules/" in r or "__pycache__" in r:
        continue
    if r in tracked:
        continue
    if BAK.search(r):
        orig = BAK.sub("", r)
        bak.append((r, "original present" if (ROOT / orig).exists() else "ORIGINAL MISSING"))
    elif r.startswith("tests/dev/_tmp_"):
        scratch.append((r, []))          # _tmp_ prefix = one-off by convention
    elif r in SCRATCH_NAMES or r.startswith(SCRATCH_DIRS):
        refs = referenced(r)
        (held if refs else scratch).append((r, refs))

print(f"ROOT {ROOT}\nmode: {'APPLY (move to ' + str(DEST) + ')' if APPLY else 'DRY RUN'}\n")
print(f"== .bakN backups (untracked): {len(bak)} ==")
for r, note in bak:
    print(f"   {r}   [{note}]")
print(f"\n== one-off scratch files (untracked, not referenced by any tracked file): {len(scratch)} ==")
for r, _ in scratch:
    print("  ", r)
print(f"\n== HELD BACK (referenced by tracked files — not touched): {len(held)} ==")
for r, refs in held:
    print("  ", r, "<-", ", ".join(refs[:5]))

if APPLY:
    moved = 0
    # --bak-only (2026-10-19): move just the .bakN backups, leave scratch files
    _scratch = [] if "--bak-only" in sys.argv else [s[0] for s in scratch]
    for r in [b[0] for b in bak if b[1] == "original present"] + _scratch:
        src = ROOT / r
        dst = DEST / r
        n = 2
        while dst.exists():              # never overwrite an earlier cleanup's file
            dst = DEST / f"{r}.run{n}"
            n += 1
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        moved += 1
    # remove now-empty scratch dirs
    for d in SCRATCH_DIRS:
        p = ROOT / d
        if p.is_dir() and not any(p.rglob("*")):
            p.rmdir()
    print(f"\nMoved {moved} file(s) to {DEST}")
    print("git status after:")
    print(git("status", "--short") or "  (clean)")
