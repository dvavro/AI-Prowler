#!/usr/bin/env python3
"""
AI-Prowler release helper.

Bumps the version, runs tests, compiles the Inno Setup installer, and prints
the manual checklist (git tag, GitHub release, subscription push, emails) that
follows. Designed to be RUN FROM ITS OWN LOCATION inside the work-folder repo
that should be released.

Layout assumption (Option B — file-location is the truth):

    <work_folder>/AI-Prowler/
    ├── release.bat                # thin wrapper (in repo root)
    ├── VERSION                    # single source of truth (e.g. "6.0.2")
    ├── rag_gui.py                 # reads VERSION at import
    ├── AI-Prowler-Setup.iss       # reads VERSION via #define
    ├── COMPLETE_USER_GUIDE.md     # bumper updates the **Version X.Y.Z** line
    ├── tests/                     # pytest tree
    ├── Output/                    # Inno Setup writes AI-Prowler_INSTALL.exe here
    └── scripts/
        └── release.py             # this file

The script is intentionally *not* a one-button "do everything". It bumps,
tests, compiles. Tagging / pushing / GitHub release / notification push stay
human-gated. See the checklist printed at the end.

Usage:
    py scripts\\release.py 6.0.2
    py scripts\\release.py 6.0.2 --skip-tests          # rare; only for hotfix iterations
    py scripts\\release.py 6.0.2 --skip-compile        # bump only, don't build installer
    py scripts\\release.py 6.0.2 --refactor-only       # one-shot: introduce VERSION-as-truth
    py scripts\\release.py --check                     # validate repo state without bumping

Exit codes:
    0  success
    1  user aborted
    2  validation failure (bad version, dirty git, etc.)
    3  tests failed
    4  Inno Setup compile failed
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Locate the repo ──────────────────────────────────────────────────────────
# Option B: this file's parent's parent IS the repo root. No CWD guessing.
SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parent.parent

VERSION_FILE = REPO_ROOT / "VERSION"
RAG_GUI = REPO_ROOT / "rag_gui.py"
SETUP_ISS = REPO_ROOT / "AI-Prowler-Setup.iss"
USER_GUIDE = REPO_ROOT / "COMPLETE_USER_GUIDE.md"
TESTS_DIR = REPO_ROOT / "tests"
ISS_OUTPUT_DIR = REPO_ROOT / "Output"
INSTALLER_NAME = "AI-Prowler_INSTALL.exe"
RELEASE_DRAFTS = REPO_ROOT / "release-drafts"
LOCAL_CONFIG = REPO_ROOT / ".release-config.json"  # gitignored, admin-repo paths

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
APP_VERSION_LINE_RE = re.compile(r'^APP_VERSION\s*=\s*"(\d+\.\d+\.\d+)"', re.M)
ISS_APPVERSION_RE = re.compile(r"^AppVersion=(\d+\.\d+\.\d+)", re.M)
GUIDE_VERSION_RE = re.compile(r"^\*\*Version\s+(\d+\.\d+\.\d+)\*\*", re.M)

# Inno Setup compiler — standard locations. Override via env ISCC_EXE.
ISCC_CANDIDATES = [
    os.environ.get("ISCC_EXE", ""),
    r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    r"C:\Program Files\Inno Setup 6\ISCC.exe",
]


# ── Tiny console helpers ─────────────────────────────────────────────────────
def info(msg: str) -> None:
    print(f"  {msg}")


def step(msg: str) -> None:
    print(f"\n── {msg} " + "─" * max(0, 70 - len(msg)))


def ok(msg: str) -> None:
    print(f"  ✅ {msg}")


def warn(msg: str) -> None:
    print(f"  ⚠️  {msg}")


def err(msg: str) -> None:
    print(f"  ❌ {msg}", file=sys.stderr)


def fatal(msg: str, code: int = 2) -> None:
    err(msg)
    sys.exit(code)


def confirm(prompt: str, default_yes: bool = False) -> bool:
    suffix = " [Y/n]: " if default_yes else " [y/N]: "
    ans = input(prompt + suffix).strip().lower()
    if not ans:
        return default_yes
    return ans in ("y", "yes")


# ── Repo verification (Option B safety check) ────────────────────────────────
def verify_repo() -> None:
    step("Verifying repo location")
    info(f"Computed repo root: {REPO_ROOT}")
    problems = []
    if not (REPO_ROOT / ".git").exists():
        problems.append("No .git folder — this doesn't look like a git repo.")
    if not RAG_GUI.exists():
        problems.append(f"rag_gui.py not found at {RAG_GUI}")
    if not SETUP_ISS.exists():
        problems.append(f"AI-Prowler-Setup.iss not found at {SETUP_ISS}")
    if problems:
        for p in problems:
            err(p)
        fatal(
            "Repo verification failed. release.py expects to live at "
            "<repo>/scripts/release.py."
        )
    ok("Repo looks like AI-Prowler.")


def confirm_repo_choice() -> None:
    print()
    print(f"  About to operate on repo: {REPO_ROOT}")
    if not confirm("  Proceed?", default_yes=False):
        info("Aborted by user.")
        sys.exit(1)


# ── Version reading / writing ────────────────────────────────────────────────
def read_current_version() -> str:
    """Return the current version. Prefer VERSION file; fall back to rag_gui.py."""
    if VERSION_FILE.exists():
        v = VERSION_FILE.read_text(encoding="utf-8").strip()
        if VERSION_RE.match(v):
            return v
        fatal(f"VERSION file contains invalid value: {v!r}")
    # Pre-refactor fallback
    text = RAG_GUI.read_text(encoding="utf-8")
    m = APP_VERSION_LINE_RE.search(text)
    if not m:
        fatal(
            "Could not find APP_VERSION in rag_gui.py and no VERSION file exists. "
            "Run with --refactor-only first."
        )
    return m.group(1)


def parse_version(v: str) -> tuple[int, int, int]:
    if not VERSION_RE.match(v):
        fatal(f"Version must be X.Y.Z (e.g. 6.0.2). Got: {v!r}")
    return tuple(int(x) for x in v.split("."))  # type: ignore[return-value]


def is_newer(new: str, old: str) -> bool:
    return parse_version(new) > parse_version(old)


# ── Git checks ───────────────────────────────────────────────────────────────
def run(cmd: list[str], cwd: Path = REPO_ROOT, check: bool = True,
        capture: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess and surface its output clearly."""
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        check=check,
        text=True,
        capture_output=capture,
    )


def git_status_clean() -> bool:
    r = run(["git", "status", "--porcelain"], check=False)
    return r.returncode == 0 and r.stdout.strip() == ""


def git_current_branch() -> str:
    r = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], check=False)
    return r.stdout.strip() if r.returncode == 0 else "?"


def git_tag_exists(tag: str) -> bool:
    r = run(["git", "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"],
            check=False)
    return r.returncode == 0


def git_preflight(new_version: str, auto_yes: bool = False) -> None:
    step("Git pre-flight")
    branch = git_current_branch()
    info(f"Branch: {branch}")
    release_branches = {"main", "master"}
    if branch not in release_branches:
        warn(f"You're not on a release branch (currently {branch}; expected main or master).")
        if not auto_yes and not confirm("  Continue anyway?", default_yes=False):
            sys.exit(1)
    if not git_status_clean():
        warn("Working tree has uncommitted changes:")
        r = run(["git", "status", "--short"], check=False)
        print(r.stdout)
        if not auto_yes and not confirm(
            "  Continue anyway? (script will add its own changes on top)",
            default_yes=False,
        ):
            sys.exit(1)
    else:
        ok("Working tree is clean.")
    if git_tag_exists(f"v{new_version}"):
        fatal(
            f"Tag v{new_version} already exists. Delete it first if you really want "
            f"to re-release: git tag -d v{new_version} && "
            f"git push origin --delete v{new_version}"
        )
    ok(f"Tag v{new_version} does not yet exist — good.")


# ── Refactor: introduce VERSION as the single source of truth ────────────────
def refactor_to_version_file(current_version: str) -> list[tuple[Path, str]]:
    """
    Return a list of (path, new_content) tuples that, when written, will
    make VERSION the single source of truth.

    Idempotent — safe to run even if the refactor has been applied before.
    """
    changes: list[tuple[Path, str]] = []

    # 1) VERSION file
    if not VERSION_FILE.exists():
        changes.append((VERSION_FILE, current_version + "\n"))

    # 2) rag_gui.py — replace hardcoded APP_VERSION = "x.y.z" with a reader
    gui_text = RAG_GUI.read_text(encoding="utf-8")
    if APP_VERSION_LINE_RE.search(gui_text):
        # Replace the constant line with a reader that loads VERSION at import.
        new_block = (
            'APP_VERSION = (Path(__file__).parent / "VERSION").read_text('
            'encoding="utf-8").strip()'
        )
        # Make sure Path is imported. rag_gui.py is huge; just check.
        if "from pathlib import Path" not in gui_text:
            warn(
                "rag_gui.py does not import pathlib.Path at the top. "
                "Add `from pathlib import Path` manually before the refactor, "
                "or accept the bumper-only path below."
            )
            if not confirm("  Skip refactor of rag_gui.py?", default_yes=True):
                sys.exit(1)
        else:
            gui_new = APP_VERSION_LINE_RE.sub(new_block, gui_text, count=1)
            if gui_new != gui_text:
                changes.append((RAG_GUI, gui_new))

    # 3) AI-Prowler-Setup.iss — use a #define that reads VERSION via ReadIni
    #    Inno Setup preprocessor: #define MyAppVersion ReadIni(...) is awkward
    #    for a plain text file; the simplest reliable pattern is:
    #       #define MyAppVersion = Trim(ReadFileLine(SourcePath + "VERSION", 0))
    #    and then AppVersion={#MyAppVersion}
    iss_text = SETUP_ISS.read_text(encoding="utf-8")
    if "{#MyAppVersion}" not in iss_text:
        # Insert preprocessor #define near the top, BEFORE [Setup]
        define_block = (
            '#define MyAppVersion Trim(ReadFileLine(SourcePath + "VERSION", 0))\n'
        )
        # Place it just before [Setup]
        if "[Setup]" not in iss_text:
            warn("No [Setup] block found in .iss — skipping refactor for .iss.")
        else:
            iss_new = iss_text.replace(
                "[Setup]",
                f"; ── Version is read from VERSION file (single source of truth) ──\n"
                f"{define_block}\n[Setup]",
                1,
            )
            # Replace AppVersion=x.y.z with AppVersion={#MyAppVersion}
            iss_new = ISS_APPVERSION_RE.sub(
                "AppVersion={#MyAppVersion}", iss_new, count=1
            )
            if iss_new != iss_text:
                changes.append((SETUP_ISS, iss_new))

    return changes


# ── Bumper: when refactor is already in place, only VERSION + user guide ────
def bump_changes(new_version: str) -> list[tuple[Path, str]]:
    changes: list[tuple[Path, str]] = []

    # VERSION file is authoritative
    changes.append((VERSION_FILE, new_version + "\n"))

    # COMPLETE_USER_GUIDE.md: replace **Version X.Y.Z** banner if present
    if USER_GUIDE.exists():
        text = USER_GUIDE.read_text(encoding="utf-8")
        new_text, n = GUIDE_VERSION_RE.subn(f"**Version {new_version}**", text, count=1)
        if n == 0:
            warn(
                f"COMPLETE_USER_GUIDE.md has no `**Version X.Y.Z**` banner to "
                f"update. Please add or update it manually."
            )
        elif new_text != text:
            changes.append((USER_GUIDE, new_text))
    else:
        warn("COMPLETE_USER_GUIDE.md not found — skipping.")

    # If rag_gui.py still has a hardcoded APP_VERSION (refactor not done yet),
    # bump that line too so this script works pre-refactor as well.
    gui_text = RAG_GUI.read_text(encoding="utf-8")
    if APP_VERSION_LINE_RE.search(gui_text):
        gui_new, _ = APP_VERSION_LINE_RE.subn(
            f'APP_VERSION = "{new_version}"', gui_text, count=1
        )
        if gui_new != gui_text:
            changes.append((RAG_GUI, gui_new))

    # Same for .iss if it still has a hardcoded AppVersion
    iss_text = SETUP_ISS.read_text(encoding="utf-8")
    if ISS_APPVERSION_RE.search(iss_text):
        iss_new, _ = ISS_APPVERSION_RE.subn(
            f"AppVersion={new_version}", iss_text, count=1
        )
        if iss_new != iss_text:
            changes.append((SETUP_ISS, iss_new))

    return changes


# ── Diff preview ─────────────────────────────────────────────────────────────
def show_diff_preview(changes: list[tuple[Path, str]]) -> None:
    step("Preview of changes")
    if not changes:
        info("(no changes to apply)")
        return
    import difflib
    for path, new_content in changes:
        old = path.read_text(encoding="utf-8") if path.exists() else ""
        diff = list(
            difflib.unified_diff(
                old.splitlines(keepends=False),
                new_content.splitlines(keepends=False),
                fromfile=f"a/{path.relative_to(REPO_ROOT)}",
                tofile=f"b/{path.relative_to(REPO_ROOT)}",
                lineterm="",
                n=2,
            )
        )
        print()
        if not diff:
            info(f"{path.relative_to(REPO_ROOT)}: (no textual diff — new file?)")
            print(new_content[:400] + ("..." if len(new_content) > 400 else ""))
            continue
        for line in diff[:80]:  # cap per-file for screen sanity
            print("  " + line)
        if len(diff) > 80:
            info(f"... ({len(diff) - 80} more diff lines suppressed)")


def apply_changes(changes: list[tuple[Path, str]]) -> None:
    step("Writing changes")
    for path, new_content in changes:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_content, encoding="utf-8")
        ok(f"wrote {path.relative_to(REPO_ROOT)}")


# ── Tests ────────────────────────────────────────────────────────────────────
def run_tests() -> None:
    step("Running tests (py -m pytest tests)")
    if not TESTS_DIR.exists():
        warn("No tests/ directory — skipping.")
        return
    # Stream output so the user sees progress live instead of a long silence
    proc = subprocess.Popen(
        [sys.executable, "-m", "pytest", str(TESTS_DIR)],
        cwd=str(REPO_ROOT),
    )
    rc = proc.wait()
    if rc != 0:
        err(f"Tests failed (exit {rc}). Aborting before any irreversible step.")
        sys.exit(3)
    ok("All tests passed.")


# ── Inno Setup compile ───────────────────────────────────────────────────────
def find_iscc() -> Optional[Path]:
    for candidate in ISCC_CANDIDATES:
        if candidate and Path(candidate).exists():
            return Path(candidate)
    # PATH fallback
    found = shutil.which("ISCC")
    return Path(found) if found else None


def compile_installer(new_version: str) -> Optional[Path]:
    step("Compiling Inno Setup installer")
    iscc = find_iscc()
    if iscc is None:
        warn(
            "ISCC.exe (Inno Setup Compiler) not found. Looked in:\n"
            "  - $ISCC_EXE env var\n"
            "  - C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe\n"
            "  - C:\\Program Files\\Inno Setup 6\\ISCC.exe\n"
            "  - PATH\n"
            "Install Inno Setup 6 from https://jrsoftware.org/isdl.php, "
            "or set ISCC_EXE to the full path. Skipping compile."
        )
        return None
    info(f"Using compiler: {iscc}")

    # Output dir is Inno's default {SourcePath}\Output unless overridden in .iss
    ISS_OUTPUT_DIR.mkdir(exist_ok=True)
    proc = subprocess.Popen(
        [str(iscc), str(SETUP_ISS)],
        cwd=str(REPO_ROOT),
    )
    rc = proc.wait()
    if rc != 0:
        err(f"Inno Setup compile failed (exit {rc}).")
        sys.exit(4)

    installer = ISS_OUTPUT_DIR / INSTALLER_NAME
    if not installer.exists():
        warn(
            f"Compile reported success but {INSTALLER_NAME} not found in "
            f"{ISS_OUTPUT_DIR}. Check OutputDir / OutputBaseFilename in .iss."
        )
        return None

    size_mb = installer.stat().st_size / (1024 * 1024)
    ok(f"Built {installer.relative_to(REPO_ROOT)} ({size_mb:.1f} MB)")
    return installer


# ── Update manifest (update_manifest.json) ──────────────────────────────────
# The auto-updater in rag_gui.py fetches this file from the release tag and
# downloads every file it lists. This is the single source of truth for "what
# files make up an install" — add a file here and the next auto-update ships
# it, with no code change to the updater. Each entry carries a SHA256 so the
# updater can (now or later) verify integrity after download.
#
# IMPORTANT: keep this list complete. A file that a running install needs but
# that is missing from the manifest will go stale on auto-updated clients
# (this is exactly the bug that motivated the manifest — the old hardcoded
# 5-file list never shipped the user guide).
MANIFEST_FILES = [
    "rag_gui.py",
    "rag_preprocessor.py",
    "ai_prowler_mcp.py",
    "mcp_diagnostics.py",
    "self_learning.py",
    "RAG_RUN.bat",
    "COMPLETE_USER_GUIDE.md",
    "VERSION",
]


def write_update_manifest(new_version: str) -> None:
    step("Writing update manifest")
    import hashlib

    entries = []
    missing = []
    for rel in MANIFEST_FILES:
        fp = REPO_ROOT / rel
        if not fp.exists():
            missing.append(rel)
            continue
        digest = hashlib.sha256(fp.read_bytes()).hexdigest()
        entries.append({
            "path": rel,
            "sha256": digest,
            "bytes": fp.stat().st_size,
        })

    if missing:
        for m in missing:
            warn(f"Manifest: listed file not found, skipping: {m}")
        warn("Auto-updated clients will NOT receive the skipped files. "
             "Fix MANIFEST_FILES or add the missing file before releasing.")

    manifest = {
        "version": new_version,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "files": entries,
    }
    out = REPO_ROOT / "update_manifest.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    ok(f"Wrote {out.relative_to(REPO_ROOT)} — {len(entries)} file(s).")
    info("This file MUST be committed and pushed with the release so the "
         "updater can fetch it at the tag URL.")


# ── Release drafts (welcome_ad.json / notifications.json) ───────────────────
def write_release_drafts(new_version: str) -> None:
    step("Writing release drafts")
    RELEASE_DRAFTS.mkdir(exist_ok=True)

    notif = {
        "version": "1.0",
        "notifications": [],
        "latest_version": new_version,
        "update_url": f"https://github.com/dvavro/AI-Prowler/releases/tag/v{new_version}",
        "update_notes": (
            f"AI-Prowler v{new_version} — see GitHub release notes for details. "
            f"EDIT THIS BEFORE PUSHING."
        ),
    }
    ad = {
        "version": "1.0",
        "headline": f"AI-Prowler v{new_version}",
        "bullets": [
            "EDIT ME — first new feature",
            "EDIT ME — second new feature",
        ],
        "cta_label": "Download the new version",
        "cta_url": f"https://github.com/dvavro/AI-Prowler/releases/tag/v{new_version}",
    }
    (RELEASE_DRAFTS / "notifications.json").write_text(
        json.dumps(notif, indent=2) + "\n", encoding="utf-8"
    )
    (RELEASE_DRAFTS / "welcome_ad.json").write_text(
        json.dumps(ad, indent=2) + "\n", encoding="utf-8"
    )
    ok(f"Drafts written to {RELEASE_DRAFTS.relative_to(REPO_ROOT)}/")
    info("Review and edit before copying into the admin repo's public/ folder.")


# ── Final manual checklist ──────────────────────────────────────────────────
def print_checklist(new_version: str, installer: Optional[Path]) -> None:
    tag = f"v{new_version}"
    step(f"REMAINING MANUAL STEPS for {tag}")
    print(f"""
  All automated steps are done. The following are intentionally manual:

  1. Review the release drafts:
       {RELEASE_DRAFTS.relative_to(REPO_ROOT)}/welcome_ad.json
       {RELEASE_DRAFTS.relative_to(REPO_ROOT)}/notifications.json
     Edit the feature descriptions, then copy into your admin repo's
     ai-prowler-public/ folder and commit+push that repo.

  2. Commit the version bump in this repo:
       git add .
       git commit -m "Release {tag}"
       git push origin main

  3. Tag and push the tag:
       git tag -a {tag} -m "Release {tag}"
       git push origin {tag}

  4. Create the GitHub release at:
       https://github.com/dvavro/AI-Prowler/releases/new?tag={tag}
     Title: AI-Prowler V{new_version}
     Body:  paste the changelog
     Asset: upload {installer if installer else f'Output/{INSTALLER_NAME}'}

  5. In Subscription Manager: push the v{new_version} notification.

  6. Send update emails to beta testers.
""")


# ── CLI ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="AI-Prowler release helper (bump + test + compile)."
    )
    p.add_argument("version", nargs="?", help="New version, e.g. 6.0.2")
    p.add_argument("--check", action="store_true",
                   help="Verify repo state and print current version, then exit.")
    p.add_argument("--refactor-only", action="store_true",
                   help="One-shot: introduce VERSION file and make rag_gui.py + .iss "
                        "read from it. Does not change the version number.")
    p.add_argument("--remanifest", action="store_true",
                   help="Re-cut path: regenerate update_manifest.json (and the "
                        "release drafts) for the CURRENT version without bumping. "
                        "Use when correcting an already-tagged release whose code "
                        "changed but whose version number stays the same.")
    p.add_argument("--skip-tests", action="store_true",
                   help="Skip pytest run (use only for hotfix iteration).")
    p.add_argument("--skip-compile", action="store_true",
                   help="Skip Inno Setup compile (bump only).")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Auto-confirm all prompts (CI mode — use with care).")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    print("AI-Prowler Release Helper")
    print(f"Script: {SCRIPT_PATH}")

    verify_repo()
    if not args.yes:
        confirm_repo_choice()

    current = read_current_version()
    info(f"Current version: {current}")

    if args.check:
        ok("Repo OK. Exiting (--check).")
        return

    if args.remanifest:
        # Re-cut path: the version is NOT changing. Regenerate the manifest
        # and drafts against whatever files are currently in the working tree,
        # so a corrected (but same-numbered) release ships accurate hashes.
        # Optionally run tests/compile via the usual flags.
        step(f"Re-manifest for current version {current} (no bump)")
        if not args.skip_tests:
            run_tests()
        else:
            warn("Skipping tests (--skip-tests).")
        write_update_manifest(current)
        write_release_drafts(current)
        if not args.skip_compile:
            compile_installer(current)
        else:
            warn("Skipping Inno Setup compile (--skip-compile).")
        ok(f"Re-manifest for {current} complete.")
        info("Next: commit the corrected files + update_manifest.json, then "
             "FORCE-MOVE the tag to the new commit:")
        info(f"    git add -A && git commit -m \"Correct v{current} — "
             f"auto-update fixes\"")
        info(f"    git tag -f v{current}")
        info(f"    git push origin main")
        info(f"    git push -f origin v{current}")
        info("Then edit the GitHub release and re-upload the corrected "
             "installer asset.")
        return

    if args.refactor_only:
        changes = refactor_to_version_file(current)
        if not changes:
            ok("Refactor already applied — nothing to do.")
            return
        show_diff_preview(changes)
        if not args.yes and not confirm("\n  Apply refactor?", default_yes=False):
            sys.exit(1)
        apply_changes(changes)
        ok("Refactor complete. Now run: py scripts/release.py <new-version>")
        return

    if not args.version:
        fatal("Provide a new version, e.g.: py scripts/release.py 6.0.2")

    new_version = args.version
    if not is_newer(new_version, current):
        fatal(f"New version {new_version} must be strictly greater than {current}.")

    git_preflight(new_version, auto_yes=args.yes)

    # If the refactor hasn't been done yet, do it as part of this release.
    refactor_changes = refactor_to_version_file(current)
    bumper_changes = bump_changes(new_version)
    # Merge — refactor changes to rag_gui.py / iss already remove the hardcoded
    # version, so bumper_changes for those files will be no-ops on those files
    # next run. For *this* run we keep both; the bumper writes VERSION to the
    # new value anyway.
    all_changes: dict[Path, str] = {}
    for path, content in refactor_changes + bumper_changes:
        all_changes[path] = content
    changes = list(all_changes.items())

    show_diff_preview(changes)
    if not args.yes and not confirm(
        f"\n  Apply {len(changes)} file change(s) to bump {current} → {new_version}?",
        default_yes=False,
    ):
        sys.exit(1)
    apply_changes(changes)

    # Generate the update manifest AFTER version files are bumped, so its
    # SHA256 hashes match exactly what will be committed and fetched at the
    # tag. Must run before tests/compile so it's part of the same working
    # tree the operator commits.
    write_update_manifest(new_version)

    if not args.skip_tests:
        run_tests()
    else:
        warn("Skipping tests (--skip-tests).")

    installer: Optional[Path] = None
    if not args.skip_compile:
        installer = compile_installer(new_version)
    else:
        warn("Skipping Inno Setup compile (--skip-compile).")

    write_release_drafts(new_version)
    print_checklist(new_version, installer)
    ok(f"Release {new_version} prepared.")


if __name__ == "__main__":
    main()
