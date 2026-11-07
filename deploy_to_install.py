"""Copy AI-Prowler's program files from this working folder to the installed AI-Prowler, to try code changes.

    deploy_to_install.bat               copy changed files (asks for admin, shows what it did)
    deploy_to_install.bat --dry-run     only list what would change
    deploy_to_install.bat --restore     put back what the last deploy replaced

What counts as a program file:
  - every file on the release list, update_manifest.json (the same list AI-Prowler's updater uses), and
  - the whole estimator\\ folder (not on the release list yet).
Nothing else is touched: your data (hr_db.json, employee\\, hr_task_tracking.json, settings in your user folder),
the installer and uninstaller, cloudflared.exe and the dev-only files stay as they are.

Safety:
  - Every .py file is compile-checked first; if any has a syntax error, nothing is copied.
  - Only files that are really different are copied (line endings don't count); each one is checked after copying.
    Text files are written with Unix line endings, the same as the release.
  - Every file it replaces is saved first to %LOCALAPPDATA%\\AI-Prowler\\deploy_backups\\<date-time>\\ (the last
    5 deploys are kept), so --restore can undo the last deploy.
  - Close AI-Prowler first (it warns you if it's running). Start it again afterwards to load the new code.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

SRC = Path(__file__).resolve().parent
DST = Path(os.environ.get("AI_PROWLER_INSTALL_DIR", r"C:\Program Files\AI-Prowler"))
BACKUPS = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "AI-Prowler" / "deploy_backups"
KEEP_BACKUPS = 5
EXTRA_FOLDERS = ("estimator",)                    # copied whole, in addition to the release list
SKIP_PARTS = {"__pycache__", ".git"}
SKIP_SUFFIX = (".pyc", ".pyo")
# Text files are compared and written with Unix line endings, like the release ships them: git on Windows checks
# files out with CRLF, and copying those would make every file look changed to AI-Prowler's updater.
TEXT_SUFFIX = {".py", ".md", ".json", ".yaml", ".yml", ".csv", ".txt", ".html", ".js", ".css", ".ini", ""}
BINARY_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".exe", ".dll", ".zip", ".docx", ".xlsx"}
# .bat and .ps1 keep their line endings when copied (Windows wants CRLF there), but line endings alone never make
# them count as changed.


def content(path: Path) -> bytes:
    """What gets written: text files with Unix line endings, everything else byte for byte."""
    data = path.read_bytes()
    return data.replace(b"\r\n", b"\n") if path.suffix.lower() in TEXT_SUFFIX else data


def same(src: Path, dst: Path) -> bool:
    a, b = src.read_bytes(), dst.read_bytes()
    if src.suffix.lower() in BINARY_SUFFIX:
        return a == b
    return a.replace(b"\r\n", b"\n") == b.replace(b"\r\n", b"\n")


def program_files() -> list[str]:
    """Relative paths (with /) of every program file to deploy."""
    manifest = SRC / "update_manifest.json"
    if not manifest.exists():
        raise SystemExit(f"Can't find {manifest}. Run this from the AI-Prowler working folder.")
    files = [f["path"] for f in json.loads(manifest.read_text(encoding="utf-8"))["files"]]
    for folder in EXTRA_FOLDERS:
        base = SRC / folder
        if base.is_dir():
            for p in base.rglob("*"):
                if p.is_file() and not (SKIP_PARTS & set(p.parts)) and not p.name.endswith(SKIP_SUFFIX) \
                        and ".bak" not in p.suffix:
                    files.append(p.relative_to(SRC).as_posix())
    files.append("update_manifest.json")
    return sorted(set(files))


def ai_prowler_running() -> list[str]:
    """Running AI-Prowler processes (rag_gui.py / ai_prowler_mcp.py), or [] if none or we can't tell."""
    if os.name != "nt":
        return []
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'rag_gui.py|ai_prowler_mcp.py' } "
          "| ForEach-Object { $_.ProcessId.ToString() + ' ' + $_.Name }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                             timeout=30).stdout
    except Exception:  # noqa: BLE001
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def compile_check(files: list[str]) -> list[str]:
    """Syntax-check every .py file in memory (nothing is written)."""
    bad = []
    for rel in files:
        path = SRC / rel
        if rel.endswith(".py") and path.exists():
            try:
                compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
            except (SyntaxError, ValueError) as exc:
                bad.append(f"{rel}: line {getattr(exc, 'lineno', '?')}: {getattr(exc, 'msg', exc)}")
    return bad


def plan(files: list[str]) -> tuple[list[str], list[str], list[str]]:
    """(new files, changed files, missing from the working folder)."""
    new, changed, missing = [], [], []
    for rel in files:
        src, dst = SRC / rel, DST / rel
        if not src.exists():
            missing.append(rel)
        elif not dst.exists():
            new.append(rel)
        elif not same(src, dst):
            changed.append(rel)
    return new, changed, missing


def prune_backups() -> None:
    if BACKUPS.is_dir():
        olds = sorted(p for p in BACKUPS.iterdir() if p.is_dir())
        for p in olds[:-KEEP_BACKUPS]:
            shutil.rmtree(p, ignore_errors=True)


def deploy(dry_run: bool) -> int:
    print(f"From:  {SRC}\nTo:    {DST}\n")
    if not DST.is_dir():
        print(f"The install folder {DST} doesn't exist. Install AI-Prowler first.")
        return 1
    files = program_files()
    bad = compile_check(files)
    if bad:
        print("These files have errors, so nothing was copied:\n  " + "\n  ".join(bad))
        return 1
    new, changed, missing = plan(files)
    if missing:
        print(f"On the release list but not in the working folder ({len(missing)}), left as installed:\n  "
              + "\n  ".join(missing) + "\n")
    if not new and not changed:
        print(f"Nothing to copy: all {len(files)} program files already match the install.")
        return 0
    for label, items in (("New", new), ("Changed", changed)):
        if items:
            print(f"{label} ({len(items)}):\n  " + "\n  ".join(items))
    if dry_run:
        print(f"\nDry run: {len(new) + len(changed)} files would be copied. Nothing was changed.")
        return 0
    running = ai_prowler_running()
    if running:
        print("\nAI-Prowler is running (" + ", ".join(running) + ").")
        answer = input("Close it now, then press Enter to go on (or type c to copy anyway, q to quit): ").strip().lower()
        if answer == "q":
            print("Stopped. Nothing was copied.")
            return 1
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    backup, n = BACKUPS / stamp, 1
    while backup.exists():                       # two deploys in the same second each keep their own backup
        n += 1
        backup = BACKUPS / f"{stamp}_{n}"
    backup.mkdir(parents=True)
    copied, failed = [], []
    for rel in changed:
        (backup / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(DST / rel, backup / rel)
    for rel in new + changed:
        src, dst = SRC / rel, DST / rel
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            data = content(src)
            dst.write_bytes(data)
            shutil.copystat(src, dst)
            if dst.read_bytes() != data:
                raise OSError("the copy doesn't match the original")
            copied.append(rel)
        except OSError as exc:
            failed.append(f"{rel}: {exc}")
    (backup / "deploy_log.json").write_text(json.dumps(
        {"when": stamp, "from": str(SRC), "to": str(DST), "replaced": changed, "added": new,
         "copied": copied, "failed": failed}, indent=1), encoding="utf-8")
    prune_backups()
    print(f"\nCopied {len(copied)} files ({len(new)} new, {len(changed)} changed).")
    print(f"Replaced files were saved to {backup}")
    if failed:
        print(f"{len(failed)} couldn't be copied (is AI-Prowler or an editor holding them open?):\n  "
              + "\n  ".join(failed))
    print("\nStart AI-Prowler again to load the new code. To undo: deploy_to_install.bat --restore")
    return 1 if failed else 0


def restore() -> int:
    if not BACKUPS.is_dir() or not any(p.is_dir() for p in BACKUPS.iterdir()):
        print(f"No deploy backups in {BACKUPS}.")
        return 1
    last = sorted(p for p in BACKUPS.iterdir() if p.is_dir())[-1]
    log = json.loads((last / "deploy_log.json").read_text(encoding="utf-8"))
    print(f"Undoing the deploy from {log['when']}: putting back {len(log['replaced'])} files and removing "
          f"{len(log['added'])} it added.")
    if ai_prowler_running():
        input("AI-Prowler is running. Close it, then press Enter to go on: ")
    for rel in log["replaced"]:
        (DST / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(last / rel, DST / rel)
    for rel in log["added"]:
        try:
            (DST / rel).unlink()
        except OSError:
            pass
    shutil.rmtree(last, ignore_errors=True)
    print("Done. Start AI-Prowler again.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Copy AI-Prowler program files to the installed AI-Prowler.")
    ap.add_argument("--dry-run", action="store_true", help="only list what would change")
    ap.add_argument("--restore", action="store_true", help="undo the last deploy")
    args = ap.parse_args()
    return restore() if args.restore else deploy(args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
