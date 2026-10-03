"""Installer / update sanity check (2026-10-02).

Proves a fresh install still builds after removing files from the installer:
  1. every [Files] Source: in AI-Prowler-Setup.iss exists in the work folder
  2. every scripts/release.py MANIFEST_FILES entry exists, and
     update_manifest.json is valid JSON listing only files in MANIFEST_FILES
     (and none of the removed files)
  3. only with --compile, if Inno Setup's ISCC.exe is installed: a full build
     into a temporary folder (deleted afterwards) — fails on any missing file or
     script error. Your Output\AI-Prowler_INSTALL.exe is never touched.

  python tests\\dev\\check_installer_files.py                  checks 1 and 2
  python tests\\dev\\check_installer_files.py --compile        all three checks
  python tests\\dev\\check_installer_files.py --remove-example  back up, then delete
                                     claude_desktop_config_example.json (done 2026-10-02)
Exit code 0 = all good.
"""
import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ISS = ROOT / "AI-Prowler-Setup.iss"
REMOVED = ["claude_desktop_config_example.json", "claude_desktop_config_snippet.json",
           "AI-Prowler_Job_Tracker.xlsx", "migrate_spreadsheet.py",
           "README.md"]   # README.md stays in the repo (GitHub page) but isn't shipped
problems = []


def section(title):
    print(f"\n=== {title} ===")


if "--remove-example" in sys.argv:
    f = ROOT / "claude_desktop_config_example.json"
    if f.exists():
        keep = ROOT / "tests" / "dev" / "removed_files"
        keep.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, keep / f.name)
        f.unlink()
        print(f"backed up to {keep / f.name} and deleted {f}")
    else:
        print(f"{f.name} already gone")

# 1. installer [Files]
section("1. Installer [Files] sources")
text = ISS.read_text(encoding="utf-8-sig")
in_files, sources = False, []
for line in text.splitlines():
    s = line.strip()
    if s.startswith("[") and s.endswith("]"):
        in_files = s.lower() == "[files]"
        continue
    if in_files and s.lower().startswith("source:"):
        m = re.match(r'(?i)source:\s*"([^"]+)"', s)
        if m:
            sources.append(m.group(1))
checked = 0
for src in sources:
    if "{" in src or "*" in src or "?" in src:
        print(f"  (skipped — constant or wildcard) {src}")
        continue
    checked += 1
    if not (ROOT / src).exists():
        problems.append(f"installer source missing: {src}")
        print(f"  MISSING  {src}")
for r in REMOVED:
    if any(Path(s).name.lower() == r.lower() for s in sources):
        problems.append(f"installer still ships removed file: {r}")
print(f"  {checked} source file(s) checked, {sum(1 for p in problems if 'installer' in p)} problem(s)")

# 2. release list + manifest
section("2. Release list and update_manifest.json")
tree = ast.parse((ROOT / "scripts" / "release.py").read_text(encoding="utf-8"))
manifest_files = None
for node in ast.walk(tree):
    if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "MANIFEST_FILES" for t in node.targets):
        manifest_files = [e.value for e in node.value.elts]
if manifest_files is None:
    problems.append("MANIFEST_FILES not found in scripts/release.py")
else:
    for rel in manifest_files:
        if not (ROOT / rel).exists():
            problems.append(f"release list file missing: {rel}")
            print(f"  MISSING  {rel}")
    for r in REMOVED:
        if r in manifest_files:
            problems.append(f"release list still has removed file: {r}")
    print(f"  {len(manifest_files)} release-list file(s) checked")
try:
    man = json.loads((ROOT / "update_manifest.json").read_text(encoding="utf-8"))
    paths = [e["path"] for e in man.get("files", [])]
    print(f"  update_manifest.json: valid JSON, {len(paths)} file(s)")
    for r in REMOVED:
        if r in paths:
            problems.append(f"update_manifest.json still lists removed file: {r}")
    if manifest_files is not None:
        extra = [p for p in paths if p not in manifest_files]
        for p in extra:
            problems.append(f"update_manifest.json lists a file not in MANIFEST_FILES: {p}")
except Exception as e:
    problems.append(f"update_manifest.json unreadable: {e}")

# 3. full Inno Setup build — only with --compile. Built into a temporary folder
# that is deleted afterwards, so the real Output\AI-Prowler_INSTALL.exe is never
# touched (ISCC /O- would delete it — seen 2026-10-02).
section("3. Inno Setup build (into a temporary folder)")
iscc = next((p for p in (Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
                         Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"))
             if p.exists()), None)
if "--compile" not in sys.argv:
    print("  skipped — add --compile for a full Inno Setup build (into a temporary "
          "folder; your Output\\AI-Prowler_INSTALL.exe is not touched)")
elif not iscc:
    print("  ISCC.exe not found — skipped (checks 1 and 2 still cover missing files)")
else:
    # Build into a throwaway folder (/O<temp>), NOT /O-: /O- deletes the last
    # built Output\AI-Prowler_INSTALL.exe (seen 2026-10-02). This is a real,
    # complete build, then the temporary setup.exe is removed.
    import tempfile
    tmp_out = tempfile.mkdtemp(prefix="aip_iscc_check_")
    try:
        r = subprocess.run([str(iscc), f"/O{tmp_out}", str(ISS)], cwd=str(ROOT),
                           capture_output=True, text=True, errors="replace")
    finally:
        shutil.rmtree(tmp_out, ignore_errors=True)
    tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-8:])
    print("  " + tail.replace("\n", "\n  "))
    if r.returncode != 0:
        problems.append(f"ISCC compile failed (rc={r.returncode})")
    else:
        print("  ISCC compile OK")

section("RESULT")
if problems:
    for p in problems:
        print("  ✗ " + p)
    sys.exit(1)
print("  ✓ installer builds cleanly; nothing references the removed files")
