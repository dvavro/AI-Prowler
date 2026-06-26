"""
fix_v800_paths.py  —  One-shot v8.0.0 cleanup script
======================================================
Tasks:
  1. Copy the newer COMPLETE_USER_GUIDE.md from OneDrive to the working dir
     (OneDrive copy is June-25, working dir copy may be older)
  2. Fix ~/.rag_auto_update_dirs.json  — replace any OneDrive AI-Prowler path
     with C:\\Users\\david\\Documents\\AI-Prowler  (local, not OneDrive)
  3. Create C:\\Users\\david\\Documents\\AI-Prowler if it doesn't exist yet
  4. Copy the user guide there too (the installer does this at install time,
     but we need it there now for the Index tab to pick it up)
  5. Report what was changed

Run with:   py scripts\\fix_v800_paths.py
"""
import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
ONEDRIVE_GUIDE  = Path(r"C:\Users\david\OneDrive\Documents\AI-Prowler\COMPLETE_USER_GUIDE.md")
WORKDIR_GUIDE   = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler\COMPLETE_USER_GUIDE.md")
LOCAL_DOCS_DIR  = Path(r"C:\Users\david\Documents\AI-Prowler")
LOCAL_GUIDE     = LOCAL_DOCS_DIR / "COMPLETE_USER_GUIDE.md"
LOCAL_TRACKER   = Path(r"C:\Users\david\AI-Prowler_Job_Tracker.xlsx")  # may not exist yet
TRACKER_DEST    = LOCAL_DOCS_DIR / "AI-Prowler_Job_Tracker.xlsx"
ONEDRIVE_TRACKER= Path(r"C:\Users\david\OneDrive\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx")

TRACK_FILE      = Path.home() / ".rag_auto_update_dirs.json"

OLD_ONEDRIVE_PATH = str(Path(r"C:\Users\david\OneDrive\Documents\AI-Prowler"))
NEW_LOCAL_PATH    = str(LOCAL_DOCS_DIR)

SEPARATOR = "=" * 60

def ts():
    return datetime.now().strftime("%H:%M:%S")

print(SEPARATOR)
print(f"  AI-Prowler v8.0.0 path fix  [{ts()}]")
print(SEPARATOR)

# ── Task 1: Ensure local Documents\AI-Prowler directory exists ───────────────
print(f"\n[1] Ensuring {LOCAL_DOCS_DIR} exists ...")
if not LOCAL_DOCS_DIR.exists():
    LOCAL_DOCS_DIR.mkdir(parents=True)
    print(f"    ✅ Created {LOCAL_DOCS_DIR}")
else:
    print(f"    ✅ Already exists")

# ── Task 2: Sync user guide — OneDrive → working dir ────────────────────────
print(f"\n[2] Syncing COMPLETE_USER_GUIDE.md ...")

def file_mtime(p):
    return p.stat().st_mtime if p.exists() else 0

onedrive_mtime  = file_mtime(ONEDRIVE_GUIDE)
workdir_mtime   = file_mtime(WORKDIR_GUIDE)

print(f"    OneDrive copy : {datetime.fromtimestamp(onedrive_mtime).strftime('%Y-%m-%d %H:%M') if onedrive_mtime else 'NOT FOUND'}")
print(f"    Working dir   : {datetime.fromtimestamp(workdir_mtime).strftime('%Y-%m-%d %H:%M') if workdir_mtime else 'NOT FOUND'}")

if ONEDRIVE_GUIDE.exists() and onedrive_mtime > workdir_mtime:
    # Backup the working dir copy first
    if WORKDIR_GUIDE.exists():
        bak = WORKDIR_GUIDE.with_suffix(".md.bak_pre_v800fix")
        shutil.copy2(WORKDIR_GUIDE, bak)
        print(f"    Backed up working dir copy → {bak.name}")
    shutil.copy2(ONEDRIVE_GUIDE, WORKDIR_GUIDE)
    print(f"    ✅ Copied OneDrive → working dir (OneDrive was newer)")
elif not ONEDRIVE_GUIDE.exists():
    print(f"    ⚠️  OneDrive copy not found — working dir copy kept as-is")
else:
    print(f"    ✅ Working dir copy is already up to date")

# ── Task 3: Copy user guide to local Documents\AI-Prowler ───────────────────
print(f"\n[3] Deploying user guide to {LOCAL_DOCS_DIR} ...")
src = WORKDIR_GUIDE if WORKDIR_GUIDE.exists() else ONEDRIVE_GUIDE
if src.exists():
    shutil.copy2(src, LOCAL_GUIDE)
    print(f"    ✅ Copied {src.name} → {LOCAL_GUIDE}")
else:
    print(f"    ❌ No user guide source found — skipped")

# ── Task 4: Copy job tracker to local Documents\AI-Prowler ──────────────────
print(f"\n[4] Checking Job Tracker spreadsheet ...")
tracker_src = None
if ONEDRIVE_TRACKER.exists():
    tracker_src = ONEDRIVE_TRACKER
    print(f"    Found tracker at OneDrive path")
elif LOCAL_TRACKER.exists():
    tracker_src = LOCAL_TRACKER
    print(f"    Found tracker at {LOCAL_TRACKER}")

if tracker_src and not TRACKER_DEST.exists():
    shutil.copy2(tracker_src, TRACKER_DEST)
    print(f"    ✅ Copied job tracker → {TRACKER_DEST}")
elif TRACKER_DEST.exists():
    print(f"    ✅ Job tracker already at {TRACKER_DEST}")
else:
    print(f"    ⚠️  No job tracker found to copy — user will get fresh copy on install")

# ── Task 5: Fix rag_auto_update_dirs.json ───────────────────────────────────
print(f"\n[5] Fixing {TRACK_FILE} ...")

if not TRACK_FILE.exists():
    # Create it fresh pointing to the new local path
    data = {"directories": [str(LOCAL_GUIDE)]}
    TRACK_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"    ✅ Created fresh tracking file pointing to {LOCAL_GUIDE}")
else:
    raw = TRACK_FILE.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"    ❌ Could not parse {TRACK_FILE}: {e}")
        data = None

    if data is not None:
        dirs = data.get("directories", [])
        changed = False
        new_dirs = []
        for d in dirs:
            # Replace OneDrive AI-Prowler path with local Documents path
            if "OneDrive" in d and "AI-Prowler" in d:
                new_d = d.replace(
                    r"C:\Users\david\OneDrive\Documents\AI-Prowler",
                    str(LOCAL_DOCS_DIR)
                )
                print(f"    🔄 {d}")
                print(f"       → {new_d}")
                new_dirs.append(new_d)
                changed = True
            else:
                new_dirs.append(d)

        # Ensure local guide file entry is present
        local_guide_str = str(LOCAL_GUIDE)
        local_docs_str  = str(LOCAL_DOCS_DIR)
        already_has_guide = any(
            local_guide_str.lower() in d.lower() or local_docs_str.lower() in d.lower()
            for d in new_dirs
        )
        if not already_has_guide:
            new_dirs.append(local_guide_str)
            print(f"    ➕ Added {local_guide_str}")
            changed = True

        if changed:
            # Backup original
            bak = TRACK_FILE.with_suffix(".json.bak_pre_v800fix")
            shutil.copy2(TRACK_FILE, bak)
            print(f"    Backed up original → {bak.name}")
            data["directories"] = new_dirs
            TRACK_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"    ✅ Updated {TRACK_FILE}")
        else:
            print(f"    ✅ No OneDrive paths found — already correct")

# ── Summary ──────────────────────────────────────────────────────────────────
print(f"\n{SEPARATOR}")
print(f"  Done [{ts()}]")
print(f"\n  Current tracking file contents:")
if TRACK_FILE.exists():
    print(f"  {TRACK_FILE.read_text(encoding='utf-8')}")
print(SEPARATOR)
print()
print("  Next steps:")
print("  1. In AI-Prowler GUI → Index Documents tab")
print(f"     → Add directory: {LOCAL_DOCS_DIR}")
print(f"     → This indexes COMPLETE_USER_GUIDE.md and Job Tracker")
print("  2. Run Update All to pick up the new path")
print("  3. Verify in Claude: 'what tools does AI-Prowler have?'")
print()
