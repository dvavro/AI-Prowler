# AI-Prowler — v7.0.0 Upgrade Guide

**Migrating from v6.x to v7.0.0 (ChromaDB 0.6.x → 1.0.x)**
_Last updated: 2026-06-03_

---

## Why this guide exists

v7.0.0 upgrades the vector database engine from **chromadb 0.6.3** to **chromadb 1.0.12**
(the Rust rewrite). The on-disk storage format changed between those versions and the
change is **irreversible** — the new engine cannot read the old store.

Because AI-Prowler's database lives **under your user profile**
(`%USERPROFILE%\AI-Prowler\rag_database`) and *not* inside `C:\Program Files`, a normal
uninstall/reinstall will **not** clear it. If the old store is left in place when v7 first
runs, ChromaDB will fail to open it.

The three migration scripts handle this cleanly:

| Script | When you run it | What it does |
|--------|-----------------|--------------|
| `AI-Prowler_PreUpgrade_Cleanup.bat` | **Before** installing v7 | Backs up durable data, then deletes only the stale Chroma store + file-tracking index |
| `AI-Prowler_PostUpgrade_Reindex.bat` | **After** installing v7 | Launcher: checks the environment, then runs the Python reindexer |
| `AI-Prowler_PostUpgrade_Reindex.py` | (called by the `.bat`) | Rebuilds the fresh 1.0.x document + learnings indexes from surviving data |

> **Keep `AI-Prowler_PostUpgrade_Reindex.bat` and `AI-Prowler_PostUpgrade_Reindex.py`
> in the same folder.** The `.bat` looks for the `.py` right next to itself.

---


## What is preserved vs. rebuilt

The cleanup is **surgical, not scorched-earth.** Here is exactly what survives.

| Item | Status during migration |
|------|-------------------------|
| Learnings source data (`self_learning_data.json`) | **Preserved** (never deleted) — reindexed into the new store |
| License / subscription | **Preserved** |
| Configuration (`.rag_config.json`) | **Preserved + backed up** |
| Tracked-paths list (`.rag_auto_update_dirs.json`) | **Preserved + backed up** |
| Write-zone allowlists (`.rag_writable_dirs.json`, `.rag_writable_pending.json`) | **Preserved + backed up** |
| `.ai-prowler\` folder | **Backed up** (full recursive copy) |
| Old ChromaDB store (`rag_database`) | **DELETED** — incompatible format |
| File-tracking index (`.rag_file_tracking.json`) | **Backed up, then DELETED** (rebuilt fresh on reindex) |

The document and learning **search indexes** are *rebuilt from files already on disk*, so
nothing you authored is lost — only the binary vector store is regenerated.

---

## Prerequisites

- **Python 3.11** installed at `%LOCALAPPDATA%\Programs\Python\Python311\python.exe`
  (this is the standard AI-Prowler runtime location).
- The v7.0.0 installer (`AI-Prowler-Setup.exe`) on hand.
- **No administrator rights are required** for the cleanup or reindex scripts — everything
  they touch is under your user profile. (The installer itself may prompt for elevation as usual.)
- A few minutes of disk space for the timestamped backup folder.

---

## Step-by-step procedure

### Step 1 — Close AI-Prowler completely

Fully exit the AI-Prowler GUI **and** make sure no background server/tunnel process is
still running. If the app holds the database open, the cleanup script cannot delete the
old store and will warn you.

> Tip: if you're unsure, check Task Manager for stray `python.exe` / `pythonw.exe`
> processes tied to AI-Prowler and end them.

### Step 2 — Run the pre-upgrade cleanup

Double-click **`AI-Prowler_PreUpgrade_Cleanup.bat`**.

It will show you exactly what it's about to back up and delete, then wait for confirmation.
**Type `YES` and press Enter** to proceed (anything else cancels safely).

The script then:

1. Creates a backup at `%USERPROFILE%\AI-Prowler-migration-backup-<timestamp>` containing
   your `.ai-prowler\` folder and all home-root config/tracking JSONs.
2. Deletes the old ChromaDB store at `%USERPROFILE%\AI-Prowler\rag_database`.
3. Deletes the stale file-tracking index `%USERPROFILE%\.rag_file_tracking.json`.

**Note the backup path it prints** — you'll want it if anything needs restoring.

> If you see `WARNING: Could not fully delete ...`, AI-Prowler is almost certainly still
> running. Close it (Step 1) and re-run the cleanup.

### Step 3 — Uninstall your existing AI-Prowler

Open **Settings → Apps → Installed apps**, find **AI-Prowler**, and uninstall it.

Alternatively, run the uninstaller directly:
```
C:\Program Files\AI-Prowler\unins000.exe
```

Your data, learnings, and settings are **not affected** — the uninstaller only removes
program files from `C:\Program Files\AI-Prowler`.

### Step 4 — Install v7.0.0

Run the v7.0.0 installer. Confirm it installs to the default location,
`C:\Program Files\AI-Prowler` (the reindex script expects this path).

Do **not** launch the GUI yet — or if you do, close it again before Step 5 so it doesn't
compete with the reindexer for the database.

### Step 5 — Run the post-upgrade reindex

With v7 installed and the GUI closed, double-click
**`AI-Prowler_PostUpgrade_Reindex.bat`** (with its `.py` companion in the same folder).

The launcher checks that Python, the install directory, and the `.py` script are all
present, then runs the rebuild. You'll see three phases:

1. **Loading embedding model** — warms the model so the first index call isn't cold.
2. **Re-indexing tracked paths** — re-indexes every folder (recursively) and file still
   listed in `.rag_auto_update_dirs.json`.
3. **Rebuilding learnings index** — rebuilds the learnings collection from
   `self_learning_data.json`.

This can take several minutes depending on how many documents you track. When it finishes
you'll see `Done. AI-Prowler's document and learning indexes have been rebuilt.`

> The reindexer only rebuilds indexes from on-disk files and is **safe to re-run** if it's
> interrupted or you add more tracked paths later.

### Step 6 — Verify

Launch AI-Prowler v7 and confirm the migration worked. Quick checks:

- **Status** — `check_ai_prowler_status` should report **ChromaDB: connected**, a non-zero
  chunk count, the embedding model loaded, and your tracked paths listed.
- **Document count** — `get_database_stats` should show a unique-document count that matches
  what you had before the upgrade.
- **Learnings** — `search_learnings` (or the GUI Learnings tab) should return your prior
  learnings. If it comes back empty, see Troubleshooting below.

---

## Troubleshooting

**Cleanup says it can't delete the store / tracking file**
AI-Prowler is still running and holding the files open. Fully close the GUI and any
background `python.exe` / `pythonw.exe` processes, then re-run the cleanup.

**Reindex `.bat`: "Python not found"**
Python 3.11 isn't at `%LOCALAPPDATA%\Programs\Python\Python311\python.exe`. Install/repair
Python 3.11 to that location, or edit `LOCAL_PYTHON` at the top of the `.bat` to point at
your interpreter.

**Reindex `.bat`: "AI-Prowler not found at C:\Program Files\AI-Prowler"**
v7 isn't installed yet, or installed to a non-default path. Install v7 first, or edit
`INSTALL_DIR` in both the `.bat` and `.py` to match your install location.

**Reindex `.bat`: ".py not found next to this .bat"**
The two scripts got separated. Put `AI-Prowler_PostUpgrade_Reindex.py` in the same folder
as the `.bat` and run again.

**Learnings come back empty after reindex**
The learnings JSON/index may be out of sync. Run the `rebuild_learnings_index` tool (or the
GUI Learnings tab's **Rebuild ChromaDB Index** button) to rebuild the learnings collection
from `self_learning_data.json`.

**Something went wrong and I want my old data back**
Your pre-upgrade backup is at `%USERPROFILE%\AI-Prowler-migration-backup-<timestamp>`. The
config/tracking JSONs and `.ai-prowler\` folder can be copied back from there. (The old
`rag_database` itself is **not** recoverable into v7 — that's the whole reason for the
migration — but all your *source* data and settings are in the backup.)

---

## Quick reference (TL;DR)

```
1. Close AI-Prowler completely.
2. Run AI-Prowler_PreUpgrade_Cleanup.bat   → type YES   (backs up + clears old DB)
3. Uninstall AI-Prowler                    → Settings → Apps, or run unins000.exe
4. Install AI-Prowler v7.0.0              → default path C:\Program Files\AI-Prowler
5. Run AI-Prowler_PostUpgrade_Reindex.bat  → rebuilds document + learnings indexes
6. Launch v7, verify with check_status / get_database_stats / search_learnings
```

**Backup location:** `%USERPROFILE%\AI-Prowler-migration-backup-<timestamp>`
**No admin rights needed** for the cleanup or reindex scripts.










