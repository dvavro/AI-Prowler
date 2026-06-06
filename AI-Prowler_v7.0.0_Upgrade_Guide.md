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

## Do I need to uninstall v6 first?

**No — and you should not.** The v7 installer performs an **in-place upgrade** over your
existing v6 install. The setup script pins a constant `AppId` GUID that stays identical
across every release, so Windows recognises v7 as the *same product* as v6 and simply
overwrites the program files in `C:\Program Files\AI-Prowler`.

A few consequences worth knowing:

- **The uninstaller is never run during an upgrade.** It's a separate, user-initiated
  action (Add/Remove Programs). It plays no part in the install flow, so don't go looking
  for an "uninstall first" step — there isn't one.
- **You will still have only ONE entry** in *Settings → Apps → Installed apps*. Because the
  AppId is constant, both versions share the same uninstall registry key; the upgrade
  updates that single entry's version to **7.0.0** rather than adding a second "AI-Prowler"
  line. (Two side-by-side entries would only appear if the GUID changed between releases —
  which the pinned AppId deliberately prevents.)
- **This is exactly why the manual cleanup is required.** Since the uninstaller isn't run
  (and even when it *is* run, it only *prompts* about the database rather than deleting it),
  the old chromadb 0.6.x store would otherwise survive straight into v7. The
  `Pre-Upgrade Cleanup` script deletes it manually so the new 1.0.x engine starts clean.
- **No admin rights** are needed for the migration scripts — they stay entirely under
  `%USERPROFILE%`. (The installer itself still prompts for elevation, as the uninstaller
  path requires admin.)

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

### Step 3 — Install v7.0.0

Run the v7.0.0 installer as you normally would — **do not uninstall v6 first.** This is an
in-place upgrade (same pinned `AppId`), so it overwrites v6 and leaves a single
"AI-Prowler" entry in *Settings → Apps*, updated to version 7.0.0. Confirm it installs to
the default location, `C:\Program Files\AI-Prowler` (the reindex script expects this path).

Do **not** launch the GUI yet — or if you do, close it again before Step 4 so it doesn't
compete with the reindexer for the database.

### Step 4 — Run the post-upgrade reindex

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

### Step 5 — Verify

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
3. Install AI-Prowler v7.0.0               → default path C:\Program Files\AI-Prowler
4. Run AI-Prowler_PostUpgrade_Reindex.bat  → rebuilds document + learnings indexes
5. Launch v7, verify with check_status / get_database_stats / search_learnings
```

**Backup location:** `%USERPROFILE%\AI-Prowler-migration-backup-<timestamp>`
**No admin rights needed** for the cleanup or reindex scripts.

/// testing the Biz multiaccess mode
✅ Business license issued
   Company       : AI-Prowler LLC
   Seat pool     : 2
   Expires       : 2027-05-29
   PARENT key    : D6F5-3FA5-E2A2-1AF1-1911-1BC3-1A16-E23A
   Child seats   : 2
      seat  1: 839C-AAB3-7694-06B6-B74C-4737-D957-FCA3
      seat  2: BF57-63EA-3C57-5C3C-573E-7367-F45C-0E6A

   ⚠️  Save the parent key — it's the company subscription. Hand each child key to one user as their license key.

📦 Seats bundle written to: C:/Users/david/AI-Prowler_V700_to_V701_work/AI-Prowler/seats.json
   Deliver this file to the customer at ~/.ai-prowler/seats.json









