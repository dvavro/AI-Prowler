# AI-Prowler — Complete User Guide
## Version 8.1.2

---

## Table of Contents

1. What is AI-Prowler?
2. Installation
3. Connecting Claude Desktop via MCP
4. Indexing Your Documents
5. Agentic RAG — How Claude Uses Your Knowledge Base
6. MCP Tools Reference
7. Remote Access — Claude.ai on Mobile and Web
8. Mobile Subscription Management
9. Business Server Mode — Multi-User Access
10. Small Business Service Tools & Job Tracker Workflow
11. SMS & WhatsApp Messaging
12. Quick Links Tab
13. Settings & Configuration
14. Supported File Types
15. OCR — Scanned Documents & Images
15a. Bilingual Language Support (English + Spanish)
16. Email Indexing
17. Scheduling & Automation
18. GPU Support
19. Debugging & Log Files
20. Troubleshooting
21. Uninstalling
22. Self-Learning System
23. Welcome Page & Update Notifications
24. Heartbeats & Analytics

---

## 1. What is AI-Prowler?

AI-Prowler is an Agentic RAG (Retrieval-Augmented Generation) knowledge base for Windows. It indexes your local documents into a private ChromaDB vector database and exposes them to Claude as a suite of intelligent search and retrieval tools.

**The key difference from traditional RAG:**

Traditional RAG retrieves a chunk, hands it to a small local model, and gets a mediocre answer. AI-Prowler's Agentic RAG lets Claude actively drive the research process:

- Claude decides what to search for based on your question
- It evaluates what it finds and identifies gaps
- It reformulates queries and searches again
- It reads surrounding context when a result is incomplete
- It synthesizes a comprehensive answer from everything it gathered

This produces dramatically better results — equivalent to having a skilled research assistant who knows your entire document library. Hardware requirements are minimal. Because Claude does the reasoning, AI-Prowler only needs to run the embedding model (~400 MB RAM) and ChromaDB. No GPU is required. No large local AI model is needed.

**New in v6.0.0 — Self-Learning at full strength:** Claude can record business lessons, fact corrections, project insights, and process improvements into a structured knowledge base — and check that knowledge before answering future questions. Learnings are instant (no GPU training required) and managed through a dedicated 🧠 Learnings tab in the GUI.

**New in v7.0.0:** Business Server Mode for multi-user team deployments, roles and scopes, role-based tool access, Tier A tool suppression, binary file write, script execution tools, and more.

**New in v8.0.0:** This release adds two-way SMS and WhatsApp messaging for field crew, new file-editing tools, RAG preprocessor improvements, Remote Access GUI enhancements, and token recovery improvements:

- **Two-Way SMS & WhatsApp** — field crew can send and receive SMS and WhatsApp messages to registered server users and spreadsheet customers directly from Claude. Five new MCP tools: `send_sms`, `send_whatsapp`, `check_sms_inbox`, `check_sms_replies`, `check_whatsapp_replies`. Provider abstraction supports Twilio, SignalWire, Vonage, and WhatsApp Business API.
- **Webhook-based inbound messaging** — inbound SMS and WhatsApp messages are captured in real time via `/sms-webhook` and `/whatsapp-webhook` endpoints and stored in a local inbox, eliminating polling lag.
- **SMS provider abstraction** — Twilio, SignalWire, and Vonage are all supported as SMS backends. Switching providers is a configuration change, not a code change.
- **New file-editing tools** — `fuzzy_replace_in_file` (whitespace-tolerant surgical edit) and `line_replace_in_file` (edit by line number range) added alongside the existing `str_replace_in_file`, giving three escalation levels for in-place file editing.
- **RAG preprocessor fixes** — code files are now indexed as single security-scan chunks; ChromaDB batch-add bug fixed.
- **Remote Access GUI — Keep It Running panel** — LED power status indicators and one-click automated power settings (sleep, hibernate, Windows Update active hours) to keep the MCP server online.
- **Token recovery simplified** — token recovery is now email-only (SMS removed). The "Forgot your token?" flow sends a recovery code to the admin's configured email address.
- **`send_sms` and `send_email` enabled for all roles** — `can_send_sms` and `can_send_email` are now `True` for owner, manager, staff, and field_crew roles in server mode.
- **`send_learnings_report` available in server mode** — with expanded filters (category, date range, tag).
- **Total tools: 80** — up from 77 in v7.0.0. New in v8.0.0: 3 agentic analysis tools (`get_pending_analysis_tasks`, `complete_analysis_task`, `save_analysis_report`), plus expanded contractor/business workflow tools. (Job image storage tools, present earlier in v8.0.0, were removed.)
- **Common Business AI Analysis renamed** — the "AI Analysis" section in the Quick Links tab is now named "Common Business AI Analysis" for clarity.
- **Scope Directory Picker** — AI Analysis buttons and Custom Analyses tasks now support optional scope restriction to specific indexed directories before queuing.
- **Server mode GUI suppression** — Common Business AI Analysis and My Custom Analyses sections are now fully hidden in server mode.
- **`last_updated` scope bug fixed** — metadata keys no longer appear as fake directory checkboxes in the scope picker.

**New in v8.1.0:**

- **Newsletter opt-in** — a dismissible "📬 Get AI-Prowler updates and usage tips by email" banner on the Home tab. Purely opt-in, independent of licensing — reaches Home, Mobile, and Business users alike. See **Section 23**.
- **Proactive Alerts redesign** — the six background email jobs (morning briefing, overdue invoices, etc.) now use independent per-job ON/OFF toggles instead of one master "Enable proactive alerts" checkbox plus a separate Save/Start/Stop button row. Every field (job toggle, time, days, shared email) auto-saves the instant it changes — Save Config and Start/Stop buttons are gone. The background engine starts automatically the moment any job is switched on, and stops automatically when the last one is switched off. See **Section 17**.
- **Two new MCP tools:**
  - `list_analysis_tasks` — lists the FULL custom-analysis task definition list (up to 25), regardless of due date. Complements `get_pending_analysis_tasks`, which only shows tasks already queued into the run queue.
  - `cleanup_job_logs` — deletes old `run_script_start` job files (`.json`/`.log`/`_wrapper.py`) from `~/.ai-prowler/jobs/`, which had no automatic retention and could accumulate thousands of files over time. Mirrors `cleanup_backups`'s dry-run-by-default design.

**New in v8.1.1:**

- **Newsletter double opt-in** — subscribing now sends a confirmation email first; you're not added to the active mailing list until you click the link in it. This protects against typos in the email field and confirms the address is actually reachable before anything gets sent to it. See **Section 23**.
- **Reset Newsletter State** — a new option in Help → Notification Status lets you manually clear your local subscription state (e.g. if you want to resubscribe with a different address, or dismissed the confirmation reminder by mistake).

**New in v8.1.2 (Business Server only):**

- **Server-mode collection routing fix** — all three background/automated indexing paths (the File Watchdog, the Windows Scheduled Task, and the GUI's Update Selected/Update All buttons) now correctly route indexed content into its proper scoped collection instead of silently falling back to the single default collection. A file that doesn't safely match a scope rule is now skipped and logged rather than mis-filed. See **Section 4 → Server-Mode Collection Routing** and **Section 17**.

---

## 2. Installation

### Quick Start

1. Download from the Releases page
2. Double-click and follow the prompts (admin rights required)
3. The installer automatically sets up:
   - Python 3.11
   - All required Python packages
   - Tesseract OCR engine
   - Claude Desktop
   - Cloudflare Tunnel client (`cloudflared`)
4. Sign in to Claude Desktop when it opens and pin it to the taskbar for quick access if you don't plan to activate mobile.
5. Click the AI-Prowler shortcut on your Desktop. For mobile/web access, click **Start HTTP Server** in the Settings tab — but you first need a license key from the AI-Prowler subscription service.
6. Open Claude Desktop — it will communicate directly with AI-Prowler via the MCP interface. If mobile is activated you will receive an email with a license key and instructions to enable it.

> **Note:** When running in mobile mode it is recommended to open Claude via https://claude.ai for all remote access (cell, tablet, web). This prevents having multiple AI-Prowler MCP connectors active simultaneously.

### What the Installer Does NOT Do

No large local AI model is installed or downloaded. The AI interface is Claude Desktop (or Claude.ai for mobile/web) via MCP, which requires no local model. AI-Prowler only runs the small embedding model (~400 MB) and ChromaDB locally; Claude does all the reasoning. Installation typically takes under 10 minutes.

### Install Log

The full installation log is saved to `C:\Program Files\AI-Prowler\install.log`. Useful for diagnosing installation failures.

### First Launch

After install, AI-Prowler opens automatically. Claude Desktop is also installed. On first use:

1. Go to the **Quick Links** tab and click **Launch Claude Desktop**. Verify it shows "AI-Prowler" in the MCP tools panel.
2. In AI-Prowler, go to **Index Documents** and add your first document folder.
3. In Claude Desktop, create a free account, go to Quick Links, copy the Initial Connection test command, paste it, and ask a question about your indexed documents.
4. For mobile or web access, subscribe to Mobile (see Section 8). You will need a Claude Pro paid tier for web-based MCP support.

### Launch Script (RAG\RUN.bat)

AI-Prowler is launched via `RUN.bat`, which sets two important environment variables before starting the GUI:

- `PYTHONNOUSERSITE=1` — prevents Python from loading stale package versions from the Roaming site-packages folder.
- `HF_HOME` — sets the HuggingFace cache path explicitly to avoid the Errno 22 / double-backslash bug on some Windows builds.

These are set automatically; no user action is required.

---

## 3. Connecting Claude Desktop via MCP

Claude Desktop connects to AI-Prowler via the MCP (Model Context Protocol) — a standard that lets Claude use external tools and data sources.

### How It Works

The installer automatically writes AI-Prowler's entry into Claude Desktop's configuration file. When Claude Desktop starts, it connects to AI-Prowler and discovers all available tools automatically. No manual configuration is needed.

> **Note:** If mobile is configured, it is strongly recommended to use only mobile access for all Claude MCP connections going forward. This prevents two connectors (local Claude Desktop + remote Claude.ai) from being active simultaneously.

### Verifying the Connection

Open Claude Desktop and start a new conversation. You should see a tools indicator showing AI-Prowler is connected. Ask: *"What tools do you have available?"* — Claude will list all available tools. If you see `search_documents` and `get_knowledge_base_overview`, the connection is working.

### MCP Diagnostics Tool

If tools are not appearing or tool calls are failing:

1. Go to **Settings → Claude Desktop MCP**
2. Click **🔬 Run MCP Diagnostics**
3. A scrollable output window shows MCP SDK version, tool count, config validity, subscription cache, and log tail.
4. Click **📋 Copy Output** to copy the full report for sharing with support.

---

## 4. Indexing Your Documents

Before Claude can search your documents, they must be indexed. Indexing extracts text, splits it into chunks, generates embeddings, and stores everything in ChromaDB.

### Index Documents Tab

1. Click **Index Documents**
2. Click **Add Directory** and select a folder containing your documents
3. Check **Include Subfolders** if needed
4. Click **Start Indexing**

Indexing is incremental — on subsequent runs, only new or modified files are processed.

### Supported Operations

- **Add Directory** — index all supported files in a folder
- **Update Index** — re-scan tracked folders for changes
- **Smart Scan** — preview what would be indexed without committing
- **Pause / Resume** — stop mid-index and continue later

### Automatic Purge of Deleted Files

When you delete a file from a tracked folder and run **Update Selected** or **Update All**, AI-Prowler automatically purges that file's chunks from ChromaDB. The vector database stays in sync with your file system — no manual cleanup required.

### Server-Mode Collection Routing (Business Server Only)

On a Business Server install, indexed content is split into separate, access-controlled collections — your own personal directory, each team's scoped area (Sales, Office, etc.), and any shared company space are kept apart from each other. This applies no matter *how* a file gets indexed: manually via **Update Selected**/**Update All**, the File Watchdog's real-time auto-indexing (below), or the Scheduled Task.

**Every tracked directory has exactly one registered scope.** This is set up once (Admin tab) and from then on any file placed anywhere inside that directory routes to the correct collection automatically — you never have to think about it file-by-file.

**If a directory is tracked but was never assigned a scope**, AI-Prowler does **not** guess. It will not silently file that content into your personal collection, a shared collection, or anyone else's — it skips indexing that file entirely and writes a clear warning to a log file (see below) so you notice and fix the missing scope rule, rather than content quietly ending up somewhere nobody expects it. The same applies if a scope rule points at an employee who has since been removed — their old rule is treated as if it no longer exists, never as a live target.

**Where to check for skipped files:** `~/AI-Prowler/logs/index_scope_skips.log` — one line per skip, with a timestamp, which indexing method caught it, the file path, and why. This is the single place to check across all indexing methods; the File Watchdog additionally keeps its own more detailed activity log (see below).

Personal/Home installs are entirely unaffected by any of this — everything simply goes into the single default collection, exactly as always.

### Mobile Write Zones — Granting Claude Write Access

Indexing a directory makes its contents searchable. It does not let Claude modify files there. Write access is a separate, opt-in permission you grant per directory.

The tracked-paths listbox shows a write-permission prefix on every row:

- `[W]` — writable. Claude can create, edit, and delete files anywhere inside.
- `[~]` — partially writable. A narrower sub-directory has write access.
- `[R]` — read-only. Claude can search content here but cannot modify any file.

Double-click a row to toggle between read-only and writable.

> **Note:** When Claude modifies a file it creates a `.bakN` backup alongside the changed file. This allows you or Claude to roll back to previous versions. After verifying changes work correctly, manually delete `.bakN` files to reduce clutter and free space.

---

## 5. Agentic RAG — How Claude Uses Your Knowledge Base

This is the core capability of AI-Prowler. Understanding it helps you get the best results.

### The Research Loop

When you ask Claude a question with AI-Prowler connected, Claude follows this pattern automatically:

1. Calls `how_to_use_ai_prowler` to get the recommended search workflow
2. Calls `get_knowledge_base_overview` to understand what's indexed
3. Calls `search_documents` or `multi_query_search` with targeted queries
4. Calls `expand_search_result` if a chunk is cut off at a boundary
5. Calls `read_document` if a full document is needed
6. Calls `search_learnings` to check stored business knowledge
7. Synthesizes a comprehensive answer from all gathered material

### Tips for Best Results

- Ask open-ended research questions — give Claude latitude to investigate.
- Let Claude finish — you'll see multiple tool calls before the answer. This is the agentic loop working.
- Ask follow-up questions — Claude retains context within a conversation.

---

## 6. MCP Tools Reference

AI-Prowler exposes **83 tools** total to Claude across thirteen categories (this doc's own category breakdown — a separate, narrower ten-family grouping is used internally by the `how_to_use_ai_prowler` tool's guide text; 81 of the 83 shipped in v8.0.0, `list_analysis_tasks` and `cleanup_job_logs` were added since). Exactly how many are actually *visible* on a given connection depends on mode — see the table below.

### 6.1 Tool Counts by Mode

| Install type | Mode | Tools visible | Notes |
|---|---|---|---|
| Personal / Home | personal | 82 | All 83 tools minus `check_sms_replies` (§6.2b — meaningless with a single user) |
| Business — employee personal install | personal | 82 | Same as above — personal mode is personal mode regardless of edition |
| Business — company server | server | 54 | All 83 tools minus the 29 in `_TIER_A_SUPPRESSED` (§6.2) — remaining 54 are further gated per-role/per-call inside the tool itself, not by registration |

### 6.2 Tier A Tool Suppression (Server Mode Only)

The following tools are never registered when AI-Prowler runs in server mode:

| Category | Suppressed tools |
|---|---|
| Dev / code execution | `run_script`, `run_script_start`, `run_script_status`, `run_script_kill`, `compile_check`, `check_python_import`, `syntax_check`, `lint_check` |
| Host filesystem writes (unscoped) | `list_directory`, `copy_to_backup`, `list_backups`, `restore_backup`, `cleanup_backups`, `cleanup_job_logs`, `reset_write_counter`, `grant_write_access`, `revoke_write_access` — backup/restore/approval-management tools remain operator/dev-only. `create_file`, `write_file`, `str_replace_in_file`, `fuzzy_replace_in_file`, `line_replace_in_file`, and `create_directory` are **not** in this list — see §6.2c, they're gated per-call instead of blanket-suppressed. |
| Raw filesystem reads | `read_file_lines`, `grep_documents` |
| Email operator tools | `configure_email`, `send_file` — use personal SMTP credentials, not appropriate for a shared server. `send_learnings_report` is **not** in this category — see the note below. |
| Bulk index rebuild | `reindex_all` |
| Agentic analysis task queue | `get_pending_analysis_tasks`, `complete_analysis_task`, `save_analysis_report`, `list_analysis_tasks` — the Quick Links tab's Common Business AI Analysis / My Custom Analyses panels are hidden in server mode's GUI, so the queue these tools drive has no server-mode caller |
| Raw/unscoped SMS inbox | `check_sms_inbox` — reads the local inbox with no per-user filtering (unlike `check_sms_replies`, which uses the per-user-scoped read path). In a multi-user server this would let any employee read every inbound SMS/WhatsApp message company-wide, not just their own. `check_sms_replies` is the server-mode equivalent. |

> **Note:** `send_sms`, `send_email`, `send_alert`, `send_whatsapp`, `send_learnings_report` (user-facing) are **not** suppressed in server mode — they remain available to users via the Tier B role gate.

### 6.2b Personal-Mode-Only Tool Suppression (Mirror Gate)

The reverse of §6.2: some tools only make sense once there's more than one registered user, so they're never registered when AI-Prowler runs in **personal** mode:

| Category | Suppressed tools |
|---|---|
| Per-user-scoped SMS replies | `check_sms_replies` — its per-user thread isolation (Mike sees Karen's reply, not Jake's) is meaningless with a single personal-install user. `check_sms_inbox` is the personal-mode equivalent — same underlying data, but with a richer filter set (provider, unread-only, `since_hours=0` for everything ever received) that doesn't need per-user scoping. |

### 6.2c Server-Mode Personal-Directory Write Scoping

Unlike the blanket suppression in §6.2, six write/modify tools use **per-call scoping** instead: `create_file`, `write_file`, `str_replace_in_file`, `fuzzy_replace_in_file`, `line_replace_in_file`, and `create_directory`.

**Personal mode:** fully unrestricted — identical to every prior version. No change.

**Server mode:** every call from every role is checked against `_check_personal_write_scope()`:

| Situation | Result |
|---|---|
| User has a personal (private) directory configured and the target path resolves inside it | ✅ Allowed |
| User has a personal directory configured but the target path is anywhere else — a shared scope, another user's private directory, the job tracker, etc. | 🚫 Denied — "outside your personal directory" |
| User does not have a personal directory configured at all (`private_collection_enabled=False`, or no folder was ever set up in the Admin tab) | 🚫 Denied for **any** path — read-only until an admin sets one up |

This means a field crew member with a personal directory can save their own notes, drafts, or working files there — but cannot touch the job tracker spreadsheet, another employee's private folder, or any shared company document. A field crew member with no personal directory configured has no write access anywhere, full stop; they can still use every read tool (`search_documents`, `read_document`, etc.).

**Setup:** a personal directory is the same private-collection folder created via the Admin tab's "Set Up Private Folder" flow when adding or editing a user (§6 — Admin Tab). If `Private collection` isn't ticked for a user, or the folder was never created, that user gets no server-mode write access under this feature.

This scoping applies independently of Tier B role gating (§6.3) — even an owner or manager writing from a *server-mode session* is scoped to their own personal directory by this check. (Owners/managers still have unrestricted write access from a *personal-mode* install, e.g. their own PC.)

### 6.3 Role-Based Tool Access in Server Mode (Tier B)

| Tool group | owner | manager | staff | field_crew |
|---|---|---|---|---|
| RAG Search (search, overview, list docs, etc.) | ✅ | ✅ | ✅ | ✅ |
| Field Service (weather, geocode, route, maps, spreadsheet) | ✅ | ✅ | ✅ | ✅ |
| SMS & WhatsApp (send_sms, send_whatsapp, check_sms_replies, check_whatsapp_replies) | ✅ | ✅ | ✅ | ✅ |
| Self-Learning (record, check, list, update, delete, stats) | ✅ | ✅ | ✅ | ✅ |
| `check_ai_prowler_status`, `how_to_use_ai_prowler` | ✅ | ✅ | ✅ | ✅ |
| `check_tools_status` (field-service health) | ✅ | ✅ | ✅ | ✅ |
| `send_email`, `send_alert` | ✅ | ✅ | ✅ | ✅ |
| `send_learnings_report` | ✅ | ✅ | ✅ | ✅ |
| `index_path` (limited — own scopes only) | ✅ | ✅ | ✅ | ⚠️ own private dir only |
| `list_tracked_directories`, `reindex_file`, `reindex_directory` | ✅ | ✅ | ❌ | ❌ |
| `untrack_directory`, `update_tracked_directories` | ✅ | ✅ | ❌ | ❌ |

**field_crew and `index_path`:** field_crew (or any role with no `manage_db` capability) can only call `index_path` if they have a personal directory configured (same one used for the write-scoping in §6.2c) — and only for files/folders located inside it. Content always lands in their own private collection, never a shared or company scope, regardless of any collection-map rule that would otherwise apply. Once indexed, it's automatically semantically searchable via `search_documents` and friends, the same as any other content in their private collection. A field_crew member with no personal directory configured cannot index at all.

**`reindex_file` / `reindex_directory` / `reindex_all` — collection-aware in server mode.** These purge stale chunks from *every* collection (own private, assigned scopes, shared) rather than only the default one, and re-index each file back into the collection it actually belongs to via the same resolver `index_path()` uses. Without this, reindexing a file or directory containing scoped content would relocate it into the shared collection — visible to every role — rather than putting it back where it started. `reindex_all` needs no separate handling: it calls `reindex_directory()` once per tracked directory and inherits the fix automatically. Personal mode is unaffected — always the single default collection, as before.

### 6.4 Complete Tool Reference Table

---

#### Agentic RAG — Knowledge Base Search (10 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `how_to_use_ai_prowler` | Returns the recommended workflow and tool sequence. Claude calls this automatically at the start of research sessions. Identical guide body in every mode and role — see its entry under "Status & System" below for why. | Personal + Server |
| `get_knowledge_base_overview` | High-level summary: document count, file types, chunk count, database location, tracked directories. Start here before any research task. | Personal + Server |
| `search_documents` | Primary retrieval tool. Semantic vector search returning raw document chunks with source metadata and similarity scores. | Personal + Server |
| `multi_query_search` | Runs 2–6 search queries in parallel and returns deduplicated results ranked by best similarity. More efficient than multiple `search_documents` calls. | Personal + Server |
| `search_within_directory` | Semantic search restricted to a single directory/case/project — use when you need to guarantee results come only from one folder tree, not the whole index. Tries an exact `parent_directory` match first, falling back to a broader search filtered by `directory_chain`/`filepath`. **Server mode:** the directory filter stacks on top of the caller's role-based collection scoping — a staff/field_crew query never touches collections outside their own private/assigned-scope/shared set, regardless of what directory is requested. This is the tool the "Vicki bug" regression suite (`test_private_dir_isolation.py`) is built around — a manager cannot read the owner's private directory just by naming it. | Personal + Server |
| `expand_search_result` | Fetches chunks immediately before and after a specific result chunk. Use when a result is cut off at a boundary and you need more context. | Personal + Server |
| `read_document` | Reads a full document in sequential chunk order. Best for contracts, manuals, and reports where you need the whole text. | Personal + Server |
| `list_indexed_documents` | Browses all indexed documents grouped by file type, with chunk counts. | Personal + Server |
| `list_indexed_directories` | Directory tree of all indexed content with document counts per folder. | Personal + Server |
| `grep_documents` | Exact text or regex search across tracked files with real line numbers. Use when semantic search returns irrelevant results for code or structured text. | Personal |
| `read_file_lines` | Reads an exact line range from a file. Pair with `grep_documents` — grep locates, this extracts. | Personal |

---

#### Knowledge Base Management (5 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `index_path` | Indexes all supported documents in a folder (or a single file) and optionally adds the path to the auto-update tracking list. | Personal + Server |
| `update_tracked_directories` | Re-scans all tracked paths and re-indexes only new or changed files. | Personal + Server |
| `list_tracked_directories` | Lists every path currently registered for auto-update tracking. | Personal + Server |
| `untrack_directory` | Removes a path from the tracking list and deletes all its chunks from ChromaDB. Destructive — chunks are gone until re-indexed. | Personal + Server |
| `get_database_stats` | Chunk count, unique document count, and file-type breakdown for the ChromaDB index. Personal mode always covers the whole database. **Server mode:** scoped to the caller's accessible collections — owners (and managers with `read_all_role_scopes`) still see the full company-wide total; staff/field_crew see only their own private, assigned scope, and shared collections. | Personal + Server |

---

#### Indexing — Reindex Tools (3 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `reindex_file` | Purges and rebuilds the ChromaDB index for a single file. Call after finishing edits to a file. | Personal + Server |
| `reindex_directory` | Fully purges and rebuilds the index for one tracked directory. More thorough than `reindex_file`. | Personal + Server |
| `reindex_all` | Nuclear option — wipes and rebuilds the entire ChromaDB index from scratch across all tracked directories. | Personal |

---

#### Self-Learning Knowledge Base (10 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `record_learning` | Saves a new lesson, fact, client preference, or business insight. Instantly indexed. In server mode the recording employee's name is automatically stamped. | Personal + Server |
| `search_learnings` | Semantic search of the learning store. Claude calls this proactively before answering questions so personal knowledge overrides generic responses. | Personal + Server |
| `list_learnings` | Browses learnings by recency with exact-match filters on category, status, or tag. | Personal + Server |
| `update_learning` | Edits fields of an existing learning — content, confidence, outcome, status, tags. **Server mode ownership:** each employee may only edit learnings they personally recorded; managers may edit any employee's learning but never the owner's; the owner may edit anything. Reading/searching learnings stays fully shared (§ above) — only modification is ownership-gated. | Personal + Server |
| `delete_learning` | Permanently removes a learning from both JSON and ChromaDB. Consider archiving instead. **Same server-mode ownership rules as `update_learning`.** | Personal + Server |
| `get_learning_stats` | Summary statistics: totals by category, source, outcome, and status. | Personal + Server |
| `get_learnings_report` | Returns learnings as formatted text in-conversation (summary, full detail, or titles-only). Works on mobile. | Personal + Server |
| `rebuild_learnings_index` | Rebuilds the ChromaDB learnings index from the JSON data file. Fixes index/data mismatches. | Personal |
| `export_learnings_file` | Exports learnings to a file (JSON pack or spreadsheet). | Personal |
| `send_learnings_report` | Emails a formatted HTML learnings report in one step. Available in server mode with category, date range, and tag filters. | Personal + Server |

---

#### Small Business Action Tools (7 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `get_weather` | Current conditions and multi-day forecast. Uses Open-Meteo and Nominatim — free, no API key. Rain probability ≥ 50% is flagged. | Personal + Server |
| `geocode_address` | Converts a street address to GPS coordinates via Nominatim / OpenStreetMap — free, no API key. | Personal + Server |
| `optimize_route` | Solves the Traveling Salesman Problem for a list of job stops using real street routing via OSRM. Returns stops in optimal order with estimated arrival times. | Personal + Server |
| `build_maps_url` | Generates a tap-to-navigate Google Maps (or Apple Maps) URL with all stops pre-loaded in optimized order. Splits into multiple leg links for routes over 9 stops. | Personal + Server |
| `read_job_spreadsheet` | Reads job data from the AI-Prowler Job Tracker spreadsheet. Supports date filtering to show today's or a specific day's jobs. | Personal + Server |
| `update_job_spreadsheet` | Updates a row in the job tracker after a job is completed — status, invoice number, duration, actual amount, etc. Auto-backs up the spreadsheet before writing. | Personal + Server |
| `check_tools_status` | Field-service health check. Reports which action tools are ready to use and which need configuration (SMTP, spreadsheet path, routing APIs). **Server mode:** the dev-tools/file-editing section reflects the caller's actual availability — most dev tools (code execution, backups, `list_directory`) are unavailable in server mode; the write/edit tools show a live check of whether the caller currently has a personal directory configured. | Personal + Server |

---

#### SMS & WhatsApp Tools (5 tools — New in v8.0.0)

These tools enable two-way SMS and WhatsApp communication between field crew, registered server users, and spreadsheet customers. `check_sms_inbox` and `check_sms_replies` are mode-exclusive — see §6.2 and §6.2b — because they answer the same underlying question ("what's come in?") with different scoping that only makes sense in one mode or the other.

| Tool | What It Does | Mode |
|---|---|---|
| `send_sms` | Sends an SMS message to a registered user (from users.json) or a spreadsheet customer (from AI-Prowler_Job_Tracker.xlsx). If neither matches, falls back to your own saved personal contacts (`save_contact`) — server mode: your own contacts only, never a coworker's. Provider-abstracted: works with Twilio, SignalWire, or Vonage. In server mode, the sending employee's identity is stamped in the thread log. | Personal + Server |
| `send_whatsapp` | Sends a WhatsApp message via the Twilio WhatsApp Business API. Same three-tier recipient lookup as `send_sms` (registered users → spreadsheet customers → your own saved contacts). Works worldwide — no carrier gateway issues. Server mode: sender identity stamped in the thread log, same as `send_sms`. | Personal + Server |
| `check_sms_inbox` | Reads the entire local SMS/WhatsApp inbox (populated in real time via the `/sms-webhook` and `/whatsapp-webhook` endpoints) — every inbound message from any sender, not just people you've texted. Filterable by provider and unread-only; `since_hours=0` returns everything ever received. Personal mode only — it has no per-user scoping, so it's suppressed in server mode to prevent one employee from reading everyone's messages. | Personal |
| `check_sms_replies` | Checks for inbound SMS replies, scoped to threads **you personally sent** — in server mode, Mike sees only Karen's reply, not Jake's or Bob's. Server mode only — with a single personal-install user this attribution is meaningless, so `check_sms_inbox` covers personal mode instead. | Server |
| `check_whatsapp_replies` | Checks for inbound WhatsApp messages. **Server mode:** scoped to threads you personally sent — same per-user isolation as `check_sms_replies` (it no longer delegates to `check_sms_inbox` internally, which would have bypassed that scoping entirely). | Personal + Server |

**SMS Setup (Personal Mode):** Tell Claude your Twilio (or SignalWire/Vonage) Account SID, Auth Token, and from-number. Claude calls `configure_sms` once and credentials are saved. For inbound messages, configure your Twilio phone number's webhook URL to point to `https://your-tunnel-domain/sms-webhook`.

**SMS Setup (Server Mode):** Configure SMS credentials directly in the AI-Prowler GUI under **Settings → SMS Configuration**. The webhook endpoints `/sms-webhook` and `/whatsapp-webhook` are registered automatically when the HTTP server starts.

**SMS Recipients:** Recipients are resolved by name or partial match against:
1. Registered server users in `users.json` (with `cell_phone` and `cell_carrier` set in the Admin tab)
2. Customers in the Customers sheet of `AI-Prowler_Job_Tracker.xlsx` (with Phone and Cell Carrier columns)

---

#### Email Tools (5 tools)

Most email tools are personal-mode only, but `send_email` and `send_alert` are also available in server mode to all roles. See Section 6.5 for SMTP setup instructions.

| Tool | What It Does | Mode |
|---|---|---|
| `configure_email` | Saves SMTP credentials so Claude can send email. Auto-detects provider from email domain. Called once; credentials persist. | Personal only |
| `send_email` | Sends a plain-text email. Optional file attachment from any tracked directory. In server mode uses the server's SMTP config with employee Reply-To header. Resolves a name-only `to` in order: Customers sheet, registered users (`users.json`), then your own saved personal contacts (`save_contact`) as a final fallback. The Customers-sheet lookup always reads the single master spreadsheet directly (unlike the job-spreadsheet tools under "Server Mode: Which Spreadsheet Gets Used," it does **not** follow per-user tracker routing) — same behavior in both modes. | Personal + Server (all roles) |
| `send_alert` | Fires a quick one-line alert email — subject auto-generated from the message. Great for voice-commanded notifications from the field. | Personal + Server (all roles) |
| `send_file` | Sends any tracked file as an email attachment. Auto-generates subject from filename if not specified. | Personal only |
| `send_learnings_report` | Emails a formatted HTML learnings report. Available in server mode with expanded filters. | Personal + Server |

---

#### Write Zone Management (2 tools — Personal Installs Only)

| Tool | What It Does | Mode |
|---|---|---|
| `grant_write_access` | Adds a directory to the write-zone allowlist so Claude can create and edit files there. The directory must already be in the read allowlist. | Personal |
| `revoke_write_access` | Removes a directory from the write allowlist. Read access is unaffected. | Personal |

---

#### Code Tools — Write-Side (14 tools — Personal + Server, Server Scoped to Own Directory)

All write operations are protected by four independent layers: read allowlist, writable allowlist, hard blocklist, and per-session circuit breaker. In server mode, a fifth layer applies to `create_file`, `write_file`, `str_replace_in_file`, `fuzzy_replace_in_file`, `line_replace_in_file`, and `create_directory`: writes are scoped to the caller's own personal directory only, and denied entirely for users without one configured (see §6.2b). The remaining dev/backup-management tools (`copy_to_backup`, `restore_backup`, `list_backups`, `list_directory`, `reset_write_counter`, `grant_write_access`, `revoke_write_access`, `cleanup_backups`, `cleanup_job_logs`) stay fully suppressed in server mode (§6.2).

| Tool | What It Does | Mode |
|---|---|---|
| `create_file` | Creates a new file. Fails if the file already exists. **Server mode:** scoped to the caller's own personal directory only — denied entirely for users without one configured. | Personal + Server (own dir) |
| `write_file` | Overwrites an existing file. Auto-backs up to `.bakN` before writing. **Server mode:** scoped to the caller's own personal directory only. | Personal + Server (own dir) |
| `str_replace_in_file` | Surgical in-place edit: replaces one unique occurrence of `old_str` with `new_str`. Requires exact whitespace match including indentation. Use `dry_run=True` to preview the diff before committing. 1000× cheaper than a full file rewrite for large files. **Server mode:** scoped to the caller's own personal directory only. | Personal + Server (own dir) |
| `fuzzy_replace_in_file` | **New in v8.0.0.** Whitespace-tolerant surgical edit. Tries four progressively looser matching strategies: exact → CRLF normalization → trailing whitespace strip → full whitespace collapse. Use when `str_replace_in_file` fails due to indentation or line-ending differences. **Server mode:** scoped to the caller's own personal directory only. | Personal + Server (own dir) |
| `line_replace_in_file` | **New in v8.0.0.** Replaces a range of lines by line number. Zero text-matching ambiguity — works on any file regardless of encoding or Unicode. Always pair with `read_file_lines` first to confirm exact line numbers. Last resort when both replace tools fail. **Server mode:** scoped to the caller's own personal directory only. | Personal + Server (own dir) |
| `create_directory` | Creates a directory and any missing parents. Idempotent. **Server mode:** scoped to the caller's own personal directory only. | Personal + Server (own dir) |
| `list_directory` | Lists the immediate contents of a directory: files, subdirectories, and backups. Read-only. | Personal |
| `copy_to_backup` | Takes a manual snapshot of a file as `.bakN` without modifying the original. | Personal |
| `list_backups` | Lists all backups for a given file with timestamps and sizes. | Personal |
| `restore_backup` | Overwrites the active file with the contents of the specified backup. | Personal |
| `cleanup_backups` | Finds and optionally deletes backup files. Always run with `dry_run=True` first to preview. | Personal |
| `cleanup_job_logs` | **Recently added.** Deletes old `run_script_start` job files (manifest `.json`, `.log`, `_wrapper.py`) from `~/.ai-prowler/jobs/`, which has no automatic retention. A job is only deleted if it's BOTH older than `older_than_days` (default 7) AND ranked beyond the `keep_last` most recent jobs (default 20) — either condition alone protects it. A job still marked "running" is never deleted. Always run with `dry_run=True` first (the default). | Personal |
| `reset_write_counter` | Resets the per-session 20-write circuit breaker so large editing sessions can continue without restarting the server. | Personal |
| `list_writable_directories` | Personal mode / server-mode owner+manager: full write-zone and read-zone allowlist. Server-mode staff/field_crew: only their own personal directory's read/write status — not the company-wide list. | Personal + Server |

**File Edit Escalation Order:** Use `str_replace_in_file` first (exact match). If it fails due to whitespace, use `fuzzy_replace_in_file`. If that also fails (Unicode characters, complex indentation), use `line_replace_in_file` with `read_file_lines` to confirm line numbers first.

---

#### Dev Tools (8 tools — Personal Installs Only)

Eight tools for code verification and script execution. Suppressed in server mode.

**Verification tools (check code without running it):**

| Tool | What It Does | Mode |
|---|---|---|
| `compile_check` | Byte-compiles a Python file to catch syntax errors. Equivalent to `python -m py_compile`. | Personal |
| `check_python_import` | Imports a Python module in a separate process to catch load-time errors that `compile_check` misses (NameError, ImportError, bad module-level references). | Personal |
| `syntax_check` | Multi-language syntax checker. Supports Python, JavaScript, TypeScript, C, C++, Go, Java, Perl, Ruby, PHP, Bash, Verilog, SystemVerilog, VHDL. | Personal |
| `lint_check` | Multi-language linter — catches unused imports, undefined names, and style issues. Uses pyflakes (Python), tsc (TypeScript), go vet (Go), ghdl -a (VHDL). | Personal |

**Execution tools (actually run scripts and programs):**

| Tool | What It Does | Mode |
|---|---|---|
| `run_script` | Runs a script synchronously and returns combined stdout+stderr. Previews the first 50 lines of the script before executing. Best for short scripts under ~60 seconds. Never elevated. | Personal |
| `run_script_start` | Launches a script as a background job and returns a `job_id` immediately. Also previews script content before launching. Use for long-running tasks (full test suites, builds) that would time out the MCP connection. Default timeout: 30 minutes. | Personal |
| `run_script_status` | Checks the status of a background job and returns a tail of its log output. Status values: `running`, `completed`, `failed`, `timeout`, `killed`. Call repeatedly to poll progress. | Personal |
| `run_script_kill` | Terminates a running background job and all its child processes. Updates the manifest to `killed` and returns the final log tail. | Personal |

> **Tip:** Use `run_script` for quick one-off executions. Use `run_script_start` + `run_script_status` for anything that takes more than a minute — including the full test suite. Pass pytest filters via the `args` parameter: `tests/test_sms.py -v --tb=short`.

---

#### Status & System (2 tools)

Two different status tools — know which to call:

- **RAG broken?** → `check_ai_prowler_status`
- **Email/SMS/routing not working?** → `check_tools_status`

| Tool | What It Does | Mode |
|---|---|---|
| `check_ai_prowler_status` | RAG engine health check. Verifies ChromaDB connectivity, embedding model status, and chunk count — always shown to every role, a basic health signal. The tracked-paths list (real folder/file names) is shown only to owner/manager in server mode, same gate as `list_tracked_directories`; staff/field_crew still get the health check, just without that section. | Personal + Server |
| `how_to_use_ai_prowler` | Returns the recommended Agentic RAG workflow and tool-call sequence. Call at the start of any new research session. **The main guide is identical across every mode and role** — deliberate, so a conversation with two connectors attached (e.g. a personal install and a company server) can't have Claude conflate "not available on this connector" with "doesn't exist at all." Server-mode caveats (dev tools, code-aware retrieval, file-editing scoping, agentic analysis) are written inline in the guide text itself, present for every reader. Only the "THIS CONNECTION" footer varies — computed live per caller, including their personal-directory write status. | Personal + Server |

---

#### Contractor & Job Tracker Tools (7 tools — Personal + Server)

| Tool | What It Does | Mode |
|---|---|---|
| `log_time_entry` | Clocks in or out for a job. Records start/stop times and computes duration in the TimeLog sheet of the Job Tracker spreadsheet. Requires an exact, unambiguous job match — an identifier matching zero or multiple jobs is rejected rather than guessed. **Server mode:** the `Crew / Technician` field is stamped with the caller's own name (not the job's pre-assigned crew), and a new `Logged By (User ID)` column tracks ownership — you can only clock out an entry you personally opened, and one teammate's open shift never blocks another's on the same job. | Personal + Server |
| `email_invoice` | Reads the Invoices sheet and emails a branded HTML invoice directly to the customer. | Personal + Server |
| `schedule_next_recurring_job` | Auto-creates the next recurring job entry (weekly, bi-weekly, monthly, quarterly) after a job is marked complete. Requires an exact, unambiguous job match — a `job_identifier` matching zero or multiple jobs is rejected with a candidate list rather than guessed. Accepts a `when` argument in **both** modes — `"today"` (default if omitted, in both modes), `"tomorrow"`, `"yesterday"`, `"this_week"`, `"next_week"`, `"any"` (no date restriction), or an explicit `"YYYY-MM-DD"` — to scope which jobs are searched by date. **Server mode:** staff/field_crew only search jobs assigned to them (`Crew / Technician` matches their own name); owner/manager search every crew's jobs. | Personal + Server |
| `get_ar_aging_report` | Generates an Accounts Receivable aging report from the Invoices sheet, broken into Current / 1–30 / 31–60 / 61–90 / 90+ day buckets. | Personal + Server |
| `save_contact` | Saves or updates a personal contact (phone and/or email) so future `send_sms` / `send_email` calls can resolve them by name. Merges with any existing saved fields rather than overwriting. **Server mode:** each user gets their own separate file (`contacts_cache_<user_id>.json`) — genuinely private, not a shared company address book; the confirmation message shows exactly which file it saved to. | Personal + Server |
| `get_sms_thread` | Returns the full two-way conversation thread with a contact — both outbound and inbound messages in chronological order. **Server mode:** only shown if you personally last sent to this contact — threads are keyed by phone number company-wide, so this prevents seeing another employee's conversation just by naming their contact. | Personal + Server |
| `list_sms_contacts_with_replies` | Lists all contacts you've texted recently, with unread inbound reply counts highlighted. **Server mode:** scoped to threads you personally sent — same per-user isolation as `check_sms_replies`. A brand-new user with no thread history yet sees everything until they send their first message. | Personal + Server |

---

#### Agentic Analysis Tools (5 tools — Personal Only)

These tools power the **Common Business AI Analysis** and **My Custom Analyses** sections in the Quick Links tab. Not available in server mode.

| Tool | What It Does | Mode |
|---|---|---|
| `create_analysis_task` | Defines a new recurring or one-off custom task from a plain-language request — the same thing the "+ New Custom Analysis" GUI dialog builds. **Day-granularity scheduling only** — there's no time-of-day in this system, so "every Monday at 8am" is stored as "due every Monday"; the "8am" isn't representable. **Pull-based, not autonomous** — creating a task doesn't make anything run unattended; the task becomes visible next time `get_pending_analysis_tasks()` is called after it's due AND queued (GUI "Queue"/"Run Due Tasks" button, or a future conversation). Enforces the same 25-task cap as the GUI dialog (`MAX_CUSTOM_TASKS`, centralized inside `create_task()` itself). | Personal |
| `list_analysis_tasks` | **Recently added.** Lists the FULL custom-analysis task definition list (`custom_analysis_tasks.json`), up to 25, regardless of due date — with an `is_due` flag per task. Complements `get_pending_analysis_tasks`, which only shows tasks that have already been queued into the run queue (`pending_tasks.json`). Use this for "what's in my task queue" / "list everything I've scheduled" — those questions are about the full definition list, not just what's currently due. Strictly read-only; never modifies or queues anything. | Personal |
| `get_pending_analysis_tasks` | Returns all pending tasks from `~/.ai-prowler/pending_tasks.json`. Claude calls this when you paste the run-queue command. Returns a JSON object with `pending_count`, `tasks` array (including `task_id`, `label`, `prompt`, `scope_dirs`, `schedule`, `next_due`, `queued_ago`), and execution instructions. Returns a plain informational message when the queue is empty. | Personal |
| `complete_analysis_task` | Marks a pending task as completed after Claude finishes the analysis. Stamps `completed_at` and stores the optional `summary`. For scheduled tasks (both built-in and custom), auto-advances `next_due` anchored to the original due date — not the completion date. | Personal |
| `save_analysis_report` | Saves a full analysis as a Word document (`.docx`) to the configured report folder. Default: `~/Documents/AI-Prowler_tasks_reports`. | Personal |


### 6.5 Email Tool Setup

#### How to Configure Email (Personal Installs)

On a personal install, email is configured by telling Claude your credentials in a conversation. Claude calls `configure_email` once and your credentials are saved to `smtp_config.json`. You never need to call the tool manually.

Example — just tell Claude:
> *"Configure email with my Gmail address yourname@gmail.com and app password xxxx xxxx xxxx xxxx"*

Claude handles the rest — it detects your provider from the email domain and sets the correct SMTP host and port automatically.

> **Important:** Use an **App Password**, not your regular email password. Most providers block SMTP login with your main password for security reasons.

**Getting an App Password — By Provider**

**Gmail**
Requirements: Google account with 2-Step Verification enabled.
Direct link: https://myaccount.google.com/apppasswords
Steps: Go to the link → Select app: Mail, device: Windows Computer → Click Generate → Copy the 16-character password immediately (shown once only).
SMTP: Host: `smtp.gmail.com` · Port: `587` · Security: STARTTLS

**Outlook / Microsoft 365 (Personal Account)**
Direct link: https://account.microsoft.com/security
Steps: Sign in → Advanced security options → App passwords → Create a new app password → Copy immediately.
SMTP: Host: `smtp.office365.com` · Port: `587` · Security: STARTTLS

**Microsoft 365 Work / School Account**
Your IT administrator must have SMTP AUTH enabled for your account. Ask IT to enable it, then use your regular M365 password (or IT-issued app password).
SMTP: Host: `smtp.office365.com` · Port: `587` · Security: STARTTLS

**Yahoo Mail**
Direct link: https://login.yahoo.com/account/security
Steps: Sign in → Generate app password → Select Other App → Name it → Click Generate → Copy the password.
SMTP: Host: `smtp.mail.yahoo.com` · Port: `587` · Security: STARTTLS

**Apple iCloud Mail**
Direct link: https://appleid.apple.com
Steps: Sign in → Sign-In and Security → App-Specific Passwords → click + → Name it → Create → Copy the generated password (format: `xxxx-xxxx-xxxx-xxxx`).
SMTP: Host: `smtp.mail.me.com` · Port: `587` · Security: STARTTLS

#### How to Configure Email in Server Mode

In server mode, `configure_email` is suppressed. Email is configured directly in the GUI:

1. Connect to the server via Remote Desktop
2. Open AI-Prowler → **Settings → 📧 Email Configuration**
3. Enter your SMTP credentials (same app password process as above)
4. Click **💾 Save Config**
5. Click **📧 Test Connection** to verify

This server-wide email config is used for: token recovery, Send Token Email (Admin tab), and all `send_email` / `send_alert` calls from field crew.

#### Who the Recipient Sees When field_crew Sends Email

When a field crew member uses `send_email` or `send_alert`, the email sends via the server's configured SMTP account but AI-Prowler personalises it using the employee's registered name and email:

| Header | Value | Where it comes from |
|---|---|---|
| From (display name) | Employee Name via Company | Employee name + server from_name |
| From (address) | server@company.com | Server SMTP address (required for sending) |
| Reply-To | employee@personal.com | Employee's email from their user record |

When the customer clicks Reply, the reply goes directly to the employee's personal email — not to the generic company inbox. The employee receives the customer reply on their phone like any normal email.

---

## 7. Remote Access — Claude.ai on Mobile and Web

The Remote Access feature lets you use AI-Prowler with Claude.ai from any device — your phone, tablet, or any web browser — using the same agentic RAG capability as Claude Desktop.

### Personal Mode Setup (v8.0.0 — Fully Automated)

1. **Set a Bearer Token** — In Settings → Remote Access, enter any string as your Bearer token — this is the password Claude uses to connect to your knowledge base. Make it something strong (e.g. `MySecret123!`). Click **Save Token**.
2. **Start the HTTP Server** — Click **▶ Start HTTP Server**. The status light turns green.
3. **Subscribe** — Click **🛒 Subscribe — Personal**. Complete Stripe checkout. Check your email for an activation code (format: `APRO-XXXXXX-XXXXXX-XXXXXX`).
4. **Configure** — Paste the activation code into the **Activation Code** field in Settings → Remote Access. Click **⚡ Configure Mobile Access**. AI-Prowler automatically:
   - Fetches your tunnel credentials from the activation server
   - Creates a Cloudflare tunnel with a permanent public URL
   - Installs `cloudflared` as a Windows service
   - Starts the tunnel (shown as **Tunnel active (Windows service)**)
   - Auto-fills your license key, domain, and tunnel token fields
5. **Connect Claude.ai** — Click the red **📖 Connect Claude.ai (auto)** button. A popup explains the steps and copies your MCP URL to the clipboard. Click OK — Claude.ai opens to the Add Custom Connector dialog. Paste the URL, name it **AI-Prowler Local**, leave OAuth fields blank, click Add. Enter your Bearer token when prompted. Set **Always Allow** for all tools.

> **No Cloudflare account needed.** The subscription automatically provisions and manages your Cloudflare tunnel. No manual DNS, no dashboard setup, no domain purchase required.

### Business Server Mode Setup (v8.0.0 — Fully Automated)

See **Section 9** for the full server deployment guide. In brief:

1. **Start the HTTP Server** in Settings → Remote Access
2. **Subscribe** — Click **🛒 Subscribe — Business** in the Business Subscription & Server Setup panel. Complete Stripe checkout.
3. You will receive **N+1 emails**:
   - One **server activation email** (subject: *AI-Prowler Business Server — Your Activation Code*) — for configuring the server machine
   - One **personal seat email per employee** (subject: *AI-Prowler Personal — Seat N of M — Forward to your employee*) — forward each to the right team member
4. **Auto-Configure** — Paste your server activation code and click **⚡ Auto-Configure Server**. The tunnel is provisioned and the server is live.
5. **Test** — Click **🌐 Test Server Connection** — the LED turns green when the server is publicly reachable.
6. **Share the Connector URL** — Copy the URL from the Server Connection Test panel and add it as a custom connector in Claude.ai (Team plan: once via Org Settings; Pro plan: each employee individually).

### Status Lights

- **Internet ●** — green when your PC can reach the internet
- **Subscription ●** — green = active; yellow = expiring/grace; red = blocked

### Keep It Running Panel

The **Keep It Running** panel ensures Windows doesn't interrupt your MCP server.

- **LED power status indicators** — green = correctly configured, red = needs attention
- **⚡ Apply Power Settings Now** — sets sleep to Never, disables hibernate, sets Windows Update Active Hours
- **📋 Power Settings Guide** — full manual instructions

### Connecting Claude.ai — Personal Mode Step by Step

1. Click the **📖 Connect Claude.ai (auto)** button in Settings → Remote Access
2. Read the popup instructions — your MCP URL is already copied to clipboard
3. Click OK — Claude.ai opens to the Add Custom Connector form
4. Paste URL into **Remote MCP server URL** field
5. Name it **AI-Prowler Local** — this exact name matters: if you ever also connect to a company **AI-Prowler Server**, distinct names let Claude tell the two knowledge bases apart instead of guessing which one you mean
6. Leave **OAuth Client ID** and **OAuth Client Secret** blank
7. Click **Add** — Claude.ai connects to your tunnel and prompts for auth
8. Enter your Bearer token
9. Set **Always Allow** for all tools in the connector panel

---

## 8. Mobile Subscription Management

### Subscription Plans

| Plan | Price | Users | Use Case |
|---|---|---|---|
| Personal | $10/month | 1 | Single user, one Windows PC + Claude.ai mobile |
| Business | $20/month | Up to 50 seats | Team deployment — server + personal PC per employee |

### Personal Plan — How to Subscribe

Click **🛒 Subscribe — Personal** in Settings → Remote Access → Mobile Access Subscription. Complete Stripe checkout. You will receive one activation email with your code within minutes. Paste the code and click **⚡ Configure Mobile Access**.

### Business Plan — How to Subscribe and What You Receive

Click **🛒 Subscribe — Business** in Settings → Remote Access → Business Subscription & Server Setup. Complete Stripe checkout.

You will receive **N+1 emails** (where N = your seat count):

| Email | Subject | For whom | What to do |
|---|---|---|---|
| 1 (server) | *AI-Prowler Business Server — Your Activation Code* | You (the owner) | Paste code into server machine, click Auto-Configure Server |
| 2…N+1 (per seat) | *AI-Prowler Personal — Seat N of M — Forward to your employee* | Each employee | Forward as-is — employees use these to set up their own PC |

**What each employee receives** (their personal seat email):
- Their own `APRO-XXXXXX-XXXXXX-XXXXXX` personal activation code
- Their own Cloudflare tunnel (unique public URL for their PC)
- Instructions to install AI-Prowler Personal and click **⚡ Configure Mobile Access**
- The company server connector URL so they can also connect to the shared company knowledge base

**What Claude plan employees need:**
Each employee needs a **Claude Pro** (individual) or the company needs a **Claude Team** plan to use custom MCP connectors.

| Option | Connector setup |
|---|---|
| **Claude Pro** (per person) | Each employee adds the connector individually: Settings → Connectors → + → Add custom connector — name it **AI-Prowler Server** |
| **Claude Team** (org plan) | Owner adds once via Organization Settings → Connectors (name it **AI-Prowler Server**); employees just click Connect |

👉 Upgrade at: https://claude.ai/upgrade

### Activation

**Personal:** Paste your `APRO-XXXXXX-XXXXXX-XXXXXX` code into the Activation Code field in Settings → Remote Access and click **⚡ Configure Mobile Access**. The entire tunnel setup is automated.

**Business server:** Paste your server code into the Activation Code field in Settings → Remote Access → Business Subscription & Server Setup and click **⚡ Auto-Configure Server**. Then click **🌐 Test Server Connection** to confirm the server is publicly reachable.

### Grace Period

If your subscription lapses, a 30-day grace period begins. After 30 days, access is suspended until renewal.

### Mobile Activation — Machine Management (Personal Mode Only)

Your personal AI-Prowler subscription activates on 1 machine at a time. The Mobile Activation section in Settings shows your current activation status and provides tools for machine management.

| Button | Purpose |
|---|---|
| **Check Activation** | Checks whether this machine is the active install. Shows activation status from the cloud registry. |
| **Transfer to This Machine** | Moves your subscription to this machine. Use when replacing your computer. Atomically releases the old machine and activates the new one. |

**How to replace your computer:**
1. On the new machine, install AI-Prowler and enter your Bearer token in Settings → Remote Access.
2. Click **Check Activation** — shows the old machine is currently active.
3. Click **Transfer to This Machine** — a confirmation dialog shows the previous and new machine IDs.
4. Confirm — the old machine is released and this machine is activated in one step.

> **Note:** The Mobile Activation panel does not appear in Business server mode. Server installs are not machine-limited.

### Token Recovery (Business Server Mode Only)

Token recovery is available in Business server mode for admins who forget their bearer token. It is **not available in personal mode** — in personal mode you simply type a new token in Settings → Remote Access → Bearer Token and click Save Token.

In server mode, if you forget your token:

1. Click **Admin** tab — the login dialog appears
2. Click **"Forgot your token? Send recovery email"**
3. Select your name from the dropdown
4. Click **Send My Token by Email** — your existing bearer token is emailed to your registered address
5. Check your email and use the token to log in

If email is not configured or you have no email on record, click **Manual Recovery** — this shows the path to `users.json` where bearer tokens are stored as the top-level keys alongside your name.

> **Note:** There are no temporary tokens or expiry timers. Your actual permanent token is emailed to you directly.

---

## 9. Business Server Mode — Multi-User Access

Business edition lets you run AI-Prowler in server mode on a company machine so a whole team reaches one shared knowledge base from Claude on their phones and laptops.

### The Big Picture

A Business subscription provisions three things automatically when you subscribe:

1. **One server tunnel** — a dedicated Cloudflare Tunnel for the company server machine. The owner activates it with the server activation code and clicks **⚡ Auto-Configure Server**.

2. **N child seat keys** (`AP-CHLD-...`) — one per seat, for authenticating each employee's mobile access to the company server. Assigned in the Admin tab.

3. **N personal licenses** (`AP-PERS-...`) — one per seat, each with its own Cloudflare Tunnel and activation code. These are emailed to the owner (one email per seat) to forward to each employee. Employees install AI-Prowler Personal on their own Windows PC and use these exactly like a standalone personal subscriber — completely separate from the company server.

**In summary: every business seat includes both mobile server access AND a personal PC license.**

### Server Deployment — Step by Step

1. Install AI-Prowler Server on the company Windows PC
2. Go to **Settings → Remote Access**
3. Start the HTTP Server (**▶ Start HTTP Server**)
4. Click **🛒 Subscribe — Business** — complete Stripe checkout
5. Check your email for the server activation code (subject: *AI-Prowler Business Server — Your Activation Code*)
6. Paste the code into the **Activation Code** field and click **⚡ Auto-Configure Server**
   - Tunnel is provisioned, cloudflared service installed, license key auto-filled
7. Click **🌐 Test Server Connection** — LED turns green when publicly reachable
8. Go to the **Admin** tab and add your employees as users
9. Forward each per-seat personal email to the right employee

> **Employees need a Claude Pro or Claude Team plan** to use custom MCP connectors. See Section 8 for plan comparison and connector setup instructions.

### Employee Setup — What Each Employee Does

Each employee receives a forwarded email containing:
- Their personal `APRO-XXXXXX-XXXXXX-XXXXXX` activation code
- Step-by-step instructions to install AI-Prowler Personal
- The company server connector URL

Employee steps:
1. Download and install **AI-Prowler Personal** from the website
2. Go to Settings → Remote Access → paste their personal activation code
3. Click **⚡ Configure Mobile Access** — their own tunnel goes live
4. Click the red **📖 Connect Claude.ai (auto)** button — adds their personal connector; name it **AI-Prowler Local**
5. Add the company server connector URL separately in Claude.ai → Settings → Connectors → + → Add custom connector, naming it **AI-Prowler Server**

They now have **two connectors** in Claude.ai: **AI-Prowler Local** (their own private documents) and **AI-Prowler Server** (the shared company knowledge base). Using these exact, distinct names — rather than naming both just "AI-Prowler" — lets Claude tell the two apart and route requests to the right one instead of guessing.

### Edition and Mode

Two runtime settings in `config.json` decide how an install behaves:

| Setting | Values | Meaning |
|---|---|---|
| `edition` | `home` / `personal` / `business` | License tier |
| `mode` | `personal` / `server` | Deployment mode |

The Admin tab appears only when `edition = business` AND `mode = server`.

> **Note:** Configuring server or personal mode should be done after install and before indexing. After that it should not be changed — the two database formats are not compatible.

### Roles

| Role | Description | Manages Users | Tool Access |
|---|---|---|---|
| owner | The company account holder. One per company. | ✅ Always | Full (all server-mode tools) |
| manager | Senior user. Can be granted delegated admin rights. | ✅ If granted | Full (all server-mode tools) |
| staff | Regular employee. | ❌ | Core RAG + limited indexing (own scopes only) |
| field_crew | Field employee. | ❌ | Core RAG + send_email + send_sms + SMS/WhatsApp tools |

### Scopes — Controlling What Each User Can See

Scopes are data-access groups you define to match how your business is organized. Each scope corresponds to a named slice of the shared knowledge base. You enter them as a comma-separated list on each user in the Admin tab.

**Scope naming convention:** `scope:name` — for example `scope:sales`, `scope:office`, `scope:ops`.

**How scopes work:**
- Each scope maps to a dedicated ChromaDB collection on the server.
- When a user searches, results are limited to the collections their scopes grant access to.
- A user can have multiple scopes (e.g. `scope:sales, scope:office`) to access more than one slice.
- A user can also have a private collection — a personal slice only they can search.

**Scope example — a window and pressure washing company:**

| Employee | Role | Scopes | What they can search |
|---|---|---|---|
| David (owner) | owner | (all) | Everything |
| Maria (office manager) | manager | `scope:office` | Office documents, invoices, customer records |
| Jake (field crew) | field_crew | `scope:field` | Job sheets, equipment manuals, cleaning procedures |

### The Admin Tab (Server Mode Only)

The Admin tab appears only when `edition = business` AND `mode = server`. Authentication required — enter your bearer token to unlock.

**Seat Summary Strip** — shows total seats, assigned seats, and available seats at the top of the Admin tab.

**Active Users Table**

| Column | Description |
|---|---|
| Name | Employee's display name |
| Email | Optional contact email (used for Reply-To on outbound emails) |
| Cell Phone | Optional cell number for SMS |
| Cell Carrier | Carrier for email-to-SMS gateway (if applicable) |
| Role | owner / manager / staff / field_crew |
| Scopes | Comma-separated data-access scopes |
| Manages Users | ✓ if this user has delegated admin rights |
| Private Coll. | ✓ if a private knowledge-base collection is enabled |
| Seat (key) | The masked child license key assigned to this user |
| Status | active or suspended |
| Token | ●●●●●●●● (always masked — use Regenerate Token to issue a new one) |

**Action Buttons**

| Button | Action |
|---|---|
| ➕ Add User | Opens the Add User dialog |
| ✏️ Edit | Opens the Edit dialog for the selected user |
| 🔑 Regenerate Token | Issues a new random bearer token — old token stops working immediately |
| 🚫 Suspend/Activate | Toggles active/suspended without deleting the user |
| 🗑 Remove | Permanently deletes the user and frees their seat |
| ↻ Refresh | Reloads users.json and repaints the table |

**Adding a User (Step by Step)**
1. Click ➕ Add User
2. Fill in Name (required), Email (optional), Cell Phone (optional), Cell Carrier (optional)
3. Choose a Role
4. Enter Scopes (comma-separated, e.g. `scope:field, scope:office`)
5. Optionally tick **Can manage users** (managers only) and **Private collection enabled**
6. Assign a **License seat** from the dropdown (unassigned child keys)
7. Bearer token — leave blank to auto-generate (recommended)
8. Click Save

**Giving Each Employee Access**
Once added, hand them:
1. Their bearer token — send securely (or use Regenerate Token in the Admin tab)
2. The company's Claude.ai connector URL — shown in Settings → Remote Access → **Server Connection Test** panel. Copy it with the **📋 Copy** button.

The employee adds that connector in Claude.ai settings, authenticates with their bearer token, and starts a new conversation. Their personal AI-Prowler (from their seat email) connects them to their private documents. The server connector connects them to the shared company knowledge base. Both connectors can be active simultaneously in Claude.ai.

### Replacing the Server Machine

1. Install AI-Prowler Server on the new machine
2. Go to Settings → Remote Access → Business Subscription & Server Setup
3. Paste your original server activation code and click **⚡ Auto-Configure Server** — the same tunnel token is returned (re-claims are allowed from a new machine)
4. Copy `users.json`, `license_seats.json`, and `rag_database/` from the old machine (if recoverable) — or re-enter users manually via the Admin tab
5. All employees' Claude.ai connectors continue to work — the URL doesn't change

> **Why no transfer step is needed:** The server license key has no machine lock. It is validated against your subscription record for validity and seat count only. You can run it on any machine.

---

## 10. Small Business Service Tools & Job Tracker Workflow

The Small Business tab provides configuration and quick-reference for the field service automation MCP tools. These tools let Claude act as your field service assistant from a conversation.

### Free Tools Panel

Four tools require no setup and work immediately:

- `get_weather` — Open-Meteo + Nominatim (no API key)
- `geocode_address` — Nominatim / OpenStreetMap (no API key)
- `optimize_route` — OSRM public routing server (no API key)
- `build_maps_url` — Google Maps / Apple Maps URL scheme (no API key)

### Job Tracker Spreadsheet

The installer deploys a pre-built `AI-Prowler_Job_Tracker.xlsx` to `Documents\AI-Prowler\`.

> **Column headers are what `update_job_spreadsheet()` and `read_job_spreadsheet()` match on — do not rename headers or the tools will fail to find the right columns.**

#### Server Mode: Which Spreadsheet Gets Used

Every job-spreadsheet tool (`read_job_spreadsheet`, `update_job_spreadsheet`, `email_invoice`, `schedule_next_recurring_job`, `log_time_entry`, `get_ar_aging_report`) resolves the file differently depending on mode:

**Personal mode:** unrestricted — an explicit `filepath` argument is used as given; otherwise falls back to the configured default path.

**Server mode:** any `filepath` argument is **ignored**. Instead, the file is resolved from **Settings → Business → Default Spreadsheet Path** (the same path/filename you pick via that tab's Browse button — defaults to `AI-Prowler_Job_Tracker.xlsx` unless you saved it under a different name):

- **Shared master (default)** — everyone reads and writes the exact file at that path. Simple, and the whole crew stays in sync automatically.
- **Per-user tracking** — drop additional files named exactly `<user_id>.xlsx` (e.g. `jake-r.xlsx`, `vicki-vavro.xlsx` — the user's ID from the Admin tab, not their display name) into the **same folder** as the master file. A user with a matching file gets their own private tracker instead of the shared one; anyone without one still falls back to the master. No separate setting to configure — it's entirely folder-based.

**Concurrent writes:** `update_job_spreadsheet`, `schedule_next_recurring_job`, and `log_time_entry` are serialized behind an internal write lock, so two crew members saving at the same moment queue up instead of one silently overwriting the other's change. Combined with the automatic pre-write backup (see below), this means a bad or conflicting write is always recoverable, and simultaneous writes are always applied cleanly one after another rather than racing.

#### Sheets

| Sheet name | Purpose |
|---|---|
| `Customers` | Customer master list — addresses, service type, frequency, email, phone, carrier, access notes |
| `Jobs_Schedule` | All service appointments with route, weather, billing, and status columns |
| `Route_Planner` | Daily route optimization — AI fills lat/lon and map URLs |
| `Quotes` | Estimates sent to customers before booking |
| `Invoices` | Billing, payment tracking, AR aging |
| `TimeLog` | Clock-in/clock-out per job via `log_time_entry()` |
| `QB_Daily_Export` | Daily export rows for QuickBooks / accounting software import |
| `Services_Pricing` | Service catalog with base prices, multipliers, and tax categories |
| `AI-Prowler_Commands` | Quick-reference Claude prompt cheat sheet |

---

#### Customers sheet columns

| Column | Description | Example |
|---|---|---|
| `CustomerID (CUST-####)` | Unique customer ID — referenced by Jobs_Schedule and Invoices | `CUST-0001` |
| `Customer Type Comm/Res` | Commercial or Residential | `Commercial` |
| `Company Name` | Company name (commercial customers) | `Sunshine Realty LLC` |
| `First Name` | Contact first name | `Karen` |
| `Last Name` | Contact last name | `Walsh` |
| `Phone` | Primary phone number | `386-555-0101` |
| `Email` | Customer email — used by `send_email()` for lookup by name | `karen@sunshine.com` |
| `Street Address ★ AI Route` | Street — used by `geocode_address()` and `optimize_route()` | `125 Harbor Blvd` |
| `City ★ AI Route` | City — used for geocoding | `New Smyrna Beach` |
| `State` | State | `FL` |
| `ZIP ★ AI Route` | ZIP — used for geocoding | `32168` |
| `Service Type(s) Win/Press/Both` | Services this customer receives | `Both` |
| `Frequency W/BW/M/Q/OT` | Weekly / Biweekly / Monthly / Quarterly / One-Time | `Monthly` |
| `Preferred Day(s)` | Preferred service days | `Mon,Wed` |
| `Pref. Time Window` | Preferred time range | `8am-5pm` |
| `Avg Job Duration (min)` | Typical job length for scheduling | `90` |
| `Standard Quote ($)` | Default quote amount | `350` |
| `Discount (%)` | Default discount percentage (decimal) | `0.1` (= 10%) |
| `Gate Code / Access Notes` | Entry instructions for field crew | `Gate code 4421` |
| `On-Site Contact` | Who to ask for on arrival | `On-site mgr: Tom` |
| `Cell Carrier` | Carrier for `send_sms()` email-to-SMS gateway | `Spectrum Mobile` |
| `SMS Gateway` | Gateway address auto-filled from carrier | `@mypixmessages.com` |
| `Status Active/Inactive` | Whether customer is currently active | `Active` |

---

#### Jobs_Schedule sheet columns

| Column | Description | Example |
|---|---|---|
| `JobID (JOB-####)` | Unique job ID — linked to Invoices and TimeLog | `JOB-0001` |
| `CustomerID (Customers!A)` | Foreign key to Customers sheet | `CUST-0001` |
| `Customer Name / Company` | Display name | `Sunshine Realty LLC` |
| `Customer Type` | Commercial or Residential | `Commercial` |
| `Street Address ★ AI Route` | Address for geocoding and routing | `125 Harbor Blvd` |
| `City ★ AI Route` | City | `New Smyrna Beach` |
| `State` | State | `FL` |
| `ZIP ★ AI Route` | ZIP | `32168` |
| `Latitude (AI Geocode)` | Auto-filled by `geocode_address()` | `28.9831` |
| `Longitude (AI Geocode)` | Auto-filled by `geocode_address()` | `-80.8512` |
| `Service Date` | Scheduled date (YYYY-MM-DD) | `2026-03-30` |
| `Day of Week` | Auto-filled day name | `Monday` |
| `Start Time` | Scheduled start (HH:MM) | `08:00` |
| `End Time` | Scheduled end (HH:MM) | `09:30` |
| `Service Type` | Window / Pressure / Both | `Window` |
| `Service Details / Notes` | Job-specific instructions or scope | `Full exterior — 12 windows` |
| `Crew / Technician` | Assigned crew member | `Mike C.` |
| `Est. Duration (min)` | Estimated job time | `90` |
| `Actual Duration (min)` | Filled by `log_time_entry()` after completion | `86` |
| `Route Stop # ★ AI Route` | Stop order in optimized route — filled by `optimize_route()` | `1` |
| `Route Map URL ★ AI Prowler` | Google Maps link — filled by `build_maps_url()` | `https://maps.google.com/...` |
| `Weather Check ★ AI Prowler` | Weather note — filled by `get_weather()` | `Partly cloudy 81°F` |
| `Job Status` | Scheduled / In Progress / Complete / Cancelled | `Scheduled` |
| `Quote Amount ($)` | Original quoted price | `350` |
| `Actual Amount ($)` | Final charged amount (Quote − Discount) | `350` |
| `Discount Applied ($)` | Dollar discount applied | `0` |
| `Tax (7%)` | Tax amount | `24.50` |
| `Invoice Total ($)` | Quote − Discount + Tax | `374.50` |
| `Recurrence (W/BW/M/Q/OT)` | Weekly / Biweekly / Monthly / Quarterly / One-Time | `Monthly` |
| `InvoiceID (INV-####)` | Linked invoice | `INV-0001` |
| `Invoice Sent Date` | Date invoice was emailed to customer | `2026-03-30` |
| `Payment Status` | Unpaid / Paid / Overdue | `Unpaid` |

---

#### Invoices sheet columns

| Column | Description | Example |
|---|---|---|
| `InvoiceID (INV-####)` | Unique invoice ID | `INV-0001` |
| `JobID (JOB-####)` | Linked job | `JOB-0001` |
| `CustomerID` | Linked customer | `CUST-0001` |
| `Customer Name / Company` | Display name | `Sunshine Realty LLC` |
| `Customer Type` | Commercial or Residential | `Commercial` |
| `Invoice Date` | Date invoice was created | `2026-03-30` |
| `Due Date (Net 30)` | Payment due date (Invoice Date + 30 days) | `2026-04-29` |
| `Service Date` | Date service was performed | `2026-03-30` |
| `Service Type` | Window / Pressure / Both | `Window` |
| `Description` | Invoice line description | `Exterior window cleaning — 12 windows` |
| `Subtotal ($)` | Pre-discount amount | `350` |
| `Discount ($)` | Dollar discount applied | `35` |
| `Taxable Amt ($)` | Subtotal − Discount | `315` |
| `Tax 7% ($)` | Tax on taxable amount | `22.05` |
| `TOTAL DUE ($)` | Taxable Amt + Tax | `337.05` |
| `Amount Paid ($)` | Payment received to date | `0` |
| `Balance Due ($)` | Total Due − Amount Paid | `337.05` |
| `Payment Status` | Unpaid / Paid / Partial | `Unpaid` |
| `Payment Date` | Date payment was received | *(blank until paid)* |
| `Payment Method` | Cash / Check / Card / Square / Zelle | *(blank until paid)* |
| `Days Overdue (AI-AR)` | Auto-calculated by `get_ar_aging_report()` | `0` |

---

#### Quotes sheet columns

| Column | Description | Example |
|---|---|---|
| `QuoteID (QTE-####)` | Unique quote ID | `QTE-0001` |
| `CustomerID` | Linked customer | `CUST-0001` |
| `Customer Name / Company` | Display name | `Sunshine Realty LLC` |
| `Customer Type` | Commercial or Residential | `Commercial` |
| `Address` | Service address | `125 Harbor Blvd` |
| `City` | City | `New Smyrna Beach` |
| `Quote Date` | Date quote was created | `2026-03-25` |
| `Valid Until` | Quote expiry date | `2026-04-25` |
| `Service Type` | Window / Pressure / Both | `Window` |
| `Service Description` | Scope of work | `Full exterior — 12 windows` |
| `Sq Ft / Units` | Area or unit count for pricing basis | `12` |
| `Unit Price ($)` | Per-unit price | `25` |
| `Labor Cost ($)` | Labor cost component | `200` |
| `Materials ($)` | Materials cost | `0` |
| `Discount (%)` | Discount percentage (decimal) | `0.1` |
| `QUOTE TOTAL ($)` | Calculated total | `300` |
| `Status (Open/Approved/Declined)` | Quote outcome | `Open` |

---

#### TimeLog sheet columns

| Column | Description | Example |
|---|---|---|
| `EntryID` | Unique time entry ID | `TE-0001` |
| `JobID` | Linked job | `JOB-0001` |
| `Customer Name / Company` | Display name | `Sunshine Realty LLC` |
| `Date` | Date of work | `2026-03-30` |
| `Clock In (HH:MM:SS)` | Start time — written by `log_time_entry()` | `08:02:15` |
| `Clock Out (HH:MM:SS)` | End time — written by `log_time_entry()` | `09:28:44` |
| `Elapsed (min)` | Auto-calculated: (Out − In) × 1440 | `86` |
| `Crew / Technician` | Who performed the work — personal mode: pulled from the job's assignment; server mode: the actual calling user's name | `Mike C.` |
| `Notes` | Entry source / notes | `Clocked via AI-Prowler log_time_entry` |
| `Logged By (User ID)` | Server mode only — the calling user's ID, used to enforce that only the person who clocked in can clock out that entry | `jake-r` |

To log time: *"Clock me in on job JOB-0003"* → Claude calls `log_time_entry()` and writes a new row. *"Clock out"* → Claude fills the Clock Out time and calculates Elapsed automatically. The job must be specified precisely enough to match exactly one row in Jobs_Schedule — a vague identifier matching several jobs returns a list of candidates instead of guessing.

---

#### update_job_spreadsheet() — Column name reference

When Claude writes back to the spreadsheet, it matches on the **exact column header text**. Multi-line headers in Excel use `\n`. Most commonly updated columns:

```python
{
    "Job\nStatus":               "Complete",
    "Actual\nDuration (min)":    86,
    "Actual\nAmount ($)":        185.00,
    "Discount\nApplied ($)":     0,
    "Payment\nStatus":           "Paid",
    "Invoice\nSent Date":        "2026-06-25",
    "Route Stop # ★ AI Route":   1,
    "Latitude\n(AI Geocode)":    28.9831,
    "Longitude\n(AI Geocode)":   -80.8512,
    "Route Map URL\n★ AI Prowler": "https://maps.google.com/...",
    "Weather Check\n★ AI Prowler": "Partly cloudy 81°F",
}
```
### Typical Small Business Contractor Workflow

The following is a recommended day-to-day workflow for a small contracting business using AI-Prowler and the Job Tracker spreadsheet. Claude handles the data work; you focus on the jobs.

---

**Step 1 — Morning Planning (5 minutes, from your phone)**

Tell Claude:
> *"What jobs do I have today?"*

Claude calls `read_job_spreadsheet` with today's date filter and reads back your schedule — customer names, addresses, service types, and any notes.

Then tell Claude:
> *"Optimize my route for today and give me a Google Maps link."*

Claude calls `geocode_address` for each stop, calls `optimize_route` to solve the Traveling Salesman Problem, then calls `build_maps_url` to generate a tap-to-navigate link with all stops pre-loaded in optimal order. Tap the link on your phone — it opens directly in Google Maps or Apple Maps.

---

**Step 2 — Weather Check**

Tell Claude:
> *"What's the weather for my area today? Any rain?"*

Claude calls `get_weather` and flags any rain probability ≥ 50% so you can decide whether to reschedule outdoor work.

---

**Step 3 — At the Job Site (from your phone)**

Before starting work, Claude can answer questions about the customer, the job history, or the service type — all from your indexed knowledge base.

If you need to send the customer a message:
> *"Send Mike Johnson a text that we're 20 minutes out."*

Claude calls `send_sms`, looks up Mike in the Customers sheet, finds his cell number and carrier, and sends the message. If Mike replies, `check_sms_replies` will show his response.

---

**Step 4 — Job Completion**

When the job is done, tell Claude:
> *"Mark the Johnson job complete. I charged $185, took 2 hours."*

Claude calls `update_job_spreadsheet` to update the row: status = complete, actual amount = $185, duration = 2 hours. It auto-backs up the spreadsheet before writing.

---

**Step 5 — Invoice or Quote**

Tell Claude:
> *"Send the Johnson invoice to mike.johnson@email.com."*

Claude calls `send_email` with the invoice details. If you have a generated invoice file, Claude calls `send_file` to attach it.

---

**Step 6 — End of Day Debrief**

Tell Claude:
> *"Log what I learned today — that pressure washing aluminum siding needs lower PSI or it dents."*

Claude calls `record_learning` and stores it in the self-learning knowledge base, stamped with your name. Next time a siding job comes up, Claude will recall this automatically.

---

**Step 7 — Add a New Customer**

When you land a new customer:
> *"Add a new customer: Sarah Connelly, 456 Oak St, Orlando FL 32801. Window cleaning, monthly service. Cell: 407-555-1234, Carrier: Verizon."*

Claude updates the Customers sheet in the Job Tracker spreadsheet with the new record, including the phone number and carrier for future SMS messaging.

---

**Example Claude Prompts Quick Reference**

| What you want | What to say to Claude |
|---|---|
| Today's schedule | "What jobs do I have today?" |
| Optimized route | "Optimize my route for today and give me a navigation link" |
| Weather check | "What's the weather for [city] today? Any rain?" |
| Mark job complete | "Mark the [customer] job done, I charged $[amount], took [X] hours" |
| Send customer a text | "Text [customer name] that [message]" |
| Check for replies | "Any replies from [customer name]?" |
| Send invoice by email | "Email the invoice to [customer email]" |
| Log a lesson | "Remember that [lesson about the job]" |
| Find past job info | "What did we do last time at the Johnson property?" |
| Add a new customer | "Add customer: [name], [address], [service type], [phone], [carrier]" |
| Get a quote ready | "Create a quote for [customer] for [service] at $[amount]" |

---

## 11. SMS & WhatsApp Messaging

### Overview

v8.0.0 introduces full two-way SMS and WhatsApp messaging for AI-Prowler. Field crew can send and receive messages from Claude.ai on their phone — no separate app or desktop required.

### Provider Support

AI-Prowler uses a provider abstraction layer. Switching between SMS providers is a configuration change, not a code change:

| Provider | Type | Notes |
|---|---|---|
| Twilio | SMS + WhatsApp | Most feature-complete. Recommended. |
| SignalWire | SMS | Twilio-compatible API. Cheaper at volume. Drop-in replacement. |
| Vonage | SMS | Good international coverage. |
| WhatsApp Business API | WhatsApp | Via Twilio. Works worldwide. No carrier gateway issues. |

### Inbound Messages — Webhook Architecture

AI-Prowler captures inbound SMS and WhatsApp messages in real time via webhook endpoints registered on the HTTP server:

- `/sms-webhook` — receives inbound SMS from Twilio/SignalWire/Vonage
- `/whatsapp-webhook` — receives inbound WhatsApp from Twilio

Messages are stored locally in `sms_inbox.json` and isolated per crew member (thread isolation). There is no polling — messages arrive instantly when the webhook fires.

**Setting up Twilio inbound webhook:**
1. In your Twilio Console, open your phone number
2. Under Messaging → Webhook, set the URL to: `https://your-tunnel-domain/sms-webhook`
3. Method: HTTP POST

### Recipient Lookup

When you say *"text Mike"*, Claude resolves the recipient by searching:

1. **Registered server users** — names and phone numbers from `users.json` (set in Admin tab)
2. **Spreadsheet customers** — names and phone numbers from the Customers sheet of `AI-Prowler_Job_Tracker.xlsx` (columns: Phone, Cell Carrier, SMS Gateway)

Partial name matches work. If multiple matches are found, Claude asks for clarification.

### SMS vs WhatsApp — When to Use Which

- **SMS (`send_sms`)** — works for any customer with a cell number. Best for quick status updates, ETA messages, and notifications.
- **WhatsApp (`send_whatsapp`)** — works worldwide without carrier restrictions. Best for international contacts, longer messages, and customers who prefer WhatsApp. Both parties need WhatsApp. Requires Twilio WhatsApp Business API setup.

---

## 12. Quick Links Tab

The Quick Links tab is a one-click launcher for the recommended Claude Desktop / Claude.ai workflow.

- 🚀 **Launch Claude Desktop** — opens Claude Desktop directly
- ⬇ **Download Claude Desktop** — opens claude.ai/download in your browser
- 🌐 **Open Claude.ai** — opens claude.ai in your browser for mobile/web access

### Initial Connection Test

The **Initial Connection Test** banner provides a copy-to-clipboard command recommended at the start of every new Claude chat:

> *Check the status of AI-Prowler and list all the tools.*

Click **📋 Copy Command**, paste into Claude, and press Enter. This verifies the MCP link is live and shows all 83+ available AI-Prowler tools.

### 🧠 Common Business AI Analysis (v8.0.0)

The **Common Business AI Analysis** section provides five one-click analysis commands that use Claude's full reasoning capability over your local data — no API key required, no cloud uploads.

> **Not available in server mode.** This section and My Custom Analyses are hidden automatically when AI-Prowler detects `mode=server` in config.json.

An explanatory **💡 How AI Analysis Tasks Work** info card is displayed directly below the section header. It explains the queue-and-paste workflow and directs users to My Custom Analyses for scheduling.

Hovering any button shows a one-line tooltip in the status bar describing what that analysis does.

#### How it works

1. Click an analysis button (e.g. **📊 Analyze My Business**)
2. A **Configure** popup opens — set scope, output, schedule, and report folder (see popup fields below). For **🧠 Run Pending Analysis**, no popup appears — the command is copied immediately.
3. Click **Queue Analysis →** — AI-Prowler writes the task to `~/.ai-prowler/pending_tasks.json` and copies the run command to your clipboard
4. Open a new Claude chat and press **Ctrl+V** — **the command runs ALL tasks currently in the queue**
5. Claude calls `get_pending_analysis_tasks()`, reads every queued task, and executes each full analysis using all available AI-Prowler tools
6. Claude records findings as learnings via `record_learning()`
7. Claude calls `complete_analysis_task(task_id, summary)` to mark each task done and auto-advance the next due date if a schedule was set

This approach works entirely within the MCP architecture — Claude is the reasoning engine, AI-Prowler is the data server. No Anthropic API key is needed in AI-Prowler itself.

#### Analysis buttons

| Button | What it does |
|---|---|
| 🧠 **Run Pending Analysis** | Copies the run-queue command to clipboard immediately — no popup. Opens a small info box reminding you to press Ctrl+V in Claude. Each queued task already has its own scope, output, and schedule from when it was created. |
| 📊 **Analyze My Business** | Full business health check. Uses QuickBooks (invoices, payments, customers, P&L, AR aging) if connected; otherwise reads Job Tracker spreadsheet. Searches indexed documents and learnings. Records 3–5 `business_insight` learnings. |
| 💡 **Weekly Business Advisor** | End-of-week debrief. Uses QuickBooks (invoices/payments this week, cash in vs out, overdue this week) if connected; otherwise reads Job Tracker. Also checks weather for next week's scheduling. Records `weekly_review` learnings. |
| ⚠️ **Find Problems** | Scans for overdue invoices by aging bucket (using QuickBooks AR/AP aging if connected, otherwise AI-Prowler AR report), jobs over estimate by >20%, unanswered customer SMS, unresolved problem flags. Records each as a `problem_flag` learning. |
| 📈 **Growth Opportunities** | Mines financial data for growth signals. With QuickBooks: P&L by service type, net margin per service, seasonal revenue trends, customer value rankings. Without QuickBooks: job history, fast-paying customers, geographic clusters, upsell pairs. Records 3–5 `growth_opportunity` learnings. |

> **🔌 QuickBooks Integration:** If you connect the QuickBooks Online MCP connector in Claude.ai (Settings → Connectors), Claude will automatically detect it when executing any of these analyses and use QuickBooks as the primary financial data source — giving you real P&L, true net margins, expense ratios, AP aging, and cash flow data that goes beyond what the Job Tracker spreadsheet can provide. No configuration change needed in AI-Prowler; the prompts detect and use QuickBooks automatically at runtime.

#### Configure Popup

When you click any button except 🧠 Run Pending Analysis, a scrollable **Configure** popup opens (806×980). All fields are always reachable by scrolling with the mouse wheel.

| Field | Description |
|---|---|
| **Analysis** | Read-only — shows the button name |
| **What this does** | Green info box explaining what data will be read and what output will be produced |
| **Prompt (auto)** | Collapsed by default. Click **▶ Show prompt** to expand and read the full Claude instruction (read-only). |
| **Scope directories** | Scrollable checklist of all indexed directories. Check one or more to restrict the analysis. Leave all unchecked to search everything. |
| **Output — 💡 Save key insights to Learnings** | Default ✅. Appends `record_learning()` instruction to the prompt. |
| **Output — 📄 Save full analysis as Word document (.docx)** | Default ☐. Appends `save_analysis_report()` instruction with the report folder path. |
| **Schedule** | **Manual only** (default) = one-shot, runs once. Choose Daily / Weekly / Every 2 weeks / Monthly / Quarterly / Yearly to make this a recurring task. AI-Prowler tracks when it's next due and surfaces it automatically. |
| **First due date** | YYYY-MM-DD. Enabled when a schedule is selected. Defaults to today if left blank. The anchor date for schedule advancement — e.g. a "Weekly" task due June 24 will next be due July 1, then July 8, etc. |
| **Report folder** | Where `.docx` reports are saved. Defaults to `~/Documents/AI-Prowler_tasks_reports`. Click **Browse…** to change. |
| **Ctrl+V reminder** | Italic reminder: *"After clicking Queue Analysis → open a new Claude chat and press Ctrl+V to run all queued tasks."* |

> **Scheduling built-in tasks:** When you set a schedule on a Common Business button, `complete_analysis_task()` automatically advances `next_due` after Claude finishes — anchored to the original due date (not the completion date). The next due date is stamped on the completed task record and reported back to Claude as `Next scheduled run: YYYY-MM-DD`.

#### Task queue JSON schema

Tasks are stored in `~/.ai-prowler/pending_tasks.json`. The full schema (v8.0.0):

```json
{
  "task_id":          "analyze_business_20260624_143022",
  "type":             "analyze_business",
  "label":            "📊 Analyze My Business",
  "prompt":           "Analyze my business data...",
  "scope_dirs":       ["C:\\Users\\david\\OneDrive\\Documents\\Invoices"],
  "output_learnings": true,
  "output_report":    false,
  "report_folder":    "C:\\Users\\david\\Documents\\AI-Prowler_tasks_reports",
  "schedule":         "weekly",
  "first_due":        "2026-06-24",
  "next_due":         "2026-06-24",
  "created_at":       "2026-06-24T14:30:22Z",
  "status":           "pending"
}
```

When Claude completes the task, `status` changes to `"completed"`, `completed_at` and `completion_summary` are added, and `next_due` is advanced if a schedule was set. Completed tasks remain for audit — they are not deleted.

The collapsible **▶ Show Queue** panel (below the analysis buttons) lets you see what's waiting, remove individual items (✕), or clear everything (🗑 Clear Queue).

#### Tips

- Queue multiple analyses before opening Claude — click several buttons in sequence, paste the command once. Claude runs all pending tasks in sequence.
- Findings are stored as learnings and immediately searchable in future Claude conversations via `search_learnings()`.
- Use **🧠 Run Pending Analysis** as a batch shortcut — just click it, press Ctrl+V in Claude, and everything in the queue runs.
- For recurring analyses (weekly review, monthly AR check), set a **Schedule** in the popup instead of clicking the button manually each time.
- **Connect QuickBooks Online** in Claude.ai for richer financial analysis — Claude automatically detects it and uses QuickBooks P&L, true margins, AP/AR aging, and cash flow data without any extra setup.

---

### 📋 My Custom Analyses (v8.0.0)

**My Custom Analyses** lets you define your own analysis tasks — with a custom name, prompt, optional directory scope, schedule, and output format. Up to 10 custom tasks are supported.

> **Not available in server mode.** Hidden automatically when `mode=server` is detected.

#### Creating a Custom Task

Click **+ New Custom Analysis** to open the task editor (scrollable, 806×884). All fields are always reachable by scrolling with the mouse wheel.

| Field | Description |
|---|---|
| **Name** | Short label shown on the task card (e.g. "Monthly Customer Review") |
| **Prompt** | Full instruction for Claude — describe what to analyze and what to produce. Be specific: mention which tools to use, which learning categories to record under, and any report preferences. |
| **Scope directories** | Scrollable checklist. Only absolute directory paths shown — metadata fields filtered out automatically. Leave all unchecked to search everything. |
| **Schedule** | Manual only / Daily / Weekly / Every 2 weeks / Monthly / Quarterly / Yearly |
| **First due date** | YYYY-MM-DD. When the first scheduled run should occur. Leave blank for manual-only tasks. Auto-populates with today when you select a schedule. |
| **Output — 💡 Save key insights to Learnings** | Claude's prompt instructs it to call `record_learning()` with key findings |
| **Output — 📄 Save full analysis as Word document (.docx)** | Claude's prompt instructs it to call `save_analysis_report()` and save a `.docx` report |
| **Report folder** | Defaults to `~/Documents/AI-Prowler_tasks_reports`. Click **Browse…** to change. |

#### Save / Save & Queue

- **Save** — saves the task definition. It appears in the My Custom Analyses list for future use.
- **Save & Queue** — saves the task AND immediately queues it in `pending_tasks.json` and copies the run-all command to clipboard. Paste into Claude to run it right away.

#### Task Cards

Each saved task appears as a card in the list showing:

- Task name and schedule badge (e.g. `Monthly`)
- Due status — e.g. `⚠ Overdue`, `Due today`, `Due in 3 days`, or `Manual only`
- Output badges — `💡 Learnings` and/or `📄 Report`
- **▶ Queue** — adds the task to the pending queue and copies the run-all command to clipboard
- **✎ Edit** — opens the task editor pre-filled with the current settings
- **🗑** — deletes the task (with confirmation dialog)

#### 🧠 Run Due Tasks

The **🧠 Run Due Tasks** button (top-right of the My Custom Analyses panel) is a batch shortcut: it finds all tasks that are overdue or due today, queues them all at once, and copies the run-all command to clipboard. Paste into Claude once to execute all due tasks in sequence.

#### Custom Task Prompt Example

Here is a well-formed custom prompt for a monthly customer review:

> Review all customers in my Job Tracker spreadsheet. Identify: (1) customers with no jobs in the last 60 days, (2) customers with 3 or more completed jobs this quarter, (3) any unpaid invoices over 30 days old. Call `read_job_spreadsheet()` for the Jobs_Schedule and Invoices sheets. Record each finding as a learning with category `client_preference` or `problem_flag` as appropriate. Save the full analysis as a Word document via `save_analysis_report()`. Then call `complete_analysis_task(task_id, summary)` with a one-sentence summary of what was found.

#### Custom Task Lifecycle

1. Task created → saved in `~/.ai-prowler/custom_analysis_tasks.json`
2. Task queued via **▶ Queue** or **🧠 Run Due Tasks** → written to `pending_tasks.json` with `status: pending`
3. Claude picks it up via `get_pending_analysis_tasks()` and executes the prompt
4. Claude calls `complete_analysis_task(task_id, summary)` → status becomes `completed`
5. Next scheduled run date is auto-advanced from the original anchor date (e.g. Monthly June 24 → July 24, not "30 days from completion")

#### Shared Scheduling Behaviour (Common Business + Custom)

Both Common Business buttons and Custom Analyses share the same scheduling engine:

- **Anchor-based advancement** — `next_due` advances from the previous `next_due`, not from the completion date. A weekly task due Monday stays on Mondays even if Claude runs it on Wednesday.
- **`complete_analysis_task()`** handles both: custom tasks update `custom_analysis_tasks.json`; built-in tasks update `next_due` directly on the completed task record in `pending_tasks.json`.
- **Schedules available:** Manual only, Daily, Weekly, Every 2 weeks, Monthly, Quarterly, Yearly.
- **Default report folder** for all outputs: `~/Documents/AI-Prowler_tasks_reports` (created automatically if it doesn't exist)

---

### ⏰ Proactive Alerts (v8.0.0)

**Proactive Alerts** is a background scheduler built into AI-Prowler that pushes email alerts to you automatically — no Claude session needed, zero API cost. It runs as a daemon thread inside the AI-Prowler process and checks every 60 seconds whether any job is due.

> **Personal mode only.** The Proactive Alerts section is automatically hidden in server mode — same suppression as Common Business AI Analysis.

#### How it works

1. Enable Proactive Alerts in the Quick Links tab — check the **Enable proactive alerts** checkbox and enter your email address
2. Configure which jobs run and when — each job has a checkbox (enable/disable), time field, and days dropdown
3. Click **💾 Save Config** — settings saved to `~/.ai-prowler/scheduler_config.json`
4. Click **▶/■ Start/Stop** to start the scheduler engine
5. At the configured time, AI-Prowler runs the job directly (calling its own Python functions — no API, no MCP hop), formats the results as HTML email, and sends it via your configured email

The status indicator top-right shows **● Running** (green) or **● Stopped** (red).

#### Available Jobs

| Job | Default Time | Default Days | Sends | Silent if? |
|---|---|---|---|---|
| ☀️ **Morning Briefing** | 07:00 | Weekdays | Today's jobs, weather, overdue invoices, unanswered SMS, due analysis tasks | Never (always sends) |
| ⚠️ **Overdue Invoice Alert** | 08:00 | Daily | AR aging buckets 31–60, 61–90, 90+ days | Nothing overdue |
| 🧠 **Due Analysis Tasks** | 08:05 | Daily | Pending scheduled tasks with Ctrl+V run command | No tasks due |
| 💬 **SMS Reply Monitor** | every_2h | Daily | Unanswered customer messages | Inbox clean |
| 🌤️ **Weekly Weather Watch** | 19:00 | Sunday | 5-day forecast — flags rain days with outdoor jobs | Error only |
| 🌙 **End of Day Summary** | 18:00 | Daily | Jobs completed vs open today, missing time entries | Never |

#### Time Field Format

- **Fixed time:** `HH:MM` in 24-hour format — e.g. `07:00`, `18:30`
- **Interval:** `every_Nh` or `every_Nm` — e.g. `every_2h` (every 2 hours), `every_30m` (every 30 minutes)

The SMS Reply Monitor defaults to `every_2h` — it checks repeatedly throughout the day rather than at one fixed time.

#### Days Options

`daily` · `weekdays` · `weekends` · `monday` · `tuesday` · `wednesday` · `thursday` · `friday` · `saturday` · `sunday`

#### Controls

| Button | What it does |
|---|---|
| **▶ Now** | Triggers that specific job immediately — useful for testing. Sends the email if there is something to report; shows a status message if the job has nothing to report (e.g. Overdue Invoice Alert when nothing is overdue). |
| **💾 Save Config** | Saves all settings to `~/.ai-prowler/scheduler_config.json` and starts/stops the engine based on the Enable checkbox |
| **▶/■ Start/Stop** | Toggles the background scheduler thread on or off without changing config |
| **📋 View Log** | Opens a scrollable log window showing the last 200 lines of scheduler activity — what ran, what was sent, any errors |

#### Configuration file

`~/.ai-prowler/scheduler_config.json` — edit directly or use the GUI:

```json
{
  "enabled":  true,
  "email_to": "david.vavro1@gmail.com",
  "location": "New Smyrna Beach, Florida",
  "name":     "David",
  "jobs": {
    "morning_briefing":      {"enabled": true,  "time": "07:00",    "days": "weekdays"},
    "overdue_invoice_alert": {"enabled": true,  "time": "08:00",    "days": "daily"},
    "due_analysis_tasks":    {"enabled": true,  "time": "08:05",    "days": "daily"},
    "sms_reply_monitor":     {"enabled": false, "time": "every_2h", "days": "daily"},
    "weather_watch":         {"enabled": true,  "time": "19:00",    "days": "sunday"},
    "end_of_day_summary":    {"enabled": false, "time": "18:00",    "days": "daily"}
  }
}
```

#### Log file

`~/.ai-prowler/scheduler_log.txt` — capped at 500 lines, auto-rotating. Each entry shows timestamp, job name, and result (sent / nothing to report / error). Viewable from the **📋 View Log** button.

#### Required files

`scheduler_jobs.py` and `scheduler_engine.py` must be in the AI-Prowler install directory. If they are missing, the Proactive Alerts section shows a warning label instead of the job list.

---.

---


## 13. Settings & Configuration

### Remote Access Tab

- **Bearer Token** — the password used to authenticate MCP connections from Claude.ai. Enter any string — make it strong (e.g. `MySecret123!`). Click **Save Token**.
- **Port** — HTTP server port (default 8000).
- **HTTP Server controls** — ▶ Start HTTP Server / ■ Stop HTTP Server / 🔨 Force Kill Port.
- **Status lights** — Internet ● and Subscription ●

**Personal mode — Mobile Access Subscription panel:**
- **🛒 Subscribe — Personal / Business** — opens Stripe checkout in browser; activation code arrives by email
- **Activation code field** — paste `APRO-XXXXXX-XXXXXX-XXXXXX` from your email
- **⚡ Configure Mobile Access** — one click fetches tunnel credentials, installs cloudflared service, starts tunnel, auto-fills all fields
- **Manage Subscription →** — opens Stripe customer portal to cancel, change payment, or adjust seats
- **📖 Connect Claude.ai (auto)** — copies MCP URL to clipboard and opens Claude.ai Add Custom Connector dialog directly; turns red after activation to prompt user
- **📋 Manual Instructions** — fallback step-by-step guide

**Server mode — Business Subscription & Server Setup panel:**
- **🛒 Subscribe — Business** — opens Stripe Business checkout; you receive N+1 emails (server code + N per-seat personal codes to forward)
- **Activation code field** — paste the server `APRO-XXXXXX-XXXXXX-XXXXXX` from your server activation email
- **⚡ Auto-Configure Server** — fetches tunnel credentials, installs cloudflared, auto-fills Parent License Key, domain, and tunnel token
- **Manage Subscription →** — opens Stripe customer portal

**Server mode — Server Connection Test panel:**
- **Connector URL** — the public MCP URL employees paste into Claude.ai (e.g. `https://mycompany.ai-prowler.com/mcp`); auto-updates from tunnel domain; **📋 Copy** button
- **🌐 Test Server Connection** — hits the public URL over the internet and turns the LED green when reachable; success dialog shows the URL with Claude Team and Claude Pro connector instructions

**Shared (both modes):**
- **Mobile Activation** — shown in personal/home mode only (hidden in server mode):
  - **Check Activation** — checks if this machine is the active install
  - **Transfer to This Machine** — use when replacing your computer
  - *(Forgot token? In personal mode just retype it in the Bearer Token field above and click Save Token)*
- **One-Time Activation panel** — shows Public hostname and Claude.ai MCP URL (read-only, assembled automatically from tunnel domain)
- **Tunnel controls** — **Activate Tunnel Service** / **Uninstall Service** / **Start Tunnel** / **Stop Tunnel**
- **Keep It Running panel** — LED status indicators + **⚡ Apply Power Settings Now** + **📋 Power Settings Guide**

### Database Section (Settings Tab)

| Button | What it clears | Keeps tracked dirs? | Keeps learnings? |
|---|---|---|---|
| View Statistics | (display only) | — | — |
| Clear Database only | All document collections + file-tracking timestamps + email index | ✅ Yes | ✅ Yes |
| Clear Database + Database list | Everything above + tracked-directories list | ❌ No | ✅ Yes |

Learnings are **always preserved**. The `ai_prowler_learnings` ChromaDB collection is never touched by either clear button.

### Smart Scan Config Tab

- Supported / Skipped extension lists — control which file types are indexed
- Exclude folder patterns — skip specific directories during indexing

### Admin Tab (Business Server Mode Only)

See Section 9 for full details. Appears only when `edition = business` AND `mode = server`.

### SMS Configuration (Settings Tab — v8.0.0)

In server mode, SMS is configured in the GUI rather than via Claude:

1. Open Settings → **📱 SMS Configuration**
2. Select your SMS provider (Twilio, SignalWire, or Vonage)
3. Enter Account SID / API Key, Auth Token, and From Number
4. For WhatsApp: enter your WhatsApp-enabled Twilio number
5. Click **💾 Save** and then **📱 Test SMS** to send a test message

---

## 14. Supported File Types

AI-Prowler indexes 65+ file formats by default.

### Supported Extensions (indexed by default)

| Extension(s) | Category | Extractor | Notes |
|---|---|---|---|
| `.txt`, `.md`, `.rst` | Plain text / Markup | Built-in text reader | Markdown/RST syntax stripped |
| `.pdf` | Document | pdfplumber + Tesseract OCR | Text layer first; OCR if no text layer |
| `.docx` | Word (modern) | python-docx | Body paragraphs and table cells |
| `.xlsx` | Excel (modern) | openpyxl | Column: Value per-row format |
| `.xls` | Excel (legacy) | xlrd | Same Column: Value format |
| `.pptx` | PowerPoint | python-pptx | Per-slide labelled sections |
| `.odt`, `.ods`, `.odp` | OpenDocument | odfpy | All paragraph text in reading order |
| `.rtf` | Rich Text Format | striprtf | RTF codes stripped |
| `.html`, `.htm` | Web | beautifulsoup4 | All tags stripped |
| `.csv`, `.tsv` | Tabular data | csv module | Column: Value per-row format |
| `.py`, `.js`, `.ts`, `.go`, `.rs`, etc. | Code | Plain text (single security-scan chunk) | Source code is searchable; indexed as one chunk per file in v8.0.0 |
| `.json`, `.yaml`, `.toml`, `.ini`, `.cfg` | Config / Data | Plain text | Config files |
| `.jpg`, `.jpeg`, `.png`, `.tif`, `.tiff`, `.bmp`, `.webp` | Images | Tesseract OCR | OCR extracts embedded text |
| `.eml` | Email (single) | email / extract-msg | Headers, sender, recipient, subject, body |
| `.mbox` | Email (archive) | mailbox | Multiple messages, incrementally indexed |
| `.msg` | Outlook email | extract-msg | Outlook format |
| `.sh`, `.bat`, `.ps1` | Scripts | Plain text | Shell scripts |

### Skipped Extensions (never indexed by default)

| Extension(s) | Category | Reason |
|---|---|---|
| `.doc`, `.ppt`, `.xls` (OLE) | Legacy Office binary | OLE binary — convert to .docx/.pptx first |
| `.exe`, `.dll`, `.so` | Executables | Binary — no readable text content |
| `.zip`, `.gz`, `.tar`, `.7z` | Archives | Compressed — extract first |
| `.mp3`, `.mp4`, `.avi`, `.mov` | Audio / Video | No text content extractable |
| `.sqlite`, `.db` | Database files | Binary containers — use SQL exports instead |

---

## 15. OCR — Scanned Documents & Images

AI-Prowler automatically applies OCR to scanned PDFs and standalone image files (`.jpg`, `.jpeg`, `.png`, `.tif`, `.tiff`, `.bmp`, `.webp`, `.heic`, `.heif`).

### How It Works

1. `pdfplumber` attempts to extract the text layer from PDFs
2. If fewer than 150 characters are found (image-only / scanned document), each page is rendered to a 300 DPI image via `pypdfium2` — no Poppler install needed
3. `pytesseract` (Tesseract 5.4) extracts text from each page image using `lang='eng+spa'`
4. The extracted text is chunked and indexed into ChromaDB normally
5. Standalone image files (`.jpg`, `.png`, `.heic`, etc.) go directly to step 3

### OCR Debug Tools

In Settings, use the **OCR Debug** button to test OCR on a specific file and see the extracted text before indexing.

---

## 15a. Bilingual Language Support (English + Spanish)

AI-Prowler has built-in bilingual support for English and Spanish documents throughout the entire indexing and search pipeline — from OCR character recognition through to semantic search. No configuration is required.

### OCR Language: `eng+spa`

Both OCR functions in AI-Prowler use Tesseract's combined English + Spanish language pack:

```python
pytesseract.image_to_string(image, lang='eng+spa')
```

This means Tesseract simultaneously uses:
- The full **Spanish character set** — `ñ Ñ á é í ó ú ü Á É Í Ó Ú ¿ ¡` — recognized correctly
- **Both English and Spanish dictionaries** for spell-correction during recognition
- Bilingual layout analysis so mixed-language documents (e.g. English headers, Spanish body) are processed in a single pass

A document scanned or photographed in Spanish will have all its characters correctly recognized without any configuration change.

### Embedding Model: Multilingual Semantic Search

After OCR, text is embedded into ChromaDB using `all-MiniLM-L6-v2` (sentence-transformers). This model was trained on multilingual parallel corpora — pairs of sentences with the same meaning in different languages were mapped to nearby points in the same vector space.

**The practical result:** you can search in English and find Spanish documents about the same topic, and vice versa.

| You ask (English) | Finds (Spanish document) | Why it works |
|---|---|---|
| *"overdue invoices"* | *"facturas vencidas"* | Same semantic meaning → similar vectors |
| *"window cleaning job"* | *"trabajo de limpieza de ventanas"* | Multilingual embedding space |
| *"customer address"* | *"dirección del cliente"* | Concepts are language-agnostic in the vector |

### Full End-to-End Flow: English Query → Spanish Documents

```
You ask Claude (in English):
  "Find all overdue invoices from last month"
          ↓
Claude calls search_documents()
          ↓
all-MiniLM-L6-v2 encodes your query as a 384-dim semantic vector
          ↓
ChromaDB computes cosine similarity against ALL indexed chunks
  — English chunks
  — Spanish chunks            ← same similarity calculation
  — Mixed-language chunks
          ↓
Top results returned (may include Spanish text)
          ↓
Claude reads Spanish text natively, synthesizes into English answer:
  "I found 3 overdue invoices. Torres owes $450 (45 days overdue),
   Ramirez owes $280 (32 days overdue)..."
```

### What Is and Isn't Translated

**Nothing is translated.** Spanish text is stored in ChromaDB exactly as extracted from the document. Claude reads it directly — Claude is natively multilingual and reads Spanish fluently. AI-Prowler never calls a translation API.

| Stage | What happens to Spanish text |
|---|---|
| OCR (scanned PDF or image) | Tesseract recognizes Spanish characters with `eng+spa` |
| Text PDF (has text layer) | pdfplumber extracts UTF-8 text — Spanish preserved exactly |
| Word / Excel / etc. | python-docx / openpyxl extract Unicode — Spanish preserved |
| ChromaDB storage | Raw Spanish text stored as-is |
| Embedding | Encoded into multilingual semantic vector — no translation |
| Claude response | Claude reads Spanish natively, responds in the language you asked in |

### Best Practices for Bilingual Document Collections

- **Mixed collections work automatically** — a folder with English invoices and Spanish contracts can be indexed together and searched in either language
- **For exact Spanish term lookup** — use `grep_documents()` with the exact Spanish term rather than semantic search (e.g. searching for a specific clause *"número de identificación fiscal"*)
- **For conceptual cross-language search** — `search_documents()` works well (English query finds Spanish documents about the same topic)
- **Customer names and proper nouns** — indexed and searchable regardless of language
- **Tesseract language pack requirement** — `spa.traineddata` must be installed alongside `eng.traineddata`. The AI-Prowler installer uses the UB-Mannheim Tesseract build which includes both by default. If you installed Tesseract manually and Spanish OCR isn't working, download `spa.traineddata` from the Tesseract GitHub and place it in your `tessdata/` folder

### Adding More Languages (Advanced)

The Tesseract `lang=` parameter accepts any combination of installed language packs separated by `+`. If you need to index documents in French, German, Portuguese, or other languages, update the two OCR calls in `rag_preprocessor.py`:

```python
# Current (English + Spanish)
pytesseract.image_to_string(image, lang='eng+spa')

# Example: add French and Portuguese
pytesseract.image_to_string(image, lang='eng+spa+fra+por')
```

Download the corresponding `.traineddata` files from the [Tesseract GitHub tessdata repository](https://github.com/tesseract-ocr/tessdata) and place them in your Tesseract `tessdata/` folder. The embedding model `all-MiniLM-L6-v2` supports 100+ languages for semantic search — no embedding model change is needed.

---

## 16. Email Indexing

Claude has built-in connector tools for Gmail and Microsoft that allow active search — it is recommended to add those connectors instead of using AI-Prowler to index email files. However, AI-Prowler does support indexing of exported email database files:

| Provider | Format | Export Method |
|---|---|---|
| Gmail | .mbox | Google Takeout |
| Apple Mail / iCloud | .mbox | File → Export Mailbox |
| Thunderbird | .mbox | Direct from profile folder |
| Yahoo Mail | Via Thunderbird IMAP | Set up IMAP in Thunderbird first |
| Outlook / Exchange | .eml, .msg | Drag-and-drop or MailStore export |

AI-Prowler uses `Message-ID` headers for deduplication. On re-import, only new emails are indexed.

---

## 17. Scheduling & Automation

### File Watchdog (Real-Time Auto-Indexing)

The File Watchdog runs continuously in the background while AI-Prowler is open — a monitor on every tracked directory that detects new or changed files and indexes them automatically, typically within 3-5 seconds, with no button click needed. It's what makes a newly-saved document searchable almost immediately.

On a Business Server install, the watchdog routes each file into its correct scoped collection using the same rules described in **Section 4 → Server-Mode Collection Routing** — a file that doesn't safely match a rule is skipped, not guessed into the wrong place.

**Log:** `~/AI-Prowler/logs/file_watchdog.log` — the watchdog's full activity log (every file it processes, not just skips). Skipped files are also written to the shared `index_scope_skips.log` described in Section 4, so you don't need to check two different logs to find a scope problem — only the watchdog's own log if you want the fuller picture of everything it's done.

### Windows Task Scheduler Integration

Set up automatic index updates from **Settings → Schedule**:

1. Choose update frequency (daily, specific days, custom)
2. Set the time (default: 2:00 AM)
3. Click **Create Schedule**

This generates `rag_auto_update.bat` and registers it with Windows Task Scheduler — it runs even when AI-Prowler itself is closed, re-scanning every tracked directory for new, changed, and deleted files the same way **Update All** does.

**Log:** `~/AI-Prowler/.rag_update.log` — the full output of every scheduled run, including any collection-routing skip warnings (Business Server only — see Section 4). Since Task Scheduler runs this with no visible window, this log file is the only way to review what a scheduled run actually did.

If you change your tracked directories after setting up the schedule, re-visit **Settings → Schedule** and click **Create Schedule** again to regenerate the script with the current list.

### Cloudflare Tunnel as Windows Service

For always-on remote access, activate the Named Tunnel as a Windows service via **Settings → Remote Access → Activate Tunnel Service**. The tunnel starts automatically at boot.

### Proactive Alerts (Background Email Scheduler)

Proactive Alerts sends scheduled email briefings and alerts without needing an active Claude session — a background daemon thread inside the AI-Prowler desktop process ticks every 60 seconds and fires any job whose configured time/day has arrived. Configured from the Links & Analysis tab.

**Six built-in jobs:** Morning Briefing, Overdue Invoice Alert, Due Analysis Tasks, SMS Reply Monitor, Weather Watch, End-of-Day Summary. Each has its own ON/OFF toggle, a time field (`HH:MM` 24-hour, or `every_Nh`/`every_Nm` for interval jobs), and a days selector (daily / weekdays / weekends / a specific day). Email is shared across all jobs — a single field, since this is a personal-mode, single-user feature.

**Auto-save, no manual Save/Start/Stop:** every field saves the instant it changes — clicking a job's toggle, tabbing out of the time field, or selecting a day all save immediately. There is no separate "Save Config" button and no master "Enable proactive alerts" checkbox. The background engine starts automatically the moment any single job is switched ON, and stops automatically the moment the last enabled job is switched OFF — the engine's running/stopped state is fully derived from the job toggles, never a separate thing to manage.

**Important limitation — this requires AI-Prowler to actually be running.** The scheduler is a thread inside the desktop app's own process, not a separate Windows service. If AI-Prowler is closed, or your PC is asleep, nothing fires — there is no cloud-side scheduler keeping it alive. For a briefing to reliably arrive every morning, AI-Prowler needs to be open (or configured to launch and stay open) at that time.

**Run any job immediately:** each job has a "▶ Now" button that runs it on demand, regardless of its schedule — useful for testing a new configuration without waiting for the next scheduled time.

**View Log:** the one remaining manual control — opens the last 200 lines of `~/.ai-prowler/scheduler_log.txt` in a read-only popup.

---

## 18. GPU Support

AI-Prowler detects NVIDIA GPUs automatically. The installer installs the correct PyTorch build (CUDA 12.8 for RTX 50xx/Blackwell, or CPU-only). The sentence-transformer embedding model (`all-MiniLM-L6-v2`) uses CUDA automatically when available, significantly speeding up indexing. This is the only place a GPU helps — all language reasoning happens in Claude (cloud).

The `all-MiniLM-L6-v2` model is multilingual — it supports English, Spanish, and 100+ other languages in the same semantic vector space. See **Section 15a** for full bilingual language support documentation.

### Blackwell (RTX 50xx) Note

PyTorch stable does not yet include CUDA 12.8 compute kernels for Blackwell SM 12.0+ architecture. Embeddings run on CPU on RTX 50xx cards even though CUDA is detected. This affects only indexing speed, not search quality or Claude's reasoning.

---

## 19. Debugging & Log Files

### Log File Locations

| Log File | Location | Contents |
|---|---|---|
| Install log | `C:\Program Files\AI-Prowler\install.log` | Full installer output |
| MCP server log | `C:\Program Files\AI-Prowler\mcp_server.log` | All MCP server activity (current session) |
| MCP server log (prev) | `C:\Program Files\AI-Prowler\mcp_server.log.1` | Previous session |
| Subscription cache | `C:\Program Files\AI-Prowler\subscription_cache.json` | Cached subscription registry |
| SMS inbox | `~/.ai-prowler/sms_inbox.json` | Inbound SMS/WhatsApp messages |
| SMS thread log | `~/.ai-prowler/sms_threads.json` | Outbound SMS thread history per crew member |

### MCP Server Log

The MCP log is the most useful for debugging Claude Desktop and Claude.ai connection issues. It captures startup sequence, tool calls, authentication, and subscription checks.

### Common Debug Workflow

**Problem: Claude says it can't find information that should be indexed**
1. Open the log and find the tool call for `search_documents`
2. Check the similarity scores — if all are below 0.3, the content may not be well-represented
3. Try `get_database_stats` to verify the file is actually indexed
4. Try `read_document` to see the raw extracted text

**Problem: Claude.ai connector fails with "MCP server error"**
- HTTP server not running → click **Start HTTP Server**
- Cloudflare Tunnel not running → click **Start Tunnel** (or check Windows Services for `cloudflared`)
- Bearer token mismatch → re-enter your token in Settings and in Claude.ai

**Problem: Cloudflare Error 1033**
Error 1033 means `cloudflared` is running but cannot reach the local AI-Prowler HTTP server.
1. Is the HTTP server running? Open a browser on your PC and navigate to `http://localhost:8000/health` — should return `{"status":"ok"}`.
2. Is `cloudflared` running? Check Task Manager → Details for `cloudflared.exe`.
3. If `cloudflared` was started before the HTTP server, restart `cloudflared` after the HTTP server is confirmed running. Correct startup order: Start HTTP server first → then `cloudflared` connects to it.

**Problem: Cloudflare tunnel credentials missing**
1. Run `cloudflared tunnel login` — browser opens to Cloudflare, downloads `cert.pem`
2. Run `cloudflared tunnel token <tunnel-name>` — restores the credentials JSON
3. In AI-Prowler Settings → Stop Tunnel → Uninstall Service → Activate Tunnel Service

**Problem: SMS not sending**
1. Run `check_tools_status` — Claude will report which SMS tools are configured and which are missing credentials
2. Check that your Twilio/SignalWire/Vonage Account SID and Auth Token are correct in Settings → SMS Configuration
3. Verify your from-number is correctly formatted (E.164: `+15555551234`)

**Problem: Inbound SMS not appearing (`check_sms_inbox` in personal mode, `check_sms_replies` in server mode)**
1. Verify the HTTP server is running and the Cloudflare Tunnel is active
2. In your Twilio Console, confirm the webhook URL for your phone number is set to `https://your-tunnel-domain/sms-webhook`
3. Check `mcp_server.log` for any webhook POST entries
4. In server mode, `check_sms_replies` only shows replies to threads *you* personally sent — if the reply was to a text a different employee sent, ask them to check instead, or the owner can pull it from `sms_inbox.json` directly.

---

## 20. Troubleshooting

**Claude Desktop can't see AI-Prowler tools**
1. Check that AI-Prowler is installed in `C:\Program Files\AI-Prowler\`
2. Restart Claude Desktop completely
3. Start a new conversation (not an existing one)

**Cloudflare Error 1033**
See Section 19. Most common cause: `cloudflared` starting before the HTTP server, or tunnel credentials missing from `~/.cloudflared/`.

**Indexing is slow**
- Enable GPU in Settings if you have an NVIDIA card
- Use Smart Scan to skip file types you don't need

**Errno 22 / double backslash error on indexing**
Known bug on some Windows builds. The launcher sets `HF_HOME` explicitly to prevent this. If it persists after reinstall, contact support.

**SMS sends but customer doesn't receive it**
- Verify the customer's phone number in the Customers sheet is in E.164 format (`+15555551234`) or a 10-digit US number
- Check that the correct Cell Carrier is set if using email-to-SMS gateway
- Twilio/SignalWire messages can be verified in your provider's message log dashboard

> **Note:** AI-Prowler requires **Windows 11** and does not support Windows 10.

---

## 21. Uninstalling

Run the uninstaller from `C:\Program Files\AI-Prowler\uninstall.exe` or use Windows Settings → Add or Remove Programs → AI-Prowler.

The uninstaller removes all AI-Prowler application files and Python (if installed by AI-Prowler), and offers to remove the RAG database, tracking files, self-learning knowledge base, and Job Tracker spreadsheet (default: keep all — safe for reinstall).

---

## 22. Self-Learning System

### Overview

The Self-Learning System gives AI-Prowler a persistent, semantically-searchable memory separate from the main document RAG. When you tell Claude "learn this" — or when Claude detects a correction or insight during conversation — the fact is written to a structured JSON file and indexed in ChromaDB. The next time a related question comes up, Claude calls `search_learnings` first, finds the stored fact, and applies it automatically.

No GPU. No training. New knowledge is queryable within roughly 1 second of being recorded.

### The Self-Learning MCP Tools

| Tool | Purpose |
|---|---|
| `record_learning` | Save a new fact, lesson, or correction |
| `search_learnings` | Semantic search the knowledge base |
| `list_learnings` | Browse by category / status / tag |
| `update_learning` | Modify an existing learning |
| `delete_learning` | Permanently remove a learning |
| `get_learning_stats` | Summary stats — totals, most applied |
| `get_learnings_report` | Return learnings as formatted text in-conversation |
| `export_learnings_file` | Export to JSON pack or spreadsheet file |
| `rebuild_learnings_index` | Rebuild ChromaDB index from JSON data file |
| `send_learnings_report` | Email a formatted HTML learnings report (all roles in v8.0.0) |

### Learning Categories

| Category | When to use |
|---|---|
| `fact_correction` | Correcting an outdated or wrong fact |
| `business_insight` | What worked or didn't in business |
| `project_learning` | Lessons from a specific project |
| `process_improvement` | A better way to do something |
| `failure_analysis` | Something went wrong — document to prevent recurrence |
| `best_practice` | Proven approach to adopt going forward |
| `client_preference` | Client-specific preferences or requirements |
| `technical_note` | Technical fact, configuration, or gotcha |
| `general` | Catch-all |

### Learning Source Attribution

AI-Prowler automatically stamps the identity of whoever recorded a learning — no manual action required.

- **Personal mode** — owner name from Settings is stamped in the `source` field automatically.
- **Server mode** — the authenticated employee's name is resolved from their bearer token and stamped in the `recorded_by` field. If no name is configured, falls back to their role (e.g. `field_crew`).

Attribution appears in `list_learnings` and `search_learnings` output so you always know the provenance of each learning.

### File Locations

- Learnings data: `~/.ai-prowler/ai_prowler_learnings.json`
- ChromaDB collection: `ai_prowler_learnings` (inside the main RAG database folder)

---

## 23. Welcome Page & Update Notifications

### Welcome Tab

The Welcome tab is the first screen when AI-Prowler launches. It shows version information, What's New, quick-start links, and update notifications.

### Update Push Notifications

AI-Prowler checks for updates on launch by reading a version file from the public GitHub repository. If a newer version is available, a notification banner appears with a download link. No automatic updating occurs — you must download and run the new installer manually.

### Footer Text

The footer at the bottom of the Welcome tab can be customized by the AI-Prowler admin via a push to the public GitHub `welcome_ad.json` file. The default text is shown until the network fetch completes.

### Newsletter Opt-In

A dismissible banner — "📬 Get AI-Prowler updates and usage tips by email" — appears on the Home tab for anyone not already subscribed. Enter an email and click Subscribe, or click the ✕ to dismiss it for the current session (it reappears next launch, since it only fully disappears once you've actually subscribed).

**Double opt-in (v8.1.1):** clicking Subscribe doesn't add you to the mailing list immediately. It sends a confirmation email first, and the banner changes to "📬 Check your email to confirm your subscription" with a **Dismiss** checkbox next to it. You're only added to the active list once you click the confirmation link in that email — this protects against typos in the email field and confirms the address is actually reachable. Checking Dismiss hides the reminder permanently (not just for the session); if you want it back — for example, to resubscribe with a different address — use **Reset Newsletter State** in Help → Notification Status, which clears your local subscription state entirely and brings back the original Subscribe form.

This is a separate, purely opt-in mailing list — independent of licensing or telemetry. Subscribing or not has no effect on which features are available, and unsubscribing (via the link in any newsletter email) doesn't affect your license or account in any way.

---

## 24. Heartbeats & Analytics

### Anonymous Daily Heartbeat

AI-Prowler sends a small daily anonymous heartbeat to a Cloudflare Worker so the developer can see how many installs are active and which versions are deployed.

**What's sent:**
- A random `install_id` (UUID, generated once per install, never tied to a name or email)
- AI-Prowler version — the actual `edition` from `config.json` (`home`, `personal`, or `business`)
- `mode` — the actual mode from `config.json` (`personal` or `server`)
- OS string (e.g. `Windows 11 64-bit`)
- Number of chunks currently indexed
- Number of MCP tool calls in the last 24 hours (total count only, no per-tool detail)

**What is NEVER sent:**
- Your name, email, or IP address
- Document content, queries, or file paths
- Bearer tokens or any credentials
- Self-learning data
- SMS message content

### How to Turn Off

Set `"heartbeat_enabled": false` in `config.json` and restart AI-Prowler.

### Heartbeat Schedule

- First heartbeat: ~5 minutes after first launch
- Subsequent: every 24 hours
- Server-side 12-hour throttle prevents duplicates

---

## Appendix A — MCP Protocol Version Notes

AI-Prowler uses Streamable HTTP transport for Claude.ai and stdio transport for Claude Desktop.

| Feature | Requires |
|---|---|
| Basic tool calls | mcp >= 1.0 |
| `stateless_http` in FastMCP constructor | mcp >= 1.2.0 |
| Streamable HTTP transport | mcp >= 1.1.0 |

To upgrade: `pip install --upgrade mcp`

---

## Appendix B — Privacy Details

**What stays on your machine:**
- All document content
- The ChromaDB vector database
- All embeddings
- Bearer tokens and credentials
- The AI-Prowler configuration
- Self-learning knowledge base
- SMS inbox and thread logs

**What leaves your machine:**
- Text of retrieved document chunks (when Claude processes them)
- Anonymous daily heartbeat (install_id, version, edition, mode, OS, chunk count, tool call count)
- Subscription check (reads public registry from GitHub — no data sent)
- Update check (read-only version check)
- Outbound SMS/email content (sent via your configured provider: Twilio, SendGrid, SMTP, etc.)

**What is never sent:**
- Original document files
- Full document content
- Bearer tokens or credentials
- Self-learning data
- SMS message content to AI-Prowler servers (messages go provider → recipient directly)

---

## Appendix C — Python Dependencies

| Package | Version | Purpose |
|---|---|---|
| chromadb | 1.0.12 | Vector database for document chunks |
| sentence-transformers | 3.3.1 | Embedding model (all-MiniLM-L6-v2) |
| huggingface-hub | 0.26.5 | Model downloads — pinned to avoid Errno 22 bug |
| transformers | 4.44.2 | Tokenizers — pinned for deterministic installs |
| pdfplumber | >=0.10.3 | PDF text extraction |
| python-docx | >=1.1.0 | Word .docx extraction |
| openpyxl | >=3.1.0 | Modern .xlsx Excel extraction |
| xlrd | >=2.0.1 | Legacy .xls Excel extraction |
| python-pptx | >=0.6.21 | PowerPoint .pptx extraction |
| beautifulsoup4 | >=4.12.0 | HTML tag stripping |
| striprtf | >=0.0.26 | RTF control code removal |
| odfpy | >=1.4.1 | OpenDocument .odt extraction |
| pytesseract | >=0.3.10 | OCR wrapper for Tesseract |
| pypdfium2 | >=4.0.0 | PDF page rendering for OCR |
| pillow | >=10.0.0 | Image I/O for OCR |
| extract-msg | >=0.45.0 | Outlook .msg email parsing |
| requests | >=2.31.0 | HTTP requests (subscription checks) |
| uvicorn | >=0.29.0 | ASGI server for HTTP MCP transport |
| twilio | >=8.0.0 | SMS and WhatsApp (Twilio provider) |
| mcp | latest | MCP SDK (FastMCP) for tool server |

> **Note:** `torch` (PyTorch) is intentionally not listed in `requirements.txt`. The installer detects GPU presence and installs the correct build automatically.

---

*AI-Prowler — Your Personal Agentic RAG Knowledge Base*
*Copyright © 2026 David Kevin Vavro · david.vavro1@gmail.com*
*Version 8.0.0 — Updated June 25, 2026 (83 tools · 234 analysis tests)*
