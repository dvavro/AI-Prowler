# AI-Prowler — Complete User Guide

**Version 7.0.0**

---

## Table of Contents

1. [What is AI-Prowler?](#1-what-is-ai-prowler)
2. [Installation](#2-installation)
3. [Connecting Claude Desktop via MCP](#3-connecting-claude-desktop-via-mcp)
4. [Indexing Your Documents](#4-indexing-your-documents)
5. [Agentic RAG — How Claude Uses Your Knowledge Base](#5-agentic-rag--how-claude-uses-your-knowledge-base)
6. [MCP Tools Reference](#6-mcp-tools-reference)
7. [Remote Access — Claude.ai on Mobile and Web](#7-remote-access--claudeai-on-mobile-and-web)
8. [Mobile Subscription Management](#8-mobile-subscription-management)
9. [Business Server Mode — Multi-User Access](#9-business-server-mode--multi-user-access)
10. [Small Business Service Tools](#10-small-business-service-tools)
11. [Quick Links Tab](#11-quick-links-tab)
12. [Settings & Configuration](#12-settings--configuration)
13. [Supported File Types](#13-supported-file-types)
14. [OCR — Scanned Documents & Images](#14-ocr--scanned-documents--images)
15. [Email Indexing](#15-email-indexing)
16. [Scheduling & Automation](#16-scheduling--automation)
17. [GPU Support](#17-gpu-support)
18. [Debugging & Log Files](#18-debugging--log-files)
19. [Troubleshooting](#19-troubleshooting)
20. [Uninstalling](#20-uninstalling)
21. [Self-Learning System](#21-self-learning-system)
22. [Welcome Page & Update Notifications](#22-welcome-page--update-notifications)
23. [Heartbeats & Analytics](#23-heartbeats--analytics)

---

## 1. What is AI-Prowler?

AI-Prowler is an **Agentic RAG (Retrieval-Augmented Generation)** knowledge base for Windows. It indexes your local documents into a private ChromaDB vector database and exposes them to Claude as a suite of intelligent search and retrieval tools.

**The key difference from traditional RAG:**

Traditional RAG retrieves a chunk, hands it to a small local model, and gets a mediocre answer. AI-Prowler's Agentic RAG lets Claude actively drive the research process:

* Claude decides what to search for based on your question
* It evaluates what it finds and identifies gaps
* It reformulates queries and searches again
* It reads surrounding context when a result is incomplete
* It synthesizes a comprehensive answer from everything it gathered

This produces dramatically better results — equivalent to having a skilled research assistant who knows your entire document library.

**Hardware requirements are minimal.** Because Claude does the reasoning, AI-Prowler only needs to run the embedding model (~400 MB RAM) and ChromaDB. No GPU is required. No large local AI model is needed.

**New in v6.0.0 — Self-Learning at full strength:** Claude can record business lessons, fact corrections, project insights, and process improvements into a structured knowledge base — and check that knowledge before answering future questions. Learnings are instant (no GPU training required) and managed through a dedicated 🧠 Learnings tab in the GUI.

**New in v7.0.0:** This is a major release introducing Business Server Mode for multi-user team deployments, plus a comprehensive set of security, management, and tooling improvements:

* **Business Server Mode** — run AI-Prowler on a company server so a whole team reaches one shared knowledge base from Claude on their phones and laptops. Managed through a new 👥 Admin tab.
* **Roles and Scopes** — four user roles (owner, manager, staff, field\_crew) with fine-grained data-access scopes that control what each employee can search. Scopes are defined by you to match your business structure (e.g. `scope:sales`, `scope:office`, `scope:field`).
* **Role-based tool access (Tier B)** — tools are gated per role in server mode. owner and manager get full database management; staff get limited indexing; field\_crew get field-service tools only.
* **Tier A tool suppression** — 28 developer/operator tools (code execution, host filesystem write, configure\_email, etc.) are hidden from the MCP tool list entirely when running in server mode. They never appear for any role in server mode — they are registered only on personal installs.
* **Email tools** — `configure_email`, `send_email`, `send_alert`, `send_file`, `send_learnings_report` using Python's built-in SMTP library. Available on personal installs; not exposed in server mode.
* **Dev tools** — `compile_check`, `check_python_import`, `syntax_check`, `lint_check`, `run_script`, `run_script_start`, `run_script_status`, `run_script_kill` — available on personal installs; suppressed in server mode.
* **Code Tools (Write-Side)** — `create_file`, `write_file`, `str_replace_in_file`, `create_directory`, `list_directory`, `copy_to_backup`, `list_backups`, `restore_backup`, `reset_write_counter` — available on personal installs; suppressed in server mode.
* **Database management** — Settings tab Database section now has three distinct buttons: **View Statistics** (shows all ChromaDB collections including any server-mode scoped ones), **Clear Database only** (wipes all document collections but keeps your tracked-directories list and learnings), and **Clear Database + Database list** (full wipe including tracked directories).
* **Mobile Activation** — the machine-activation panel in Settings is now hidden in server mode (irrelevant for server installs) and correctly documented as 1 machine per install for personal mode. The **Transfer to This Machine** button atomically releases the old machine and activates the new one — the right tool when replacing your computer.
* **Admin tab security** — bearer tokens in the Admin tab are fully masked (●●●●●●●●) in the user table, masked while typing in the Add User dialog, and masked by default in the Show Token dialog with a Reveal toggle.
* **Telemetry accuracy** — the daily heartbeat now sends the actual `edition` and `mode` from config.json rather than a hardcoded `home` value, so your analytics correctly distinguish home, mobile, and business installs.
* **Windows 11 required** — Windows 10 is not supported. The installer requires Windows 11 (64-bit).
* **Binary file write** — `create_file` and `write_file` now accept `encoding="base64"` to write binary files (`.docx`, `.xlsx`, `.pdf`, `.png`, `.zip`, etc.) directly to your machine from Claude. Claude generates the file, base64-encodes it, and AI-Prowler decodes and writes it — no download step needed.
* **Script execution tools** — four new Dev Tools (personal installs only): `run_script` (blocking, short scripts), `run_script_start` (async background job launcher), `run_script_status` (poll progress + log tail), `run_script_kill` (terminate running job). Supports `.bat`, `.cmd`, `.py`, `.js`, `.sh`, `.rb`, `.pl`, `.go`, `.c`, `.cpp`, `.java`. Never runs elevated.
* **Script content preview** — before executing any script, AI-Prowler shows Claude the first 50 lines of the script content so Claude's built-in values apply before any execution occurs.
* **Learning source attribution** — `record_learning` automatically stamps the owner's name into the `source` field on personal installs (reads from Settings). Server mode stamps the authenticated employee's name into `recorded_by`. No action required from Claude or the user in either case.
* **Total tools: 63** — up from 60; net +4 execution tools, `pytest_check` removed (replaced by `run_script` family).

---

## 2. Installation

### Quick Start

1. Download `AI-Prowler\_INSTALL.exe` from the [Releases page](https://github.com/dvavro/AI-Prowler/releases)
2. Double-click and follow the prompts (admin rights required)
3. The installer automatically sets up:

   * Python 3.11
   * All required Python packages
   * Tesseract OCR engine
   * Claude Desktop
   * Cloudflare Tunnel client
4. Sign in to Claude Desktop when it opens and pin it to the taskbar for quick access if you don't plan to activate mobile.
5. Click the AI-Prowler shortcut on your Desktop. For mobile/web access, click **Start HTTP Server** in the Settings tab but you first need a license key from AI-Prowler service after subscribing to mobile. Note when running in mobile mode is recommended to open Claude by https://claude.ai for desktop and remote access such as Cell, tablet, Web.
6. Open Claude Desktop — it will communicate directly with AI-Prowler via the MCP interface. If mobile is activated you should receive an email with a license key and instructions to enable it.

### What the Installer Does NOT Do

**No large local AI model is installed or downloaded.** The AI interface is Claude Desktop (or Claude.ai for mobile/web) via MCP, which requires no local model. AI-Prowler only runs the small embedding model (~400 MB) and ChromaDB locally; Claude does all the reasoning.

This makes installation significantly faster — typically under 10 minutes.

### Install Log

The full installation log is saved to:

```
%LOCALAPPDATA%\Temp\AI-Prowler\install_log.txt
```

This is useful for diagnosing installation failures.

### First Launch

After install, AI-Prowler opens automatically. Claude Desktop is also installed. On first use:

1. Go to Quick links Tab in AI-Prowler and hit Launch Claude Desktop button and verify it shows "AI-Prowler" in the MCP tools panel (Desktop should find it automatically).
2. In AI-Prowler, go to **Index Documents** and add your first document folder (if you skip this step Claude may complain about the database not being available).
3. In Claude Desktop, create a free account in Claude, Go to Quick Links and copy the Initial Connection test command and paste (ctrl v) and then you can ask a question about your documents that you just indexed.
4. For Mobile Access or Web access consider subscribing to Mobile. You will have to upgrade your Claude account to Pro paid tier to get Web based MCP support. In addition to all of the Claude AI capabilities, Mobile operation allows/extends Claude to search your local documents, edit documents, create documents, write code and compile code, record learning, check learning, draft and send email, and small business action tools, and others from the 63 MCP tools all locally to your computer — all with the convenience of voice command or text using the Claude App. For the person who does not want to be chained to their desk it is a great addition to Claude.

### Launch Script (RAG\_RUN.bat)

AI-Prowler is launched via `RAG\_RUN.bat`, which sets two important environment variables before starting the GUI:

* **`PYTHONNOUSERSITE=1`** — prevents Python from loading stale package versions from the Roaming site-packages folder.
* **`HF\_HUB\_CACHE`** — sets the HuggingFace cache path explicitly to avoid the Errno 22 / double-backslash bug on some Windows 10 builds (see Section 19).

These are set automatically; no user action is required.

---

## 3. Connecting Claude Desktop via MCP

Claude Desktop connects to AI-Prowler via the MCP (Model Context Protocol) — a standard that lets Claude use external tools and data sources.

### How It Works

The installer automatically writes AI-Prowler's entry into Claude Desktop's configuration file:

```
%APPDATA%\Claude\claude_desktop_config.json
```

When Claude Desktop starts, it connects to AI-Prowler and discovers all available tools automatically. No manual configuration is needed. Note: if mobile is configured, it is highly recommended that only mobile access will be used for all Claude MCP connections going forward. This includes when in Claude Desktop application. This prevents multiple AI-Prowler MCP Connectors from being used by Claude — one local (Claude connects automatically) and one remote you set up for web access to AI-Prowler.

### Verifying the Connection

Open Claude Desktop and start a new conversation. You should see a tools indicator showing AI-Prowler is connected. Ask:

```
What is the status of AI-Prowler and what AI-Prowler tools do you have available? (note: you can copy this command from the quick links tab in AI-Prowler.)
```

Claude will list all available tools. If you see `get_knowledge_base_overview` and `search_documents`, the connection is working.


### MCP Diagnostics Tool

If tools are not appearing or tool calls are failing in Claude Desktop, use the built-in diagnostics tool:

1. Go to **Settings → Claude Desktop MCP**
2. Click **🔬 Run MCP Diagnostics**
3. A scrollable output window shows: MCP SDK version, tool count, config validity, subscription cache, and log tail.
4. Click **📋 Copy Output** to copy the full report for sharing with AI-Prowler support.

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

* **Add Directory** — index all supported files in a folder
* **Update Index** — re-scan tracked folders for changes
* **Smart Scan** — selects file types and allows preview of what would be indexed without committing
* **Pause / Resume** — stop mid-index and continue later

### Tracking Directories

Directories added for indexing are tracked automatically. The **Update Index** tab re-scans all tracked directories and indexes only what has changed. Set up scheduling (see Section 16) for fully automatic updates.

### Automatic Purge of Deleted Files

When you delete a file from a tracked folder and then run **Update Selected** or **Update All**, AI-Prowler automatically purges that file's chunks from ChromaDB. This keeps the vector database in sync with your file system — no manual cleanup required.

### Mobile Write Zones — Granting Claude Write Access

Indexing a directory makes its contents **searchable**. It does *not* let Claude **modify** files there. Write access is a separate, opt-in permission you grant per directory through the **Update Index** tab.

The tracked-paths listbox shows a write-permission prefix on every row:

```
[W]   C:\Users\david\AI-Prowler-ADMIN
[W*]  C:\Users\david\AI-Prowler_V601_to_V602_work
[R]   C:\Users\david\AI_Evolution\UserManualDOC
[R]   C:\Users\david\OneDrive\Documents\AI-Prowler
```

* `[W]` — **writable.** Claude can create, edit, and delete files anywhere inside.
* `[W*]` — **partially writable.** A narrower sub-directory is granted write access.
* `[R]` — **read-only.** Claude can search content here but cannot modify any file.

**Double-click a row to toggle** between read-only and writable.

Note: Claude will not/cannot delete files and when it modifies a file it creates a backup of that file along side of the file it changed for each change separately, this allows you or Claude to go back to previous versions when needed. After the new files are working or verified, you should manually delete the .bakN files to reduce clutter and free up space. 

---

## 5. Agentic RAG — How Claude Uses Your Knowledge Base

This is the core capability of AI-Prowler. Understanding it helps you get the best results.

### The Research Loop

When you ask Claude a question with AI-Prowler connected, Claude follows this pattern automatically:

```
Step 1 — Orient
  Claude calls: get_knowledge_base_overview()
  Claude learns: what documents are indexed, file types, topics covered

Step 2 — Explore
  Claude calls: list_indexed_documents(filter_ext="pdf")
  Claude learns: which specific files might be relevant

Step 3 — Search
  Claude calls: search_documents("your main topic")
  Claude calls: search_documents("related angle or synonym")
  Claude gathers: relevant chunks from multiple angles

Step 4 — Expand
  Claude calls: get_chunk_context("file.pdf", 12)
  Claude reads: the paragraphs around a promising but incomplete result

Step 5 — Deep Read
  Claude calls: get_document_chunks("contract.pdf", start_chunk=0)
  Claude reads: an entire document sequentially when needed

Step 6 — Synthesize
  Claude writes: a comprehensive answer from everything it gathered
```

### Tips for Best Results

**Ask open-ended research questions.** Claude works best when given latitude to investigate.

**Let Claude finish.** You'll see multiple tool calls before Claude answers. This is the agentic loop working.

**Ask follow-up questions.** Claude retains context within a conversation.

---

## 6. MCP Tools Reference

AI-Prowler exposes **63 tools** to Claude across nine categories. The table below lists every tool with a plain-English description of what it does.

### 6.1 Tool Counts by Mode

The number of tools Claude sees depends on where AI-Prowler is running:

| Install type | Mode | Tools visible | Notes |
|---|---|---|---|
| Personal / Home | personal | **63** | All tools available |
| Business — employee personal install | personal | **63** | Full individual tool set |
| Business — company server | server | **35** | Tier A tools suppressed; remaining tools further gated by role |

**Why the difference?** In server mode, 28 Tier A tools (developer/operator tools) are suppressed at registration time — they never appear in Claude's tool list for any user, regardless of role. This is a server-wide security boundary. The remaining 35 tools are further gated per role (see Role-Based Tool Access below).

### 6.2 Tier A Tool Suppression (Server Mode Only)

The following 28 tools are **never registered** when AI-Prowler runs in server mode. They are completely invisible to any Claude client connecting to the server:

| Category | Suppressed tools |
|---|---|
| Dev / code execution | `compile_check`, `syntax_check`, `lint_check`, `run_script`, `run_script_start`, `run_script_status`, `run_script_kill`, `check_python_import` |
| Host filesystem writes | `create_file`, `write_file`, `str_replace_in_file`, `create_directory`, `copy_to_backup`, `restore_backup`, `list_backups`, `list_directory`, `reset_write_counter`, `grant_write_access`, `revoke_write_access` |
| Raw filesystem reads | `grep_documents`, `read_file_lines` |
| Email operator tools | `configure_email`, `send_file`, `send_learnings_report`, `export_learnings_file` |
| Bulk index rebuild | `rebuild_learnings_index` |

Note: `send_email` and `send_alert` are **not** suppressed in server mode — they remain available to `field_crew` users via the Tier B role gate.

### 6.3 Role-Based Tool Access in Server Mode (Tier B)

After Tier A suppression, the remaining 35 tools are further gated by the user's role:

| Tool group | owner | manager | staff | field\_crew |
|---|---|---|---|---|
| RAG Search (search, overview, list docs, etc.) | ✅ | ✅ | ✅ | ✅ |
| Field Service (weather, geocode, route, maps, spreadsheet) | ✅ | ✅ | ✅ | ✅ |
| Self-Learning (record, check, list, update, delete, stats) | ✅ | ✅ | ✅ | ✅ |
| `check_ai_prowler_status` *(RAG health)*, `how_to_use_ai_prowler` | ✅ | ✅ | ✅ | ✅ |
| `check_tools_status` *(field-service health — see Small Business)* | ✅ | ✅ | ✅ | ✅ |
| `get_database_stats` | ✅ | ✅ | ✅ | ✅ |
| `index_path` (limited indexing — own scopes only) | ✅ | ✅ | ✅ | ❌ |
| `update_tracked_directories`, `untrack_directory` | ✅ | ✅ | ❌ | ❌ |
| `reindex_file`, `reindex_directory`, `reindex_all` | ✅ | ✅ | ❌ | ❌ |
| `send_email`, `send_alert` | ❌ | ❌ | ❌ | ✅ |

**Summary by role:**

| Role | Tool count (server) | Notes |
|---|---|---|
| owner | ~33 | Full access to all 35 registered tools |
| manager | ~33 | Same as owner |
| staff | ~25 | 24 core tools + `index_path` (own scopes only) |
| field\_crew | ~26 | 24 core tools + `send_email` + `send_alert` |

---

### 6.4 Complete Tool Reference Table

#### Agentic RAG — Knowledge Base Search (10 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `how_to_use_ai_prowler()` | Returns the recommended workflow and tool sequence. Claude calls this automatically at the start of research sessions. | Personal + Server |
| `get_knowledge_base_overview()` | High-level summary of the knowledge base: document count, file types, chunk count, database location, and tracked directories. **Start here** before any research task. | Personal + Server |
| `search_documents(query, n_results, min_similarity)` | Primary retrieval tool. Performs semantic vector search and returns raw document chunks with source metadata and similarity scores. | Personal + Server |
| `multi_query_search(queries, n_results_each, min_similarity)` | Runs 2–6 search queries in parallel and returns deduplicated results ranked by best similarity. More efficient than calling `search_documents` multiple times for multi-angle topics. | Personal + Server |
| `expand_search_result(filename, chunk_index, window)` | Fetches the chunks immediately before and after a specific result chunk — use when a result is cut off at a boundary and you need more context. | Personal + Server |
| `read_document(filename, start_chunk, max_chunks)` | Reads a full document in sequential chunk order. Best for contracts, manuals, and reports where you need the whole text, not just search fragments. | Personal + Server |
| `list_indexed_documents(filter_ext, filter_path, limit)` | Browses all indexed documents grouped by file type, with chunk counts. Use to discover what's in the knowledge base. | Personal + Server |
| `list_indexed_directories()` | Directory tree of all indexed content with document counts per folder. Use to scope a search to the right folder. | Personal + Server |
| `grep_documents(pattern, filter_path, context_lines, max_results, regex)` | Exact text or regex search across tracked files with real line numbers. Use when semantic search returns irrelevant results for code or structured text. | Personal |
| `read_file_lines(filepath, start_line, end_line)` | Reads an exact line range from a file. Pair with `grep_documents` — grep locates, this extracts. | Personal |

#### Knowledge Base Management (5 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `index_path(directory, recursive, track)` | Indexes all supported documents in a folder (or a single file) and optionally adds the path to the auto-update tracking list. | Personal + Server |
| `update_tracked_directories()` | Re-scans all tracked paths and re-indexes only new or changed files. | Personal + Server |
| `list_tracked_directories()` | Lists every path (directory or individual file) currently registered for auto-update tracking. | Personal + Server |
| `untrack_directory(directory)` | Removes a path from the tracking list and deletes all its chunks from ChromaDB. Destructive — chunks are gone until re-indexed. | Personal + Server |
| `get_database_stats()` | Chunk count, unique document count, and file-type breakdown for the ChromaDB index. In server mode shows scoped collections separately. | Personal + Server |

#### Indexing — Reindex Tools (3 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `reindex_file(filepath)` | Purges and rebuilds the ChromaDB index for a single file. Call once after finishing edits to a file. | Personal + Server |
| `reindex_directory(directory, purge_first)` | Fully purges and rebuilds the index for one tracked directory. More thorough than `update_tracked_directories`. | Personal + Server |
| `reindex_all(purge_first)` | Nuclear option — wipes and rebuilds the entire ChromaDB index from scratch across all tracked directories. | Personal + Server |

#### Self-Learning Knowledge Base (10 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `record_learning(title, content, category, ...)` | Saves a new lesson, fact, client preference, or business insight to the self-learning store. Instantly indexed in ChromaDB. In server mode the recording employee's name is automatically stamped in the `recorded_by` field. | Personal + Server |
| `search_learnings(query, n_results, category, include_deprecated)` | Semantic search of the learning store. Claude calls this proactively before answering questions so personal knowledge overrides generic responses. | Personal + Server |
| `list_learnings(category, status, tag, limit)` | Browses learnings by recency with exact-match filters on category, status, or tag. | Personal + Server |
| `update_learning(learning_id, updates)` | Edits any field of an existing learning — content, confidence, outcome, status, tags. | Personal + Server |
| `delete_learning(learning_id)` | Permanently removes a learning from both JSON and ChromaDB. Consider archiving instead. | Personal + Server |
| `get_learning_stats()` | Summary statistics: totals by category, source, outcome, and status. Most frequently applied learnings included. | Personal + Server |
| `get_learnings_report(category, status, format)` | Returns learnings as formatted text in-conversation (summary, full detail, or titles-only). No desktop required — works on mobile. | Personal + Server |
| `rebuild_learnings_index()` | Rebuilds the ChromaDB learnings index from the JSON data file. Fixes index/data mismatches. | Personal |
| `export_learnings_file(filepath, format, category, include_inactive)` | Exports learnings to a `.aiplearn` pack (importable by other installs) or `.csv` spreadsheet. | Personal |
| `send_learnings_report(to, category, subject, include_inactive)` | Emails a formatted HTML learnings report in one step. Combines `get_learnings_report` and `send_email`. | Personal |

#### Small Business Action Tools (7 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `get_weather(location, days)` | Current conditions and multi-day forecast. Uses Open-Meteo and Nominatim — free, no API key. Rain probability ≥ 50% is flagged. | Personal + Server |
| `geocode_address(address)` | Converts a street address to GPS coordinates via Nominatim / OpenStreetMap — free, no key. | Personal + Server |
| `optimize_route(stops, origin, optimize_for, departure_hour, return_to_origin)` | Solves the Traveling Salesman Problem for a list of job stops using real street routing via OSRM. Returns stops in optimal order with estimated arrival times. | Personal + Server |
| `build_maps_url(stops, origin, app)` | Generates a tap-to-navigate Google Maps (or Apple Maps) URL with all stops pre-loaded in optimized order. For routes over 9 stops, splits into multiple leg links automatically. | Personal + Server |
| `read_job_spreadsheet(filepath, sheet_name, filter_date, max_rows)` | Reads job data from the AI-Prowler Job Tracker `.xlsx` spreadsheet. Supports date filtering to show today's or a specific day's jobs. | Personal + Server |
| `update_job_spreadsheet(job_identifier, updates, filepath, id_column, sheet_name, backup)` | Updates a row in the job tracker after a job is completed — status, invoice number, duration, actual amount, etc. Auto-backs up the spreadsheet before writing. | Personal + Server |
| `check_tools_status()` | **Field-service health check.** Reports which action tools are ready to use and which need configuration (SMTP, spreadsheet path, etc.). Use this when setting up email or before a field day to confirm routing and weather tools are live. | Personal + Server |

#### Email Tools (5 tools)

Most email tools are **personal mode only**, but `send_email` and `send_alert` are also available in **server mode** to `field_crew` users (see Section 6.3). The operator-level tools (`configure_email`, `send_file`, `send_learnings_report`) are Tier A suppressed and never available on a shared server. See Section 6.5 below for SMTP setup instructions.

| Tool | What It Does | Mode |
|---|---|---|
| `configure_email(smtp_host, smtp_port, username, password, ...)` | Saves SMTP credentials so Claude can send email. Auto-detects provider from email domain. Called once; credentials persist across sessions. | Personal only |
| `send_email(to, subject, body, attachment_path)` | Sends an email via the configured SMTP account. Optional file attachment from any tracked directory. | Personal + Server (field\_crew) |
| `send_alert(message, to)` | Fires a quick one-line alert email — subject auto-generated from the message. Great for voice-commanded notifications. | Personal + Server (field\_crew) |
| `send_file(filepath, to, subject, body)` | Sends any tracked file as an email attachment. Auto-generates subject from the filename if not specified. | Personal only |
| `send_learnings_report(to, category, subject, include_inactive)` | Emails a formatted HTML learnings report. See Self-Learning section above. | Personal only |

#### Write Zone Management (2 tools — Personal Installs Only)

| Tool | What It Does | Mode |
|---|---|---|
| `grant_write_access(directory)` | Adds a directory to the write-zone allowlist so Claude can create and edit files there. The directory must already be in the read allowlist. | Personal |
| `revoke_write_access(directory)` | Removes a directory from the write allowlist. Read access is unaffected. | Personal |

#### Code Tools — Write-Side (11 tools — Personal Installs Only)

All write operations are protected by four independent layers: read allowlist, writable allowlist, hard blocklist, and per-session circuit breaker. **Suppressed in server mode.**

| Tool | What It Does | Mode |
|---|---|---|
| `create_file(filepath, content)` | Creates a new file. Fails if the file already exists. | Personal |
| `write_file(filepath, content, verify_after_write)` | Overwrites an existing file. Auto-backs up to `<filepath>.bak<N>` before writing. | Personal |
| `str_replace_in_file(filepath, old_str, new_str, dry_run)` | Surgical in-place edit: replaces one unique occurrence of `old_str`. 1000× cheaper than a full file rewrite for large files. `dry_run=True` previews the diff before committing. | Personal |
| `create_directory(dirpath)` | Creates a directory and any missing parents. Idempotent. | Personal |
| `list_directory(dirpath, show_hidden)` | Lists the immediate contents of a directory: files, subdirectories, and `.bak<N>` backups. Read-only. | Personal |
| `copy_to_backup(filepath)` | Takes a manual snapshot of a file as `<filepath>.bak<N>` without modifying the original. | Personal |
| `list_backups(filepath)` | Lists all `.bak<N>` backups for a given file with timestamps and sizes. | Personal |
| `restore_backup(filepath, backup_number)` | Overwrites the active file with the contents of the specified `.bak<N>` backup. | Personal |
| `cleanup_backups(path, dry_run)` | Finds and optionally deletes `.bakN` backup files. Always run with `dry_run=True` first to preview. | Personal |
| `reset_write_counter()` | Resets the per-session 20-write circuit breaker so large editing sessions can continue without restarting the server. | Personal |
| `list_writable_directories()` | Lists all directories currently in the write-zone allowlist along with the read allowlist for reference. | Personal |

#### Dev Tools (8 tools — Personal Installs Only)

Eight tools for code verification and script execution. **Suppressed in server mode.**

**Verification tools** (check code without running it):

| Tool | What It Does | Mode |
|---|---|---|
| `compile_check(filepath, timeout_sec)` | Byte-compiles a Python file to catch syntax errors. Equivalent to `python -m py_compile`. | Personal |
| `check_python_import(module_or_path, timeout_sec)` | Imports a Python module in a separate process to catch load-time errors that `compile_check` misses (NameError, ImportError, bad module-level references). | Personal |
| `syntax_check(filepath, timeout_sec)` | Multi-language syntax checker. Supports Python, JavaScript, TypeScript, C, C++, Go, Java, Perl, Ruby, PHP, Bash, Verilog, SystemVerilog, VHDL. | Personal |
| `lint_check(filepath, timeout_sec)` | Multi-language linter — catches unused imports, undefined names, and style issues. Uses pyflakes (Python), tsc (TypeScript), go vet (Go), ghdl -a (VHDL). | Personal |

**Execution tools** (actually run scripts and programs):

| Tool | What It Does | Mode |
|---|---|---|
| `run_script(script_path, args, timeout_sec, max_output_lines)` | Runs a script synchronously and returns combined stdout+stderr. **Always shows a content preview of the script (first 50 lines) before executing** — this puts the script in Claude's context so Claude's built-in values apply before any execution occurs. Best for short scripts under ~60 seconds. Supports `.bat`, `.cmd`, `.py`, `.js`, `.sh`, `.rb`, `.pl`, `.go`, `.c`, `.cpp`, `.java`. Never elevated — runs as current user only. | Personal |
| `run_script_start(script_path, args, timeout_sec)` | Launches a script as a **background job** and returns a `job_id` immediately. **Also shows a content preview before launching** for the same transparency reason. Use for long-running tasks (full test suites, builds) that would time out the MCP connection. Timeout defaults to 30 minutes. | Personal |
| `run_script_status(job_id, tail_lines)` | Checks the status of a background job and returns a tail of its log output. Status values: `running`, `done`, `failed`, `timeout`, `error`, `killed`. Call repeatedly to poll progress. | Personal |
| `run_script_kill(job_id)` | Terminates a running background job and all its child processes. Updates the manifest to `killed` and returns the final log tail. | Personal |

> **Tip:** Use `run_script` for quick one-off executions. Use `run_script_start` + `run_script_status` for anything that takes more than a minute — including the full test suite (`run_script_start("run_tests.bat")`). Pass pytest `-k` filters via the `args` parameter: `run_script_start("run_tests.bat", args="tests\\mcp\\ -k binary_write")`.

#### Status & System (2 tools)

> **Two different status tools — know which to call:**
> - `check_ai_prowler_status()` → RAG engine health (ChromaDB, embedding model, chunk count). Call this if Claude can't find documents or the knowledge base seems broken.
> - `check_tools_status()` → Field-service tool readiness (SMTP, spreadsheet path, routing APIs). Call this when setting up email or before a field day. Lives in the Small Business section above.

| Tool | What It Does | Mode |
|---|---|---|
| `check_ai_prowler_status()` | **RAG engine health check.** Verifies ChromaDB connectivity, embedding model status, chunk count, and tracked paths. Call this if document search isn't working or the knowledge base seems broken. | Personal + Server |
| `how_to_use_ai_prowler()` | Returns the recommended Agentic RAG workflow and tool-call sequence. Call this at the start of any new research session. | Personal + Server |

---

### 6.5 Email Tool Setup

#### How to Configure Email (Personal Installs)

On a personal install, email is configured by telling Claude your credentials in a conversation. Claude calls `configure_email()` once and your credentials are saved to `~/.ai-prowler/email_config.json`. You never need to call the tool manually.

**Example — just tell Claude:**
```
Configure my email. My address is dave@gmail.com and my app password is abcd efgh ijkl mnop
```

Claude handles the rest — it detects your provider from the email domain and sets the correct SMTP host and port automatically.

> **Important: Use an App Password, not your regular email password.** Most providers block SMTP login with your main password for security reasons. An App Password is a special one-time code generated in your account security settings. Your regular password is never used.

---

#### Getting an App Password — By Provider

##### Gmail

**Requirements:** Google account with 2-Step Verification enabled. (If 2-Step Verification is off, Google blocks all third-party SMTP access regardless.)

**Direct link:** https://myaccount.google.com/apppasswords

**Steps:**
1. Go to the link above (you must be signed in)
2. Under "Select app" choose **Mail**, under "Select device" choose **Windows Computer**
3. Click **Generate** — Google shows a 16-character password (e.g. `abcd efgh ijkl mnop`)
4. Copy it immediately — it is only shown once
5. Use this password when telling Claude to configure email. Spaces in the password are optional.

**SMTP settings Claude will use:**
- Host: `smtp.gmail.com` · Port: `587` · Security: STARTTLS

> **Google Workspace (company Gmail) note:** Your IT administrator may need to enable "Less secure app access" or create an App Password policy. Contact your IT department if the App Password option is not visible.

---

##### Outlook / Microsoft 365 (Personal Account)

**Requirements:** Microsoft account with two-step verification enabled.

**Direct link:** https://account.microsoft.com/security

**Steps:**
1. Go to the link above and sign in
2. Click **Advanced security options**
3. Scroll to **App passwords** → click **Create a new app password**
4. Microsoft generates a password — copy it immediately
5. Use this password when telling Claude to configure email

**SMTP settings Claude will use:**
- Host: `smtp.live.com` · Port: `587` · Security: STARTTLS

---

##### Microsoft 365 Work / School Account (Office 365)

**Requirements:** Your IT administrator must have SMTP AUTH enabled for your account. App passwords for work accounts are controlled at the tenant level.

**Direct link:** https://admin.microsoft.com (IT admin only)

**Steps for users:**
1. Ask your IT administrator to enable SMTP AUTH for your account
2. Once enabled, you can use your regular Microsoft 365 password for SMTP (or IT may issue an app password)
3. Tell Claude: `Configure email with address dave@company.com, password is [your password or app password]`

**SMTP settings Claude will use:**
- Host: `smtp.office365.com` · Port: `587` · Security: STARTTLS

---

##### Yahoo Mail

**Requirements:** Yahoo account with two-step verification enabled.

**Direct link:** https://login.yahoo.com/account/security

**Steps:**
1. Go to the link above and sign in
2. Scroll to **Generate app password**
3. Select **Other App** from the dropdown, name it `AI-Prowler`
4. Click **Generate** — copy the password shown

**SMTP settings Claude will use:**
- Host: `smtp.mail.yahoo.com` · Port: `587` · Security: STARTTLS

---

##### Apple iCloud Mail

**Requirements:** Apple ID with two-factor authentication enabled.

**Direct link:** https://appleid.apple.com

**Steps:**
1. Go to the link above and sign in
2. Under **Sign-In and Security** → **App-Specific Passwords** → click **+**
3. Name it `AI-Prowler` and click **Create**
4. Copy the generated password (format: `xxxx-xxxx-xxxx-xxxx`)

**SMTP settings Claude will use:**
- Host: `smtp.mail.me.com` · Port: `587` · Security: STARTTLS

---

#### How to Configure Email in Server Mode

In server mode, the `configure_email` MCP tool is suppressed — it is not available to any Claude user regardless of role. Instead, email is configured directly in the AI-Prowler GUI:

1. Connect to the server via Remote Desktop
2. Open AI-Prowler → **Settings** tab → **📧 Email Configuration** section
3. Enter your SMTP credentials (same app password process as above)
4. Click **💾 Save Config**
5. Click **📧 Test Connection** to verify — a test email arrives in your inbox

This server-wide email configuration is used for:
- **Token recovery** — "Forgot your token?" sends a recovery code to the admin's email or phone
- **Send Token Email** — the Admin tab button that emails an employee their bearer token
- **field\_crew send\_email / send\_alert** — outbound notifications from field technicians

---

#### Who the Recipient Sees When field\_crew Sends Email

When a field crew member uses `send_email` or `send_alert` from Claude.ai, the email is sent using the **server's configured SMTP credentials** — the same email account the admin set up. However, AI-Prowler automatically personalises the email using the employee's registered name and email address from the Admin tab user record.

**What the recipient sees:**

| Header | Value | Where it comes from |
|---|---|---|
| **From** (display name) | `Jake Smith via ABC Window Cleaning` | Employee name + server from\_name |
| **From** (address) | `service@abcwindows.com` | Server SMTP address (required for sending) |
| **Reply-To** | `jake.smith@gmail.com` | Employee's email from their user record |

**The Reply-To header is the key feature.** When the customer clicks Reply in their email app (Gmail, Outlook, Apple Mail, or any mobile client), the reply goes directly to the employee's personal email — not to the generic company inbox. The employee gets the customer's reply on their phone just like any normal email.

**What this requires:** The employee must have their personal email address entered in their user record in the Admin tab. If no email is registered, the email sends with the company name only and no Reply-To (same behaviour as before this feature was added).

**How it looks in the customer's inbox:**

```
From:     Jake Smith via ABC Window Cleaning
          <service@abcwindows.com>
Reply-To: Jake Smith <jake.smith@gmail.com>
Subject:  Job Complete - Miller Residence
```

Customer hits Reply → the reply goes to `jake.smith@gmail.com` directly.

**Graceful fallback:** If the employee has no email on record, nothing breaks — the email sends with the company name only, exactly as before.

---

#### Email Tool Reference

#### `configure_email(smtp_host, smtp_port, username, password, from_name, default_to)` *(personal only)*
Call once to save SMTP credentials. On personal installs, tell Claude your email address and app password — it fills in the SMTP settings automatically from your email domain.

#### `send_email(to, subject, body, attachment_path)`
Sends a plain-text email. Available to `field_crew` in server mode; available to all roles on personal installs.

#### `send_alert(message, to)`
Sends a short one-line notification email. Available to `field_crew` in server mode.

#### `send_file(to, filepath, subject, body)` *(personal only)*
Sends a file from a tracked directory as an email attachment.

#### `send_learnings_report(to, category, subject, include_inactive)` *(personal only)*
Sends learnings as a formatted HTML email table.

### Learnings Export Tools

#### `get_learnings_report(category, status, format)`
Returns learnings as formatted text in the conversation. No file created.

#### `export_learnings_file(filepath, format, category, include_inactive)` *(personal only)*
Exports learnings to a file in a writable zone. Formats: `pack` (`.aiplearn` JSON) or `csv`.

#### `rebuild_learnings_index()` *(personal only)*
Rebuilds the ChromaDB learnings index from the JSON data file.

### Write Zone Management Tools

#### `list_writable_directories()`
Returns all directories in the writable allowlist with `[W]` indicators.

#### `grant_write_access(directory)` *(personal only)*
Adds a directory to the writable allowlist. The directory must already be tracked.

#### `revoke_write_access(directory)` *(personal only)*
Removes a directory from the writable allowlist.

### Reindex Tools

#### `reindex_file(filepath)`
Re-indexes a single file in ChromaDB.

#### `reindex_directory(directory, purge_first)`
Re-indexes a single tracked directory. With `purge_first=True` (default), all existing chunks are deleted first.

#### `reindex_all(purge_first)` *(owner/manager only in server mode)*
Re-indexes all tracked directories.

---

## 7. Remote Access — Claude.ai on Mobile and Web

The Remote Access feature lets you use AI-Prowler with Claude.ai from any device — your phone, tablet, or any web browser — using the same agentic RAG capability as Claude Desktop.

### Architecture

```
Your Phone/Browser
       ↓ HTTPS
Claude.ai
       ↓ MCP (HTTP + OAuth 2.0 + PKCE)
Cloudflare Tunnel (public HTTPS URL)
       ↓ localhost
AI-Prowler HTTP Server (on your PC)
       ↓
ChromaDB (your local documents)
```

### Setup Steps

1. **Set a Bearer Token** — In Settings → Remote Access, enter a Bearer token (minimum 10 characters, mixed case and numbers). Click **Save Token**.
2. **Start the HTTP Server** — Click **▶ Start HTTP Server**. The status light turns green.
3. **Set up a Named Tunnel** — For permanent daily use, set up a Named Tunnel with your own domain (see below).
4. **Connect Claude.ai** — Add your tunnel URL as a custom connector in Claude.ai Settings → Connectors.

### Status Lights

* **Internet ●** — green when your PC can reach GitHub
* **Mobile Subscription ●** — green = active; yellow = expiring/grace; red = blocked/unregistered

### Named Tunnel Setup (Permanent)

A Named Tunnel gives you a permanent, branded URL (e.g. `https://mobile.your-company.com/mcp`).

**Prerequisites:** AI-Prowler subscription will provide you with a free Cloudflare account (max up to 50 tunnels for the free account) and a domain name added to Cloudflare.

**One-time setup:**

1. In Settings → Remote Access → Named Tunnel, enter your **Public hostname** and **Tunnel token** (from Cloudflare Zero Trust dashboard → Networks → Tunnels → your tunnel → Token).
2. Click **Activate Tunnel Service** — this installs cloudflared as a Windows background service.
3. The status shows **Tunnel active (Windows service)** with a green dot.

After this one-time setup, the tunnel starts automatically at boot. Use **Start Tunnel** / **Stop Tunnel** to control it manually.

### Connecting Claude.ai — Step by Step

1. Open [claude.ai](https://claude.ai) and sign in (Claude Pro or Team required)
2. Click your profile icon → **Settings** → **Connectors** → **Add custom connector**
3. Enter your tunnel URL followed by `/mcp` (e.g. `https://your-name.your-company.com/mcp`)
4. Claude.ai redirects you to your AI-Prowler authorization page
5. Enter your Bearer token and click **Connect**

---

## 8. Mobile Subscription Management

### Subscription Plans

| Plan | Price | Users | Use Case |
|---|---|---|---|
| Individual | $10/month | 1 | Personal use |
| Small Business | $20/month | Up to 50 | Team deployment |
| Enterprise | Contact us | 6+ | Custom deployment |

### How to Subscribe

Email david.vavro1@gmail.com with:

* Your name or company name
* Which plan you want

### Grace Period

If your subscription lapses, a 30-day grace period begins. After 30 days, access is suspended until renewal.

### Mobile Activation — Machine Management

Your personal AI-Prowler subscription activates on **1 machine at a time**. The **Mobile Activation** section in Settings shows your current activation status and provides tools for machine management.

| Button | Purpose |
|---|---|
| **Check Activation** | Checks whether this machine is the active install. Shows activation status from the cloud registry. |
| **Transfer to This Machine** | Moves your subscription to this machine. Use when replacing your computer. Atomically releases the old machine and activates the new one. |

**How to replace your computer:**
1. On the new machine, install AI-Prowler and enter your Bearer token in Settings → Remote Access.
2. Click **Check Activation** — this shows that the old machine is currently active.
3. Click **Transfer to This Machine** — a confirmation dialog shows the previous machine ID and this machine ID.
4. Confirm — the old machine is released and this machine is activated in one step.
5. The old machine's remote access is immediately disabled.

> **Note:** The Mobile Activation panel does **not** appear in Business server mode — server installs are not machine-limited. The parent license key can be entered on a replacement server without any transfer step.

---

## 9. Business Server Mode — Multi-User Access

Business edition can run AI-Prowler in **server mode** on a company machine, so a whole team reaches one shared knowledge base from Claude on their phones and laptops.

### The Big Picture

A Business license is a **parent key** plus a pool of **child seat keys** (one per employee). The same child key works in two independent places:

1. **The company server** — the owner runs one AI-Prowler in server mode. Each employee is added as a user there, assigned a child seat, and given a personal bearer token. They reach the shared company knowledge base via Claude.ai on their phone or laptop using the company's Cloudflare Tunnel URL.
2. **A personal install (optional)** — the same employee can install AI-Prowler on their own laptop, activate it with the same child key in **personal mode**, and index their own private documents. They get their own Cloudflare Tunnel and their own Claude.ai connector pointing to their personal install — giving them mobile access to their private knowledge base via Claude.ai, completely separate from the company server.

These two are completely separate AI-Prowler instances with separate knowledge bases. The child key ties them to the company's license but does not share data between them.

### Edition and Mode

Two runtime settings in `~/.ai-prowler/config.json` decide how an install behaves:

| Setting | Values | Meaning |
|---|---|---|
| `edition` | `home` / `mobile` / `business` | License tier |
| `mode` | `personal` / `server` | Deployment mode |

The **Admin tab** appears only when `edition=business` AND `mode=server`. A personal-mode install — even one activated with a Business child key — never shows the Admin tab and behaves like a full-featured single-user install.

Note: Configuring server or personal mode must be done after the initial install and before indexing. After that it should not be changed because the Database of the two are not compatible. 

### Roles

Each user on the company server has one of four roles, in descending privilege:

| Role | Description | Manages Users | Tool Access |
|---|---|---|---|
| **owner** | The company account holder. One per company. | ✅ Always | Full (all 35 server-mode tools) |
| **manager** | Senior user. Can be granted delegated admin rights. | ✅ If granted | Full (all 35 server-mode tools) |
| **staff** | Regular employee. | ❌ | 25 tools — core RAG + limited indexing (own scopes only) |
| **field\_crew** | Field employee. | ❌ | 26 tools — core RAG + `send_email` + `send_alert` |

The **Manages Users** (delegated admin) checkbox is only valid for the *manager* role — staff and field\_crew can never be granted it.

### Scopes — Controlling What Each User Can See

**Scopes** are data-access groups you define to match how your business is organized. Each scope corresponds to a named slice of the shared knowledge base. You enter them as a comma-separated list on each user in the Admin tab.

**Scope naming convention:** `scope:name` — for example `scope:sales`, `scope:office`, `scope:field`.

> **Note:** Scopes were called `role:name` in earlier releases (e.g. `role:sales`). They are now named `scope:name` to avoid confusion with user roles. The underlying ChromaDB collections are unchanged — only the display name changed.

**How scopes work:**
* Each scope maps to a dedicated ChromaDB collection on the server.
* When a user searches, their results are limited to the collections their scopes grant access to.
* A user can have multiple scopes (e.g. `scope:sales, scope:office`) to access more than one slice.
* A user can also have a **private collection** — a personal slice only they can search.

**Scope example — a window and pressure washing company:**

| Employee | Role | Scopes | What they can search |
|---|---|---|---|
| David (owner) | owner | `scope:office, scope:field` | Everything |
| Maria (office manager) | manager | `scope:office` | Office documents, invoices, customer records |
| Jake (field crew) | field\_crew | `scope:field` | Job sheets, equipment manuals, cleaning procedures |

In this setup:
* Jake cannot see office financials — they're in `scope:office` which he doesn't have.
* Maria cannot see field-specific job procedures — they're in `scope:field`.
* David as owner sees everything.

Documents are indexed into scopes by the admin — when indexing a folder, you assign it to a scope. The ChromaDB collection for `scope:office` only receives documents the admin has tagged for that scope.

### The Admin Tab (Server Mode Only)

When AI-Prowler runs in business + server mode, a **👥 Admin** tab appears as the last tab. The admin tab requires authentication — enter your bearer token to unlock it.

**Security:** Bearer tokens are fully masked (●●●●●●●●) everywhere in the Admin tab. The table never shows any characters of a user's token. The only time a full token is displayed is in the **Show Token** dialog after clicking 🔑 Regenerate Token — and even then it is masked by default with a **👁 Reveal token** checkbox to prevent shoulder-surfing.

#### Seat Summary Strip

At the top of the Admin tab:
```
Seats: 3/5 used · 2 available  ·  Company key: XXXX-…-XXXX
```

#### Active Users Table

| Column | Description |
|---|---|
| Name | Employee's display name |
| Email | Optional contact email |
| Role | owner / manager / staff / field\_crew |
| Scopes | Comma-separated data-access scopes (e.g. `scope:sales, scope:office`) |
| Manages Users | ✓ if this user has delegated admin rights |
| Private Coll. | ✓ if a private knowledge-base collection is enabled for this user |
| Seat (key) | The masked child license key assigned to this user |
| Status | active or suspended |
| Token | ●●●●●●●● (always masked — use Regenerate Token to issue a new one) |

#### Action Buttons

| Button | Action |
|---|---|
| **➕ Add User** | Opens the Add User dialog to create a new user |
| **✏️ Edit** | Opens the Edit dialog for the selected user |
| **🔑 Regenerate Token** | Issues a new random bearer token — old token stops working immediately. Shows the new token masked with a Reveal checkbox. |
| **🚫 Suspend/Activate** | Toggles active/suspended without deleting the user |
| **🗑 Remove** | Permanently deletes the user and frees their seat |
| **↻ Refresh** | Reloads users.json and repaints the table |

### Adding a User (Step by Step)

1. Click **➕ Add User**
2. Fill in **Name** (required) and **Email** (optional)
3. Choose a **Role** (owner / manager / staff / field\_crew)
4. Enter **Scopes** — comma-separated: e.g. `scope:sales, scope:office`
5. Optionally tick **Can manage users** (managers only) and **Private collection enabled**
6. Assign a **License seat** from the dropdown (unassigned child keys)
7. **Bearer token** — leave blank to auto-generate (recommended). This is the employee's password for connecting from Claude.ai.
8. Click **Save**

### Giving Each Employee Access

Once added, hand them two things:

1. **Their bearer token** — send it securely (not plain email if possible).
2. **The company's Claude.ai connector URL** — your server's Cloudflare Tunnel address (e.g. `https://server.your-company.com/mcp`).

The employee adds that connector in Claude.ai settings, authenticates with their bearer token, and starts a new conversation. No software install required on their side.

### Removing or Suspending Access

* **🚫 Suspend** — disables access immediately; token stops working. Record preserved for audit. Toggle again to re-enable.
* **🗑 Remove** — deletes the user entirely and frees the seat back to the pool.
* **🔑 Regenerate Token** — issues a fresh token if the existing one may have leaked. Old token stops working at once.

### Each Child Seat: Company Access AND a Personal Install

One employee — for example a salesperson with child key `XXXX`:

* **On the company server:** added as `staff` with scope `scope:sales` and a bearer token. From Claude.ai on their phone they search the company's shared sales knowledge base. They cannot see office financials (different scope).
* **On their own laptop (optional):** install AI-Prowler, activate with the same child key in `personal` mode, and index their own documents. This gives them the full 63-tool individual set — search, file read/write in their own folders, dev tools — plus their own mobile access to their personal knowledge base via Claude.ai using their own Cloudflare Tunnel. Nothing here touches the company server; it is their private instance, licensed under the company's umbrella.

### Replacing the Server Machine

If the server machine fails and needs to be replaced:

1. Install AI-Prowler on the new machine
2. Enter the same **Parent License Key** in Settings → Remote Access → Parent License Key and click Save Key
3. Copy `~/.ai-prowler/users.json`, `seats.json`, and `config.json` from the old machine (if recoverable) — or re-enter users manually via the Admin tab
4. Reconfigure the Cloudflare Tunnel on the new machine with the same tunnel token (from Cloudflare Zero Trust dashboard)
5. All employees' Claude.ai connectors continue to work — the URL doesn't change

> **Why no transfer step is needed:** The parent license key has no install_id machine lock. It is validated against your subscription record for validity and seat count only. You can run it on any machine.

### Replacing an Employee's Personal Machine

When an employee gets a new computer and needs to transfer their personal AI-Prowler install:

1. On the new machine, install AI-Prowler and enter their Bearer token in Settings → Remote Access
2. In Settings → Mobile Activation, click **Check Activation** — shows the old machine is currently active
3. Click **Transfer to This Machine** — releases the old machine and activates the new one atomically
4. The employee's Claude.ai connector continues to work (same bearer token)

### Server Mode Configuration File

`~/.ai-prowler/config.json` controls server mode behaviour:

| Field | Values | Description |
|---|---|---|
| `edition` | `home` / `mobile` / `business` | License tier |
| `mode` | `personal` / `server` | Deployment mode |
| `parent_license_key` | string | Company parent key |
| `telemetry_enabled` | `true` / `false` | Controls daily heartbeat |

Edit this file directly to switch modes, then restart AI-Prowler.

### Related Files (Server Mode)

| File | Location | Purpose |
|---|---|---|
| `users.json` | `~/.ai-prowler/users.json` | All user records — the live auth source |
| `seats.json` | `~/.ai-prowler/seats.json` | Delivered seat pool (child keys + total count) |
| `license_warnings.json` | `~/.ai-prowler/license_warnings.json` | Engine-written seat validation warnings |
| `config.json` | `~/.ai-prowler/config.json` | Runtime edition/mode/license settings |

---

## 10. Small Business Service Tools

The Small Business tab provides configuration and quick-reference for the field service automation MCP tools. These tools let Claude act as your field service assistant from a conversation.

### Free Tools Panel

Four tools require no setup and work immediately:

* **get\_weather** — Open-Meteo + Nominatim (no API key)
* **geocode\_address** — Nominatim / OpenStreetMap (no API key)
* **get\_route\_optimization** — OSRM public routing server (no API key)
* **build\_maps\_url** — Google Maps / Apple Maps URL scheme (no API key)

### Job Tracker Spreadsheet

The installer deploys a pre-built `AI-Prowler_Job_Tracker.xlsx` to your `Documents\AI-Prowler\` folder.

| Tab | Purpose |
|---|---|
| Customers | Customer master list with addresses, service type, frequency |
| Jobs\_Schedule | All service appointments with route and weather columns |
| Route\_Planner | Daily route optimization — AI fills lat/lon and map URLs |
| Quotes | Estimates sent to customers |
| Invoices | Billing and payment tracking |
| QB\_Daily\_Export | Daily export rows for accounting software import |
| Services\_Pricing | Service catalog with pricing |
| AI-Prowler\_Commands | Quick reference for Claude prompts |

### Example Claude Prompts

```
"What is the weather forecast for New Smyrna Beach for the next 3 days?"
"Optimize my route for these 6 jobs today and give me a Google Maps link."
"Mark the Miller Windows job complete in my jobs spreadsheet and record invoice #1048."
"What jobs do I have scheduled for today?"
"Show me all open jobs in my spreadsheet this week."
```

---

## 11. Quick Links Tab

The **Quick Links** tab is a one-click launcher for the recommended Claude Desktop / Claude.ai workflow.

* **🚀 Launch Claude Desktop** — opens Claude Desktop directly
* **⬇ Download Claude Desktop** — opens claude.ai/download in your browser
* **🌐 Open Claude.ai** — opens claude.ai in your browser for mobile/web access

---

## 12. Settings & Configuration

### Remote Access Tab

* **Bearer Token** — the password used to authenticate MCP connections from Claude.ai. Enter at least 10 characters of mixed case and numbers, then click **Save Token**.
* **Port** — HTTP server port (default 8000).
* **HTTP Server controls** — **▶ Start HTTP Server** / **■ Stop HTTP Server**.
* **Status lights** — Internet ● and Mobile Subscription ●
* **License Key / Parent License Key** — enter your subscription key to activate remote access. In server mode this shows as "Parent License Key" for the company's seat pool.
* **Mobile Activation** — shown in personal/home mode only (hidden in server mode):
  * **Check Activation** — checks if this machine is the active install
  * **Transfer to This Machine** — use when replacing your computer (see Section 8)
* **Named Tunnel** — enter Public hostname and Tunnel token, then click **Activate Tunnel Service** to install as a Windows background service. **Start Tunnel** / **Stop Tunnel** for manual control.

### Database Section (Settings Tab)

The Database section has three buttons:

| Button | What it clears | Keeps tracked dirs? | Keeps learnings? |
|---|---|---|---|
| **View Statistics** | (display only — shows all collections) | — | — |
| **Clear Database only** | All document collections (documents + any scoped collections) + file-tracking timestamps + email index | ✅ Yes | ✅ Yes |
| **Clear Database + Database list** | Everything above + tracked-directories list | ❌ No | ✅ Yes |

**View Statistics** enumerates every ChromaDB collection and reports:
* 🔧 Learnings KB — the learnings collection (never cleared by any button)
* 📄 Personal docs — the `documents` collection
* 📁 Scoped buckets — any `scope-role-*` collections (from server mode)
* 🌐 Scoped shared — any `shared` collection (from server mode)

If scoped collections appear on a personal install, it means the machine was previously run in server mode and those collections are now orphaned. Use **Clear Database only** to remove them while keeping your tracked folders.

**Clear Database only** is the right choice when:
* You switched from server mode back to personal mode and want to clean up orphaned scoped collections
* You want a fresh start on document indexing without re-adding all your tracked folders
* You want to reclaim disk space from old or duplicate collections

**Clear Database + Database list** is the right choice when:
* You want a completely clean installation state (you will need to re-add tracked folders)

> **Learnings are always preserved.** The `ai_prowler_learnings` ChromaDB collection is never touched by either clear button. Your recorded learnings are safe regardless of which button you press.

### Smart Scan Config Tab

* **Supported / Skipped extension lists** — control which file types are indexed
* **Exclude folder patterns** — skip specific directories during indexing

### Admin Tab (Business Server Mode Only)

See Section 9 for full details. The Admin tab appears only when `edition=business` AND `mode=server`.

### Learnings Tab

See Section 21 for full details.

---

## 13. Supported File Types

AI-Prowler indexes **65+ file formats** by default. Extensions are split into two sets: **Supported** (indexed) and **Skipped** (never indexed). Both can be customised in **Settings → Smart Scan Config**.

### Supported Extensions (indexed by default)

| Extension(s) | Category | Extractor | Notes |
|---|---|---|---|
| `.txt` `.md` `.rst` | Plain text / Markup | Built-in text reader | `.md`/`.rst` syntax stripped |
| `.pdf` | Document | pdfplumber + Tesseract OCR | Text layer first; OCR if no text layer |
| `.docx` | Word (modern) | python-docx | Body paragraphs and table cells |
| `.xlsx` | Excel (modern) | openpyxl | Column: Value per-row format |
| `.xls` | Excel (legacy) | xlrd | Same Column: Value format |
| `.pptx` | PowerPoint | python-pptx | Per-slide labelled sections |
| `.odt` | OpenDocument | odfpy | All paragraph text in reading order |
| `.rtf` | Rich Text Format | striprtf | RTF codes stripped |
| `.html` `.htm` `.xhtml` | Web | beautifulsoup4 | All tags stripped |
| `.csv` `.tsv` | Tabular data | csv module | Column: Value per-row format |
| `.py` `.js` `.ts` `.jsx` `.tsx` | Code | Plain text | Source code is searchable text |
| `.cs` `.java` `.cpp` `.c` `.h` | Code | Plain text | Compiled languages |
| `.json` `.yaml` `.yml` `.toml` `.ini` | Config / Data | Plain text | Config files |
| `.jpg` `.jpeg` `.png` `.bmp` `.tiff` | Images | Tesseract OCR | OCR extracts embedded text |
| `.eml` `.msg` `.emlx` | Email (single) | email / extract-msg | Headers, sender, recipient, subject, body |
| `.mbox` | Email (archive) | mailbox | Multiple messages, incrementally indexed |
| `.sh` `.bash` `.ps1` `.bat` `.cmd` | Scripts | Plain text | Shell scripts |

### Skipped Extensions (never indexed by default)

| Extension(s) | Category | Reason |
|---|---|---|
| `.doc` `.ppt` | Legacy Office binary | OLE binary — no pure-Python extractor. Convert to .docx/.pptx first. |
| `.exe` `.dll` `.so` | Executables | Binary — no readable text content |
| `.zip` `.rar` `.7z` | Archives | Compressed — extract first |
| `.mp3` `.wav` `.mp4` `.mkv` | Audio / Video | No text content extractable |
| `.db` `.sqlite` | Database files | Binary containers — use SQL exports instead |

---

## 14. OCR — Scanned Documents & Images

AI-Prowler automatically applies OCR to scanned PDFs and standalone image files (`.jpg`, `.jpeg`, `.png`, `.bmp`, `.tiff`, `.gif`).

### How It Works

1. `pdfplumber` attempts to extract the text layer from PDFs
2. If no text found, `pypdfium2` renders each page to a 300 DPI image
3. `pytesseract` (Tesseract 5.4) extracts text from the image
4. The extracted text is chunked and indexed normally

### OCR Debug Tools

In **Settings**, use the **OCR Debug** button to test OCR on a specific file and see the extracted text before indexing.

---

## 15. Email Indexing

Claude has built-in connector tools for Gmail and Microsoft that allow active search and it is recommended to add those connectors instead of using AI-Prowler to index email files. However, AI-Prowler does support indexing of exported email database files from the following providers; to export those files you need to visit their sites and make a request.

### AI-Prowler Supported Formats

| Provider | Format | Export Method |
|---|---|---|
| Gmail | .mbox | Google Takeout |
| Apple Mail / iCloud | .mbox | File → Export Mailbox |
| Thunderbird | .mbox | Direct from profile folder |
| Yahoo Mail | Via Thunderbird IMAP | Set up IMAP in Thunderbird first |
| Outlook / Exchange | .eml, .msg | Drag-and-drop or MailStore export |

### Incremental Indexing

AI-Prowler uses `Message-ID` headers for deduplication. On re-import, only new emails are indexed.

---

## 16. Scheduling & Automation

### Windows Task Scheduler Integration

Set up automatic index updates from **Settings → Schedule**:

1. Choose update frequency (daily, specific days, custom)
2. Set the time (default: 2:00 AM)
3. Click **Create Schedule**

### Cloudflare Tunnel as Windows Service

For always-on remote access, activate the Named Tunnel as a Windows service via **Settings → Remote Access → Activate Tunnel Service**. The tunnel starts automatically at boot.

---

## 17. GPU Support

AI-Prowler detects NVIDIA GPUs automatically. The installer installs the correct PyTorch build (CUDA 12.8 for RTX 50xx/Blackwell, or CPU-only).

The sentence-transformer embedding model (`all-MiniLM-L6-v2`) uses CUDA automatically when available, significantly speeding up indexing. This is the only place a GPU helps — all language reasoning happens in Claude (cloud).

### Blackwell (RTX 50xx) Note

PyTorch stable does not yet include CUDA 12.8 compute kernels for Blackwell SM 12.0+ architecture. Embeddings run on CPU on RTX 50xx cards even though CUDA is detected. This affects only indexing speed, not search quality or Claude's reasoning.


---

## 18. Debugging & Log Files

### Log File Locations

| Log File | Location | Contents |
|---|---|---|
| Install log | `%LOCALAPPDATA%\Temp\AI-Prowler\install_log.txt` | Full installer output |
| MCP server log | `%LOCALAPPDATA%\AI-Prowler\mcp_server.log` | All MCP server activity (current session) |
| MCP server log (prev) | `%LOCALAPPDATA%\AI-Prowler\mcp_server.log.1` | Previous session |
| Subscription cache | `%LOCALAPPDATA%\AI-Prowler\subs_cache.json` | Cached subscription registry |

### MCP Server Log

The MCP log is the most useful for debugging Claude Desktop and Claude.ai connection issues. It captures startup sequence, tool calls, authentication, and subscription checks.

### Common Debug Workflow

**Problem: Claude says it can't find information that should be indexed**

1. Open `mcp_server.log` and find the tool call for `search_documents`
2. Check the similarity scores — if all are below 0.3, the content may not be well-represented
3. Try `list_indexed_documents()` to verify the file is actually indexed
4. Try `get_document_chunks("filename.pdf")` to see the raw extracted text

**Problem: Claude.ai connector fails with "MCP server error"**

* HTTP server not running → click Start HTTP Server
* Cloudflare Tunnel not running → click Start Tunnel (or check Windows Services for cloudflared)
* Bearer token mismatch → re-enter your token in Settings and in Claude.ai

**Problem: Cloudflare Error 1033**

Error 1033 means cloudflared is running but cannot reach the local AI-Prowler HTTP server. Check:

1. Is the HTTP server running? Open a browser on your PC and navigate to `http://localhost:8000/health` — should return `OK`.
2. Is cloudflared running? Check Task Manager → Details for `cloudflared.exe`.
3. If cloudflared was started before the HTTP server, restart cloudflared after the HTTP server is confirmed running.

**Correct startup order:** Start HTTP server first → then cloudflared connects to it.

**Problem: Cloudflare tunnel credentials missing (cert.pem / ai-prowler.json missing)**

1. Run `cloudflared tunnel login` — browser opens to Cloudflare, downloads `cert.pem`
2. Run `cloudflared tunnel token --cred-file "C:\Users\david\.cloudflared\ai-prowler.json" ai-prowler` — restores the credentials JSON
3. In AI-Prowler Settings → Stop Tunnel → Uninstall Service → Activate Tunnel Service

---

## 19. Troubleshooting

### Claude Desktop can't see AI-Prowler tools

1. Check that AI-Prowler is installed in `C:\Program Files\AI-Prowler\`
2. Restart Claude Desktop completely
3. Start a **new conversation** (not an existing one)

### Cloudflare Error 1033

See Section 18 — Debugging for the step-by-step fix. The most common cause is cloudflared starting before the HTTP server, or the tunnel credentials files being missing from `~/.cloudflared/`.

### Indexing is slow

* Enable GPU in Settings if you have an NVIDIA card
* Use Smart Scan to skip file types you don't need

### Errno 22 / double backslash error on indexing

This is a known `huggingface_hub` bug on some Windows builds. The `RAG_RUN.bat` launcher sets `HF_HUB_CACHE` explicitly to prevent this. If it persists after reinstall, contact support. Note: AI-Prowler requires Windows 11 and does not support Windows 10.

---

## 20. Uninstalling

Run `UNINSTALL.bat` from `C:\Program Files\AI-Prowler\` or use Windows Settings → Add or Remove Programs → AI-Prowler.

The uninstaller removes all AI-Prowler application files, Python (if installed by AI-Prowler), and offers to remove the RAG database, tracking files, self-learning knowledge base, and Job Tracker spreadsheet (default: keep all — safe for reinstall).

---

## 21. Self-Learning System

### Overview

The Self-Learning System gives AI-Prowler a persistent, semantically-searchable memory separate from the main document RAG. When you tell Claude "learn this" — or when Claude detects a correction or insight during conversation — the fact is written to a structured JSON file and indexed in ChromaDB. The next time a related question comes up, Claude calls `search_learnings()` first, finds the stored fact, and applies it automatically.

No GPU. No training. New knowledge is queryable within roughly 1 second of being recorded.

### The Six Self-Learning MCP Tools

| Tool | Purpose |
|---|---|
| `record_learning()` | Save a new fact, lesson, or correction |
| `search_learnings()` | Semantic search the knowledge base |
| `list_learnings()` | Browse by category / status / tag |
| `update_learning()` | Modify an existing learning |
| `delete_learning()` | Permanently remove a learning |
| `get_learning_stats()` | Summary stats — totals, most applied |

### Learning Categories

| Category | When to use |
|---|---|
| `fact_correction` | Correcting an outdated or wrong fact |
| `business_lesson` | What worked or didn't in business |
| `project_insight` | Lessons from a specific project |
| `process_improvement` | A better way to do something |
| `mistake_learned` | Something went wrong — document to prevent recurrence |
| `best_practice` | Proven approach to adopt going forward |
| `client_preference` | Client-specific preferences or requirements |
| `technical_note` | Technical fact, configuration, or gotcha |
| `general` | Catch-all |

### Learning Source Attribution (`source` and `recorded_by`)

AI-Prowler automatically stamps the identity of whoever recorded a learning — no manual action required from the user or Claude. This works in both personal and server mode.

**Personal mode — owner name stamped in `source`:**

When you record a learning on a personal install, AI-Prowler reads your name from Settings and stamps it into the `source` field automatically. The `source` field appears in list and search output so you always know the provenance of each learning. If no name is configured in Settings, `source` falls back to `"operator"`.

**Server mode — employee name stamped in `recorded_by`:**

In server mode, multiple employees share the same self-learning knowledge base and it matters who added each entry. When a server-mode user records a learning, AI-Prowler automatically stamps their name into a `recorded_by` field. This happens without any action from the employee — Claude resolves the identity from the authenticated bearer token and fills the field in silently.

**Where attribution appears:**

- **Confirmation message** — immediately after recording, Claude shows `Recorded by: <name>` (server) or `Source: <name>` (personal) in the summary so the user can verify attribution.
- **`list_learnings()` output** — each entry shows the attribution field when set, so anyone auditing the knowledge base can see who contributed what.
- **`search_learnings()` output** — search results include the attribution field so Claude and the user know the provenance of each retrieved learning.

**Fallback behaviour:**
- Server mode: if an employee's user record has no name configured, `recorded_by` falls back to their role (e.g. `staff`, `field_crew`) so attribution is never completely blank.
- Personal mode: if no owner name is set in Settings, `source` is set to `"operator"`.

**Example — server mode list output:**
```
[1] ✅ Crabby's Daytona prefers second Tuesday of the month
    client_preference | ❓ unknown | confidence: 95% | applied: 3x
    Created: 2026-06-01T09:15:00
    Recorded by: Jake Smith
    ID: a1b2c3d4-...
    → Client confirmed preference after scheduling conflict in May 2026...
```

**Example — personal mode list output:**
```
[1] ✅ Always use the soft-bristle brush on painted window frames
    best_practice | ✅ confirmed | confidence: 98% | applied: 12x
    Created: 2026-06-10T14:30:00
    Source: David Vavro
    ID: e5f6g7h8-...
    → Learned after a customer complaint about scratching in March 2026...
```

### Example Workflow

```
You: "Remember this: Crabby's Daytona prefers we wash the windows on
      the second Tuesday of the month, not the first."

Claude: [calls record_learning(...)] — shows confirmation including
        "Recorded by: Jake Smith" in server mode,
        or "Source: David Vavro" in personal mode.

You (in a new chat): "When should I schedule Crabby's next window cleaning?"

Claude: [calls search_learnings("Crabby's window cleaning schedule")] — finds
        the learning and answers based on it.
```

### File Locations

* **Learnings data:** `~/.ai-prowler/learnings/self_learning_data.json`
* **ChromaDB collection:** `ai_prowler_learnings` (inside the main RAG database folder)

---

## 22. Welcome Page & Update Notifications

### Welcome Tab

The Welcome tab is the first screen when AI-Prowler launches. It shows version information, What's New, quick-start links, and update notifications.

### Update Push Notifications

AI-Prowler checks for updates on launch by reading a version file from the public GitHub repository. If a newer version is available, a notification banner appears with a download link. No automatic updating occurs — you must download and run the new installer manually.

### Footer Text

The footer text at the bottom of the Welcome tab can be customized by the AI-Prowler admin via a push to the public GitHub welcome\_ad.json file. The default text ("AI-Prowler — Free for personal use") is shown until the network fetch completes.

---

## 23. Heartbeats & Analytics

### Anonymous Daily Heartbeat

AI-Prowler sends a small daily anonymous heartbeat to a Cloudflare Worker so the developer can see how many installs are active and which versions are deployed.

**What's sent:**

* A random `install_id` (UUID, generated once per install, never tied to a name or email)
* AI-Prowler version
* `edition` — the actual edition from config.json (`home`, `mobile`, or `business`)
* `mode` — the actual mode from config.json (`personal` or `server`)
* OS string (e.g. `"Windows-11"`)
* Number of chunks currently indexed
* Number of MCP tool calls in the last 24 hours (total count, no per-tool detail)

**What is NEVER sent:**

* Your name, email, or IP address
* Document content, queries, or file paths
* Bearer tokens or any credentials
* Self-learning data

The endpoint is `https://ai-prowler-telemetry.david-vavro1.workers.dev` by default (overridable via `telemetry_endpoint` in `~/.ai-prowler/config.json`).

### How to Turn Off

Set `"telemetry_enabled": false` in `~/.ai-prowler/config.json` and restart AI-Prowler.

### Heartbeat Schedule

* First heartbeat: ~5 minutes after first launch
* Subsequent: every 24 hours
* Server-side 12-hour throttle prevents duplicates

---

## Appendix A — MCP Protocol Version Notes

AI-Prowler uses **Streamable HTTP** transport for Claude.ai and **stdio** transport for Claude Desktop.

| Feature | Requires |
|---|---|
| Basic tool calls | mcp >= 1.0 |
| `instructions=` in FastMCP constructor | mcp >= 1.2.0 |
| Streamable HTTP transport | mcp >= 1.1.0 |

To upgrade: `pip install --upgrade mcp`

---

## Appendix B — Privacy Details

**What stays on your machine:**
* All document content
* The ChromaDB vector database
* All embeddings
* Bearer tokens and credentials
* The AI-Prowler configuration
* Self-learning knowledge base

**What leaves your machine:**
* Text of retrieved document chunks (when using Claude)
* Anonymous daily heartbeat (install\_id, version, edition, mode, OS, chunk count, tool call count)
* Subscription check (reads public `subs.json` from GitHub — no data sent)
* Update check (read-only version check)

**What is never sent:**
* Original document files
* Full document content
* Bearer tokens or credentials
* Self-learning data

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
| mcp | latest | MCP SDK (FastMCP) for tool server |

Note: `torch` (PyTorch) is intentionally not listed in `requirements.txt`. The installer detects GPU presence and installs the correct build automatically.

---

*AI-Prowler — Your Personal Agentic RAG Knowledge Base*
*Copyright © 2026 David Kevin Vavro · david.vavro1@gmail.com*
