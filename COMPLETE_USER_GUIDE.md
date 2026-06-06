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
* **Tier A tool suppression** — 23 developer/operator tools (code execution, host filesystem write, configure\_email, etc.) are hidden from the MCP tool list entirely when running in server mode. They never appear for any role in server mode — they are registered only on personal installs.
* **Email tools** — `configure_email`, `send_email`, `send_alert`, `send_file`, `send_learnings_report` using Python's built-in SMTP library. Available on personal installs; not exposed in server mode.
* **Dev tools** — `compile_check`, `check_python_import`, `syntax_check`, `lint_check`, `pytest_check` — available on personal installs; suppressed in server mode.
* **Code Tools (Write-Side)** — `create_file`, `write_file`, `str_replace_in_file`, `create_directory`, `list_directory`, `copy_to_backup`, `list_backups`, `restore_backup`, `reset_write_counter` — available on personal installs; suppressed in server mode.
* **Database management** — Settings tab Database section now has three distinct buttons: **View Statistics** (shows all ChromaDB collections including any server-mode scoped ones), **Clear Database only** (wipes all document collections but keeps your tracked-directories list and learnings), and **Clear Database + Database list** (full wipe including tracked directories).
* **Mobile Activation** — the machine-activation panel in Settings is now hidden in server mode (irrelevant for server installs) and correctly documented as 1 machine per install for personal mode. The **Transfer to This Machine** button atomically releases the old machine and activates the new one — the right tool when replacing your computer.
* **Admin tab security** — bearer tokens in the Admin tab are fully masked (●●●●●●●●) in the user table, masked while typing in the Add User dialog, and masked by default in the Show Token dialog with a Reveal toggle.
* **Telemetry accuracy** — the daily heartbeat now sends the actual `edition` and `mode` from config.json rather than a hardcoded `home` value, so your analytics correctly distinguish home, mobile, and business installs.
* **Windows 10 support** — fully supported. The HF\_HUB\_CACHE Errno 22 fix is pre-applied.

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
4. Sign in to Claude Desktop when it opens and pin it to the taskbar for quick access
5. Click the AI-Prowler shortcut on your Desktop. For mobile/web access, click **Start HTTP Server** in the Settings tab
6. Open Claude Desktop — it will communicate directly with AI-Prowler via the MCP interface

### What the Installer Does NOT Do

**No large local AI model is installed or downloaded.** The AI interface is Claude Desktop (or Claude.ai for mobile/web) via MCP, which requires no local model. AI-Prowler only runs the small embedding model (~400 MB) and ChromaDB locally; Claude does all the reasoning.

This makes installation significantly faster — typically under 10 minutes vs 30+ minutes previously.

### Install Log

The full installation log is saved to:

```
%LOCALAPPDATA%\Temp\AI-Prowler\install_log.txt
```

This is useful for diagnosing installation failures.

### First Launch

After install, AI-Prowler opens automatically. Claude Desktop is also installed. On first use:

1. Open Claude Desktop and verify it shows "AI-Prowler" in the MCP tools panel
2. In AI-Prowler, go to **Index Documents** and add your first document folder
3. In Claude Desktop, ask a question about your documents
4. For Mobile Access or Web access consider subscribing to Mobile.

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

When Claude Desktop starts, it connects to AI-Prowler and discovers all available tools automatically. No manual configuration is needed. Note: if mobile is configured, only mobile access will be used for all Claude MCP connections going forward. This includes when in Claude Desktop application.

### Verifying the Connection

Open Claude Desktop and start a new conversation. You should see a tools indicator showing AI-Prowler is connected. Ask:

```
What AI-Prowler tools do you have available?
```

Claude will list all available tools. If you see `get_knowledge_base_overview` and `search_documents`, the connection is working.

### If Claude Desktop Loses the Connection

1. Open AI-Prowler
2. Go to **Settings → Claude Desktop MCP**
3. Click **Write MCP Config** to re-write the configuration
4. Restart Claude Desktop completely (quit from the system tray, then relaunch)
5. Start a **new chat or conversation** — existing conversations do not pick up reconnected tools

### Manual Config Reference

If you need to add AI-Prowler to Claude Desktop manually, the config entry looks like:

```json
{
  "mcpServers": {
    "AI-Prowler": {
      "command": "C:\\Users\\YourName\\AppData\\Local\\Programs\\Python\\Python311\\python.exe",
      "args": ["C:\\Program Files\\AI-Prowler\\ai_prowler_mcp.py"]
    }
  }
}
```

A pre-filled example is in `C:\Program Files\AI-Prowler\claude_desktop_config_example.json`.

### MCP Diagnostics Tool

If tools are not appearing or tool calls are failing in Claude Desktop, use the built-in diagnostics tool:

1. Go to **Settings → Claude Desktop MCP**
2. Click **🔬 Run MCP Diagnostics**
3. A scrollable output window shows: MCP SDK version, tool count, config validity, subscription cache, and log tail.
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

### Tool Counts by Mode

The number of tools Claude sees depends on where AI-Prowler is running:

| Install type | Mode | Tools visible | Notes |
|---|---|---|---|
| Personal / Home | personal | **58** | All tools available |
| Business — employee personal install | personal | **58** | Full individual tool set |
| Business — company server | server | **35** | Tier A tools suppressed; remaining tools further gated by role |

**Why the difference?** In server mode, 23 Tier A tools (developer/operator tools) are suppressed at registration time — they never appear in Claude's tool list for any user, regardless of role. This is a server-wide security boundary. The remaining 35 tools are further gated per role (see Role-Based Tool Access below).

### Tier A Tool Suppression (Server Mode Only)

The following 23 tools are **never registered** when AI-Prowler runs in server mode (`edition=business`, `mode=server`). They are completely invisible to any Claude client connecting to the server:

| Category | Suppressed tools |
|---|---|
| Dev / code execution | `compile_check`, `syntax_check`, `lint_check`, `pytest_check`, `check_python_import` |
| Host filesystem writes | `create_file`, `write_file`, `str_replace_in_file`, `create_directory`, `copy_to_backup`, `restore_backup`, `list_backups`, `list_directory`, `reset_write_counter`, `grant_write_access`, `revoke_write_access` |
| Raw filesystem reads | `grep_documents`, `read_file_lines` |
| Email operator tools | `configure_email`, `send_file`, `send_learnings_report`, `export_learnings_file` |
| Bulk index rebuild | `rebuild_learnings_index` |

Note: `send_email` and `send_alert` are **not** suppressed in server mode — they remain available to `field_crew` users via the Tier B role gate.

### Role-Based Tool Access in Server Mode (Tier B)

After Tier A suppression, the remaining 35 tools are further gated by the user's role:

| Tool group | owner | manager | staff | field\_crew |
|---|---|---|---|---|
| RAG Search (search, overview, list docs, etc.) | ✅ | ✅ | ✅ | ✅ |
| Field Service (weather, geocode, route, maps, spreadsheet) | ✅ | ✅ | ✅ | ✅ |
| Self-Learning (record, check, list, update, delete, stats) | ✅ | ✅ | ✅ | ✅ |
| `check_ai_prowler_status`, `check_tools_status`, `how_to_use_ai_prowler` | ✅ | ✅ | ✅ | ✅ |
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

### Agentic RAG Tools

#### `how_to_use_ai_prowler()`
Returns the recommended workflow and tool sequence. Claude calls this automatically at the start of research sessions.

#### `get_knowledge_base_overview()`
Returns a summary of the entire knowledge base: document count, file types, chunk count, database location, and tracked directories.

#### `search_documents(query, n_results, min_similarity)`
The primary retrieval tool. Performs semantic vector search and returns raw document chunks with source metadata and similarity scores.

Parameters:
* `query` — natural language search query
* `n_results` — chunks to return (default 8, max 20)
* `min_similarity` — filter threshold 0.0–1.0 (default 0.0)

#### `search_by_multiple_queries(queries, n_results_each, min_similarity)`
Runs 2–6 search queries in parallel and returns deduplicated results ranked by best similarity.

#### `get_chunk_context(filename, chunk_index, window)`
Retrieves the chunks immediately before and after a specific chunk.

#### `get_document_chunks(filename, start_chunk, max_chunks)`
Retrieves chunks from a specific document in reading order.

#### `list_indexed_documents(filter_ext, filter_path, limit)`
Lists all indexed documents grouped by file type.

#### `search_within_directory(query, directory, n_results, min_similarity)`
Directory-scoped semantic search — restricts results to a single folder tree.

#### `list_directories()`
Returns the directory tree of all indexed content with document counts per folder.

### Knowledge Base Management Tools

#### `add_and_index_directory(directory, recursive, track)`
Indexes all documents in a folder and optionally adds it to the auto-update tracking list.

#### `update_tracked_directories(directory)`
Re-scans tracked directories and indexes only changed files.

#### `get_database_stats()`
Returns statistics across all ChromaDB collections: chunk count, unique document count, breakdown by file type, and database location. In server mode, shows scoped collections separately.

#### `list_tracked_directories()`
Lists all directories currently registered for auto-update tracking.

#### `remove_directory(directory)`
Removes a directory from tracking and deletes all its chunks from ChromaDB.

### Small Business Action Tools

#### `get_weather(location, days)`
Current conditions and multi-day forecast. Uses Open-Meteo and Nominatim — free, no API key.

#### `geocode_address(address)`
Converts a street address to GPS coordinates via Nominatim / OpenStreetMap — free, no key.

#### `get_route_optimization(stops, origin, optimize_for, departure_hour, return_to_origin)`
Solves the Traveling Salesman Problem for a list of job stops.

#### `build_maps_url(stops, origin, app)`
Generates a tap-to-navigate Google Maps (or Apple Maps) URL with all stops pre-loaded.

#### `update_job_spreadsheet(filepath, job_identifier, updates, id_column, sheet_name, backup)`
Updates a row in an `.xlsx` job tracking spreadsheet after a job is completed.

#### `read_job_spreadsheet(filepath, sheet_name, filter_date, max_rows)`
Reads job data from the AI-Prowler job tracking spreadsheet and returns it as structured text.

#### `get_action_tools_status()`
Returns a full status report for all action tools: which are ready, which need configuration, and setup instructions.

### Self-Learning Tools

Six tools for RAG-based knowledge accumulation. See Section 21 for full details.

#### `record_learning(title, content, category, ...)`
Records a new learning into the self-learning knowledge base.

#### `check_learned(query, n_results, category, include_deprecated)`
Semantic search across the self-learning knowledge base.

#### `list_learnings(category, status, tag, limit)`
Browses all learnings with exact-match filters.

#### `update_learning(learning_id, updates)`
Modifies fields on an existing learning.

#### `delete_learning(learning_id)`
Permanently removes a learning.

#### `get_learning_stats()`
Returns summary statistics: totals by category/source/outcome/status, most frequently applied learnings.

### Code Tools — Write-Side (Personal Installs Only)

Nine tools for file creation, editing, listing, backup, and restore. **Suppressed in server mode.** All write operations are subject to the four-layer security model (read allowlist, writable allowlist, hard blocklist, per-session circuit breaker).

#### `create_file(filepath, content)`
Creates a new file. Fails if the file already exists. Content is written to disk immediately but is **not** automatically indexed — call `reindex_file()` once done.

#### `write_file(filepath, content, verify_after_write)`
Overwrites an existing file. Detects and preserves the existing CRLF/LF line-ending convention. An automatic backup is created as `<filepath>.bak<N>` before any change.

#### `str_replace_in_file(filepath, old_str, new_str, dry_run)`
Surgical in-place edit: replaces one unique occurrence of `old_str` with `new_str`. Refuses if the string appears zero or more than once. Backup created automatically.

#### `create_directory(dirpath)`
Creates a directory and any missing parents. Idempotent.

#### `list_directory(dirpath)`
Lists the immediate contents of a directory: files, subdirectories, and `.bak<N>` backups. Read-only.

#### `copy_to_backup(filepath)`
Creates a manual snapshot of a file as `<filepath>.bak<N>`.

#### `list_backups(filepath)`
Lists all `<filepath>.bak<N>` backups with timestamps and sizes.

#### `restore_backup(filepath, backup_number)`
Overwrites the active file with the contents of `<filepath>.bak<N>`.

#### `reset_write_counter()`
Resets the per-session 20-write circuit breaker.

### Code Tools — Read (Personal Installs Only)

These tools give Claude raw filesystem read access. **Suppressed in server mode.**

#### `grep_documents(pattern, filter_path, context_lines, max_results, regex)`
Locates exact text or regex matches across tracked files. Like `grep` for your knowledge base source files.

#### `read_file_lines(filepath, start_line, end_line)`
Reads an exact line range from a file on disk. Essential for code-aware edits.

### Code Tools — Security Model (Personal Installs)

Write-side tools are protected by four independent layers:

1. **Read allowlist** (`~/.rag_auto_update_dirs.json`) — the file's parent must be tracked for indexing.
2. **Writable allowlist** (`~/.rag_writable_dirs.json`) — a separate opt-in write permission.
3. **Hard blocklist** — unconditionally refuses writes under `C:\Windows`, `C:\Program Files`, `%AppData%`, `.git`, `.ssh`, `.aws`, and AI-Prowler's own state files.
4. **Per-session circuit breaker** — maximum 20 writes per server lifetime; call `reset_write_counter()` to continue.

### Dev Tools (Personal Installs Only)

Five tools for code verification. **Suppressed in server mode.**

#### `compile_check(filepath, timeout_sec=120)`
Byte-compiles a Python file to catch syntax errors. Equivalent to `python -m py_compile`.

#### `check_python_import(module_or_path, timeout_sec=120)`
Imports a Python module to catch load-time errors that compile\_check misses.

#### `syntax_check(filepath, timeout_sec=120)`
Multi-language syntax checker. Supports Python, JavaScript, TypeScript, C, C++, Go, Java, Perl, Ruby, PHP, Bash, Verilog, SystemVerilog, VHDL.

#### `lint_check(filepath, timeout_sec=120)`
Multi-language linter. Uses pyflakes for Python, tsc for TypeScript, go vet for Go, ghdl -a for VHDL.

#### `pytest_check(test_path, k_filter, timeout_sec=300, max_output_lines=200)`
Runs pytest and returns a clean summary plus the first failure trace.

### Email Tools (Personal Installs Only)

Email tools are available on personal installs only. **Suppressed in server mode** (each employee configures their own email on their own personal install). The `send_email` and `send_alert` tools remain available on the server for `field_crew` users who need to send quick job notifications.

#### `configure_email(smtp_host, smtp_port, username, password, from_name, default_to)`
Call once to save SMTP credentials.

| Provider | smtp\_host | smtp\_port |
|---|---|---|
| Gmail | smtp.gmail.com | 587 |
| Outlook / Office 365 | smtp.office365.com | 587 |
| Yahoo | smtp.mail.yahoo.com | 587 |

#### `send_email(to, subject, body, attachment_path)`
Sends a plain-text email. Available to field\_crew in server mode; full config on personal installs.

#### `send_alert(message, to)`
Sends a short notification email. Available to field\_crew in server mode.

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

**Prerequisites:** A free Cloudflare account and a domain name added to Cloudflare.

**One-time setup:**

1. In Settings → Remote Access → Named Tunnel, enter your **Public hostname** and **Tunnel token** (from Cloudflare Zero Trust dashboard → Networks → Tunnels → your tunnel → Token).
2. Click **Activate Tunnel Service** — this installs cloudflared as a Windows background service.
3. The status shows **Tunnel active (Windows service)** with a green dot.

After this one-time setup, the tunnel starts automatically at boot. Use **Start Tunnel** / **Stop Tunnel** to control it manually.

**If the tunnel stops working:**
1. Click **Stop Tunnel** then **Uninstall Service**
2. Get a fresh token from Cloudflare Zero Trust dashboard if needed
3. Click **Activate Tunnel Service** to reinstall

### Connecting Claude.ai — Step by Step

1. Open [claude.ai](https://claude.ai) and sign in (Claude Pro or Team required)
2. Click your profile icon → **Settings** → **Connectors** → **Add custom connector**
3. Enter your tunnel URL followed by `/mcp` (e.g. `https://mobile.your-company.com/mcp`)
4. Claude.ai redirects you to your AI-Prowler authorization page
5. Enter your Bearer token and click **Connect**

---

## 8. Mobile Subscription Management

### Subscription Plans

| Plan | Price | Users | Use Case |
|---|---|---|---|
| Individual | $10/month | 1 | Personal use |
| Small Business | $30/month | Up to 5 | Team deployment |
| Enterprise | Contact us | 6+ | Custom deployment |

### How to Subscribe

Email david.vavro1@gmail.com with:

* Your name or company name
* Which plan you want
* Your Bearer token (shown in Settings → Remote Access)

Your Bearer token **never changes** between billing periods.

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
* **On their own laptop (optional):** install AI-Prowler, activate with the same child key in `personal` mode, and index their own documents. This gives them the full 58-tool individual set — search, file read/write in their own folders, dev tools — plus their own mobile access to their personal knowledge base via Claude.ai using their own Cloudflare Tunnel. Nothing here touches the company server; it is their private instance, licensed under the company's umbrella.

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

### Supported Formats

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

### Windows 10 Support

AI-Prowler fully supports Windows 10. The HF\_HUB\_CACHE Errno 22 fix (a known `huggingface_hub` bug on some Windows 10 builds) is pre-applied in `RAG_RUN.bat`.

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
2. In AI-Prowler → Settings → Claude Desktop MCP → click **Write MCP Config**
3. Restart Claude Desktop completely
4. Start a **new conversation** (not an existing one)
5. Click **🔬 Run MCP Diagnostics** for a detailed health report

### Cloudflare Error 1033

See Section 18 — Debugging for the step-by-step fix. The most common cause is cloudflared starting before the HTTP server, or the tunnel credentials files being missing from `~/.cloudflared/`.

### Indexing is slow

* Enable GPU in Settings if you have an NVIDIA card
* Use Smart Scan to skip file types you don't need

### Errno 22 / double backslash error on indexing

This is a known `huggingface_hub` bug on some Windows 10 builds. The `RAG_RUN.bat` launcher sets `HF_HUB_CACHE` explicitly to prevent this. If it persists after reinstall, contact support.

---

## 20. Uninstalling

Run `UNINSTALL.bat` from `C:\Program Files\AI-Prowler\` or use Windows Settings → Add or Remove Programs → AI-Prowler.

The uninstaller removes all AI-Prowler application files, Python (if installed by AI-Prowler), and offers to remove the RAG database, tracking files, self-learning knowledge base, and Job Tracker spreadsheet (default: keep all — safe for reinstall).

---

## 21. Self-Learning System

### Overview

The Self-Learning System gives AI-Prowler a persistent, semantically-searchable memory separate from the main document RAG. When you tell Claude "learn this" — or when Claude detects a correction or insight during conversation — the fact is written to a structured JSON file and indexed in ChromaDB. The next time a related question comes up, Claude calls `check_learned()` first, finds the stored fact, and applies it automatically.

No GPU. No training. New knowledge is queryable within roughly 1 second of being recorded.

### The Six Self-Learning MCP Tools

| Tool | Purpose |
|---|---|
| `record_learning()` | Save a new fact, lesson, or correction |
| `check_learned()` | Semantic search the knowledge base |
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

### Example Workflow

```
You: "Remember this: Crabby's Daytona prefers we wash the windows on 
      the second Tuesday of the month, not the first."

Claude: [calls record_learning(...)] — shows confirmation.

You (in a new chat): "When should I schedule Crabby's next window cleaning?"

Claude: [calls check_learned("Crabby's window cleaning schedule")] — finds 
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
| chromadb | 0.6.3 | Vector database for document chunks |
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
