# AI-Prowler — Complete User Guide

**Version 6.0.0**

\---

## Table of Contents

1. [What is AI-Prowler?](#1-what-is-ai-prowler)
2. [Installation](#2-installation)
3. [Connecting Claude Desktop via MCP](#3-connecting-claude-desktop-via-mcp)
4. [Indexing Your Documents](#4-indexing-your-documents)
5. [Agentic RAG — How Claude Uses Your Knowledge Base](#5-agentic-rag--how-claude-uses-your-knowledge-base)
6. [MCP Tools Reference](#6-mcp-tools-reference)
7. [Remote Access — Claude.ai on Mobile and Web](#7-remote-access--claudeai-on-mobile-and-web)
8. [Mobile Subscription Management](#8-mobile-subscription-management)
9. [Small Business Service Tools](#9-small-business-service-tools)
10. [Quick Links Tab](#10-quick-links-tab)
11. [Settings \& Configuration](#11-settings--configuration)
12. [Supported File Types](#12-supported-file-types)
13. [OCR — Scanned Documents \& Images](#13-ocr--scanned-documents--images)
14. [Email Indexing](#14-email-indexing)
15. [Scheduling \& Automation](#15-scheduling--automation)
16. [GPU Support](#16-gpu-support)
17. [Debugging \& Log Files](#17-debugging--log-files)
18. [Troubleshooting](#18-troubleshooting)
19. [Uninstalling](#19-uninstalling)
20. [Self-Learning System](#20-self-learning-system)
21. [Welcome Page \& Update Notifications](#21-welcome-page--update-notifications)
22. [Heartbeats \& Analytics](#22-heartbeats--analytics)

\---

## 1\. What is AI-Prowler?

AI-Prowler is an **Agentic RAG (Retrieval-Augmented Generation)** knowledge base for Windows. It indexes your local documents into a private ChromaDB vector database and exposes them to Claude as a suite of intelligent search and retrieval tools.

**The key difference from traditional RAG:**

Traditional RAG retrieves a chunk, hands it to a small local model, and gets a mediocre answer. AI-Prowler's Agentic RAG lets Claude actively drive the research process:

* Claude decides what to search for based on your question
* It evaluates what it finds and identifies gaps
* It reformulates queries and searches again
* It reads surrounding context when a result is incomplete
* It synthesizes a comprehensive answer from everything it gathered

This produces dramatically better results — equivalent to having a skilled research assistant who knows your entire document library.

**Hardware requirements are minimal.** Because Claude does the reasoning, AI-Prowler only needs to run the embedding model (\~400 MB RAM) and ChromaDB. No GPU is required. No large local AI model is needed.

**New in v6.0.0 — Self-Learning at full strength:** Claude can record business lessons, fact corrections, project insights, and process improvements into a structured knowledge base — and check that knowledge before answering future questions. Learnings are instant (no GPU training required) and managed through a dedicated 🧠 Learnings tab in the GUI. 6.0 hardens the system with a comprehensive automated test suite (147 tests covering indexing, MCP, GUI, and self-learning), plus several engine reliability fixes for change detection, deletion purging, and database wipes. See Section 20 for full self-learning details.

**New in v6.0.2 — Mobile Write Zones & Code Tools:** Claude can now create, edit, list, back up, and restore files in directories you've explicitly pre-authorized. Nine new MCP code tools (`create_file`, `write_file`, `str_replace_in_file`, `create_directory`, `list_directory`, `copy_to_backup`, `list_backups`, `restore_backup`, `reset_write_counter`) are gated by a double-lock security model — a read allowlist plus a separate writable allowlist — with a per-session 20-write circuit breaker and a hard blocklist that always wins. The new **Update Index** tab UI lets you grant or revoke write access by double-clicking a row, with `[W]` / `[W*]` / `[R]` indicators showing each path's current state. Edits to existing CRLF files now preserve their Windows line endings cleanly. See Section 4 for the Mobile Write Zones UI and Section 6 for the new code tools.

\---

## 2\. Installation

### Quick Start

1. Download `AI-Prowler\\\_INSTALL.exe` from the [Releases page](https://github.com/dvavro/AI-Prowler/releases)
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

**Ollama is not installed or downloaded automatically.** The primary AI interface is Claude Desktop via MCP, which requires no local model. The standalone local-AI Q&A controls are hidden by default in v6.0.0 to keep the GUI clean — most users never need them. If you specifically want offline local-AI Q&A, see the **Advanced / Power-User Features** note in Section 10 for how to re-enable the controls and install Ollama from within AI-Prowler.

This makes installation significantly faster — typically under 10 minutes vs 30+ minutes previously.

### Install Log

The full installation log is saved to:

```
%LOCALAPPDATA%\\\\Temp\\\\AI-Prowler\\\\install\\\_log.txt
```

This is useful for diagnosing installation failures.

### First Launch

After install, AI-Prowler opens automatically. Claude Desktop is also installed. On first use:

1. Open Claude Desktop and verify it shows "AI-Prowler" in the MCP tools panel
2. In AI-Prowler, go to **Index Documents** and add your first document folder
3. Launch Claude and In Claude Desktop, ask a question about your documents
4. For Mobile Access or Web access consider subscribing to Mobile.

### Launch Script (RAG\_RUN.bat)

AI-Prowler is launched via `RAG\\\_RUN.bat`, which sets two important environment variables before starting the GUI:

* **`PYTHONNOUSERSITE=1`** — prevents Python from loading stale package versions from the Roaming site-packages folder. This fixes a class of "wrong version" bugs that can occur after reinstalls.
* **`HF\\\_HUB\\\_CACHE`** — sets the HuggingFace cache path explicitly to avoid the Errno 22 / double-backslash bug on some Windows 10 builds (see Section 17).

These are set automatically; no user action is required.

\---

## 3\. Connecting Claude Desktop via MCP

Claude Desktop connects to AI-Prowler via the MCP (Model Context Protocol) — a standard that lets Claude use external tools and data sources.

### How It Works

The installer automatically writes AI-Prowler's entry into Claude Desktop's configuration file:

```
%APPDATA%\\\\Claude\\\\claude\\\_desktop\\\_config.json
```

When Claude Desktop starts, it connects to AI-Prowler and discovers all available tools automatically. No manual configuration is needed. Note if mobile is configured, only mobile access will be used for all Claude MCP connections going forward. This includes when in Claude Desktop application.

### Verifying the Connection

Open Claude Desktop and start a new conversation. You should see a tools indicator showing AI-Prowler is connected. Ask:

```
What AI-Prowler tools do you have available?
```

Claude will list all available tools. If you see `get\\\_knowledge\\\_base\\\_overview` and `search\\\_documents`, the connection is working.

### If Claude Desktop Loses the Connection

1. Open AI-Prowler
2. Go to **Settings → Claude Desktop MCP**
3. Click **Write MCP Config** to re-write the configuration
4. Restart Claude Desktop completely (quit from the system tray, then relaunch)
5. Start a **new chat or conversation** — note, existing conversations do not pick up reconnected tools

### Manual Config Reference

If you need to add AI-Prowler to Claude Desktop manually, the config entry looks like:

```json
{
  "mcpServers": {
    "AI-Prowler": {
      "command": "C:\\\\\\\\Users\\\\\\\\YourName\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Programs\\\\\\\\Python\\\\\\\\Python311\\\\\\\\python.exe",
      "args": \\\["C:\\\\\\\\Program Files\\\\\\\\AI-Prowler\\\\\\\\ai\\\_prowler\\\_mcp.py"]
    }
  }
}
```

A pre-filled example is in `C:\\\\Program Files\\\\AI-Prowler\\\\claude\\\_desktop\\\_config\\\_example.json`.

### MCP Diagnostics Tool

If tools are not appearing or tool calls are failing in Claude Desktop, use the built-in diagnostics tool:

1. Go to **Settings → Claude Desktop MCP**
2. Click **🔬 Run MCP Diagnostics**
3. A scrollable output window shows:

   * MCP SDK version and `instructions=` support status
   * FastMCP constructor parameters
   * Whether all agentic RAG tools are present in `ai\\\_prowler\\\_mcp.py`
   * Claude Desktop config validity
   * Subscription cache status
   * MCP server log tail
   * rag\_preprocessor import and ChromaDB path check
4. Click **📋 Copy Output** to copy the full report for sharing with support

### stdio Transport and stdout Protection

If AI-Prowler is not configured for Mobile, When Claude Desktop launches AI-Prowler's MCP server, it communicates over the stdio pipe (standard input/output). The server includes a critical protection mechanism:

* **`\\\_STDIO\\\_MODE` flag** — set to `True` before `mcp.run()` is called; this disables all internal stdout redirection so no tool call can accidentally corrupt the MCP pipe
* **stdout sealed to devnull** — immediately before the MCP server starts, `sys.stdout` is redirected to `os.devnull`, ensuring that any stray `print()` from third-party libraries cannot corrupt the JSON-RPC stream

This prevents the "Claude's response was interrupted" error that can occur when tool calls try to capture print output.

\---

## 4\. Indexing Your Documents

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
* **Smart Scan** — Selects file types and allows preview of what would be indexed without committing
* **Pause / Resume** — stop mid-index and continue later

### Index Size

There is no practical limit on index size. A 10,000-document collection with 500,000 chunks is typical for a large business knowledge base.

### Tracking Directories

Directories added for indexing are tracked automatically. The **Update Index** tab re-scans all tracked directories and indexes only what has changed. Set up scheduling (see Section 15) for fully automatic updates.

### Automatic Purge of Deleted Files

When you delete a file from a tracked folder and then run **Update Selected** or **Update All** in the Update Index tab, AI-Prowler automatically purges that file's chunks from ChromaDB. This keeps the vector database in sync with your file system — no manual cleanup required.

Previously, deleted files were detected by the scan and removed from the tracking database but their chunks remained in ChromaDB, causing the knowledge base to return stale results for files that no longer existed. This is fixed in v5.0.0: the update run now performs a **purge pass first** (removing all ChromaDB chunks for deleted files), then the **index pass** (adding new and modified files). The output panel shows a `🗑️ PURGING DELETED FILES` section whenever purged files are found.

This same auto-purge fires across all entry points: the GUI Update buttons, the MCP `update\_tracked\_directories` tool, and the scheduled `.bat` task.

### Automatic Purge of Skipped Extensions

When you add a file extension to the **Skipped** list in Smart Scan Config and then run indexing, AI-Prowler automatically purges any existing chunks for that extension from the database at the start of the index run. It also removes those files from the tracking database so they are treated as new if you ever move them back to Supported. This keeps the knowledge base consistent with your current extension settings without requiring a full re-index.

### Progress Display

The indexing progress display shows:

* A progress bar that grows as files are processed
* An elapsed-time counter updated every second
* Per-file status messages in the output panel
* File counts (e.g., `\\\[File 47/312] report.pdf`)

### Mobile Write Zones — Granting Claude Write Access

Indexing a directory makes its contents **searchable**. It does *not* let Claude **modify** files there. Write access is a separate, opt-in permission you grant per directory through the **Update Index** tab.

The tracked-paths listbox at the top of the Update Index tab now shows a write-permission prefix on every row:

```
[W]   C:\Users\david\AI-Prowler-ADMIN
[W*]  C:\Users\david\AI-Prowler_V601_to_V602_work
[R]   C:\Users\david\AI_Evolution\UserManualDOC
[R]   C:\Users\david\OneDrive\Documents\AI-Prowler
```

* `[W]` — **writable.** This path is in your writable allowlist (or an ancestor is). Claude can create, edit, and delete files anywhere inside, from desktop *and* mobile, with no further prompt.
* `[W*]` — **partially writable.** A narrower sub-directory of this path is granted, but the path itself isn't. Files inside that sub-directory are writable; everything else here is not.
* `[R]` — **read-only.** Claude can search content here but cannot modify any file.

**Double-click a row to toggle:**

* `[R]` → `[W]` — opens a confirmation dialog warning that the grant applies to all sessions including mobile. On YES, the path is added to `~/.rag_writable_dirs.json`.
* `[W*]` → `[W]` — opens a "widen?" dialog listing the narrower sub-grants that will be absorbed. On YES, those narrower entries are removed and replaced with a single grant at this path's level.
* `[W]` → `[R]` — instant revoke, no confirmation. If write access is inherited from an ancestor in the allowlist, an info dialog tells you which ancestor grants it so you can revoke from there.

The legend below the listbox documents these indicators for at-a-glance reference.

**The writable allowlist is a separate file from the tracked-paths list:**

```
%USERPROFILE%\.rag_writable_dirs.json
```

You can edit it by hand if you prefer — it's a sorted JSON array of full directory paths. The GUI re-reads it every time the list refreshes, so changes show up immediately.

**Why this is separate from indexing:** searching documents is permissive (you want Claude to know about as much as possible). Writing to disk is restrictive (a runaway edit loop is a real risk). The two-allowlist design lets you index broadly while writing narrowly. See Section 6 — Code Tools (Write-Side) for the full security model.

\---

## 5\. Agentic RAG — How Claude Uses Your Knowledge Base

This is the core capability of AI-Prowler. Understanding it helps you get the best results.

### The Research Loop

When you ask Claude a question with AI-Prowler connected, Claude follows this pattern automatically (guided by built-in instructions):

```
Step 1 — Orient
  Claude calls: get\\\_knowledge\\\_base\\\_overview()
  Claude learns: what documents are indexed, file types, topics covered

Step 2 — Explore
  Claude calls: list\\\_indexed\\\_documents(filter\\\_ext="pdf")
  Claude learns: which specific files might be relevant

Step 3 — Search
  Claude calls: search\\\_documents("your main topic")
  Claude calls: search\\\_documents("related angle or synonym")
  Claude calls: search\\\_by\\\_multiple\\\_queries(\\\["term1", "term2", "term3"])
  Claude gathers: relevant chunks from multiple angles

Step 4 — Expand
  Claude calls: get\\\_chunk\\\_context("file.pdf", 12)
  Claude reads: the paragraphs around a promising but incomplete result

Step 5 — Deep Read
  Claude calls: get\\\_document\\\_chunks("contract.pdf", start\\\_chunk=0)
  Claude reads: an entire document sequentially when needed

Step 6 — Synthesize
  Claude writes: a comprehensive answer from everything it gathered
```

### Tips for Best Results

**Ask open-ended research questions.** Claude works best when given latitude to investigate. "What does our policy say about refunds?" is better than "find the word refund."

**Let Claude finish.** You'll see multiple tool calls before Claude answers. This is the agentic loop working. Don't interrupt unless it's taking an unusually long time.

**Ask follow-up questions.** Claude retains context within a conversation. "What about international orders?" after a refund policy question will trigger another search with that refinement.

**Specify document types when relevant.** "In our PDF contracts, what are the liability limits?" helps Claude narrow its search efficiently.

### Calling Tools Manually

You can also direct Claude explicitly:

```
Call search\\\_documents("Q3 financial results") and show me the raw chunks.
```

```
Use get\\\_document\\\_chunks to read the entire executive summary document.
```

This is useful when you want to see what's in the knowledge base before asking Claude to interpret it.

\---

## 6\. MCP Tools Reference

AI-Prowler exposes **39 tools** to Claude. They fall into six categories: Agentic RAG (8), Knowledge Base Management (5), Status (1), Small Business Actions (7), Self-Learning (6), and Code Tools (9). Three additional anchor tools — `how_to_use_ai_prowler`, `get_database_stats`, and `check_status` — sit alongside.

### Agentic RAG Tools (Primary)

These tools require no local LLM. Claude does all reasoning directly.

#### `how\\\_to\\\_use\\\_ai\\\_prowler()`

Returns the recommended workflow and tool sequence. Claude calls this automatically at the start of research sessions. You can also call it explicitly to see usage guidance and confirm the MCP connection is active. Also reports the active MCP SDK version and whether the `instructions=` parameter is supported.

#### `get\\\_knowledge\\\_base\\\_overview()`

Returns a summary of the entire knowledge base: document count, file types, chunk count, database location, and tracked directories. Call this to orient Claude at the start of a research task.

#### `search\\\_documents(query, n\\\_results, min\\\_similarity)`

The primary retrieval tool. Performs semantic vector search and returns raw document chunks with source metadata and similarity scores. Claude calls this multiple times with different query phrasings to gather comprehensive context.

Parameters:

* `query` — natural language search query
* `n\\\_results` — chunks to return (default 8, max 20)
* `min\\\_similarity` — filter threshold 0.0–1.0 (default 0.0)

#### `search\\\_by\\\_multiple\\\_queries(queries, n\\\_results\\\_each, min\\\_similarity)`

Runs 2–6 search queries in parallel and returns deduplicated results ranked by best similarity. More efficient than calling `search\\\_documents` repeatedly when a topic has multiple angles or synonyms.

#### `get\\\_chunk\\\_context(filename, chunk\\\_index, window)`

Retrieves the chunks immediately before and after a specific chunk, providing fuller context around a result that may be cut off at a chunk boundary.

Parameters:

* `filename` — filename from a search result (partial match accepted)
* `chunk\\\_index` — zero-based index from the search result
* `window` — chunks before and after to include (default 2, max 5)

#### `get\\\_document\\\_chunks(filename, start\\\_chunk, max\\\_chunks)`

Retrieves chunks from a specific document in reading order. Use for full document summaries or when a user asks "what does this document say?"

Parameters:

* `filename` — filename to retrieve (partial match accepted)
* `start\\\_chunk` — zero-based starting position (default 0)
* `max\\\_chunks` — chunks per call (default 10, max 30)

#### `list\\\_indexed\\\_documents(filter\\\_ext, filter\\\_path, limit)`

Lists all indexed documents grouped by file type. Use to browse available content before searching.

Parameters:

* `filter\\\_ext` — show only this type, e.g. "pdf", "docx"
* `filter\\\_path` — show only files whose path contains this string
* `limit` — max documents shown (default 50)

#### `search\\\_within\\\_directory(query, directory, n\\\_results, min\\\_similarity)`

Directory-scoped semantic search. Restricts results to a single folder tree, filtering by the `parent_directory` and `directory_chain` metadata recorded at index time. Use this when the user asks about a specific case, project, client, or folder and you need to guarantee results don't bleed in from other parts of the corpus.

Parameters:

* `query` — natural language search query
* `directory` — directory name or path fragment to restrict the search to (e.g. `"Smith\_v\_Jones"`, `"2024"`, `"Contracts"`). Matches against `parent_directory` exactly first; falls back to substring match on `directory_chain` if too few results.
* `n\\\_results` — chunks to return (default 8, max 20)
* `min\\\_similarity` — filter threshold 0.0–1.0 (default 0.0)

#### `list\\\_directories()`

Returns the directory tree of all indexed content with document counts per folder. Sorted alphabetically. Use this to orient before calling `search_within_directory` — it tells Claude what scopes are available. Reads from `directory_chain` / `parent_directory` metadata recorded at index time, so documents indexed before the provenance system was added (very old installs) won't appear here until re-indexed.

### Knowledge Base Management Tools

These tools let Claude help you manage your knowledge base from a conversation.

#### `add\\\_and\\\_index\\\_directory(directory, recursive, track)`

Indexes all documents in a folder and optionally adds it to the auto-update tracking list.

#### `update\\\_tracked\\\_directories(directory)`

Re-scans tracked directories and indexes only changed files. Omit `directory` to update all tracked folders.

#### `get\\\_database\\\_stats()`

Returns statistics: chunk count, unique document count, breakdown by file type, and database location. Queries ChromaDB directly for accurate counts.

#### `list\\\_tracked\\\_directories()`

Lists all directories currently registered for auto-update tracking.

#### `remove\\\_directory(directory)`

Removes a directory from tracking and deletes all its chunks from ChromaDB. Destructive — requires re-indexing to restore.

### Status Tool

#### `check\\\_status()`

Checks ChromaDB connectivity, reports the chunk count, database path, embedding model status, and tracked directories. No Ollama or local LLM is involved.

### Small Business Action Tools

Seven tools for field service automation. Free tools require no setup; spreadsheet tools use the default path from Settings.

#### `get\\\_weather(location, days)`

Current conditions and a multi-day forecast for any location. Uses Open-Meteo and Nominatim — free, no API key. Rain probability ≥ 50% is flagged with ⚠️. Use before scheduling outdoor jobs.

#### `geocode\\\_address(address)`

Converts a street address to GPS coordinates (latitude/longitude) via Nominatim / OpenStreetMap — free, no key. Useful before running route optimization to verify addresses can be geocoded.

#### `get\\\_route\\\_optimization(stops, origin, optimize\\\_for, departure\\\_hour, return\\\_to\\\_origin)`

Solves the Traveling Salesman Problem for a list of job stops. Geocodes addresses via Nominatim (0.35 s/address courtesy delay), routes via OSRM public server using real street distances. Returns the optimal stop sequence with estimated arrival time per stop.

#### `build\\\_maps\\\_url(stops, origin, app)`

Generates a tap-to-navigate Google Maps (or Apple Maps) URL with all stops pre-loaded in optimized order. Auto-splits routes longer than 9 stops into legs (Google Maps URL limit). Works on iPhone, Android, CarPlay, and Android Auto — free, no key.

#### `update\\\_job\\\_spreadsheet(filepath, job\\\_identifier, updates, id\\\_column, sheet\\\_name, backup)`

Updates a row in an `.xlsx` job tracking spreadsheet after a job is completed. Finds the customer row by name match, writes new values to specified columns (status, invoice number, amount, last service date, etc.). Uses `openpyxl` — no new packages needed.

The `backup` parameter (default `True`) saves a timestamped copy of the spreadsheet to a `\_backups` subfolder next to the file before any changes are written. Backups older than 30 days are pruned automatically. Pass `backup=False` to skip the backup step.

Column headers with embedded newlines (e.g. `"Job\\nStatus"`) can be passed either with the newline or with a space (`"Job Status"`) — the tool normalises both forms automatically.

#### `read\\\_job\\\_spreadsheet(filepath, sheet\\\_name, filter\\\_date, max\\\_rows)`

Reads job data from the AI-Prowler job tracking spreadsheet and returns it as structured text. Use this to answer scheduling questions, review open jobs, or check what's planned for a specific date.

Parameters:

* `filepath` — full path to the `.xlsx` spreadsheet (omit to use the configured default)
* `sheet\_name` — sheet to read (default: `Jobs\_Schedule`; use `"Customers"` for the customer master list)
* `filter\_date` — optional date filter: `"today"`, `"2026-03-31"`, `"03/31/2026"`, etc.
* `max\_rows` — maximum data rows to return (default 200, max 500)

Both spreadsheet tools auto-detect the real header row by scanning the first five rows and using the first row with three or more non-empty cells. This correctly skips decorative title/banner rows at the top of the sheet.

#### `get\\\_action\\\_tools\\\_status()`

Returns a full status report for all action tools: which are ready, which need configuration, and setup instructions for anything missing. Call this first when troubleshooting the Small Business tools.

### Self-Learning Tools

Six tools for RAG-based knowledge accumulation. See Section 20 for full details.

#### `record\\\_learning(title, content, category, context, source, confidence, tags, supersedes\\\_id, outcome, auto\\\_detected)`

Records a new learning (fact, lesson, insight) into the self-learning knowledge base. Instantly indexed in ChromaDB. Categories include: `fact\_correction`, `business\_lesson`, `project\_insight`, `process\_improvement`, `mistake\_learned`, `best\_practice`, `client\_preference`, `technical\_note`, and `general`. The `auto\_detected` flag controls whether Claude shows a prominent confirmation banner (auto-detected) or a concise confirmation (operator-requested). Claude calls this automatically when it detects corrections, project outcomes, or process improvements in conversation.

#### `check\\\_learned(query, n\\\_results, category, include\\\_deprecated)`

Semantic search across the self-learning knowledge base. Claude calls this proactively before answering questions about clients, projects, scheduling, or procedures. Returns matching learnings ranked by relevance with confidence scores, context, and metadata. Also increments the `applied\_count` on each returned learning for usage tracking.

#### `list\\\_learnings(category, status, tag, limit)`

Browses all learnings with exact-match filters (category, status, tag). Unlike `check\_learned` (semantic search), this lists by recency. Use to audit the knowledge base or review all learnings in a category.

#### `update\\\_learning(learning\\\_id, updates)`

Modifies fields on an existing learning: title, content, context, category, confidence, tags, status, or outcome. Used after the confirmation protocol when the user corrects a recorded learning.

#### `delete\\\_learning(learning\\\_id)`

Permanently removes a learning from both the JSON file and ChromaDB index. Destructive — consider archiving with `update\_learning(id, {status: "archived"})` instead.

#### `get\\\_learning\\\_stats()`

Returns summary statistics: total count, breakdown by category/source/outcome/status, most frequently applied learnings, and file path.

### Code Tools (Write-Side)

Nine tools for file creation, editing, listing, backup, and restore. Together they let Claude work as a coding agent on directories you've explicitly authorized — from desktop or mobile. All write operations are subject to the security model described at the end of this sub-section.

#### `create\\\_file(filepath, content)`

Creates a new file with the given content. Fails if the file already exists (use `write_file` to overwrite). Content is encoded as UTF-8. On Windows, pure-LF content (`\n`-only) is automatically translated to CRLF (`\r\n`) so new files match the platform convention; content with explicit `\r` bytes is written verbatim. Newly-created files in tracked directories are immediately indexed in ChromaDB.

#### `write\\\_file(filepath, content, verify\\\_after\\\_write)`

Overwrites an existing file with new content. Fails if the file doesn't exist (use `create_file` to create new). Detects the existing file's line-ending convention (CRLF or LF) and preserves it on write — so editing a Windows file from a tool that produces LF input still leaves a clean CRLF file on disk. An automatic backup is created as `<filepath>.bak<N>` before any change. If `verify_after_write=True`, the tool reads the file back and includes the first/last few lines in the response for visual confirmation.

#### `str\\\_replace\\\_in\\\_file(filepath, old\\\_str, new\\\_str, dry\\\_run)`

Surgical in-place edit: replaces one unique occurrence of `old_str` with `new_str`. The `old_str` must appear exactly once in the file — if it appears zero times or more than once, the tool refuses and reports the count. Useful for narrow code edits where you don't want to send the whole file across the wire. Set `dry_run=True` to see the unified diff and byte-count impact without writing. An automatic backup is created as `<filepath>.bak<N>` before any change. Line endings of the original file are preserved on write.

#### `create\\\_directory(dirpath)`

Creates a directory (and any missing parents). Idempotent — succeeds if the directory already exists. Subject to the writable allowlist just like file writes.

#### `list\\\_directory(dirpath)`

Lists the immediate contents of a directory: files (with byte sizes), subdirectories, and any `.bak<N>` backups, with backups segregated from active files so you can see at a glance what's been edited. Read-only; works on any tracked path regardless of write permissions.

#### `copy\\\_to\\\_backup(filepath)`

Creates a manual snapshot of a file as `<filepath>.bak<N>`, where `N` is the next unused backup number. The active file is not changed. Use before destructive operations you want extra protection on, or to bookmark a known-good state before a series of edits.

#### `list\\\_backups(filepath)`

Lists all `<filepath>.bak<N>` backups for a given file, with timestamps and sizes, newest backup last. Read-only.

#### `restore\\\_backup(filepath, backup\\\_number)`

Overwrites the active file with the contents of `<filepath>.bak<N>`. The backup itself is preserved on disk (restore is non-destructive to backups). Note: this does *not* automatically snapshot the current state before restoring — if you want to roll back the rollback, call `copy_to_backup` first.

#### `reset\\\_write\\\_counter()`

Resets the per-session write circuit breaker (see Security Model below). Reports the previous count and confirms reset to `0 / 20`. Useful during long sessions involving many writes — Claude calls this only on operator request.

### Code Tools — Security Model

Write-side tools are protected by four independent layers. All four must permit an operation for it to succeed.

**Layer 1 — Read allowlist (`~/.rag_auto_update_dirs.json`).** A file's parent directory must be tracked for indexing before any write tool can address it. If you haven't indexed a folder, Claude cannot write to it.

**Layer 2 — Writable allowlist (`~/.rag_writable_dirs.json`).** A *separate* file from the read allowlist. The file's parent (or an ancestor) must be in this list. Indexing alone is not enough — write access is a distinct opt-in granted through the Mobile Write Zones UI (see Section 4) or by hand-editing the JSON.

**Layer 3 — Hard blocklist (always wins).** Even if a path passes layers 1 and 2, writes are *unconditionally refused* if the path is under any of: `C:\Windows`, `C:\Program Files` (except AI-Prowler's own writable state), `%AppData%` (except AI-Prowler's own state), `%LocalAppData%` (same exception), `.git`, `.ssh`, `.aws`, the active job tracker `.xlsx`, and any of AI-Prowler's own JSON state files. Adding these paths to the writable allowlist does *not* override the blocklist.

**Layer 4 — Per-session circuit breaker.** A maximum of 20 writes per server lifetime. After the 20th write, all write tools return a "circuit breaker tripped" error until you call `reset_write_counter` explicitly. This caps the blast radius of a runaway edit loop and forces a human in the loop on long sessions.

**Backup-as-audit-trail.** There is no separate audit log. Instead, *every* modification leaves a `.bak<N>` next to the file, and the `<N>` is monotonic for the file's lifetime. Backups are never auto-deleted — only you can remove them. This means the full history of any edited file is reconstructible from the filesystem alone, with no external dependency.

**Mobile implications.** Because all four layers are enforced at the MCP server (not at the client), they apply identically to desktop, mobile, and any future Claude client. Granting a Mobile Write Zone via the GUI is a *deliberate desktop action* — the chat channel cannot create or widen a zone, only the GUI can. This is by design: the trust root for "may Claude write here" stays at the keyboard, not in the conversation.

\---

## 7\. Remote Access — Claude.ai on Mobile and Web

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

### Setup Steps (Quick Start)

**1. Set a Bearer Token**

In AI-Prowler, go to **Settings → Remote Access**. Enter a Bearer token — this is a password you create. Make it at least 10 characters with mixed case and numbers. Click **Save Token**.

**2. Start the HTTP Server**

Click **▶ Start HTTP Server**. The status light turns green when running. You will also see the internet and subscription status lights update.

**3. Start a Cloudflare Tunnel**

For quick testing, use **🚀 Quick Tunnel** (temporary URL, changes on restart). For permanent daily use, set up a **Named Tunnel** with your own domain. See the detailed guides below.

**4. Connect Claude.ai**

Add your tunnel URL as a custom connector in Claude.ai Settings → Connectors. See "Connecting Claude.ai to Your Knowledge Base" below for step-by-step instructions.

  ### Status Lights

  The HTTP MCP Server section in Settings shows two status indicators:

* **Internet ●** — green when your PC can reach GitHub (required for subscription checks)
* **Mobile Subscription ●** — shows your subscription status:

  * 🟢 Green `Active` — subscription paid and current
  * 🟡 Yellow `Expiring in Xd` — expiring within 30 days
  * 🟡 Yellow `Unpaid — Xd left` — expired but within the 30-day grace period
  * 🔴 Red `Access Blocked` — grace period elapsed, renewal required
  * 🔴 Red `Not Subscribed` — token not registered in the subscription system

  ### Sleep Prevention

  When the HTTP server is running, AI-Prowler automatically prevents Windows from going to sleep using the Windows `SetThreadExecutionState` API. This ensures Claude.ai connections remain active without needing to change your power settings. Sleep is restored automatically when you stop the server or close AI-Prowler.

  ### Cloudflare Tunnel — Quick Tunnel (Testing)

  For quick testing without permanent DNS setup, use the **Quick Tunnel** option:

1. Click **▶ Start HTTP Server** to start the MCP server
2. Click **🚀 Quick Tunnel** — this creates a temporary Cloudflare Tunnel with an auto-generated URL (e.g. `https://random-words.trycloudflare.com`)
3. Copy the URL shown in the status area
4. Add it as a custom connector in Claude.ai (append `/mcp` to the URL)
5. The tunnel lasts as long as AI-Prowler is running — the URL changes every time you restart

  Quick Tunnels are ideal for initial testing, demos, or temporary access. For permanent daily use, set up a Named Tunnel instead.

  ### Cloudflare Tunnel — Named Tunnel Setup (Permanent)

  A Named Tunnel gives you a permanent, branded URL (e.g. `https://mobile.your-company.com/mcp`) that never changes. This is the recommended setup for daily use.

  **Prerequisites:**
  * A free Cloudflare account at [dash.cloudflare.com](https://dash.cloudflare.com)
  * A domain name added to your Cloudflare account (free domains work fine)

  **Step-by-step setup:**

  1. **Login** — Click the **Login** button in Settings → Remote Access → Cloudflare Tunnel. This opens your browser to authenticate with Cloudflare. After login, a certificate file is saved locally. You only need to do this once per machine.

  2. **Create Tunnel** — Click **Create Tunnel**. Enter a name for your tunnel (e.g. `ai-prowler`). AI-Prowler creates the tunnel in your Cloudflare account and saves the tunnel credentials locally.

  3. **Route DNS** — Click **Route DNS**. Enter the hostname you want to use (e.g. `mobile.your-company.com`). AI-Prowler creates a CNAME record in your Cloudflare DNS that points to the tunnel. This is what makes the URL permanent.

  4. **Save Config** — Click **Save Config**. This writes the tunnel configuration file that tells `cloudflared` how to route traffic from your public URL to the local HTTP server.

  5. **Start Tunnel** — Click **▶ Start Tunnel**. The tunnel connects to Cloudflare and your public URL is now live. The status indicator turns green.

  After this one-time setup, daily operation is just two clicks: **Start HTTP Server** → **Start Tunnel**.

  ### Installing Tunnel as a Windows Service

  For always-on access (e.g. accessing your knowledge base from your phone without opening AI-Prowler):

  * Click **Install as Windows Service** — this registers `cloudflared` as a Windows background service
  * The tunnel starts automatically at boot, even without logging in
  * AI-Prowler's HTTP server must still be running for Claude.ai to reach your knowledge base

  ### Connecting Claude.ai to Your Knowledge Base — Step by Step

  The HTTP/Cloudflare path is exclusively for Claude.ai (web and mobile). **Do not add this URL to Claude Desktop** — Claude Desktop uses the stdio path configured automatically by the installer.

1. Open [claude.ai](https://claude.ai) in a browser and sign in (Claude Pro or Team required)
2. Click your profile icon (top right) → **Settings**
3. In the left sidebar, click **Connectors**
4. Click **Add custom connector** (or **+ Add** depending on your plan)
5. In the **MCP Server URL** field, enter your tunnel URL followed by `/mcp`:

```
   https://mobile.your-company.com/mcp
   ```

6. Claude.ai redirects you to your AI-Prowler authorization page
7. Enter your Bearer token and click **Connect**
8. Claude.ai redirects back — AI-Prowler now appears in your Connectors list with a green status dot

   **To use the connector in a conversation:**

* Start a new conversation on Claude.ai
* In the chat toolbar, click the **Connectors** or **Tools** button (puzzle-piece icon)
* Select **AI-Prowler** to enable it for that conversation
* Ask any research question — Claude will call your knowledge base tools automatically

  **Tip:** Claude.ai in the browser supports downloading any files that Claude produces (code, documents, reports) directly to your machine, whereas the Claude Desktop app may open some file types in-app. If you need to save Claude's outputs as files, Claude.ai in the browser is the better choice for that workflow.

  **Troubleshooting the connection:**

* If the connector shows a red dot, check that both the HTTP server and tunnel are running in AI-Prowler
* If authentication fails, verify your Bearer token matches exactly between AI-Prowler Settings and the Claude.ai authorization page
* After any configuration change, remove and re-add the connector in Claude.ai Settings
* Start a **new conversation** after reconnecting — existing conversations do not pick up reconnected tools

  \---

  ## 8\. Mobile Subscription Management

  ### Subscription Plans

|Plan|Price|Users|Use Case|
|-|-|-|-|
|Individual|$10/month|1|Personal use|
|Small Business|$30/month|Up to 5|Team deployment|
|Enterprise|Contact us|6+|Custom deployment|

### How to Subscribe

Email david.vavro1@gmail.com with:

* Your name or company name
* Which plan you want
* Your Bearer token (shown in Settings → Remote Access)

Your Bearer token **never changes** between billing periods. No reconfiguration is needed on renewal.

### Grace Period

If your subscription lapses, a 30-day grace period begins:

* Remote access continues working with a warning banner on the login page
* The subscription light turns yellow showing remaining days
* After 30 days, access is suspended until renewal

### Subscription Manager GUI

The **Subscription Manager** (`subscription\\\_manager\\\_gui.py`) is a separate admin tool for managing subscribers. Run it with the provided `RUN.bat` in your private admin folder. Note: this is not for users, AI-Prowler ADMIN uses this program to manage subscribers via GitHub.

Features:

* List all subscribers with status
* Add new subscribers
* Renew subscriptions (no token change needed)
* Revoke access
* Check which subscriber owns a token
* View expiring subscriptions

### Subscription Registry

Subscription data is stored in a public GitHub repository (`ai-prowler-subs`). The repository is public for reading (no authentication needed on subscriber machines) but only the ADMIN can write to it.

Data stored: token hashes (not the tokens themselves), expiry dates, subscriber names. No payment details, no personal information beyond what you enter.

\---

## 9\. Small Business Service Tools

The Small Business tab (the last tab before 🧠 Learnings in AI-Prowler) provides configuration and quick-reference for the field service automation MCP tools. These tools let Claude act as your field service assistant from a conversation — no forms or menus needed. Note: This tool is designed for a service orientated small business to make scheduling, servicing, and tracking jobs easy with the help of your local data and Claude AI.

### Accessing the Tab

Click the **🏢 Small Business** tab in AI-Prowler. If you are in the Settings tab, a **➜ Go to Small Business Service Tools** button links directly to it.

### Free Tools Panel

Four tools require no setup and work immediately:

* **get\_weather** — Open-Meteo + Nominatim (no API key)
* **geocode\_address** — Nominatim / OpenStreetMap (no API key)
* **get\_route\_optimization** — OSRM public routing server (no API key)
* **build\_maps\_url** — Google Maps / Apple Maps URL scheme (no API key)

### Job Tracker Spreadsheet

The installer deploys a pre-built `AI-Prowler\_Job\_Tracker.xlsx` to your `Documents\\AI-Prowler\\` folder. This spreadsheet has eight interconnected tabs designed to work with the `update\_job\_spreadsheet` MCP tool:

|Tab|Purpose|
|-|-|
|Customers|Customer master list with addresses, service type, frequency|
|Jobs\_Schedule|All service appointments with route and weather columns|
|Route\_Planner|Daily route optimization — AI fills lat/lon and map URLs|
|Quotes|Estimates sent to customers|
|Invoices|Billing and payment tracking|
|QB\_Daily\_Export|Daily export rows for accounting software import|
|Services\_Pricing|Service catalog with pricing|
|AI-Prowler\_Commands|Quick reference for Claude prompts|

> \*\*Important:\*\* Do not rename column headers in the Job Tracker. The `update\_job\_spreadsheet` tool matches rows by the column header text. Renamed headers will cause the tool to fail to find the correct column. Column headers with embedded newlines (e.g. `"Job\\nStatus"`) can be passed either with the newline or with a space — the tool normalises both automatically.

> \*\*Backup:\*\* Every `update\_job\_spreadsheet` call automatically saves a timestamped backup to a `\_backups` folder next to the spreadsheet file before writing changes. Backups older than 30 days are pruned automatically. Pass `backup=False` if you want to skip this step.

The default spreadsheet path is written to `\~/.ai-prowler/config.json` during installation and pre-filled in the Small Business tab's Browse field.

### Route \& Navigation Notes

* **Nominatim geocoding delay:** 0.35 seconds per address is required by OpenStreetMap's terms of service. Geocoding 20 addresses takes approximately 7 seconds — this is normal, not a bug.
* **Google Maps URL limit:** Google Maps supports 9 waypoints per URL. Routes longer than 9 stops are automatically split into legs.
* **Apple Maps option:** Pass `app='apple'` to `build\_maps\_url` for iPhone/iPad-only navigation links.

### Example Claude Prompts

```
"What is the weather forecast for New Smyrna Beach for the next 3 days?"
"Optimize my route for these 6 jobs today and give me a Google Maps link."
"Mark the Miller Windows job complete in my jobs spreadsheet and record invoice #1048."
"What jobs do I have scheduled for today?"
"Show me all open jobs in my spreadsheet this week."
"Read the Customers sheet and tell me who is on a monthly schedule."
"Call get\_action\_tools\_status() and tell me what needs to be configured."
```

\---

## 10\. Quick Links Tab

The **Quick Links** tab (formerly "Ask Questions" in v5.x) is a one-click launcher for the recommended Claude Desktop workflow. It is the second tab from the left in the GUI.

### What you see by default

The tab contains:

* **AI Agent Smart Guided Questions & Answers** banner — a blue "⭐ RECOMMENDED" panel that briefly explains why Claude Desktop with Agentic RAG produces far better answers than a single-shot local Q&A box. The banner is purely informational.
* **🚀 Launch Claude Desktop** button — opens Claude Desktop directly using its registered Windows AUMID. If your install is fresh and Claude Desktop isn't reachable, the button falls back to a PowerShell-based dynamic lookup that survives Claude Desktop updates.
* **⬇ Download Claude Desktop** button — opens `claude.ai/download` in your default browser for users who don't have it yet.
* **🌐 Open Claude.ai** button — opens `claude.ai` in your browser for mobile/web access via the HTTP MCP server (see Section 7 for tunnel setup).

That's it. No Q&A input box, no model picker, no microphone, no spell checker.

### Why the Q&A box is hidden

AI-Prowler v6.0.0 ships with `SUPPORT_LOCAL_HW_LLM = False` as the default. This hides several local-AI features that earlier versions exposed by default:

* Your-Question input box
* Attach-files button
* Ask Question / submit button
* Microphone button with Whisper voice input
* Inline spell-checker
* Cloud-API provider selection

The reasoning: the typical AI-Prowler user's workflow is **Claude Desktop or Claude.ai → MCP → AI-Prowler RAG**. Claude does its own LLM hosting, its own UI, its own conversation history. A second Q&A box inside AI-Prowler duplicates that work for no benefit, and adds visual clutter and configuration knobs that aren't needed.

### Advanced / Power-User Features (off by default)

If you specifically need the standalone Q&A interface — e.g. fully offline operation with Ollama, or using a cloud LLM provider directly — you can re-enable it by editing `rag_gui.py`:

```python
# Near the top of rag_gui.py (around line 120):
SUPPORT_LOCAL_HW_LLM = True   # was False
```

Restart AI-Prowler. The Quick Links tab will then show the full Q&A interface as described below. The Settings tab will also gain AI Model selection, External AI APIs, Ollama Server controls, and Microphone settings (see Section 11).

### What appears when `SUPPORT_LOCAL_HW_LLM = True`

The Quick Links tab gains a full local-AI Q&A interface below the Claude Desktop launcher banner:

* **Your Question** — text entry box with inline spell-check (red underline for misspellings, right-click for suggestions)
* **🎤 microphone** — Whisper-powered voice input (large-v3-turbo model, ~1.6 GB, downloaded on first use, runs entirely locally)
* **📎 Attachments** — image or text files; vision support requires a cloud provider with vision capability
* **🤖 Ask Question** — sends the question to the active model

#### Local Ollama models

Install via **Settings → Start the Ollama server → Browse & Install Model**. Recommended models by RAM:

|RAM|Model|Quality|
|-|-|-|
|4 GB|llama3.2:1b or qwen2.5:1.5b|Basic|
|8 GB|llama3.2:3b or qwen2.5:7b|Good|
|16 GB|llama3.1:8b or qwen2.5:14b|Very good|
|32 GB+|qwen2.5:32b or llama3.1:70b|Excellent|

#### Cloud AI providers

Add API keys in **Settings → External AI APIs**:

|Provider|Notes|
|-|-|
|ChatGPT (OpenAI)|GPT-4o, pay-per-use|
|Claude (Anthropic)|claude-sonnet-4-6|
|Gemini (Google)|Free tier available|
|Grok (xAI)|Limited free|
|Llama API (Meta)|Free tier available|
|Mistral Large|Limited free|

#### Voice Input

Whisper runs entirely locally — voice is never sent to any cloud service. Adjust the **microphone silence timeout** in Settings (default 3.0 s) if speech is being cut off early or if there's lag after you stop speaking.

#### File output

When the AI produces code, a 💾 Save button appears automatically. Works with all providers, though some local and external models don't trigger the save flow.

### Note on Agentic vs. single-pass retrieval

Even with `SUPPORT_LOCAL_HW_LLM = True`, the standalone Q&A box does **not** use the Agentic RAG tool loop. It does a single retrieval pass and sends the retrieved chunks to the chosen model. For multi-step research with follow-up queries and full document reading, use Claude Desktop or Claude.ai (which call the full 28-tool MCP surface).

\---

## 11\. Settings \& Configuration

> **v6.0.0 visibility note:** Several Settings sub-sections from earlier versions are now hidden by default to keep the GUI clean for the typical Claude Desktop / Claude.ai user. The underlying code is still present and the features still work — only the UI surfaces are suppressed. Sub-sections marked **🔒 hidden by default** below appear only when `SUPPORT_LOCAL_HW_LLM = True` or `DEBUG_EN = True` is set near the top of `rag_gui.py` (around line 120). Restart AI-Prowler after flipping a flag.

### Remote Access Tab

* **Bearer Token** — the password used to authenticate MCP connections from Claude.ai. Enter at least 10 characters of mixed case and numbers, then click **Save Token**. This token never changes between billing periods.
* **Port** — HTTP server port (default 8000). Only change this if port 8000 is in use by another service; you will also need to update your Cloudflare Tunnel route.
* **HTTP Server controls** — **▶ Start HTTP Server** / **■ Stop HTTP Server**. The status dot turns green when the server is listening. Starting the server automatically prevents Windows from sleeping (see Sleep Prevention below).
* **Status lights** — Internet ● (green = GitHub reachable) and Mobile Subscription ● (green = active, yellow = expiring/grace, red = blocked/unregistered)
* **Cloudflare Tunnel** — one-time setup buttons (Login, Create Tunnel, Route DNS, Save Config) and daily-use buttons (Start Tunnel, Stop Tunnel). See Section 7 for full setup walkthrough.
* **Install as Windows Service** — installs the Cloudflare Tunnel as a Windows background service that starts automatically at boot, even without AI-Prowler running.

> \\\*\\\*Note:\\\*\\\* The HTTP server and Cloudflare Tunnel are only needed for Claude.ai web/mobile access. Claude Desktop does \\\*\\\*not\\\*\\\* use these — it connects via the stdio MCP path configured automatically by the installer.

### Claude Desktop MCP Tab  🔒 hidden by default (requires `DEBUG_EN = True`)

This sub-section was suppressed in v6.0.0 because Claude Desktop registration happens automatically during install and rarely needs manual intervention. Enable `DEBUG_EN` to expose:

* **MCP Status** — shows whether AI-Prowler is correctly registered in Claude Desktop's `claude\\\_desktop\\\_config.json`
* **Transport mode note** — confirms that Claude Desktop uses the stdio (local process) path, not the HTTP server. If your config shows an HTTP URL here, click **Auto-configure Claude Desktop** to fix it.
* **⚙️ Auto-configure Claude Desktop** — writes the correct stdio entry for AI-Prowler into Claude Desktop's config file. Also offers to restart Claude Desktop immediately.
* **Open Claude Desktop Config** — opens `claude\\\_desktop\\\_config.json` in Notepad for manual inspection
* **View Example Config** — shows a reference configuration you can copy from
* **Copy Config Path** — copies the config file path to the clipboard
* **🔬 Run MCP Diagnostics** — runs a full health check and shows a scrollable report covering: MCP SDK version, tool count, config validity, subscription cache, and log tail. Use **📋 Copy Output** to share the report with support.

### Models Tab  🔒 hidden by default (requires `SUPPORT_LOCAL_HW_LLM = True`)

* **Active model** — switches between installed Ollama models for the Quick Links tab Q&A box
* **Browse \& Install Model** — opens a browser to Ollama's model library; you can then download a model directly from AI-Prowler's Settings
* **Auto-start Ollama** — when enabled, AI-Prowler launches the Ollama server automatically on startup. Not required if you are using Claude Desktop as your primary interface.

> The **GPU Layers** spinbox that used to appear here is now hidden — but the underlying value still drives Ollama prewarm and subprocess args. To override the default `-1` (auto), edit `gpu_layers` in `~/.ai-prowler/config.json` directly.

### External AI APIs Tab  🔒 hidden by default (requires `SUPPORT_LOCAL_HW_LLM = True`)

* API key fields for each supported cloud provider (ChatGPT, Claude, Gemini, Grok, Llama API, Mistral)
* **Test Connection** button per provider — verifies your key is valid and the endpoint is reachable
* Timeout settings — controls how long the Quick Links Q&A box waits for a cloud response before showing a timeout error

### Smart Scan Config Tab

* **Supported / Skipped extension lists** — add or remove file extensions to control which types are indexed. Drag an extension from Supported to Skipped (or vice versa) to change its status.
* **Exclude folder patterns** — enter partial path strings (e.g. `node\\\_modules`, `\\\\.git`) to skip those directories during indexing
* When an extension is moved to Skipped, existing chunks for that type are **purged automatically** at the start of the next index run — no manual cleanup needed
* These settings apply to all indexing operations (initial index, Update Index, and scheduled runs)

### Small Business Tab

* **Free Tools panel** — overview and backend attribution for weather, routing, geocoding, and maps URL tools (all free, no setup)
* **Job Spreadsheet Updater** — default `.xlsx` path with Browse button, pre-filled from installation; Save/Open Spreadsheet buttons
* **Route \& Navigation** — OSRM and Nominatim notes, typical 4-step workflow, Open Google Maps and Open Apple Maps shortcuts
* Configuration is stored in `\~/.ai-prowler/config.json`

### 🧠 Learnings Tab

The Learnings tab provides a desktop GUI for viewing and managing Claude's self-learning knowledge base. See Section 20 for full details.

* **Overview banner** — explains self-learning and shows example prompts
* **Statistics panel** — live counts: total, active, deprecated, archived, total applied, plus category breakdown
* **Learnings table** — sortable, filterable Treeview with columns for title, category, status, confidence, outcome, applied count, created date, and source. Filter by category, status, or free-text search. Click any row to expand details.
* **Detail panel** — full content, "why this was learned" context box, supersession chain info, copyable learning ID
* **Action buttons** — Refresh, Archive Selected, Delete Selected, Rebuild ChromaDB Index, Export to CSV, Open JSON File, Open Learnings Folder
* Data source: `~/.ai-prowler/learnings/self\_learning\_data.json`
* Works in view-only mode if `self\_learning.py` is not present (reads JSON directly)

### Scheduler Tab

* **Update frequency** — Daily, specific days of the week, or custom cron expression
* **Time** — what time to run the update (default 2:00 AM)
* **Create Schedule** — registers the task with Windows Task Scheduler
* **View Schedule** — shows the current scheduled task status and next run time
* The scheduler runs `update\\\_tracked\\\_directories` — only changed files are re-indexed, so scheduled runs are fast

### OCR Debug (in Settings toolbar)

* **OCR Debug button** — select any scanned PDF or image file and see the extracted text in a preview window before committing to indexing. Use this to verify OCR quality.
* **Enable OCR Debug logging** — writes full OCR output to a log file during every index run, useful for diagnosing extraction quality across a large batch.

### GPU Detection  🔒 hidden by default (requires `DEBUG_EN = True`)

The **GPU Acceleration** panel in Settings is suppressed in v6.0.0 — the auto-detection still runs at startup, picks sensible defaults, and writes to log files. The panel exposed manual GPU-layer overrides and a "🔍 Detect GPU" button which were rarely useful in practice. If you specifically need to see GPU status or override `gpu_layers`, enable `DEBUG_EN` in `rag_gui.py` and the panel returns.

When visible, the panel shows GPU model and VRAM, CUDA availability, current embedding device (CPU or CUDA), Ollama GPU layer allocation if Ollama is running, and a "Suggested GPU layers" hint based on available VRAM.

### Voice Input (Mic Settings)  🔒 hidden by default (requires `SUPPORT_LOCAL_HW_LLM = True`)

* **Silence timeout** — controls how many seconds of silence trigger end-of-speech detection (default 3.0 s). Increase if your speech is being cut off; decrease to reduce lag after you stop speaking. Visible only when the Quick Links Q&A Q&A box is enabled.

\---

## 12\. Supported File Types

AI-Prowler indexes **65+ file formats** by default. Extensions are split into two sets: **Supported** (indexed) and **Skipped** (never indexed). Both sets can be customised in **Settings → Smart Scan Config**.

### How File Content Is Extracted

Each supported format has a dedicated loader that converts its content into clean, searchable text before chunking. The table below shows which loader is used and any special processing notes relevant to search quality.

### Supported Extensions (indexed by default)

|Extension(s)|Category|Extractor|Notes|
|-|-|-|-|
|`.txt` `.md` `.rst`|Plain text / Markup|Built-in text reader / Markdown stripper|`.md`/`.rst` syntax (headers, links, code fences) is stripped so only prose is indexed|
|`.pdf`|Document|pdfplumber + Tesseract OCR|Text layer extracted first; if insufficient text is found the page is rendered at 300 DPI and OCR'd automatically — see Section 12|
|`.docx`|Word (modern)|python-docx|Body paragraphs **and table cells** are both extracted. Tables are rendered as pipe-separated rows so financial tables, schedules, and data grids are fully indexed|
|`.xlsx`|Excel (modern)|openpyxl|Each data row is rendered as self-contained `Column: Value` pairs. Dates are formatted as `YYYY-MM-DD`. All numeric values (currency, hours, decimals) are preserved exactly as stored. Every chunk carries full column context regardless of where the chunk boundary falls.|
|`.xls`|Excel (legacy BIFF8)|xlrd|Same `Column: Value` per-row format as `.xlsx`. Date serial numbers are converted to `YYYY-MM-DD` using xlrd's cell-type detection. Numeric values preserved as-is.|
|`.pptx`|PowerPoint (modern)|python-pptx|Each slide extracted as a labelled section `\[Slide N]`. All text frames, titles, body text, and text boxes included.|
|`.odt`|OpenDocument Text|odfpy|All paragraph text extracted in reading order.|
|`.rtf`|Rich Text Format|striprtf|RTF control codes (`\\rtf1\\ansi\\deff0…`) stripped; only readable prose indexed.|
|`.html` `.htm` `.xhtml`|Web / Markup|beautifulsoup4|All tags, `<script>`, `<style>`, and `<head>` blocks stripped. Only human-readable body text is indexed.|
|`.csv` `.tsv`|Tabular data|Built-in csv module|Same `Column: Value` per-row format as Excel. Header row is detected automatically and attached to every data row so column context is preserved across all chunks.|
|`.py` `.js` `.ts` `.jsx` `.tsx`|Code|Plain text|Source code is plain text — highly searchable for developer knowledge bases|
|`.cs` `.java` `.cpp` `.c` `.h` `.hpp`|Code|Plain text|Compiled languages — source is still plain text|
|`.go` `.rs` `.rb` `.php` `.swift` `.kt` `.scala` `.r`|Code|Plain text|Modern and niche languages — same reasoning|
|`.css` `.scss` `.sass` `.less`|Stylesheet|Plain text|Text-based style rules; useful for front-end knowledge bases|
|`.xml`|Markup / Data|Plain text|Structured text; content is readable as-is|
|`.json` `.yaml` `.yml` `.toml` `.ini` `.cfg` `.conf` `.env`|Config / Data|Plain text|Human-readable config files — valuable for dev/ops knowledge bases|
|`.log`|Logs|Plain text|Useful for searching error history|
|`.sql`|Database scripts|Plain text|Plain text queries and schema definitions|
|`.jpg` `.jpeg` `.png` `.bmp` `.tiff` `.tif` `.gif`|Images|Tesseract OCR|**OCR via Tesseract** extracts embedded text from scanned documents and screenshots — see Section 12|
|`.eml` `.msg` `.emlx`|Email (single)|email / extract-msg|Individual email files; headers, sender, recipient, subject, and body extracted|
|`.mbox`|Email (archive)|mailbox|Gmail Takeout, Thunderbird exports — multiple messages per file, incrementally indexed|
|`.rmail` `.babyl` `.mmdf`|Email (legacy)|mailbox|GNU Emacs / old Unix mail formats|
|`.sh` `.bash` `.zsh` `.ps1` `.bat` `.cmd`|Scripts|Plain text|Shell scripts — plain text, useful for ops knowledge bases|
|`.gitignore` `.dockerignore` `.editorconfig`|Config files|Plain text|Extensionless-style config — plain text|

### Skipped Extensions (never indexed by default)

|Extension(s)|Category|Reason Skipped|
|-|-|-|
|`.doc` `.ppt`|Legacy Office binary|OLE compound binary format with no pure-Python text extractor. Produces unreadable garbage when read as text. **Convert to `.docx` / `.pptx` before indexing.**|
|`.exe` `.dll` `.so` `.dylib` `.lib` `.a` `.o` `.obj`|Executables / compiled|Binary — no readable text content|
|`.class` `.pyc` `.pyd` `.pyo`|Compiled bytecode|Binary compiled output — no source text value|
|`.pdb` `.ilk` `.exp` `.com` `.scr` `.sys` `.drv` `.ocx` `.ax`|Windows system / debug|Binary system files — no text content|
|`.zip` `.rar` `.7z` `.tar` `.gz` `.bz2` `.xz` `.tgz`|Archives|Compressed containers — contents must be extracted first|
|`.jar` `.war` `.ear` `.whl` `.egg` `.nupkg` `.vsix`|Package archives|Language-specific packages — binary containers|
|`.deb` `.rpm` `.msi` `.pkg` `.dmg` `.iso` `.img`|Installers / disk images|Binary system installers — no indexable text|
|`.webp` `.ico` `.svg` `.psd` `.ai` `.eps`|Image formats (design)|No OCR value — vector/design formats or low-text web images|
|`.raw` `.cr2` `.nef` `.orf` `.arw`|Camera RAW|Photo data only — no embedded text worth indexing|
|`.mp3` `.wav` `.flac` `.aac` `.ogg` `.wma` `.m4a` `.opus` `.aiff`|Audio|No text content extractable|
|`.mp4` `.avi` `.mkv` `.mov` `.wmv` `.flv` `.webm` `.m4v`|Video|No text content extractable|
|`.ttf` `.otf` `.woff` `.woff2` `.eot`|Fonts|Binary font data — no text content|
|`.db` `.sqlite` `.sqlite3` `.mdb` `.accdb`|Database files|Binary database containers — use SQL exports instead|
|`.vmdk` `.vhd` `.vhdx` `.ova` `.ovf`|VM / disk images|Large binary disk images — no text content|
|`.tmp` `.temp` `.cache` `.lock` `.bak` `.swp` `.swo`|Temp / cache|Transient files — no stable content worth indexing|
|`.DS\\\_Store` `.Thumbs.db`|OS metadata|macOS/Windows filesystem metadata blobs — binary, no value|

### Excel, Word, and Legacy Office Format Notes

#### .xlsx and .xls — Modern and Legacy Excel

`.xlsx` files (Excel 2007 and later) are extracted using `openpyxl`. Each data row is rendered as a series of `Column: Value` pairs so Claude always knows which column a value came from, even across chunk boundaries. Dates are formatted as `YYYY-MM-DD`; numeric values (currency, hours, floats) are preserved exactly as stored.

`.xls` files (Excel 97–2003, BIFF8 binary format) are extracted using `xlrd`. The same `Column: Value` per-row format is applied.

> \*\*Note on `.xls`:\*\* The legacy `.xls` format is supported for read-only extraction only. If you edit `.xls` files regularly, save them as `.xlsx` in Excel first for best results.

#### .docx — Word Documents

`.docx` files are extracted using `python-docx`. Both paragraph text and table content are extracted. Table cells are converted to readable `Row N | Column: Value` format so financial tables, schedules, and structured grids inside Word documents are fully searchable.

#### .doc and .xls — Legacy Formats Not Supported

`.doc` (Word 97–2003 OLE binary) and the related legacy `.xls` with OLE compound document structure are **not supported for indexing** and are excluded from the default Supported extensions list.

These formats use a proprietary binary structure with no reliable pure-Python extractor. Attempting to index them produces unreadable binary garbage that pollutes the knowledge base with noise rather than content.

**What to do:** Open the file in Microsoft Word or Excel and use **File → Save As → .docx / .xlsx** to convert it. The converted file will index correctly and fully.

If AI-Prowler encounters a `.doc` or `.xls` file during indexing, it logs a warning and skips the file rather than indexing corrupt content. You can verify which files were skipped in the indexing output panel.

### Notes on Special Cases

* **`.doc` and `.ppt`** are intentionally skipped. These are OLE compound binary formats (Word 97–2003 and PowerPoint 97–2003) that have no pure-Python text extractor. Reading them as plain text produces binary garbage identical to the original Excel problem. Convert to `.docx` / `.pptx` using Word, PowerPoint, LibreOffice, or any online converter before indexing.
* **`.xlsx` / `.xls` column context** — each data row is a self-contained chunk entry. This means Claude can always answer "what is column X for row Y?" even when a large spreadsheet spans many chunks, because the column header is embedded in every row entry rather than appearing once at the top of the file.
* **`.docx` tables** — table content was silently dropped in earlier versions. v5.0.0 extracts both paragraph text and table cells, so financial tables, parenting schedules, and any structured data inside Word documents is now fully searchable.
* **`.svg`** is skipped even though it is technically XML text — it is treated as a design asset rather than a document.
* **Common image formats** (`.jpg`, `.png`, etc.) are **supported** via OCR, but camera RAW formats are skipped since they contain raw photo sensor data, not document text.
* **`.webp`** is skipped (web delivery format), even though `.jpg`/`.png` of the same content would be OCR'd — this is intentional.
* All extension lists can be customised per-installation in **Settings → Smart Scan Config** without any code changes.

### Skipped Directories

AI-Prowler also skips these directory names when walking folder trees:

|Category|Directories|
|-|-|
|Version control|`.git` `.svn` `.hg` `.bzr`|
|Package managers|`node\\\_modules` `bower\\\_components` `vendor` `packages` `.nuget`|
|Python|`\\\_\\\_pycache\\\_\\\_` `.venv` `venv` `env` `.env` `site-packages`|
|Build output|`build` `dist` `out` `output` `bin` `obj` `target` `.next` `.nuxt`|
|IDE / editor|`.idea` `.vscode` `.vs` `.eclipse`|
|OS / system|`$RECYCLE.BIN` `System Volume Information` `Windows` `Program Files`|

\---

## 13\. OCR — Scanned Documents \& Images

AI-Prowler automatically applies OCR (Optical Character Recognition) to:

* Scanned PDFs (PDFs with no text layer)
* Standalone image files (`.jpg`, `.jpeg`, `.png`, `.bmp`, `.tiff`, `.tif`, `.gif`)

### How It Works

1. `pdfplumber` attempts to extract the text layer from PDFs
2. If no text is found (scanned document), `pypdfium2` renders each page to a 300 DPI image
3. `pytesseract` (Tesseract 5.4) extracts text from the image
4. The extracted text is chunked and indexed normally

### OCR Quality Tips

* 300 DPI rendering provides high accuracy for most documents
* Handwritten text has limited accuracy
* Very small fonts (below 8pt) may have reduced accuracy
* Clean, horizontal text gives the best results

### OCR Debug Tools

In **Settings**, use the **OCR Debug** button to test OCR on a specific file and see the extracted text before indexing. You can also enable **OCR Debug logging** to write full OCR text output to a log file during every index run — useful for diagnosing extraction quality on a large batch.

\---

## 14\. Email Indexing

### Supported Formats

|Provider|Format|Export Method|
|-|-|-|
|Gmail|.mbox|Google Takeout|
|Apple Mail / iCloud|.mbox|File → Export Mailbox|
|Thunderbird|.mbox|Direct from profile folder|
|Yahoo Mail|Via Thunderbird IMAP|Set up IMAP in Thunderbird first|
|Outlook / Exchange|.eml, .msg|Drag-and-drop or MailStore export|
|Windows Live Mail|.eml|Point at the Mail folder|

### Incremental Indexing

AI-Prowler uses `Message-ID` headers for deduplication. On re-import, only emails that haven't been seen before are indexed. A 100,000-email archive that gained 200 new messages will only process those 200 on re-import.

### Large Archives

For very large archives (100,000+ emails), indexing may take several hours on first import. Use Pause / Resume if needed. Progress is shown as `\\\[Email 4,271/52,000] Subject line`.

\---

## 15\. Scheduling \& Automation

### Windows Task Scheduler Integration

Set up automatic index updates from **Settings → Schedule**:

1. Choose update frequency (daily, specific days, custom)
2. Set the time (default: 2:00 AM)
3. Click **Create Schedule**

The scheduler runs `update\\\_tracked\\\_directories` — only changed files are re-indexed.

### Auto-Start Ollama

Enable **Auto-start Ollama** in Settings to launch the Ollama server automatically when AI-Prowler opens. Not needed if you're using Claude Desktop as your primary interface.

### Cloudflare Tunnel as Windows Service

For always-on remote access, install the Cloudflare Tunnel as a Windows service. The tunnel starts automatically at boot and runs in the background without AI-Prowler being open.

In **Settings → Cloudflare Tunnel**, click **Install as Windows Service**.

\---

## 16\. GPU Support

> **v6.0.0 visibility note:** The **GPU Acceleration** panel that previously appeared in the Settings tab is now suppressed by default. **GPU detection, embedding acceleration, and Ollama GPU offload all still work automatically** — only the manual control panel is hidden. To re-expose the panel (advanced users), see Section 11 → GPU Detection.

### NVIDIA GPUs

AI-Prowler detects NVIDIA GPUs automatically. The installer installs the correct PyTorch build:

* **CUDA 12.8 (cu128)** — for RTX 50xx (Blackwell) and most modern NVIDIA GPUs
* **CPU-only** — for systems without an NVIDIA GPU

### Embedding Acceleration

The sentence-transformer embedding model (`all-MiniLM-L6-v2`) uses CUDA automatically when available, significantly speeding up indexing.

### Blackwell (RTX 50xx) Note

PyTorch stable does not yet include CUDA 12.8 compute kernels for Blackwell SM 12.0+ architecture. Embeddings run on CPU on RTX 50xx cards even though CUDA is detected. Ollama itself supports Blackwell for inference. This will be resolved in a future PyTorch release.

### Controlling GPU Layers (advanced)

The `gpu_layers` value still controls how many model layers Ollama offloads to GPU. The default `-1` (auto) is correct for almost everyone. If you need to override:

* `-1` = auto (let Ollama decide — recommended)
* `0` = CPU only
* `N` = N layers on GPU (partial offload)

Edit the `gpu_layers` field directly in `~/.ai-prowler/config.json` and restart AI-Prowler, or enable `DEBUG_EN` to use the in-GUI spinbox.

\---

## 17\. Debugging \& Log Files

AI-Prowler maintains comprehensive logs for troubleshooting. This section covers all log files, what they contain, and how to use them.

### Log File Locations

|Log File|Location|Contents|
|-|-|-|
|Install log|`%LOCALAPPDATA%\\\\Temp\\\\AI-Prowler\\\\install\\\_log.txt`|Full installer output, package installs, errors|
|Uninstall log|`%LOCALAPPDATA%\\\\Temp\\\\AI-Prowler\\\\uninstall\\\_log.txt`|Uninstall steps and cleanup results|
|MCP server log|`%LOCALAPPDATA%\\\\AI-Prowler\\\\mcp\\\_server.log`|All MCP server activity (current session)|
|MCP server log (prev)|`%LOCALAPPDATA%\\\\AI-Prowler\\\\mcp\\\_server.log.1`|Previous session log|
|MCP server log (older)|`%LOCALAPPDATA%\\\\AI-Prowler\\\\mcp\\\_server.log.2`|Two sessions ago|
|Subscription cache|`%LOCALAPPDATA%\\\\AI-Prowler\\\\subs\\\_cache.json`|Cached subscription registry|

Open `%LOCALAPPDATA%` by pressing Win + R and typing `%LOCALAPPDATA%`.

### MCP Server Log

The MCP log (`mcp\\\_server.log`) is the most useful for debugging Claude Desktop and Claude.ai connection issues. It captures:

**Startup sequence:**

```
AI-Prowler MCP server process started
Python : 3.11.8
Script : C:\\\\Program Files\\\\AI-Prowler\\\\ai\\\_prowler\\\_mcp.py
Importing MCP SDK (FastMCP)... OK
Importing rag\\\_preprocessor... OK
FastMCP created with instructions= (mcp >= 1.2.0)
```

**stdio mode protection (Claude Desktop):**

```
STDIO mode: \\\_STDIO\\\_MODE=True — \\\_capture\\\_stdout() is now a no-op
STDIO mode: sys.stdout redirected to devnull — MCP pipe protected
Starting stdio transport (Claude Desktop mode)
```

**Every incoming request (HTTP mode):**

```
REQUEST  POST /mcp
HEADERS from Claude.ai (POST /mcp):
  host: mobile.dvavro-ai-prowler.com
  authorization: Bearer xxxxxxxx...
  content-type: application/json
AUTH OK  -> mcp\\\_asgi  (POST /mcp)
FASTMCP RESPONSE: POST /mcp → HTTP 200
```

**Tool calls:**

```
Processing request of type ListToolsRequest
Dispatching request of type CallToolRequest
Response sent
```

**Subscription checks:**

```
Subscription registry fetched from GitHub OK
Startup subscription check: Subscription OK — 'ACME Corp', 25 day(s) remaining
```

**Errors:**

```
AUTH FAIL: no valid Bearer token for POST /mcp
SUBSCRIPTION EXPIRED: subscription for 'ACME Corp' expired 5 days ago
```

### Log Rotation

The MCP log rotates on each server start:

* `mcp\\\_server.log` — current session
* `mcp\\\_server.log.1` — previous session
* `mcp\\\_server.log.2` — two sessions ago

This means restarting the server creates a new log, preserving the last two sessions for comparison.

### Log Timestamps and Stderr Capture

The MCP server log uses **millisecond-precision timestamps** (e.g. `2026-03-31 12:04:22.847`) for all entries — useful for diagnosing timing issues like slow startup or tool call delays. Stderr output (Python tracebacks and third-party library errors) is also captured into the same log file via a `\_StderrToLog` redirect, so crashes that don't reach the normal log handlers are still visible.

### MCP Server Startup Performance

The v5.0.0 MCP server includes several startup speed improvements that are logged and worth understanding when reading `mcp\_server.log`:

**HuggingFace offline mode** — On startup the server sets `HF\_HUB\_OFFLINE=1` and `TRANSFORMERS\_OFFLINE=1` before any imports. This prevents sentence-transformers from making unnecessary network update-check calls on every load, saving 4–5 seconds per startup. The model is cached locally; no network access is needed.

**requests timeout patch** — During `rag\_preprocessor` import the server temporarily patches `requests.Session.request` to cap all HTTP timeouts to 0.8 seconds. This prevents the Ollama connectivity probe (which runs at import time) from blocking the MCP startup for the full requests default timeout. The patch is removed immediately after import and confirmed in the log:

```
requests.Session.request patched: timeout capped to 0.8s during import
requests patch removed — normal timeouts restored
```

**Background prewarm thread** — In stdio mode (Claude Desktop), loading ChromaDB and the embedding model is offloaded to a background thread so `mcp.run()` starts immediately and Claude Desktop's initialize handshake is never delayed. Tool handlers that need ChromaDB wait on `\_prewarm\_event` (max 60 seconds) before proceeding. You will see these lines in the log:

```
PREWARM: background thread started — loading ChromaDB + embedding model...
PREWARM: done — 12,450 chunks indexed, model cached, asyncio-safe
PREWARM: complete, tool handlers unblocked
```

If a tool call returns "AI-Prowler is still initializing" it means the prewarm hasn't finished yet. Wait a few seconds and retry.

### Install Log

The install log captures every step of the installation process with return codes:

```
\\\[Python] Installing Python 3.11.8...
\\\[Python] Return code: 0  Status: SUCCESS
\\\[pip] Installing requirements.txt...
\\\[Claude Desktop] Downloading MSIX package...
\\\[MCP Config] Writing claude\\\_desktop\\\_config.json...
\\\[Summary] Install complete
```

If installation fails, this log shows exactly which step failed and why.

### Debug View in GUI

In the Quick Links tab (with `SUPPORT_LOCAL_HW_LLM = True` to expose the Q&A box), enable **Debug View** (toggle in toolbar) to see:

* Which document chunks were retrieved for each query
* Similarity scores for each chunk
* The full prompt sent to the LLM
* Raw LLM response before formatting

For Claude Desktop or Claude.ai workflows (the default v6.0.0 path), look at the MCP server log instead — it captures all tool calls, their arguments, and responses. See the Log File Locations table above.

### OCR Debug Tool

In **Settings**, the **OCR Debug** button lets you test OCR on any file:

1. Click OCR Debug
2. Select a scanned PDF or image file
3. The extracted text is displayed in a preview window
4. Use this to verify OCR quality before indexing

### Checking What's in the Knowledge Base

Ask Claude (via MCP):

```
Call get\\\_database\\\_stats() to show me what's in the knowledge base.
```

Or from the Update Index tab, click **Show Stats**.

### Common Debug Workflow

**Problem: Claude says it can't find information that should be indexed**

1. Open `mcp\\\_server.log` and find the tool call for `search\\\_documents`
2. Check the similarity scores returned — if all are below 0.3, the content may not be well-represented
3. Try `list\\\_indexed\\\_documents()` to verify the file is actually indexed
4. Try `get\\\_document\\\_chunks("filename.pdf")` to see the raw extracted text — OCR issues may have degraded the content

**Problem: Claude Desktop shows "response was interrupted" on tool calls**

1. Check `mcp\\\_server.log` for the stdio mode protection lines:

   * `STDIO mode: \\\_STDIO\\\_MODE=True` — should be present
   * `STDIO mode: sys.stdout redirected to devnull` — should be present
2. If these lines are missing, the fixed `ai\\\_prowler\\\_mcp.py` may not have been deployed
3. Run **🔬 Run MCP Diagnostics** from the Settings tab for a full health check
4. Re-write the MCP config and restart Claude Desktop

**Problem: Claude.ai connector shows "not subscribed" even after subscribing**

1. Check `mcp\\\_server.log` for subscription check lines
2. Look for "Subscription registry fetch failed" — network issue
3. Check `subs\\\_cache.json` for the cached data
4. Verify your Bearer token matches what was registered

**Problem: HTTP server returns 421**

This means a header mismatch between Claude.ai and the server. Check `mcp\\\_server.log` for:

* `REWRITE Host` lines — confirm host rewriting is active
* `INJECT MCP-Protocol-Version` lines — confirms protocol version injection is working
* `Invalid Host header` — the fix may not have applied
* `FASTMCP RESPONSE: POST /mcp → HTTP 421` — server version mismatch

**Problem: Install failed**

Open `%LOCALAPPDATA%\\\\Temp\\\\AI-Prowler\\\\install\\\_log.txt` and search for `Status: FAILURE`. The lines around the failure show the exact command that failed and any error output.

\---

## 18\. Troubleshooting

### Claude Desktop can't see AI-Prowler tools

1. Check that AI-Prowler is installed in `C:\\\\Program Files\\\\AI-Prowler\\\\`
2. In AI-Prowler → Settings → Claude Desktop MCP → click **Write MCP Config**
3. Restart Claude Desktop completely (check Task Manager for `claude.exe`)
4. Start a **new conversation** (not an existing one)
5. If still failing, click **🔬 Run MCP Diagnostics** for a detailed health report

### Claude Desktop shows "response was interrupted"

This is caused by stdout corruption on the MCP pipe. Ensure you are running the latest `ai\\\_prowler\\\_mcp.py` which includes the stdio protection fix. Confirm by checking `mcp\\\_server.log` for the two lines:

```
STDIO mode: \\\_STDIO\\\_MODE=True — \\\_capture\\\_stdout() is now a no-op
STDIO mode: sys.stdout redirected to devnull — MCP pipe protected
```

If these are absent, copy the latest `ai\\\_prowler\\\_mcp.py` to `C:\\\\Program Files\\\\AI-Prowler\\\\` and restart Claude Desktop.

### Claude.ai connector fails with "MCP server error"

Check the `mcp\\\_server.log` for the specific error. Common causes:

* HTTP server not running — click Start HTTP Server
* Cloudflare Tunnel not running — click Start Tunnel
* Bearer token mismatch — re-enter your token in Settings and in Claude.ai

### Indexing is slow

* Enable GPU in Settings if you have an NVIDIA card
* Reduce the chunk size in Settings (smaller chunks = faster indexing, less context per chunk)
* Use Smart Scan to skip file types you don't need

### OCR produces garbled text

* Check image resolution — very low DPI scans may not OCR well
* Use OCR Debug to preview the extraction before indexing
* For critical documents, try re-scanning at higher resolution

### Errno 22 / double backslash error on indexing

This is a known `huggingface\\\_hub` bug on some Windows 10 builds. The `RAG\\\_RUN.bat` launcher sets `HF\\\_HUB\\\_CACHE` explicitly to prevent this. If it persists after reinstall run the following commands:

```
Win + R → type cmd → Enter
%LOCALAPPDATA%\\\\Programs\\\\Python\\\\Python311\\\\python.exe -m pip uninstall huggingface-hub
rmdir /s /q "%USERPROFILE%\\\\.cache\\\\huggingface\\\\hub\\\\models--sentence-transformers--all-MiniLM-L6-v2"
%LOCALAPPDATA%\\\\Programs\\\\Python\\\\Python311\\\\python.exe -m pip install huggingface-hub==0.26.5
```

### Stale packages from Roaming site-packages

If you see unexpected import errors or wrong package versions after a reinstall, the `PYTHONNOUSERSITE=1` variable in `RAG\\\_RUN.bat` prevents Python from loading packages from `%APPDATA%\\\\Roaming\\\\Python`. This is set automatically. If running the script directly without the bat file, set this variable manually.

### Voice input not working

The Whisper model downloads on first use (\~1.6 GB). Ensure internet access on first mic use. If it fails, check that `sounddevice` is installed: run `pip list | grep sounddevice`. Adjust the silence timeout in Settings if speech is being cut off too early.

\---

## 19\. Uninstalling

### Using the Uninstaller

Run `UNINSTALL.bat` from `C:\\\\Program Files\\\\AI-Prowler\\\\` or use Windows Settings → Add or Remove Programs → AI-Prowler.

The uninstaller:

* Removes all AI-Prowler application files
* Removes Python (if installed by AI-Prowler)
* Offers to remove the RAG database, index tracking files, self-learning knowledge base, AND the Job Tracker spreadsheet in one combined prompt (default: keep all — safe for reinstall)
* Offers to remove Ollama and downloaded models

The uninstall log is saved to `%LOCALAPPDATA%\\\\Temp\\\\AI-Prowler\\\\uninstall\\\_log.txt`.

### Manual Cleanup

If the uninstaller fails, manually delete:

* `C:\\\\Program Files\\\\AI-Prowler\\\\` — application files
* `%LOCALAPPDATA%\\\\Programs\\\\Python\\\\Python311\\\\` — Python
* `%USERPROFILE%\\\\AI-Prowler\\\\` — database (if you want to keep your index, don't delete this)
* `%USERPROFILE%\\\\Documents\\\\AI-Prowler\\\\AI-Prowler\\\_Job\\\_Tracker.xlsx` — Job Tracker spreadsheet (keep if you have live job data)
* `%USERPROFILE%\\\\.ai-prowler\\\\learnings\\\\` — Self-learning knowledge base (keep if you want to preserve learnings across reinstall)
* `%LOCALAPPDATA%\\\\AI-Prowler\\\\` — logs and caches

\---

## 20\. Self-Learning System

### Overview

The Self-Learning System gives AI-Prowler a persistent, semantically-searchable memory that is **separate from the main document RAG**. When you tell Claude *"learn this"* — or when Claude detects a correction, lesson, or preference during conversation — the fact is written to a structured JSON file and indexed in ChromaDB. The next time a related question comes up, Claude calls `check\_learned()` first, finds the stored fact, and applies it automatically.

No GPU. No training. No 30-minute LoRA cycle. New knowledge is queryable within roughly 1 second of being recorded.

You can manage learnings three ways:

1. **Talking to Claude** — natural language; Claude handles the 6 MCP tools for you
2. **The 🧠 Learnings tab** in the AI-Prowler desktop GUI — visual browsing, filtering, archive/delete, export
3. **Editing the JSON file directly** at `~/.ai-prowler/learnings/self\_learning\_data.json`

### Quick Start — Try It in Two Minutes

After install, have this conversation with Claude:

> **You:** "Remember this: Crabby's Daytona prefers we wash the windows on the second Tuesday of the month, not the first."
>
> **Claude:** *(calls `record\_learning(...)`)* — shows a confirmation message with the title, category, confidence, and ID.
>
> **You:** *(later, in a new chat)* "When should I schedule Crabby's next window cleaning?"
>
> **Claude:** *(calls `check\_learned("Crabby's window cleaning schedule")` first)* — finds the learning and answers based on it.

That's the entire feedback loop. The rest of this section explains how to use it productively at scale.

### How It Works

Learnings are stored in two places simultaneously:

* **JSON file** (`~/.ai-prowler/learnings/self\_learning\_data.json`) — human-readable, easy to back up, read directly by the GUI tab
* **ChromaDB collection** (`ai\_prowler\_learnings`) — separate from the main document knowledge base, enables semantic search

When Claude records a learning, both stores are updated atomically. No training, no GPU, no restart required.

### The Six Self-Learning MCP Tools at a Glance

| Tool | Purpose | When Claude calls it |
|------|---------|---------------------|
| `record\_learning()` | Save a new fact, lesson, or correction | When you say "remember this" / "learn this" — or auto, when Claude detects a correction |
| `check\_learned()` | Semantic search the knowledge base | **Before answering** any question about clients, projects, procedures, or anywhere a stored correction might exist |
| `list\_learnings()` | Browse by category / status / tag (no search) | When you ask "what have we learned about X?" |
| `update\_learning()` | Modify an existing learning | When you correct Claude's confirmation message, or mark an outcome after seeing results |
| `delete\_learning()` | Permanently remove a learning | When you reject a learning ("that's wrong, remove it") |
| `get\_learning\_stats()` | Summary stats — totals by category/status/source, top-applied | Health check, audit, or "what do we know?" |

All six tools are loaded automatically when AI-Prowler starts.

### Three Operational Modes

**Mode 1 — Proactive Checking.** Claude calls `check\_learned()` before answering questions about clients, projects, scheduling, procedures, or any topic where stored corrections might exist. This is instructed via the MCP instructions block in `ai\_prowler\_mcp.py`. Example: when you ask *"Can you plan next week's HVAC schedule?"* Claude calls `check\_learned(query="HVAC scheduling crew management", n\_results=5)`, finds any double-booking lessons, applies them to the proposed schedule, and surfaces *"I'm avoiding double-booking Crew A based on what we learned from the Johnson/Smith jobs"* in its response.

**Mode 2 — Recording.** When you say "learn this" or "remember that", Claude calls `record\_learning()` with all metadata. Claude also auto-records when it detects fact corrections, project outcomes, client preferences, or process improvements in conversation — always with confirmation.

**Mode 3 — Post-Operation Analysis.** When you ask Claude to review a completed project or job, it follows a structured workflow: gathers project docs via `search\_documents()` or `search\_within\_directory()`, checks existing learnings via `check\_learned()`, identifies what went right and wrong, records each insight as a separate learning, and presents the whole batch for confirmation. A single post-op review typically yields 3–5 separate learnings, all instantly indexed.

### Talking to Claude — What to Say

You don't need to remember tool names. Claude reads the `_INSTRUCTIONS` block at every MCP handshake and recognises natural-language triggers. Patterns that work:

**Recording explicitly:**

* "Remember this: …"
* "Learn this: …"
* "Save this lesson: …"
* "Note for next time: …"
* "Don't forget — …"

**Asking Claude to recall:**

* "What did we learn about \[topic\]?"
* "Do you remember anything about \[client/project\]?"
* "Have we had issues with \[topic\] before?"

**Reviewing or auditing:**

* "Show me everything you've learned this week"
* "List all client preferences"
* "What mistakes have we logged?"
* "Give me the learning stats"

**Correcting a recent confirmation:**

* "Change the confidence to 95%"
* "The category should be `best\_practice`"
* "That's wrong, delete it"
* "Update that learning — the outcome was actually positive"

### Auto-Detection — Triggers and Confirmation Banner

Claude auto-records (with `auto\_detected=True`) when it detects any of these patterns in conversation. No "learn this" required:

| Trigger | Example | Category Claude usually picks |
|---------|---------|-------------------------------|
| User corrects a fact | "Actually, the number is 555-0200" | `fact\_correction` |
| User shares a project outcome | "The Smith job went over budget by 40%" | `project\_insight` |
| User mentions a client preference | "They hate phone calls" | `client\_preference` |
| Post-op review reveals a gap | "We should have photographed the site first" | `mistake\_learned` |
| New info contradicts an existing learning | "The permit office changed their hours" | `fact\_correction` (with `supersedes\_id`) |
| User describes a better approach | "Next time we should submit permits earlier" | `process\_improvement` |

When Claude auto-records, it always shows a prominent banner asking you to confirm. You can approve, adjust, or reject in the same turn. Example banner:

```
🧠 AUTO-LEARNING — I detected something worth remembering and recorded it:
══════════════════════════════════════════════════════

  📌 "Client X prefers email over phone calls"

  What I recorded:
    After 3 failed phone attempts, switching to email resulted in
    same-day response. Always use email as primary contact.

  Why I recorded it:
    User mentioned that Client X never answers phone calls during
    discussion about the March HVAC project.

  Category   : client\_preference
  Confidence : 85%
  ID         : e5f6g7h8-...

══════════════════════════════════════════════════════
⚡ Is this correct? If anything is off, tell me what to change
   and I'll update or remove it immediately.
```

If you say something is wrong, Claude immediately calls `update\_learning()` or `delete\_learning()` to fix it. You can chain corrections — *"change the category to `best_practice` and bump confidence to 95"* — and Claude will issue a single `update\_learning()` call with both fields.

To **disable auto-detection** entirely, remove the AUTO-RECORDING section from the `_INSTRUCTIONS` block in `ai\_prowler\_mcp.py` and restart the server. Operator-requested learning (you saying "learn this") will still work.

### Learning Categories

| Category | When to use |
|---|---|
| `fact\_correction` | Correcting an outdated or wrong fact |
| `business\_lesson` | What worked or didn't in business |
| `project\_insight` | Lessons from a specific project |
| `process\_improvement` | A better way to do something |
| `mistake\_learned` | Something went wrong — document so it doesn't happen again |
| `best\_practice` | Proven approach to adopt going forward |
| `client\_preference` | Client-specific preferences or requirements |
| `technical\_note` | Technical fact, configuration, or gotcha |
| `general` | Catch-all (default if no category fits) |

### Sources

| Source | Meaning |
|---|---|
| `operator` | Explicitly told by the user (default for "learn this" calls) |
| `claude\_detected` | Claude identified a learning trigger during conversation |
| `project\_review` | Logged during a post-project review |
| `post\_mortem` | After-incident analysis |
| `research` | Came from web search or document research |
| `observation` | Pattern noticed across conversations |

### Outcomes and Status

**Outcomes** (mainly for `business\_lesson` and `project\_insight`): `positive`, `negative`, `neutral`, `unknown` (default).

**Status:** `active` (default — searchable), `deprecated` (replaced by a newer learning), `archived` (manually hidden, kept for history).

### Supersession Chain

When a learning replaces an older one, both are linked automatically:

```
Learning A: "Client X phone number is 555-0100"
     ↓ superseded by
Learning B: "Client X phone number is 555-0200"   (supersedes\_id = A.id)
```

* Learning A is automatically marked `status: "deprecated"` and `superseded\_by: B.id`
* Learning B has `supersedes: A.id`
* `check\_learned()` returns only B by default. Pass `include\_deprecated=True` to also see A — useful for *"what did we used to think?"* auditing
* The GUI detail panel shows the full supersession chain when you select either learning

### Applied-Count Tracking

Every time `check\_learned()` returns a learning, that learning's `applied\_count` increments and its `last\_applied` timestamp updates. This gives you visibility into which learnings are actually being used. The GUI stats panel shows the total applied count, and `get\_learning\_stats()` lists the most-applied learnings — invaluable for spotting high-value knowledge vs. dead weight.

The GUI's Learnings tab uses `track\_application=False` when refreshing the table so just browsing doesn't inflate the counter. Only real Claude-driven retrievals bump it.

### Conflict Detection

`find\_conflicts()` scans for pairs of active learnings whose semantic similarity exceeds a configurable threshold (default 0.85, range 0.5–0.95). Real contradictions get flagged for review — for example, one learning saying *"use a Phillips screwdriver on Client X panels"* and another saying *"use a flathead on Client X panels"* would surface as a potential conflict.

When you dismiss a flagged pair (the GUI's "this isn't actually a conflict" action), the system records the dismissal bidirectionally so it won't re-flag the same pair. You can later clear a dismissal if you change your mind.

Supersession-linked pairs are automatically excluded from conflict detection — you've already resolved that relationship.

### Confirmation Protocol Summary

Claude **never records silently.** Every successful `record\_learning()` call returns a confirmation summary, and Claude is instructed to always show it to you. Two styles:

* **Operator-requested** (you explicitly asked): concise confirmation with title, summary, category, confidence, ID, and *"Does this look right?"*
* **Auto-detected** (Claude initiated without being asked): prominent banner with the "🧠 AUTO-LEARNING" header shown above

Correction shortcuts:

| You say | Claude calls |
|---|---|
| "Change the confidence to 95%" | `update\_learning(id, {"confidence": 0.95})` |
| "The category should be `best_practice`" | `update\_learning(id, {"category": "best\_practice"})` |
| "Update the outcome — that turned out positive" | `update\_learning(id, {"outcome": "positive"})` |
| "Archive that one" | `update\_learning(id, {"status": "archived"})` |
| "That's wrong, delete it" | `delete\_learning(id)` |

### 🧠 Learnings Tab — Desktop GUI

The Learnings tab in AI-Prowler provides a visual interface for managing the knowledge base without going through Claude. It reads directly from the JSON file, so it always shows the latest data — just click **↻ Refresh** to reload. See Section 11 for the full layout breakdown.

Key things you can do from the tab:

* **Browse and filter** by category, status, or free-text search across title/content/context/tags
* **Sort** any column by clicking its header
* **Inspect** a single learning's full content, "why this was learned" context, supersession chain, and ID
* **Archive** a learning (hide from Claude's search but keep in history)
* **Delete** permanently
* **Export to CSV** for spreadsheet-friendly backup
* **Rebuild ChromaDB Index** if the search index drifts out of sync with the JSON (safe — no data lost)
* **Open the raw JSON** or the learnings folder for manual editing or external backup

If `self\_learning.py` is not in the same directory as `rag\_gui.py`, the tab still works but in view-only mode — Archive, Delete, and Reindex show an *"Unavailable"* message prompting you to use Claude instead. Export and file browsing always work.

### Smoke Test — Verifying the System After Install or Update

Takes under 60 seconds:

1. **Tools loaded?** Ask Claude: *"Show me the AI-Prowler self-learning tools."* You should see all 6 listed.
2. **Stats reachable?** Ask Claude: *"Run get\_learning\_stats."* Expect a clean report (zero learnings on a fresh install is normal).
3. **Round-trip a learning:**
   * *"Learn this: my favorite test phrase is 'purple flamingo on a unicycle'."*
   * In a new chat: *"What's my favorite test phrase?"*
   * Claude should call `check\_learned()` and answer correctly.
4. **GUI sanity check:** Open the 🧠 Learnings tab. The test learning should appear (click ↻ Refresh if not).
5. **Cleanup:** *"Delete the purple flamingo learning."*

If steps 1–4 pass, the system is healthy. AI-Prowler 6.0's automated test suite (`tests\learning\`) covers 75 deterministic regression tests across the same functionality.

### Example Workflow — Post-Op Review Yielding Multiple Learnings

> **You:** "Analyze the Johnson roofing job — it went over budget by 40% and the customer complained about cleanup."

Claude records three learnings in one turn:

| # | Title | Category | Outcome |
|---|-------|----------|---------|
| 1 | Get material quotes within 48 hours of estimate | `mistake\_learned` | negative |
| 2 | Assign dedicated cleanup crew on roofing jobs | `process\_improvement` | negative |
| 3 | Johnson prefers text message updates over email | `client\_preference` | neutral |

Next time a roofing job is scheduled, Claude calls `check\_learned("roofing job scheduling")` and applies all three lessons automatically.

### Example Prompts

```
"Remember: always submit permits 2 weeks before job start"
"What do we know about Client X?"
"Analyze the Johnson project — what went right and wrong?"
"Show me all business lessons we have learned"
"How many learnings do we have and which are most applied?"
"Find conflicting learnings — anything contradictory in the knowledge base?"
"Export everything we know to a learning pack so I can back it up"
"Archive the old phone number for Bob — we updated it to 555-0200"
```

### Common Failure Modes and Fixes

| Symptom | Likely cause | Fix |
|---|---|---|
| Tools don't appear in Claude | MCP server didn't restart after install | Fully restart AI-Prowler (server + GUI) |
| `record\_learning` succeeds but `check\_learned` returns nothing | ChromaDB index out of sync with JSON | GUI → 🔄 Rebuild ChromaDB Index |
| Claude isn't auto-detecting corrections | `_INSTRUCTIONS` block didn't update | Confirm `ai\_prowler\_mcp.py` is the v6.0 build; restart server |
| Confirmation message doesn't appear | Claude is recording silently | Confirm `_INSTRUCTIONS` block is present and complete |
| 🧠 Learnings tab shows "Unavailable" on action buttons | `self\_learning.py` not next to `rag\_gui.py` | Copy `self\_learning.py` into the install directory and restart GUI |
| GUI shows old data | JSON file was edited externally | Click ↻ Refresh |
| Same learning recorded twice | Duplicate detection is not automatic (by design — sometimes context warrants two entries) | Manually delete one, or use `update\_learning` to merge |

### File Locations

* **Learnings data:** `~/.ai-prowler/learnings/self\_learning\_data.json`
* **Conflict settings:** `~/.ai-prowler/learnings/conflict\_settings.json` (threshold + dismissed pairs)
* **ChromaDB collection:** `ai\_prowler\_learnings` (inside the main RAG database folder)
* **Engine module:** `C:\\Program Files\\AI-Prowler\\self\_learning.py`

\---

## 21\. Welcome Page \& Update Notifications

### Welcome Tab

The Welcome tab (tab index 0) is the first screen when AI-Prowler launches. It provides:

* **Version information** — the current AI-Prowler version displayed prominently
* **What's New** — a summary of new features and changes in the current release
* **Quick Start links** — shortcuts to common tasks (Index Documents, Start HTTP Server, etc.)
* **Update notifications** — when a new version of AI-Prowler is available, a notification banner appears on the Welcome tab with a download link

### Update Push Notifications

AI-Prowler checks for updates on launch by reading a version file from the public GitHub repository. If a newer version is available:

* A notification banner appears on the Welcome tab
* The notification includes the new version number and a brief changelog summary
* A download link opens the Releases page where the latest installer can be downloaded
* No automatic updating occurs — the user must download and run the new installer manually

This is a read-only check (no data is sent from your machine). The check can be disabled in Settings if desired.

\---

## 22\. Heartbeats \& Analytics

> **v6.0.0 visibility note:** The **Privacy & Analytics** panel in the Settings tab (with the on/off toggle, "📡 Send Heartbeat Now" button, and Last-success indicator) is hidden by default in v6.0.0. The anonymous daily heartbeat still runs in the background per the defaults below. Enable `DEBUG_EN = True` near the top of `rag_gui.py` to re-expose the panel.

### Anonymous daily heartbeat — what it is

AI-Prowler v6.0.0 sends a small daily anonymous heartbeat to a Cloudflare Worker so the developer can see how many installs are active and which versions are deployed. This is on by default and can be turned off (see below).

**What's sent:**

* A random `install_id` (UUID, generated once per install, never tied to a name or email)
* AI-Prowler version
* OS string (e.g. `"Windows-11"`)
* Number of chunks currently indexed
* Number of MCP tool calls in the last 24 hours

**What is NEVER sent:**

* Your name, email, IP address (the Worker discards client IPs after rate-limiting)
* Document content, queries, or file paths
* Document or learning database contents
* API keys, Bearer tokens, or any credentials

The endpoint is `https://ai-prowler-telemetry.david-vavro1.workers.dev` by default. It can be overridden via `telemetry_endpoint` in `~/.ai-prowler/config.json`.

### Heartbeat schedule

* First heartbeat fires roughly 5 minutes after first launch (`_TELEMETRY_FIRST_DELAY_SEC`)
* Subsequent heartbeats fire every 24 hours (`_TELEMETRY_HEARTBEAT_INTERVAL_SEC`)
* On failure: retry once after 1 hour, then back off to the normal 24-hour cycle
* The receiver applies an additional 12-hour server-side throttle to prevent duplicate uploads from accidentally re-firing

The "last successful heartbeat" timestamp is written to `~/.ai-prowler/telemetry_last_success.txt`.

### How to turn it off

Two options:

1. **Settings → Privacy & Analytics → uncheck "Send anonymous usage heartbeat"** — this is the user-facing toggle, but is hidden in v6.0.0 unless `DEBUG_EN = True`.
2. **Manually edit `~/.ai-prowler/config.json`** — set `"telemetry_enabled": false`. Restart AI-Prowler. No heartbeats will be sent.

Either method writes to the same config file; AI-Prowler honors it on next launch.

### Local analytics (never sent)

AI-Prowler also tracks several metrics purely for in-app display. These are local-only and have no connection to the heartbeat above:

* **Tool call counts** — how many times each MCP tool has been called since the server started (used to populate the `tools_called_24h` field in the heartbeat, then aggregated and discarded — no per-tool detail is sent)
* **Self-learning statistics** — total learnings, active vs deprecated, most applied learnings, breakdown by category and source (accessible via `get\_learning\_stats()` or the 🧠 Learnings tab)
* **Indexing metrics** — total documents, chunks, file types, tracked directories (accessible via `get\_database\_stats()` or `check\_status()`)
* **Applied count tracking** — every time `check\_learned()` returns a learning, its `applied\_count` increments, providing visibility into which knowledge is actually being used

Local analytics live in your ChromaDB, in `~/.ai-prowler/learnings/`, and in the various JSON tracking files. They are never sent to any external service.

\---

## Appendix A — MCP Protocol Version Notes

AI-Prowler uses the **Streamable HTTP** MCP transport for Claude.ai connections and **stdio** transport for Claude Desktop. The MCP SDK version installed determines feature support:

|Feature|Requires|
|-|-|
|Basic tool calls|mcp >= 1.0|
|`instructions=` in FastMCP constructor|mcp >= 1.2.0|
|Streamable HTTP transport|mcp >= 1.1.0|

To check your version, ask Claude to call `how\\\_to\\\_use\\\_ai\\\_prowler()` and check the `MCP SDK version` line in the output. Or run **🔬 MCP Diagnostics** from the Settings tab.

To upgrade: `pip install --upgrade mcp` in a command prompt.

\---

## Appendix B — Privacy Details

**What stays on your machine:**

* All document content
* The ChromaDB vector database
* All embeddings
* API keys and Bearer tokens
* The AI-Prowler configuration
* Self-learning knowledge base (JSON file + ChromaDB learnings collection)

**What leaves your machine:**

* When using Claude Desktop MCP: the text of retrieved document chunks (the relevant excerpts Claude found, not your original files) and your questions
* When using cloud API providers (Quick Links tab Q&A, when enabled via `SUPPORT_LOCAL_HW_LLM = True`): your question and retrieved document excerpts
* **Anonymous daily heartbeat** (on by default, can be disabled): install_id, version, OS string, indexed chunk count, MCP tool calls in last 24h — sent to the AI-Prowler telemetry endpoint. See Section 22 for full details and how to turn off.
* Subscription check: a connection to GitHub to read the public `subs.json` file (contains only token hashes, not your data)
* Update check: a read-only version check against the GitHub repository (no data is sent)

**What is never sent anywhere:**

* Your original document files
* Full document content (only the chunks Claude retrieves are shared)
* Your ChromaDB database
* Your API keys or Bearer tokens
* Your self-learning data (learnings stay entirely local)

\---

## Appendix C — Python Dependencies

Key packages and their roles:

|Package|Version|Purpose|
|-|-|-|
|chromadb|0.6.3|Vector database for document chunks|
|sentence-transformers|3.3.1|Embedding model (all-MiniLM-L6-v2)|
|huggingface-hub|0.26.5|Model downloads — pinned to avoid Errno 22 bug|
|transformers|4.44.2|Tokenizers — pinned for deterministic installs|
|pdfplumber|>=0.10.3|PDF text extraction|
|python-docx|>=1.1.0|Word `.docx` extraction — paragraphs and tables|
|pypdf|>=3.17.4|PDF fallback parsing|
|openpyxl|>=3.1.0|Modern `.xlsx` Excel extraction — `Column: Value` per-row format|
|xlrd|>=2.0.1|Legacy `.xls` Excel extraction (BIFF8) — date serial conversion included|
|python-pptx|>=0.6.21|PowerPoint `.pptx` extraction — per-slide labelled sections|
|beautifulsoup4|>=4.12.0|HTML tag stripping for `.html`/`.htm`/`.xhtml` files|
|striprtf|>=0.0.26|RTF control code removal for `.rtf` files|
|odfpy|>=1.4.1|OpenDocument `.odt` text extraction|
|pytesseract|>=0.3.10|OCR wrapper for Tesseract|
|pypdfium2|>=4.0.0|PDF page rendering for OCR (no poppler required)|
|pillow|>=10.0.0|Image I/O for OCR|
|extract-msg|>=0.45.0|Outlook `.msg` email parsing|
|pyspellchecker|>=0.7.2|Inline spell checking in Quick Links Q&A box (when enabled via `SUPPORT_LOCAL_HW_LLM = True`)|
|requests|>=2.31.0|HTTP requests (subscription checks)|
|uvicorn|>=0.29.0|ASGI server for HTTP MCP transport|
|faster-whisper|>=1.0.0|Voice-to-text (mic input)|
|sounddevice|>=0.4.6|Microphone audio capture|
|numpy|>=1.24.0|Array operations for audio processing|
|mcp|latest|MCP SDK (FastMCP) for tool server|

Note: `torch` (PyTorch) is intentionally not listed in `requirements.txt`. The installer detects whether an NVIDIA GPU is present and installs the correct build automatically (CUDA or CPU-only).

**Packages new in v5.0.0:** `openpyxl`, `xlrd`, `python-pptx`, `beautifulsoup4`, `striprtf`, `odfpy` — all installed automatically by the installer. No manual action required.

**New in v5.1.0:** `self\_learning.py` is a new module installed alongside the other app files. It uses only stdlib plus ChromaDB and sentence-transformers (already installed) — no new pip packages required.

\---

*AI-Prowler — Your Personal Agentic RAG Knowledge Base*  
*Copyright © 2026 David Kevin Vavro · david.vavro1@gmail.com*

