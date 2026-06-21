# AI-Prowler — Complete User Guide
## Version 8.0.0

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
- **Total tools: 77** — up from 63 in v7.0.0.

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

AI-Prowler exposes **77 tools** to Claude across ten categories in v8.0.0.

### 6.1 Tool Counts by Mode

| Install type | Mode | Tools visible | Notes |
|---|---|---|---|
| Personal / Home | personal | 77 | All tools available |
| Business — employee personal install | personal | 77 | Full individual tool set |
| Business — company server | server | 35+ | Tier A tools suppressed; remaining gated by role |

### 6.2 Tier A Tool Suppression (Server Mode Only)

The following tools are never registered when AI-Prowler runs in server mode:

| Category | Suppressed tools |
|---|---|
| Dev / code execution | `run_script`, `run_script_start`, `run_script_status`, `run_script_kill`, `compile_check`, `check_python_import`, `syntax_check`, `lint_check` |
| Host filesystem writes | `create_file`, `write_file`, `str_replace_in_file`, `fuzzy_replace_in_file`, `line_replace_in_file`, `create_directory`, `list_directory`, `copy_to_backup`, `list_backups`, `restore_backup`, `cleanup_backups`, `reset_write_counter` |
| Raw filesystem reads | `read_file_lines`, `grep_documents` |
| Email operator tools | `configure_email`, `send_file`, `send_learnings_report` (operator config) |
| Bulk index rebuild | `reindex_all` |

> **Note:** `send_sms`, `send_email`, `send_alert`, `send_whatsapp`, `send_learnings_report` (user-facing) are **not** suppressed in server mode — they remain available to users via the Tier B role gate.

### 6.3 Role-Based Tool Access in Server Mode (Tier B)

| Tool group | owner | manager | staff | field_crew |
|---|---|---|---|---|
| RAG Search (search, overview, list docs, etc.) | ✅ | ✅ | ✅ | ✅ |
| Field Service (weather, geocode, route, maps, spreadsheet) | ✅ | ✅ | ✅ | ✅ |
| SMS & WhatsApp (send_sms, send_whatsapp, check_sms_inbox, check_sms_replies, check_whatsapp_replies) | ✅ | ✅ | ✅ | ✅ |
| Self-Learning (record, check, list, update, delete, stats) | ✅ | ✅ | ✅ | ✅ |
| `check_ai_prowler_status`, `how_to_use_ai_prowler` | ✅ | ✅ | ✅ | ✅ |
| `check_tools_status` (field-service health) | ✅ | ✅ | ✅ | ✅ |
| `send_email`, `send_alert` | ✅ | ✅ | ✅ | ✅ |
| `send_learnings_report` | ✅ | ✅ | ✅ | ✅ |
| `index_path` (limited — own scopes only) | ✅ | ✅ | ✅ | ❌ |
| `reindex_file`, `reindex_directory` | ✅ | ✅ | ❌ | ❌ |
| `untrack_directory`, `update_tracked_directories` | ✅ | ✅ | ❌ | ❌ |

### 6.4 Complete Tool Reference Table

---

#### Agentic RAG — Knowledge Base Search (10 tools)

| Tool | What It Does | Mode |
|---|---|---|
| `how_to_use_ai_prowler` | Returns the recommended workflow and tool sequence. Claude calls this automatically at the start of research sessions. | Personal + Server |
| `get_knowledge_base_overview` | High-level summary: document count, file types, chunk count, database location, tracked directories. Start here before any research task. | Personal + Server |
| `search_documents` | Primary retrieval tool. Semantic vector search returning raw document chunks with source metadata and similarity scores. | Personal + Server |
| `multi_query_search` | Runs 2–6 search queries in parallel and returns deduplicated results ranked by best similarity. More efficient than multiple `search_documents` calls. | Personal + Server |
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
| `get_database_stats` | Chunk count, unique document count, and file-type breakdown for the ChromaDB index. In server mode shows scoped collections separately. | Personal + Server |

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
| `update_learning` | Edits any field of an existing learning — content, confidence, outcome, status, tags. | Personal + Server |
| `delete_learning` | Permanently removes a learning from both JSON and ChromaDB. Consider archiving instead. | Personal + Server |
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
| `check_tools_status` | Field-service health check. Reports which action tools are ready to use and which need configuration (SMTP, spreadsheet path, routing APIs). | Personal + Server |

---

#### SMS & WhatsApp Tools (5 tools — New in v8.0.0)

These tools enable two-way SMS and WhatsApp communication between field crew, registered server users, and spreadsheet customers. Available to all roles in server mode.

| Tool | What It Does | Mode |
|---|---|---|
| `send_sms` | Sends an SMS message to a registered user (from users.json) or a spreadsheet customer (from AI-Prowler_Job_Tracker.xlsx). Provider-abstracted: works with Twilio, SignalWire, or Vonage. In server mode, the sending employee's identity is stamped in the thread log. | Personal + Server |
| `send_whatsapp` | Sends a WhatsApp message via the Twilio WhatsApp Business API. Same recipient lookup as `send_sms`. Works worldwide — no carrier gateway issues. | Personal + Server |
| `check_sms_inbox` | Reads the local SMS inbox (populated in real time via the `/sms-webhook` endpoint). Returns inbound messages grouped by sender phone number. Thread-isolated per crew member. | Personal + Server |
| `check_sms_replies` | Checks for inbound SMS replies from a specific contact or phone number. Returns the most recent replies in chronological order. | Personal + Server |
| `check_whatsapp_replies` | Checks for inbound WhatsApp messages from a specific contact. Returns the most recent messages in chronological order. | Personal + Server |

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
| `send_email` | Sends a plain-text email. Optional file attachment from any tracked directory. In server mode uses the server's SMTP config with employee Reply-To header. | Personal + Server (all roles) |
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

#### Code Tools — Write-Side (13 tools — Personal Installs Only)

All write operations are protected by four independent layers: read allowlist, writable allowlist, hard blocklist, and per-session circuit breaker. Suppressed in server mode.

| Tool | What It Does | Mode |
|---|---|---|
| `create_file` | Creates a new file. Fails if the file already exists. | Personal |
| `write_file` | Overwrites an existing file. Auto-backs up to `.bakN` before writing. | Personal |
| `str_replace_in_file` | Surgical in-place edit: replaces one unique occurrence of `old_str` with `new_str`. Requires exact whitespace match including indentation. Use `dry_run=True` to preview the diff before committing. 1000× cheaper than a full file rewrite for large files. | Personal |
| `fuzzy_replace_in_file` | **New in v8.0.0.** Whitespace-tolerant surgical edit. Tries four progressively looser matching strategies: exact → CRLF normalization → trailing whitespace strip → full whitespace collapse. Use when `str_replace_in_file` fails due to indentation or line-ending differences. | Personal |
| `line_replace_in_file` | **New in v8.0.0.** Replaces a range of lines by line number. Zero text-matching ambiguity — works on any file regardless of encoding or Unicode. Always pair with `read_file_lines` first to confirm exact line numbers. Last resort when both replace tools fail. | Personal |
| `create_directory` | Creates a directory and any missing parents. Idempotent. | Personal |
| `list_directory` | Lists the immediate contents of a directory: files, subdirectories, and backups. Read-only. | Personal |
| `copy_to_backup` | Takes a manual snapshot of a file as `.bakN` without modifying the original. | Personal |
| `list_backups` | Lists all backups for a given file with timestamps and sizes. | Personal |
| `restore_backup` | Overwrites the active file with the contents of the specified backup. | Personal |
| `cleanup_backups` | Finds and optionally deletes backup files. Always run with `dry_run=True` first to preview. | Personal |
| `reset_write_counter` | Resets the per-session 20-write circuit breaker so large editing sessions can continue without restarting the server. | Personal |
| `list_writable_directories` | Lists all directories in the write-zone allowlist with read allowlist for reference. | Personal |

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
| `check_ai_prowler_status` | RAG engine health check. Verifies ChromaDB connectivity, embedding model status, chunk count, and tracked paths. | Personal + Server |
| `how_to_use_ai_prowler` | Returns the recommended Agentic RAG workflow and tool-call sequence. Call at the start of any new research session. | Personal + Server |

---

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

### Setup Steps

1. **Set a Bearer Token** — In Settings → Remote Access, enter a Bearer token (minimum 10 characters, mixed case and numbers). Click **Save Token**.
2. **Start the HTTP Server** — Click **▶ Start HTTP Server**. The status light turns green.
3. **Set up a Named Tunnel** — For permanent daily use, set up a Named Tunnel with your own domain (see below).
4. **Connect Claude.ai** — Add your tunnel URL as a custom connector in Claude.ai Settings → Connectors.

### Status Lights

- **Internet ●** — green when your PC can reach GitHub
- **Mobile Subscription ●** — green = active; yellow = expiring/grace; red = blocked/unregistered

### Keep It Running Panel (New in v8.0.0)

The **Keep It Running** panel in the Remote Access tab ensures Windows doesn't interrupt your MCP server with sleep, hibernate, or automatic restarts.

- **LED power status indicators** — shows current sleep setting status at a glance (green = correctly configured, red = needs attention)
- **⚡ Apply Power Settings Now** — one-click button that automatically sets:
  - Screen and sleep to Never (plugged in only; battery settings unchanged)
  - Lid close action to Do Nothing (plugged in only)
  - Hibernate disabled (`powercfg /h off`)
  - Windows Update Active Hours to 6 AM – 11 PM (prevents auto-restarts during the day)
- **📋 Power Settings Guide** — opens a scrollable popup with full step-by-step manual instructions for all three power settings, for users who want more insight and control.

> **Safe to apply:** All changes are plugged-in only and reversible. Battery behavior is unchanged. Hibernate can be re-enabled anytime with `powercfg /h on`.

### Named Tunnel Setup (Permanent)

A Named Tunnel gives you a permanent, branded URL (e.g. `https://mycompany.ai-prowler.com`).

Prerequisites: AI-Prowler subscription provides a free Cloudflare account and domain name.

One-time setup:
1. In Settings → Remote Access → Named Tunnel, enter your **Public hostname** and **Tunnel token** (from Cloudflare Zero Trust dashboard → Networks → Tunnels → your tunnel → Token).
2. Click **Activate Tunnel Service** — this installs `cloudflared` as a Windows background service.
3. Status shows **Tunnel active (Windows service)** with a green dot.

After this one-time setup, the tunnel starts automatically at boot. Use **Start Tunnel / Stop Tunnel** for manual control.

### Connecting Claude.ai — Step by Step

1. Open claude.ai and sign in (Claude Pro or Team required)
2. Click your profile icon → Settings → Connectors → **Add custom connector**
3. Enter your tunnel URL followed by `/mcp` (e.g. `https://mycompany.ai-prowler.com/mcp`)
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

Email david.vavro1@gmail.com with your name or company name and which plan you want.

### Grace Period

If your subscription lapses, a 30-day grace period begins. After 30 days, access is suspended until renewal.

### Mobile Activation — Machine Management

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

### Token Recovery (v8.0.0)

Token recovery is **email-only**. If you forget your Bearer token:

1. Click **"Forgot your token?"** in the Settings → Remote Access panel
2. AI-Prowler sends a recovery code to the admin's configured email address
3. Enter the recovery code to reveal or reset your token

SMS-based token recovery has been removed in v8.0.0.

---

## 9. Business Server Mode — Multi-User Access

Business edition lets you run AI-Prowler in server mode on a company machine so a whole team reaches one shared knowledge base from Claude on their phones and laptops.

### The Big Picture

A Business license is a parent key plus a pool of child seat keys (one per employee). The same child key works in two independent places:

1. **The company server** — the owner runs one AI-Prowler in server mode. Each employee is added as a user, assigned a child seat, and given a personal bearer token. They reach the shared company knowledge base via Claude.ai on their phone or laptop using the company's Cloudflare Tunnel URL.

2. **A personal install (optional)** — the same employee can install AI-Prowler on their own laptop, activate it with the same child key in personal mode, and index their own private documents. They get their own Cloudflare Tunnel and their own Claude.ai connector pointing to their personal install — completely separate from the company server.

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
1. Their bearer token — send securely
2. The company's Claude.ai connector URL — your server's Cloudflare Tunnel address (e.g. `https://mycompany.ai-prowler.com/mcp`)

The employee adds that connector in Claude.ai settings, authenticates with their bearer token, and starts a new conversation. No software install required on their side.

### Replacing the Server Machine

1. Install AI-Prowler on the new machine
2. Enter the same Parent License Key in Settings → Remote Access → Parent License Key
3. Copy `users.json`, `license_seats.json`, and `rag_database/` from the old machine (if recoverable) — or re-enter users manually via the Admin tab
4. Reconfigure the Cloudflare Tunnel on the new machine with the same tunnel token
5. All employees' Claude.ai connectors continue to work — the URL doesn't change

> **Why no transfer step is needed:** The parent license key has no machine lock. It is validated against your subscription record for validity and seat count only. You can run it on any machine.

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

The installer deploys a pre-built `AI-Prowler_Job_Tracker.xlsx` to your Documents folder.

| Tab | Purpose |
|---|---|
| Customers | Customer master list with addresses, service type, frequency, email, phone, cell carrier, SMS gateway |
| Jobs_Schedule | All service appointments with route and weather columns |
| Route_Planner | Daily route optimization — AI fills lat/lon and map URLs |
| Quotes | Estimates sent to customers |
| Invoices | Billing and payment tracking |
| QB_Daily_Export | Daily export rows for accounting software import |
| Services_Pricing | Service catalog with pricing |
| AI-Prowler_Commands | Quick reference for Claude prompts |

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

---

## 13. Settings & Configuration

### Remote Access Tab

- **Bearer Token** — the password used to authenticate MCP connections from Claude.ai. Enter at least 10 characters of mixed case and numbers, then click **Save Token**.
- **Port** — HTTP server port (default 8000).
- **HTTP Server controls** — ▶ Start HTTP Server / ■ Stop HTTP Server.
- **Status lights** — Internet ● and Mobile Subscription ●
- **License Key / Parent License Key** — enter your subscription key to activate remote access. In server mode shows as "Parent License Key".
- **Mobile Activation** — shown in personal/home mode only (hidden in server mode):
  - **Check Activation** — checks if this machine is the active install
  - **Transfer to This Machine** — use when replacing your computer
  - **"Forgot your token?"** — sends recovery code to admin email (v8.0.0: email-only)
- **Named Tunnel** — enter Public hostname and Tunnel token, then click **Activate Tunnel Service**.
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

AI-Prowler automatically applies OCR to scanned PDFs and standalone image files (`.jpg`, `.jpeg`, `.png`, `.tif`, `.tiff`, `.bmp`, `.webp`).

### How It Works

1. `pdfplumber` attempts to extract the text layer from PDFs
2. If no text found, renders each page to a 300 DPI image
3. `pytesseract` (Tesseract 5.4) extracts text from the image
4. The extracted text is chunked and indexed normally

### OCR Debug Tools

In Settings, use the **OCR Debug** button to test OCR on a specific file and see the extracted text before indexing.

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

### Windows Task Scheduler Integration

Set up automatic index updates from **Settings → Schedule**:

1. Choose update frequency (daily, specific days, custom)
2. Set the time (default: 2:00 AM)
3. Click **Create Schedule**

### Cloudflare Tunnel as Windows Service

For always-on remote access, activate the Named Tunnel as a Windows service via **Settings → Remote Access → Activate Tunnel Service**. The tunnel starts automatically at boot.

---

## 18. GPU Support

AI-Prowler detects NVIDIA GPUs automatically. The installer installs the correct PyTorch build (CUDA 12.8 for RTX 50xx/Blackwell, or CPU-only). The sentence-transformer embedding model (`all-MiniLM-L6-v2`) uses CUDA automatically when available, significantly speeding up indexing. This is the only place a GPU helps — all language reasoning happens in Claude (cloud).

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

**Problem: Inbound SMS not appearing in `check_sms_inbox`**
1. Verify the HTTP server is running and the Cloudflare Tunnel is active
2. In your Twilio Console, confirm the webhook URL for your phone number is set to `https://your-tunnel-domain/sms-webhook`
3. Check `mcp_server.log` for any webhook POST entries

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
*Version 8.0.0*
