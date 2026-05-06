# AI-Prowler — Complete User Guide

**Version 5.1.0**

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
10. [Desktop Ask Questions Tab (Optional Local AI)](#10-desktop-ask-questions-tab-optional-local-ai)
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

**New in v5.1.0 — Self-Learning:** AI-Prowler now includes a RAG-based self-learning system. Claude can record business lessons, fact corrections, project insights, and process improvements into a structured knowledge base — and check that knowledge before answering future questions. Learnings are instant (no GPU training required) and managed through a dedicated 🧠 Learnings tab in the GUI. See Section 20 for full details.

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

**Ollama is not installed or downloaded automatically.** The primary AI interface is Claude Desktop via MCP, which requires no local model. If you want to use the standalone Ask Questions tab offline, you can install Ollama and download models manually from **Settings → Browse \& Install Model** after the main install completes.

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

AI-Prowler exposes **19 tools** to Claude. They fall into three categories.

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

## 10\. Desktop Ask Questions Tab (Optional Local AI)

The Ask Questions tab provides a traditional chat interface for querying your knowledge base. It is not Agentic (Agent based) smart Query based Question and answer and it works independently of Claude Desktop and is useful for fully offline operation and requires that the LLM be downloaded locally or you can access the external LLM via API interface but you will need to get API keys and sign up for the service plans offered by the external LLM providers.

### Ollama (Local AI)

Ollama is not installed automatically. To use local AI:

1. Download and install Ollama from the setting tab -> Install Ollama button [ollama.com](https://ollama.com)
2. In AI-Prowler, go to **Settings → Start the Ollama server and then Browse \& Install Models**
3. Select a model appropriate for your hardware
4. Click Install

**Recommended models by RAM:**

|RAM|Model|Quality|
|-|-|-|
|4 GB|llama3.2:1b or qwen2.5:1.5b|Basic|
|8 GB|llama3.2:3b or qwen2.5:7b|Good|
|16 GB|llama3.1:8b or qwen2.5:14b|Very good|
|32 GB+|qwen2.5:32b or llama3.1:70b|Excellent|

### Cloud AI Providers

Add API keys in **Settings → External AI APIs**:

|Provider|Notes|
|-|-|
|ChatGPT (OpenAI)|GPT-4o, pay-per-use|
|Claude (Anthropic)|claude-sonnet-4-6|
|Gemini (Google)|Free tier available|
|Grok (xAI)|Limited free|
|Llama API (Meta)|Free tier available|
|Mistral Large|Limited free|

### Voice Input

Click the microphone button to speak your question. AI-Prowler uses Whisper (large-v3-turbo model, \~1.6 GB, downloaded on first use) running entirely locally. Voice is never sent to any cloud service.

**Microphone silence timeout** — in Settings, you can adjust the silence detection timeout (default 3.0 seconds). Increase this if your speech is being cut off early; decrease it if there is too much lag after you stop speaking.

### Inline Spell Checker

The question text box includes an inline spell checker powered by `pyspellchecker`:

* Misspelled words are underlined in red as you type
* Right-click a highlighted word for a correction menu showing up to 8 suggestions
* Click a suggestion to replace the word
* The word is also added to your personal dictionary so it won't be flagged again

The spell checker activates automatically if `pyspellchecker` is installed. No configuration is needed.

### File Attachments

Attach images or text files to questions using the paperclip button. Vision support (image analysis) requires a cloud provider with vision capability.

### File Output Mode

When the AI produces code, a 💾 Save button appears automatically. Code is saved to a file with an auto-generated name based on the content. Works with all providers but some local and external AI models don't support this.

\---

## 11\. Settings \& Configuration

### Remote Access Tab

* **Bearer Token** — the password used to authenticate MCP connections from Claude.ai. Enter at least 10 characters of mixed case and numbers, then click **Save Token**. This token never changes between billing periods.
* **Port** — HTTP server port (default 8000). Only change this if port 8000 is in use by another service; you will also need to update your Cloudflare Tunnel route.
* **HTTP Server controls** — **▶ Start HTTP Server** / **■ Stop HTTP Server**. The status dot turns green when the server is listening. Starting the server automatically prevents Windows from sleeping (see Sleep Prevention below).
* **Status lights** — Internet ● (green = GitHub reachable) and Mobile Subscription ● (green = active, yellow = expiring/grace, red = blocked/unregistered)
* **Cloudflare Tunnel** — one-time setup buttons (Login, Create Tunnel, Route DNS, Save Config) and daily-use buttons (Start Tunnel, Stop Tunnel). See Section 7 for full setup walkthrough.
* **Install as Windows Service** — installs the Cloudflare Tunnel as a Windows background service that starts automatically at boot, even without AI-Prowler running.

> \\\*\\\*Note:\\\*\\\* The HTTP server and Cloudflare Tunnel are only needed for Claude.ai web/mobile access. Claude Desktop does \\\*\\\*not\\\*\\\* use these — it connects via the stdio MCP path configured automatically by the installer.

### Claude Desktop MCP Tab

* **MCP Status** — shows whether AI-Prowler is correctly registered in Claude Desktop's `claude\\\_desktop\\\_config.json`
* **Transport mode note** — confirms that Claude Desktop uses the stdio (local process) path, not the HTTP server. If your config shows an HTTP URL here, click **Auto-configure Claude Desktop** to fix it.
* **⚙️ Auto-configure Claude Desktop** — writes the correct stdio entry for AI-Prowler into Claude Desktop's config file. Also offers to restart Claude Desktop immediately.
* **Open Claude Desktop Config** — opens `claude\\\_desktop\\\_config.json` in Notepad for manual inspection
* **View Example Config** — shows a reference configuration you can copy from
* **Copy Config Path** — copies the config file path to the clipboard
* **🔬 Run MCP Diagnostics** — runs a full health check and shows a scrollable report covering: MCP SDK version, tool count, config validity, subscription cache, and log tail. Use **📋 Copy Output** to share the report with support.

### Models Tab

* **Active model** — switches between installed Ollama models for the Ask Questions tab
* **Browse \& Install Model** — opens a browser to Ollama's model library; you can then download a model directly from AI-Prowler's Settings
* **GPU layers** — set how many layers Ollama offloads to GPU (`-1` = auto, `0` = CPU only, `N` = N layers on GPU)
* **Auto-start Ollama** — when enabled, AI-Prowler launches the Ollama server automatically on startup. Not required if you are using Claude Desktop as your primary interface.

### External AI APIs Tab

* API key fields for each supported cloud provider (ChatGPT, Claude, Gemini, Grok, Llama API, Mistral)
* **Test Connection** button per provider — verifies your key is valid and the endpoint is reachable
* Timeout settings — controls how long the Ask Questions tab waits for a cloud response before showing a timeout error

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

### GPU Detection

* **🔍 Detect GPU** — shows your GPU model, VRAM, CUDA availability, current embedding device (CPU or CUDA), and Ollama GPU layer allocation if Ollama is running. Run this after install to confirm GPU acceleration is active.

### Voice Input (Mic Settings)

* **Silence timeout** — controls how many seconds of silence trigger end-of-speech detection (default 3.0 s). Increase if your speech is being cut off; decrease to reduce lag after you stop speaking. Found in Settings → Ask Questions options.

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

### NVIDIA GPUs

AI-Prowler detects NVIDIA GPUs automatically. The installer installs the correct PyTorch build:

* **CUDA 12.8 (cu128)** — for RTX 50xx (Blackwell) and most modern NVIDIA GPUs
* **CPU-only** — for systems without an NVIDIA GPU

### Embedding Acceleration

The sentence-transformer embedding model (`all-MiniLM-L6-v2`) uses CUDA automatically when available, significantly speeding up indexing.

### GPU Detect Tool

**Settings → 🔍 Detect GPU** shows:

* GPU model and VRAM
* CUDA availability
* Current embedding device (CPU or CUDA)
* Ollama GPU layer allocation (if Ollama is running)

### Blackwell (RTX 50xx) Note

PyTorch stable does not yet include CUDA 12.8 compute kernels for Blackwell SM 12.0+ architecture. Embeddings run on CPU on RTX 50xx cards even though CUDA is detected. Ollama itself supports Blackwell for inference. This will be resolved in a future PyTorch release.

### Controlling GPU Layers

In **Settings → GPU Layers**, set how many model layers Ollama offloads to GPU:

* `-1` = auto (let Ollama decide)
* `0` = CPU only
* `N` = N layers on GPU

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

In the Ask Questions tab, enable **Debug View** (toggle in toolbar) to see:

* Which document chunks were retrieved for each query
* Similarity scores for each chunk
* The full prompt sent to the LLM
* Raw LLM response before formatting

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

The Self-Learning System adds RAG-based knowledge accumulation to AI-Prowler. Instead of training LoRA adapters (which would take 30+ minutes and require a GPU), learnings are written to a structured JSON file and semantically indexed in ChromaDB — making new knowledge instantly available to Claude through the existing MCP toolchain.

This is useful for business operations where you want Claude to remember: what went wrong on a project, client communication preferences, process improvements discovered over time, corrected facts, and best practices.

### How It Works

Learnings are stored in two places simultaneously:

* **JSON file** (`~/.ai-prowler/learnings/self\_learning\_data.json`) — human-readable, easy to backup, read directly by the GUI
* **ChromaDB collection** (`ai\_prowler\_learnings`) — separate from the main document knowledge base, enables semantic search

When Claude records a learning, it is instantly available for retrieval. No training, no GPU, no restart required.

### Three Operational Modes

**Mode 1 — Proactive Checking:** Claude calls `check\_learned()` before answering questions about clients, projects, scheduling, procedures, or any topic where stored corrections might exist. This is instructed via the MCP instructions block in `ai\_prowler\_mcp.py`.

**Mode 2 — Recording:** When the user says "learn this" or "remember that", Claude calls `record\_learning()` with all metadata. Claude also auto-records when it detects fact corrections, project outcomes, client preferences, or process improvements in conversation — always with confirmation.

**Mode 3 — Post-Operation Analysis:** When asked to review a completed project or job, Claude follows a structured workflow: gathers project docs via `search\_documents()`, checks existing learnings via `check\_learned()`, identifies what went right/wrong, records each insight as a separate learning with `record\_learning()`, and presents all recorded learnings to the user for confirmation.

### Confirmation Protocol

Claude never records silently. Every learning gets a confirmation message:

* **Operator-requested** (user said "learn this"): concise confirmation with title, summary, and "Does this look right?"
* **Auto-detected** (Claude initiated): prominent banner with "🧠 AUTO-LEARNING" header, explains WHAT was recorded and WHY, asks "Is this correct?" explicitly

If the user says the learning is wrong, Claude immediately calls `update\_learning()` or `delete\_learning()` to fix it.

### Auto-Detection Triggers

Claude automatically records learnings (with `auto\_detected=True`) when it detects:

* User corrects a fact ("actually, the number is 555-0200")
* User shares a project outcome ("the Smith job went over budget by 40%")
* User mentions a client preference ("they hate phone calls")
* Post-op review reveals a process gap
* New information contradicts an existing active learning
* User describes a better approach ("next time we should submit permits earlier")

### Learning Categories

|Category|When to use|
|-|-|
|`fact\_correction`|Correcting an outdated or wrong fact|
|`business\_lesson`|What worked or didn't in business|
|`project\_insight`|Lessons from a specific project|
|`process\_improvement`|A better way to do something|
|`mistake\_learned`|Something went wrong — learn from it|
|`best\_practice`|Proven approach to adopt|
|`client\_preference`|Client-specific preferences|
|`technical\_note`|Technical fact or configuration gotcha|
|`general`|Catch-all|

### Supersession Chain

When a learning is replaced by newer information, the old learning is automatically marked as `deprecated` and linked to the new one. Claude sees the chain and knows to prefer the newer fact. The GUI detail panel shows supersession info when you select a learning.

### 🧠 Learnings Tab (Desktop GUI)

The Learnings tab in AI-Prowler provides a visual interface for managing the knowledge base without needing Claude. It reads directly from the JSON file — click **↻ Refresh** to reload. See Section 11 for the full panel breakdown.

### Managing Learnings

* **Archive** — hides a learning from Claude's search but keeps it for history. Use the GUI's **📦 Archive Selected** button or ask Claude: `"Archive the learning about X"`
* **Delete** — permanently removes from both JSON and ChromaDB. Use the GUI's **🗑 Delete Selected** button or ask Claude: `"Delete learning [ID]"`
* **Export** — click **💾 Export to CSV** in the GUI for a spreadsheet-friendly backup of all learnings
* **Rebuild Index** — click **🔄 Rebuild ChromaDB Index** in the GUI if the search index gets out of sync with the JSON file. Safe — no data is lost.

### Example Prompts

```
"Remember: always submit permits 2 weeks before job start"
"What do we know about Client X?"
"Analyze the Johnson project — what went right and wrong?"
"Show me all business lessons we have learned"
"How many learnings do we have and which are most applied?"
```

### File Locations

* **Learnings data:** `~/.ai-prowler/learnings/self\_learning\_data.json`
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

### MCP Server Heartbeat

The HTTP MCP server includes a heartbeat mechanism to monitor connection health:

* The server sends periodic heartbeat signals to confirm the Cloudflare Tunnel connection is active
* If the heartbeat detects a lost connection, it logs the event and can optionally attempt reconnection
* Heartbeat status is visible in the MCP server log (`mcp\_server.log`)
* Useful for diagnosing intermittent connection drops when using Claude.ai remotely

### Analytics Dashboard

AI-Prowler tracks basic usage metrics locally (never sent externally):

* **Tool call counts** — how many times each MCP tool has been called since the server started
* **Self-learning statistics** — total learnings, active vs deprecated, most applied learnings, breakdown by category and source (accessible via `get\_learning\_stats()` or the 🧠 Learnings tab)
* **Indexing metrics** — total documents, chunks, file types, tracked directories (accessible via `get\_database\_stats()` or `check\_status()`)
* **Applied count tracking** — every time `check\_learned()` returns a learning, its `applied\_count` increments, providing visibility into which knowledge is actually being used

All analytics data stays on your machine. No telemetry is sent to Anthropic, Cloudflare, or any external service.

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
* When using cloud API providers (Ask Questions tab): your question and retrieved document excerpts
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
|pyspellchecker|>=0.7.2|Inline spell checking in Ask Questions tab|
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

