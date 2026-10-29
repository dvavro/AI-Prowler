# AI-Prowler — Complete User Guide
## Version 9.6.0 — updated October 22, 2026

---

## Table of Contents

1. What is AI-Prowler?
2. Installation
3. Connecting Claude Desktop via MCP
4. Indexing Your Documents
5. Agentic RAG — How Claude, Muse, or Grok Uses Your Knowledge Base
6. MCP Tools Reference
7. Remote Access — Claude.ai on Mobile and Web
8. Mobile Subscription Management
9. Business Server Mode — Multi-User Access (roles, scopes, Admin tab, Jobs App access)
10. Small Business Service Tools & Job Tracker Workflow (Job Board & SQLite-Backed Database)
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
25. Jobs PWA App (the mobile app for crews and owners — incl. roles & data access in server mode)
26. Remote PWA App
27. Service Desk (tickets)

---

## 1. What is AI-Prowler?

AI-Prowler is an Agentic RAG (Retrieval-Augmented Generation) knowledge base for Windows. It indexes your local documents into a private ChromaDB vector database and exposes them to Claude, Muse, or Grok as a suite of intelligent search and retrieval tools.

**The key difference from traditional RAG:**

Traditional RAG retrieves a chunk, hands it to a small local model, and gets a mediocre answer. AI-Prowler's Agentic RAG lets Claude, Muse, or Grok actively drive the research process:

- Claude, Muse, or Grok decides what to search for based on your question
- It evaluates what it finds and identifies gaps
- It reformulates queries and searches again
- It reads surrounding context when a result is incomplete
- It synthesizes a comprehensive answer from everything it gathered

This produces dramatically better results — equivalent to having a skilled research assistant who knows your entire document library. Hardware requirements are minimal. Because Claude, Muse, or Grok does the reasoning, AI-Prowler only needs to run the embedding model (~400 MB RAM) and ChromaDB. No GPU is required. No large local AI model is needed.

### Key Capabilities

Beyond core document search, AI-Prowler includes:

- **Self-Learning knowledge base** — Claude, Muse, or Grok can record business lessons, fact corrections, project insights, and process improvements into a structured knowledge base, and checks that knowledge before answering future questions. Instant — no GPU training required. Managed through a dedicated 🧠 Learnings tab in the GUI. See **Section 22**.
- **Business Server Mode** — multi-user team deployments with roles, scopes, and role-based tool access, so a whole company reaches one shared knowledge base from Claude, Muse, or Grok on their own phones and laptops. See **Section 9**.
- **Small Business / Job Tracker tools** — a full contractor workflow (customers, scheduling, quoting, invoicing, route planning, time tracking, AR aging) that Claude, Muse, or Grok reads and writes in plain English, backed by a SQLite database (`ai_prowler_jobs.db`). Excel is available as a generated export. See **Section 10**.
- **Job Board** — a live admin kanban/grid of the day's jobs, updating on a 1-minute poll as crew clock in, upload photos, and complete work, with safe concurrent editing all day long. See **Section 10 → Job Board**.
- **Data Portability** — export to Excel/CSV/QuickBooks-ready CSV for accountants and bookkeeping, plus lossless backup/restore for safekeeping or moving to a new PC. See **Section 10 → Data Portability**.
- **Two-way SMS & WhatsApp messaging** — field crew can send and receive SMS and WhatsApp messages to customers directly from Claude, Muse, or Grok, with real-time inbound capture via webhook (no polling lag). Provider abstraction supports Twilio, SignalWire, Vonage, and WhatsApp Business API. See **Section 11**.
- **File editing & code tools** — Claude, Muse, or Grok can create, edit, and manage files directly (exact-match replace, line-number replace, directory tools, backups), plus run and debug scripts. See **Section 6**.
- **Remote Access & mobile apps** — reach AI-Prowler from Claude.ai on any phone or browser, plus two dedicated PWAs: the **Jobs App** for field crew (Section 25) and the **Remote PWA** for managing AI-Prowler itself remotely (Section 26).
- **Agentic analysis task queue** — schedule recurring or one-off AI analysis tasks (e.g. "check overdue invoices every Monday") that run autonomously and record their findings as learnings. See **Section 10** and **Section 26**.
- **Proactive email alerts** — background jobs (morning briefing, overdue invoices, weather watch, etc.) with independent per-job scheduling. See **Section 17**.

### What's New — October 27–28, 2026

**🎫 Service Desk (tickets)** — new, optional, for personal (Solo) and server (team) installs. Customers request service from their phone, every ticket is tracked Open → Closed with one owner and a history, photos and documents ride along, and Claude, Muse or Grok can run it all by chat or voice. Off on new installs — turn it on (or off again) in Settings → MCP Tool Configuration. The Business tab has the phone link with Copy / Email / QR. Watchers on your team are emailed on every change; customers just hear "in progress" and "closed". See **Section 27**.

### What's New — October 21–22, 2026

**AI routing with any AI chat (Jobs app → Route tab)**
- **📋 Copy AI Route for Any AI** — one tap makes a ready-to-paste prompt that plans the day's route (fixed appointment times respected, soft jobs fill the gaps, real drive times). Paste it into Claude, Muse, Grok — any AI chat that has AI-Prowler connected — and watch it work; the route is saved back to the Route tab for you to review and Approve. See **Section 25 → Route**.
- **🗓️ Plan Week with Any AI** — for any week, the AI suggests moving **soft** jobs so jobs near each other are done on the same day. Hard (committed) jobs never move, moves stay on working days and the customer's Preferred Day(s), and **nothing changes until you approve** the moves you want. See **Section 25 → Route**.
- **New setting: Week Plan Distance (miles)** — how close two jobs must be to count as "near each other" for Plan Week (default 5). See **Section 10 → Week Plan Distance (miles)**.
- Each prompt carries a one-time code, so if you have more than one AI-Prowler connected (personal and company server), the chat uses only the one that made it.
- **Voice and chat (Oct 23):** no pasting needed — say or type "Route me for today" or "Plan my week" and the AI runs it; approve in the app or by saying yes after it reads the changes back. See **Section 6.4 → AI Routing with Any AI Chat**.

**Removed: the Claude CLI "🧠 Run AI Route"** — in personal and server mode. It needed the Claude Code CLI and a Claude token per person (a new token could cancel another computer's), ran in the background for minutes with nothing to watch, and could start a second copy of AI-Prowler. Gone with it: the Jobs app's "Connect your Claude account" screens, the Small Business tab's **🧭 AI Route Optimizer Task** / **Set Up On-Demand AI Routing**, and on servers the Admin tab's **🧠 AI Route runner** panel, **🤖 AI Route Token** button and **AI Route** column — **an admin no longer manages any Claude passwords.** AI-Prowler removes the old "AI Route Optimizer (full reasoning)" custom analysis, its Windows task and the saved per-person tokens automatically the first time the new version starts.

**AI analyses always use the AI-Prowler that's already running** — every Autonomous AI Task Queue run (Claude or Grok, scheduled or ▶ NOW) talks to this PC's running AI-Prowler and never starts a second copy. It needs remote access (a Bearer Token); if AI-Prowler isn't running when a scheduled run fires, the run starts the normal app and waits, or skips and says why (see **Section 12 → Autonomous AI Task Queue**).

**Jobs app**
- **Version badge** (top-right of the Jobs, Remote, HR Admin, HR Portal and Service Desk apps) — tap it to see whether your phone has the latest app (green) or a newer one is waiting (red — tap again to load it).
- **Route map pull-down bar** now works on a PC: drag it down to make the map bigger, up to make it smaller.
- **"Settings aren't filled out" warning** lists exactly which business settings invoices still need, with a button that opens the Settings card; it disappears once they're saved.
- **Reports → 📅 Net Revenue (after sales tax)** — a calendar-year card: actual + projected net revenue, with sales tax taken off invoiced jobs once and pre-tax estimates left as they are.
- **Recurring jobs and 🔮 projections land on the customer's Preferred Day(s)** — a Weekly "Thursday" customer's next job and every projected visit fall on a Thursday.

**Desktop app**
- **Update downloaded — NOT installed yet**: after Download Update, AI-Prowler offers **🔄 Restart Now** (or Later) and keeps a reminder on the status bar and Home/Server tab until the update is really installed.
- **Setup Center**: new installs get a blinking nudge — first **➕ Add a service**, then **🧭 Set up AI-Prowler**. **Connect your AI** now has two tabs: **Claude Desktop** (free) and **phone / web** (Claude, Grok or Muse via the mobile subscription). The **Scheduled analyses** step says up front that it needs the Claude Code CLI signed in with Claude Pro. The **Crew routes** step no longer installs Claude Code — it explains the any-AI buttons and sets the Plan Week distance.

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

> **Note:** When running in mobile mode it is recommended to open Claude, Muse, or Grok via https://claude.ai for all remote access (cell, tablet, web). This prevents having multiple AI-Prowler MCP connectors active simultaneously.

### What the Installer Does NOT Do

No large local AI model is installed or downloaded. The AI interface is Claude Desktop (or Claude.ai for mobile/web) via MCP, which requires no local model. AI-Prowler only runs the small embedding model (~400 MB) and ChromaDB locally; Claude, Muse, or Grok does all the reasoning. Installation typically takes under 10 minutes.

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

Claude Desktop connects to AI-Prowler via the MCP (Model Context Protocol) — a standard that lets Claude, Muse, or Grok use external tools and data sources.

### How It Works

The installer automatically writes AI-Prowler's entry into Claude Desktop's configuration file. When Claude Desktop starts, it connects to AI-Prowler and discovers all available tools automatically. No manual configuration is needed.

> **Note:** If mobile is configured, it is strongly recommended to use only mobile access for all MCP (Claude, Muse, or Grok) connections going forward. This prevents two connectors (local Claude Desktop + remote Claude.ai) from being active simultaneously.

### Verifying the Connection

Open Claude Desktop and start a new conversation. You should see a tools indicator showing AI-Prowler is connected. Ask: *"What tools do you have available?"* — Claude, Muse, or Grok will list all available tools. If you see `search_documents` and `get_knowledge_base_overview`, the connection is working.

### MCP Diagnostics Tool

If tools are not appearing or tool calls are failing:

1. Go to **Settings → Claude Desktop MCP**
2. Click **🔬 Run MCP Diagnostics**
3. A scrollable output window shows MCP SDK version, tool count, config validity, subscription cache, and log tail.
4. Click **📋 Copy Output** to copy the full report for sharing with support.

---

## 4. Indexing Your Documents

Before Claude, Muse, or Grok can search your documents, they must be indexed. Indexing extracts text, splits it into chunks, generates embeddings, and stores everything in ChromaDB.

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
- **⏹ Stop** — halt an in-progress index or update cleanly. AI-Prowler finishes the current file, then stops.

### Automatic Purge of Deleted Files

When you delete a file from a tracked folder and run **Update Selected** or **Update All**, AI-Prowler automatically purges that file's chunks from ChromaDB. The vector database stays in sync with your file system — no manual cleanup required.

### Corruption Protection — Startup Integrity Check

Every time the AI-Prowler server starts, it runs `PRAGMA quick_check` on the ChromaDB SQLite store (takes under a second). If the index is corrupted, the status check reports **"index corrupted — run reindex_all(purge_first=True)"** instead of dying silently.

When a reindex starts, AI-Prowler writes a crash marker file (`.reindex_in_progress.json`) and deletes it on success. If the server finds that marker on startup, it warns **"previous reindex interrupted"** — the last reindex was killed partway through. Re-run the reindex to fix it.

### Duplicate Path Detection

Tracked folders are always scanned **recursively**, so a folder that sits **inside** an already-indexed folder — or one that **contains** an already-indexed folder — would have every shared file indexed twice. AI-Prowler checks for both whenever a folder (or a single file) is added, in **personal and server mode alike**:

- **Adding to the Index Queue** (Update Index tab) — an **Overlapping Index Path** warning if the folder is inside / contains an already-indexed folder *or* an already-queued one.
- **When indexing registers it for tracking** — a **Duplicate or Overlapping Path** popup (and the same line in the output log).
- **When Claude, Muse, or Grok indexes it** (`index_path`, the only way in on a server) — the warning is in Claude/Muse/Grok's reply, together with the advice to untrack one of the two.
- **In the tracked folder list** — any row covered by another tracked row is shown in **red** (re-checked every time the list reloads, so it clears once you untrack the parent).

These are warnings, not blocks: the folder is still added, because tracking a sub-folder on purpose (e.g. a single file you want watched) is sometimes legitimate. An exact duplicate is simply ignored ("already tracked"); on Windows a different-case spelling of the same folder replaces the old entry.

### Server-Mode Scope Tagging (Business Server Only)

On a Business Server install, every indexed chunk is tagged with a **scope** (`sales`, `office`, `shared`, `private:<user>`, etc.) instead of being routed into a separate physical database. All indexed content lives in one shared knowledge base; the scope tag is what search filters on at query time — see **Section 9 → Scopes** for the full access-control picture. This applies no matter *how* a file gets indexed: manually via **Update Selected**/**Update All**, the File Watchdog's real-time auto-indexing (below), or the Scheduled Task.

**Every tracked directory has exactly one assigned scope**, set from the Update Index tab (**Section 9 → Assigning Scopes to Folders**). From then on, any file placed anywhere inside that directory is tagged with that scope automatically — you never have to think about it file-by-file.

**A directory with no scope assigned is never skipped or blocked** — it indexes normally and defaults to `shared`, visible to everyone. Scope is purely a metadata label applied at index time, not a routing decision that can misfire.

Personal/Home installs are entirely unaffected by any of this — everything simply goes into the single database, with no scope tagging needed since there's only one user.

### Mobile Write Zones — Granting Claude, Muse, or Grok Write Access

Indexing a directory makes its contents searchable. It does not let Claude, Muse, or Grok modify files there. Write access is a separate, opt-in permission you grant per directory.

The tracked-paths listbox shows a write-permission prefix on every row:

- `[W]` — writable. Claude, Muse, or Grok can create, edit, and delete files anywhere inside.
- `[~]` — partially writable. A narrower sub-directory has write access.
- `[R]` — read-only. Claude, Muse, or Grok can search content here but cannot modify any file.

Double-click a row to toggle between read-only and writable.

> **Note:** When Claude, Muse, or Grok modifies a file it creates a `.bakN` backup alongside the changed file. This allows you or Claude, Muse, or Grok to roll back to previous versions. After verifying changes work correctly, manually delete `.bakN` files to reduce clutter and free space.

### Access-Only Folders — File Access Without Indexing (Personal mode only)

An **access-only folder** is one Claude, Muse, or Grok can **read** without it ever being **indexed into ChromaDB**: no embeddings, no disk cost, no reindex time, and its contents never show up in `search_documents` results. Claude/Muse/Grok's file tools (`read_file_lines`, `grep_documents`, `list_directory`, …) still work on files inside it. Use it for reference folders or working directories you want Claude, Muse, or Grok to open on request but don't need searchable.

**Rules for adding a folder** (the same everywhere — desktop, Remote app and Claude, Muse, or Grok):

1. **Folders only, always including their sub-folders.** Individual files can't be added — add the folder that contains them.
2. **No duplicates.** A folder that's already on the list is refused ("already an access-only folder").
3. **Nothing already covered.** A folder inside an access-only folder is refused ("already covered by access-only folder …") — it's readable already. So is a folder inside, or equal to, an **indexed** folder ("already readable — it's inside indexed folder …").
4. **Adding a bigger folder is fine.** If you add a folder that contains folders already on the list, it's added and those inner entries are removed ("folded in") since the new folder now covers them. Their write switches aren't changed.

Keeping one entry per area makes it simple to set read or read + write per folder.

**Read access only, by default.** Adding a folder does *not* let Claude, Muse, or Grok change anything there. Write access is a separate switch: each access-only row has the same **[W]** / **[R]** toggle as the indexed folders (see Mobile Write Zones above). The hard blocklist always wins — a blocked system folder stays unreadable even if it's listed here.

**Where to manage them (all three edit the same list, `~/.rag_access_only_dirs.json`):**

- **Desktop:** the **Access-Only Folders** panel on the Update Index tab — **📁 Add…**, **🗑 Remove Selected**, **🔄 Reload List**; double-click a row to toggle write access.
- **Phone / browser:** the Remote Control app's **Perms** tab → **Access-Only Folders** section — type the folder path and tap **Add** (you'll re-enter your Bearer token to confirm), tap **🗑** to remove (instant), and use the switch on a row for write access.
- **Claude, Muse, or Grok:** ask it to "let Claude, Muse, or Grok read C:\Manuals without indexing it" (`grant_access`) or "remove Claude/Muse/Grok's access to C:\Manuals" (`revoke_access`). `list_tracked_directories` shows them in their own **📂 Access-only folders** section.

**Personal installs only.** On an AI-Prowler **Business server** the feature is switched off completely: the Update Index panel isn't shown, `grant_access` / `revoke_access` aren't offered to Claude, Muse, or Grok (and refuse if called), `list_tracked_directories` has no access-only section, and an access-only list left on the server's disk makes nothing readable. To share a folder with your team on a server, index it (`index_path`) and give the right scope access instead.

---

## 5. Agentic RAG — How Claude, Muse, or Grok Uses Your Knowledge Base

This is the core capability of AI-Prowler. Understanding it helps you get the best results.

### The Research Loop

When you ask Claude, Muse, or Grok a question with AI-Prowler connected, Claude, Muse, or Grok follows this pattern automatically:

1. Calls `how_to_use_ai_prowler` to get the recommended search workflow
2. Calls `get_knowledge_base_overview` to understand what's indexed
3. Calls `search_documents` or `multi_query_search` with targeted queries
4. Calls `expand_search_result` if a chunk is cut off at a boundary
5. Calls `read_document` if a full document is needed
6. Calls `search_learnings` to check stored business knowledge
7. Synthesizes a comprehensive answer from all gathered material

### Tips for Best Results

- Ask open-ended research questions — give Claude, Muse, or Grok latitude to investigate.
- Let Claude, Muse, or Grok finish — you'll see multiple tool calls before the answer. This is the agentic loop working.
- Ask follow-up questions — Claude, Muse, or Grok retains context within a conversation.

---

## 6. MCP Tools Reference

AI-Prowler exposes its features to Claude, Muse, or Grok as MCP tools, grouped in this guide by category (§6.4). Which tools are actually *visible* on a given connection isn't a fixed number — it depends on the install's mode and on what the owner has chosen to turn off, as described below.

### 6.1 Which Tools Are Available

Three layers decide whether a tool is available, in this order:

| Layer | Who controls it | What it does |
|---|---|---|
| **1. Mode** | Built into AI-Prowler | Some tools only exist in one mode. Server mode hides developer, unscoped-filesystem, and single-owner tools (§6.2); personal mode hides the one tool that only makes sense with multiple users (§6.2b). Every other tool, including the Job Tracker, Route & Schedule Advisor, and AI Routing families, is available in both modes. |
| **2. Your tool configuration** | The install's owner, in **Settings → 🧩 MCP Tool Configuration** | Turns off whole feature groups (or individual tools) this install doesn't use. Can only remove tools — it can never bring back one that layer 1 hides. |
| **3. Role gates (server mode)** | Built into each tool | A registered tool still checks the caller's role on every call (§6.3, §6.2c) — e.g. who may delete a customer or write outside their personal directory. |

**Seeing the current number.** The MCP Tool Configuration panel shows a live "*N* of *M* tools enabled in *personal/server* mode" line for this install. That line is the authoritative count; this guide deliberately doesn't quote one, because it changes whenever a tool is added or a group is turned off. You can also ask Claude, Muse, or Grok *"What tools do you have available?"* to see exactly what it can call on the current connection.

**Using the MCP Tool Configuration panel.** The panel is folded by default, like the Home page's **🧭 Set up AI-Prowler** panel: its header row always shows a **▸ / ▾** button and the live tool count; click the button to open or close the panel. AI-Prowler remembers whether you left it open. When open, each feature group is one row:

- 🔒 groups (Status & System, Core Knowledge Base & Search, Self-Learning, Email, Agentic Analysis, File & Code Tools) are always on. Click **Details…** to see every tool in the group and what it does.
- Groups with a checkbox (Job Tracker & Routing, SMS & WhatsApp, and on a server HR apps) can be turned on or off. Click the checkbox to turn the whole group on or off, or click **Configure…** to pick individual tools. A dash in the checkbox means some of the group's tools are off.
- **Turning a tool off also turns it off in the Jobs App.** The app can't use a tool you've switched off here — for example, turning off *Send an SMS* removes texting from the app too. Every tool the app uses is marked, and you're asked to confirm before turning one off.
- **The Jobs App is optional.** Turn off the whole **Job Tracker & Routing** group and the Jobs App is switched off: anyone who tries to sign in is told the Jobs App is turned off on this AI-Prowler.
- **Job Tracker & Routing and SMS & WhatsApp start off on a new install** (personal and server mode). Tick the group and click **💾 Save**, then restart AI-Prowler, to turn it on. An install that already uses them — customers or jobs in the jobs database, or an SMS provider set up — keeps them on when it's updated. **↺ Reset to Defaults** turns them off again (until you Save).
- **HR apps (HR Admin + HR Portal)** — *AI-Prowler Server only.* This one checkbox turns on both HR apps and Claude, Muse, or Grok's HR tools together; it starts **off**. Turning it off closes both apps straight away; the HR tools follow after a restart. See *HR Admin and HR Portal* below.
- Ticking and unticking boxes changes nothing until you click **💾 Save (restart required)**; then restart AI-Prowler — tools are registered at startup, so changes don't apply to a running session. **↺ Reset to Defaults** puts every box back to its default — on, except Job Tracker & Routing, SMS & WhatsApp and (on a server) HR apps, which default to off; it too is saved only when you click Save.
- **Save changes only your tool choices.** It writes `tool_config.json` and nothing else, and afterwards checks your other settings files (`config.json`, email, remote access, scheduler and analysis settings) — if any of them came out missing or damaged, it puts the previous copy back. The message after saving confirms *"Saved MCP tool choices only — your other settings were not changed."*

Personal and server mode keep separate settings (saved in `~/.ai-prowler/tool_config.json`), so changing one never alters the other.

#### HR Admin and HR Portal (AI-Prowler Server only)

Two phone/desktop web apps for running HR on an AI-Prowler server. Turn them on in **Settings → 🧩 MCP Tool Configuration → HR apps (HR Admin + HR Portal)**. A personal install doesn't have them.

- **HR Admin** (`/hr_admin/`) — for owners and managers: employee records, onboarding tasks, documents, time off, schedules and compliance. Sign in with your **name and AI-Prowler token** (the same ones you use for the Jobs app).
- **HR Portal** (`/hr_portal/`) — for employees: their own profile, pay, time off, schedule, tasks, trainings, documents, company news and messages. Employees sign in with **their own AI-Prowler name and token** — the ones in the server's **Admin** tab.
- **Sharing the apps** — on the **Small Business** tab, each app's row has **📋 Copy**, **📧 Email to user** and **📱 QR** (scan the code from your screen with a phone to open the app).

**First-time setup.** The first time HR Admin opens, the **Company Setup** wizard asks for your company details, EIN, payroll and tax registrations, and **Work States** — every state plus DC is listed (hover over a code to see the state's name). The states you pick decide which state registrations and tasks are created.

**Changing your setup later** (for example, you start hiring in another state): open **🧭 Company Setup** — the first item in HR Admin's left menu, or the **Company Setup** card at the top of **Settings**, which also lists your current work states. The wizard opens with your saved answers already filled in and your states already ticked, so change only what you need (tick the new state) and tap **Save Changes** — it's on every step, so you don't have to click through the rest. **Settings → Configure Work States** opens the wizard right at the Work States step. **Back** keeps what you typed, and **Cancel** closes it without saving. Your employees and other settings aren't affected.

Then, in HR Admin → **Settings**:
- **Time Off Policy** — paid days off per year, how many unused days carry over, sick days per year (counted separately), and whether a first-year employee gets a share based on their start date.
- **Paid Holidays** — tick the holidays you pay. Holiday dates are worked out for every year automatically (for example Thanksgiving is the 4th Thursday of November; a holiday on a weekend moves to the Friday or Monday). Paid holidays are never taken off anyone's time-off balance.
- **Backups** — see *Where HR data is kept* below.
- **Who clocks in** (under *Time Clock, Privacy & Location*) — see *Clock in / clock out* below.
- **View All Federal & State Forms** — the federal forms (W-4, I-9, W-2, 941, COBRA, FMLA and more) and the state forms for your work states, each with what it's for, when it's due, and links to the official PDF and instructions. For a state with no income tax on wages (such as Florida) it says there's no state withholding form; for a state not in the library yet, get the form from that state's department of revenue.
- **About the Company**, **Announcements** and **Employee Resources** (handbook, policies, forms) — what employees see on the HR Portal's News, Feed, Documents and HR Handbook pages.

**Every server user is an employee.** Everyone in the server's **Admin** tab with status *active* gets an employee record in HR automatically, linked to their AI-Prowler login — it happens each time HR Admin opens the employee list, and the first time they sign in to the HR Portal. Their name, email and cell phone come from the Admin tab (their home address doesn't — it has its own privacy setting there); HR fills in the rest (title, department, start date, work state, pay, usual hours). No onboarding tasks or welcome emails are created for these records, because the person already works for you — use **+** in HR Admin when you hire someone new, which does start onboarding. It doesn't matter which comes first: if the new hire was already added in the Admin tab (so they have one of these automatic records), **+ New Employee** with the same name turns that record into the proper hire — with their start date, onboarding tasks and welcome email — keeping their AI-Prowler login link.
- An existing employee with the same name is linked, never duplicated. If two records have the same name, HR Admin says so and links neither — open the right one and use **🔗 AI-Prowler login** to link it yourself.
- Renamed someone in the Admin tab (for example after a marriage)? Their record is found again by email and re-linked. In HR Admin, change their name on the record — the old name is kept under **Previous names** on their record, so older paperwork still matches them.
- One AI-Prowler login can be linked to one employee; un-linking it signs that employee out of the HR Portal at once.

**Contractors and other non-employees.** Someone who needs the AI-Prowler server but isn't an employee — a contractor, for example — should not be in HR: no onboarding, time off, pay or HR Portal. Open their record in HR Admin → **⋮ Options** → **Not an employee**. Their record leaves HR (its folder is set aside, not erased), their AI-Prowler login keeps working for everything else, they're never added back automatically (even if renamed), and if they open the HR Portal it tells them it's for employees. Deleting a server user's employee record does the same. To undo it, go to **Settings → Server Users Who Aren't Employees** → **Make an employee**. A contractor's W-9 and 1099 stay with your bookkeeping, not in HR.

**Clock in / clock out.** Not every company tracks time, and many track it only for some people. HR Admin → **Settings → Time Clock, Privacy & Location → Who clocks in**:
- **Everyone** (the default) — every employee uses the HR Portal's Time Clock.
- **Only non-exempt employees** — people whose **FLSA Status** is *Non-exempt* clock in; *Exempt* staff don't. The law requires hours records for non-exempt employees — including salaried non-exempt ones — so FLSA status decides, not salary vs. hourly. If someone's FLSA status isn't set, pay type decides (hourly clocks in, salary doesn't); with neither set, they clock in. Set FLSA status on the employee's record (tap **FLSA Status**). Being paid a salary doesn't by itself make someone exempt — check with your payroll provider or accountant if unsure.
- **Nobody** — no one is asked to clock in or out.

To make an exception for one person, open their record and tap **⏱ Clocks in** → **Required**, **Not required**, or **Company rule**. That row always shows whether the person clocks in and why (for example *Yes · non-exempt* or *No · set on their record*).

If someone forgets to clock in or out, HR can do it for them: open their record → **Attendance** → **Clock in now** / **Clock out now**. It's a real entry in the **Clock In/Out Log**, marked *entered by HR*.

Someone who doesn't clock in sees no Clock In button, hours tile or clock-in instructions in the HR Portal — their **Time Clock** page becomes **Running Late / Out**, because **Running Late** and **Out Today** always work. The server also refuses a clock-in from them. If the rule changes while someone is clocked in, they can still clock out, and earlier clock entries stay in HR Admin's **Clock In/Out Log**. When nobody clocks in, the *Track location on Clock In / Clock Out* switch is greyed out, since there's nothing to track.

**Onboarding paperwork.** HR Admin → **Onboarding** shows a folder for each employee with the onboarding forms, and which are done — saved on the server, so every computer sees the same thing.
- **Forms HR fills in** — *Personal Information & Emergency Contact*, *Emergency Contact*, *Direct Deposit* and *Benefits Enrollment* save straight into the employee's record. For direct deposit only the **last 4 digits** of the routing and account numbers are kept.
- **Forms the employee signs** — *W-4*, *state withholding*, *I-9*, and the *pay rate*, *handbook*, *NDA* and *final sign-off* acknowledgements. The employee fills in and signs the official form (there's a link to the blank form); HR then attaches the signed copy (it's saved in the employee's **Onboarding** documents) or ticks that the signed paper copy is on file. The app never asks for a Social Security number. Keep I-9s together, separate from personnel files.
- Saving a form also ticks the matching onboarding task. A form marked done by mistake can be set back (**Mark not done**).

**What employees see in the HR Portal.** Everything comes from HR Admin — there's no sample content:
- **Feed** and **News** — HR's announcements (employees can mark *I've reviewed this* or RSVP to an event; HR Admin shows who did) plus automatic items: new teammates, work anniversaries and birthdays this month, and paid holidays coming up.
- **Schedule → This Week** — their usual weekly hours (set on their record in HR Admin under **Usual hours**), with approved time off and paid holidays filled in.
- **Time off** — days left, used, sick days left and pending requests, worked out from your Time Off Policy, their start date and their approved requests. HR can add or take away paid or sick days for one person: open their record and tap **🏖 PTO this year** (an optional note records why).
- **Tasks** — tasks HR assigned to them (they mark their own done), plus their own personal to-do list.
- **Trainings**, **Documents** and **HR Handbook** — their real assignments and completions, their own files, and the company resources HR published.
- Their photo, reminders and goals are saved on the server, so they're the same on every phone or computer they use.

**Where HR data is kept.** All HR information is kept on the AI-Prowler server — nothing personal stays in the browser. Each employee has their own folder (for example `EMP-00001_Smith_Jane`) holding their record and their files (pay stubs, contracts, tax and benefit papers, photo…), and company-wide information (settings, announcements, resources) is in a `company` folder. Bank details for direct deposit are kept as **the last 4 digits only** — the full routing and account numbers are never sent to or stored on the server. Changes to pay, deposits, tax filings and compliance records are logged (who changed what kind of record — never the values).
- **Backups** — HR Admin → **Settings → Backups**: choose a backup folder (ideally on another drive), turn backups on, pick daily, weekly or monthly and the time, and how many to keep. Each backup is one complete dated copy of all HR data. **Back up now** makes one straight away and shows whether it worked.
- **Protect the drives** — HR data includes pay and personal details, so turn on **BitLocker** (Start → *Manage BitLocker*) for the server's drive and the backup drive, and save the recovery key somewhere safe.
- **Employee status follows the calendar** — a daily job at 5 am moves each employee along: **Pre-Start → Onboarding** on their start date, **Onboarding → Active** once every onboarding task is completed or waived, and **Offboarding → Terminated** the day after their last day.
- **Terminating someone** (HR Admin → Terminations, or asking Claude, Muse, or Grok) starts the full offboarding: the offboarding tasks are created with their deadlines (system access, the state's final-pay rule, COBRA notice, equipment return, exit interview…), and the employee shows as **Offboarding** while they work their notice — they can still use the HR Portal until their last day. After that they're **Terminated** and the HR Portal no longer lets them in (an open session stops working too). If the last day has already passed, they're Terminated straight away.

### 6.2 Tier A Tool Suppression (Server Mode Only)

The following tools are never registered when AI-Prowler runs in server mode (this table mirrors the `_TIER_A_SUPPRESSED` set in `ai_prowler_mcp.py`):

| Category | Suppressed tools |
|---|---|
| Dev / code execution | `run_script`, `run_script_start`, `run_script_status`, `run_script_kill`, `compile_check`, `check_python_import`, `syntax_check`, `lint_check` |
| Host filesystem writes (unscoped) | `list_directory`, `copy_to_backup`, `list_backups`, `restore_backup`, `cleanup_backups`, `cleanup_job_logs`, `reset_write_counter`, `grant_write_access`, `revoke_write_access`, `grant_access`, `revoke_access` — backup/restore/approval-management and access-only-folder tools remain operator/dev-only (access-only folders are a personal-mode feature; see §4 Access-Only Folders). `create_file`, `write_file`, `str_replace_in_file`, `line_replace_in_file`, and `create_directory` are **not** in this list — see §6.2c, they're gated per-call instead of blanket-suppressed. |
| Raw filesystem reads | `read_file_lines`, `grep_documents` |
| Email operator tools | `configure_email`, `send_file`, `list_outlook_accounts` — use personal SMTP credentials or the local Outlook profile, not appropriate for a shared server. `send_learnings_report` is **not** in this category — see the note below. |
| Learnings export/rebuild | `export_learnings_file`, `rebuild_learnings_index` — file-export and destructive index-rebuild operator actions. |
| Agentic analysis task queue | `get_pending_analysis_tasks`, `complete_analysis_task`, `save_analysis_report`, `create_analysis_task`, `list_analysis_tasks`, `delete_analysis_task`, `update_analysis_task`, `queue_single_task`, `get_all_queued_tasks` — the Links & Analysis tab's Common Business AI Analysis / My Custom AI Analyses panels are hidden in server mode's GUI, so the queue these tools drive has no server-mode caller. (Server-mode AI Routing doesn't use this queue — it has its own runner, set up on the Admin tab.) |
| Raw/unscoped SMS inbox | `check_sms_inbox` — reads the local inbox with no per-user filtering (unlike `check_sms_replies`, which uses the per-user-scoped read path). In a multi-user server this would let any employee read every inbound SMS/WhatsApp message company-wide, not just their own. `check_sms_replies` is the server-mode equivalent. |
| Home address (single-owner concept) | `get_home_address` — the Settings tab's Home address field is one street/city/state/zip with no per-user equivalent in a multi-user server; there's no meaningful "whose home address" to resolve for a shared install. `get_route_start_options` is the server-mode, per-crew-member equivalent. |
| File transfer bridge tools | `get_file_download_url`, `get_file_upload_url` — bridge Claude, Muse, or Grok directly to the `/remote/download` and `/remote/upload` HTTP endpoints built into the Remote Control PWA, both of which are themselves personal-mode-only (403 in server mode). |

> **Note:** `send_sms`, `send_email`, `send_alert`, `send_whatsapp`, `send_learnings_report` (user-facing) are **not** suppressed in server mode — they remain available to users via the Tier B role gate.

> **Resolved — `reindex_all` is intentionally open to every role, and that's correct.** Its own source comment confirms this was a deliberate design decision, not an oversight: *"role-based manage_db gate removed — indexing isn't a leak; every tracked path was already admin/owner-created"* (the identical rationale `index_path` uses). It is correctly absent from `_TIER_A_SUPPRESSED`. One clarification worth keeping in mind, though: despite the name pattern suggesting "reindex what changed," `reindex_all`'s default (`purge_first=True`) is a **full wipe-and-rebuild of the entire ChromaDB index** across every tracked directory — the incremental, changed-files-only tool is `update_tracked_directories`, a different tool. Not an access-control concern, just a heavier operation ("may take several minutes") than its name might suggest to someone triggering it casually.

### 6.2b Personal-Mode-Only Tool Suppression (Mirror Gate)

The reverse of §6.2: some tools only make sense once there's more than one registered user, so they're never registered when AI-Prowler runs in **personal** mode:

| Category | Suppressed tools |
|---|---|
| Per-user-scoped SMS replies | `check_sms_replies` — its per-user thread isolation (Mike sees Karen's reply, not Jake's) is meaningless with a single personal-install user. `check_sms_inbox` is the personal-mode equivalent — same underlying data, but with a richer filter set (provider, unread-only, `since_hours=0` for everything ever received) that doesn't need per-user scoping. |

### 6.2c Server-Mode Personal-Directory Write Scoping

Unlike the blanket suppression in §6.2, five write/modify tools use **per-call scoping** instead: `create_file`, `write_file`, `str_replace_in_file`, `line_replace_in_file`, and `create_directory`.

**Personal mode:** fully unrestricted — identical to every prior version. No change.

**Server mode:** every call from every role is checked against `_check_personal_write_scope()`:

| Situation | Result |
|---|---|
| User has a personal (private) directory configured and the target path resolves inside it | ✅ Allowed |
| User has a personal directory configured but the target path is anywhere else — a shared scope, another user's private directory, the job tracker, etc. | 🚫 Denied — "outside your personal directory" |
| User does not have a personal directory configured at all (`private_collection_enabled=False`, or no folder was ever set up in the Admin tab) | 🚫 Denied for **any** path — read-only until an admin sets one up |

This means a field crew member with a personal directory can save their own notes, drafts, or working files there — but cannot touch the job tracker database, another employee's private folder, or any shared company document. A field crew member with no personal directory configured has no write access anywhere, full stop; they can still use every read tool (`search_documents`, `read_document`, etc.).

**Setup:** a personal directory is the same private-collection folder created via the Admin tab's "Set Up Private Folder" flow when adding or editing a user (§6 — Admin Tab). If `Private collection` isn't ticked for a user, or the folder was never created, that user gets no server-mode write access under this feature.

This scoping applies independently of Tier B role gating (§6.3) — even an owner or manager writing from a *server-mode session* is scoped to their own personal directory by this check. (Owners/managers still have unrestricted write access from a *personal-mode* install, e.g. their own PC.)

### 6.3 Role-Based Tool Access in Server Mode (Tier B)

| Tool group | owner | manager | staff | field_crew |
|---|---|---|---|---|
| RAG Search (search, overview, list docs, etc.) | ✅ | ✅ | ✅ | ✅ |
| Field Service (weather, geocode, route, maps, job tracker) | ✅ | ✅ | ✅ | ✅ |
| SMS & WhatsApp (send_sms, send_whatsapp, check_sms_replies, check_whatsapp_replies) | ✅ | ✅ | ✅ | ✅ |
| Self-Learning (record, check, list, update, delete, stats) | ✅ | ✅ | ✅ | ✅ |
| `check_ai_prowler_status`, `how_to_use_ai_prowler` | ✅ | ✅ | ✅ | ✅ |
| `check_tools_status` (field-service health) | ✅ | ✅ | ✅ | ✅ |
| `send_email`, `send_alert` | ✅ | ✅ | ✅ | ✅ |
| `send_learnings_report` | ✅ | ✅ | ✅ | ✅ |
| `index_path`, `update_tracked_directories`, `reindex_file`, `reindex_directory` | ✅ | ✅ | ✅ | ✅ |
| `list_tracked_directories` | ✅ | ✅ | ✅ | ✅ |
| `untrack_directory` | ✅ | ✅ | ⚠️ own dir only¹ | ⚠️ own dir only¹ |

¹ **Two-tier gate for `untrack_directory`:** any role may untrack a path inside their OWN personal directory (no admin flag needed). Outside it — a shared scope, another user's private folder, or general company-wide tracked state — requires the owner, or a manager/staff member with delegated admin rights ("Can manage users" in the Admin tab). A plain manager or staff member without that flag is denied outside their own directory; the flag, not the role name, is what actually grants it.

**Indexing is open to every role.** `index_path`, `update_tracked_directories`, and `reindex_*` have no owner/manager gate — indexing was never the actual confidentiality boundary, since every role's *search* results are already scoped independently (§9 — Scopes). Any authenticated user can trigger indexing on any already-tracked path; a path only becomes tracked in the first place through an owner/manager action in the Admin tab or Index Docs tab, so this doesn't open up arbitrary filesystem access. `untrack_directory` uses the two-tier gate described above — own personal directory (any role) vs. everywhere else (owner or delegated admin). `list_tracked_directories` is gated by **scope**, not role: it never reveals anything beyond shared + the caller's own assigned scopes + their own private folder, so every role sees the list, filtered to what they can already reach.

**`reindex_file` / `reindex_directory` / `reindex_all` — single unified index.** These purge and rebuild against the one shared ChromaDB collection every install uses — there's no separate physical collection per scope to sweep. Each chunk is retagged with its current scope during the rebuild (see §9), so a reindex always reflects whatever scope assignment is in effect at that moment. `reindex_all` calls `reindex_directory()` once per tracked directory and inherits this automatically. Personal mode is unaffected either way — always the single database.

### 6.4 Complete Tool Reference Table

---

#### Agentic RAG — Knowledge Base Search

| Tool | What It Does | Mode |
|---|---|---|
| `how_to_use_ai_prowler` | Returns the recommended workflow and tool sequence. Claude, Muse, or Grok calls this automatically at the start of research sessions. Identical guide body in every mode and role — see its entry under "Status & System" below for why. | Personal + Server |
| `get_knowledge_base_overview` | High-level summary: document count, file types, chunk count, database location, tracked directories. Start here before any research task. | Personal + Server |
| `search_documents` | Primary retrieval tool. Semantic vector search returning raw document chunks with source metadata and similarity scores. | Personal + Server |
| `multi_query_search` | Runs 2–6 search queries in parallel and returns deduplicated results ranked by best similarity. More efficient than multiple `search_documents` calls. | Personal + Server |
| `search_within_directory` | Semantic search restricted to a single directory/case/project — use when you need to guarantee results come only from one folder tree, not the whole index. Tries an exact `parent_directory` match first, falling back to a broader search filtered by `directory_chain`/`filepath`. **Server mode:** the directory filter stacks on top of the caller's scope-based access — a staff/field_crew query never returns chunks tagged with a scope outside their own private/assigned/shared set, regardless of what directory is requested. This is the tool the private-directory isolation regression suite (`test_owner_dir_isolation.py`) is built around — a manager cannot read the owner's private content just by naming the directory. | Personal + Server |
| `expand_search_result` | Fetches chunks immediately before and after a specific result chunk. Use when a result is cut off at a boundary and you need more context. | Personal + Server |
| `read_document` | Reads a full document in sequential chunk order. Best for contracts, manuals, and reports where you need the whole text. | Personal + Server |
| `list_indexed_documents` | Browses all indexed documents grouped by file type, with chunk counts. | Personal + Server |
| `list_indexed_directories` | Directory tree of all indexed content with document counts per folder. | Personal + Server |
| `grep_documents` | Exact text or regex search across tracked files with real line numbers. Use when semantic search returns irrelevant results for code or structured text. | Personal |
| `read_file_lines` | Reads an exact line range from a file. Pair with `grep_documents` — grep locates, this extracts. | Personal |

---

#### Knowledge Base Management

| Tool | What It Does | Mode |
|---|---|---|
| `index_path` | Indexes all supported documents in a folder (or a single file) and optionally adds the path to the auto-update tracking list. | Personal + Server |
| `update_tracked_directories` | Re-scans all tracked paths and re-indexes only new or changed files. | Personal + Server |
| `list_tracked_directories` | Lists every tracked path. Personal mode shows two sections: **📁 Indexed directories (in ChromaDB)** and **📂 Access-only folders (readable, not indexed)**. Each entry shows **[W]** (writable) or **[R]** (read-only). **Server mode:** indexed directories only (no access-only section — that feature is personal-only); gated by scope, not role — every role may call it; filtered to paths within the caller's own accessible scopes. | Personal + Server |
| `untrack_directory` | Removes a path from the tracking list and deletes all its chunks from ChromaDB. Destructive — chunks are gone until re-indexed. | Personal + Server |
| `get_database_stats` | Chunk count, unique document count, and file-type breakdown for the ChromaDB index. Personal mode always covers the whole database. **Server mode:** scoped to the caller's own accessible scopes — every role, including owner, sees only their own private, assigned scope, and shared totals (§9 — no role gets a company-wide-total exception). | Personal + Server |

---

#### Indexing — Reindex Tools

| Tool | What It Does | Mode |
|---|---|---|
| `reindex_file` | Purges and rebuilds the ChromaDB index for a single file. Call after finishing edits to a file. | Personal + Server |
| `reindex_directory` | Fully purges and rebuilds the index for one tracked directory. More thorough than `reindex_file`. | Personal + Server |
| `reindex_all` | Nuclear option — wipes and rebuilds the entire ChromaDB index from scratch across all tracked directories. | Personal |
| `cancel_indexing` | Stops a running index job cleanly — finishes the current file, then halts. | Personal + Server |
| `indexing_status` | Shows whether an index/reindex is running and its current progress. | Personal + Server |

---

#### Self-Learning Knowledge Base

| Tool | What It Does | Mode |
|---|---|---|
| `record_learning` | Saves a new lesson, fact, client preference, or business insight. Instantly indexed. In server mode the recording employee's name is automatically stamped. | Personal + Server |
| `search_learnings` | Semantic search of the learning store. Claude, Muse, or Grok calls this proactively before answering questions so personal knowledge overrides generic responses. | Personal + Server |
| `list_learnings` | Browses learnings by recency with exact-match filters on category, status, or tag. | Personal + Server |
| `get_learning` | Returns one learning's full record (title, content, context, category, outcome, tags, …) as JSON — read-only. The Remote Control app's Learn tab uses it to fill its Edit form. | Personal + Server |
| `update_learning` | Edits fields of an existing learning — content, confidence, outcome, status, tags. **Server mode ownership:** each employee may only edit learnings they personally recorded; managers may edit any employee's learning but never the owner's; the owner may edit anything. Reading/searching learnings stays fully shared (§ above) — only modification is ownership-gated. | Personal + Server |
| `delete_learning` | Permanently removes a learning from both JSON and ChromaDB. Consider archiving instead. **Same server-mode ownership rules as `update_learning`.** | Personal + Server |
| `get_learning_stats` | Summary statistics: totals by category, source, outcome, and status. | Personal + Server |
| `get_learnings_report` | Returns learnings as formatted text in-conversation (summary, full detail, or titles-only). Works on mobile. | Personal + Server |
| `rebuild_learnings_index` | Rebuilds the ChromaDB learnings index from the JSON data file. Fixes index/data mismatches. | Personal |
| `export_learnings_file` | Exports learnings to a file (JSON pack or spreadsheet). | Personal |
| `send_learnings_report` | Emails a formatted HTML learnings report in one step. Available in server mode with category, date range, and tag filters. | Personal + Server |

---

#### Small Business Action Tools

| Tool | What It Does | Mode |
|---|---|---|
| `get_weather` | Current conditions and multi-day forecast. Uses Open-Meteo and Nominatim — free, no API key. Rain probability ≥ 50% is flagged. | Personal + Server |
| `geocode_address` | Converts a street address to GPS coordinates via Nominatim / OpenStreetMap — free, no API key. | Personal + Server |
| `get_home_address` | **New.** Returns the owner's configured home/business address (Street, City, State, ZIP) from Settings → Home address, formatted as a single string — resolves "my address," "the shop," "home" before a routing or geocoding call, most commonly right before `optimize_route()` or `geocode_address()`. | Personal only — see §6.2. The server-mode, per-crew-member equivalent is `get_route_start_options` (§6.4 → Route & Schedule Advisor). |
| `optimize_route` | Solves the Traveling Salesman Problem for a list of job stops using real street routing via OSRM. Returns stops in optimal order with estimated arrival times. | Personal + Server |
| `build_maps_url` | Generates a tap-to-navigate Google Maps (or Apple Maps) URL with all stops pre-loaded in optimized order. Splits into multiple leg links for routes over 9 stops. | Personal + Server |
| `read_job_spreadsheet` | Reads job data from AI-Prowler's job tracker database — the same data the Jobs PWA App's Board/Jobs/Database tabs show. Supports date filtering to show today's or a specific day's jobs. **Server mode, `Jobs_Schedule` sheet only:** field_crew see only rows where `Crew / Technician` matches their own name — the same filtering the Jobs PWA App applies to their view; owner, manager and staff see every row. `field_crew` has no access at all to the `Settings`, `Services_Pricing`, `Quotes`, or `Invoices` sheets. Doesn't apply to the `Customers` sheet (stays fully readable for `send_email`/`send_sms` lookups) or to anyone on their own per-employee database file — those rows already belong to them by construction. | Personal + Server |
| `update_job_spreadsheet` | Updates a row in the job tracker after a job is completed — status, invoice number, duration, actual amount, etc. — the same edit a person could make from the Jobs PWA App's Database tab or an edit form. Auto-backs up the database before writing. **Server mode:** rejected if the row isn't assigned to you (`Jobs_Schedule`, `TimeLog`, `Route_Planner`); `field_crew` is locked out of `Settings` and `Services_Pricing` entirely, and out of pricing/status master fields on `Customers` (Frequency, Standard Quote, Discount, Net Price, Status, Total Jobs Completed, Lifetime Revenue) even for their own customers. Owner, manager, staff and anyone on their own per-employee file are unrestricted. | Personal + Server |
| `get_working_days` | Returns the **Working Days** setting (e.g. `Mon,Tue,Wed,Thu,Fri`) — the days multi-day jobs are worked and routed. Read-only and open to every role, so field crew (who can't read the Settings sheet) get the same working days on their Calendar as the office. See **Section 10 → Multi-day jobs and Working Days**. | Personal + Server (all roles) |
| `get_sheet_columns` | **New.** Returns a sheet's full ordered column list, plus any dropdown-backed columns (e.g. Customers' `Frequency`), so an edit form can show every field a row could have — including ones empty on that particular row — rather than only the fields already populated. Powers the Jobs PWA's row-edit form. | Personal + Server |
| `check_tools_status` | Field-service health check. Reports which action tools are ready to use and which need configuration (SMTP, database path, routing APIs). **Server mode:** the dev-tools/file-editing section reflects the caller's actual availability — most dev tools (code execution, backups, `list_directory`) are unavailable in server mode; the write/edit tools show a live check of whether the caller currently has a personal directory configured. | Personal + Server |

---

#### Job Tracker — Record Creation

Before these tools existed, `update_job_spreadsheet()` could only edit an existing row — there was no way to add a brand-new customer, job, quote, invoice, setting, or pricing entry at all. Each of these always appends a new row and auto-assigns the next ID in that sheet's own numbering (`CUST-####`, `JOB-####`, `QTE-####`, `INV-####`); none of them ever edits an existing row.

| Tool | What It Does | Mode |
|---|---|---|
| `create_job` | Appends a new row to `Jobs_Schedule`, auto-assigning the next `JOB-####`. **Requires an existing `CustomerID`** — a job can no longer be created for a customer that doesn't exist yet (`create_customer` first, then pass the `CustomerID` it returns). Unlike `update_job_spreadsheet`, creation is not restricted to a crew member's own existing jobs, since a brand-new row has no prior owner to check against. | Personal + Server (all roles) |
| `create_customer` | Appends a new row to `Customers`, auto-assigning the next `CUST-####`. | Personal + Server (all roles) |
| `create_quote` | Appends a new row to `Quotes`, auto-assigning the next `QTE-####`. Does not compute totals/tax/discount — pass the amounts you want written directly. | Personal + Server (all roles) |
| `create_invoice` | Creates an invoice for a job and links it back (writes the new `InvoiceID` onto the job's `Jobs_Schedule` row) — the missing step between a priced job and `email_invoice()`/`text_invoice()`, neither of which can create one. Any price/description override you pass is written back onto the job row too, so the job listing stays in sync. Refuses to run if the job is already invoiced (one invoice per job). **Server mode:** a restricted role may only invoice jobs assigned to them; owner/manager unrestricted. | Personal + Server |
| `create_setting` | Appends a new key/value row to `Settings`. Fails if the key already exists (use `update_job_spreadsheet` to change an existing key). | **Server: staff/manager/owner only** — company-wide configuration, not per-job data a field_crew member would create. Personal: unrestricted. |
| `create_service_pricing` | Appends a new priced service line to `Services_Pricing` (e.g. "Window Cleaning — $150 flat"). The `Service Code` you supply is the row's own key and must be unique. | **Server: staff/manager/owner only.** Personal: unrestricted. |

---

#### Job Tracker — Record Deletion

By design, almost nothing in AI-Prowler deletes a row — the standard pattern is to retire a record (e.g. set a customer's Status to Inactive) rather than remove it, so history stays intact. These six tools are the deliberate, narrow exceptions, each gated by a two-step confirmation (`confirm=True` required; a first, unconfirmed call only returns a preview of what would be deleted and changes nothing) and each preceded by an automatic safety backup of the whole database.

| Tool | What It Does | Mode |
|---|---|---|
| `delete_customer` | Permanently deletes a customer **and every row that references them** (Jobs, Invoices, Quotes, TimeLog entries, route stops). Requires the customer to already be Status = Inactive — there is no way to delete an Active customer in one call. | **Server: staff/manager/owner only.** Personal: unrestricted. |
| `delete_job` | Permanently deletes a job. Requires Job Status = Cancelled. A Completed job can **never** be deleted through this tool, under any confirm value — it's linked to invoicing/accounting history and must stay in the database permanently. Cascades to any TimeLog entries and route-stop rows the cancelled job had. | **Server: staff/manager/owner only.** Personal: unrestricted. |
| `delete_quote` | Permanently deletes a quote, any status (not just Declined). No cascade — nothing else references a quote by foreign key. | **Server: staff/manager/owner only.** Personal: unrestricted. |
| `delete_service_pricing` | Permanently deletes a Services_Pricing entry. No cascade — Jobs and Invoices always copy their own Service Type/amount at creation time rather than linking back to the price list. | **Server: staff/manager/owner only.** Personal: unrestricted. |
| `delete_route` | Permanently deletes an **entire day's route** (every stop for a given date), not one stop at a time — the whole-route sibling of `delete_route_stop`. | Personal + Server, crew-scoped: a field_crew member may delete a day's route only if every stop on it is their own. |
| `delete_route_stop` | Permanently deletes a single `Route_Planner` stop. No status pre-condition, no cascade. | Personal + Server, crew-scoped: a field_crew member may delete a stop only on their own route. |

---

#### Job Tracker — Billing Variants, Reminders & Mileage

| Tool | What It Does | Mode |
|---|---|---|
| `text_invoice` | Sends an SMS notification for an invoice — amount due, plus a payment link if enabled in Settings → Small Business. Text alone can't carry the actual formatted invoice document; use `email_invoice` for that. Mutually exclusive with `email_invoice` by design — bill through one channel, not both. | Personal + Server |
| `email_receipt` | Emails a payment-received receipt (not an invoice) after a customer pays by cash, check, or other offline method — a thank-you / proof-of-payment, not a bill. | Personal + Server |
| `text_receipt` | Same as `email_receipt`, sent via SMS. | Personal + Server |
| `find_stale_customers` | Lists Active customers who haven't had a Completed job in `days_threshold` days (default reads Settings → "Stale Customer Reminder Days," 60 if never set) — or have never had one at all — most-overdue first. "Last serviced" comes from actual job history, not the Customers sheet's hand-maintained field. Powers Reports → Customer Reminders. | **Server: owner only.** Personal: unrestricted. |
| `send_customer_reminders` | Sends a check-in/reminder message to specific customers found by `find_stale_customers` — by email or SMS, using each customer's own contact info on file. Nothing messages a customer automatically; this is the explicit, reviewed send step. Greets by the actual person (First Name / On-Site Contact), not the account name. | **Server: owner only.** Personal: unrestricted. |
| `get_daily_mileage` | Estimates miles driven on a given day, computed from real GPS points already captured at clock-in/clock-out (not continuous background tracking — a browser PWA can't do that reliably, especially iOS Safari). Sums OSRM driving distance between consecutive clock-out → clock-in GPS pairs; legs with a missing GPS point are skipped and listed separately rather than guessed. | Personal + Server |

---

#### SMS & WhatsApp Tools

These tools enable two-way SMS and WhatsApp communication between field crew, registered server users, and customers from the job tracker's Customers records (the same list shown in the Jobs PWA App). `check_sms_inbox` and `check_sms_replies` are mode-exclusive — see §6.2 and §6.2b — because they answer the same underlying question ("what's come in?") with different scoping that only makes sense in one mode or the other.

| Tool | What It Does | Mode |
|---|---|---|
| `check_sms_configured` | **New.** Lightweight check for whether an SMS provider (Twilio, SignalWire, or Vonage) is configured — returns exactly `"✅ SMS configured"` or `"❌ SMS not configured"`. Backs the Jobs PWA's SMS-dependent buttons, same pattern as `check_email_configured` (§ Email Tools). | Personal + Server |
| `send_sms` | Sends an SMS message to a registered user (from users.json) or a job tracker Customer record (the same Customers list shown in the Jobs PWA App). If neither matches, falls back to your own saved personal contacts (`save_contact`) — server mode: your own contacts only, never a coworker's. Provider-abstracted: works with Twilio, SignalWire, or Vonage. **The old email-to-SMS carrier-gateway fallback (vtext.com, txt.att.net, etc.) has been removed** — see the note below. In server mode, the sending employee's identity is stamped in the thread log. | Personal + Server |
| `send_whatsapp` | Sends a WhatsApp message via the Twilio WhatsApp Business API. Same three-tier recipient lookup as `send_sms` (registered users → job tracker Customer records → your own saved contacts). Works worldwide — no carrier gateway issues. Server mode: sender identity stamped in the thread log, same as `send_sms`. | Personal + Server |
| `check_sms_inbox` | Reads the entire local SMS/WhatsApp inbox (populated in real time via the `/sms-webhook` and `/whatsapp-webhook` endpoints) — every inbound message from any sender, not just people you've texted. Filterable by provider and unread-only; `since_hours=0` returns everything ever received. Personal mode only — it has no per-user scoping, so it's suppressed in server mode to prevent one employee from reading everyone's messages. | Personal |
| `check_sms_replies` | Checks for inbound SMS replies, scoped to threads **you personally sent** — in server mode, Mike sees only Karen's reply, not Jake's or Bob's. Server mode only — with a single personal-install user this attribution is meaningless, so `check_sms_inbox` covers personal mode instead. | Server |
| `check_whatsapp_replies` | Checks for inbound WhatsApp messages. **Server mode:** scoped to threads you personally sent — same per-user isolation as `check_sms_replies` (it no longer delegates to `check_sms_inbox` internally, which would have bypassed that scoping entirely). | Personal + Server |
| `list_sms_consents` | Lists SMS opt-in records captured via the `/consent-signup` website widget, kept in sync with STOP/START replies. Filterable to currently-opted-in only, or a time window. See §11 → SMS Consent Capture. | Personal + Server |
| `delete_sms_consent` | Permanently deletes a consent record by phone number or record ID — for CCPA/GDPR-style removal requests. Distinct from an opt-out (STOP), which marks a record inactive but keeps it. | Personal + Server |

**SMS Setup (Personal Mode):** Tell Claude your Twilio (or SignalWire/Vonage) Account SID, Auth Token, and from-number. Claude calls `configure_sms` once and credentials are saved. For inbound messages, configure your Twilio phone number's webhook URL to point to `https://your-tunnel-domain/sms-webhook`.

**SMS Setup (Server Mode):** Configure SMS credentials directly in the AI-Prowler GUI under **Settings → SMS Configuration**. The webhook endpoints `/sms-webhook`, `/whatsapp-webhook`, and `/consent-signup` are registered automatically when the HTTP server starts.

**SMS Recipients:** Recipients are resolved by name or partial match against:
1. Registered server users in `users.json`
2. Customers in the Customers sheet / `Customers` table (by Phone)

> **The free email-to-SMS carrier-gateway approach has been removed.** Earlier revisions of this guide (and the `Customers` sheet's `Cell Carrier`/`SMS Gateway` columns, described below) documented `send_sms` as able to fall back to a carrier's email-to-SMS gateway (e.g. `@vtext.com`, `@mypixmessages.com`, `@txt.att.net`). That path is gone — those gateways are being shut down industry-wide (AT&T's is already gone; Verizon's is mid-shutdown through 2027) and were unreliable even while active (spam filtering, no delivery confirmation, no two-way replies). `send_sms` now requires a real SMS provider — Twilio, SignalWire, or Vonage — configured in Settings → SMS / Text Messaging. The `Cell Carrier` and `SMS Gateway` columns on the Customers sheet are vestigial as far as `send_sms` is concerned; they are not read by the current implementation.

---

#### Email Tools

Most email tools are personal-mode only, but `send_email` and `send_alert` are also available in server mode to all roles. See Section 6.5 for SMTP setup instructions.

| Tool | What It Does | Mode |
|---|---|---|
| `configure_email` | Saves SMTP credentials so Claude, Muse, or Grok can send email. Auto-detects provider from email domain. Called once; credentials persist. | Personal only |
| `check_email_configured` | **New.** Lightweight check for whether SMTP email is configured — returns exactly `"✅ Email configured"` or `"❌ Email not configured"`, safe for exact-match parsing. Backs the Jobs PWA's Email Invoice button (enabled/dimmed before the user taps it). | Personal + Server |
| `send_email` | Sends a plain-text email. Optional file attachment from any tracked directory. In server mode uses the server's SMTP config with employee Reply-To header. Resolves a name-only `to` in order: Customers sheet, registered users (`users.json`), then your own saved personal contacts (`save_contact`) as a final fallback. The Customers-sheet lookup reads the one shared job database — same behavior in both modes. | Personal + Server (all roles) |
| `send_alert` | Fires a quick one-line alert email — subject auto-generated from the message. Great for voice-commanded notifications from the field. | Personal + Server (all roles) |
| `send_file` | Sends any tracked file as an email attachment. Auto-generates subject from filename if not specified. | Personal only |
| `send_learnings_report` | Emails a formatted HTML learnings report. Available in server mode with expanded filters. | Personal + Server |
| `list_outlook_accounts` | **New.** Lists every email account configured in the local Microsoft Outlook installation, so `send_email`'s optional `from_account` argument can target a specific one (e.g. "email the Torres invoice from my Yahoo account, not my work email") instead of always sending from the default. Only meaningful when the Outlook backend is active. | Personal only |

> Both SMS and email now have a matching "is this configured?" pre-check tool — `check_sms_configured` (§ SMS & WhatsApp Tools) and `check_email_configured` above — both return the same `"✅ … configured"` / `"❌ … not configured"` shape so the Jobs PWA can enable or dim a send button before the user taps it, rather than letting them tap something that's guaranteed to fail.

---

#### Write Zone Management (Personal Installs Only)

| Tool | What It Does | Mode |
|---|---|---|
| `grant_write_access` | Adds a directory to the write-zone allowlist so Claude, Muse, or Grok can create and edit files there. The directory must already be in the read allowlist. | Personal |
| `revoke_write_access` | Removes a directory from the write allowlist. Read access is unaffected. | Personal |
| `grant_access` | Adds a **folder** (always including its sub-folders) to the access-only list — **readable** by Claude, Muse, or Grok, never indexed. Refuses files, duplicates, and folders already covered by an access-only or indexed folder; a folder containing access-only folders folds them in. Does not grant write access (use `grant_write_access` for that, which accepts access-only folders). Hidden and refused on a server. | Personal |
| `revoke_access` | Removes a directory from the access-only list; Claude, Muse, or Grok can no longer read it through that list. Hidden and refused on a server. | Personal |

---

#### Code Tools — Write-Side (Personal + Server, Server Scoped to Own Directory)

All write operations are protected by four independent layers: read allowlist, writable allowlist, hard blocklist, and per-session circuit breaker. In server mode, a fifth layer applies to `create_file`, `write_file`, `str_replace_in_file`, `line_replace_in_file`, and `create_directory`: writes are scoped to the caller's own personal directory only, and denied entirely for users without one configured (see §6.2b). The remaining dev/backup-management tools (`copy_to_backup`, `restore_backup`, `list_backups`, `list_directory`, `reset_write_counter`, `grant_write_access`, `revoke_write_access`, `grant_access`, `revoke_access`, `cleanup_backups`, `cleanup_job_logs`) stay fully suppressed in server mode (§6.2).

| Tool | What It Does | Mode |
|---|---|---|
| `create_file` | Creates a new file. Fails if the file already exists. **Server mode:** scoped to the caller's own personal directory only — denied entirely for users without one configured. | Personal + Server (own dir) |
| `write_file` | Overwrites an existing file. Auto-backs up to `.bakN` before writing. **Server mode:** scoped to the caller's own personal directory only. | Personal + Server (own dir) |
| `str_replace_in_file` | Surgical in-place edit: replaces one unique occurrence of `old_str` with `new_str`. Requires exact whitespace match including indentation. Use `dry_run=True` to preview the diff before committing. 1000× cheaper than a full file rewrite for large files. **Server mode:** scoped to the caller's own personal directory only. | Personal + Server (own dir) |
| `line_replace_in_file` | Replaces a range of lines by line number. Zero text-matching ambiguity — works on any file regardless of encoding or Unicode. Always pair with `read_file_lines` first to confirm exact line numbers. Last resort when `str_replace_in_file` fails (e.g. whitespace or Unicode differences make an exact match impractical). **Server mode:** scoped to the caller's own personal directory only. | Personal + Server (own dir) |
| `create_directory` | Creates a directory and any missing parents. Idempotent. **Server mode:** scoped to the caller's own personal directory only. | Personal + Server (own dir) |
| `list_directory` | Lists the immediate contents of a directory: files, subdirectories, and backups. Read-only. | Personal |
| `copy_to_backup` | Takes a manual snapshot of a file as `.bakN` without modifying the original. | Personal |
| `list_backups` | Lists all backups for a given file with timestamps and sizes. | Personal |
| `restore_backup` | Overwrites the active file with the contents of the specified backup. | Personal |
| `cleanup_backups` | Finds and optionally deletes backup files. Always run with `dry_run=True` first to preview. | Personal |
| `cleanup_job_logs` | Deletes old `run_script_start` job files from `~/.ai-prowler/jobs/`. **Note:** as of Oct 2026, files older than 48 hours are auto-deleted on every server startup — this tool is now only useful for manual cleanup of newer files. Always run with `dry_run=True` first. | Personal |
| `reset_write_counter` | Resets the per-session 20-write circuit breaker so large editing sessions can continue without restarting the server. | Personal |
| `list_writable_directories` | Personal mode / server-mode owner+manager: full write-zone and read-zone allowlist. Server-mode staff/field_crew: only their own personal directory's read/write status — not the company-wide list. | Personal + Server |

**File Edit Escalation Order:** Use `str_replace_in_file` first (exact match). If it fails due to whitespace, Unicode characters, or complex indentation making an exact match impractical, use `line_replace_in_file` with `read_file_lines` to confirm line numbers first.

---

#### Dev Tools (Personal Installs Only)

Tools for code verification, comparison, and script execution. Suppressed in server mode.

**Verification tools (check code without running it):**

| Tool | What It Does | Mode |
|---|---|---|
| `compile_check` | Byte-compiles a Python file to catch syntax errors. Equivalent to `python -m py_compile`. | Personal |
| `check_python_import` | Imports a Python module in a separate process to catch load-time errors that `compile_check` misses (NameError, ImportError, bad module-level references). | Personal |
| `syntax_check` | Multi-language syntax checker. Supports Python, JavaScript, TypeScript, C, C++, Go, Java, Perl, Ruby, PHP, Bash, Verilog, SystemVerilog, VHDL. | Personal |
| `lint_check` | Multi-language linter — catches unused imports, undefined names, and style issues. Uses pyflakes (Python), tsc (TypeScript), go vet (Go), ghdl -a (VHDL). | Personal |
| `diff_files` | **New.** Compares two text files and returns a unified diff Claude, Muse, or Grok can read directly — verify what `str_replace_in_file` just changed, compare a file to an older `.bakN` backup, or confirm a fix before running tests. Both files must be under a tracked directory (or be `.bakN` backups of one). | Personal |

**Execution tools (actually run scripts and programs):**

| Tool | What It Does | Mode |
|---|---|---|
| `run_script` | Runs a script synchronously and returns combined stdout+stderr. Previews the first 50 lines of the script before executing. Best for short scripts under ~60 seconds. Never elevated. | Personal |
| `run_script_start` | Launches a script as a background job and returns a `job_id` immediately. Also previews script content before launching. Use for long-running tasks (full test suites, builds) that would time out the MCP connection. Default timeout: 30 minutes. | Personal |
| `run_script_status` | Checks the status of a background job and returns a tail of its log output. Status values: `running`, `completed`, `failed`, `timeout`, `killed`. Call repeatedly to poll progress. | Personal |
| `run_script_kill` | Terminates a running background job and all its child processes. Updates the manifest to `killed` and returns the final log tail. | Personal |

> **Tip:** Use `run_script` for quick one-off executions. Use `run_script_start` + `run_script_status` for anything that takes more than a minute — including the full test suite. Pass pytest filters via the `args` parameter: `tests/test_sms.py -v --tb=short`.

---

#### Status & System

Two different status tools — know which to call:

- **RAG broken?** → `check_ai_prowler_status`
- **Email/SMS/routing not working?** → `check_tools_status`

| Tool | What It Does | Mode |
|---|---|---|
| `check_ai_prowler_status` | RAG engine health check. Verifies ChromaDB connectivity, embedding model status, and chunk count — always shown to every role, a basic health signal. The tracked-paths list (real folder/file names) is still shown only to owner/manager in server mode; staff/field_crew still get the health check, just without that section. (Note: this is a role gate, unlike `list_tracked_directories`, which is scope-gated — the two tools' tracked-paths sections are gated differently.) | Personal + Server |
| `how_to_use_ai_prowler` | Returns the recommended Agentic RAG workflow and tool-call sequence. Call at the start of any new research session. **The main guide is identical across every mode and role** — deliberate, so a conversation with two connectors attached (e.g. a personal install and a company server) can't have Claude, Muse, or Grok conflate "not available on this connector" with "doesn't exist at all." Server-mode caveats (dev tools, code-aware retrieval, file-editing scoping, agentic analysis) are written inline in the guide text itself, present for every reader. Only the "THIS CONNECTION" footer varies — computed live per caller, including their personal-directory write status. | Personal + Server |

---

#### Contractor & Job Tracker Tools (Personal + Server)

| Tool | What It Does | Mode |
|---|---|---|
| `log_time_entry` | Clocks in or out for a job — the same action available from the Jobs PWA App's Clock screen. Records start/stop times and computes duration in the TimeLog sheet of the job tracker database. Requires an exact, unambiguous job match — an identifier matching zero or multiple jobs is rejected rather than guessed. **Server mode:** rejected outright if the job isn't assigned to you (`Crew / Technician` column) — checked before any TimeLog entry is written, not just stamped afterward. Owner, manager, staff and anyone on their own per-employee database file are unrestricted. The `Crew / Technician` field is then stamped with the caller's own name, and a new `Logged By (User ID)` column tracks ownership — you can only clock out an entry you personally opened, and one teammate's open shift never blocks another's on the same job. | Personal + Server |
| `email_invoice` | Reads the Invoices sheet and emails a branded HTML invoice directly to the customer — the same invoice the Jobs PWA App can email from its own Invoices screen. **Server mode:** rejected if the invoice's job isn't assigned to you (cross-referenced against `Jobs_Schedule`'s `Crew / Technician` column, since Invoices has no crew column of its own). Owner, manager, staff and anyone on their own per-employee database file are unrestricted. | Personal + Server |
| `schedule_next_recurring_job` | Auto-creates the next recurring job entry (weekly, bi-weekly, monthly, quarterly) after a job is marked complete. Requires an exact, unambiguous job match — a `job_identifier` matching zero or multiple jobs is rejected with a candidate list rather than guessed. Accepts a `when` argument in **both** modes — `"today"` (default if omitted, in both modes), `"tomorrow"`, `"yesterday"`, `"this_week"`, `"next_week"`, `"any"` (no date restriction), or an explicit `"YYYY-MM-DD"` — to scope which jobs are searched by date. **Server mode:** field_crew only search jobs assigned to them (`Crew / Technician` matches their own name); owner, manager and staff search every crew's jobs. | Personal + Server |
| `get_ar_aging_report` | Generates an Accounts Receivable aging report from the Invoices sheet, broken into Current / 1–30 / 31–60 / 61–90 / 90+ day buckets. | Personal + Server |
| `save_contact` | Saves or updates a personal contact (phone and/or email) so future `send_sms` / `send_email` calls can resolve them by name. Merges with any existing saved fields rather than overwriting. **Server mode:** each user gets their own separate file (`contacts_cache_<user_id>.json`) — genuinely private, not a shared company address book; the confirmation message shows exactly which file it saved to. | Personal + Server |
| `get_sms_thread` | Returns the full two-way conversation thread with a contact — both outbound and inbound messages in chronological order. **Server mode:** only shown if you personally last sent to this contact — threads are keyed by phone number company-wide, so this prevents seeing another employee's conversation just by naming their contact. | Personal + Server |
| `list_sms_contacts_with_replies` | Lists all contacts you've texted recently, with unread inbound reply counts highlighted. **Server mode:** scoped to threads you personally sent — same per-user isolation as `check_sms_replies`. A brand-new user with no thread history yet sees everything until they send their first message. | Personal + Server |
| `get_board_updates` | **New.** Returns every row changed since a given timestamp (`WHERE last_edited_at > ?`) — the live-update polling query behind the admin Job Board (§10 → Job Board), meant to be called on a ~60-second interval so the board reflects crew activity without a manual refresh. Returns raw JSON, not a formatted digest — built for a UI to render into cards. **Server mode:** field_crew only receive `Jobs_Schedule` rows assigned to them; `field_crew` gets no access at all to Settings, Services_Pricing, Quotes, or Invoices via this path either. | Personal + Server |

---

#### Mileage Tracker Tools (Personal + Server)

The IRS business-mileage log behind the Jobs app's **Mileage** tab, **Database → 🚗 Miles**, and the Reports mileage card — and what Claude, Muse, or Grok use when you simply *say* "I drove to Home Depot for ladders, 12 miles." Every role can use them; **field crew see and change only their own trips** (the server enforces it). Every trip records date, destination, a specific business purpose, and miles (IRS Pub. 463); every edit needs a reason and is kept with who and when; trips are never deleted, only removed (void) with the reason. See **Mileage tracker (business miles for taxes)** below for how the app uses them.

| Tool | What It Does | Mode |
|---|---|---|
| `get_mileage_log` | The log for a date range as JSON: trips (from → to, miles, purpose, vehicle, business / commute / personal, reimbursable, edited / corrected / removed flags), days that need a fix (missing clock-out or location), vehicles, the IRS rate table, week and year-to-date totals, reminders due, and your crew-reimbursement status. Days whose jobs or clock times changed since they were built are rebuilt first. Owner/manager/staff can filter by driver. | Personal + Server, crew-scoped |
| `build_mileage_log` | Builds or rebuilds a day's trips from clock-ins: home (or the company location) → each job in clock order → home. **Settings → Route Origin Mode** decides the commute rule (*Jobs Only* = home office, home legs are business; *Company Location* = home ↔ company is commute). With a date range it **backfills** past days from existing clock-ins — `preview=true` (default) shows counts and writes nothing; owner/manager only. Hand-edited, locked, and submitted/paid trips are never overwritten. | Personal + Server, crew-scoped |
| `add_mileage_trip` | Logs any business trip — supplies, bank, estimate, client meeting, repairs, training — from form fields, Start/End GPS points, odometer start/end, or free text (`text="Home Depot for ladders, 12 miles, round trip"`). With text it reads the trip back (📝) and saves only on confirmation; if something's missing it says what (❓ miles or a start place, a specific purpose). Miles left blank are calculated from the places. Round trips save as two legs. Owner/manager/staff can log for a crew member (`for_crew`). | Personal + Server, crew-scoped |
| `update_mileage_trip` | `action="edit"` changes miles, from/to, purpose, date, vehicle, business/commute/personal, category, times, parking, tolls, or notes (reason required); `"void"` removes a trip from totals (kept in the record); `"split"` inserts a stop (a supply run between two jobs turns one leg into two); `"history"` shows every change. Locked months and submitted/paid reimbursements can't be changed. | Personal + Server, crew-scoped |
| `fix_mileage_gap` | Fills a missing clock-out (dead phone, forgot to clock out) with the time you left and a reason — recorded on the time entry — then rebuilds that day; the affected trips are marked corrected. | Personal + Server, crew-scoped |
| `job_cancelled_on_arrival` | The customer cancelled at the door: records a short visit at the job so the drive there still counts as a business trip (purpose "<customer> – cancelled on site"), marks the job **Cancelled** with a note, and rebuilds today's mileage. Field crew only for jobs assigned to them. | Personal + Server, crew-scoped |
| `manage_vehicles` | Vehicles by **VIN** (17 characters, check digit verified): `add` (business-owned, or a crew member's own car — its trips are reimbursable, not the business deduction), `update`, `retire`, `odometer` (start-of-year, end-of-year, or spot reading — the IRS asks for total yearly miles per vehicle), `set_default` (your usual vehicle), `set_day` (the vehicle you drove today). Field crew can add only their own crew-owned car. | Personal + Server, crew-scoped |
| `get_mileage_report` | Business and commute miles by driver, vehicle, and month; the **deduction** at the IRS standard rate for each rate period (2026: 72.5¢ Jan–Jun, 76¢ Jul–Dec) plus parking and tolls; **crew reimbursement** owed / submitted / approved-unpaid / paid; the **Form 4562 Part V** sheet per business vehicle (business, commute, other personal, total from odometer); and **IRS record checks** (missing purpose or vehicle, late entries, missing odometer readings, 5+ business vehicles used the same day). | Personal + Server, crew-scoped |
| `export_mileage_log` | The IRS mileage log as **PDF** (summary, deduction by rate period, reimbursement status, Form 4562 sheet, record checks, then every trip), **Excel** (Trips, Summary, Reimbursement, Vehicles sheets), or **CSV** (one row per trip). `deliver="file"` saves it next to the job database in `Mileage_Exports`; `"email"` sends it as an attachment to `email_to` (e.g. your accountant); `"download"` is what the Jobs app's ⬇ buttons use. | Personal + Server, crew-scoped |
| `mileage_reimbursement` | Crew reimbursement for business driving in a crew member's own car, per pay period (weekly, every 2 weeks, or monthly), at the IRS rate plus parking and tolls. `status` (current period + history; owner/manager also get the approval queue), `submit` (refused while a day needs a fix), `approve` (fixes the amount), `return` (with a note — trips reopen for edits), `paid` (date, method: check / cash / payroll / transfer, reference — trips lock), `list`, and `statement` (PDF; file / email / download). Submitted and approved trips can't be changed; **nobody can approve, return, or pay their own**; every status change is kept with who and when. | Personal + Server; approve / return / paid owner + manager only |
| `review_mileage_log` | **AI mileage review** of a date range — finds logged miles more than 25 % off the approved route, trips that don't match odometer readings, unusually long legs for the distance (missed stop, detour, bad GPS), duplicate trips, job trips on days nobody clocked in, one vehicle used by two drivers the same day, vague purposes, trips with no vehicle, commute legs misclassified for Route Origin Mode, trips edited long after the date, and paid reimbursements changed afterwards. Each finding has an id and, where safe, a proposed fix. **Changes nothing.** | Personal + Server, crew-scoped |
| `apply_mileage_review_fix` | Applies ONE review finding the user agreed to (`action="accept"`) through the normal audited edit, with the reason "AI review: …" — or dismisses it for good (`"dismiss"`), so it isn't raised again. | Personal + Server, crew-scoped |
| `mileage_settings` | `get` (tracking on/off, rate table, locked periods, pay period, reminders); owner/manager: `set_enabled` (same as Database → Settings → Mileage Tracking Enabled; off = the app never asks anyone for miles and adds no new trips to the log, route miles still show, the tabs stay, logged trips are kept), `set_rate` (cents per mile from an effective date, e.g. the 2027 rate), `lock` / `unlock` a month (`2026-09`) or year (`2026`) — a locked period can't be edited, removed, added to, or rebuilt, `set_period` (reimbursement pay period), `set_reminder` (gaps / weekly / pay_period / odometer on or off). Anyone: `reminders` (what's due for you now). | Personal + Server; changes owner + manager only |

> **By voice or chat:** "Log a bank deposit at Chase, 6 miles", "Change yesterday's Home Depot trip to 14 miles — I took a detour", "My phone died at Norwoods, I left at 3:30", "The Smiths cancelled when I got there", "Submit my mileage for October", "Approve Sam's mileage", "Review October mileage and fix the obvious problems", "Email my 2026 mileage log to my accountant". Claude asks for anything missing and confirms before anything is approved, paid, or fixed. *Not tax advice — your accountant confirms how to claim mileage.*

---

#### Route & Schedule Advisor

Everything the Jobs PWA's **Route** tab buttons call — building, reordering, re-planning, and approving a day's route — plus the tools behind letting Claude, Muse, or Grok reason through a day's stop order itself rather than using the built-in nearest-neighbor heuristic.

| Tool | What It Does | Mode |
|---|---|---|
| `build_daily_route` | The Route tab's full route builder: finds every job scheduled on a date (optionally one crew), geocodes any missing addresses and writes the coordinates back onto the job row, orders the stops (by TSP-optimized order from a given `origin`, or by each job's own Start Time if no origin is given), and writes the result into `Route_Planner` — replacing whatever was there for that day/crew. Runs a pre-flight savings check when an origin is given: if reordering would save 10+ minutes of drive time, it stops and asks for confirmation (`accept_reorder=True`) before committing. Surfaces GEOCODING FAILED / LATE ARRIVAL / SCHEDULE OVERLAP warnings without blocking the write. | Personal + Server |
| `suggest_route_schedule` | The Route tab's "Get AI Suggestion" button — a free, instant, deterministic scheduling heuristic (not a live LLM call): splits hard-committed jobs from soft (placeable-anywhere) jobs, builds a geographically sensible order, then repairs it so hard jobs never violate their own committed order, chains real OSRM drive times through the day, and applies the daily lunch pause wherever it lands. Writes straight into `Route_Planner`, same storage path as manual route-building. | Personal + Server |
| `apply_route_order` | Writes a **caller-reasoned** visit order into `Route_Planner` — the "let something that can actually think about the day decide the order" alternative to `suggest_route_schedule`'s heuristic. Runs the exact same timeline engine (real drive times, lunch pause, hard/soft violation checking), so the result looks and behaves identically either way; the only difference is who chose the order. Get the day's real numbers first via `get_route_drive_matrix()`, reason through the order, then call this. | Personal + Server |
| `get_route_drive_matrix` | Returns a real drive-time/drive-distance matrix (minutes and miles) between every geocoded job scheduled on a date — one OSRM `/table` call — for something doing its own reasoning about visit order to work from before calling `apply_route_order`. | Personal + Server |
| `reorder_route_stop` | Moves one stop to a new position within its own day's route (the Route tab's drag-and-drop / ▲▼ buttons), then **re-plans the whole day** in the new order using the same timeline engine as `build_daily_route` — every stop's arrival time is recomputed, not just the moved ones, so moving a stop and moving it back always returns exactly the same times. | Personal + Server, crew-scoped |
| `replan_route_day` | Re-plans a day's stored route **in its current order** — recomputes every arrival time, the lunch pause, and every warning after a job's own schedule (Start Time, Duration, Hard/Soft type) was edited elsewhere, without changing the visit order itself. | Personal + Server, crew-scoped |
| `approve_route_schedule` | The Route tab's "Approve — Allows Email & Link Viewing" button — records the route as approved. Approval is a pure flag: it allows emailing the route and pins its tap-to-navigate link so it is viewable on the Jobs and Calendar pages. It NEVER changes any job's Start Time / End Time — a job's window always stays as the customer settings. | Personal + Server |
| `unapprove_route_schedule` | The exact inverse of `approve_route_schedule` — fully undoes approval: clears the approval flag, unpins the route link (Jobs/Calendar stop showing it), and revokes email eligibility. Rebuilding a route also clears its approval — a rebuilt route is experimental until re-approved. | Personal + Server |
| `email_route_now` | Emails the currently-approved route (stop order + arrival times + tap-to-navigate link) for a date/crew right now, on request — the manual counterpart to Settings → "Email Route On Approve", and it works even when that setting is Disabled. Only an approved route can ever be emailed: an unapproved route reports "Email is only allowed for approved routes — approve the route first" instead of sending. **Server mode:** a field_crew caller can only email their own route; owner/manager/staff may email any crew's. | Personal + Server, crew-scoped |

---

#### AI Routing with Any AI Chat — 📋 Copy AI Route & 🗓️ Plan Week

*(New 2026-10-22.)* The Jobs app's **📋 Copy AI Route for Any AI** and **🗓️ Plan Week with Any AI** buttons build a ready-made prompt that you paste into **any AI chat that has AI-Prowler connected** — Claude, Muse, Grok — on your phone or computer. The chat does the reasoning *in front of you* and saves the result back through these tools. No Claude Code CLI, no per-user Claude token, no background run, and nothing to set up on a server. (These replaced the old Claude CLI **🧠 Run AI Routing** button and its tools — `start_ai_routing`, `poll_ai_routing`, `get_route_start_options`, `start_cli_signin`, `submit_cli_signin_code`, `cancel_cli_signin`, `save_my_cli_token` — which were removed on 2026-10-22.)

Every prompt carries a one-time **code** (`RT-XXXXXX` for a day's route, `WK-XXXXXX` for a week; good for 24 hours). If you have more than one AI-Prowler connected — for example your personal one and your company server — the chat checks the code against each one and uses **only** the AI-Prowler that made it, so a route can never land on the wrong computer.

**Just say it — by voice or by typing (2026-10-23).** You don't have to paste anything. In any AI chat with AI-Prowler connected, say or type **"Route me for today"**, **"Plan tomorrow's route"** or **"Plan my week"** and the AI makes the prompt itself (`get_ai_route_prompt` / `get_week_plan_prompt`) and does its steps in the same chat. A spoken or typed request is treated exactly like the Jobs app's buttons. To approve, either use the Route tab as usual **or say yes in the chat** — the AI first reads back what will change (the route, or each suggested move) and only approves after a clear yes; you can also approve just some moves ("move Crabby's but not the Norwoods"). Replies are kept short because you may be driving and listening. Every other Jobs and Remote tool works the same way by voice or text ("Put JOB-4095 on hold", "What time am I at each stop today?"). For HR (server mode), the AI can do what the 20 `hr_*` tools cover — look up, add and update employees, start a termination, list and complete HR tasks, check documents, run HR backups and reports, look up state rules and forms. Everything else in the HR apps (time off, time clock, attendance, schedules, messages, announcements, training and the rest) is done on the HR app screens.

| Tool | What It Does | Mode |
|---|---|---|
| `get_ai_route_prompt` | The **📋 Copy AI Route** button: builds the prompt that plans one day's route (same reasoning steps as before — hard appointment times respected, soft jobs fill the gaps, real drive times) with a new `RT-` code. The Settings values the plan needs are written into the prompt, so it also works for field crew. Nothing is planned or written here. **Server mode:** a field_crew caller always gets their own day; a blank crew means the caller's own day. | Personal + Server |
| `confirm_route_code` | Step 1 of a pasted prompt: answers **MATCH** (this AI-Prowler made the code — use it for every step) or **NO MATCH** (try your other AI-Prowler connector). Read-only. | Personal + Server |
| `apply_route_order` *(with `route_code`)* | When a pasted prompt saves the route it passes its code, and AI-Prowler **refuses** a code that is unknown, expired, for another date or crew, or a week code — so a prompt can only change the day it was made for. | Personal + Server |
| `get_week_plan_prompt` | The **🗓️ Plan Week** button: builds the prompt for any week (pick any day in it) with a new `WK-` code. | Personal + Server |
| `get_week_plan_data` | Everything the chat needs for that week: each job, whether it may move and to which days, the booked minutes per day, and the **nearby pairs** — jobs on different days within the *Week Plan Distance (miles)* setting of each other. | Personal + Server |
| `propose_week_moves` | Saves the chat's **suggested** moves. Every move is checked: soft jobs only (hard/committed times never move), not closed / in progress / paused / multi-day, never into the past, only onto a working day and one of the job's (or customer's) **Preferred Day(s)**, date only (the time window is kept). Moves that break a rule are rejected with the reason. **No job changes here.** | Personal + Server |
| `get_week_proposal` | The Jobs app's **📥 Check for suggestions**: the newest suggestion waiting for approval for that week (and crew). Read-only. | Personal + Server |
| `apply_week_moves` | **✅ Approve selected**: moves the ticked jobs to their suggested dates. Each move is checked again first — a job that changed since the AI looked is skipped, never forced. Then route each day as usual. | Personal + Server |
| `dismiss_week_proposal` | **Dismiss**: closes the suggestion without moving anything. | Personal + Server |

#### Agentic Analysis Tools (Personal Only)

These tools power the **Common Business AI Analysis** and **My Custom AI Analyses** sections in the Quick Links tab. Not available in server mode.

| Tool | What It Does | Mode |
|---|---|---|
| `create_analysis_task` | Defines a new recurring or one-off custom task from a plain-language request — the same thing the "+ New Custom Analysis" GUI dialog builds. **Day-granularity scheduling only for weekly/biweekly/monthly** — `schedule="daily"` additionally supports `daily_start_time`/`daily_end_time`/`daily_times_per_day` for N evenly-spaced runs per day; weekly/biweekly/monthly remain day-granularity only, and `schedule_day_of_week` can pin the run to a specific weekday. Enforces the same 25-task cap as the GUI dialog (`MAX_CUSTOM_TASKS`). | Personal |
| `list_analysis_tasks` | Lists the FULL custom-analysis task definition list (`custom_analysis_tasks.json`), up to 25, regardless of due date — with an `is_due` flag per task. Complements `get_pending_analysis_tasks`, which only shows tasks that have already been queued into the run queue (`pending_tasks.json`). Strictly read-only; never modifies or queues anything. | Personal |
| `get_pending_analysis_tasks` | Returns tasks from `~/.ai-prowler/pending_tasks.json` that are **due right now** — `status == "pending"` AND `is_queue_entry_ready()`. Due-filtered: a recurring task queued ahead of its `next_due` date stays hidden until that date arrives (it remains in the queue, it just isn't "ready" yet). One-shot entries (`schedule: "none"`) are always ready once queued. If the queue has items but none are due yet, says so explicitly rather than implying the queue is empty. | Personal |
| `queue_single_task` | **New — replaces the removed `sync_due_tasks_to_queue`.** Queues exactly one custom task for immediate execution regardless of its scheduled `next_due`, without touching any other task in the queue. Idempotent — a task already pending/ready is skipped. The queue is populated manually only (there is no bulk "sync everything currently due" tool anymore); this is the tool for "run this one now." | Personal |
| `get_all_queued_tasks` | **New — replaces part of the removed `sync_due_tasks_to_queue`'s use case.** Returns EVERY item currently in the queue, regardless of whether it's due yet, so the user can see what's scheduled to run in the future — not just what `get_pending_analysis_tasks` would surface right now. | Personal |
| `complete_analysis_task` | Marks a queued task as done for this run. **Unified re-arm:** one-shot entries (`schedule: "none"`, built-in or custom) complete permanently. Recurring entries — **built-in and custom behave identically by design** — instead have `next_due` advanced and `status` reset back to `"pending"`, so the SAME queue entry re-arms itself and resurfaces automatically once next_due arrives, rather than requiring a manual re-queue. Anchors to the original due date, not the completion date; for custom tasks the source definition in `custom_analysis_tasks.json` is kept in sync. | Personal |
| `delete_analysis_task` | Removes a task from chat. Accepts either a custom definition's `task_id` (deletes the definition AND any linked queue entries) or a single queue entry's `task_id` (removes just that instance, leaving a recurring definition intact). | Personal |
| `update_analysis_task` | Edits an existing custom task's label, prompt, schedule, first_due, output options, or scope_dirs from chat — only the fields you pass are changed. Uses the same `update_task()` logic as the GUI editor, including correctly recomputing `next_due` when schedule, first_due, or the daily-time fields actually change. Built-in tasks aren't editable this way; they have no standalone definition. | Personal |
| `save_analysis_report` | Saves a full analysis as a Word document (`.docx`) to the configured report folder. Default: `~/Documents/AI-Prowler_tasks_reports`. | Personal |

> **Note — stale tool name removed:** earlier revisions of this guide (and this section) referenced `sync_due_tasks_to_queue`, which pushed all due custom tasks into the run queue automatically. It was fully removed from the codebase once the real usage model turned out to be "the user adds tasks to the queue manually only, no auto-syncing." `queue_single_task` (queue one specific task now) and `get_all_queued_tasks` (see everything queued, due or not) cover what it did. If you have an older prompt or script that calls `sync_due_tasks_to_queue`, it will fail — switch to one of these two.

---

#### Data Portability & Backup

Full detail, decision table ("which one do I want?"), and the Small Business tab's own panel: **§10 → Data Portability — Export, Backup, Restore.**

**Who can use these in server mode:** the owner, managers and staff. Field crew are always refused — an export, backup or restore contains the whole company's data, not just their own jobs. Personal mode is unchanged.

| Tool | What It Does | Mode |
|---|---|---|
| `export_to_excel` | One-way, lossy-by-design snapshot: a workbook with one sheet per table, built from whatever's in the database right now. Edits made to the exported file are never read back. | Personal + Server (not field crew) |
| `export_to_csv` | Same idea as `export_to_excel`, as one `.csv` per table; scope with `tables=[...]` for just a couple of tables. | Personal + Server (not field crew) |
| `export_to_quickbooks_csv` | Customers/Invoices CSVs pre-labeled with QuickBooks Online's own field names — QBO's own "map your fields" import screen still appears, but the mapping is fast since the column names already match. | Personal + Server (not field crew) |
| `backup_job_database` | Lossless, round-trippable full-database backup via SQLite's own online Backup API — safe to run while the database is being actively written to. Defaults to `backup/AI-Prowler-Backup-<timestamp>.db` next to the live database. | Personal + Server (not field crew) |
| `restore_job_database` | Replaces the live database with a backup file — meant for **moving to a new PC**. Requires `confirm=True`; an unconfirmed call changes nothing and shows how many jobs, customers, invoices, quotes, time entries and route stops are live now and how many are in the backup. Always validates the incoming file and takes a safety backup of whatever's live before overwriting it. **Server mode:** if the live database already has records, a confirmed restore is still refused unless `replace_existing=True` is also passed — Claude, Muse, or Grok should only do that after you have seen both counts and said plainly that you want the current data wiped. | Personal + Server (not field crew) |




### 6.5 Email Tool Setup

#### How to Configure Email (Personal Installs)

On a personal install, email is configured by telling Claude, Muse, or Grok your credentials in a conversation. Claude, Muse, or Grok calls `configure_email` once and your credentials are saved to `smtp_config.json`. You never need to call the tool manually.

Example — just tell Claude, Muse, or Grok:
> *"Configure email with my Gmail address yourname@gmail.com and app password xxxx xxxx xxxx xxxx"*

Claude, Muse, or Grok handles the rest — it detects your provider from the email domain and sets the correct SMTP host and port automatically.

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

### Personal Mode Setup (Fully Automated)

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

### Business Server Mode Setup (Fully Automated)

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
5. Name it **AI-Prowler Local** — this exact name matters: if you ever also connect to a company **AI-Prowler Server**, distinct names let Claude, Muse, or Grok tell the two knowledge bases apart instead of guessing which one you mean
6. Leave **OAuth Client ID** and **OAuth Client Secret** blank
7. Click **Add** — Claude.ai connects to your tunnel and prompts for auth
8. Enter your Bearer token
9. Set **Always Allow** for all tools in the connector panel

---

> **Remote PWA app (personal mode only — not available in Server mode):** the same tunnel also serves a standalone browsable dashboard app at `/remote/` — separate from the MCP connection above. Full setup and tab-by-tab reference: **Section 26 — Remote PWA App**.

---

### File Transfer Tools (Personal Mode Only)

Two MCP tools let Claude, Muse, or Grok read and write files directly via the Remote Control PWA's existing HTTP endpoints, with no base64 encoding and no context-window overhead. Both tools are **personal mode only** — they are invisible in the MCP tool list on server-mode installs (Tier A suppressed) and return a ⛔ error if somehow called on a server install. The underlying HTTP endpoints enforce the same gate independently.

#### Prerequisites

- Remote Access must be configured (Cloudflare Tunnel active, bearer token set)
- The file must be inside a **tracked directory** (use `index_path()` if not already tracked)
- For uploads: the destination directory must be in the **writable allowlist** — call `grant_write_access(directory)` first if it's a new destination

#### `get_file_download_url(file_path)` — Reading files without base64

Returns a signed HTTPS URL that Claude, Muse, or Grok passes straight to `web_fetch()` to read any tracked file directly into the conversation.

**The workflow:**
```
You: "Read the contents of C:\Users\david\Documents\Misc\notes.md"
Claude, Muse, or Grok: [calls get_file_download_url("C:\Users\david\Documents\Misc\notes.md")]
Claude: [tool returns {"download_url": "https://your-tunnel.../remote/download?path=...&token=..."}]
Claude, Muse, or Grok: [calls web_fetch(download_url)]
Claude, Muse, or Grok: [file content arrives inline — readable in the conversation]
```

**What the endpoint enforces:**
- Bearer-token auth (embedded in the URL query string)
- File must be inside a tracked readable directory
- Extension allowlist: `.pdf`, `.docx`, `.xlsx`, `.doc`, `.xls`, `.pptx`, `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.heic`, `.mp4`, `.mov`, `.avi`, `.txt`, `.md`, `.csv`, `.json`, `.log`, `.py`, `.js`, `.html`, `.css`
- 50 MB size limit
- 20 downloads per bearer-token per hour (rate limit)

**Text files** (`.txt`, `.md`, `.csv`, `.py`, `.js`, `.html`, `.json`, `.log`) arrive fully readable inline in the conversation. **Binary files** (`.pdf`, `.docx`, `.xlsx`, images, video) arrive as describable content Claude, Muse, or Grok can summarise or comment on.

**Common errors:**
- `❌ File not found` — check the path is correct and the file exists on disk
- `❌ not in the download allowlist` — file type not supported; convert or use a supported extension
- `❌ not inside a tracked directory` — call `index_path(directory)` to track the parent folder first
- `❌ exceeds the 50 MB download limit` — split or compress the file
- `❌ No tunnel_domain configured` — set up Remote Access (Cloudflare Tunnel) in Settings first
- `❌ No remote_token configured` — set a Bearer Token in Settings → Remote Access first

#### `get_file_upload_url(filename, target_directory)` — Uploading files without base64

Returns a signed HTTPS URL and `multipart/form-data` field instructions so Claude, Muse, or Grok can upload a file to any writable tracked directory. The file is saved and automatically re-indexed into ChromaDB so it immediately becomes searchable.

**Workflow — Claude, Muse, or Grok uploads a file it generated (via `run_script`):**
```
You: "Save this report to C:\Users\david\Documents\Misc\report.md"
Claude, Muse, or Grok: [calls get_file_upload_url("report.md", "C:\Users\david\Documents\Misc")]
Claude, Muse, or Grok: [tool returns {"upload_url": "...", "curl_example": "curl -X POST ..."}]
Claude, Muse, or Grok: [creates the file locally, then calls run_script(curl_example)]
```

**Workflow — Browser artifact upload:**
```
Claude, Muse, or Grok: [calls get_file_upload_url("data.csv", target_dir)]
Claude, Muse, or Grok: [builds a React/HTML artifact with the returned upload_url and field names]
You: [drag-drop your file into the artifact — it POSTs directly to AI-Prowler]
```

**What the endpoint enforces:**
- Bearer-token auth (token in the `token` form field)
- Directory must be in the writable allowlist
- File is saved as `target_directory\filename` and the directory is re-indexed immediately
- Any existing file with the same name is overwritten

**Multipart fields (for custom artifact/curl use):**
| Field | Value |
|---|---|
| `file` | The file bytes, with the correct filename |
| `dir` | Absolute Windows path to the target directory |
| `token` | Your bearer token (from `config.json → remote_token`) |

**Common errors:**
- `❌ not in the writable allowlist` — call `grant_write_access(target_directory)` first, then retry
- `❌ not inside a tracked directory` — call `index_path(directory)` to track the folder, then `grant_write_access()` to make it writable, then retry
- `❌ filename must not be empty` — provide a non-empty filename
- `❌ No tunnel_domain configured` — set up Remote Access first

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

Business edition lets you run AI-Prowler in server mode on a company machine so a whole team reaches one shared knowledge base from Claude, Muse, or Grok on their phones and laptops.

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

They now have **two connectors** in Claude.ai: **AI-Prowler Local** (their own private documents) and **AI-Prowler Server** (the shared company knowledge base). Using these exact, distinct names — rather than naming both just "AI-Prowler" — lets Claude, Muse, or Grok tell the two apart and route requests to the right one instead of guessing.

### Edition and Mode

Two runtime settings in `config.json` decide how an install behaves:

| Setting | Values | Meaning |
|---|---|---|
| `edition` | `home` / `personal` / `business` | License tier |
| `mode` | `personal` / `server` | Deployment mode |

The Admin tab appears only when `edition = business` AND `mode = server`.

> **Note:** Configuring server or personal mode should be done after install and before indexing. After that it should not be changed — the two database formats are not compatible.

### Roles

| Role | Description | Manages Users |
|---|---|---|
| owner | The company account holder. One per company. | ✅ Always |
| manager | Senior user. Can be granted delegated admin rights. | ✅ If granted |
| staff | Regular employee — also the crew-lead tier: sees and edits every crew's jobs in the Jobs App. | ❌ |
| field_crew | Field employee — sees and edits only the jobs assigned to them in the Jobs App. | ❌ |

**For the knowledge base, role gates only two things:** Admin tab access (owner, and manager if granted "Can manage users") and part of `untrack_directory` (see §6.3 — own personal directory is open to every role; owner or delegated admin is required only outside it). It does **not** gate what a user can search, whether they can index, or whether they can list tracked paths (`list_tracked_directories` is scope-gated, same visibility as search) — those are controlled entirely by scopes, below.

**For job data (the job tracker and the Jobs App), role does matter** — it decides which jobs a user sees and edits, which Database tables they can open, and whether they get the Reports screen. Scopes play no part there. See **Roles and Scopes in the Jobs App** below and **Section 25**.

The role labels are also useful for the Admin tab's own bookkeeping — a quick visual read of who's who in the Active Users table.

### Scopes — Controlling What Each User Can See

Scopes are the data-access groups you define to match how your business is organized. Under the hood, every install uses **one shared knowledge base** — there's no separate database "collection" per scope. Each indexed chunk carries a scope tag (`sales`, `office`, `shared`, `private:<user>`, etc.), and search results are filtered by that tag at query time. A scope is purely a label you assign, not infrastructure you have to keep in sync.

**Every user's search visibility follows the exact same formula, with no exceptions for role — including the owner:**

- `shared` (always included — the company-wide default)
- their own assigned scopes
- their own private scope, if **Private collection enabled** is ticked for them

There is no "see everything" role. If the owner needs to see a scope, it has to be assigned to them like anyone else. This also means indexing content doesn't leak it to anyone new — indexing was never the confidentiality boundary; scope + search is the *only* boundary.

**Managing the scope catalog:** scopes are picked from an admin-managed list, not free-typed. In the Admin tab, click **🏷️ Manage Scopes** to add or remove entries (up to 15). `shared` is always available and isn't listed — it can't be removed. Private scopes are per-user and also aren't listed here — they're controlled by the **Private collection enabled** checkbox on each user, not the catalog. Removing a scope from the catalog only stops it being offered for *new* assignments — it does not retroactively unassign it from anyone who already has it, or unscope any file already tagged with it.

**Scope example — a window and pressure washing company:**

| Employee | Scopes assigned | Private enabled | What they can search |
|---|---|---|---|
| David (owner) | `office`, `sales` | ✅ | office docs, sales docs, shared, own private |
| Maria (office manager) | `office` | ❌ | office docs, shared |
| Jake (field crew) | `field` | ✅ | job sheets/manuals, shared, own private |

Note David (the owner) only sees `office`/`sales`/shared/his own private here — not Maria's or Jake's content — because there's no more owner-sees-everything exception. If David needs visibility into a scope he doesn't have, he assigns it to himself the same way he'd assign it to anyone else.

### Roles and Scopes in the Jobs App

Every server-mode user can open the Jobs App (Section 25) at `/jobs/` on the server's tunnel URL and log in with their **name and personal token** from the Admin tab. What they see there depends on their **role**, not their scopes:

| In the Jobs App… | owner | manager | staff | field_crew |
|---|---|---|---|---|
| Jobs, Board, Calendar, Route — whose jobs | every crew | every crew | every crew | only jobs whose **Crew / Technician** is their name (a blank crew means *unassigned*, not *everyone*) |
| Edit, reschedule, delete a job | any job | any job | any job | their own jobs only |
| Route for another crew (build, reorder, approve, 📧 email) | ✅ | ✅ | ✅ | their own route; 📧 Email Route always goes to themselves |
| Clock in / out | ✅ | ✅ | ✅ | ✅ on their own jobs |
| Photos | any job | any job | any job | their own jobs |
| Database tab — Jobs_Schedule, Customers, TimeLog, Route_Planner | ✅ | ✅ | ✅ | ✅ (job rows filtered to their own; Customers readable for gate codes and access notes; pricing/status fields on Customers are locked) |
| Database tab — Settings, Services_Pricing, Quotes, Invoices | ✅ | ✅ | ✅ | ❌ not shown, and refused by the server |
| Reports screen (revenue, hours, stale customers, reminders) | ✅ | ❌ | ❌ | ❌ |
| Messages (SMS/WhatsApp) | ✅ | ✅ | ✅ | ✅ |

- **Scopes don't apply to job data.** Scopes decide which *indexed documents* a user can search. The job tracker is one database; the role decides how much of it a user sees. A field crew member with no scopes at all still sees their own jobs.
- **One job database for everyone.** Every user works in the same shared job database; only their role decides which rows they see (see Section 10 → *Server Mode: One Shared Job Database*).
- **Tools hidden on the server.** Tools that act on the server machine itself (running scripts, file tools, the SMS inbox — see §6.2 Tier A) are not available to anyone in server mode, including the owner, and so never appear in the Jobs App.
- **Rules are enforced on the server.** Hiding a tab in the app is only a convenience; the server refuses the same actions if they are tried another way.
- **Changing a role** takes effect the next time the user logs in to the Jobs App.

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
| Role | owner / manager / staff / field_crew — see §9's note on what role does and doesn't gate |
| Scopes | The data-access scopes assigned to this user, from the catalog |
| Manages Users | ✓ if this user has delegated admin rights |
| Private Coll. | ✓ if a private knowledge-base scope is enabled for this user |
| Home Addr. | ✓ if a home address is saved for this user (used when their route starts/ends at home) — the address itself is never shown in the table |
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
| 🏷️ Manage Scopes | Add or remove entries in the shared scope catalog (up to 15) — see the Scopes section above |
| ↻ Refresh | Reloads users.json and repaints the table |

> **No AI passwords to manage (2026-10-22).** AI routing in the Jobs app is done with each person's own AI chat (📋 Copy AI Route / 🗓️ Plan Week — Section 25), so there is nothing to set up for it here. The old **🤖 AI Route Token** button, **AI Route** column and **🧠 AI Route runner** panel (Claude Code CLI install, on-demand runner, per-user Claude tokens) were removed; tokens saved by an older version are deleted automatically.

**Adding a User (Step by Step)**
1. Click ➕ Add User
2. Fill in Name (required), Email (optional), Cell Phone (optional), Cell Carrier (optional)
3. Choose a Role
4. **Select Scopes** — a multi-select list (Ctrl/Shift-click for multiple) populated from the scope catalog. Manage the catalog itself via 🏷️ Manage Scopes if the scope you need isn't listed yet.
5. Optionally tick **Can manage users** (managers only) and **Private collection enabled**
6. Assign a **License seat** from the dropdown (unassigned child keys)
7. Bearer token — leave blank to auto-generate (recommended)
8. Click Save

**Giving Each Employee Access**
Once added, hand them:
1. Their bearer token — send securely (or use Regenerate Token in the Admin tab)
2. The company's Claude.ai connector URL — shown in Settings → Remote Access → **Server Connection Test** panel. Copy it with the **📋 Copy** button.

The employee adds that connector in Claude.ai settings, authenticates with their bearer token, and starts a new conversation. Their personal AI-Prowler (from their seat email) connects them to their private documents. The server connector connects them to the shared company knowledge base. Both connectors can be active simultaneously in Claude.ai.

### Assigning Scopes to Folders — Update Index Tab

Beyond assigning scopes to *users*, an owner/manager also assigns a scope to each tracked *folder or file*, from the Update Index tab:

1. Select a tracked folder or file in the list.
2. Click **🔀 Change Scope for Selected**.
3. Pick a scope from the dropdown (same catalog as the Admin tab) and click **Stage Change**.

The change is **staged, not immediate** — the tracked-items list shows `→<scope> (pending)` for that row until you actually run **Update Selected** or **Update All**. Running either commits the staged scope and re-indexes the path in the same step, so every chunk comes out freshly tagged with the new scope. Nothing is written to disk from the staging step alone; if you stage a change and never run an update, it simply never takes effect.

A folder with no scope assigned at all defaults to `shared` once it's tracked and indexed — never blocked, never silently guessed into something more restrictive.

### Replacing the Server Machine

1. Install AI-Prowler Server on the new machine
2. Go to Settings → Remote Access → Business Subscription & Server Setup
3. Paste your original server activation code and click **⚡ Auto-Configure Server** — the same tunnel token is returned (re-claims are allowed from a new machine)
4. Copy `users.json`, `license_seats.json`, and `rag_database/` from the old machine (if recoverable) — or re-enter users manually via the Admin tab
5. All employees' Claude.ai connectors continue to work — the URL doesn't change

> **Why no transfer step is needed:** The server license key has no machine lock. It is validated against your subscription record for validity and seat count only. You can run it on any machine.

---

## 10. Small Business Service Tools & Job Tracker Workflow

The Small Business tab provides configuration and quick-reference for the field service automation MCP tools. These tools let Claude, Muse, or Grok act as your field service assistant from a conversation.

> **The job tracker's canonical live data store is a SQLite database (`ai_prowler_jobs.db`) — see Job Tracker Database (SQLite) below.** This section also covers two purpose-built features: the **Job Board** (a live admin kanban view) and **Data Portability** (export/backup/restore tools).

### Free Tools

Five tools require no setup and work immediately: `get_weather` (Open-Meteo + Nominatim), `geocode_address` (Nominatim / OpenStreetMap), `optimize_route` (OSRM public routing server), `build_maps_url` (Google Maps / Apple Maps URL scheme), and `build_daily_route` (Nominatim + OSRM, same as `optimize_route` — see below). None need an API key.

> These tools are documented, along with every other Small Business tool, an end-to-end daily workflow, and example prompts, in the **🔧 View All Service Tools & Example Prompts** popup opened from the Small Business tab — they no longer have a dedicated always-visible panel there.

### Complete Contractor / Job Tracker Tool List

Every MCP tool built for the field-service/contractor workflow, in one place. Full detail on `create_customer`, `create_quote`, and `build_daily_route` is in the section immediately below this table; everything else is documented at the point where it's first used in the **Typical Small Business Contractor Workflow** walkthrough further down this section.

**Reading & editing job tracker data** *(the same data shown in the Jobs PWA App's Board, Jobs, and Database tabs)*

| Tool | What it does |
|---|---|
| `read_job_spreadsheet` | Reads rows from any table, with optional date/customer/status filters |
| `update_job_spreadsheet` | Edits an **existing** row's columns by exact header match — status, payment, notes, anything |
| `get_sheet_columns` | Lists a table's exact column headers — useful before an `update_job_spreadsheet` call that needs to match them precisely |
| `check_tools_status` | Reports which Small Business tools are configured/available on this connection |

**Creating new records** *(each appends a brand-new row with an auto-generated ID — never use these to edit an existing row; use `update_job_spreadsheet` for that)*

| Tool | Sheet | Auto-generated ID |
|---|---|---|
| `create_job` | `Jobs_Schedule` | `JOB-####` |
| `create_customer` | `Customers` | `CUST-####` |
| `create_quote` | `Quotes` | `QTE-####` |

**Routing & location** *(all free, no API key needed)*

| Tool | What it does |
|---|---|
| `geocode_address` | Address → latitude/longitude (Nominatim / OpenStreetMap) |
| `get_weather` | Current conditions + forecast (Open-Meteo + Nominatim) |
| `optimize_route` | Solves the optimal visit order + drive times for a list of stops (OSRM) |
| `build_maps_url` | Turns a stop list into a tap-to-navigate Google/Apple Maps link |
| `build_daily_route` | Builds the **whole day's** route from `Jobs_Schedule` in one call — auto-geocodes, flags conflicts, writes `Route_Planner`, emails the link. See below. |
| `get_home_address` | Returns your configured home/shop address (personal mode only) |

**Time tracking**

| Tool | What it does |
|---|---|
| `log_time_entry` | Clocks in or out for a job and calculates elapsed time |

**Mileage tracker (business miles for taxes)**

An IRS-ready mileage log in the Jobs app's **Mileage** tab (Personal and Server mode). Trips build themselves when you clock out of your last job of the day: home (or the company location) → each job → home, using the clock-in/out GPS points, or the job address when GPS is missing. **Settings → Route Origin Mode** decides the commuting rule: *Jobs Only* treats home as your office, so the home legs count as business; *Company Location* counts home ↔ company as commuting, which is not deductible.

- **Any business trip, any time:** tap **▶ Start trip / ■ End trip**, use **＋ Add trip**, type a sentence ("Home Depot for ladders, 12 miles, round trip"), or just tell Claude, Muse, or Grok (by voice or typing) — they log it with `add_mileage_trip` and ask for anything missing, such as the miles or the purpose. A specific business purpose is required — the IRS doesn't accept just "business".
- **Database → 🚗 Miles:** the running log of every trip as a table (newest first), with a date range, search, Show removed, and ＋ Add trip. Tap a row to edit it, remove it, add a stop, or see its change history — the same audited edit as the Mileage tab.
- **Vehicles by VIN:** add every vehicle with its VIN; mark a crew member's own car as crew-owned (its trips are reimbursable, not the business's deduction). Pick today's vehicle on the **Clock** screen. Record the odometer on Jan 1 and Dec 31 for each vehicle's total yearly miles (Form 4562).
- **Changes are kept:** every edit needs a reason and is stored with who and when. Removing a trip marks it removed, it is never deleted. Owners can lock a month once it's reviewed.
- **Phone died / forgot to clock out:** the Mileage tab shows **Needs fix**. Enter the time you left and a reason, and the day rebuilds. Use **Add a stop** to insert a supply run between two jobs.
- **Schedule changes are followed automatically:** when a job is moved, cancelled, deleted, re-addressed, its clock times are fixed, or the route is rebuilt, that day's trips are rebuilt the next time anyone opens the Mileage tab or a report — whichever app or tool made the change. Trips you edited by hand, locked months, and submitted or paid reimbursements are never overwritten. **Recalculate a day** still works any time.
- **Customer cancelled at the door:** tap **🚫 Cancelled on arrival** and pick the job. The drive there still counts as a business trip ("Smiths – cancelled on site") and the job is marked Cancelled.
- **Past days:** owners can **Rebuild past mileage** from existing clock-ins. Preview first; nothing is written until you confirm.
- **Crew reimbursement (crew-owned cars):** paid back at the IRS rate plus parking and tolls, per pay period (Database → Settings → Mileage Reimbursement Period: weekly, biweekly, or monthly). The crew member taps **Submit** on the Mileage tab (not allowed while a day needs a fix); the owner or a manager **Approves** (the amount is then fixed) or **Returns** it with a note; once paid, **Mark paid** with the date, method (check, cash, payroll, transfer) and reference. Submitted and approved trips can't be changed, paid trips are locked, and nobody can approve their own. Every step is kept with who and when. **PDF** gives the reimbursement statement.
- **Reminders** (each can be turned off in Database → Settings → Mileage Reminder - …): gaps to fix (after 7 PM), Monday's weekly review, submit / approve / pay at the end of a pay period, and odometer readings at year end and for vehicles with none. They show at the top of the Mileage tab; the owner also gets them in the 🚗 Mileage Reminders email (Proactive Alerts, 7 PM) and the Morning Briefing.
- **🤖 Review with AI** (Mileage tab and Reports): checks the range for miles far from the approved route, trips that don't match the odometer, unusually long legs, duplicates, job trips on days nobody clocked in, one vehicle with two drivers, vague purposes, trips with no vehicle, commute legs misclassified for Route Origin Mode, late edits, and paid reimbursements changed afterwards. Nothing changes until you tap **Fix**; **Skip** hides a finding for good. On Mondays the Morning Briefing includes a short review of last week. You can also ask Claude, Muse, or Grok: "Review October mileage and fix the obvious problems" — each fix is applied only after you confirm.
- **Export:** **⬇ PDF / Excel / CSV** on the Mileage tab (this view) and Reports (any range). The PDF is the IRS mileage log: summary, deduction by rate period, crew reimbursement status, the Form 4562 per-vehicle sheet, record checks, then every trip. Excel has Trips, Summary, Reimbursement, and Vehicles sheets. Ask Claude to email it to your accountant.
- **Reports → Mileage & deduction:** business and commute miles by driver, vehicle, and month; the deduction at the IRS rate for each period (2026: 72.5¢ Jan–Jun, 76¢ Jul–Dec) plus parking and tolls; crew reimbursement owed, submitted, approved but unpaid, and paid; the per-vehicle Form 4562 sheet; and IRS record checks.
- **Turn it off:** Database → Settings → **Mileage Tracking Enabled** → Disabled (owner/manager). It's on by default. Off is for a business where the vehicle is used 100% for work and the miles are tracked by the odometer at the start and end of the year: the app then never asks anyone about miles. There's no vehicle picker at clock-in, no Start/Add trip, no gaps, reminders or reimbursements, and no new trips are added to the mileage log. Your **route still shows miles driven** exactly as before. The Mileage tab, Reports → Mileage and Database → Miles stay; they just get no new data. Trips already logged are kept.
- **Mileage settings (Database → Settings):** Mileage Tracking Enabled, Mileage Reimbursement Period (weekly / biweekly / monthly), Mileage Pay Period Start (the date weekly and biweekly periods count from), and one Enabled/Disabled row per reminder — Mileage Reminder - Daily Gaps, - Weekly Review, - Pay Period, - Odometer. Changes apply as soon as you save.

| Tool | What it does |
|---|---|
| `get_mileage_log` | Trips, gaps to fix, vehicles, rates, totals, reminders, and reimbursement status for a date range |
| `build_mileage_log` | Rebuilds a day from clock-ins, or backfills a date range (preview first) |
| `add_mileage_trip` | Logs a business trip by form fields, GPS points, or free text / voice |
| `update_mileage_trip` | Edits (with a reason), removes, or splits a trip; shows its change history |
| `fix_mileage_gap` | Fills a missing clock-out (dead phone) and rebuilds the day |
| `manage_vehicles` | Adds vehicles by VIN, crew-owned cars, odometer readings, today's vehicle |
| `get_mileage_report` | Miles, deduction by IRS rate period, reimbursement status, Form 4562 sheet, record checks |
| `mileage_settings` | Tracking on/off, IRS rates, lock/unlock a month, reimbursement pay period, reminders |
| `export_mileage_log` | The IRS mileage log as PDF, Excel, or CSV — saved, emailed, or downloaded |
| `mileage_reimbursement` | Crew reimbursement: status, submit, approve, return, mark paid, PDF statement |
| `review_mileage_log` | AI review of a date range — findings and proposed fixes, nothing changed |
| `apply_mileage_review_fix` | Applies (audited) or dismisses one review finding |
| `job_cancelled_on_arrival` | Records the visit so the drive counts, marks the job Cancelled, rebuilds the day |

*Not tax advice — your accountant confirms how to claim mileage.*

**Billing & collections**

| Tool | What it does |
|---|---|
| `create_invoice` | Generates an invoice from a completed job |
| `email_invoice` | Emails an existing invoice to the customer |
| `text_invoice` | Texts an existing invoice to the customer (requires SMS configured) |
| `email_receipt` | Emails a payment receipt after an invoice is marked paid |
| `text_receipt` | Texts a payment receipt after an invoice is marked paid (requires SMS configured) |
| `schedule_next_recurring_job` | Creates the next occurrence of a recurring job from a completed one |
| `get_ar_aging_report` | Lists unpaid invoices grouped by how overdue they are |

**Job Board — live updates**

| Tool | What it does |
|---|---|
| `get_board_updates` | Returns every row changed since a given timestamp (`WHERE last_edited_at > ?`) — the polling query behind the admin Job Board. Returns raw JSON for a UI, not the formatted text `read_job_spreadsheet` returns. See **Job Board** below. |

**Data portability — export, backup & restore**

| Tool | What it does |
|---|---|
| `export_to_excel` | Generates a fresh `.xlsx` snapshot of the whole job tracker from the live database — one sheet per table. One-way; never a write target. |
| `export_to_csv` | Generates one `.csv` per table (or a `tables=[...]`-scoped subset) — the lowest-common-denominator format for accountants and manual QuickBooks import. |
| `export_to_quickbooks_csv` | Same idea as `export_to_csv`, but Customers/Invoices columns are labeled with QuickBooks Online's own field names, so QBO's mandatory field-mapping screen goes faster. |
| `backup_job_database` | Makes a lossless, byte-faithful copy of the live `ai_prowler_jobs.db` via SQLite's own online Backup API — safe to run mid-write. Renamed from `backup_database` — this operates on the job tracker database, not the ChromaDB knowledge-base index, which has no backup/restore tool of its own. |
| `restore_job_database` | Replaces the live database with a previous backup — meant for moving to a new PC. Requires `confirm=True`; shows live-vs-backup record counts; always safety-backs-up whatever's currently live first. In server mode a non-empty live database also needs `replace_existing=True`. The one genuinely destructive tool in AI-Prowler. Renamed from `restore_database`. |

> **Server mode:** export, backup and restore are for the owner, managers and staff only — field crew are always refused.

> Export tools (`export_to_excel`/`export_to_csv`/`export_to_quickbooks_csv`) and backup/restore tools solve **different** problems — see **Data Portability** below for which to reach for.

### Importing from QuickBooks (Conversational Import)

AI-Prowler does not connect directly to QuickBooks. There are no QuickBooks buttons, OAuth flows, or logins in the app. Instead, imports happen conversationally through Claude, Muse, or Grok.

**How it works:**

1. In Claude.ai, open **Connectors** and connect **QuickBooks Online**.
2. Ask Claude, Muse, or Grok to import, by text or voice. Examples:
   - "Import my customers from QuickBooks into AI-Prowler"
   - "Pull last month's invoices from QuickBooks into AI-Prowler"
   - "Mark JOB-4099 as paid — the customer paid $180"
   - "Show me all unpaid invoices"
   - "Which customers owe me money?"

**What gets imported:**
- **Customers** — name, address, contact info, payment terms. Existing customers are matched (by phone, then name + email) and never duplicated. On matched customers, only blank fields are filled in — your service preferences (frequency, time windows, pricing) are never overwritten.
- **Invoices** — invoice details linked to the correct job and customer.
- **Payments and sales receipts** — applied to the matching invoice.

**Data out:** The `export_to_quickbooks_csv` tool writes a QuickBooks-ready CSV for your accountant or for importing back into QuickBooks.

**Where this is introduced:** The Jobs PWA onboarding wizard (Step 1) leads with "Import from QuickBooks (fastest start)" so new users see this option before manual entry.

### create_customer, create_quote, build_daily_route

`update_job_spreadsheet()` only ever edits a row that *already exists* — it can't add a brand-new customer or quote, and building a whole day's route from scratch (rather than one stop at a time) needs its own dedicated logic. These three tools cover that ground.

**`create_customer(updates, filepath="", backup=True)`** — appends a new row to the `Customers` sheet with an auto-generated `CustomerID` in `CUST-YEAR-NUMBER` form (e.g. `CUST-2026-1`): the year comes from the server clock, the number increments within the year, resets each January, and numbers are never reused. Always creates a new row; never use it to edit an existing customer (e.g. marking one inactive) — use `update_job_spreadsheet(sheet_name="Customers", ...)` for that instead.

> *"Add a new customer: Sunshine Grill, 501 Canal St, New Smyrna Beach FL 32168, phone 386-555-0142, biweekly pressure washing"*

**`create_quote(updates, filepath="", backup=True)`** — same append-with-auto-ID pattern for the `Quotes` sheet (`QuoteID (QTE-####)`). Does not compute totals/tax/discount math — pass the amounts you want written directly, mirroring the manual quoting workflow it replaces. To approve or edit an existing quote afterward, use `update_job_spreadsheet(sheet_name="Quotes", ...)`, never `create_quote` again (that would append a second, duplicate row).

> *"Create a quote for Sunshine Grill — pressure washing, $275, valid for 30 days"*
> *"Sunshine Grill accepted the quote — mark it approved"* (→ `update_job_spreadsheet`, not `create_quote`)

**`build_daily_route(route_date, crew="", departure_hour=7, accept_reorder=False, email_link=True, email_to="", backup=True)`** — builds the full optimized route for every job scheduled on a given date and writes it to `Route_Planner`, replacing whatever was there before (Route_Planner always shows exactly one day, never a history — see §10 "Sheets" above). What it does, end to end:

1. Finds every `Jobs_Schedule` row for `route_date` (optionally filtered to one `crew`).
2. Auto-geocodes any matching job missing `Latitude`/`Longitude` and writes the result back to that job's own row — no need to run `geocode_address()` separately first. A job whose address can't be geocoded is excluded from the route and clearly flagged, never silently dropped.
3. Computes the optimal visit order and real drive times (OSRM `/trip`, the same engine `optimize_route()` uses), starting and ending at the address from `get_home_address()`.
4. **Pre-flight savings check:** also computes the drive time for the jobs' *currently scheduled* order (by Start Time). If reordering to the optimal sequence would save 10+ minutes, the tool stops here and returns a comparison — Route_Planner is **not** written yet. Call it again with `accept_reorder=True` to proceed with the faster order.
5. Flags two kinds of scheduling problems as warnings (the route still builds either way — these are advisory, not a block): **LATE ARRIVAL** (the route's computed arrival at a stop is 10+ minutes after that job's own recorded Start Time) and **SCHEDULE OVERLAP** (two jobs that day have overlapping Start Time/Duration windows, independent of routing).
6. Writes the day's stops to `Route_Planner` with a tap-to-navigate link per stop, and **also** persists that same link onto each matched job's own `Jobs_Schedule` row (the `Route Map URL` column) — this is what lets the link survive Route_Planner later being rebuilt for a *different* date, and is what the Jobs App's "today's route" banner and Calendar day view read from.
7. Emails the route link by default (`email_link=True`) once the build succeeds. If email isn't configured, this is skipped with a plain note — the route still builds, and the link is still available as a clickable cell in Route_Planner and the Jobs App either way.

> *"Build the route for tomorrow"*
> *"Plan the route for September 22nd for Carlos"*

Uses the same free Nominatim/OSRM services as `optimize_route()` — no API key needed.

### Job Tracker Database (SQLite)

The job tracker's canonical live store is a SQLite database file, `ai_prowler_jobs.db`. Excel is available as a generated export (`export_to_excel()`) — see **Excel Export**, below — never a live file.

- Every write tool (`create_job`, `create_customer`, `create_quote`, `create_invoice`, `update_job_spreadsheet`, `log_time_entry`, `build_daily_route`, `schedule_next_recurring_job`) writes via a row-level SQLite transaction. Tool names, arguments, and return shapes are exactly what's documented throughout this section — nothing calling these tools (Claude, Muse, or Grok, voice commands, your own prompts) needs to think about the database underneath them.
- Concurrent writes to *different* rows happen in parallel — no whole-file lock. You (or an admin) can have the **Job Board** (see below) open and actively editing all day while field crew clock in/out, upload photos, and create jobs — none of it can block or corrupt anything else.
- The `Jobs_Schedule`/`Customers`/`Invoices`/`Quotes`/`TimeLog`/`Route_Planner`/`Settings`/`Services_Pricing` names live on as the tools' `sheet_name` argument and as table concepts — refer to them the same way in a prompt.
- Crew-scoping rules (field_crew sees only their own assigned jobs; the locked pricing fields on Customers; audit trail columns) apply exactly as documented throughout this section.
- No delete capability anywhere — "retire" means `Status = Inactive`, never destructive.

#### Excel Export

Call **`export_to_excel()`** any time you want a spreadsheet snapshot — one sheet per table, built from whatever's in the database right now. If you (or an accountant) edit that exported file and save it, **those edits go nowhere** — nothing ever reads changes back out of an export. Think of it the same way you'd think of a PDF export: useful to look at, print, or hand to someone, never something to write into.

#### Job Board

A live kanban/grid view of the day's jobs (Scheduled / In Progress / Completed columns), with drag-and-drop to reschedule or reassign.

- **Live updates via 1-minute polling.** The board calls `get_board_updates(since=...)` roughly every 60 seconds and refreshes only the rows that actually changed (clock-ins, photo uploads, completions, any edit) — no manual refresh needed, and no push/SSE infrastructure required.
- **Conflict handling: reload-and-redo, no silent auto-merge.** Every edit carries the row's `last_edited_at` from when it was loaded. If that row changed underneath since then, the write is rejected outright with a clear "this job was updated by [name] at [time] — reload and try again." There's no attempt at field-level merging — genuine same-field conflicts between two people are rare enough that an honest "someone beat you to it" is the right amount of complexity.
- **Personal mode gets the Job Board too — merged into one app, not split off.** In Server mode, the admin Job Board and the crew-facing Jobs App are naturally two different experiences for two different people. In Personal mode there's only ever one person, who is simultaneously admin and field crew — so Personal mode's app shows the Job Board and the crew tools (Clock, Photos, etc.) side by side in one unified navigation, with no role-based screen-hiding.
- **Server mode — each crew's route is independent.** Routes are keyed by date *and* crew, so each crew's stops live in their own independently addressable rows — building Sam's route never touches Vicki's, and admin/staff/manager can see every crew's route for the day at once.
- **No missed changes.** Change times are recorded to the millisecond, so two changes made within the same second (a job created and then marked In Progress straight away, say) both reach every open Board on the next poll.
- **A drag always sticks.** If you drag a card while the Board is still loading, refreshing (↻), or in the middle of its 60-second check, that load's result is from *before* your move — the Board recognises this and ignores it instead of putting the card back in its old column. The next check picks everything up.

#### Multi-day jobs and Working Days

A job can last more than one day — a roof, a fence, a renovation. Give it an **End Date** (or an **Est. Duration** with **Est. Duration Unit** = *day*, and the End Date is worked out for you), and the job appears on each of its days on the Calendar, on each day's route, and in each day's job list.

**Working Days** decides *which* of those days count. It's a row in the **Settings** sheet (Database tab → Settings, or ask Claude, Muse, or Grok), default **`Mon,Tue,Wed,Thu,Fri`**:

- A multi-day job is shown, routed and listed only on working days inside its span. The day it was **booked for** always counts, even if that's a Saturday.
- A job measured in days gets its End Date by counting working days — a 7-day job starting Monday ends the following Tuesday with Mon–Fri, but the following Monday with Mon–Sat.
- A job still open after its End Date carries over to the **next working day**, so it doesn't drop off the plan while it's running late.
- **Running behind on a project?** Add the weekend: `Mon,Tue,Wed,Thu,Fri,Sat,Sun`. Friendly forms work too — `Mon-Sat`, `Weekdays,Sat`, `Fri-Mon`, `All`. AI-Prowler stores it in one tidy form, and refuses anything it can't read (e.g. a typo like `Wendsday`) with a clear message instead of quietly falling back to Mon–Fri.
- **Changes apply immediately** — no restart and no reload. The server reads the setting fresh every time; saving it in the Jobs App shows *"✓ Working Days applied: …"*, and the Calendar and the Route tab's day list follow straight away (also on other phones the next time they open those screens).
- When the working days change, the End Date of every **open** job measured in days is recounted. Completed and cancelled jobs keep their history.
- In server mode, field crew can't open the Settings sheet, but their Calendar still uses the company's Working Days (through `get_working_days`).
- **In-app switch instead of a sheet edit (2026-10-02):** the Jobs app's Settings now offers a simple **weekday-only vs every-day** choice for Working Days — weekday-only saves `Mon,Tue,Wed,Thu,Fri`, every-day saves `Mon,Tue,Wed,Thu,Fri,Sat,Sun`, the same values the sheet row holds, so everything above applies either way.

#### Customer scheduling preferences & new-job autofill

Each customer record carries scheduling preferences that flow into new jobs, so they don't have to be retyped every visit:

- **Preferred Day(s)** — a Mon–Sun checkbox group on the customer (stored as `Monday/Friday`). When you pick a customer on a new job, its Preferred Day(s) carry over to the job — still editable there for one-off adjustments.
- **Pref. Time Start / Pref. Time End** — two separate columns (`H:MM AM/PM`); either end may be empty. A "before X" window is an empty start plus an end — e.g. start empty, end `10:00 AM` means "any time before 10:00 AM". When scheduling, a missing start or end falls back to the Settings working-hours start/end; the customer record itself stays as entered.
- **Schedule Type** — `Soft` (flexible, the route may move it) or `Hard` (fixed commitment), default `Soft`. New jobs inherit the customer's setting; you can still change it per job.
- Picking a customer on a new job also prefills **Window Opens/Closes** (from Pref. Time Start/End), **Est. Duration** (from Avg Job Duration), and **Service Type** — all editable on the job.

Two advisory warnings watch these preferences — they flag the issue, never block the save:

- **"Preferred day not met"** — the job has Preferred Day(s) set but is scheduled or routed on a day outside that list. Blank preferred days means no preference: no check, no warning.
- **"⚠️ outside window"** — a soft job's scheduled time falls outside its true Start Time / End Time window.

#### Recurring jobs — automatic next-job scheduling

Once a customer has a **Last Service Date**, the next visit schedules itself:

- The next job is created automatically with **Service Date = last service + the customer's Frequency interval**: Weekly +7 days, Biweekly +14, Monthly +1 month, Bi-Monthly +2, Quarterly +3, Semi-Annually +6, Annually +12.
- **Preferred Day(s) (2026-10-21):** if the customer has Preferred Day(s), that date moves **forward** to the next preferred weekday (never earlier) — a Weekly "Thursday" customer always gets a Thursday job, and a monthly rhythm doesn't creep. The Calendar's 🔮 projections follow the same rule. Blank or unreadable Preferred Day(s) = no change.
- It appears on the **Calendar** at its calculated date, and the customer's **Next Sched. Date** reflects it.
- The generated job carries the customer's scheduling preferences (schedule type, time window, duration, service type, preferred days) and is fully editable afterward — adjust or reschedule it like any job.
- One-time customers (blank or one-time Frequency) are skipped — nothing is generated for them.
- **Lead time:** the daily sweep creates jobs due within the next **14 days** (Settings → `Recurring Job Lead Time (days)`), so the rolling 2-week Calendar view stays populated with upcoming recurring work. Overdue recurring customers always generate their next job regardless of lead time.

#### No Sales Tax (tax-exempt jobs)

Some jobs are tax-exempt — resale, nonprofit, out-of-state work. Mark the job itself and the $0 flows through everywhere on its own:

- **Check the box on the job.** In the Jobs App, open the job's edit popup — right after **Payment Status** you'll find the **🚫🧾 No Sales Tax** checkbox. Check it for a tax-exempt job. (Asking Claude, Muse, or Grok or using the tools: it's the `No Sales Tax` column on the job row — `1` = exempt, `0` = taxable, default `0`.)
- **Invoices store $0.00 tax.** When the invoice is created, tax is computed as `(quote − discount) × rate` — for an exempt job that's `$0.00`, and the invoice confirmation shows **"Tax (exempt): $0.00"**. Tax is frozen at invoice creation, so unchecking the box later won't rewrite an invoice you've already sent.
- **Receipts follow automatically.** Receipts pull the tax from the stored invoice, so the $0 carries through with nothing extra to do.
- **Where you'll see it.** Tax-exempt jobs get a **🚫🧾** badge on their Board cards. In **Database → Jobs**, the **Tax Disabled** column (right after the Tax column) shows ✓ for exempt jobs, — for taxable ones.

#### Email Route On Approve


Whether approving a route also emails it out automatically. A Settings-sheet row (Database tab → Settings, or ask Claude, Muse, or Grok) — a simple on/off toggle, **`Enabled`** or **`Disabled`** (default):

- **Disabled (default)** = approving a route never emails it. When you want the route in your inbox, use the **📧 Email Approved Route Now** button on the Jobs page or the Route tab — it sends an approved route on request, any time, and it works regardless of this setting.
- **Enabled** = the route results + link are emailed automatically each time a route is approved.
- Only an **approved** route can ever be emailed — a just-built route is never approved, so trying to email one reports "Email is only allowed for approved routes — approve the route first" instead of sending.
- **Server mode:** the auto-email goes to the requesting user's own email (Admin → Users). The manual button lets any crew member fetch their own copy of an admin-approved route even with this Disabled.
- **Personal mode:** the auto-email uses the SMTP recipient configured in Email Configuration (see §6.5).

#### Customer Reminder Email Enabled

The master switch for sending customer reminders by email. A Settings-sheet row — **`Enabled`** (default) or **`Disabled`**:

- **Enabled (default)** = the **Reports → Customer Reminders** screen's **"Email Selected"** button works normally (and `send_customer_reminders` with `channel=email` sends).
- **Disabled** = that button is grayed out and the send is refused with a clear message — no email goes out.
- Independent of **Customer Reminder SMS Enabled** — either channel, both, or neither can be on.
- This does *not* touch the daily digest (**Customer Reminder Daily Digest**) — that one only ever emails the owner, never a customer.

#### Customer Reminder SMS Enabled

The master switch for sending customer reminders by text. A Settings-sheet row — **`Enabled`** (default) or **`Disabled`**:

- **Enabled (default)** = the **Reports → Customer Reminders** screen's **"Text Selected"** button works normally (and `send_customer_reminders` with `channel=sms` sends).
- **Disabled** = that button is grayed out and the send is refused with a clear message — no text goes out.
- Independent of **Customer Reminder Email Enabled** — either channel, both, or neither can be on.
- Even when Enabled, you still need an SMS provider configured in **Settings → SMS / Text Messaging** (Section 11) for anything to actually send.

#### Route Origin Mode

Where your routes start and end. A Settings-sheet row with two values — **`Jobs Only`** (default) or **`Company Location`** (added 2026-09-29):

- **Jobs Only (default)** = the route is your scheduled jobs in order. Your home address counts as the start and end for mileage, but the phone's tap-to-navigate link starts from your live GPS location (which is not a stop), visits each job, and ends at your home address.
- **Company Location** = the **Start/End Address** below is added as the first and last stop of the route. The navigation link starts from your live GPS location, goes to the Start/End Address, then your jobs, then back to the Start/End Address — and on to your home address (if you decide not to go home, just end the route manually).
- The Start/End Address can be different from the **Business Address** — your yard, office, or shop isn't always where the invoices say you are.
- Not to be confused with `build_daily_route()`'s `origin` *tool parameter* — that's a per-call routing input; this setting is the standing choice for where your routes begin and end.

#### Start/End Street Address

The street line of the start/end address used when **Route Origin Mode** is set to **Company Location**. A plain Settings-sheet row — not a toggle, so there's nothing to switch on or off; just fill it in once (with the City/State/ZIP rows below). The Route Origin Mode form re-saves the current values automatically when Company Location mode is used, so switching modes won't lose them.

#### Start/End City

The city part of the start/end address (see **Start/End Street Address** above). A plain Settings-sheet row, not a toggle — only used when **Route Origin Mode** is **Company Location**, and re-saved automatically by the Route Origin Mode form in that mode.

#### Start/End State

The state part of the start/end address (see **Start/End Street Address** above). A plain Settings-sheet row, not a toggle — only used when **Route Origin Mode** is **Company Location**, and re-saved automatically by the Route Origin Mode form in that mode.

#### Start/End ZIP

The ZIP part of the start/end address (see **Start/End Street Address** above). A plain Settings-sheet row, not a toggle — only used when **Route Origin Mode** is **Company Location**, and re-saved automatically by the Route Origin Mode form in that mode.

#### Week Plan Distance (miles)

*(New 2026-10-22.)* How close two jobs must be — straight-line miles — to count as "near each other" for the Jobs app's **🗓️ Plan Week with Any AI** (Section 25 → Route). Default **5**. Make it smaller (e.g. `2`) to only pair jobs on the same few streets, or larger (e.g. `10`) for a spread-out service area. Any number from 0.1 to 100; anything outside that is clamped, and a blank or unreadable value means 5. Change it in the Jobs app's Database → Settings, the Setup Center's **Crew routes** step, or by asking Claude, Muse, or Grok. It only decides which jobs are suggested as pairs — it never moves anything by itself.

### Job Tracker Database — File Layout Reference

> **Column headers are what `update_job_spreadsheet()` and `read_job_spreadsheet()` match on — do not rename headers or the tools will fail to find the right columns.** This is the sheet/column layout the SQLite tables mirror, and it's what any export uses too.

#### Server Mode: One Shared Job Database

There is exactly **one** job database, `ai_prowler_jobs.db`, and every server-mode user — every role — reads and writes it. It lives in AI-Prowler's own data folder on the server (`.ai-prowler\jobs_database\` in the home folder of the Windows account the server runs as), deliberately away from Documents/OneDrive so a sync client can never interfere with it. There is no setting for it and no per-user copy; the whole crew always stays in sync.

**Personal mode:** the same single database in your own `.ai-prowler\jobs_database\` folder.

**Server mode:** any `filepath` argument a tool is given is **ignored** — every call uses the one shared database.

**Row-level scoping:** what a user *sees* inside that database depends only on their role. `read_job_spreadsheet`, `get_board_updates`, `update_job_spreadsheet`, `log_time_entry`, `email_invoice` and the route tools restrict **field_crew** to the rows tied to their own name — `Jobs_Schedule` rows where `Crew / Technician` matches them, their own clock-ins in `TimeLog`, and their own route in `Route_Planner`. A blank crew field is treated as unassigned, not as "visible to everyone." Owner, manager and staff (the crew-lead tier) are never restricted. Full table: **Section 9 → Roles and Scopes in the Jobs App**.

> Older versions (spreadsheet era) let you give a user their own tracker by dropping a `<user_id>.xlsx` file next to the master. That no longer exists — v9.2 removed the last of it.

**Concurrent writes:** handled at the row level by SQLite (see **Job Tracker Database (SQLite)** above). Two crew members writing to *different* rows proceed in parallel — no queuing, no waiting on each other. Two writes to the exact *same* row are resolved safely and in order (SQLite's own row-level locking), and the Job Board's stale-write rejection (reload-and-redo, no silent auto-merge) is what surfaces a genuine same-row conflict to the person making the second edit, rather than either silently overwriting the other.

#### The Jobs App (Server Mode)

Beyond talking to Claude, Muse, or Grok directly, each server-mode employee also gets a dedicated mobile app screen for the field — reachable at `/jobs/` on your tunnel URL, installable to the phone's home screen like any other app ("Add to Home Screen," no app store).

- **Filtered by role** — field crew see only their own jobs, using the exact same row-level scoping described above; owner, manager and staff see every crew's jobs. Full table: **Section 9 → Roles and Scopes in the Jobs App**.
- **Clock in / clock out**, **attach job photos** straight from the camera, and **email invoices** — all without opening a Claude, Muse, or Grok conversation.
- **Log in once.** An employee enters their name and personal token the first time they open the app; the login persists (stored on the device, not tied to the browser tab or app staying open) until they tap **Sign Out / Change Device** in the app's profile screen, or until the app goes **unused for 30 days** — then it simply asks them to sign in again. Closing or restarting the app never signs them out. (A server restart also ends every session.)
- **Personal mode** gets the same app and the same one-time login screen, but checks the entered password against the single owner token fetched automatically from AI-Prowler's own config — nothing to set up per employee, since there's only one user.

The Jobs PWA App and talking to Claude, Muse, or Grok directly are two paths into the same data, not two separate systems — an employee can clock in from the app in the truck, then later ask Claude, Muse, or Grok "what's my schedule tomorrow?" from the same phone's browser, and both are reading and writing the identical job tracker database.

> **Full tab-by-tab reference, setup, and every feature (including today's route banner, Calendar route indicators, and the Sheet tab's refresh button and clickable map links):** **Section 25 — Jobs PWA App**.

#### Sheets

| Sheet name | Purpose |
|---|---|
| `Customers` | Customer master list — addresses, service type, frequency, email, phone, carrier, access notes |
| `Jobs_Schedule` | All service appointments with route, weather, billing, and status columns |
| `Route_Planner` | ONE day's optimized route at a time per crew, not a history — rebuilt from scratch by `build_daily_route()` each time it's called for a given date+crew (see §10 above); previous rows for that same crew/date are cleared, not appended to. Routes are keyed by date *and* crew, so building one crew's route never touches another crew's route for the same day — see **Job Board** above. |
| `Quotes` | Estimates sent to customers before booking |
| `Invoices` | Billing, payment tracking, AR aging |
| `TimeLog` | Clock-in/clock-out per job via `log_time_entry()` |
| `QB_Daily_Export` | Daily export rows for QuickBooks / accounting software import |
| `Services_Pricing` | Service catalog with base prices, multipliers, and tax categories |
| `AI-Prowler_Commands` | Quick-reference Claude, Muse, or Grok prompt cheat sheet |

---

#### Data Portability — Export, Backup, Restore

Two distinct capabilities cover "give my data to my accountant," "get this into QuickBooks," "back this up," and "move to a new PC" — pick the one that matches what you're doing:

**Capability A — Export for humans/other software** (lossy-by-design, one-way, never a write target):

| Need | Tool | Notes |
|---|---|---|
| Hand data to an accountant / tax preparer | `export_to_excel()` | One workbook, one sheet per table — usually all a bookkeeper needs |
| Same, but as plain files | `export_to_csv()` | One `.csv` per table; scope with `tables=[...]` if you only need a couple |
| Import into QuickBooks Online | `export_to_quickbooks_csv()` | Customers/Invoices columns pre-labeled with QBO's own field names — QBO's own "map your fields" screen still appears (that's built into QBO's importer, not something any export can skip), but the mapping is fast because the column names already match |

**Capability B — Backup/Restore** (lossless, round-trippable, operates on the database file itself):

| Need | Tool | Notes |
|---|---|---|
| Keep a safety backup | `backup_job_database(destination_path="")` | Uses SQLite's own online Backup API — safe to run even while the database is being actively written to. Defaults to `backup/AI-Prowler-Backup-<timestamp>.db` next to the live database if no destination is given. |
| Move to a new PC | `backup_job_database()` on the old PC → copy that one file → `restore_job_database(<path>, confirm=True)` on the new PC | A full-database restore *is* the migration — there's no separate migration wizard. The new PC's database is empty, so no extra step is needed. |
| Recover from a bad state | `restore_job_database(backup_path, confirm=True)` (server mode: plus `replace_existing=True`) | Always takes a safety backup of whatever's currently live **before** overwriting it, and validates the incoming file actually looks like an AI-Prowler database first. Requires `confirm=True` — a first, unconfirmed call makes no changes and shows the live-vs-backup record counts. In server mode, a live database that already has records is only replaced when `replace_existing=True` is passed as well. |

> **Restore safety (server mode):** restore is meant for setting up a new PC. If the server's job database already has jobs, customers, invoices, quotes, time entries or route stops, restoring would wipe them. So: through Claude, Muse, or Grok, a restore is refused unless you explicitly say to wipe the current data; with the ♻️ Restore from Backup button, you see both record counts and must type **REPLACE** to go ahead. Either way a safety copy of the current data is made first. Only the owner, managers and staff can export, back up or restore — field crew are always refused.

> **Scheduled automatic backups:** the "Your Business Data" panel (Small Business tab — see below) has a Backup & Restore row with a Weekly/Monthly dropdown that reuses the same scheduler as automatic Excel exports. Off by default; turning it on schedules the first run immediately.

**The write-safety backup mechanism is separate.** Every write tool already makes its own timestamped safety copy (`_backups/ai_prowler_jobs_<timestamp>.db`) before writing, purely to protect against a bad write corrupting the live file — that's automatic, local-only, and not the same thing as a user-facing "give me a backup right now."

**"Your Business Data" panel (Small Business tab):**

- The database itself has no folder setting — it always lives in `.ai-prowler\jobs_database\` (see *Server Mode: One Shared Job Database* above).
- **Share your data:** 📤 Export to Excel · 📄 Export to CSV · 📖 Multi-Employee & QuickBooks Guide
- **Backup & Restore:** 🗄️ Backup Now · ♻️ Restore from Backup (shows how many records are live now and in the backup; in server mode a non-empty database needs you to type REPLACE) · a Weekly/Monthly scheduled-backup dropdown

---

#### Customers sheet columns

| Column | Description | Example |
|---|---|---|
| `CustomerID (CUST-YYYY-N)` | Unique customer ID — referenced by Jobs_Schedule and Invoices. Year-numbered: the year comes from the server clock, the number increments per year, resets each January, and numbers are never reused. | `CUST-2026-1` |
| `Customer Type Comm/Res` | Commercial or Residential | `Commercial` |
| `Company Name` | Company name (commercial customers) | `Sunshine Realty LLC` |
| `First Name` | Contact first name | `Karen` |
| `Last Name` | Contact last name | `Walsh` |
| `Phone` | Primary phone number | `386-555-0101` |
| `Email` | Customer email — used by `send_email()` for lookup by name | `karen@sunshine.com` |
| `Street Address` | Street — used by `geocode_address()` and `optimize_route()` | `125 Harbor Blvd` |
| `City` | City — used for geocoding | `New Smyrna Beach` |
| `State` | State | `FL` |
| `ZIP` | ZIP — used for geocoding | `32168` |
| `Service Type(s) Win/Press/Both` | Services this customer receives | `Both` |
| `Frequency` | How often the customer is serviced — drives automatic recurring-job scheduling (Weekly +7 days, Biweekly +14, Monthly +1 month, Bi-Monthly +2, Quarterly +3, Semi-Annually +6, Annually +12). Short codes W/BW/M/BM/Q/SA/A also accepted. | `Monthly` |
| `Schedule Type` | `Soft` (flexible — the route can move it) or `Hard` (fixed commitment). New jobs inherit it; changeable per job. | `Soft` |
| `Preferred Day(s)` | Preferred service days, picked from a Mon–Sun checkbox group | `Monday/Friday` |
| `Pref. Time Start` | Preferred window start (`H:MM AM/PM`), or empty for "no start requirement" | `7:00 AM` |
| `Pref. Time End` | Preferred window end (`H:MM AM/PM`), or empty for "no end requirement" | `10:00 AM` |
| `Avg Job Duration (min)` | Typical job length for scheduling | `90` |
| `Standard Quote ($)` | Default quote amount | `350` |
| `Discount (%)` | Default discount percentage (decimal) | `0.1` (= 10%) |
| `Gate Code / Access Notes` | Entry instructions for field crew | `Gate code 4421` |
| `On-Site Contact` | Who to ask for on arrival | `On-site mgr: Tom` |
| `Cell Carrier` | Legacy field — not read by `send_sms()`. The email-to-SMS carrier-gateway path this supported was removed (see §6.4 → SMS & WhatsApp Tools); `send_sms()` now sends via a configured Twilio/SignalWire/Vonage provider using the `Phone` column instead. | `Spectrum Mobile` |
| `SMS Gateway` | Legacy field — not read by `send_sms()`, for the same reason as `Cell Carrier` above. | `@mypixmessages.com` |
| `Status Active/Inactive` | Whether customer is currently active | `Active` |

---

#### Jobs_Schedule sheet columns

| Column | Description | Example |
|---|---|---|
| `JobID (JOB-####)` | Unique job ID — linked to Invoices and TimeLog | `JOB-0001` |
| `CustomerID (Customers!A)` | Foreign key to Customers sheet | `CUST-0001` |
| `Customer Name / Company` | Display name | `Sunshine Realty LLC` |
| `Customer Type` | Commercial or Residential | `Commercial` |
| `Street Address` | Address for geocoding and routing | `125 Harbor Blvd` |
| `City` | City | `New Smyrna Beach` |
| `State` | State | `FL` |
| `ZIP` | ZIP | `32168` |
| `Latitude (AI Geocode)` | Auto-filled by `geocode_address()` | `28.9831` |
| `Longitude (AI Geocode)` | Auto-filled by `geocode_address()` | `-80.8512` |
| `Service Date` | Scheduled date (YYYY-MM-DD) | `2026-03-30` |
| `Day of Week` | Auto-filled day name | `Monday` |
| `Start Time` | Scheduled start (`H:MM AM/PM`) | `8:00 AM` |
| `End Time` | Scheduled end (`H:MM AM/PM`) | `9:30 AM` |
| `Schedule Type` | `Soft` (flexible) or `Hard` (fixed commitment) — inherited from the customer on new jobs, changeable per job | `Soft` |
| `Preferred Day(s)` | Preferred service days, inherited from the customer. Scheduling or routing the job on another day raises a "preferred day not met" warning; blank means no preference, no warning. | `Monday/Friday` |
| `Service Type` | Window / Pressure / Both | `Window` |
| `Service Details / Notes` | Job-specific instructions or scope | `Full exterior — 12 windows` |
| `Crew / Technician` | Assigned crew member | `Mike C.` |
| `Est. Duration (min)` | Estimated job time | `90` |
| `Actual Duration (min)` | Filled by `log_time_entry()` after completion | `86` |
| `Route Stop #` | Stop order in optimized route — filled by `optimize_route()` | `1` |
| `Route Map URL` | Google Maps link — filled by `build_maps_url()`, or persisted here per-job by `build_daily_route()` so the link survives Route_Planner later being rebuilt for a different date | `https://maps.google.com/...` |
| `Weather Check` | Weather note — filled by `get_weather()` | `Partly cloudy 81°F` |
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
| `No Sales Tax` | `1` = tax-exempt job — invoices compute $0 tax (total = quote − discount only); shows a 🚫🧾 badge on Board cards | `0` |

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

To log time: *"Clock me in on job JOB-0003"* → Claude, Muse, or Grok calls `log_time_entry()` and writes a new row. *"Clock out"* → Claude, Muse, or Grok fills the Clock Out time and calculates Elapsed automatically. The job must be specified precisely enough to match exactly one row in Jobs_Schedule — a vague identifier matching several jobs returns a list of candidates instead of guessing.

---

#### update_job_spreadsheet() — Column name reference

When Claude, Muse, or Grok writes back to the job tracker, it matches on the **exact column header text** — the same field labels shown on the Jobs PWA App's own edit forms. Multi-line headers (carried over from the original Excel template) use `\n`. Most commonly updated columns:

```python
{
"Job\nStatus":               "Complete",
"Actual\nDuration (min)":    86,
"Actual\nAmount ($)":        185.00,
"Discount\nApplied ($)":     0,
"Payment\nStatus":           "Paid",
"Invoice\nSent Date":        "2026-06-25",
"Route Stop #":   1,
"Latitude\n(AI Geocode)":    28.9831,
"Longitude\n(AI Geocode)":   -80.8512,
"Route Map URL\n★ AI Prowler": "https://maps.google.com/...",
"Weather Check\n★ AI Prowler": "Partly cloudy 81°F",
}
```
### Typical Small Business Contractor Workflow

The following is a recommended day-to-day workflow for a small contracting business using AI-Prowler and the Jobs PWA App as the day-to-day view of the job tracker. Claude, Muse, or Grok handles the data work; you focus on the jobs.

---

**Step 1 — Morning Planning (5 minutes, from your phone)**

Tell Claude, Muse, or Grok:
> *"What jobs do I have today?"*

Claude, Muse, or Grok calls `read_job_spreadsheet` with today's date filter and reads back your schedule — customer names, addresses, service types, and any notes.

Then tell Claude, Muse, or Grok:
> *"Optimize my route for today and give me a Google Maps link."*

Claude, Muse, or Grok calls `geocode_address` for each stop, calls `optimize_route` to solve the Traveling Salesman Problem, then calls `build_maps_url` to generate a tap-to-navigate link with all stops pre-loaded in optimal order. Tap the link on your phone — it opens directly in Google Maps or Apple Maps.

---

**Step 2 — Weather Check**

Tell Claude, Muse, or Grok:
> *"What's the weather for my area today? Any rain?"*

Claude, Muse, or Grok calls `get_weather` and flags any rain probability ≥ 50% so you can decide whether to reschedule outdoor work.

---

**Step 3 — At the Job Site (from your phone)**

Before starting work, Claude, Muse, or Grok can answer questions about the customer, the job history, or the service type — all from your indexed knowledge base.

If you need to send the customer a message:
> *"Send Mike Johnson a text that we're 20 minutes out."*

Claude, Muse, or Grok calls `send_sms`, looks up Mike in the Customers sheet, finds his cell number and carrier, and sends the message. If Mike replies, `check_sms_replies` will show his response.

---

**Step 4 — Job Completion**

When the job is done, tell Claude, Muse, or Grok:
> *"Mark the Johnson job complete. I charged $185, took 2 hours."*

Claude, Muse, or Grok calls `update_job_spreadsheet` to update the row: status = complete, actual amount = $185, duration = 2 hours — the same change reflected instantly on the Jobs PWA App's Board and Database tabs. It auto-backs up the database before writing.

---

**Step 5 — Invoice or Quote**

Tell Claude, Muse, or Grok:
> *"Send the Johnson invoice to mike.johnson@email.com."*

Claude, Muse, or Grok calls `send_email` with the invoice details. If you have a generated invoice file, Claude, Muse, or Grok calls `send_file` to attach it.

---

**Step 6 — End of Day Debrief**

Tell Claude, Muse, or Grok:
> *"Log what I learned today — that pressure washing aluminum siding needs lower PSI or it dents."*

Claude, Muse, or Grok calls `record_learning` and stores it in the self-learning knowledge base, stamped with your name. Next time a siding job comes up, Claude, Muse, or Grok will recall this automatically.

---

**Step 7 — Add a New Customer**

When you land a new customer:
> *"Add a new customer: Sarah Connelly, 456 Oak St, Orlando FL 32801. Window cleaning, monthly service. Cell: 407-555-1234, Carrier: Verizon."*

Claude, Muse, or Grok calls `create_customer()` and appends the new record to the Customers sheet, including the phone number and carrier for future SMS messaging.

---

**Step 8 — Quote, Then Build the Day's Route**

Before booking a job, send a quote:
> *"Create a quote for Sarah Connelly — window cleaning, $185, valid for 30 days."*

Claude, Muse, or Grok calls `create_quote()`. Once she accepts:
> *"Sarah accepted — mark the quote approved and schedule the job for next Tuesday."*

When the day arrives, instead of manually chaining `geocode_address` → `optimize_route` → `build_maps_url` for each job (Step 1 above), one call handles the whole day:
> *"Build today's route."*

Claude, Muse, or Grok calls `build_daily_route()` — it geocodes anything missing automatically, computes the optimal order and real drive times, flags any job that's now running late or overlapping another, writes the route to Route_Planner with a tap-to-navigate link on every stop, and emails you the link. See §10 above for the full behavior, including the pre-flight savings check if your jobs' scheduled times aren't already in the fastest order.

---

**Example Claude, Muse, or Grok Prompts Quick Reference**

| What you want | What to say to Claude, Muse, or Grok |
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

AI-Prowler supports full two-way SMS and WhatsApp messaging. Field crew can send and receive messages from Claude.ai on their phone — no separate app or desktop required. This includes a configurable outbound message footer, a HELP auto-reply, and a website SMS-consent capture widget so a business can collect opt-ins directly from their own site.

### Provider Support

AI-Prowler uses a provider abstraction layer. Switching between SMS providers is a configuration change, not a code change:

| Provider | Type | Notes |
|---|---|---|
| Twilio | SMS + WhatsApp | Most feature-complete. Recommended. |
| SignalWire | SMS | Twilio-compatible API. Cheaper at volume. Drop-in replacement. |
| Vonage | SMS | Good international coverage. |
| WhatsApp Business API | WhatsApp | Via Twilio. Works worldwide. No carrier gateway issues. |

### Setting Up Twilio for Your Business

This walks through connecting a real Twilio account to AI-Prowler from scratch, in the GUI's **Settings → SMS / Text Messaging** tab.

1. **Create a Twilio account** at [twilio.com/try-twilio](https://www.twilio.com/try-twilio) — trial credit is available, no upfront payment required to start testing.
2. **Get a phone number.** In the Twilio Console, go to Phone Numbers → Buy a Number. Toll-free and local (long code) numbers both work; a toll-free number typically activates faster but has the HELP-keyword limitation described below.
3. **Find your credentials.** On the Twilio Console home page, note your **Account SID** (starts with `AC...`) and **Auth Token** (click "Show" to reveal it) — both live under Account Info on the dashboard.
4. **Enter everything in AI-Prowler.** Open Settings → SMS / Text Messaging, select **Twilio** as the provider, check **Enable SMS Messaging**, then paste the Account SID, Auth Token, and From Number (your new Twilio number, in `+1XXXXXXXXXX` format).
5. **Test outbound.** Enter your own phone number in "Test recipient" and click **Send Test SMS**. If a text arrives, sending works.
6. **Save Config.**
7. **Copy the Inbound Webhook URL.** The same settings panel shows a unique webhook URL for your install (e.g. `https://your-tunnel-domain.ai-prowler.com/sms-webhook`). Click Copy.
8. **Paste it into Twilio.** In the Twilio Console, open your phone number → Messaging Configuration → "A message comes in" → paste the copied URL, set the method to **HTTP POST**, and save.
9. **Test inbound.** Text your Twilio number from your own phone, then ask Claude, Muse, or Grok "check my SMS inbox" (`check_sms_inbox` in personal mode, `check_sms_replies` in server mode). The message should appear within seconds — no polling delay.

### Inbound Messages — Webhook Architecture

AI-Prowler captures inbound SMS and WhatsApp messages in real time via webhook endpoints registered on the HTTP server:

- `/sms-webhook` — receives inbound SMS from Twilio/SignalWire/Vonage
- `/whatsapp-webhook` — receives inbound WhatsApp from Twilio
- `/consent-signup` — receives website opt-in form submissions (see **SMS Consent Capture** below)

Messages are stored locally in `sms_inbox.json` and isolated per crew member (thread isolation). There is no polling — messages arrive instantly when the webhook fires.

### Outbound Message Footer — Callback Signature & STOP Disclosure

Every message sent via `send_sms` can automatically carry two short lines appended to the end, both configured in Settings → SMS / Text Messaging:

- **Callback signature** — a free-text line (e.g. *"Call/text David back: 480-747-0358"*) so a customer who doesn't recognize the business's SMS number knows how to reach a real person. Leave blank to disable.
- **Include "Reply STOP to opt out"** — checkbox, on by default. Adds the standard opt-out disclosure line that carriers and TCPA generally expect on business texts. Twilio separately auto-blocks future delivery to any number that replies STOP regardless of this setting — the checkbox only controls whether the disclosure *text* itself is included in outbound messages.

### HELP Auto-Reply

Optionally configure a message Claude, Muse, or Grok sends automatically when a customer texts **HELP** — typically your support contact info plus a STOP reminder. Configured in the same SMS settings panel. Leave blank to send no reply, which is the safe default: a blank field means no message goes out pointing customers at the wrong business.

> **Platform limitation:** on Toll-Free US numbers that aren't part of a Twilio Messaging Service, Twilio intercepts HELP at the carrier level and replies with its own canned message before it ever reaches AI-Prowler — this setting has no effect for those numbers, and the message never appears in `check_sms_inbox`. STOP and START are unaffected and always reach AI-Prowler normally regardless of number type. To customize HELP's reply on a Toll-Free number, the number needs to be placed in a Twilio Messaging Service with Advanced Opt-Out enabled — that's a Twilio Console configuration, not an AI-Prowler one.

### SMS Consent Capture — Website Opt-In Widget

Every AI-Prowler install can collect SMS opt-in signups directly from the business's own website — fully decentralized, with no data passing through AI-Prowler LLC's infrastructure. Each business's consent records live only on that business's own AI-Prowler install, the same way inbound SMS already does.

**How it works**

1. AI-Prowler exposes a public `/consent-signup` endpoint alongside the existing SMS webhooks. Find your install's unique URL in Settings → SMS / Text Messaging → **SMS Consent Form Endpoint URL**.
2. Embed a small widget script on your website, pointed at that URL.
3. When a visitor submits the form, their name, phone number, and consent choice are recorded locally in `sms_consent.json` — instantly available to ask Claude, Muse, or Grok about.

**Embedding the form**

The widget script is hosted once at `https://ai-prowler.com/consent-widget.js` and used by every AI-Prowler customer. Two ways to use it:

*Fastest — auto-rendered default form:*
```html
<div data-ai-prowler-consent-widget></div>
<script src="https://ai-prowler.com/consent-widget.js"
data-endpoint="YOUR_CONSENT_FORM_ENDPOINT_URL"></script>
```

*Full control — your own custom-styled form:* build the HTML yourself with fields named `name` and `phone`, and a `consent` checkbox, add `data-ai-prowler-consent-form` to the `<form>` tag, and include the same script tag. The widget only wires up the submit handler over `fetch()` — your styling is untouched.

**Reading the list**

Ask Claude, Muse, or Grok *"who's opted in for SMS?"* or *"show me my consent list"* — calls `list_sms_consents`. Filter to only currently opted-in contacts, or see everyone including people who submitted the form without checking the consent box, useful for a full audit trail.

**Staying in sync with SMS replies**

If someone who signed up on the website later replies **STOP** to a text, AI-Prowler automatically flips their consent record to opted-out — the list stays accurate without manual bookkeeping. Replying **START** or **UNSTOP** restores it, preserving their original signup details (name, signup date, source).

**Deleting a record**

For a CCPA/GDPR-style removal request, ask Claude, Muse, or Grok *"delete the consent record for [phone number]"* — calls `delete_sms_consent`. This permanently erases the record, unlike an opt-out (via STOP) which just marks it inactive while keeping the history.

### Using Claude, Muse, or Grok as Your Twilio Setup Assistant — What to Expect

Claude, Muse, or Grok can walk through the entire Twilio setup and troubleshooting process conversationally, but it's worth knowing the actual division of labor:

- **Claude, Muse, or Grok cannot log into your Twilio Console directly** — there's no browser automation into Twilio's dashboard. You click through the Twilio Console yourself; Claude, Muse, or Grok tells you exactly where to go and what to enter.
- **Claude, Muse, or Grok can fully inspect the AI-Prowler side** — current SMS settings, the server log, whether a webhook request actually arrived, and the contents of the local SMS inbox and consent list — to pinpoint exactly which step is failing rather than guessing.
- **Screenshots close the loop.** If something looks wrong, a screenshot of the relevant Twilio Console page (phone number configuration, messaging logs, etc.) lets Claude, Muse, or Grok review it directly and spot common mistakes — wrong webhook URL, wrong HTTP method, a setting that didn't actually save.
- **Real test texts are the fastest way to verify.** Sending a real text and then asking Claude, Muse, or Grok to check the inbox is more reliable than reasoning about configuration in the abstract — it either shows up or it doesn't.

**The most common setup problems, in order of likelihood:**
1. The webhook URL wasn't actually saved in the Twilio Console (always double-check by re-opening the page after saving).
2. The AI-Prowler server or Cloudflare Tunnel isn't running, so the webhook has nowhere to reach.
3. Account SID / Auth Token typo, or the wrong pair (e.g. an API Key's SID/Secret instead of the account's main Auth Token — signature validation specifically needs the main Auth Token).
4. HELP not being received — check whether the number is a standalone Toll-Free number first (see the platform limitation above) before assuming it's an AI-Prowler configuration issue.

### Recipient Lookup

When you say *"text Mike"*, Claude, Muse, or Grok resolves the recipient by searching:

1. **Registered server users** — names and phone numbers from `users.json` (set in Admin tab)
2. **Job tracker customers** — names and phone numbers from the Customers table (the same list shown in the Jobs PWA App's Sheet tab), columns: Phone, Cell Carrier, SMS Gateway

Partial name matches work. If multiple matches are found, Claude, Muse, or Grok asks for clarification.

### SMS vs WhatsApp — When to Use Which

- **SMS (`send_sms`)** — works for any customer with a cell number. Best for quick status updates, ETA messages, and notifications.
- **WhatsApp (`send_whatsapp`)** — works worldwide without carrier restrictions. Best for international contacts, longer messages, and customers who prefer WhatsApp. Both parties need WhatsApp. Requires Twilio WhatsApp Business API setup.

---

## 12. Quick Links Tab

The Quick Links tab is a one-click launcher for the AI apps that connect to AI-Prowler. A mobile subscription enables MCP HTTPS connections to the Claude.ai, Muse.ai and Grok.com web apps — on phone, tablet, or desktop browser.

- 🌐 **Open Claude.ai** — opens claude.ai in your browser
- 🌐 **Open Muse.ai** — opens muse.ai in your browser
- 🌐 **Open Grok.com** — opens grok.com in your browser
- 🚀 **Launch Claude Desktop** — opens Claude Desktop directly (desktop alternative)
- ⬇ **Install Claude Desktop** — opens claude.ai/download in your browser

### Initial Connection Test

Optional — MCP finds AI-Prowler's tools on its own. To check the connection, click **📋 Copy Command**, paste it into a Claude, Muse, or Grok chat and press Enter: it verifies the MCP link is live and lists all available AI-Prowler tools.

### 🤖 Autonomous AI Task Queue

The **Autonomous AI Task Queue** runs your queued analysis tasks — both **Common Business AI Analysis** and **My Custom AI Analyses**, below — on a schedule via Claude Code, without you opening a chat and pasting the run command yourself.

These are AI-assisted tasks that can be queued and stored for repeated and/or future execution. Claude, Muse, or Grok has tools to manage, add, and run these task queues via AI-Prowler MCP tools remotely, in addition to the manual configuration described here.

> **Not available in server mode.**

> **Unattended runs work with Claude and Grok.** Claude runs use the Claude Code CLI (via your subscription or an Anthropic API key). Grok runs call the xAI API directly with a Grok API key — no CLI needed. Muse has no API key released yet, so unattended Muse runs aren't possible; with Muse, queue the tasks (**▶ Queue**), then open a Muse chat and paste the run command (**Ctrl+V**).

> **Requires a Claude Pro subscription or higher** to use Claude Code CLI — the free Claude tier does not include Claude Code access. Not required if you use an API Key instead (see Auth, below).

#### The On/Off toggle

A single large button — reading **"Toggle On/Off"** with **"Autonomous AI Task Queue OFF"** beneath it in red, or **"Autonomous AI Task Queue ON"** in green — is the entire control for turning automation on and off. Click it and it flips color and state immediately: green/ON installs (or updates) a Windows Scheduled Task at the time and frequency you've set below; red/OFF genuinely removes the real Windows Scheduled Task (`schtasks /delete`), not just a soft disable. There's no separate checkbox to keep in sync — the button's color and text are always the real, currently-applied state.

Below the toggle, a live status line shows the *actual* Windows-reported state — e.g. **🟢 Armed — Daily at 06:00:00 (next: 7/27/2026 6:00:00 AM)** or **🔴 Not armed** — read directly from `schtasks /query`, not just echoed back from what's typed into the fields above it. This ensures the GUI's own fields never silently drift from what Windows actually has scheduled; you can always tell at a glance whether real automated runs are currently armed.

#### Setup

| Field | Description |
|---|---|
| **Scheduled time** | 24-hour `HH:MM` — the time of the single daily run when **Check queue** (below) is set to 1×/day. Click **💾 Apply** right next to the field to push a change to the real Windows Scheduled Task immediately — editing the field alone has no effect until Apply is clicked or the toggle is cycled. Apply works whether automation is currently on or off, and **flashes green** on click as visual confirmation it took effect. |
| **Check queue: N times/day** | How often the queue itself gets checked for due work — independent of any individual task's own schedule. **1** (default) keeps the classic once-a-day check at Scheduled time above. **>1** switches to an hourly-interval Windows trigger instead (e.g. 10×/day ≈ every 2 hours), checking around the clock. A task still only actually *runs* when it's due per its own schedule — this field only controls how often AI-Prowler looks. |
| **Credit-usage warning** | Appears automatically next to the times/day field once it's set above 1 — a reminder that each automatic check draws from your Claude subscription's usage pool (or metered API billing, if configured that way). Not shown at 1×/day, since a single daily check barely costs anything. |
| **Text me when a run finishes** | Optional SMS/WhatsApp notification, sent to whichever method is selected. |
| **Auth** | **Subscription (OAuth)** — uses your Claude Pro/Max plan; click **🔑 Get / Renew Token** to sign in. **Anthropic API Key (metered billing)** — Claude only; a separate pay-as-you-go account; paste a key from console.anthropic.com and click **Save Key** (and **Clear Key** to remove one). **Grok API Key (xAI)** — Grok only; paste a key from console.x.ai and click **Save Key**. Muse has no API key released yet. |
| **🧪 Test Setup (Dry Run)** | Runs a checklist (Claude Code CLI installed, **Remote access (Bearer Token)** set up, **Running AI-Prowler (local connection)** answering, MCP config current, token/key valid) without actually running any tasks, so you can confirm everything is wired up before turning it on. It never starts anything. |
| **📄 View Audit Log** | Read-only history of past autonomous runs. |

Turning automation on for the first time (off → on) automatically resyncs any overdue custom-task backlog to start from today, rather than firing every accumulated overdue occurrence at once.

**Always uses the AI-Prowler that's already running (2026-10-22).** Every queue run — scheduled or **▶ NOW**, Claude or Grok — talks to this computer's running AI-Prowler over its local connection (`localhost:8000`, never the internet), signed in with this install's Bearer Token so AI-Prowler knows the run is yours. A run **never starts a second copy of AI-Prowler** (two copies on the same database used to make runs slow or hang). What that means for you:

- **Remote access must be set up.** The local connection only exists when there's a Bearer Token (**Settings → Remote Access**). Without one, the queue can't be turned on and **🧪 Test Setup** says so.
- **AI-Prowler starts with your PC.** The installer sets AI-Prowler to start when you sign in to Windows, so it's normally already running when a scheduled run fires.
- **If it isn't running** when a scheduled run fires, the run starts the normal AI-Prowler app (the same way signing in does — on your desktop, never a hidden copy), waits up to **5 minutes** for it, then runs. If it still doesn't answer, the run is **skipped** and says why in the status line, the run log and the audit log — nothing is lost: the tasks stay due and the next run does them. Windows only starts the app while you're signed in. **▶ NOW** never starts anything — the app with the button is the running AI-Prowler.
- The run uses **only** AI-Prowler's own connection, never other MCP servers set up in your Claude account (which might include a second AI-Prowler).
- **Missed runs don't pile up.** If the PC was off for a day, each overdue task runs **once** at the next run and its next due time moves to the next slot after now.

---

### 🧠 Common Business AI Analysis

The **Common Business AI Analysis** section provides five one-click analysis commands that use Claude/Muse/Grok's full reasoning capability over your local data — no API key required, no cloud uploads.

> **Not available in server mode.** This section and My Custom AI Analyses are hidden automatically when AI-Prowler detects `mode=server` in config.json.

An explanatory **💡 How AI Analysis Tasks Work** info card is displayed directly below the section header. It explains the queue-and-paste workflow and directs users to My Custom AI Analyses for scheduling.

Hovering any button shows a one-line tooltip in the status bar describing what that analysis does.

#### How it works

1. Click an analysis button (e.g. **📊 Analyze My Business**)
2. A **Configure** popup opens — set scope, output, schedule, and report folder (see popup fields below). For **🧠 Run Pending Analysis**, no popup appears — the command is copied immediately.
3. Click **Queue Analysis →** — AI-Prowler writes the task to `~/.ai-prowler/pending_tasks.json` and copies the run command to your clipboard
4. Open a new Claude, Muse, or Grok chat and press **Ctrl+V** — **the command runs ALL tasks currently in the queue**
5. Claude, Muse, or Grok calls `get_pending_analysis_tasks()`, reads every queued task, and executes each full analysis using all available AI-Prowler tools
6. Claude, Muse, or Grok records findings as learnings via `record_learning()`
7. Claude, Muse, or Grok calls `complete_analysis_task(task_id, summary)` to mark each task done and auto-advance the next due date if a schedule was set

This approach works entirely within the MCP architecture — Claude, Muse, or Grok is the reasoning engine, AI-Prowler is the data server. No Anthropic API key is needed in AI-Prowler itself.

#### Analysis buttons

| Button | What it does |
|---|---|
| 🧠 **Run Pending Analysis** | Copies the run-queue command to clipboard immediately — no popup. Opens a small info box reminding you to press Ctrl+V in Claude, Muse, or Grok. Each queued task already has its own scope, output, and schedule from when it was created. |
| 📊 **Analyze My Business** | Full business health check. Uses QuickBooks (invoices, payments, customers, P&L, AR aging) if connected; otherwise reads job tracker data (the same data shown in the Jobs PWA App). Searches indexed documents and learnings. Records 3–5 `business_insight` learnings. |
| 💡 **Weekly Business Advisor** | End-of-week debrief. Uses QuickBooks (invoices/payments this week, cash in vs out, overdue this week) if connected; otherwise reads the job tracker. Also checks weather for next week's scheduling. Records `weekly_review` learnings. |
| ⚠️ **Find Problems** | Scans for overdue invoices by aging bucket (using QuickBooks AR/AP aging if connected, otherwise AI-Prowler AR report), jobs over estimate by >20%, unanswered customer SMS, unresolved problem flags. Records each as a `problem_flag` learning. |
| 📈 **Growth Opportunities** | Mines financial data for growth signals. With QuickBooks: P&L by service type, net margin per service, seasonal revenue trends, customer value rankings. Without QuickBooks: job history, fast-paying customers, geographic clusters, upsell pairs. Records 3–5 `growth_opportunity` learnings. |

> **🔌 QuickBooks Integration:** If you connect the QuickBooks Online MCP connector in Claude.ai (Settings → Connectors), Claude, Muse, or Grok will automatically detect it when executing any of these analyses and use QuickBooks as the primary financial data source — giving you real P&L, true net margins, expense ratios, AP aging, and cash flow data that goes beyond what the job tracker can provide on its own. No configuration change needed in AI-Prowler; the prompts detect and use QuickBooks automatically at runtime.

**Importing from QuickBooks into the job tracker.** With the QuickBooks connector connected in Claude.ai, you can also ask Claude, Muse, or Grok conversationally to pull data from QuickBooks into the Jobs database — for example: *"Import new customers from QuickBooks,"* *"Import this month's QuickBooks invoices and link them to jobs,"* or *"Import QuickBooks payments and update job payment statuses."* What Claude, Muse, or Grok does:

- **Customers:** queries QuickBooks customers, matches against the Jobs DB (by phone, then name + email), and creates only the new ones (`CUST-####`, never reusing numbers). On matched customers it fills in blank fields only — never overwrites your service preferences (frequency, time windows, pricing).
- **Invoices:** imports QuickBooks invoices, links each to its job by customer + date, and writes the invoice ID back onto the job. Already-imported invoices are skipped, so re-running is safe.
- **Payments:** applies QuickBooks payments to their invoices (`amount paid`, `payment date`, `payment method`, Paid/Partial status) and cascades the status to the linked jobs.
- **Receipts (sales receipts):** creates paid-in-full invoice records and stamps the job's receipt-sent date.

Claude, Muse, or Grok always previews counts and matches before writing anything, so you can review before it commits. (There are no QuickBooks buttons in the app itself — that would require building Intuit OAuth into AI-Prowler, which isn't included; the conversational path above is the supported workflow.)

#### Configure Popup

When you click any button except 🧠 Run Pending Analysis, a scrollable **Configure** popup opens (806×980). All fields are always reachable by scrolling with the mouse wheel.

| Field | Description |
|---|---|
| **Analysis** | Read-only — shows the button name |
| **What this does** | Green info box explaining what data will be read and what output will be produced |
| **Prompt (auto)** | Collapsed by default. Click **▶ Show prompt** to expand and read the full Claude, Muse, or Grok instruction (read-only). |
| **Scope directories** | Scrollable checklist of all indexed directories. Check one or more to restrict the analysis. Leave all unchecked to search everything. |
| **Output — 💡 Save key insights to Learnings** | Default ✅. Appends `record_learning()` instruction to the prompt. |
| **Output — 📄 Save full analysis as Word document (.docx)** | Default ☐. Appends `save_analysis_report()` instruction with the report folder path. |
| **Output — ✉️ Email the analysis** | Default ☐. Sends the finished analysis via AI-Prowler's own configured SMTP account (`send_email`) — if a Word document is also checked, the report is attached automatically. **At least one of the three outputs must be selected** — a task with none checked has nowhere for its results to go when run unattended, since there's no chat window in a headless run to display them in. |
| **Schedule** | **Manual only** (default) = one-shot, runs once. Choose Daily / Weekly / Every 2 weeks / Monthly / Quarterly / Yearly to make this a recurring task. AI-Prowler tracks when it's next due and surfaces it automatically. |
| **Start time / End time / Times per day** (Daily only) | Shown only when **Daily** is selected. Times per day = 1 (default) runs once, at Start time. Greater than 1 spreads that many runs evenly across the day, landing exactly on Start time and exactly on End time (e.g. Start 08:00, End 20:00, 3×/day → 08:00, 14:00, 20:00). Max 24/day — "24× between 00:00–23:00" is how an hourly cadence is expressed; there's no separate Hourly option. A live **"Runs at: ..."** preview below the fields shows exactly what your settings produce, and the credit-usage warning (below) appears automatically once times/day is set above 1. |
| **First due date** | YYYY-MM-DD. Enabled when a schedule is selected. Defaults to today if left blank. The anchor date for schedule advancement — e.g. a "Weekly" task due June 24 will next be due July 1, then July 8, etc. |
| **Report folder** | Where `.docx` reports are saved. Defaults to `~/Documents/AI-Prowler_tasks_reports`. Click **Browse…** to change. |
| **Ctrl+V reminder** | Italic reminder: *"After clicking Queue Analysis → open a new Claude, Muse, or Grok chat and press Ctrl+V to run all queued tasks."* |

> **Autonomous AI Task Queue usage note:** a static reminder appears in this popup — *"If the Autonomous AI Task Queue is enabled, each automatic check uses Claude subscription usage credits."* This is plain GUI text, not something Claude, Muse, or Grok says in conversation.

> **Scheduling built-in tasks:** When you set a schedule on a Common Business button, `complete_analysis_task()` automatically advances `next_due` after Claude, Muse, or Grok finishes — anchored to the original due date (not the completion date). The entry re-arms — `status` resets to `"pending"` and it stays in the queue permanently, resurfacing in `get_pending_analysis_tasks()` on its own once the new `next_due` arrives. You don't need to re-queue it manually each cycle; only one-shot (`schedule: none`) buttons complete permanently. The next due date is reported back to Claude, Muse, or Grok as `Next scheduled run: YYYY-MM-DD`.

#### Task queue JSON schema

Tasks are stored in `~/.ai-prowler/pending_tasks.json`. The full schema:

```json
{
"task_id":          "analyze_business_20260624_143022",
"type":             "analyze_business",
"label":            "📊 Analyze My Business",
"prompt":           "Analyze my business data...",
"scope_dirs":       ["C:\\Users\\david\\OneDrive\\Documents\\Invoices"],
"output_learnings": true,
"output_report":    false,
"output_email":     false,
"report_folder":    "C:\\Users\\david\\Documents\\AI-Prowler_tasks_reports",
"schedule":         "daily",
"first_due":        "2026-06-24",
"next_due":         "2026-06-25T09:00:00",
"daily_start_time":    "09:00",
"daily_end_time":      "17:00",
"daily_times_per_day": 1,
"created_at":       "2026-06-24T14:30:22Z",
"status":           "pending"
}
```

`next_due` is a full date+time (`YYYY-MM-DDTHH:MM:SS`) for `"daily"` schedule entries — it carries the actual next run time, not just the date — and stays a plain date (`YYYY-MM-DD`) for every other schedule (weekly, monthly, etc.), which have no time-of-day granularity.

When Claude, Muse, or Grok completes the task, a one-shot entry (`schedule: "none"`) has `status` change to `"completed"` permanently — `completed_at` and `completion_summary` are added, and it's kept for audit rather than deleted. A recurring entry instead has `next_due` advanced and `status` reset back to `"pending"` (re-armed) — it stays live in the queue and resurfaces on its own next cycle rather than needing to be re-queued manually.

The collapsible **▶ Show Queue** panel (below the analysis buttons) lets you see what's waiting, remove individual items (✕), or clear everything (🗑 Clear Queue). Each recurring item shows a due badge — 🟢 **Due now** if it's actually ready to run, or ⏳ **Due YYYY-MM-DD** if it's queued but the date hasn't arrived yet — so you can tell at a glance whether something sitting in the queue is about to fire or just waiting. The list also refreshes live the moment a new task is saved & queued while the panel is already expanded, instead of requiring a manual collapse/re-expand.

#### Tips

- Queue multiple analyses before opening Claude, Muse, or Grok — click several buttons in sequence, paste the command once. Claude, Muse, or Grok runs all pending tasks in sequence.
- Findings are stored as learnings and immediately searchable in future Claude, Muse, or Grok conversations via `search_learnings()`.
- Use **🧠 Run Pending Analysis** as a batch shortcut — just click it, press Ctrl+V in Claude, Muse, or Grok, and everything in the queue runs.
- For recurring analyses (weekly review, monthly AR check), set a **Schedule** in the popup instead of clicking the button manually each time.
- **Connect QuickBooks Online** in Claude.ai for richer financial analysis — Claude, Muse, or Grok automatically detects it and uses QuickBooks P&L, true margins, AP/AR aging, and cash flow data without any extra setup.

---

### 📋 My Custom AI Analyses

**My Custom AI Analyses** lets you define your own analysis tasks — with a custom name, prompt, optional directory scope, schedule, and output format. Up to **25** custom tasks are supported.

These user custom-defined tasks are AI-assisted tasks that can be queued and stored for repeated and/or future execution. In addition to manual configuration here, Claude, Muse, or Grok can also create and add these via AI-Prowler MCP tools remotely.

> **Not available in server mode.** Hidden automatically when `mode=server` is detected.

> **AI Route Optimizer task retired (2026-10-22).** The Small Business tab used to create an **"AI Route Optimizer (full reasoning)"** custom analysis here. Route planning is now done from the Jobs app with **📋 Copy AI Route** (Section 25), so that button is gone and the task is removed automatically (with any queued run of it) the first time the new version starts. Your other custom analyses are not touched — and a copy you renamed yourself is kept.

#### Creating a Custom Task

Click **+ New Custom Analysis** to open the task editor (scrollable, 806×884). All fields are always reachable by scrolling with the mouse wheel.

| Field | Description |
|---|---|
| **Name** | Short label shown on the task card (e.g. "Monthly Customer Review") |
| **Prompt** | Full instruction for Claude, Muse, or Grok — describe what to analyze and what to produce. Be specific: mention which tools to use, which learning categories to record under, and any report preferences. |
| **Scope directories** | Scrollable checklist. Only absolute directory paths shown — metadata fields filtered out automatically. Leave all unchecked to search everything. |
| **Schedule** | Manual only / Daily / Weekly / Every 2 weeks / Monthly / Quarterly / Yearly |
| **Start time / End time / Times per day** (Daily only) | Shown only when **Daily** is selected. Times per day = 1 (default) runs once, at Start time. Greater than 1 spreads that many runs evenly across the day, landing exactly on Start time and exactly on End time (e.g. Start 08:00, End 20:00, 3×/day → 08:00, 14:00, 20:00). Max 24/day — "24× between 00:00–23:00" is how an hourly cadence is expressed; there's no separate Hourly option. A live **"Runs at: ..."** preview shows exactly what your settings produce. |
| **First due date** | YYYY-MM-DD. When the first scheduled run should occur. Leave blank for manual-only tasks. Auto-populates with today when you select a schedule. |
| **Output — 💡 Save key insights to Learnings** | Claude/Muse/Grok's prompt instructs it to call `record_learning()` with key findings |
| **Output — 📄 Save full analysis as Word document (.docx)** | Claude/Muse/Grok's prompt instructs it to call `save_analysis_report()` and save a `.docx` report |
| **Output — ✉️ Email the analysis** | Sends the finished analysis via AI-Prowler's own configured SMTP account — attaches the Word document automatically if that output is also checked. **At least one of the three outputs must be selected.** |
| **Report folder** | Defaults to `~/Documents/AI-Prowler_tasks_reports`. Click **Browse…** to change. |

A static reminder — *"If the Autonomous AI Task Queue is enabled, each automatic check uses Claude subscription usage credits"* — appears in this dialog too, matching the Common Business Configure popup.

#### Save / Save & Queue

- **Save** — saves the task definition. It appears in the My Custom AI Analyses list for future use.
- **Save & Queue** — saves the task AND immediately queues it in `pending_tasks.json` and copies the run-all command to clipboard. Paste into Claude, Muse, or Grok to run it right away.

#### Task Cards

Each saved task appears as a card in the list showing:

- Task name and schedule badge (e.g. `Monthly`)
- Due status — e.g. `⚠ Overdue`, `Due today`, `Due in 3 days`, or `Manual only`
- Output badges — `💡 Learnings` and/or `📄 Report`
- **▶ Queue** — adds the task to the pending queue and copies the run-all command to clipboard
- **✎ Edit** — opens the task editor pre-filled with the current settings
- **🗑** — deletes the task (with confirmation dialog)

#### Automatic execution

There is no longer a manual "Run Due Tasks" batch button in this panel — running the whole pending queue unattended on a schedule is now handled by the **🤖 Autonomous AI Task Queue** panel above once turned on, which supersedes it. Individual tasks can still be queued manually at any time via each card's **▶ Queue** button.

#### Custom Task Prompt Example

Here is a well-formed custom prompt for a monthly customer review:

> Review all customers in my job tracker. Identify: (1) customers with no jobs in the last 60 days, (2) customers with 3 or more completed jobs this quarter, (3) any unpaid invoices over 30 days old. Call `read_job_spreadsheet()` for the Jobs_Schedule and Invoices sheets. Record each finding as a learning with category `client_preference` or `problem_flag` as appropriate. Save the full analysis as a Word document via `save_analysis_report()`. Then call `complete_analysis_task(task_id, summary)` with a one-sentence summary of what was found.

#### Custom Task Lifecycle

1. Task created → saved in `~/.ai-prowler/custom_analysis_tasks.json`
2. Task queued via **▶ Queue** (in the GUI, or the same **▶ Queue / ▶ Re-Queue** button in the Remote App, or `queue_single_task()`) — written to `pending_tasks.json` with `status: pending` and its own self-describing `schedule`/`next_due`. Tasks are queued one at a time only; there's no bulk "queue everything that's due" step, since one tap could otherwise start several AI runs (and spend credits) at once.
3. `get_pending_analysis_tasks()` returns it once `next_due` is today or earlier (`is_queue_entry_ready()`) — a task queued ahead of time stays hidden until then
4. Claude, Muse, or Grok picks it up and executes the prompt
5. Claude, Muse, or Grok calls `complete_analysis_task(task_id, summary)` → for a recurring task, `next_due` advances and `status` resets back to `pending` (re-armed, not closed) — same entry surfaces again automatically next cycle. A one-shot (`schedule: none`) task closes permanently instead.
6. Next scheduled run date is auto-advanced from the original anchor date (e.g. Monthly June 24 → July 24, not "30 days from completion")
7. `update_analysis_task()` and `delete_analysis_task()` let Claude, Muse, or Grok edit or remove a task from chat without opening the GUI

#### Shared Scheduling Behaviour (Common Business + Custom)

Both Common Business buttons and Custom Analyses share the same scheduling engine:

- **Anchor-based advancement** — `next_due` advances from the previous `next_due`, not from the completion date. A weekly task due Monday stays on Mondays even if Claude, Muse, or Grok runs it on Wednesday.
- **`complete_analysis_task()` unified re-arm** — built-in and custom recurring tasks are handled by the exact same code path and behave identically: `next_due` advances and `status` resets to `pending`, so the queue entry stays alive and resurfaces on its own next cycle. Custom tasks additionally sync the advanced `next_due` back to `custom_analysis_tasks.json` so the GUI's task list stays accurate. Only one-shot (`schedule: none`) tasks — built-in or custom — close permanently.
- **Queueing is manual, one task at a time** — `queue_single_task()` (or ▶ Queue in the GUI / Remote App) puts one specific task in the run queue now. The old `sync_due_tasks_to_queue()`, which pushed every due custom task in at once, was removed so a single tap can't start several AI runs together.
- **Schedules available:** Manual only, Daily (once a day, or up to 24 evenly spaced runs between a start and end time), Weekly, Every 2 weeks, Monthly. Weekly, every-2-weeks and monthly tasks can be pinned to a weekday. (Quarterly and Yearly were removed — use Monthly.)
- **Default report folder** for all outputs: `~/Documents/AI-Prowler_tasks_reports` (created automatically if it doesn't exist)

---

### ⏰ Proactive Alerts

**Proactive Alerts** is a background scheduler built into AI-Prowler that pushes email alerts to you automatically — no Claude, Muse, or Grok session needed, zero API cost. It runs as a daemon thread inside the AI-Prowler process and checks every 60 seconds whether any job is due.

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

- **🟢 Index healthy / 🔴 Corruption detected** — Checks the ChromaDB index with `PRAGMA quick_check`. Green = healthy, red = corrupted. Clicking red asks for confirmation, then clears and reindexes. Auto-checks when you open the Settings tab and after every reindex.

### Smart Scan Config Tab

- Supported / Skipped extension lists — control which file types are indexed
- Exclude folder patterns — skip specific directories during indexing

### Admin Tab (Business Server Mode Only)

See Section 9 for full details. Appears only when `edition = business` AND `mode = server`.

### SMS Configuration (Settings Tab)

In server mode, SMS is configured in the GUI rather than via Claude, Muse, or Grok:

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
| `.py`, `.js`, `.ts`, `.go`, `.rs`, etc. | Code | Plain text (single security-scan chunk) | Source code is searchable; indexed as one chunk per file |
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
You ask Claude, Muse, or Grok (in English):
"Find all overdue invoices from last month"
↓
Claude, Muse, or Grok calls search_documents()
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
Claude, Muse, or Grok reads Spanish text natively, synthesizes into English answer:
"I found 3 overdue invoices. Torres owes $450 (45 days overdue),
Ramirez owes $280 (32 days overdue)..."
```

### What Is and Isn't Translated

**Nothing is translated.** Spanish text is stored in ChromaDB exactly as extracted from the document. Claude, Muse, or Grok reads it directly — Claude, Muse, or Grok is natively multilingual and reads Spanish fluently. AI-Prowler never calls a translation API.

| Stage | What happens to Spanish text |
|---|---|
| OCR (scanned PDF or image) | Tesseract recognizes Spanish characters with `eng+spa` |
| Text PDF (has text layer) | pdfplumber extracts UTF-8 text — Spanish preserved exactly |
| Word / Excel / etc. | python-docx / openpyxl extract Unicode — Spanish preserved |
| ChromaDB storage | Raw Spanish text stored as-is |
| Embedding | Encoded into multilingual semantic vector — no translation |
| Claude, Muse, or Grok response | Claude, Muse, or Grok reads Spanish natively, responds in the language you asked in |

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

Claude, Muse, or Grok has built-in connector tools for Gmail and Microsoft that allow active search — it is recommended to add those connectors instead of using AI-Prowler to index email files. However, AI-Prowler does support indexing of exported email database files:

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

Proactive Alerts sends scheduled email briefings and alerts without needing an active Claude, Muse, or Grok session — a background daemon thread inside the AI-Prowler desktop process ticks every 60 seconds and fires any job whose configured time/day has arrived. Configured from the Links & Analysis tab.

**Six built-in jobs:** Morning Briefing, Overdue Invoice Alert, Due Analysis Tasks, SMS Reply Monitor, Weather Watch, End-of-Day Summary. Each has its own ON/OFF toggle, a time field (`HH:MM` 24-hour, or `every_Nh`/`every_Nm` for interval jobs), and a days selector (daily / weekdays / weekends / a specific day).

**Recipient and location come from Settings, not this panel.** This panel shows two read-only lines — "📧 Sends to: ..." and "📍 Weather location: ..." — confirming what will actually be used, but neither is editable here. There is exactly one place to change each:

- **Recipient:** set the default recipient in **Settings → Email Configuration** — the same SMTP setup used for every other emailing feature in AI-Prowler.
- **Location:** set your home address (Street/City/State/ZIP) in **Settings → Owner Name → Home Address**. If you've never set one, the panel shows "(not set — ...)" instead of guessing a town.

**Per-job weather:** Morning Briefing looks up weather for **each job's own City/State** (read directly from the Jobs_Schedule table — the same data shown in the Jobs PWA App), since a real day's jobs are often scattered across several towns — rather than one fixed location for the whole day. Weather is fetched once per unique town among the day's jobs, not once per job, so having five jobs in the same town doesn't trigger five lookups. A job with no rain risk shows plainly; a job with a rainy forecast gets a **⚠️ Rain risk** flag right next to it. Your Settings home address is only used as a fallback — when a specific job has no City on file, or when there are no jobs scheduled at all for the day. Weekly Weather Watch always uses your Settings home address, since it's a general week-ahead outlook rather than a per-job breakdown; with no address configured, it simply produces nothing that week rather than reporting on a guessed town.

**Auto-save, no manual Save/Start/Stop:** every field saves the instant it changes — clicking a job's toggle, tabbing out of the time field, or selecting a day all save immediately. There is no separate "Save Config" button and no master "Enable proactive alerts" checkbox. The background engine starts automatically the moment any single job is switched ON, and stops automatically the moment the last enabled job is switched OFF — the engine's running/stopped state is fully derived from the job toggles, never a separate thing to manage.

**Important limitation — this requires AI-Prowler to actually be running.** The scheduler is a thread inside the desktop app's own process, not a separate Windows service. If AI-Prowler is closed, or your PC is asleep, nothing fires — there is no cloud-side scheduler keeping it alive. For a briefing to reliably arrive every morning, AI-Prowler needs to be open (or configured to launch and stay open) at that time.

**Run any job immediately:** each job has a "▶ Now" button that runs it on demand, regardless of its schedule — useful for testing a new configuration without waiting for the next scheduled time.

**View Log:** the one remaining manual control — opens the last 200 lines of `~/.ai-prowler/scheduler_log.txt` in a read-only popup.

---

## 18. GPU Support

AI-Prowler detects NVIDIA GPUs automatically. The installer installs the correct PyTorch build (CUDA 12.8 for RTX 50xx/Blackwell, or CPU-only). The sentence-transformer embedding model (`all-MiniLM-L6-v2`) uses CUDA automatically when available, significantly speeding up indexing. This is the only place a GPU helps — all language reasoning happens in Claude, Muse, or Grok (cloud).

The `all-MiniLM-L6-v2` model is multilingual — it supports English, Spanish, and 100+ other languages in the same semantic vector space. See **Section 15a** for full bilingual language support documentation.

### Blackwell (RTX 50xx) Note

PyTorch stable does not yet include CUDA 12.8 compute kernels for Blackwell SM 12.0+ architecture. Embeddings run on CPU on RTX 50xx cards even though CUDA is detected. This affects only indexing speed, not search quality or Claude/Muse/Grok's reasoning.

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
| Proactive Alerts log | `~/.ai-prowler/scheduler_log.txt` | Every scheduled job run — sent / nothing to report / error, capped at 500 lines |
| File Watchdog log | `~/AI-Prowler/logs/file_watchdog.log` | Real-time auto-indexing activity — every file detected and indexed |
| Scheduled Task (index) log | `~/AI-Prowler/.rag_update.log` | Full output of every Windows-Task-Scheduler-triggered index update |
| Scope-routing skip log (Business Server) | `~/AI-Prowler/logs/index_scope_skips.log` | Shared across the File Watchdog, Scheduled Task, and GUI Update buttons — one line per file skipped because it didn't safely match a collection scope rule |

### MCP Server Log

The MCP log is the most useful for debugging Claude Desktop and Claude.ai connection issues. It captures startup sequence, tool calls, authentication, and subscription checks.

### Common Debug Workflow

**Problem: Claude, Muse, or Grok says it can't find information that should be indexed**
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
1. Run `check_tools_status` — Claude, Muse, or Grok will report which SMS tools are configured and which are missing credentials
2. Check that your Twilio/SignalWire/Vonage Account SID and Auth Token are correct in Settings → SMS Configuration
3. Verify your from-number is correctly formatted (E.164: `+15555551234`)

**Problem: Inbound SMS not appearing (`check_sms_inbox` in personal mode, `check_sms_replies` in server mode)**
1. Verify the HTTP server is running and the Cloudflare Tunnel is active
2. In your Twilio Console, confirm the webhook URL for your phone number is set to `https://your-tunnel-domain/sms-webhook`
3. Check `mcp_server.log` for any webhook POST entries
4. In server mode, `check_sms_replies` only shows replies to threads *you* personally sent — if the reply was to a text a different employee sent, ask them to check instead, or the owner can pull it from `sms_inbox.json` directly.

**Problem: HELP auto-reply not being sent, or a generic message is sent instead of the configured one**
1. Confirm a message is actually entered in Settings → SMS / Text Messaging → HELP reply message — a blank field means no reply is sent by design.
2. Check `check_sms_inbox` for the HELP message itself — if it never appears there at all, Twilio intercepted it before it reached AI-Prowler. This is expected, unavoidable behavior on standalone Toll-Free numbers (see §11 → HELP Auto-Reply); it is not an AI-Prowler bug.
3. If the number is a long code (not Toll-Free) and HELP still doesn't appear in the inbox, treat it the same as any other inbound-SMS-not-appearing problem above.

**Problem: Website consent form submits but nothing shows in `list_sms_consents`**
1. Confirm the `<script>` tag's `data-endpoint` attribute matches exactly the URL shown in Settings → SMS / Text Messaging → SMS Consent Form Endpoint URL (copy-paste it rather than retyping).
2. Verify the HTTP server and Cloudflare Tunnel are running — the endpoint is unreachable if either is down.
3. Open the browser DevTools Console on the page with the form and check for a fetch error after submitting — a "Failed to fetch" with no other detail usually means the tunnel is down or the URL is wrong, not a form problem.
4. If the form has a field named `website`, make sure it's genuinely empty on submission — that field is a spam honeypot and any value in it causes the submission to be silently discarded by design.

### Automatic Cleanup of Background Job Files

The background-jobs spool folder (`~/.ai-prowler/jobs/`) cleans itself: on every server startup and every new background-job launch, files older than **48 hours** are deleted automatically. Stuck "running" jobs get their process checked — dead ones cleaned up, live ones after 2 days killed.

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

The uninstaller removes all AI-Prowler application files and Python (if installed by AI-Prowler), and offers to remove the RAG database, tracking files, self-learning knowledge base, and the job tracker database (default: keep all — safe for reinstall).

---

## 22. Self-Learning System

### Overview

The Self-Learning System gives AI-Prowler a persistent, semantically-searchable memory separate from the main document RAG. When you tell Claude, Muse, or Grok "learn this" — or when Claude, Muse, or Grok detects a correction or insight during conversation — the fact is written to a structured JSON file and indexed in ChromaDB. The next time a related question comes up, Claude, Muse, or Grok calls `search_learnings` first, finds the stored fact, and applies it automatically.

No GPU. No training. New knowledge is queryable within roughly 1 second of being recorded.

### The Self-Learning MCP Tools

| Tool | Purpose |
|---|---|
| `record_learning` | Save a new fact, lesson, or correction |
| `search_learnings` | Semantic search the knowledge base |
| `list_learnings` | Browse by category / status / tag |
| `get_learning` | One learning's full record (JSON) |
| `update_learning` | Modify an existing learning |
| `delete_learning` | Permanently remove a learning |
| `get_learning_stats` | Summary stats — totals, most applied |
| `get_learnings_report` | Return learnings as formatted text in-conversation |
| `export_learnings_file` | Export to JSON pack or spreadsheet file |
| `rebuild_learnings_index` | Rebuild ChromaDB index from JSON data file |
| `send_learnings_report` | Email a formatted HTML learnings report (available to all roles) |

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

**Downloaded but not installed yet (2026-10-21).** **Download Update** only *stages* the new files — they are installed the next time AI-Prowler starts. When the download finishes, AI-Prowler now says so plainly (**"Update downloaded — NOT installed yet"**) and offers **🔄 Restart Now** or **Later**. Restart Now closes AI-Prowler cleanly (same as File → Exit) and starts it again, which installs the update. If you choose Later, a reminder with its own Restart Now button stays on the status bar and on the Home tab (the Server tab in server mode) until the update is really installed — so a server left running can no longer sit on the old version without anyone noticing.

### Footer Text

The footer at the bottom of the Welcome tab can be customized by the AI-Prowler admin via a push to the public GitHub `welcome_ad.json` file. The default text is shown until the network fetch completes.

### Newsletter Opt-In

A dismissible banner — "📬 Get AI-Prowler updates and usage tips by email" — appears on the Home tab for anyone not already subscribed. Enter an email and click Subscribe, or click the ✕ to dismiss it for the current session (it reappears next launch, since it only fully disappears once you've actually subscribed).

**Double opt-in:** clicking Subscribe doesn't add you to the mailing list immediately. It sends a confirmation email first, and the banner changes to "📬 Check your email to confirm your subscription" with a **Dismiss** checkbox next to it. You're only added to the active list once you click the confirmation link in that email — this protects against typos in the email field and confirms the address is actually reachable. Checking Dismiss hides the reminder permanently (not just for the session); if you want it back — for example, to resubscribe with a different address — use **Reset Newsletter State** in Help → Notification Status, which clears your local subscription state entirely and brings back the original Subscribe form.

This is a separate, purely opt-in mailing list — independent of licensing or telemetry. Subscribing or not has no effect on which features are available, and unsubscribing (via the link in any newsletter email) doesn't affect your license or account in any way.

### Setup Center — What the Status Lights Mean

The **Setup Center** is the panel on the Home tab — look for the "🧭 Set up AI-Prowler" header. It’s a step-by-step guide for new users, and for adding new capabilities later (connecting an AI, phone access, the Jobs app, and more). You start by answering "What do you want AI-Prowler to do?" — your answers build your personal setup plan, and the header shows a status light plus "N of M done" so you always know where you stand.

Each step has its own light:

- 🟢 **Green** — the step is done.
- 🟡 **Yellow** — partly done (started, or half-configured).
- 🔴 **Red** — not done yet.
- ⚪ **Grey** — you skipped this step (it can be undone later with the step’s **Undo skip** button).

The overall light follows one simple rule: **red is reserved for the core steps you chose yourself.** Those are the four steps that come with "🔎 Ask questions about my own files" — **Index your first folder**, **Connect your AI**, **Keep your index up to date**, and **Teach AI-Prowler**. If any of those isn’t finished, the overall light stays red.

Everything else shows yellow until it’s done — requirements pulled into your plan automatically (Phone access, the Jobs app, Email), and other steps you chose yourself that aren’t core (crew routes, scheduled analyses). The overall light turns green when every step in your plan is finished.

Two things that never happen: a skipped step never shows red — it counts as decided. And steps you never chose are invisible to the light — they can never turn anything red.

**New installs get a nudge (2026-10-21).** On a brand-new install, **➕ Add a service** blinks red until you've opened (and closed) the service picker, then turns green; next, **🧭 Set up AI-Prowler** blinks red until clicked, and opens straight to the first unfinished step. Existing users never see the blinking.

**Connect your AI** has two tabs: **Claude Desktop** — free, no subscription, nothing to link on your phone — and **Phone / web** for Claude, Grok or Muse on any device (needs the $10/month mobile subscription → activation code → your personal connector URL).

**Scheduled analyses** says up front what it needs: the Claude Code CLI on this PC, signed in with a Claude Pro (or higher) account — with buttons to install it, sign in, or skip for now.

**Crew routes** (2026-10-22): where routes start and end, whether to email a route when it's built, and — new — the **Plan Week distance** (Section 10 → Week Plan Distance (miles)). It explains the Jobs app's any-AI buttons instead of installing Claude Code: there is nothing to install for AI routing any more.

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

## 25. Jobs PWA App

### What It Is

The Jobs App is a mobile-friendly web app for field crew and business owners to manage the day's work without opening a Claude, Muse, or Grok conversation — clock in/out, view the schedule, build and follow routes, take job photos, message customers, and send invoices, all from a phone in the truck. It reads and writes the exact same SQLite-backed job tracker database Claude, Muse, or Grok uses through its MCP tools — the app and talking to Claude, Muse, or Grok are two paths into one dataset, never two separate systems. Since the job tracker's canonical store is a database rather than a spreadsheet you'd open in Excel, **the Jobs App is the primary day-to-day view into that data for a person** — Claude, Muse, or Grok handles conversational and bulk work, the app handles the moment-to-moment tapping-on-a-phone work. Clocking in from the app and later asking Claude, Muse, or Grok "what's my schedule tomorrow?" from the same phone's browser both see the identical, up-to-date data.

### Setup & Access

1. **Turn on Remote Access first** (Section 7) — the Jobs App is served over the same Cloudflare Tunnel used for Claude.ai mobile access. Personal mode: Settings → Remote Access → Start HTTP Server + Subscribe + Configure. Server mode: see Section 9.
2. **Open the app URL** — `https://your-tunnel-domain.ai-prowler.com/jobs/`. The exact URL is also shown on the **Small Business tab** next to "Jobs App URL."
3. **Install to the home screen (recommended)** — **iPhone:** open it in **Safari** → Share → Add to Home Screen. If the QR opened in another browser, copy the link into Safari first (or set Safari as the default in Settings → Apps — the iPhone Camera QR scanner opens links in your default browser, not necessarily Safari). **Android:** open it in **Chrome** and tap the **Install** button on the page (or ⋮ → Install app). It then opens full-screen like a native app, no browser chrome, no app store needed.
4. **Log in once:**
- **Personal mode** — enter your single owner token (the same Bearer Token set in Settings → Remote Access).
- **Server mode** — each employee enters their **name** and their own personal token, set up for them in the Admin tab. What they then see depends on their role: **field crew** see only their own assigned jobs (schedule, board, calendar, route, database rows); **owner, manager and staff** see every crew's jobs. See **Server Mode — Roles and What Each User Sees** below.
5. **Login persists on the device** — not tied to the browser tab or the app staying open. Closing or restarting the app never signs you out. To switch users or sign out, use **Sign Out / Change Device** on the Profile tab.

**Which version is my phone running? (2026-10-21)** A small badge in the top-right corner shows the app's version, e.g. `v9.3.0 · a1b2c3`. Tap it: it checks with AI-Prowler and turns **green ✓ latest**, or **red → v… — tap to update** when a newer app is waiting; tap again to load it. The Remote, HR Admin and HR Portal apps have the same badge. Support may ask you to read it out.

**"Settings aren't filled out" (2026-10-21).** If the business details invoices and receipts need (Tax Rate, Business Name, Address, Phone, Email) aren't all saved yet, a warning lists exactly which ones are missing, and its button opens the Settings card. It disappears as soon as the last one is saved. Field crew, who can't open Settings, never see it.

### Jobs Setup Popup — Skipping What You Don’t Need Yet

When you set up the Jobs app from the Setup Center on AI-Prowler’s Home page, a setup popup walks you through three sections:

1. **Your business** — name, address, tax rate, and the other details printed on invoices and receipts.
2. **Customers** — add your first customer, or import a whole list from a CSV file.
3. **The Jobs app on your phone** — scan the QR code (or copy/email the link), install the app, and sign in.

You don’t have to do everything at once. Sections 1 and 2 each have their own **Skip** button, so you can get going and come back later. Each skipped section shows a note: you can add the data anytime in the Jobs app → Database tab — and the skip clears itself automatically as soon as the real data is entered. Section 3 can’t be skipped: the Jobs setup only counts as complete once the app has signed in from a phone.

### What It Can Do — Tab by Tab

The app has ten bottom-nav tabs: **Jobs**, **Board**, **Route**, **Calendar**, **Clock**, **Photos**, **Messages**, **Database**, **Reports**, **Profile**. (**Reports** appears in personal mode and, in server mode, for the owner only.)

**Jobs** — today's schedule at a glance, split into a **Today** section and an **Upcoming** section. Each job is a card showing its ID, customer, service type, status badge, time window, city, and assigned crew. Tapping a card opens the full job-detail popup: clock in/out for that job, add notes, and — for any unpaid, un-invoiced completed job — a green **🧾 Create Invoice** button that opens a pre-filled form (quote, discount, tax rate, service type, description, payment terms) with a live Taxable / Tax / Total Due strip that recalculates on every keystroke. The job edit form also has a **No sales tax** checkbox (after Payment Status) for tax-exempt jobs — when enabled, invoices compute $0 tax and the job shows a 🚫🧾 badge on Board cards. Once an invoice exists, **Email Invoice** / **Text Invoice** buttons send it directly from the app.
- If today's route has been **approved** (Route tab → Approve — see Section 10), a tappable **"📍 Today's route is ready — tap to navigate"** banner appears at the top of this tab, above the job list. Unapproved/experimental routes show no banner.
- A refresh button (spinning-icon control, top-right) manually re-fetches the list. Simply navigating to this tab also refreshes it automatically — you'll never see stale data just from switching back to it.

**Board** — the live kanban/grid Job Board described in **Section 10 → Job Board**: Scheduled / In Progress / Completed columns, drag-and-drop to reschedule or reassign, polling `get_board_updates()` roughly every 60 seconds so it reflects crew activity without a manual refresh. The exact same markup renders for every role — owner, manager, staff, field_crew — in both Personal and Server mode; what actually differs is only which rows come back from the server (the same crew-scoping every other job-tracker tool applies), never anything role-specific on the client side.

Board columns, order and clean-up (2026-10-23):

| Column | Order (top → bottom) | When a card leaves the Board |
|---|---|---|
| **Unscheduled** (no Service Date) | by Job ID | never — until it gets a date |
| **Scheduled** | oldest date first; within a day, approved route order, then start time | never — a job past its date stays (and says how late it is) |
| **In Progress** | same as Scheduled | never |
| **Complete** | **newest date first**; within a day, route order / start time | **Unpaid or Partial: never. Paid: 7 days after the job's date** (the job's own date, not the day it was marked paid) |
| **Cancelled** | newest date first | 7 days after it was last edited |

- **⏰ N days late** — shown on Scheduled / In Progress cards whose date (end date for a multi-day job) has passed.
- **💳 Unpaid · N days** (or **Partial · N days**, **Not paid · N days**) — shown on Complete cards not paid yet, counting from the job's date.
- Nothing is deleted when a card leaves the Board — the job stays in the Database tab, Reports and every AI tool.

**Calendar** — a rolling 2-week day-by-day agenda, followed by a scrollable 12-month overview grid. Tapping any day, past or future, in either view opens a modal listing that day's jobs.
- The 12-month overview also shows 🔮 dashed **projected** entries for recurring customers' future visits across the full year — view-only planning aids synthesized from each customer's frequency + last service date, landing on the customer's **Preferred Day(s)** when set (2026-10-21). They are not real jobs: they can't be tapped, scheduled, or edited, they never create database rows, and a real job on the same date suppresses its projection. A legend at the top of the overview explains this.
- Any day whose route has been **approved** shows a small tappable **📍** icon — next to the date header in the 2-week agenda, next to the day number in the 12-month grid, and as a full "Route for this day — tap to navigate" banner inside the day-tap modal. Unapproved routes show no icon. This works for *any* date with an approved route, not just today, which is what makes it practical to build and approve routes for several days ahead of time and still have each one reachable later from the Calendar.
- Auto-refreshes every time you navigate to this tab.

**Route** — pick a day, check it for problems (prescreen), build the day's route, adjust the stop order (▲▼, drag ✋, edit ✏️, remove 🗑️), pin stops with 📌 "Fix stop #", approve it, and send the route or a phone link to the crew. Approving (**Approve — Allows Email & Link Viewing**) allows emailing the route and makes its link viewable on the Jobs and Calendar pages — it never changes any job's time window, and un-approving fully undoes it. Where each route starts and ends is set by **Route Origin Mode** (see #### Route Origin Mode). Whether approving a route also emails it automatically is set by **Email Route On Approve** — the **📧 Email Approved Route Now** button sends an approved route on request either way (see #### Email Route On Approve). In server mode field crew work only with their own route.
- **Map size:** drag the bar under the map **down** to make the map bigger, **up** to make it smaller — on a phone and, since 2026-10-21, on a PC too. When map and stop list no longer fit, the Route screen scrolls.
- **The route buttons** (one row, short labels on a phone): **Route Selected Date** (free and instant — orders the jobs by real drive time), **📋 Copy AI Route for Any AI** (📋 Any AI), **🗓️ Plan Week with Any AI** (🗓️ Week) and **📧 Email Approved Route Now**.

**📋 Copy AI Route for Any AI (2026-10-22).** For a smarter plan than Route Selected Date — fixed appointment times respected, soft jobs fitted into the gaps, real drive times — without any Claude CLI or setup:
1. Pick the day (and, in server mode, the crew) and tap **📋 Copy AI Route for Any AI**. The day is pre-checked first (the same prescreen as building a route); if it finds problems you can fix them first or carry on.
2. A sheet shows the prompt, its **route code** (`RT-…`, good for 24 hours) and which AI-Prowler made it. It's already copied (if your phone refuses, tap **📋 Copy**).
3. Paste it into **Claude, Muse, Grok — any AI chat that has AI-Prowler connected** — on your phone or computer, and send. You can watch the AI read the jobs, get the drive times, reason through the order and save the route.
4. When it says it's done, tap **Refresh route** (or reopen the Route tab), review the stops, and **Approve** as usual.

*If you have more than one AI-Prowler connected* (for example your personal one and your company's server), the AI first checks the route code against each and then uses **only** the AI-Prowler that made it — so a route can never be saved to the wrong computer. A code can only change the day (and crew) it was made for. In server mode, field crew always plan their own day.

**🗓️ Plan Week with Any AI (2026-10-22).** Groups nearby work onto the same day:
1. Tap **🗓️ Plan Week with Any AI** and pick the week (any day in it — it starts on the Route tab's week). Tap **📋 Copy week prompt** (`WK-…` code) and paste it into your AI chat.
2. The AI looks at the week and **suggests** moving soft jobs so jobs within the **Week Plan Distance** of each other (Section 10, default 5 miles) share a day. AI-Prowler checks every suggestion: only **soft** jobs move — hard/committed jobs never do — and never onto a past day, a non-working day, or a day outside the job's (or customer's) **Preferred Day(s)**. Only the date changes; the job's time window stays. Closed, in-progress, paused and multi-day jobs stay put. Suggestions that break a rule are turned down with the reason.
3. Back in the app, tap **📥 Check for suggestions**. Each suggested move is listed (job, customer, from → to, and why). **Untick** any you don't want, then **✅ Approve selected** — only the ticked jobs move (each is checked again first; a job that changed in the meantime is skipped). Or **Dismiss** to close the suggestion without moving anything. Nothing changes until you approve.
4. Then route each day as usual (Route Selected Date or 📋 Copy AI Route).

> **The old 🧠 Run AI Route button is gone (2026-10-22).** It ran the Claude Code CLI in the background with each person's own Claude token. 📋 Copy AI Route replaces it: no CLI, no token, nothing to wait on blindly — and it works with any AI chat.

**Clock** — shows active clock-in status and a simple manual clock in/out control, the same underlying action as asking Claude, Muse, or Grok to clock you in or out.

**Photos** — attach job photos straight from the camera or camera roll.

**Messages** — the SMS/WhatsApp thread view, where SMS is configured (Section 11). Checking for new replies is a deliberate manual action (a button press), not automatic, so opening this tab never silently fires an outbound API call.

**Database** — a raw, tab-switchable table view of every table in the job tracker (Jobs_Schedule, Customers, Invoices, Quotes, TimeLog, Route_Planner, Services_Pricing, Settings, Commands) — this is the app's general-purpose, row-level view into the same SQLite database Claude, Muse, or Grok reads and writes, for anything the Board and Jobs tabs don't have a purpose-built screen for. (Labeled "Database" in the app; still called the "Sheet" screen internally and in a few places in this guide — same tab, same name change reflecting that there's no underlying spreadsheet file anymore.) Every row is editable via a generic edit form, and tables that support it have a **+ Add** button for appending a brand-new row.
- A manual refresh button next to the table tabs re-fetches whichever one is currently open, in place — no need to switch tabs away and back just to see new data. Switching between table tabs has always re-fetched fresh data on every switch.
- The Customers table's **⇅ ID** button cycles the CustomerID sort: default order → ascending → descending. It's numeric-aware (`CUST-2026-10` sorts after `CUST-2026-2`), and sorting is view-only — it never changes the database order.
- After you save an edit, the table keeps your scroll position instead of jumping back to the top-left — handy when working across a wide table.
- Any cell whose value is a URL (`Route Map URL`, `Waypoint Map URL`) renders as a real tappable **"📍 Open in Maps"** link — in both the row-edit form and the plain table list view — instead of unclickable raw text.
- Auto-refreshes every time you navigate to this tab.
  - In the **Jobs** table, the **Tax Disabled** column (right after the Tax column) shows ✓ for tax-exempt jobs and — for taxable ones. See **No Sales Tax** in Section 10.

**Reports** — weekly revenue (collected and still owed), hours, **tax collected**, stale customers and customer reminders. Owner only in server mode.
- The **🧾 Weekly Tax Collected** card tracks the sales tax you're collecting, week by week. Each week gets a bar, split two ways: **solid bars = tax actually collected**, **hatched bars = projected/outstanding tax** (what's still owed).
  - The table under it has four columns: **Week**, **Actual Tax**, **Proj Tax**, **Total Tax**.
  - **The math:** collected = invoice tax × (amount_paid ÷ total_due) — a half-paid invoice with $100 of tax counts as $50 collected. Projected = tax − collected. Tax-exempt jobs (`No Sales Tax`) contribute $0.
  - Tax is frozen when the invoice is created — tax = (quote − discount) × rate — so the chart never shifts under you after the fact.
- The **📅 Net Revenue (after sales tax)** card (2026-10-21) shows net revenue month by month: **actual** plus **projected**, with this year's total. Sales tax is taken off invoiced jobs once; a job that isn't invoiced yet is an estimate before tax, so nothing is taken off it.
- **Range (2026-10-23):** **Weeks each direction** now defaults to **52** — a full year back and a year ahead (4, 8, 12 and 26 are still there). Every chart covers that whole range, including the monthly Net Revenue chart, which also shows the total for the whole range. The charts are wider than the screen, so **scroll sideways**; each one opens scrolled to this week / this month.
- **🔮 recurring visits count everywhere as projected** — revenue, tax, hours and Net Revenue — up to the end of the range, even though they aren't scheduled jobs yet. Each visit is valued at the customer's **Net Price** (or Standard Quote less Discount). **If the customer has no price filled in, it uses that customer's most recent priced job** (Quote less Discount), plus 7% projected tax. A customer only gets 🔮 visits when they have a **Frequency** and a **Last Service Date** — the same rule as the calendar.

**Profile** — the logged-in user's info (in server mode: name and role) and **Sign Out / Change Device**.

### Personal Mode vs. Server Mode

| | Personal mode | Server mode |
|---|---|---|
| Login | Single owner token, fetched automatically from AI-Prowler's own config — nothing to set up per user | Each employee's name + own personal token, configured in the Admin tab |
| Data shown | Every job in the job tracker, on every tab | **By role:** field crew see only their own assigned jobs (same filtering on every tab); owner, manager and staff see every crew's jobs |
| Screens | All ten tabs | Reports for the owner only; field crew don't get the Settings, Services_Pricing, Quotes and Invoices tables |
| Setup | Automatic — same app, same login flow, no extra configuration | Requires each employee to be added as a user first (Section 9) |

### Server Mode — Roles and What Each User Sees

In server mode the Jobs App is shared by everyone the owner has added in the Admin tab. Each person logs in with their name and personal token, and the **role** set for them in the Admin tab decides what they get. The full table is in **Section 9 → Roles and Scopes in the Jobs App**; in short:

- **owner** — everything, including the Reports screen.
- **manager** and **staff** — every crew's jobs, routes and database tables; no Reports screen. Staff is the crew-lead tier: unrestricted for jobs, even though staff don't manage users.
- **field_crew** — only the jobs assigned to them (by name in **Crew / Technician**): their own schedule, board, calendar, route, clock entries and photos. Customers are readable (gate codes, access notes, on-site contact); Settings, Services_Pricing, Quotes and Invoices are not available.

Knowledge-base **scopes** (Section 9 → Scopes) do not change what anyone sees in the Jobs App — they only affect document search.

Good to know:
- A job with no name in **Crew / Technician** is invisible to field crew until someone assigns it.
- The top bar and the Profile tab show who is logged in and their role — useful when several people share a tablet.
- If a role is changed in the Admin tab, the person sees the change the next time they log in.

---

## 26. Remote PWA App

> **Personal mode only.** Unlike the Jobs App (Section 25), the Remote PWA is not available in Business Server mode at all. It gives whoever's logged in full access to browse and write files anywhere on the machine, manage the tracked-directory permission allowlist, and view system internals — appropriate for the single owner of a personal install, but not something to expose to individual field crew members on a shared company server. There is no per-employee scoping here the way the Jobs App has; if it were available in server mode, any employee with the login would effectively be remote-controlling the server machine itself, not just their own job data.

### What It Is

The Remote PWA is a standalone, human-facing dashboard for managing your own personal AI-Prowler install from any phone or browser — separate from the Jobs App (field-service focused, Section 25) and separate from the MCP connection Claude.ai uses to actually reach your knowledge base. Where the Jobs App is about running the day's work, the Remote PWA is about checking on and administering AI-Prowler while away from the PC it runs on: browsing files, running a search, managing permissions, reviewing self-learning entries, checking the agentic task queue, and viewing system health — all without a Claude, Muse, or Grok conversation open.

### Setup & Access

1. **Turn on Remote Access first** (Section 7) — the same Cloudflare Tunnel and Bearer Token used for Claude.ai mobile access also serves this app. If you've already set up mobile access, there's nothing additional to configure.
2. **Open the app URL** — `https://your-tunnel-domain.ai-prowler.com/remote/`. It shows as **AI-Prowler Remote** in the browser tab.
3. **Install to the home screen (recommended)** — an install banner appears at the top of the page the first time you open it in the phone's browser. On **Android/Chrome** it shows a one-tap **Install** button (via the browser's install prompt); on **iPhone** there's one manual step — Apple allows no automatic install: (1) open the page in **Safari** (if the QR opened in another browser, copy the link into Safari first), (2) tap **Share → Add to Home Screen**. Once installed, it opens full-screen like a native app — no browser chrome, no app store needed. The banner never appears when the app is already installed (running standalone), and tapping **Later** dismisses it; that choice is remembered on the device, so it won't nag you again.
4. **Log in with your Bearer Token** — the same token from Settings → Remote Access. The session persists on the device.

The top-right **version badge** works like the Jobs app's (Section 25): tap it to check for a newer app.

### What It Can Do — Tab by Tab

The app has seven bottom-nav tabs: **Dashboard**, **Files**, **Search**, **Perms**, **Learn**, **Tasks**, **System**.

**Dashboard** — an at-a-glance status view, plus a **Quick Access** panel of shortcuts straight into the other six tabs.

**Files** — browse, download, and upload tracked files directly from the phone or browser, with no Claude, Muse, or Grok conversation needed. This is the human-usable counterpart to the `get_file_download_url()` / `get_file_upload_url()` MCP tools (Section 7 → File Transfer Tools), which let *Claude, Muse, or Grok* do the same thing programmatically during a conversation.

The tab has two sections: **Indexed Folders** (your tracked folders) and, below them, **Access-Only Folders** (readable by Claude, Muse, or Grok, never indexed — see §4). Both work the same way: **📥 Download** opens a folder browser (Open → / ← Back, **👁 View** for text and images, **⬇ Get** to download), and **📷 Upload** appears on folders with write access (a folder without it shows 🔒 Read only — turn write access on in the **Perms** tab). The difference is what happens to an upload: in an indexed folder it's saved **and indexed** into AI-Prowler; in an access-only folder it's **saved only — never indexed**, and the folder is not added to tracking.

**Search** — run a semantic search against your knowledge base directly from this tab, using the same underlying search `search_documents()` uses when Claude, Muse, or Grok searches on your behalf.

**Perms** — view and manage the readable/writable directory allowlist, the same permission set the `list_writable_directories()`, `grant_write_access()`, and `revoke_write_access()` MCP tools operate on. Useful for checking or fixing folder permissions without needing to ask Claude to do it. Turning write access **on** asks you to re-enter your Bearer token; turning it off is instant.

Below the indexed folders is the **Access-Only Folders** section (folders Claude can read but that are never indexed — see §4): type a folder path and tap **Add** (re-enter your Bearer token to confirm), tap **🗑** on a row to remove it (instant), and use a row's switch to give or take away write access. This is the same list as the desktop's Update Index panel and the `grant_access()` / `revoke_access()` tools. Like the whole Remote Control app, it's personal-mode only.

**Learn** — browse and search self-learning entries, add a new one (**+ Add Learning**), **edit** one (**✎ Edit** on its card opens the form filled in with its title, content, category, outcome, tags and context — change anything, or empty Tags/Context to clear them, then **✓ Save Changes**), or delete one (**🗑 Delete**, with confirmation) — all without a conversation, on the same knowledge base `record_learning()`, `update_learning()` and `search_learnings()` use.

**Tasks** — the agentic analysis task queue, grouped into **Due Now**, **Scheduled**, and **Completed / One-off**, with a **+ New Custom AI Task** form for defining a new one and **Edit** on each task. In Edit, every field can be changed — and cleared: emptying the Report folder or un-ticking every scope folder removes them, and First due can be emptied on a **Run once** task (a scheduled task always needs one, so the form says so instead of saving). Mirrors what `list_analysis_tasks()`, `get_pending_analysis_tasks()`, `create_analysis_task()` and `update_analysis_task()` work with.

**System** — **AI-Prowler Status** and **Database Stats** panels, the same information `check_ai_prowler_status()` and `get_database_stats()` return to Claude, Muse, or Grok.

### Personal Mode vs. Server Mode

**Personal mode only — not available in Server mode at all.** This matches the same restriction already documented for the underlying `get_file_download_url()` / `get_file_upload_url()` MCP tools (Section 7 → File Transfer Tools), which are also personal-mode-only for the identical reason: unrestricted file/permission/system access has no safe per-employee scoping story on a shared company server. The Jobs App (Section 25) is the field-crew-facing app for Business Server installs — it has the row-level scoping this app deliberately lacks.

---

## 27. Service Desk (tickets)

Service Desk tracks requests and problems from **Open → Assigned → In Progress → Fixed → Closed**, with **On Hold** as a side state. Customers can file requests from their phone, every ticket has one owner and a history, and Claude, Muse or Grok can run it all by chat or voice.

### Editions

| | Solo (Personal Mobile) | Business (server mode) |
|---|---|---|
| Who works tickets | The owner — every ticket goes to you | Owner, managers, staff, field crew |
| Customer requests (form, text, email, status page) | Yes | Yes |
| Your own tickets (to-dos) | Yes — can be switched off | Internal tickets for the team |
| Subcontractor tickets | Yes — can be switched off | Yes |
| Queues, assignment rules, round-robin | — | Yes |
| SLA timers with escalation | Simple due dates and reminders | Yes |
| Photos, documents, export, import, backups | Yes | Yes |

Service Desk is **not** part of the free Desktop edition.

### Turning it on — or off

Home tab → **➕ Add a service** → tick **🎫 File and track tickets (customer requests, to-dos)** → Save, then restart AI-Prowler. The Setup Center then has a **Service Desk (tickets)** step with the phone app's QR code, Copy and Email links and your customers' request-page link. (It's the same switch as Settings → **MCP Tool Configuration** → **Service Desk (tickets)**, so either place works; unticking it asks before turning Service Desk off.) It starts off on new installs (like Job Tracker) and stays on once tickets exist. Personal and server mode each keep their own choice.

Don't want a help desk? Untick the same group. Then Claude, Muse and Grok are offered none of the ticket tools, the Service Desk app and the customer request pages answer "turned off", and nothing runs in the background (no alerts, digests, email intake or texts). Your tickets stay saved, ready if you turn it back on.

### The Service Desk app

Open **https://your-tunnel-address/desk/** on your phone and add it to your home screen. The **Business** tab has the link ready under **🎫 Service Desk — Mobile URL for Tickets**: **📋 Copy**, **📧 Email** (with install steps) or **📱 QR** to scan from your screen — and the same for the customer request page, to put on your website.

- **Sign in** — personal install: your Bearer Token. Server: your AI-Prowler name and token (the same ones as the Jobs app). You're signed out after the same idle time as the Jobs app.
- **Top bar** — same as the Jobs app: the AI-Prowler icon and your name/role at the left, a green dot while connected (red = offline, changes won't save), **↻** to refresh whatever you're looking at, **🔔** phone alerts and **⎋** sign out. The small **version badge** top-right shows which build the phone is running — tap it to check (green = latest, red = tap again to update). When a new version is installed a **"A new version is available — Refresh Now"** banner appears; **Later** hides it until you change tabs.
- **On a phone** — every screen fits the width; the tab row and the Board scroll sideways on their own. Boxes use large text so iPhones don't zoom in while you type, and saving a note or a change keeps your place on a long ticket.
- **Tabs** — My tickets, Open, Overdue, Board (drag cards between columns), Closed, 📊 Reports (owner and managers), ⚙︎ Settings (owner).
- **⏱ waiting** — every open ticket's card shows how long it has waited since it was filed (minutes, hours, then days), red once it's past its due date, so you can see at a glance who has waited longest. Fixed and Closed tickets don't show it.
- **A ticket** — move it with the state buttons (a reason is asked for On Hold, reopening, "not fixed" and closing without the customer confirming); add photos with 📷 Camera or files with 📎 File; write an internal note or a reply to the customer or subcontractor; copy the customer's status link; schedule a re-do job in the Jobs app; download a PDF; write the resolution.
- **🔔 Alerts on this phone** — tap the bell to get alerts even when the app is closed. On iPhone, first add the app to the home screen (Share → Add to Home Screen) and open it from there.
- If someone else changes a ticket while you have it open, the app tells you instead of overwriting their change.

### How a ticket moves

| From | Can move to | Notes |
|---|---|---|
| Open | Assigned, Closed | Assigning someone moves it to Assigned by itself |
| Assigned | In Progress, On Hold, Fixed, Closed, back to Open | |
| In Progress | On Hold, Fixed, Closed, back to Assigned | |
| On Hold | In Progress, Closed | The SLA clock is paused while On Hold |
| Fixed | Closed, In Progress | Back to In Progress = "not fixed" |
| Closed | Assigned (reopen) | Goes back to the person who had it |

A written **reason** is required for: anything → On Hold; closing a ticket that wasn't Fixed first; Fixed → In Progress ("not fixed"); and reopening. The reason goes in the history; customers never see it.

The ticket page only shows the buttons **you** are allowed to press.

### Who can do what (team edition)

| | Owner | Manager | Staff | Field crew |
|---|---|---|---|---|
| Sees | Every ticket | Their queues + the shared inbox + their own | Unassigned tickets in their queue / shared inbox + their own | Tickets assigned to or filed by them |
| Assign | Anyone | Anyone | Only take an unassigned ticket themselves | Same as staff |
| Move state | Any move | Any move | Only on their own tickets; can't close or reopen | Same as staff |
| Reply to customer / edit / resolution | Yes | Yes | On their own tickets | On their own tickets |
| Internal notes | Yes | Yes | Yes | Yes |
| Watchers | Anyone | Anyone | Themselves (anyone, if they're the assignee) | Same as staff |
| Reports, export, triage | Yes | Yes | — | — |
| Settings, queues, import, backups, restore, delete | Yes | — | — | — |

**Private** tickets are seen only by whoever filed them and the owner. Customers see only their own requests; subcontractors only tickets shared with them (and can only mark their part done). In **Solo** you are the only internal user, so everything above is yours.

### Who is told what

| What happened | Who hears |
|---|---|
| New ticket with an assignee | The assignee |
| New ticket nobody owns yet | The owner and managers (Solo: your alert email/phone) |
| Ticket assigned | The new assignee |
| Customer replied, or says it's **not** fixed | The assignee (or owner and managers if nobody has it) |
| Reopened | The assignee (or owner and managers) |
| SLA 75% / overdue | The assignee; at **twice** the target the owner and managers |
| Any change of state | Every **watcher** — except the person who made the change and anyone already told above |
| In Progress, Closed (customer tickets) | The customer — one line, by email (or text if no email) |
| Each morning | Digest of overdue / due today / unassigned to the owner and managers |

Alerts go by email, by text if **Also alert by text** is ticked on the ticket, and to phones that turned on 🔔 alerts.

### A normal day

- **Owner / manager:** read the morning digest; open the **Open** tab and assign anything unowned (or ask Claude: "Triage the tickets"); watch **Overdue**; drag cards on the **Board**; close tickets once the customer confirms (or let auto-close do it); check 📊 Reports weekly.
- **Staff / field crew:** open **My tickets**; tap a ticket → **In Progress** when you start, add photos and a note, **Fixed** when done (write the resolution — it helps find the fix next time). Need a part or the customer? **On Hold** with the reason. Staff can take an unowned ticket from **Open**.
- **Solo:** everything comes to you. Use your own tickets as a to-do list with due dates; customer requests come in from the form, texts and email.
- **By voice while driving:** "What's on my plate?", "Start ticket 42", "Mark 42 fixed — replaced the latch", "Put 42 on hold, waiting on the part".

### When something isn't right

- **Someone can't see a ticket** — check who it's assigned to and its queue (table above). Staff stop seeing a ticket once someone else takes it.
- **A button is missing** — the page only shows moves your role may make; staff and crew need a manager to close or reopen.
- **"Someone else changed this ticket"** — reload; the app never overwrites a newer change.
- **Watcher can't be added** — the address must be a real email, and a ticket's own customer can't be a watcher. A name with no email on file: type the address instead.
- **Customer didn't get an update** — they only get In Progress and Closed; check their email/phone on the ticket and that **Tell customers (one line)…** is on in ⚙︎ Settings. Each reply shows whether it was sent.
- **App says "Service Desk is turned off"** — tick **Service Desk (tickets)** in Settings → MCP Tool Configuration and restart.
- **No phone alerts** — tap 🔔 on that phone again (iPhone: open it from the home-screen icon first).

### Customers and subcontractors

- **Request form:** https://your-tunnel-address/support/new — the customer enters a name, mobile number or email, and what they need; a 6-digit code confirms it's them. They get a link to their **status page**.
- **Status page:** shows only their own request and its public messages. They can reply, add photos, confirm the fix or say it isn't fixed, reopen within 7 days, and rate the job once it's closed. A subcontractor's page also has **My part is done**.
- **Replies** you send go out by email (or text if there's no email) with the status-page link. Each message shows whether it was sent.
- **Texts:** a text from someone with an open ticket is added to that ticket. A text from anyone else follows your setting — **Do nothing** (default), **Ask** if they want a request opened (YES / NO), **Text back the form link**, or **Open a ticket automatically**. STOP / START / HELP work exactly as before, and your team's own phones are never treated as customers.
- **Email:** turn on **Read our email account for ticket replies** to add customer email replies (subject contains [T-####]) to their ticket. Uses the email account AI-Prowler already sends from (needs IMAP; Outlook-only setups can't be read). Your other mail stays unread.
- Update your Twilio A2P campaign description to mention service-request updates before turning on automatic texts.

### Picking addresses, watchers and customer updates

- **Address book:** as you type an email on a new ticket (or a name under Watchers), the app suggests addresses from your team, **your own** saved contacts (on a server each person's saved contacts stay private to them), your Jobs app customers and past ticket contacts. Pick one and the name and phone fill in. **Assign to** suggests your team as you type.
- **Watchers** (team edition and Solo): people on your side who are emailed whenever the ticket changes state — From → To, the reason, and who did it. Never the person who made the change, and never twice for the same change. The owner, managers and the ticket's assignee can add or remove anyone; everyone else can only **👁 Watch this ticket** / **Stop watching** themselves. Customers and subcontractors never see the list, and a ticket's own customer can't be a watcher.
- **Customer updates:** the customer hears just two short lines — when work is **in progress** and when it's **closed** (with the reopen link) — by email, or text if there's no email. No reasons, notes or other details, and nothing for changes they made themselves. Turn it off in ⚙︎ Settings → **Tell customers (one line) when their request is in progress and when it's closed**.
- By voice: "Add Vicki to ticket 42", "Who's watching 42?", "Take Sam off 42".

### Business features

- **Settings → Team:** queues (members get new tickets round-robin, skipping anyone with PTO or an absence today in the HR apps), assignment rules (first match wins: by keyword, type or customer → a person or a queue) and ticket types. A ticket for a job goes to that job's crew lead.
- **SLA timers** run in business hours on your Jobs app working days: P1 reply in 1 hour and fixed the same day; P2 4 hours / 2 days; P3 1 day / 5 days; P4 3 days. On Hold pauses the clock. The assignee is warned at 75%, told when it's overdue, and the owner and managers are told at twice the target.
- **Morning digest** of overdue, due-today and unassigned tickets (7am by default), emailed to the owner and managers — or, in Solo, to your alert email.
- **Auto-close:** a customer ticket marked **Fixed** closes by itself after **3 days** with no word from the customer (any reply from them starts the 3 days again). Change the number in ⚙︎ Settings, or set **0** to never auto-close. The history shows it was closed by *system*, and the customer can still reopen it from their status link for 7 days. Your own and internal tickets are never auto-closed.
- **Status links** stop working 30 days after a ticket is closed. A request-form code is good for 10 minutes — the customer taps **Send a new code** if it runs out.

### Data and backups (Settings → Data, owner)

- **Export:** Excel, CSV, a full export (with photos) that moves to another Service Desk, and a one-ticket PDF. Exports are copies — editing them never changes your tickets.
- **Import:** CSV, Excel (with column names like Subject / Status / Priority / Requester / Phone, as other help desks export) or a full export. It always checks the file first; a real import takes a backup, sends no alerts, and can be undone for 7 days.
- **Backups:** daily at 2am by default (hourly or weekly if you prefer), verified, with 14 daily / 8 weekly / 12 monthly copies kept and an optional second copy to a drive, NAS or synced folder. Restore everything or a single ticket; a safety backup is taken first. Two failed backups in a row email you.
- Everything lives in **C:\Users\you\.ai-prowler\tickets_database** — the database, one folder per ticket (ticket.json plus its photos and documents), exports, imports and backups.

### With Claude, Muse or Grok

Ask in plain language — "File a ticket: Mrs. Lopez says the front windows are streaky", "What tickets do I have?", "Triage the tickets", "Tell the customer on 42 we'll be there Thursday", "Schedule a redo for 42 next Tuesday", "How did support go this week?". Claude previews customer messages before sending, and asks before closing, merging, importing or restoring. Every change Claude makes is recorded as made by Claude and approved by you.

Tools: create_ticket, get_ticket, list_tickets, my_tickets, update_ticket, assign_ticket, set_ticket_state, add_ticket_note, reply_to_customer, create_job_from_ticket, search_tickets, ticket_summary, triage_inbox, apply_triage, link_ticket, merge_tickets, manage_ticket_queues, manage_ticket_rules, ticket_report, export_tickets, import_tickets, tickets_backup_now, backup_tickets_database, list_tickets_backups, tickets_backup_settings, restore_tickets_database, get_ticket_updates, tickets_settings, ticket_watchers.

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
- Text of retrieved document chunks (when Claude, Muse, or Grok processes them)
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
*Version 9.1.0 — Updated August 2026*
