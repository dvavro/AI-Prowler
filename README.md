# 🐾 AI-Prowler — Agentic RAG Knowledge Base & Small Business Assistant
**Version 9.2.0** · Windows 10/11 · Local-first · Agent-powered

**Connect your documents and your business to Claude — and let AI actively research and run the day-to-day for you.**

No technical knowledge required &nbsp;•&nbsp; One-click installer &nbsp;•&nbsp; Works with Claude Desktop & Claude.ai &nbsp;•&nbsp; Your data stays on your PC

---

## 📥 Download & Install

> **One installer. No configuration. Under 10 minutes.**

1. Go to the **[Releases page](https://github.com/dvavro/AI-Prowler/releases)** and download `AI-Prowler_INSTALL.exe`
2. Double-click the installer and follow the prompts (admin rights required)
3. The installer sets up Python 3.11, all packages, Tesseract OCR, Claude Desktop and the Cloudflare Tunnel client — and registers AI-Prowler with Claude Desktop for you
4. Sign in to Claude Desktop when it opens — then you're done

AI-Prowler and Claude Desktop are ready to use as soon as the install finishes. The **🧭 Set up AI-Prowler** panel on the Home page then walks you through indexing your documents and turning on the optional services (remote access, the phone apps, job tracking, AI routing) as you need them.

---

## 🎯 What Is AI-Prowler?

AI-Prowler is an **Agentic RAG (Retrieval-Augmented Generation)** knowledge base for Windows. It indexes your local documents into a private vector database and exposes them to Claude as a set of intelligent search tools — so Claude can actively research your documents, follow leads, reformulate queries, and synthesize comprehensive answers on its own.

```
You ask Claude:    "Summarise the key risks in our Q3 contracts."

Claude thinks:     I should look at what contract documents are indexed...
Claude calls:      get_knowledge_base_overview()
Claude calls:      search_documents("Q3 contract risks")
Claude calls:      search_documents("liability indemnification clauses")
Claude calls:      expand_search_result("contract_q3.pdf", 14)
Claude answers:    A detailed synthesis across all relevant documents.
```

Beyond documents, AI-Prowler gives Claude a complete **small business toolkit** — customers, jobs, scheduling, quotes, invoices, route planning, time tracking and messaging — plus phone apps for you and your crew.

Your documents **never leave your machine**. Claude sees only the relevant excerpts it retrieves.

---

## ✨ Why Agentic RAG Is Different

Traditional RAG systems retrieve a chunk and hand it to a small local model that generates a mediocre answer. AI-Prowler takes a fundamentally different approach:

| | Classic RAG | AI-Prowler Agentic RAG |
|---|---|---|
| **Who reasons** | Small local model | Claude (full intelligence) |
| **Search strategy** | Single fixed query | Multiple adaptive queries |
| **Follow-up** | None | Automatic multi-hop |
| **Hardware** | GPU + large local model | Any PC — no GPU needed |
| **Quality** | Limited by local model | Full Claude capability |

Claude decides what to search for, evaluates what it finds, identifies gaps, and searches again — just like a research assistant would.

---

## 🔗 How You Connect

### Option 1 — Claude Desktop (Recommended)
Claude Desktop connects to AI-Prowler via MCP (Model Context Protocol) on your own PC. No internet is needed for the connection itself.

- Set up automatically by the installer
- No AI-Prowler subscription required
- Requires a Claude account (free tier available)
- Full agentic RAG — Claude calls your knowledge base and business tools automatically

### Option 2 — Claude.ai on Any Device (Mobile Subscription)
AI-Prowler's HTTP server and Cloudflare Tunnel make your knowledge base reachable from Claude.ai on your phone, tablet or any browser — and power the two phone apps (below).

- Requires an AI-Prowler mobile subscription (see **Plans**)
- Claude.ai custom connectors need a paid Claude plan (Pro, or Team for a company)
- Setup is automated: subscribe, paste your activation code, click **⚡ Configure Mobile Access**

**Adding AI-Prowler as a Claude.ai connector:**

1. In AI-Prowler → **Settings → Remote Access**, configure mobile access and start the HTTP server
2. In Claude.ai → **Settings → Connectors → Add custom connector**
3. Enter your tunnel URL (shown in AI-Prowler), e.g. `https://your-tunnel.ai-prowler.com/mcp`
4. Authorize when prompted
5. In any Claude.ai conversation, enable AI-Prowler from the Connectors/Tools panel

> **Tip:** Claude.ai in the browser lets you download any files Claude generates (code, reports, documents) directly to your device. If downloading Claude's outputs matters to your workflow, use Claude.ai in the browser.

---

## ✨ Features

### Document Indexing & Agentic RAG
- 📚 **65+ file types** — PDFs, Word, Excel, PowerPoint, code, email, images (OCR), and more
- 🔍 **Semantic search** — finds relevant content even when exact words don't match
- ⚡ **Incremental indexing** — only re-processes files that changed; deleted files are purged automatically
- 🕑 **Automatic re-indexing** — a file watcher plus a scheduled catch-up keep the index current
- 🧠 **Self-learning** — Claude records lessons, corrections and preferences, and checks them before answering
- 🔒 **Local** — your documents and index never leave your machine

| Tool | What Claude uses it for |
|---|---|
| `get_knowledge_base_overview` | Orients itself — what's indexed, what types |
| `search_documents` / `multi_query_search` | Semantic search, one or several phrasings at once |
| `search_within_directory` | Search limited to one project, client or folder |
| `expand_search_result` / `read_document` | Reads around a result, or a whole document in order |
| `grep_documents` | Exact text / code search with line numbers |
| `how_to_use_ai_prowler` | Self-orienting guidance tool |

Claude can also manage the index, edit files in folders you allow, and run analysis tasks — all from a conversation. Every tool can be switched on or off in **Settings → 🧩 MCP Tool Configuration**.

### Small Business Job Tracker
A complete contractor workflow that Claude reads and writes in plain English — "what's on today?", "invoice the Torres job", "route tomorrow for Jake".

- 👥 **Customers, jobs, quotes, invoices, time logs and pricing** in a local database (`ai_prowler_jobs.db`) — created automatically, nothing to set up
- 📋 **Job Board** — a live board of the day's jobs; drag a card to change its status, with updates from the crew appearing within a minute
- 🗺️ **Route planning** — real street routing (OSRM), a quick suggestion, or full AI route reasoning; tap-to-navigate links for Google/Apple Maps
- 📆 **Working Days** — set which days your crews work (Settings → *Working Days*); add Saturday or Sunday when a project is running late
- 💵 **Invoices, receipts and payment links** by email or text; **AR aging** report
- 📤 **Data portability** — export to Excel, CSV or QuickBooks-ready CSV; full backup and restore for moving to a new PC
- 🌦️ **Free helpers** — weather (rain risk for outdoor jobs), geocoding, maps links

### Phone Apps (Mobile Subscription)
- 📱 **Jobs App** — for owners and field crew: today's jobs, the Job Board, calendar, routes, clock in/out, photos, invoices and messages — installs to the home screen from the browser
- 🛰️ **Remote App** — manage your AI-Prowler PC from your phone

### Messaging & Automation
- 💬 **Two-way SMS & WhatsApp** — Twilio, SignalWire, Vonage; replies arrive instantly
- 📧 **Email** — Outlook or any SMTP account
- 🔔 **Proactive alerts** — morning briefing, overdue invoices, weather watch and more
- 🤖 **AI task queue** — recurring or one-off analysis tasks (e.g. "check overdue invoices every Monday") that run on their own and record what they find

### Business Server Mode (Business Plan)
- 🏢 One shared company knowledge base and job database on a server PC, reached by every employee from Claude on their own phone or laptop
- 👤 **Roles and scopes** — owner, manager, staff and field crew each see and do only what they should; field crew see only their own jobs

### OCR, Email & GPU
- 🖼️ **Automatic OCR** — scanned PDFs, contracts, old manuals, image files (English + Spanish)
- 📬 **Email indexing** — Gmail, Outlook, Thunderbird, Apple Mail and more; only new messages re-indexed
- 🎮 **NVIDIA GPU support** — embeddings use CUDA automatically when available (not required)

---

## 💳 Plans

| Plan | Price | For |
|---|---|---|
| Desktop | Free | AI-Prowler with Claude Desktop on your own PC |
| Personal | $10/month | One user — adds Claude.ai on phone/web and the phone apps |
| Business | $20/month | Teams — a company server plus a personal setup for each employee (up to 50 seats) |

A lapsed subscription gets a 30-day grace period before remote access is suspended.

---

## 🖥️ System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 64-bit | Windows 11 64-bit |
| RAM | 4 GB | 16 GB+ |
| Storage | 3 GB free | 10 GB free |
| CPU | Any modern 64-bit | Quad-core or better |
| GPU | Not required | NVIDIA (any) for faster indexing |
| Internet | Install only for Claude Desktop | Always on for remote access and phone apps |
| Claude account | Required | Claude Pro (or Team) for Claude.ai connectors |

> **RAM note:** Claude does the reasoning, so AI-Prowler only runs a small embedding model (~400 MB) and its database locally. No large local AI model is needed.

---

## 📦 What Gets Installed

| Component | Size | Purpose |
|---|---|---|
| Python 3.11 | ~30 MB | Runtime |
| Python packages | ~600 MB | ChromaDB, sentence-transformers, OCR, document readers |
| Tesseract OCR 5.4 | ~50 MB | Scanned PDF and image text extraction |
| PyTorch (auto-detected) | ~200 MB – 2.5 GB | Embeddings (CPU or CUDA build) |
| Claude Desktop | ~200 MB | Primary AI interface via MCP |
| Cloudflare Tunnel client | ~30 MB | Remote access for Claude.ai and the phone apps |
| **Total** | **~1–3 GB** | |

The job tracker database is created by AI-Prowler the first time you use it — the installer doesn't ship one. No large local AI model is downloaded.

---

## 📁 Repository Structure

```
AI-Prowler/
├── rag_gui.py                    ← Desktop app (Home, Index, Settings, Small Business, Admin …)
├── rag_preprocessor.py           ← Indexing & retrieval engine
├── ai_prowler_mcp.py             ← MCP server (Claude Desktop, Claude.ai, phone apps)
├── mcp_tool_catalog.py           ← Tool list behind Settings → MCP Tool Configuration
├── db_*.py                       ← Job tracker database (SQLite)
├── setup_wizard.py               ← 🧭 Set up AI-Prowler panel
├── jobs/                         ← Jobs App (phone)
├── remote/                       ← Remote App (phone)
├── AI-Prowler-Setup.iss          ← Installer script (Inno Setup)
├── requirements.txt              ← Python package list
├── COMPLETE_USER_GUIDE.md        ← Full documentation
├── AI-Prowler Setup License.txt  ← License agreement
├── tests/                        ← Test suites (unit, GUI, end-to-end)
└── README.md                     ← This file
```

The installer itself (`AI-Prowler_INSTALL.exe`) is published on the **[Releases page](https://github.com/dvavro/AI-Prowler/releases)**.

---

## 🔐 Privacy

| ✅ Does | ❌ Does NOT |
|---|---|
| Store your documents, index and job data on your PC | Upload your documents anywhere |
| Send only retrieved excerpts to Claude | Send document content, queries or file paths to us |
| Run indexing and embeddings locally | Share any data with third parties |
| Keep credentials in your local config | Send your name, email or credentials |

AI-Prowler sends one small **anonymous daily heartbeat** (a random install ID, version, edition, mode, Windows version, number of indexed chunks and a total tool-call count) so we can see how many installs are active. Turn it off with `"heartbeat_enabled": false` in `config.json`.

---

## 📖 Documentation

The full **[COMPLETE_USER_GUIDE.md](COMPLETE_USER_GUIDE.md)** is included in every release and opens from **Help → 📖 User Guide** inside the app.

---

## 🐛 Reporting Issues

Found a bug? Open an **[Issue](https://github.com/dvavro/AI-Prowler/issues)** and include:

- Windows version and GPU model
- What you did and what happened (the error message, if any)
- The logs in `%USERPROFILE%\.ai-prowler\logs\` — `mcp_server.log` (the server) and `install_log.txt` (the install)
- The output of **Settings → 🔬 Run MCP Diagnostics**

---

## 📝 Changelog

### v9.2.0 (current)
- 📆 **Working Days setting** — choose which days crews work; multi-day jobs, routes, the calendar and overrun carry-over all follow it, and a change applies immediately
- 📋 **Job Board** — changes made from another device in the same second are no longer missed; a card dragged while the board is refreshing no longer jumps back to its old column
- 🧩 **MCP Tool Configuration** — collapsible panel; Save changes only the tool choices and protects all other settings
- 🧭 **Set up AI-Prowler wizard** — fixes for its windows and settings
- 📜 **Logs** — each server process writes its own log, and rotation can no longer lose older logs
- 🧹 **Installer** — the old spreadsheet and Claude Desktop example/snippet files are no longer installed; upgrades remove stale copies

### v9.0 – v9.1
- 🗄️ **Job tracker moved to a SQLite database** — replaces the Excel spreadsheet; Excel/CSV/QuickBooks exports, backup and restore
- 📱 **Jobs App and Remote App** for phones, with the **Job Board**, calendar, routes and time tracking
- 🗺️ **AI route planning** with hard/soft appointment times, lunch breaks and multi-day jobs
- 🏢 **Business Server Mode** — roles, scopes and an Admin tab for teams
- 💬 **Two-way SMS & WhatsApp**, consent capture and payment links
- 🧠 **Self-learning knowledge base** and an **autonomous AI task queue**

### v5.0.0
- 🏢 Small Business tab with field-service tools and the original Excel job tracker
- 📊 Much better extraction for Excel, PowerPoint, HTML, RTF, ODT, CSV and Word tables
- 🖥️ Auto-start after reboot

### v4.x
- 🤖 **Agentic RAG** — Claude actively researches your knowledge base
- 📱 Claude.ai connector with mobile subscriptions and secure sign-in

### v3.0 and earlier
- 🎮 NVIDIA Blackwell GPU support, 🖼️ Tesseract OCR, ☁️ cloud AI providers

---

## ⚖️ License

Desktop use is free under the AI-Prowler Software License.
Mobile / remote access and Business Server Mode require a subscription.
See [AI-Prowler Setup License.txt](AI-Prowler%20Setup%20License.txt) for full terms.

Copyright © 2026 David Kevin Vavro · david.vavro1@gmail.com

---

*AI-Prowler — Your Personal Agentic RAG Knowledge Base & Business Assistant*
*Local-first &nbsp;•&nbsp; Agent-powered &nbsp;•&nbsp; Yours*
