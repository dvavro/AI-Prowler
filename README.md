# 🔍 AI Prowler — Personal AI Knowledge Base (PC version free for Win 10/11)

**Ask questions about YOUR documents using AI — running locally on your Windows PC**

No API keys required for local AI &nbsp;•&nbsp; No cloud services for local AI &nbsp;•&nbsp; No subscription for local use &nbsp;•&nbsp; Complete privacy

---

## 📥 Download & Install

> **No technical knowledge required — one batch file does everything.**

1. Go to the **[Releases page](https://github.com/dvavro/AI-Prowler/releases)** 
   and download the latest `AI-Prowler-v2.0.zip`
2. Extract the ZIP to a permanent folder — e.g. `C:\Users\Joe
3. Double-click **`INSTALL.bat`** — it installs Python, all packages, Ollama, and the AI model automatically
4. Wait for **"INSTALLATION COMPLETE"** (15–30 minutes, ~4 GB download)
5. Double-click the **AI Prowler** shortcut that appears on your Desktop

That's it. No terminal, no configuration, no accounts.

---

## 🎯 What Is AI Prowler?

AI Prowler uses **RAG (Retrieval-Augmented Generation)** — it indexes your local documents, then when you ask a question it retrieves the most relevant passages and feeds them to an AI model that writes a grounded, accurate answer. Everything runs on your own machine.

```
You:         "What was the mutation rate in my NEAT project?"

AI Prowler:  According to NEAT_Documentation.md, the mutation rate
             is set to 0.02 (2%). This controls how frequently
             weights and connections mutate during evolution...
```

Your documents are **never uploaded anywhere**. The AI runs entirely on your hardware.

---

## ✨ Features

### Core
- 📚 **55+ file types** — documents, code, spreadsheets, PDFs, email, and more
- 🔍 **Semantic search** — finds relevant content even when exact words don't match
- ⚡ **Incremental indexing** — only re-processes files that have actually changed
- ⏸ **Pause / Resume** — stop indexing mid-run and continue exactly where you left off
- 🔒 **100% local by default** — nothing leaves your machine

### AI Providers
- 🤖 **Local Ollama** — 20+ models from tiny (0.5b) to powerful (70b+), completely free and offline
- ☁️ **Cloud AI (optional)** — connect ChatGPT, Claude, Gemini, Grok, Llama API, or Mistral Large for higher-quality answers
- 🔄 **Auto-fallback** — if a cloud provider fails, automatically falls back to your local model

### Query Tools
- 🎤 **Voice input** — speak your questions via local Whisper speech recognition
- 📎 **File attachments** — attach images or files to questions (vision support with cloud providers)
- 💾 **File Output Mode** — AI-written code gets automatic 💾 Save buttons — no copy-paste
- ⏹ **Stop query** — cancel any running query instantly

### Email Support
- 📬 **All major providers** — Gmail (`.mbox`), Apple Mail, Thunderbird, Yahoo, Outlook/Exchange
- 🔢 **Incremental email indexing** — only new messages are processed on re-import
- 📊 **Per-message progress** — `[Email 4,271/52,000] Re: Budget` — always know where you are

### Automation
- ⏰ **Windows Task Scheduler** — set daily or weekday auto-updates
- 🟢 **Auto-start Ollama** — launch the AI server automatically on app open
- 🗂 **Auto Scan Config** — customise exactly which file types and folders are included

---

## 🖥️ System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10 64-bit | Windows 11 64-bit |
| RAM | 8 GB | 16 GB |
| Storage | 6 GB free | 15 GB free |
| CPU | Any modern 64-bit | Quad-core or better |
| GPU | Not required | Speeds up 7b+ models significantly |
| Internet | Install only | Install + cloud AI providers (optional) |

---

## 📦 What's Installed

| Component | Size | Purpose |
|-----------|------|---------|
| Python 3.11 | ~30 MB | Runtime |
| Python packages (11) | ~600 MB | ChromaDB, sentence-transformers, PDF support, etc. |
| Ollama engine | ~400 MB | Local AI model runner |
| llama3.2:1b (default model) | ~1.3 GB | Fast, capable local AI |
| Whisper large-v3-turbo | ~1.6 GB | Local speech recognition |
| **Total** | **~4 GB** | One-time download |

---

## 📁 Repository Structure

```
AI-Prowler/
├── INSTALL.bat              ← One-click installer — run this first
├── UNINSTALL.bat            ← Clean removal tool
├── RAG_RUN.bat              ← Launch AI Prowler
├── rag_gui.py               ← Main GUI application
├── rag_preprocessor.py      ← Core indexing & query engine
├── requirements.txt         ← Python package list
├── create_shortcut.py       ← Desktop shortcut creator
├── rag_icon.ico             ← Application icon
└── COMPLETE_USER_GUIDE.md   ← Full documentation
```

---

## 🚀 Supported AI Models (Local)

Models are ranked automatically based on your PC's RAM. Install any of them from within the app.

| Model | Size | Min RAM | Best for |
|-------|------|---------|---------|
| `qwen2.5:0.5b` | 0.4 GB | 2 GB | Ultra-fast, basic queries |
| `llama3.2:1b` ⭐ | 1.3 GB | 4 GB | **Default** — fast and capable |
| `llama3.2:3b` | 2.0 GB | 6 GB | Better quality, still fast |
| `llama3.1:8b` | 4.7 GB | 8 GB | Strong general-purpose |
| `qwen2.5:14b` | 9.0 GB | 16 GB | High quality |
| `llama3.1:70b` | 40 GB | 48 GB | Near-frontier quality |

---

## ☁️ Optional Cloud AI Providers

Add an API key in Settings to use these alongside your local model:

| Provider | Model | Free Tier |
|----------|-------|-----------|
| ChatGPT (OpenAI) | GPT-4o | Pay-per-use |
| Claude (Anthropic) | claude-opus-4-5 | $5 credit |
| Gemini (Google) | gemini-2.0-flash | ✅ Generous free tier |
| Grok (xAI) | grok-beta | Limited free |
| Llama API (Meta) | Llama-4-Scout-17B | ✅ Free tier |
| Mistral Large | mistral-large-latest | Limited free |

> **Privacy:** Only your question and retrieved document excerpts are sent to cloud providers — your original files never leave your PC.

---

## 📬 Email Indexing

AI Prowler has deep support for every major email provider:

| Provider | Export format | Notes |
|----------|--------------|-------|
| Gmail | `.mbox` via Google Takeout | Label-by-label or full mailbox |
| Apple Mail / iCloud | `.mbox` export or `.emlx` direct | No conversion needed |
| Thunderbird | `.mbox` direct from profile | No export step required |
| Yahoo Mail | Via Thunderbird IMAP bridge | App password required |
| Outlook / Exchange | `.eml` drag-and-drop or MailStore | `.pst` needs conversion first |
| Windows Live Mail | `.eml` files direct | Point at the Mail folder |

The incremental email indexer uses `Message-ID` deduplication — a 100,000-message archive that gained 200 new emails only processes those 200 on re-import.

---

## 🔐 Privacy

AI Prowler is **local-first**. Cloud AI is entirely opt-in.

| ✅ Does | ❌ Does NOT |
|--------|-----------|
| Runs 100% offline by default | Upload your documents anywhere |
| Store all data on your hard drive | Collect telemetry or analytics |
| Keep API keys in your local config | Phone home or require an account |
| Use Ollama for local inference | Send original files to cloud providers |

---

## 📖 Documentation

The full **[COMPLETE_USER_GUIDE.md](COMPLETE_USER_GUIDE.md)** is included in every release. It covers:

- Complete installation walkthrough
- All 6 GUI tabs in detail
- Email export instructions for every major provider
- Cloud AI setup and provider reference
- Scheduling, GPU tuning, and voice input
- Troubleshooting for every common issue
- Command-line usage reference

The User Guide is also accessible from within the app via **Help → 📖 User Guide**.

---

## 🐛 Reporting Issues

Found a bug or have a feature request? Open an **[Issue](https://github.com/dvavro/AI-Prowler/issues)** and include:

- Your Windows version
- The error message (run `python rag_gui.py` from Command Prompt to capture it)
- What you were doing when it happened

---

## 📝 Changelog

See the **[Releases page](https://github.com/dvavro/AI-Prowler/releases)** for full version history and release notes.

**Latest: v2.0**
- ☁️ Six cloud AI providers (ChatGPT, Claude, Gemini, Grok, Llama API, Mistral)
- 📎 File attachments (images + text files) with vision support
- 💾 File Output Mode — auto-detected code blocks with Save buttons
- 🏅 RAM-aware model selector with ✅/⚠️ fit badges
- 🔍 Debug View — hide/show background processes
- 🔧 Various bug fixes and stability improvements

---

## ⚖️ License

PC version is free open source. Mobile Access requires a small App Download fee and a small monthly user subscription cost.

---

*AI Prowler — Your Personal AI Knowledge Base*  
*Local-first &nbsp;•&nbsp; Cloud-optional &nbsp;•&nbsp; 100% Yours*
