# 🔍 AI Prowler — Personal AI Knowledge Base
**Version 3.0.0** · Free for Windows 10/11 · Local-first · Cloud-optional

**Ask questions about YOUR documents using AI — running locally on your Windows PC**

No API keys required for local AI &nbsp;•&nbsp; No cloud for local use &nbsp;•&nbsp; No subscription &nbsp;•&nbsp; Complete privacy

---

## 📥 Download & Install

> **No technical knowledge required — one installer does everything.**

1. Go to the **[Releases page](https://github.com/dvavro/AI-Prowler/releases)** and download the latest `AI-Prowler_INSTALL.exe`
2. Double-click the installer and follow the prompts
3. Wait for **"Installation complete"** — it downloads Python, all packages, Tesseract OCR, Ollama, and the default AI model automatically (~4 GB, 15–30 minutes)
4. Click the **AI Prowler** shortcut that appears on your Desktop

That's it. No terminal. No configuration. No accounts.

---

## 🎯 What Is AI Prowler?

AI Prowler uses **RAG (Retrieval-Augmented Generation)** — it indexes your local documents into a private vector database, then when you ask a question it retrieves the most relevant passages and feeds them to an AI model that writes a grounded, accurate answer. Everything runs on your own machine.

```
You ask:       "What was the mutation rate in my NEAT project?"

AI Prowler:    According to NEAT_Documentation.md, the mutation rate
               is set to 0.02 (2%). This controls how frequently
               weights and connections mutate during evolution...
```

Your documents are **never uploaded anywhere**. The AI runs entirely on your hardware.

---

## ✨ Features

### Core
- 📚 **65+ file types** — documents, code, spreadsheets, PDFs, images (OCR), email archives, and more
- 🔍 **Semantic search** — finds relevant content even when exact words don't match
- ⚡ **Incremental indexing** — only re-processes files that have actually changed
- ⏸ **Pause / Resume** — stop indexing mid-run and continue exactly where you left off
- 🔒 **100% local by default** — nothing leaves your machine

### AI Providers
- 🤖 **Local Ollama** — 20+ models from tiny (0.5b) to powerful (70b+), completely free and offline
- ☁️ **Cloud AI (optional)** — connect ChatGPT, Claude, Gemini, Grok, Llama API, or Mistral Large for higher-quality answers
- 🔄 **Auto-fallback** — if a cloud provider fails or rate-limits, automatically falls back to your local model

### Query Tools
- 🎤 **Voice input** — speak your questions via local Whisper speech recognition (never sent to a cloud)
- 📎 **File attachments** — attach images or text files to questions (vision support with cloud providers)
- 💾 **File Output Mode** — AI-written code gets automatic 💾 Save buttons across all providers, not just Claude — no copy-paste needed
- ⏹ **Stop query** — cancel any running query instantly

### Email Support
- 📬 **All major providers** — Gmail (`.mbox`), Apple Mail, Thunderbird, Yahoo, Outlook (`.eml`, `.msg`)
- 🔢 **Incremental email indexing** — only new messages are processed on re-import via Message-ID deduplication
- 📊 **Per-message progress** — `[Email 4,271/52,000] Re: Budget` — always know where you are

### OCR — Scanned Documents
- 🖼️ **Automatic OCR** — scanned PDFs, contracts, court docs, old manuals, and standalone image files
- 🔬 **Smart detection** — pdfplumber checks for a text layer first; only falls back to OCR when needed
- 🏎️ **300 DPI rendering** — pypdfium2 renders pages to high-quality images before Tesseract processing

### Automation
- ⏰ **Windows Task Scheduler** — set daily or custom-day auto-updates directly from the app UI
- 🟢 **Auto-start Ollama** — launch the AI server automatically on app open
- 🗂 **Smart Scan Config** — customise exactly which file types and folders are included or skipped

### GPU Support
- 🎮 **Full NVIDIA support** — including Blackwell RTX 50xx series (CUDA 12.8 / cu128)
- ⚡ **GPU embeddings** — sentence-transformer embeddings use CUDA automatically
- 🔧 **GPU Detect tool** — one-click check showing VRAM usage, GPU layers, and model offload status

---

## 🖥️ System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10 64-bit | Windows 11 64-bit |
| RAM | 8 GB | 16 GB+ |
| Storage | 6 GB free | 15 GB free |
| CPU | Any modern 64-bit | Quad-core or better |
| GPU | Not required | NVIDIA (any, including RTX 50xx) |
| Internet | Install only | Install + cloud AI providers (optional) |

---

## 📦 What Gets Installed

| Component | Size | Purpose |
|-----------|------|---------|
| Python 3.11 | ~30 MB | Runtime |
| Python packages | ~600 MB | ChromaDB, sentence-transformers, PDF support, OCR, speech |
| Tesseract OCR 5.4 | ~50 MB | Scanned PDF and image text extraction |
| PyTorch (CUDA 12.8 or CPU) | ~2.5 GB / ~200 MB | GPU-accelerated embeddings |
| Ollama engine | ~400 MB | Local AI model runner (always latest version) |
| llama3.2:1b (default model) | ~1.3 GB | Fast, capable default local AI |
| Whisper large-v3-turbo | ~1.6 GB | Local speech recognition (on first mic use) |
| **Total** | **~4 GB** | One-time download |

---

## 📁 Repository Structure

```
AI-Prowler/
├── AI-Prowler_INSTALL.exe       ← One-click installer (run this first)
├── UNINSTALL.bat                ← Clean removal tool
├── RAG_RUN.bat                  ← Launch AI Prowler directly
├── rag_gui.py                   ← Main GUI application
├── rag_preprocessor.py          ← Core indexing & query engine
├── requirements.txt             ← Python package list
├── create_shortcut.py           ← Desktop shortcut creator
├── generate_license.py          ← License key generator (developer tool)
├── rag_icon.ico                 ← Application icon
├── AI-Prowler Setup License.txt ← License agreement
├── COMPLETE_USER_GUIDE.md       ← Full documentation (also accessible from Help menu)
└── README.md                    ← This file
```

---

## 🚀 Supported AI Models (Local)

Models are ranked automatically based on your PC's RAM. Install any of them from within the app via Settings → Browse & Install Model.

| Model | Size | Min RAM | Maker | Best for |
|-------|------|---------|-------|---------|
| `qwen2.5:0.5b` | 0.4 GB | 2 GB | Alibaba | Ultra-fast, basic queries |
| `qwen2.5:1.5b` | 1.0 GB | 4 GB | Alibaba | Very fast, capable |
| `llama3.2:1b` ⭐ | 1.3 GB | 4 GB | Meta | **Default** — fast and capable |
| `gemma:2b` | 1.7 GB | 4 GB | Google | Compact and efficient |
| `llama3.2:3b` | 2.0 GB | 6 GB | Meta | Better quality, still fast |
| `qwen2.5:7b` | 4.7 GB | 8 GB | Alibaba | Excellent quality/speed ratio |
| `llama3.1:8b` | 4.7 GB | 8 GB | Meta | Strong general-purpose |
| `qwen2.5:14b` | 9.0 GB | 16 GB | Alibaba | High quality |
| `qwen2.5:32b` | 20.0 GB | 32 GB | Alibaba | Near-frontier on CPU |
| `llama3.1:70b` | 40.0 GB | 48 GB | Meta | Near-frontier quality |

*See COMPLETE_USER_GUIDE.md for the full 21-model catalogue.*

---

## ☁️ Optional Cloud AI Providers

Add an API key in Settings → External AI APIs to use these alongside your local model:

| Provider | Model | Free Tier |
|----------|-------|-----------|
| ChatGPT (OpenAI) | GPT-4o | Pay-per-use |
| Claude (Anthropic) | claude-opus-4-5 | $5 credit |
| Gemini (Google) | gemini-2.0-flash | ✅ Generous free tier |
| Grok (xAI) | grok-beta | Limited free |
| Llama API (Meta) | Llama-4-Scout-17B | ✅ Free tier |
| Mistral Large (Mistral AI) | mistral-large-latest | Limited free |

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
| Stores all data on your hard drive | Collect telemetry or analytics |
| Keeps API keys in your local config | Phone home or require an account |
| Uses Ollama for local inference | Send original files to cloud providers |
| Sends only question text + excerpts | Share any data with third parties |

---

## 📖 Documentation

The full **[COMPLETE_USER_GUIDE.md](COMPLETE_USER_GUIDE.md)** is included in every release and covers every feature in detail. It is also accessible from within the app via **Help → 📖 User Guide**.

---

## 🐛 Reporting Issues

Found a bug or have a feature request? Open an **[Issue](https://github.com/dvavro/AI-Prowler/issues)** and include:

- Your Windows version
- The error message (run `RAG_RUN.bat` to capture it in a console window)
- Your GPU model and the output of Settings → 🔍 Detect GPU
- What you were doing when it happened

errno22 manule fix
- in a doc command prompt or shortcut is Win + R key together, type cmd, press Enter
-uninstall huggingface-hub
"%LOCALAPPDATA%\Programs\Python\Python311\python.exe" -m pip uninstall huggingface-hub
- Delete the corrupted model cache
rmdir /s /q "%USERPROFILE%\.cache\huggingface\hub\models--sentence-transformers--all-MiniLM-L6-v2"
- Reinstall huggingface-hub
"%LOCALAPPDATA%\Programs\Python\Python311\python.exe" -m pip install huggingface-hub==0.26.5



---

## 📝 Changelog

See the **[Releases page](https://github.com/dvavro/AI-Prowler/releases)** for full version history.

### v3.0.0 (current)
- 🎮 NVIDIA Blackwell GPU support (RTX 50xx / CUDA 12.8)
- 🔄 Installer always updates Ollama to latest version (fixes GPU support on reinstall)
- 💾 File Output Mode now works with all providers including Ollama — auto-names unnamed code blocks
- 🖼️ OCR with Tesseract 5.4 — scanned PDFs and standalone images indexed automatically
- 🔧 GPU Detect tool with VRAM occupancy reporting
- 📄 System prompt injection for Ollama file-output instructions (more reliable filenames)

### v2.0
- ☁️ Six cloud AI providers (ChatGPT, Claude, Gemini, Grok, Llama API, Mistral)
- 📎 File attachments (images + text files) with vision support
- 💾 File Output Mode — auto-detected code blocks with Save buttons
- 🏅 RAM-aware model selector with ✅/⚠️ fit badges
- 🔍 Debug View — hide/show background processes
- 🗂 Smart Scan configuration tab

---

## ⚖️ License

PC version is free and open source. See [AI-Prowler Setup License.txt](AI-Prowler%20Setup%20License.txt) for full terms.

Mobile access requires a small app download fee and monthly subscription.

Copyright © 2026 David Kevin Vavro

---

*AI Prowler — Your Personal AI Knowledge Base*
*Local-first &nbsp;•&nbsp; Cloud-optional &nbsp;•&nbsp; 100% Yours*
