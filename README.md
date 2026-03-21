# 🐾 AI-Prowler — Agentic RAG Knowledge Base
**Version 4.1.0** · Free for Windows 10/11 · Local-first · Agent-powered

**Connect your personal document library to Claude — and let AI actively research it for you.**

No technical knowledge required &nbsp;•&nbsp; One-click installer &nbsp;•&nbsp; Works with Claude Desktop & Claude.ai &nbsp;•&nbsp; 100% private

---

## 📥 Download & Install

> **One installer. No configuration. Under 10 minutes.**

1. Go to the **[Releases page](https://github.com/dvavro/AI-Prowler/releases)** and download `AI-Prowler_INSTALL.exe`
2. Double-click the installer and follow the prompts
3. The installer sets up Python, all packages, Tesseract OCR, and Claude Desktop automatically
4. Sign in to Claude Desktop when it opens — then you're done

That's it. AI-Prowler and Claude Desktop are ready to use immediately after install.

---

## 🎯 What Is AI-Prowler?

AI-Prowler is an **Agentic RAG (Retrieval-Augmented Generation)** knowledge base. It indexes your local documents into a private vector database and exposes them to Claude as a set of intelligent search tools — so Claude can actively research your documents, follow leads, reformulate queries, and synthesize comprehensive answers on its own.

```
You ask Claude:    "Summarise the key risks in our Q3 contracts."

Claude thinks:     I should look at what contract documents are indexed...
Claude calls:      get_knowledge_base_overview()
Claude calls:      search_documents("Q3 contract risks")
Claude calls:      search_documents("liability indemnification clauses")
Claude calls:      get_chunk_context("contract_q3.pdf", 14)
Claude answers:    A detailed synthesis across all relevant documents.
```

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

### Option 1 — Claude Desktop (Recommended, Free)
Claude Desktop connects to AI-Prowler via MCP (Model Context Protocol) on your local machine. No internet needed for the connection itself.

- Installed automatically during setup
- No subscription required for the MCP connection
- Requires a Claude account (free tier available)
- Full agentic RAG — Claude calls your knowledge base tools automatically

### Option 2 — Claude.ai on Any Device (Mobile Subscription)
AI-Prowler's HTTP server and Cloudflare Tunnel expose your knowledge base to Claude.ai from anywhere — phone, tablet, or any browser.

- Requires an active Mobile Access subscription ($9.99/month)
- Works from any device with a browser
- Same full agentic RAG capability as Claude Desktop
- No app installation required on mobile devices

**Adding AI-Prowler as a Claude.ai Connector:**

1. In AI-Prowler → Settings → Remote Access, set a Bearer token and start the HTTP server and Cloudflare Tunnel
2. In Claude.ai → Settings → **Connectors** → **Add custom connector**
3. Enter your tunnel URL, e.g. `https://your-tunnel.com/mcp`
4. Authorize with your Bearer token when prompted
5. In any Claude.ai conversation, enable AI-Prowler from the Connectors/Tools panel

> **Tip:** Claude.ai in the browser lets you download any files Claude generates (code, reports, documents) directly to your device. The Claude Desktop app opens some file types in-app instead. If downloading Claude's outputs matters to your workflow, use Claude.ai in the browser.

### Option 3 — Desktop Ask Questions Tab (Optional, Local)
The built-in Ask Questions tab works standalone with a local Ollama model or cloud API keys. This is the classic RAG mode — useful for fully offline operation or privacy-sensitive environments where no Claude subscription is wanted.

- Optional — Ollama is NOT installed automatically
- Install Ollama and download models from Settings → Browse & Install Model
- Cloud providers (ChatGPT, Gemini, etc.) also supported via API keys

---

## ✨ Features

### Document Indexing
- 📚 **65+ file types** — PDFs, Word, Excel, PowerPoint, code, email, images (OCR), and more
- 🔍 **Semantic search** — finds relevant content even when exact words don't match
- ⚡ **Incremental indexing** — only re-processes files that have actually changed
- ⏸ **Pause / Resume** — stop mid-index and continue exactly where you left off
- 🔒 **100% local** — your documents never leave your machine

### Agentic RAG Tools (Claude Desktop & Claude.ai)
All tools are automatically available when Claude connects — no configuration needed.

| Tool | What Claude uses it for |
|---|---|
| `get_knowledge_base_overview` | Orients itself — what's indexed, what types |
| `search_documents` | Semantic search, called multiple times |
| `search_by_multiple_queries` | Parallel search with synonym queries |
| `get_chunk_context` | Expands around promising results |
| `get_document_chunks` | Reads a full document sequentially |
| `list_indexed_documents` | Browses available files by type or path |
| `how_to_use_ai_prowler` | Self-orienting guidance tool |

Claude also has tools to manage your knowledge base: add directories, update the index, check status, and more — all from a Claude conversation.

### Remote Access (Mobile Subscription)
- 🌐 **Cloudflare Tunnel** — secure HTTPS without opening firewall ports
- 🔐 **OAuth 2.0 + PKCE** — secure login flow compatible with Claude.ai connectors
- 😴 **Sleep prevention** — Windows stays awake while the HTTP server is running
- 📊 **Subscription status lights** — green/yellow/red in the Settings tab
- 🔔 **30-day grace period** — warning before access is suspended on non-payment

### OCR & Email
- 🖼️ **Automatic OCR** — scanned PDFs, contracts, old manuals, image files
- 📬 **All major email providers** — Gmail, Apple Mail, Thunderbird, Outlook, Yahoo
- 📊 **Incremental email indexing** — Message-ID deduplication, only new emails re-indexed

### Desktop Ask Questions Tab (Optional)
- 🤖 **Local Ollama** — 20+ models, completely offline (install separately)
- ☁️ **Cloud AI** — ChatGPT, Claude, Gemini, Grok, Llama API, Mistral
- 🎤 **Voice input** — local Whisper speech recognition
- 📎 **File attachments** — images and text files with vision support
- ⏹ **Stop query** — cancel any running query instantly

### GPU Support
- 🎮 **NVIDIA support** — including Blackwell RTX 50xx series (CUDA 12.8)
- ⚡ **GPU embeddings** — sentence-transformer embeddings use CUDA automatically
- 🔧 **GPU Detect tool** — one-click VRAM and model offload status check

---

## 🖥️ System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 64-bit | Windows 11 64-bit |
| RAM | 4 GB | 16 GB+ |
| Storage | 3 GB free | 10 GB free |
| CPU | Any modern 64-bit | Quad-core or better |
| GPU | Not required | NVIDIA (any) for local Ollama |
| Internet | Install only | Claude Desktop works locally |
| Claude account | Required for MCP | Claude Pro for Claude.ai connector |

> **RAM note:** Without local Ollama, AI-Prowler needs only 4 GB RAM. The embedding model (sentence-transformers) uses ~400 MB. Local Ollama models require additional RAM per model.

---

## 📦 What Gets Installed

| Component | Size | Purpose |
|---|---|---|
| Python 3.11 | ~30 MB | Runtime |
| Python packages | ~600 MB | ChromaDB, sentence-transformers, OCR, speech |
| Tesseract OCR 5.4 | ~50 MB | Scanned PDF and image text extraction |
| PyTorch (auto-detected) | ~200 MB – 2.5 GB | Embeddings (CPU or CUDA build) |
| Claude Desktop | ~200 MB | Primary AI interface via MCP |
| Cloudflare Tunnel | ~30 MB | Remote access for mobile/Claude.ai |
| **Total (no Ollama)** | **~1–3 GB** | Fast install, no model download |

**Ollama and AI models are NOT downloaded during install.** Add them later from Settings → Browse & Install Model if you want local offline AI.

---

## 📁 Repository Structure

```
AI-Prowler/
├── AI-Prowler_INSTALL.exe          ← One-click installer
├── UNINSTALL.bat                   ← Clean removal tool
├── RAG_RUN.bat                     ← Launch AI-Prowler directly
├── rag_gui.py                      ← Main GUI application
├── rag_preprocessor.py             ← Core indexing & retrieval engine
├── ai_prowler_mcp.py               ← MCP server (Claude Desktop & Claude.ai)
├── subscription_instructions.txt  ← Mobile subscription info (editable)
├── requirements.txt                ← Python package list
├── rag_icon.ico                    ← Application icon
├── AI-Prowler Setup License.txt    ← License agreement
├── COMPLETE_USER_GUIDE.md          ← Full documentation
└── README.md                       ← This file
```

---

## ☁️ Optional Cloud AI Providers (Ask Questions Tab)

| Provider | Model | Notes |
|---|---|---|
| ChatGPT (OpenAI) | GPT-4o | Pay-per-use |
| Claude (Anthropic) | claude-opus-4-5 | $5 credit to start |
| Gemini (Google) | gemini-2.0-flash | Generous free tier |
| Grok (xAI) | grok-beta | Limited free |
| Llama API (Meta) | Llama-4-Scout-17B | Free tier available |
| Mistral Large | mistral-large-latest | Limited free |

> These are for the standalone Ask Questions tab only. Claude Desktop MCP uses your Claude subscription, not an API key.

---

## 🔐 Privacy

| ✅ Does | ❌ Does NOT |
|---|---|
| Store all data on your hard drive | Upload your documents anywhere |
| Send only retrieved excerpts to Claude | Collect telemetry or analytics |
| Run indexing and embeddings locally | Require an account for desktop use |
| Keep API keys in your local config | Share any data with third parties |
| Work 100% offline for indexing | Send original files to any cloud |

---

## 📖 Documentation

The full **[COMPLETE_USER_GUIDE.md](COMPLETE_USER_GUIDE.md)** is included in every release and accessible from **Help → 📖 User Guide** inside the app.

---

## 🐛 Reporting Issues

Found a bug? Open an **[Issue](https://github.com/dvavro/AI-Prowler/issues)** and include:

- Windows version and GPU model
- Error message from `RAG_RUN.bat` (keeps a console window open)
- Output of Settings → 🔍 Detect GPU
- The install log at `%LOCALAPPDATA%\Temp\AI-Prowler\install_log.txt`
- The MCP log at `%LOCALAPPDATA%\AI-Prowler\mcp_server.log`

---

## 📝 Changelog

### v4.1.0 (current)
- 🌐 **Open Claude.ai button** — one-click launch of Claude.ai in the browser next to Launch Claude Desktop
- 🚀 **Agentic RAG Quick Start** — Help → Quick Start rewritten to lead with Agentic RAG + Claude Desktop as primary workflow; mobile subscription path as Option 2
- 📖 **Connector setup guide** — User Guide now includes step-by-step instructions for adding AI-Prowler as a Claude.ai connector
- ⚙️ **Settings documentation** — complete Settings tab reference added to User Guide (all options, OCR debug, GPU detect, mic silence timeout)
- 🔒 **stdio/HTTP clarity** — documentation explicitly distinguishes Claude Desktop (stdio, no server needed) from Claude.ai (HTTP + Cloudflare Tunnel)

### v4.0.0
- 🤖 **Agentic RAG** — 6 new MCP tools for Claude to actively research your knowledge base
- 🗣️ **MCP guidance** — instructions sent to Claude at every handshake for optimal tool use
- 📱 **Mobile subscriptions** — Claude.ai connector with subscription management GUI
- 🔐 **OAuth 2.0 + PKCE** — secure Claude.ai connector authentication
- 😴 **Sleep prevention** — PC stays awake while HTTP server is running
- 📊 **Subscription status lights** — live green/yellow/red indicators in Settings
- ⚡ **Faster install** — no Ollama or model auto-download (add manually if needed)

### v3.0.0
- 🎮 NVIDIA Blackwell GPU support (RTX 50xx / CUDA 12.8)
- 💾 File Output Mode for all providers
- 🖼️ Tesseract OCR 5.4 — scanned PDFs and images
- 🔧 GPU Detect tool

### v2.0
- ☁️ Six cloud AI providers
- 📎 File attachments with vision support
- 🏅 RAM-aware model selector

---

## ⚖️ License

Desktop use is free and open source under the AI-Prowler Software License.
Mobile / remote access requires a managed subscription.
See [AI-Prowler Setup License.txt](AI-Prowler%20Setup%20License.txt) for full terms.

Copyright © 2026 David Kevin Vavro · david.vavro1@gmail.com

---

*AI-Prowler — Your Personal Agentic RAG Knowledge Base*
*Local-first &nbsp;•&nbsp; Agent-powered &nbsp;•&nbsp; 100% Yours*
