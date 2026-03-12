# AI Prowler — Personal AI Knowledge Base
**Complete User Guide · Version 3.0.0**

*Local-first · Cloud-optional · 100% Yours*

---

## Table of Contents

1. [What Is AI Prowler?](#1-what-is-ai-prowler)
2. [System Requirements](#2-system-requirements)
3. [Installation](#3-installation)
4. [Quick Start (5 Minutes)](#4-quick-start-5-minutes)
5. [Tab Reference](#5-tab-reference)
   - [🔍 Ask Questions](#51--ask-questions)
   - [📚 Index Documents](#52--index-documents)
   - [🔄 Update Index](#53--update-index)
   - [🗂 Smart Scan](#54--smart-scan)
   - [⏰ Schedule](#55--schedule)
   - [⚙️ Settings](#56-️-settings)
6. [AI Models — Local](#6-ai-models--local)
7. [Cloud AI Providers](#7-cloud-ai-providers)
8. [File Attachments & File Output Mode](#8-file-attachments--file-output-mode)
9. [Voice Input (Microphone)](#9-voice-input-microphone)
10. [Email Indexing](#10-email-indexing)
11. [OCR — Scanned PDFs & Images](#11-ocr--scanned-pdfs--images)
12. [GPU Acceleration](#12-gpu-acceleration)
13. [Supported File Types](#13-supported-file-types)
14. [Scheduling Automatic Updates](#14-scheduling-automatic-updates)
15. [Command Line (Advanced)](#15-command-line-advanced)
16. [Privacy & Security](#16-privacy--security)
17. [Troubleshooting](#17-troubleshooting)
18. [Tips & Best Practices](#18-tips--best-practices)
19. [Frequently Asked Questions](#19-frequently-asked-questions)
20. [Uninstalling](#20-uninstalling)
21. [File & Folder Reference](#21-file--folder-reference)
22. [Version History](#22-version-history)

---

## 1. What Is AI Prowler?

AI Prowler is a **local RAG (Retrieval-Augmented Generation)** application. It indexes your documents into a private vector database, and when you ask a question it retrieves the most relevant passages and feeds them to an AI model that writes a grounded, accurate answer.

```
You ask:       "What was the mutation rate in my NEAT project?"

AI Prowler:    According to NEAT_Documentation.md, the mutation rate
               is set to 0.02 (2%). This controls how frequently
               weights and connections mutate during evolution...
```

Everything runs on your own machine by default. Your documents are never uploaded anywhere unless you choose to use a cloud AI provider — in that case only your question text and short retrieved excerpts are sent, never your original files.

**What it does:**
- 📚 Indexes documents, code, email, spreadsheets, and 55+ file types
- 🔍 Answers questions using your own content, not just general AI knowledge
- 🤖 Runs 100% offline using local Ollama (default)
- ☁️ Optionally connects to cloud AI — ChatGPT, Claude, Gemini, Grok, Llama API, Mistral Large
- 🔒 Local-first — no cloud contact unless you explicitly add an API key
- 📬 Deep email support — Gmail, Apple Mail, Thunderbird, Yahoo, Outlook, and more
- ⚡ Incremental updates — only re-processes files that changed
- 🎤 Voice input — speak questions using local Whisper speech recognition
- 📎 File attachments — attach images and documents to questions
- 💾 File Output Mode — AI-written code files get one-click Save buttons
- ⏰ Scheduled auto-updates — keep the index current automatically
- 🖨 OCR support — scanned PDFs and image files are automatically read with Tesseract

---

## 2. System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10 64-bit | Windows 11 64-bit |
| RAM | 8 GB | 16 GB+ |
| Storage | 6 GB free | 15 GB free |
| CPU | Any modern 64-bit | Quad-core or better |
| GPU | Not required | NVIDIA (speeds up 7b+ models) |
| Internet | Install only | Install + cloud AI (optional) |

**GPU note:** Any NVIDIA GPU is supported including the RTX 50xx Blackwell series (RTX 5060, 5070, 5080, 5090). The installer automatically detects your GPU and installs the CUDA 12.8 build of PyTorch for full Blackwell compatibility. AMD and Intel GPUs are not supported for Ollama inference — they fall back to CPU automatically.

### Download Sizes (First Install Only)

| Component | Size |
|-----------|------|
| Python 3.11.8 | ~30 MB |
| Python packages | ~600 MB |
| Tesseract OCR | ~50 MB |
| Ollama engine | ~400 MB |
| AI model — llama3.2:1b (default) | ~1.3 GB |
| Whisper speech model (first mic use) | ~1.6 GB |
| **Total** | **~4 GB** |

---

## 3. Installation

### Running the Installer

Double-click **AI-Prowler_INSTALL.exe** and follow the prompts. The installer handles everything automatically.

| Step | What happens |
|------|-------------|
| 1 | Installs Python 3.11.8 to `%LocalAppData%\Programs\Python\Python311` |
| 2 | Upgrades pip and installs all Python packages from `requirements.txt` |
| 3 | Downloads and installs Tesseract OCR 5.4 (enables scanned PDF and image indexing) |
| 4 | Detects your GPU and installs the correct PyTorch build (CUDA 12.8 or CPU-only) |
| 5 | Downloads and installs the latest Ollama (always updated, even on reinstall) |
| 6 | Pulls the `llama3.2:1b` default AI model (~1.3 GB) |
| 7 | Creates a Desktop shortcut and Start Menu entry |

### Reinstalling / Upgrading

Just run the installer again. It will update Ollama to the latest version (important for new GPU architectures), update all application files, and preserve your existing RAG database and settings.

### What Gets Installed Where

| Item | Location |
|------|----------|
| Application files | `C:\Program Files\AI-Prowler\` |
| Python 3.11 | `%LocalAppData%\Programs\Python\Python311\` |
| Tesseract OCR | `%LocalAppData%\Programs\Tesseract-OCR\` |
| Ollama engine | `%LocalAppData%\Programs\Ollama\` |
| Ollama models | `%UserProfile%\.ollama\models\` |
| RAG database | `%UserProfile%\AI-Prowler\rag_database\` |
| Config file | `%UserProfile%\.rag_config.json` |
| Install log | `%LocalAppData%\Temp\AI-Prowler\install_log.txt` |

> **Tip:** If anything goes wrong during install, open `install_log.txt` — it contains the exact error, return codes, and every step the installer took. This is the first place to look when troubleshooting.

---

## 4. Quick Start (5 Minutes)

**Step 1 — Index your documents**
1. Open AI Prowler from the Desktop shortcut
2. Click the **📚 Index Documents** tab
3. Click **Browse… ▼** and choose **Browse Folder…** to select a folder
4. Click **▶ Start Indexing Queue** and wait for it to finish

**Step 2 — Ask a question**
1. Click the **🔍 Ask Questions** tab
2. Type your question in the text box
3. Press **Ctrl+Enter** or click **Ask Question**
4. The answer streams in the box below

**Step 3 — Get code files with one-click Save**
1. Tick **📄 File Output Mode** in the Ask Questions tab
2. Ask the AI to write you a script
3. A **💾 Save** button appears automatically for each file in the answer

---

## 5. Tab Reference

### 5.1 🔍 Ask Questions

This is the main tab you use every day.

#### Your Question box

Type your question here. The box supports multi-line input — press **Enter** for a new line and **Ctrl+Enter** to submit.

#### 🎤 Microphone button *(shown when faster-whisper is installed)*

Click the microphone to speak your question using the local Whisper `large-v3-turbo` model. Nothing is sent to any cloud transcription service. The model downloads automatically (~1.6 GB) on first use.

- **Append mode** — tick "Append (add to existing text)" to add spoken words to whatever is already in the question box
- **Auto-stop** — recording stops automatically after a configurable silence period (set in Settings → Microphone)

#### 📎 Attachments

Click **📎 Attach Files…** to include images or files alongside your question.

- **Images** (.jpg, .png, .bmp, .gif, .tiff) — included as base64 for vision-capable models. Cloud providers (Claude, Gemini, ChatGPT-4o) fully support vision; local Ollama requires a vision model such as `llava`
- **Text files** (.txt, .md, .pdf, .docx) — file content is extracted and appended to your question before it is sent to the AI
- **Clear All** removes all attached files at once

#### 📄 File Output Mode

When ticked, AI Prowler instructs the AI to label every code block it writes with a filename. After the answer finishes, the **📁 Files in Answer** panel appears with a **💾 Save** button and **📋 Copy** button for each detected file.

Supported auto-detection patterns:
- ` ```python my_script.py ` — language + filename
- ` ```my_script.py ` — filename only
- `### FILE: name.ext ###` ... `### END FILE ###` — explicit block marker
- ` ```python ` (no filename) — Ollama fallback: auto-named `script_1.py`, etc.

#### Context Chunks

Controls how many document excerpts are retrieved from your index and fed to the AI.

| Setting | Use when |
|---------|----------|
| Auto (3) | Best default — calculates optimally for most questions |
| 1–3 | Fast answers, focused topics |
| 4–6 | Broader questions spanning multiple files |
| 7–20 ⚠ reload | Deep research — triggers model reload, adds 2–12 minutes on CPU |

Values marked **⚠ reload** require a larger model context window. AI Prowler automatically re-prewarns the model at the required size when you switch to these values.

#### AI Provider

Select which AI to use for this question. The dropdown lists all installed Ollama models first, then any configured cloud providers.

The coloured dot shows current status:
- 🟢 Green — ready (Ollama warmed, or cloud key valid)
- 🟡 Yellow — loading / connecting
- 🔴 Red — not available

#### Action Buttons

| Button | Action |
|--------|--------|
| **Ask Question** | Submit the question (same as Ctrl+Enter) |
| **⏹ Stop** | Cancel a running query immediately |
| **💾 Save Answer** | Save the full answer text to `.txt` or `.md` |
| **⚡ Load AI Model** | Manually trigger Ollama model loading |

#### Model Status Indicator

| Indicator | Meaning |
|-----------|---------|
| ⚫ Grey — "Model not loaded" | Ollama has not yet been contacted |
| 🟡 Yellow — "Loading model…" | Pre-warm is in progress |
| 🟢 Green — "Model ready" | The model is loaded and queries respond quickly |

If you see grey and your first query feels slow, click **⚡ Load AI Model** to pre-warm before you start typing.

#### Answer Box

Responses stream in token-by-token. After the answer finishes:
- The elapsed time is shown (e.g. `✅ Done in 5s`)
- The **📁 Files in Answer** panel appears if any code blocks were detected

---

### 5.2 📚 Index Documents

Use this tab to build or rebuild your knowledge base.

#### The Directory Queue

AI Prowler uses a queue system — stage as many folders and files as you want, then process them all in one batch.

| Button | What it does |
|--------|-------------|
| **Browse… ▼** | Opens a dropdown with two choices (see below) |
| **Browse Files (multi-select)…** | File picker — Ctrl/Shift click to select multiple files |
| **Browse Folder…** | Opens a folder browser |
| **➕ Add to Queue** | Adds the path currently typed in the entry box |
| **Type + Enter** | Type a path directly and press Enter |

| Button | What it does |
|--------|-------------|
| **❌ Remove Selected** | Removes the highlighted item from the queue |
| **🗑 Clear Queue** | Clears the entire queue |
| **Include subdirectories** | When checked, every subfolder is scanned recursively (default ON) |

#### Smart Scan Option

When ticked (default), AI Prowler pre-scans and automatically skips:
- Executable and compiled binary files (`.exe`, `.dll`, `.pyc`, …)
- Media files — images, audio, video, fonts
- Archive files — `.zip`, `.rar`, `.7z`, …
- System directories — `.git`, `node_modules`, `__pycache__`, `venv`, `build`, `.idea`, `.vscode`, and more

**Pre-scan only** — check this to see a full report of what *would* be indexed without actually indexing anything. Useful before committing to a large folder.

#### Action Buttons

| Button | Function |
|--------|---------|
| **▶ Start Indexing Queue** | Begin processing all queued items |
| **⏸ Pause** | Freeze at the end of the current file — click again to Resume |
| **⏹ Stop** | Stop cleanly after the current file and save progress |
| **🔍 Scan Queue** | Run pre-scan and show a report without indexing |

#### Progress Display

Three live indicators appear while indexing runs:
- **Animated progress bar** on the left
- **Directory/file counter** in the centre — e.g. `Dir 2/4: Projects` or `[Email 847/12,034] Re: Budget`
- **Elapsed timer** on the right — ticks up in real time

#### Pause and Resume

- **Pause** freezes the worker thread immediately. The timer pauses too. Click **Resume** to continue from exactly where you stopped.
- **Stop** saves your exact position — the Start button changes to **▶ Resume Indexing**. Clicking it picks up from where you stopped, including position within a partially-processed directory.

#### After Indexing

When a directory finishes indexing it is automatically **registered for tracking** — it appears in the Update Index tab and becomes eligible for scheduled updates.

---

### 5.3 🔄 Update Index

Use this tab to keep your knowledge base current after adding or changing files.

#### How File Tracking Works

When a directory is indexed, AI Prowler records each file's path, modification time, and size in `%UserProfile%\.rag_file_tracking.json`. On the next update run:

| File status | What happens |
|-------------|-------------|
| New file | Indexed and added to ChromaDB |
| Modified file | Old chunks deleted, new chunks added |
| Deleted file | Chunks removed from ChromaDB |
| Unchanged file | Skipped entirely — no processing |

For email archives the engine goes deeper — see the Email chapter for how per-message deduplication works.

#### Tracked Directories List

Shows every directory registered for tracking. The info bar shows the exact paths of both tracking data files so you know where they live — they are separate from the ChromaDB database and survive a database wipe.

| Button | Action |
|--------|--------|
| **🔄 Refresh List** | Re-reads the directory list from disk |
| **🗑 Remove Selected** | Untracks the selected directory and deletes its vectors from the database |

The actual files on disk are NOT touched. You can re-index the directory later if needed.

#### Update Buttons

| Button | Action |
|--------|--------|
| **Update Selected** | Re-index only the highlighted directory |
| **Update All** | Re-index every tracked directory |

---

### 5.4 🗂 Smart Scan

Customise exactly which file types AI Prowler indexes and which it ignores. All changes take effect immediately and are saved to `%UserProfile%\.rag_config.json`.

#### Supported Extensions (left panel)

The **✅ Supported Extensions** list contains every file type that will be indexed (55+ types by default).
- **➕ Add** — type an extension (e.g. `.nfo`) and press Enter or click Add. The leading dot is added automatically.
- **❌ Remove** — click an extension to select it, then click Remove.
- **Conflict detection** — if you try to add an extension already in the Skipped list, AI Prowler warns and blocks the add.

#### Skipped Extensions (right panel)

Types that are always ignored — compiled binaries, media, archives, etc. Same Add/Remove controls.

#### Skipped Directories (bottom panel)

Folder *names* (not full paths) that are skipped when walking any directory tree. Defaults include `.git`, `node_modules`, `__pycache__`, `venv`, `build`, `dist`, `.idea`, `.vscode`, and more.

Add project-specific folders (e.g. `backup`, `.cache`, `temp`) to exclude them from all future scans.

#### Save and Reset

| Button | Effect |
|--------|--------|
| **💾 Save Changes** | Explicitly saves (changes also auto-save as you edit) |
| **↩ Reset to Defaults** | Restores all three lists to built-in defaults — asks for confirmation |

---

### 5.5 ⏰ Schedule

Automate index updates so your knowledge base stays current without manual effort.

#### Schedule Setup

1. Enter a **Run time** in 24-hour format (e.g. `08:00`, `14:30`)
2. Tick the days you want it to run — **Weekdays** and **Every day** buttons for quick selection
3. Click **✅ Set Schedule**

AI Prowler registers a Windows Task Scheduler task named `AI Prowler Auto-Update` that runs the update command against all tracked directories.

#### Schedule Control

| Control | Effect |
|---------|--------|
| **Disable Schedule** | Suspends the task without deleting it |
| **Remove Schedule** | Permanently deletes the scheduled task |
| **Refresh Status** | Polls Task Scheduler and updates the display |

#### Status Display

```
Active:
  ✅ Schedule Active
  Next Run: 2/25/2026 8:00 AM

Not set:
  ❌ No Schedule Set
```

#### Requirements

- At least one tracked directory in the Update Index tab
- Windows Task Scheduler service running (on by default in all Windows versions)

---

### 5.6 ⚙️ Settings

The Settings tab is scrollable — scroll down to see all sections.

#### Active Model

Selects which local Ollama model is used for queries. The dropdown displays each model with a RAM-fit indicator:
- **✅** — fits comfortably in your RAM (recommended)
- **⚠️** — may run slowly or cause memory swapping

Click **Browse & Install Model…** to open the model browser, which shows all available models with their size, minimum RAM, maker, and install status.

#### External AI APIs

Enter API keys for cloud providers. Keys are stored locally in `%UserProfile%\.rag_config.json` and are never transmitted anywhere except directly to the provider's own API when you make a query.

For each provider you can:
- **👁 Toggle** — show or hide the key in the entry field
- **Save** — save the key to config
- **🔌 Test** — fire a live test ping and see a detailed result popup
- **🔑 Get Key** — open the provider's API key page in your browser

**Status dot colours:**

| Dot | Meaning |
|-----|---------|
| ⚫ Grey | No API key saved |
| 🟢 Green | Key saved and connection verified |
| 🟠 Orange | Provider is temporarily rate-limited |

**Auto-fallback to Local Ollama** — when this checkbox is ON (default), if an external provider fails or returns a rate-limit error, AI Prowler silently falls back to your local Ollama model and notes the fallback in the answer.

#### Database

| Button | Effect |
|--------|--------|
| **View Statistics** | Shows total chunks, unique files, and collection metadata |
| **Clear Database** | Permanently deletes all indexed content — asks for confirmation. Does not affect the file-tracking database or email index. |

#### Query Output

| Option | Effect |
|--------|--------|
| **Show source references** | Prints file paths, similarity scores, and query timing with every answer |
| **Enable debug output** | Prints token counts, context details, and a full curl test command |
| **Debug View** | Shows background DOS windows in the foreground instead of hidden |

> **Tip:** Use Debug View temporarily if you need to inspect Ollama server logs or troubleshoot connection issues, then turn it off for everyday use.

#### Microphone / Speech Input *(visible when faster-whisper is installed)*

**Auto-stop after silence** — a slider from 1.0 to 8.0 seconds controlling how long Whisper waits after you stop speaking before ending the recording automatically.
- **Short (1–2s)** — snappy for short direct questions
- **Long (4–8s)** — better if you pause between phrases or speak slowly

#### GPU Acceleration

Controls how many AI model layers Ollama offloads to your GPU.

| Value | Meaning |
|-------|---------|
| -1 (default) | **Auto** — Ollama decides how many layers fit in available VRAM |
| 0 | **CPU only** — use if GPU causes errors or VRAM is insufficient |
| 1–99 | **Partial offload** — fine-tune for laptops with limited VRAM |

**🔍 Detect GPU** — runs a background scan identifying your GPU model, VRAM size, and whether the embedding model is using CUDA.

**✅ Apply & Reload** — saves the layers value and reloads the Ollama configuration immediately — no app restart needed.

#### OCR — Scanned PDFs & Image Files

Shows the current status of Tesseract OCR:
- ✅ **OCR active — Tesseract detected** — scanned PDFs and image files will be indexed automatically
- ⚠️ **Tesseract binary not found** — reinstall AI Prowler to restore the Tesseract binary

#### Ollama Server

**Auto-start Ollama server** — when enabled, AI Prowler launches `ollama serve` automatically on startup and shuts it down on exit. The window visibility depends on the **Debug View** setting.

> **Recommendation:** Enable auto-start if you only use Ollama through AI Prowler and want a one-click experience. Leave it disabled if you run other Ollama-based tools and want the server to stay running independently.

---

## 6. AI Models — Local

Models run entirely on your hardware via Ollama — no internet required after download.

| Model | Size | Min RAM | Maker | Best for |
|-------|------|---------|-------|---------|
| `qwen2.5:0.5b` | 0.4 GB | 2 GB | Alibaba | Ultra-fast, basic queries |
| `qwen2.5:1.5b` | 1.0 GB | 4 GB | Alibaba | Very fast, surprisingly capable |
| `llama3.2:1b` ⭐ | 1.3 GB | 4 GB | Meta | **Default** — fast and capable |
| `gemma:2b` | 1.7 GB | 4 GB | Google | Compact and efficient |
| `qwen2.5:3b` | 1.9 GB | 6 GB | Alibaba | Efficient small model |
| `llama3.2:3b` | 2.0 GB | 6 GB | Meta | Better quality, still fast |
| `mistral:7b` | 4.1 GB | 8 GB | Mistral AI | Fast and efficient 7B |
| `llama3.1:8b` | 4.7 GB | 8 GB | Meta | Strong general-purpose |
| `qwen2.5:7b` | 4.7 GB | 8 GB | Alibaba | Excellent quality/speed ratio |
| `gemma2:9b` | 5.5 GB | 8 GB | Google | Improved Gemma, strong |
| `qwen2.5:14b` | 9.0 GB | 16 GB | Alibaba | High quality |
| `gemma2:27b` | 16.0 GB | 32 GB | Google | Large, high quality |
| `llama3.1:70b` | 40.0 GB | 48 GB | Meta | Near-frontier quality |
| `qwen2.5:72b` | 47.0 GB | 64 GB | Alibaba | Top-tier, high RAM needed |

**Installing a model:** Go to Settings → Browse & Install Model, select a model, click **Download**.

**Choosing a model:**
- Start with `llama3.2:1b` (default) for speed on any machine
- Move to `llama3.1:8b` or `qwen2.5:7b` for better quality on 16 GB+ RAM
- Use `qwen2.5:14b` or higher only if your PC has 16 GB+ free RAM

---

## 7. Cloud AI Providers

Cloud providers give you access to frontier models (GPT-4o, Claude, Gemini) that are far larger than any model you can run locally. Only your question and retrieved document excerpts are sent — never your original files.

| Provider | Model | Free Tier |
|----------|-------|-----------|
| ChatGPT (OpenAI) | GPT-4o | Pay-per-use |
| Claude (Anthropic) | claude-opus-4-5 | $5 credit on sign-up |
| Gemini (Google) | gemini-2.0-flash | ✅ Generous free tier |
| Grok (xAI) | grok-beta | Limited free |
| Llama API (Meta) | Llama-4-Scout-17B | ✅ Free tier |
| Mistral Large (Mistral AI) | mistral-large-latest | Limited free |

### Setting Up a Cloud Provider

1. Go to **Settings → External AI APIs**
2. Click **🔑 Get Key** to open the provider's key page in your browser
3. Paste your key into the entry field
4. Click **Save**, then **🔌 Test** to verify it works
5. In the **Ask Questions** tab, select the provider from the **AI Provider** dropdown

### Provider Notes

**Gemini (Google)** — the most generous free tier. Great first choice for trying cloud AI at no cost.

**Llama API (Meta)** — free tier access to Meta's latest Llama 4 models hosted on Meta's infrastructure.

**Claude (Anthropic)** — high-quality reasoning, excellent at code and document analysis.

**ChatGPT (OpenAI)** — GPT-4o is multimodal; image attachment queries work especially well here.

---

## 8. File Attachments & File Output Mode

### Attaching Files to a Question

Click **📎 Attach Files…** in the Ask Questions tab. Supported types:
- **Images** (.jpg, .png, .bmp, .gif, .tiff) — sent as vision data to cloud providers; requires a vision-enabled Ollama model (e.g. `llava`) for local use
- **Text files** (.txt, .md, .pdf, .docx) — content is extracted and appended to your question

Use **🗑 Clear All** to remove all attached files before your next question.

### File Output Mode

Tick **📄 File Output Mode** to instruct the AI to label every file it produces with a filename. After the answer streams in, the **📁 Files in Answer** panel appears above the answer box.

Each detected file gets its own row showing:
- The filename (e.g. `hello_world.py`)
- A **💾 Save** button — opens a Save dialog with the filename pre-filled
- A **📋 Copy** button — copies the file content to the clipboard

This works with all providers. If Ollama doesn't label a file, the fallback auto-names unnamed code blocks (`script_1.py`, `script_1.js`, etc.).

---

## 9. Voice Input (Microphone)

The microphone button (🎤) appears in the Ask Questions tab when `faster-whisper` and `sounddevice` are installed (included in the default install).

### First Use

The Whisper `large-v3-turbo` model (~1.6 GB) downloads automatically the first time you click the mic button. This is a one-time download — subsequent launches load it instantly from cache.

### Using the Microphone

1. Click 🎤 to start recording (button turns red / shows "🔴 Recording…")
2. Speak your question
3. Recording stops automatically after the silence threshold (default 3 seconds)
4. The transcribed text appears in the question box
5. Click **Ask Question** or press **Ctrl+Enter** to submit

### Append Mode

Tick **Append (add to existing text)** before recording to add the transcription after whatever is already in the question box. Useful for composing long questions across multiple recording sessions.

### Adjusting the Silence Threshold

Go to **Settings → Microphone / Speech Input** and drag the **Auto-stop after silence** slider:
- **1–2 seconds** — stops quickly after you finish speaking
- **4–8 seconds** — waits longer, giving you time to pause mid-sentence

---

## 10. Email Indexing

AI Prowler has first-class support for email from every major provider. Indexed emails behave exactly like documents — ask "What did John say about the budget in April?" and get answers citing specific messages.

### How It Works

**Single-message files** (`.eml`, `.msg`, `.emlx`) are indexed like any other document.

**Multi-message archives** (`.mbox`, `.rmail`, `.babyl`, `.mmdf`) use the **per-email incremental indexer**:

1. Every message is identified by a **stable unique ID** derived from its `Message-ID` header (or a fingerprint of From + Date + Subject when no Message-ID is present)
2. A local database at `%UserProfile%\.rag_email_index.json` records which IDs have already been indexed
3. On re-import, only messages with a new ID are processed — a 100,000-message archive that gained 200 new emails processes only those 200
4. Messages removed from the archive are automatically deleted from ChromaDB
5. The Stop button responds after every individual message — clicking Stop while processing a 50 GB archive responds within seconds

### Supported Formats

| Format | Extension | Providers |
|--------|-----------|-----------|
| MBOX archive | `.mbox` | Gmail, Thunderbird, Apple Mail, Yahoo (via bridge) |
| Single message | `.eml` | Outlook drag-and-drop, Windows Live Mail |
| Outlook message | `.msg` | Outlook, Exchange |
| Apple Mail message | `.emlx` | Apple Mail direct folder |
| GNU RMAIL / Babyl | `.rmail` `.babyl` | GNU Emacs mail formats |
| MMDF format | `.mmdf` | Legacy Unix mail |

### Exporting From Every Major Provider

#### Gmail (Google)

Gmail exports in `.mbox` format via Google Takeout.

1. Go to [takeout.google.com](https://takeout.google.com) and sign in
2. Click **Deselect all**, then scroll down and check only **Mail**
3. Click **All Mail data included** to choose specific labels (Inbox, Sent, a project label) rather than your entire mailbox
4. Choose delivery: `.zip`, frequency: Export once, size: up to 50 GB per file
5. Click **Create export** — Google emails a download link when it's ready
6. Download and extract the `.zip` — inside you will find files like `All mail Including Spam and Trash.mbox` or one `.mbox` per label
7. Add the `.mbox` file(s) to the AI Prowler index queue

> **Re-exporting:** When you export again next month, Google regenerates the `.mbox` from scratch. AI Prowler handles this correctly — it uses `Message-ID` to identify what's new, so only genuinely new messages are processed even though the whole file is new.

#### Apple Mail and iCloud Mail

**Export as .mbox (recommended for large mailboxes):**
1. Open the Mail app on your Mac
2. In the sidebar, select the mailbox you want to export
3. Go to **Mailbox → Export Mailbox…**
4. Choose a save location and click **Choose**
5. Apple Mail saves a `.mbox` package — on Windows (after copying) it becomes a standard `.mbox` file
6. Add it to the AI Prowler index queue

**Access raw .emlx files directly (no export needed):**
Apple Mail's internal storage is at `~/Library/Mail/`. Each message is an individual `.emlx` file. Add the `Mail` folder or specific account sub-folders to the AI Prowler queue — smart scan will find and index all `.emlx` files recursively.

**iCloud Mail** uses the same Apple Mail client. Make sure your iCloud Mail is synced to the local Mail app first (Mail → Preferences → Accounts → check the account is enabled).

#### Thunderbird (Mozilla)

Thunderbird stores each folder as a single raw `.mbox` file on disk — **no export step is needed**.

| OS | Default path |
|----|-------------|
| Windows | `C:\Users\YourName\AppData\Roaming\Thunderbird\Profiles\[profile]\Mail\` |
| macOS | `~/Library/Thunderbird/Profiles/[profile]/Mail/` |
| Linux | `~/.thunderbird/[profile]/Mail/` |

Inside each account folder you will find files named `Inbox`, `Sent`, `Drafts`, etc. with no file extension — these are standard mbox files. Either add the entire `Mail` folder to the queue (smart scan finds them automatically), or copy specific files, rename with a `.mbox` extension, and add those.

> **Keeping it current:** Because Thunderbird's mbox files are updated as new mail arrives, you can schedule AI Prowler to re-scan the Thunderbird folder weekly. The incremental indexer picks up only new messages each time.

#### Yahoo Mail

Yahoo does not provide a direct export tool. The recommended path is to use Thunderbird as a bridge.

**Thunderbird bridge (recommended):**
1. Add your Yahoo account to Thunderbird using IMAP
2. Let Thunderbird sync (can take hours for a large mailbox)
3. Point AI Prowler at the Thunderbird profile folder

**Yahoo IMAP settings:**
- Server: `imap.mail.yahoo.com` · Port: `993` · SSL/TLS: Yes
- Use a Yahoo **App Password** — go to [security.yahoo.com](https://security.yahoo.com) → Manage app passwords → Generate one for Thunderbird. Your regular Yahoo password will not work for IMAP.

**Alternative — MailStore Home (free):**
Download from [mailstore.com](https://www.mailstore.com/en/products/mailstore-home), add Yahoo via IMAP, export to `.mbox`.

#### Outlook / Microsoft 365 / Exchange

Outlook's native format is `.pst`/`.ost` — a proprietary format that requires conversion.

**Option A — Drag to folder (small batches):**
1. Open Outlook
2. Select messages (Ctrl+A to select all in a folder)
3. Drag and drop them onto a Windows folder — Outlook saves each as an `.eml` file
4. Add that folder to the AI Prowler queue

**Option B — MailStore Home (large mailboxes, recommended):**
1. Download MailStore Home (free)
2. Add your Outlook/Exchange account or import from a `.pst` file
3. Export to `.mbox` or `.eml` format
4. Add to the AI Prowler queue

> **Note:** `.pst` and `.ost` files cannot be indexed directly — they use a proprietary binary format. Conversion to `.mbox` or a folder of `.eml` files first is the reliable path.

#### Windows Live Mail / Windows Mail (legacy)

These apps stored each message as an individual `.eml` file.

Default storage location: `C:\Users\YourName\AppData\Local\Microsoft\Windows Live Mail\`

Add that folder directly to the AI Prowler queue — smart scan finds all `.eml` files recursively.

#### Other Clients

| Client | How to export |
|--------|--------------|
| **Evolution** (Linux) | File → Save As Mbox |
| **KMail** (Linux) | Folder → Export → mbox |
| **Mutt / Neomutt** | Uses mbox or Maildir natively — add the mbox file or folder directly |
| **Proton Mail** | Use Proton Mail Bridge (IMAP) → Thunderbird → AI Prowler |
| **Fastmail** | Settings → Export → mbox per folder |
| **Zoho Mail** | Settings → Data Migration → Export → mbox |

---

## 11. OCR — Scanned PDFs & Images

AI Prowler automatically OCRs any document where the text layer is missing or too short.

### What Gets OCRed

- **Scanned PDFs** — contracts, court documents, manuals, old reports, living trusts
- **Image files** — `.jpg`, `.jpeg`, `.png`, `.bmp`, `.tiff`, `.tif`, `.gif`

### How It Works

1. `pdfplumber` attempts to extract the text layer from each PDF page
2. If fewer than 150 characters are found, the page is treated as image-only
3. `pypdfium2` renders the page at 300 DPI to a PIL image
4. `pytesseract` (Tesseract 5.4 OCR engine) extracts the text
5. The extracted text is chunked and indexed normally

### Verifying OCR Status

Go to **Settings → OCR — Scanned PDFs & Image Files**:
- ✅ **OCR active — Tesseract detected** — everything is working
- ⚠️ **Tesseract binary not found** — reinstall AI Prowler to restore Tesseract

---

## 12. GPU Acceleration

AI Prowler uses the GPU in two places:

| Component | GPU support |
|-----------|-------------|
| Sentence embeddings (indexing & search) | ✅ NVIDIA CUDA — automatic via PyTorch |
| LLM inference (Ollama) | ✅ NVIDIA CUDA — controlled by GPU Layers setting |

### Checking GPU Status

Go to **Settings → GPU Acceleration** and click **🔍 Detect GPU**. The output shows:
- GPU model and VRAM
- Whether the embedding model is using CUDA
- Whether Ollama's LLM is running on GPU or CPU
- How much VRAM the loaded model is occupying

### Updating Ollama for New GPUs

If you upgrade your GPU to a newer architecture, run the AI Prowler installer again. It always downloads the latest Ollama, which includes support for newer GPU architectures. After reinstalling, click **✅ Apply & Reload** in Settings to reload the model with GPU support.

### GPU Layers Explained

- **-1 (auto)** — let Ollama decide how many layers fit in VRAM (recommended)
- **0** — force CPU inference (use if GPU is causing errors)
- **1–99** — manual partial offload (advanced: tune if VRAM is limited)

---

## 13. Supported File Types

### Documents & Text
`.txt` `.md` `.rst` `.rtf` `.odt` `.pdf` `.docx` `.doc` `.xlsx` `.xls` `.pptx` `.ppt`

### Code & Markup
`.py` `.js` `.ts` `.jsx` `.tsx` `.cs` `.java` `.cpp` `.c` `.h` `.hpp` `.go` `.rs` `.rb` `.php` `.swift` `.kt` `.scala` `.r` `.html` `.htm` `.css` `.scss` `.sass` `.less` `.xml` `.xhtml`

### Data & Config
`.json` `.yaml` `.yml` `.toml` `.ini` `.cfg` `.conf` `.env` `.csv` `.tsv` `.log` `.sql`

### Images *(OCR — text is extracted)*
`.jpg` `.jpeg` `.png` `.bmp` `.tiff` `.tif` `.gif`

### Email
`.eml` `.msg` `.emlx` `.mbox` `.rmail` `.babyl` `.mmdf`

### Scripts
`.sh` `.bash` `.zsh` `.ps1` `.bat` `.cmd` `.gitignore` `.dockerignore` `.editorconfig`

### Not Indexed *(skipped by default)*
Executables, DLLs, archives (`.zip`, `.rar`, `.7z`), audio/video, design files (`.psd`, `.ai`), database files, and other binary formats. Customise the skip list in the **🗂 Smart Scan** tab.

---

## 14. Scheduling Automatic Updates

The **⏰ Schedule** tab configures AI Prowler to re-index your documents automatically via Windows Task Scheduler.

### Recommended Schedules

| Use case | Recommended schedule |
|----------|---------------------|
| Actively changing documents | Daily at 08:00 weekdays |
| Stable documents + email | Weekly on Monday at 08:00 |
| Thunderbird sync | Daily (Thunderbird updates live) |
| Large Gmail archive | Weekly (re-export monthly, update daily) |

### What the Schedule Runs

The scheduled task calls `rag_preprocessor.py auto-update`, which runs the full change-detection pipeline against all tracked directories. Only changed files are re-processed — unchanged files are skipped instantly, making weekly updates fast even on large collections.

---

## 15. Command Line (Advanced)

All core functions are available without the GUI:

```bash
# Index a directory (recursive by default)
python "C:\Program Files\AI-Prowler\rag_preprocessor.py" index "C:\Users\YourName\Documents"

# Ask a question
python "C:\Program Files\AI-Prowler\rag_preprocessor.py" query "What is in my documents?"

# List indexed files
python "C:\Program Files\AI-Prowler\rag_preprocessor.py" list

# Show database statistics
python "C:\Program Files\AI-Prowler\rag_preprocessor.py" stats

# Scan a directory for changes without updating
python "C:\Program Files\AI-Prowler\rag_preprocessor.py" check "C:\Users\YourName\Documents"

# Update only changed files in a directory
python "C:\Program Files\AI-Prowler\rag_preprocessor.py" update "C:\Users\YourName\Documents"

# Auto-update all tracked directories
python "C:\Program Files\AI-Prowler\rag_preprocessor.py" auto-update

# Change the active AI model
python "C:\Program Files\AI-Prowler\rag_preprocessor.py" model llama3.1:8b

# Clear the entire database
python "C:\Program Files\AI-Prowler\rag_preprocessor.py" clear
```

Use `%LocalAppData%\Programs\Python\Python311\python.exe` if `python` is not on your PATH.

---

## 16. Privacy & Security

**AI Prowler is local-first. Cloud AI is entirely opt-in.**

| ✅ AI Prowler does | ❌ AI Prowler does NOT |
|-------------------|----------------------|
| Run 100% offline by default | Upload your documents anywhere |
| Store all data on your hard drive | Collect telemetry or usage analytics |
| Keep API keys in your local config file | Phone home or require an account |
| Use Ollama for local-only LLM inference | Send original files to cloud providers |
| Send only question text + excerpts to cloud | Share any data with third parties |

When you use a cloud AI provider, only these things leave your machine:
1. Your question text
2. Short retrieved excerpts from your indexed documents (typically 1–3 paragraphs per chunk)

Your original source files are never transmitted.

> **API keys** are stored in `%UserProfile%\.rag_config.json` under your user home folder — not in the AI Prowler installation folder, and not transmitted anywhere other than to the provider you explicitly selected.

---

## 17. Troubleshooting

### Installation

| Problem | Solution |
|---------|---------|
| Install fails / Python not found | Ensure 6 GB free space; run installer as Administrator |
| Package install failed | Check internet connection and re-run the installer |
| Ollama not installed | Download from [ollama.com/download/windows](https://ollama.com/download/windows) or re-run the installer |
| Whisper download failed | Non-critical — model downloads on first mic button use |
| Any install error | Open `%LocalAppData%\Temp\AI-Prowler\install_log.txt` for the exact error and return codes |

### GUI

| Problem | Solution |
|---------|---------|
| GUI won't open | Run `python rag_gui.py` from Command Prompt to see the error message |
| "Could not import AI Prowler modules" | Ensure `rag_preprocessor.py` is in `C:\Program Files\AI-Prowler\` |
| Microphone button missing | Packages are installed by default — if missing, run `pip install faster-whisper sounddevice numpy` and restart |
| Tab appears blank | Try launching via `RAG_RUN.bat` instead of the desktop icon |
| Status indicator stays grey | Click **⚡ Load AI Model** or check that Ollama is running |
| Settings not saving | Verify write access to your home folder (`C:\Users\YourName\`) |

### Indexing

| Problem | Solution |
|---------|---------|
| Indexing error: Errno 22 Invalid argument | AI Prowler detects this automatically and repairs the model cache on the next run. If it persists, delete `%UserProfile%\.cache\huggingface\hub\models--sentence-transformers--all-MiniLM-L6-v2` and restart |
| OCR not working / scanned PDFs not indexed | Go to Settings → OCR. If Tesseract not found, reinstall AI Prowler |
| Large .mbox import is slow | Normal for first import — per-message progress shows in output. Use Stop/Resume to spread across sessions |
| Stop button slow to respond | Stop responds after each individual message — current message is still processing |
| Re-importing same .mbox re-indexes everything | Check that the archive file path hasn't changed — the incremental indexer tracks by path + Message-ID |

### Queries

| Problem | Solution |
|---------|---------|
| "No documents found. Index some documents first." | Go to Index Documents, add a folder, and click Start Indexing |
| First query takes 2–3 minutes | Normal — AI model is loading into memory for the first time. Use ⚡ Load AI Model to pre-warm |
| "Cannot connect to Ollama" | Enable Auto-start Ollama in Settings, or open Command Prompt and run `ollama serve` |
| Answers are vague or off-topic | Try a larger model or increase Context Chunks; enable Show source references to see what was retrieved |
| Context chunks ⚠reload is very slow | Expected on CPU-only systems for >6 chunks — use a GPU or limit chunks to 5 or fewer |

### Cloud AI Providers

| Problem | Solution |
|---------|---------|
| 🔌 Test shows "Invalid API key" | Double-check the key was copied fully with no spaces; regenerate if needed |
| Provider returns HTTP 429 | Rate limit reached — AI Prowler notes the timeout and falls back to local Ollama |
| Image attachments not working | Confirm you are using a cloud provider with vision support (ChatGPT, Claude, Gemini) |
| Auto-fallback kicked in | The selected provider failed; answer came from local Ollama. Check the status dot in Settings |

### Ollama Server

| Problem | Solution |
|---------|---------|
| No CMD window on startup | Expected when Debug View is OFF — Ollama runs silently in background |
| Ollama CMD window closed by accident | Re-enable auto-start and restart AI Prowler, or run `ollama serve` manually |
| "ollama is not recognized as a command" | Use AI Prowler's built-in controls; Ollama installs to LocalAppData, not system PATH |
| Ollama LLM: Running on CPU (0 bytes in VRAM) | Your Ollama version doesn't support your GPU — re-run the installer and click Apply & Reload |

### Scheduling

| Problem | Solution |
|---------|---------|
| Schedule not running | Check the Schedule tab shows "✅ Schedule Active" and verify Task Scheduler is running |
| Can't create schedule | Right-click AI Prowler → Run as administrator |
| Schedule shows wrong time | Remove and recreate; check Windows time zone settings |

---

## 18. Tips & Best Practices

### Indexing

✅ Use **Pre-scan first** on any unfamiliar large folder before committing  
✅ Start with one focused project folder to test, then expand  
✅ Use **Pause/Stop freely** — progress is always saved and resumable  
✅ For email, keep exported archives in a dedicated folder and re-export periodically  
✅ Schedule weekly re-imports for actively-used mailboxes (Thunderbird especially)  

❌ Don't index your entire C:\ drive  
❌ Don't index temp folders, Downloads, or the Recycle Bin  
❌ Don't run indexing and querying at the same time on low-RAM machines  

### Queries

✅ Use complete natural-language questions — not single keywords  
✅ Reference document names or dates when you know them  
✅ Keep **Context Chunks at Auto (3)** or 3–5 for everyday use  
✅ Only increase to ⚠reload chunks when you need broad coverage — be prepared to wait on CPU  
✅ Use **voice input** for longer or more natural questions  
✅ Click **⚡ Load AI Model** when you open AI Prowler to pre-warm while you work on another tab  
✅ Enable **File Output Mode** when asking the AI to write or modify code  

❌ Don't ask about content that hasn't been indexed yet  
❌ Don't use 70b+ models unless you have 32+ GB RAM  

### Cloud AI Providers

✅ Try **Gemini or Llama API** first — both have free tiers and are easy to set up  
✅ Use cloud providers for complex multi-document questions that need higher reasoning quality  
✅ Use **image attachments** with ChatGPT, Claude, or Gemini for screenshot analysis  
✅ Keep **Auto-fallback ON** so queries always get an answer  

❌ Don't put API keys anywhere other than the Settings → External AI APIs fields  
❌ Don't send highly sensitive personal data via cloud providers — use Local Ollama for maximum privacy  

### Email

✅ Export by label/folder from Gmail rather than "All Mail" if you only need specific content  
✅ Keep archive files at a stable path — the incremental indexer deduplicates by path + Message-ID  
✅ Use the per-message progress counter to estimate time for very large archives  
✅ Schedule **Thunderbird folder** scans daily — new mail arrives continuously  

❌ Don't delete and recreate archive files unnecessarily — the incremental engine works best when file paths stay stable  

---

## 19. Frequently Asked Questions

**Q: Do I need an API key or account?**  
No — everything runs locally with no accounts, keys, or registration. Cloud AI providers are entirely optional.

**Q: Does this work offline?**  
Yes — 100% offline by default. Cloud providers obviously need an internet connection, but local Ollama queries work with no network at all.

**Q: Is my data private?**  
Completely private when using local Ollama. When you use a cloud provider, only your question and retrieved excerpts are sent — your original files never leave your computer.

**Q: How much does it cost?**  
The app is free. Local Ollama is free. Cloud providers are billed by the provider — Gemini and Llama API have generous free tiers.

**Q: Does it need a GPU?**  
No. The default model runs well on CPU-only hardware. A GPU significantly speeds up larger models.

**Q: How many documents can I index?**  
Thousands — limited only by available disk space.

**Q: My Gmail export is 8 GB. Will AI Prowler handle it?**  
Yes. The incremental indexer processes messages one at a time with Stop/Resume support, so you can spread a large initial import over multiple sessions. Future re-imports only process new messages.

**Q: Do I need to re-index everything when files change?**  
No — the Update Index tab re-indexes only new and changed files. For email archives, only new messages are processed.

**Q: What if my computer is off when a schedule is due?**  
Windows Task Scheduler runs the task the next time the computer is on and the trigger time is reached.

**Q: Can I use a different AI model?**  
Yes — any Ollama-compatible model works. Install it from Settings → Browse & Install Model.

**Q: What does the Auto-start Ollama option do?**  
When enabled, AI Prowler automatically launches the Ollama server when you open the app and shuts it down on exit. The server window is hidden by default — enable Debug View in Settings if you need to see it.

**Q: What is the ⚡ Load AI Model button for?**  
It manually triggers the model pre-warm so the AI is ready before you type your first question. The model loads automatically when you switch to the Ask Questions tab, but this button lets you start loading earlier while you're on another tab.

**Q: What does File Output Mode do?**  
It instructs the AI to label any code or script files it writes with a filename. AI Prowler then detects those filenames in the answer and shows a 💾 Save button for each one — eliminating copy-paste for code file answers.

**Q: What context chunks setting should I use?**  
"Auto (3)" is the best default — it calculates the optimal number for your model. Increase to 5–6 for broader questions. Only use ⚠reload values (7+) when you need wide coverage and can wait for the model to reload on CPU.

---

## 20. Uninstalling

Run the AI Prowler uninstaller from **Windows Settings → Apps → AI-Prowler → Uninstall**, or from `C:\Program Files\AI-Prowler\`.

The uninstaller will:

| Step | What is removed |
|------|----------------|
| 1 | Windows Task Scheduler task |
| 2 | Desktop shortcut and Start Menu entry |
| 3 | AI Prowler entry from Windows PATH |
| 4 | Config files (`.rag_config.json`, tracking files, email index, etc.) |
| 5 | ChromaDB database — **asks for confirmation before deleting** |
| 6 | AI Prowler program files from `C:\Program Files\AI-Prowler\` |
| 7 | Python 3.11 (if installed by AI Prowler) |
| 8 | Ollama engine and optionally its model files |
| 9 | Whisper model cache — targets only the AI Prowler model, leaving other HuggingFace models untouched |

Python packages are intentionally kept during uninstall to avoid breaking other programs. Remove Python separately via Settings → Apps if needed.

### Manual Removal

If the uninstaller is not available, delete:
- `C:\Program Files\AI-Prowler\`
- From your home folder: `.rag_config.json`, `.rag_auto_update_dirs.json`, `.rag_file_tracking.json`, `.rag_email_index.json`, `rag_auto_update.bat`
- Desktop shortcut: `AI Prowler.lnk`
- Task Scheduler task: open Task Scheduler from Start menu → find and delete the "AI Prowler Auto-Update" task
- Whisper cache: `%UserProfile%\.cache\huggingface\hub\models--Systran--faster-whisper-large-v3-turbo\`

---

## 21. File & Folder Reference

| File / Folder | Purpose |
|---------------|---------|
| `C:\Program Files\AI-Prowler\rag_gui.py` | Main GUI application |
| `C:\Program Files\AI-Prowler\rag_preprocessor.py` | Core indexing and query engine |
| `C:\Program Files\AI-Prowler\RAG_RUN.bat` | Launch script (used by the Desktop shortcut) |
| `C:\Program Files\AI-Prowler\requirements.txt` | Python package list |
| `C:\Program Files\AI-Prowler\COMPLETE_USER_GUIDE.md` | This document |
| `%UserProfile%\.rag_config.json` | All settings (model, GPU layers, API keys, etc.) |
| `%UserProfile%\AI-Prowler\rag_database\` | ChromaDB vector database |
| `%UserProfile%\.rag_file_tracking.json` | File modification baselines for change detection |
| `%UserProfile%\.rag_auto_update_dirs.json` | List of tracked directories |
| `%UserProfile%\.rag_email_index.json` | Per-email Message-ID tracking database |
| `%UserProfile%\.ollama\models\` | Downloaded Ollama models |
| `%UserProfile%\.cache\huggingface\hub\` | Sentence-transformer embedding model cache |
| `%LocalAppData%\Programs\Python\Python311\` | Python runtime |
| `%LocalAppData%\Programs\Tesseract-OCR\` | Tesseract OCR engine |
| `%LocalAppData%\Programs\Ollama\` | Ollama engine |
| `%LocalAppData%\Temp\AI-Prowler\install_log.txt` | Full installer log — first place to look when troubleshooting |

---

## 22. Version History

### Version 3.0.0 (Current)

**New features:**
- 🔧 **Professional Windows installer** — `AI-Prowler_INSTALL.exe` replaces `INSTALL.bat`. Full Inno Setup installer with license agreement, progress bar, Start Menu and Desktop shortcuts. Handles Python, pip, Tesseract OCR, Ollama, and the default model in a single step.
- 🖨 **Tesseract OCR integration** — scanned PDFs and image files (`.jpg`, `.png`, `.bmp`, `.tiff`, `.gif`) are automatically OCR'd and indexed using Tesseract 5.4 (UB-Mannheim build). No manual setup required — the installer downloads and configures Tesseract automatically.
- ⚡ **RTX 50xx Blackwell support** — GPU detection now installs CUDA 12.8 / cu128 PyTorch on NVIDIA Blackwell cards (RTX 5060, 5070, 5080, 5090) for full GPU acceleration.
- 🔑 **`HF_HUB_CACHE` env var fix** — prevents the Windows 10 Errno 22 double-backslash path bug in huggingface_hub that caused indexing to fail silently after install.
- 🛠 **Self-healing model cache** — if a corrupted model cache is detected at startup (Errno 22), the app automatically deletes it and re-downloads a clean copy. Users see a clear message in the output panel; no manual intervention is required.
- 📦 **Pinned package versions** — `huggingface-hub==0.26.5`, `sentence-transformers==3.3.1`, and `transformers==4.44.2` are pinned together to prevent the double-backslash path bug and eliminate the 20-version pip backtracking that made installs slow and nondeterministic.

---

### Version 2.0

**New features:**
- ☁️ **External AI APIs** — six cloud providers integrated: ChatGPT, Claude, Gemini, Grok, Llama API, Mistral Large
- 🔄 **Auto-fallback** — transparent fallback to local Ollama if a cloud provider fails
- 📎 **Attachments panel** — attach images and text files to questions
- 📄 **File Output Mode** — AI-labelled code blocks get per-file 💾 Save buttons
- 💾 **Save Answer button** — save the full answer to `.txt` or `.md`
- 🏅 **RAM-aware model selector** — ✅/⚠️ fit badges based on detected system RAM
- 🔭 **Browse & Install Model** — model browser for downloading new Ollama models from within the app
- ⚠️ **Context chunks reload warnings** — values ≥7 labelled "⚠reload" to signal model context reload

---

### Version 1.8

**New features:**
- 🎤 Voice input with Whisper large-v3-turbo, auto-stop silence detection
- ⏸ Pause / Resume indexing mid-run
- 📬 Per-email incremental indexing for `.mbox`, `.rmail`, `.babyl`, `.mmdf` with Message-ID deduplication
- 🗂 Auto Scan Config tab — live editor for supported/skipped extensions and directories
- 📁 Multi-folder queue with custom tree browser
- 🔍 Pre-scan mode — preview what will be indexed before committing
- ⚡ GPU acceleration controls — Detect GPU, set layers, Apply & Reload without restarting

---

## 🎉 You're Ready!

You now know how to index documents, ask questions, export and index email from every major provider, use cloud AI for higher-quality answers, set up scheduled updates, and troubleshoot every common issue.

**Start exploring your documents with AI!** 🚀

---

*AI Prowler v3.0.0 — Your Personal AI Knowledge Base*  
*Local-first · Cloud-optional · 100% Yours*  
*Copyright © 2026 David Kevin Vavro*
