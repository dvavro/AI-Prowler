# AI Prowler — Personal AI Knowledge Base

**Complete User Guide · Version 1.9**

**Ask questions about YOUR documents using AI — running 100% locally on your computer**

No API keys &nbsp;•&nbsp; No cloud services &nbsp;•&nbsp; No subscription fees &nbsp;•&nbsp; Complete privacy

---

## 📦 What's in the Box

```
AI-Prowler/
├── RAG_RUN.bat              ← Double-click to launch
├── INSTALL.bat              ← One-click installer (run once)
├── UNINSTALL.bat            ← Clean removal tool
├── rag_gui.py               ← GUI application
├── rag_preprocessor.py      ← Core indexing & query engine
├── create_shortcut.py       ← Desktop shortcut creator
├── requirements.txt         ← Python package list (11 packages)
├── rag_icon.ico             ← Application icon
├── COMPLETE_USER_GUIDE.md   ← This guide
└── generate_license.py      ← License tool (optional)
```

---

## ⚡ Quick Start

```
Step 1 — Double-click INSTALL.bat
  • Installs Python 3.11 if not found (automatic)
  • Installs all 11 required Python packages
  • Downloads and installs Ollama AI engine
  • Downloads default AI model — llama3.2:1b (~1.3 GB)
  • Downloads Whisper speech model — large-v3-turbo (~1.6 GB)
  • Creates "AI Prowler" shortcut on your Desktop
  • Total download: ~4 GB · Time: 15–30 minutes

Step 2 — Wait for "INSTALLATION COMPLETE"

Step 3 — Double-click the "AI Prowler" Desktop icon
  • GUI opens — no terminal window visible
  • AI model begins loading silently in background
  • Ready to index and query immediately
```

---

## 🎯 What Is AI Prowler?

AI Prowler uses **RAG (Retrieval-Augmented Generation)** — when you ask a question it first searches your own indexed documents for relevant passages, then feeds those passages to a local AI model that writes a grounded, accurate answer. Your documents never leave your computer.

**What it does:**
- 📚 Indexes documents, code, email, spreadsheets, and 55+ file types
- 🔍 Answers questions using your own content, not just general knowledge
- 🤖 Runs 100% offline after installation
- 🔒 Zero cloud contact — no uploads, no telemetry, no accounts
- 📬 Deep email support — Gmail, Apple Mail, Thunderbird, Yahoo, and more
- ⚡ Incremental updates — only re-processes files that changed
- 🎤 Voice input — speak questions via local Whisper speech recognition
- ⏰ Scheduled auto-updates — keep the index current automatically
- 💡 15+ AI models — tune speed vs. quality for your hardware
- 🟢 Auto-start Ollama — optionally launch the AI server automatically

**Example conversation:**
```
You:         "What was the mutation rate in my NEAT project?"

AI Prowler:  According to NEAT_Documentation.md, the mutation rate
             is set to 0.02 (2%). This controls how frequently
             weights and connections mutate during evolution...
```

---

## 🚀 Launching AI Prowler

| Method | How |
|--------|-----|
| Desktop icon (easiest) | Double-click "AI Prowler" |
| From install folder | Double-click `RAG_RUN.bat` |
| Command line | `python rag_gui.py` |

When the GUI opens, the embedding model begins warming up in the background. If **Auto-start Ollama** is enabled in Settings, the Ollama server also launches automatically in a separate window — you do not need to start it manually.

---

## 🎛️ Menu Bar

### File
- **Exit** — close AI Prowler

### Help
- **📖 User Guide** — opens this guide in a built-in scrollable viewer window
- **🚀 Quick Start** — abbreviated quick-start guide in a separate window
- **ℹ️ About AI Prowler** — version, feature list, and credits

> **Note:** The User Guide viewer loads this `COMPLETE_USER_GUIDE.md` file directly from the installation folder. Keep the file in the same directory as `rag_gui.py` for the best reading experience.

---

## 📚 Tab 1 — Index Documents

**Purpose:** Add documents to your knowledge base.

### The Directory Queue

AI Prowler uses a **queue system** — stage as many folders and individual files as you want, then process them all in one batch.

**Adding items to the queue:**

| Button | What it does |
|--------|-------------|
| 📁 Browse Folders… | Opens a custom tree browser. Navigate your filesystem, select one or more folders (Ctrl/Shift click for multiple), click Add |
| 📄 Browse Files… | Opens a standard file picker. Ctrl/Shift click to select multiple individual files |
| ➕ Add to Queue | Adds whatever is typed in the path entry box |
| Type + Enter | Type a path directly and press Enter |

The **Queue counter** at the top right updates live as you add and remove items.

**Managing the queue:**

| Button | What it does |
|--------|-------------|
| ❌ Remove Selected | Removes the highlighted item before starting |
| 🗑 Clear Queue | Removes everything and starts fresh |
| Include subdirectories | Checkbox (default ON) — when checked every subfolder is scanned recursively |

### Options

**Smart scan** (default ON, recommended) — before indexing, AI Prowler pre-scans the queue and automatically skips:
- Executable and compiled binary files (`.exe`, `.dll`, `.pyc`, …)
- Media files — images, audio, video, fonts
- Archive files — `.zip`, `.rar`, `.7z`, …
- Database and VM image files
- Known system/tool directories — `.git`, `node_modules`, `__pycache__`, `venv`, `build`, `dist`, `.idea`, `.vscode`, and more

**Pre-scan only** — check this to see a full report of what *would* be indexed without actually indexing anything. Useful before committing to a large folder.

### Action Buttons

| Button | Function |
|--------|---------|
| ▶ Start Indexing Queue | Begin processing all queued items |
| ⏸ Pause | Freeze at the end of the current file. Click again to Resume |
| ⏹ Stop | Stop cleanly after the current file and save position |
| 🔍 Scan Queue | Run pre-scan and show report without indexing |

### Progress Display

Three live indicators appear while indexing runs:

- **Animated progress bar** on the left
- **Directory/file counter** in the centre — e.g. `Dir 2/4: Projects` or `[Email 847/12,034] Re: Budget`
- **Elapsed timer** on the right — ticks up in real time (e.g. `⏱ 3m 42s`)

For email archives the counter shows per-message progress so you always know exactly where you are inside a large export.

### Pause and Resume

- **Pause** freezes the worker thread immediately. The timer pauses too. Click **Resume** to continue from exactly where you stopped.
- **Stop** saves your exact position — the Start button changes to **▶ Resume Indexing**. Clicking it picks up from where you stopped, including the position within a partially-processed directory.

### What Gets Indexed

**Documents:** `.txt` `.md` `.rst` `.rtf` `.odt` `.pdf` `.docx` `.doc` `.xlsx` `.xls` `.pptx` `.ppt`

**Code and markup:** `.py` `.js` `.ts` `.jsx` `.tsx` `.cs` `.java` `.cpp` `.c` `.h` `.hpp` `.go` `.rs` `.rb` `.php` `.swift` `.kt` `.scala` `.r` `.html` `.htm` `.css` `.scss` `.sass` `.less` `.xml` `.xhtml`

**Config and data:** `.json` `.yaml` `.yml` `.toml` `.ini` `.cfg` `.conf` `.env` `.csv` `.tsv` `.log` `.sql`

**Scripts:** `.sh` `.bash` `.zsh` `.ps1` `.bat` `.cmd` `.gitignore` `.dockerignore` `.editorconfig`

**Email — single-message files:**
`.eml` `.msg` `.emlx`

**Email — multi-message archives** *(incremental indexer — see Email chapter below):*
`.mbox` `.rmail` `.babyl` `.mmdf`

### After Indexing

When a directory finishes indexing it is automatically **registered for tracking** — it appears in the Update Index tab and becomes eligible for scheduled updates.

---

## 📬 Email Indexing — Complete Guide

AI Prowler has first-class support for email from every major provider. This chapter covers how the engine works and exactly how to export from each service.

---

### How It Works

**Single-message files** (`.eml`, `.msg`, `.emlx`) are indexed like any other document — one file in, one record out. The standard file-change tracker handles re-indexing: if the file's modification time hasn't changed since the last run, it is skipped.

**Multi-message archives** (`.mbox`, `.rmail`, `.babyl`, `.mmdf`) use a completely different engine called the **per-email incremental indexer**:

1. Every message in the archive is identified by a **stable unique ID** derived from its `Message-ID` header — an RFC 5322 globally-unique string assigned by the sending mail server. When a message has no `Message-ID`, a fingerprint is computed from `From + Date + Subject` instead.

2. A local database at `~/.rag_email_index.json` records which IDs have already been indexed for each archive file path.

3. On every re-import run, the engine compares the set of IDs in the archive against the set already in the database:
   - **New ID** (in archive, not in database) → message is indexed and its chunks are added to ChromaDB
   - **Known ID** (in both) → message is skipped entirely — no re-processing
   - **Removed ID** (in database but no longer in archive) → its chunks are automatically deleted from ChromaDB

4. A 100,000-message archive that gained 200 new emails this week processes only those 200 — not the whole archive.

**Stop response:** The Stop button is checked after every single message (not just between files), so clicking Stop while processing a 50 GB archive responds within a second or two.

**Per-message progress:** The output panel shows `[Email 4,271/52,000] Re: Q3 Budget (87 words)` so you always know what is happening and can estimate completion time.

---

### Supported Archive Formats

| Format | Extension(s) | Notes |
|--------|-------------|-------|
| Unix mbox | `.mbox` | The most common export format. Used by Gmail Takeout, Thunderbird, Apple Mail, iCloud Mail, and many others |
| GNU Babyl / RMAIL | `.rmail` `.babyl` | GNU Emacs mail format — rare but fully supported |
| MMDF | `.mmdf` | Legacy SCO/Unix mail server format — rare but fully supported |

Single-message formats `.eml`, `.msg`, and `.emlx` are supported natively — no special configuration needed, just add the files or their containing folder to the index queue.

---

### Exporting From Every Major Provider

---

#### Gmail (Google)

Gmail exports in `.mbox` format — one file per label — via Google Takeout.

**Steps:**
1. Go to [takeout.google.com](https://takeout.google.com) and sign in
2. Click **Deselect all**, then scroll down and check only **Mail**
3. Click **All Mail data included** to choose specific labels (Inbox, Sent, a project label, etc.) rather than your entire mailbox if you don't need everything
4. Choose delivery: `.zip`, frequency: **Export once**, size: up to 50 GB per file
5. Click **Create export** — Google emails a download link when it's ready (minutes to hours depending on mailbox size)
6. Download and extract the `.zip` — inside you will find files named like `All mail Including Spam and Trash.mbox` or one `.mbox` per label
7. Add the `.mbox` file(s) to the AI Prowler index queue

> **Tip:** Label-by-label exports are easier to manage. Export just "Work" or "Projects" if that is all you need to query.

> **Re-exporting:** When you export again next month, Google regenerates the `.mbox` from scratch with all messages including new ones. AI Prowler's incremental indexer handles this correctly — it uses `Message-ID` to identify what's new, so only genuinely new messages are processed even though the whole file is new.

---

#### Apple Mail and iCloud Mail

Apple Mail stores mail internally as `.emlx` files and can export entire mailboxes as `.mbox` bundles.

**Export as .mbox (recommended for large mailboxes):**
1. Open the Mail app on your Mac
2. In the sidebar, select the mailbox you want to export (e.g. Inbox, a project folder)
3. Go to **Mailbox → Export Mailbox…**
4. Choose a save location and click **Choose**
5. Apple Mail saves a `.mbox` package — on macOS this looks like a folder but on Windows (after copying) it is treated as a standard `.mbox` file
6. Add it to the AI Prowler index queue

**Access raw .emlx files directly (no export needed):**
If you have access to the macOS filesystem, Apple Mail's internal storage is at `~/Library/Mail/`. Each message is an individual `.emlx` file. Add the `Mail` folder or specific account sub-folders to the AI Prowler queue — smart scan will find and index all `.emlx` files recursively.

**iCloud Mail** uses the same Apple Mail client, so the export process is identical. Make sure your iCloud Mail is synced to the local Mail app first (Mail → Preferences → Accounts → check the account is enabled and synced).

---

#### Thunderbird (Mozilla)

Thunderbird stores each folder as a single raw `.mbox` file on disk — **no export step is needed**. You point AI Prowler directly at the profile folder.

**Finding your Thunderbird mbox files:**

| OS | Default path |
|----|-------------|
| Windows | `C:\Users\YourName\AppData\Roaming\Thunderbird\Profiles\[profile]\Mail\` |
| macOS | `~/Library/Thunderbird/Profiles/[profile]/Mail/` |
| Linux | `~/.thunderbird/[profile]/Mail/` |

Inside each account folder you will find files named `Inbox`, `Sent`, `Drafts`, etc. with no file extension — these are standard mbox files. You can either:

- Add the entire `Mail` folder to the AI Prowler queue. Smart scan will find all mbox files automatically.
- Copy specific mailbox files, rename them with a `.mbox` extension, and add those instead.

> **Keeping it current:** Because Thunderbird's mbox files live on your disk permanently and are updated as new mail arrives, you can schedule AI Prowler to re-scan the Thunderbird folder weekly. The incremental indexer will pick up only new messages each time.

---

#### Yahoo Mail

Yahoo does not provide a direct export tool. The recommended path is to use a third-party tool to pull your mail via IMAP and save it as `.mbox`.

**Recommended approach — Thunderbird bridge:**
1. Add your Yahoo account to Thunderbird using IMAP
2. Let Thunderbird sync (can take hours for a large mailbox)
3. Point AI Prowler at the Thunderbird profile folder as described above

**Yahoo IMAP settings for Thunderbird:**
- Server: `imap.mail.yahoo.com` · Port: `993` · SSL/TLS: Yes
- You **must** use a Yahoo App Password — go to [security.yahoo.com](https://security.yahoo.com) → Manage app passwords → Generate one for Thunderbird. Your regular Yahoo password will not work for IMAP.

**Alternative — MailStore Home (free):**
1. Download MailStore Home from [mailstore.com/en/products/mailstore-home](https://www.mailstore.com/en/products/mailstore-home)
2. Add Yahoo as a source using the IMAP settings above
3. Export to `.mbox` format
4. Add the exported file to the AI Prowler queue

---

#### Outlook / Microsoft 365 / Exchange

Outlook's native format is `.pst`/`.ost` — a proprietary binary format that requires conversion. The cleanest approach depends on how many emails you need.

**Option A — Drag to folder (small batches):**
1. Open Outlook
2. Select messages (Ctrl+A to select all in a folder)
3. Drag and drop them onto a Windows folder — Outlook saves each as an `.eml` file
4. Add that folder to the AI Prowler index queue

**Option B — MailStore Home (large mailboxes, recommended):**
1. Download MailStore Home (free) from [mailstore.com](https://www.mailstore.com/en/products/mailstore-home)
2. Add your Outlook/Exchange account or import from a `.pst` file
3. Export to `.mbox` format
4. Add the `.mbox` to the AI Prowler queue

**Option C — Aid4Mail or similar PST converter:**
Converts `.pst` directly to `.mbox`. Several free and paid tools are available — search for "PST to mbox converter".

> **Note:** `.pst` and `.ost` files cannot be indexed directly because they use a proprietary binary format that requires Microsoft libraries to read. Conversion to `.mbox` or a folder of `.eml` files first is the reliable path.

---

#### Windows Live Mail / Windows Mail (legacy)

These apps stored each message as an individual `.eml` file in a folder hierarchy on disk.

**Default storage location:**
`C:\Users\YourName\AppData\Local\Microsoft\Windows Live Mail\`

Add that folder (or specific account sub-folders) directly to the AI Prowler index queue — smart scan finds all `.eml` files recursively.

---

#### Other Clients

| Client | How to export |
|--------|--------------|
| **Evolution** (Linux) | File → Save As Mbox |
| **KMail** (Linux) | Folder → Export → mbox |
| **Mutt / Neomutt** | Uses mbox or Maildir natively — add the mbox file or folder directly |
| **Postfix / Dovecot** | Maildir format — add the mail spool directory |
| **Proton Mail** | Use Proton Mail Bridge (IMAP) → Thunderbird → AI Prowler |
| **Fastmail** | Settings → Export → mbox per folder |
| **Zoho Mail** | Settings → Data Migration → Export → mbox |

---

### Re-Importing Updated Archives

When you export a fresh copy of your Gmail `.mbox` or Thunderbird folder next month:

- **New messages** added since the last import → indexed
- **Messages present in both** old and new export → skipped (already indexed)
- **Messages in old export but absent from new** → chunks automatically removed from ChromaDB

This works because AI Prowler tracks individual `Message-ID` values, not file modification times. Even when Google Takeout regenerates the entire `.mbox` from scratch, only genuinely new messages are processed.

---

## 🔍 Tab 2 — Ask Questions

**Purpose:** Ask natural language questions about your indexed documents.

### Asking a Question

1. Click the **🔍 Ask Questions** tab
2. Type your question in the entry box — or use the 🎤 mic button (see below)
3. Press **Enter** or click **Ask Question**

The model pre-warms automatically when you switch to this tab, so the first query is faster than it would otherwise be.

### Action Buttons

| Button | What it does |
|--------|-------------|
| **Ask Question** | Submits the typed question and begins the query |
| **⏹ Stop** | Cancels the current query in progress |
| **⚡ Load AI Model** | Manually triggers the Ollama model pre-warm — useful if the model is not yet loaded or you want to reload it before asking a question |

### Model Status Indicator

A small **coloured dot** and status label appear to the right of the action buttons. They show the current state of the AI model at all times:

| Indicator | Meaning |
|-----------|---------|
| ⚫ Grey — "Model not loaded" | Ollama has not yet been contacted |
| 🟡 Yellow — "Loading model…" | Pre-warm is in progress; the model is being loaded into memory |
| 🟢 Green — "Model ready" | The model is loaded and queries will respond quickly |

If you see the grey indicator and your first query feels slow, click **⚡ Load AI Model** to start pre-warming manually before you need to ask anything.

### Voice Input (🎤 Microphone)

When `faster-whisper`, `sounddevice`, and `numpy` are installed (they are by default), a microphone button appears next to the question entry box.

| State | What to do |
|-------|-----------|
| 🎤 (grey) | Click to start recording |
| 🔴 (red, recording) | Speak your question. Click again to stop early |
| Transcribing… | Whisper is converting your speech to text |
| Question populated | Review, edit if needed, then press Enter |

**Auto-stop:** recording ends automatically after a configurable silence period (default 3 seconds). Set in the Settings tab.

The Whisper `large-v3-turbo` model (~1.6 GB) is downloaded once on first use and cached. Subsequent launches load it instantly from the local cache.

### Context Chunks

The **Context chunks** dropdown controls how many document excerpts are retrieved from the index to give the AI context for generating its answer.

| Setting | Best for |
|---------|---------|
| Auto (default) | Calculates the optimal number based on the selected model's context window size — usually the best choice |
| 3–5 | Quick factual lookups |
| 7–10 | Broader questions that span multiple documents |
| 15–20 | Summarisation or questions that need wide coverage |

### Progress and Timing

A **progress bar** animates while the query runs. An **elapsed timer** ticks up in real time. When the answer arrives the timer freezes, showing total time — e.g. `✅ 14s`.

### Example Questions

```
Factual lookups:
  "What was the mutation rate in my NEAT config?"
  "What's the deadline for the Smith project?"
  "Find my flight confirmation number for the Paris trip"

Broad summaries:
  "What documents do I have about machine learning?"
  "Summarise my project documentation"
  "What are the recurring issues in my support tickets?"

Technical:
  "Show me all Python functions that use asyncio"
  "What libraries are imported in my backend code?"
  "Explain the authentication flow in my app"

Email:
  "What did John say about the Q3 budget?"
  "Find any emails about the server outage in January"
  "What agreements did I make with Acme Corp last year?"
```

### Tips

- The **first query after launch** triggers model loading — allow 20–60 seconds
- Use **⚡ Load AI Model** before your first question to pre-load and avoid the wait
- Subsequent queries run in 10–30 seconds (model stays loaded in memory)
- **Specific questions** get better answers than vague ones
- If an answer feels shallow, increase the context chunks or try a larger model

---

## 🔄 Tab 3 — Update Index

**Purpose:** Keep your knowledge base current without re-indexing everything.

### How File Tracking Works

When a directory is indexed, AI Prowler records each file's path, modification time, and size in `~/.rag_file_tracking.json`. On the next update run:

| File status | What happens |
|-------------|-------------|
| New file | Indexed and added to ChromaDB |
| Modified file | Old chunks deleted, new chunks added |
| Deleted file | Chunks removed from ChromaDB |
| Unchanged file | Skipped entirely |

For email archives the engine goes deeper — see the Email chapter for how per-message deduplication works.

### Tracked Directories List

Shows every directory registered for tracking. Click **🔄 Refresh List** to reload from disk.

The info bar at the top shows the exact paths of both tracking data files so you know where they live and that they are separate from the ChromaDB database (they survive a database wipe).

### Update Buttons

| Button | What it does |
|--------|-------------|
| Update Selected | Updates only the highlighted directory |
| Update All | Updates every tracked directory in sequence |

Both buttons run the full change detection pipeline and show a per-file log in the output panel.

### Removing a Tracked Directory

Select a directory and click **🗑 Remove Selected (untrack + delete its vectors)**. This does four things atomically:
1. Removes the directory from the auto-update list
2. Deletes all file-tracking timestamps for that directory
3. Deletes all ChromaDB chunks whose filepath falls within that directory
4. Removes any email index entries for archive files inside that directory

---

## ⏰ Tab 4 — Schedule

**Purpose:** Run automatic index updates on a timer using Windows Task Scheduler.

### Why Schedule

Your documents change constantly. Scheduling ensures the AI always knows your latest content without you having to remember to click Update.

### Quick Schedule Presets

| Preset | Runs |
|--------|------|
| Daily at 8:00 AM | Every day at 8 AM |
| Daily at 9:00 AM | Every day at 9 AM |
| Weekdays at 8:00 AM | Monday–Friday at 8 AM |

### Custom Schedule

1. Enter a time in **HH:MM** 24-hour format — e.g. `07:30`, `13:00`, `22:15`
2. Choose **DAILY** or **WEEKDAYS**
3. Click **Set Schedule**

### Schedule Controls

| Control | Effect |
|---------|--------|
| Disable Schedule | Suspends the task without deleting it |
| Remove Schedule | Permanently deletes the Task Scheduler task |
| Refresh Status | Polls Task Scheduler and refreshes the display |

### Status Display

```
Active:
  ✅ Schedule Active
  Next Run: 2/25/2026 8:00 AM

Not set:
  ❌ No Schedule Set
```

### Requirements

- At least one tracked directory in the Update Index tab
- Windows Task Scheduler service running (on by default in all Windows versions)
- AI Prowler installed in a permanent location — the task uses the full install path

---

## 🗂 Tab 5 — Auto Scan Config

**Purpose:** Control exactly which file types and directories are included or excluded during smart scan.

All changes take effect immediately and are saved to `~/.rag_config.json`. They apply to every future scan and update run.

### Supported Extensions (left panel)

The **✅ Supported Extensions** list contains every file type that will be indexed. The default list covers 55+ types.

- **➕ Add** — type an extension (e.g. `.nfo`) and press Enter or click Add. The leading dot is added automatically if you omit it.
- **❌ Remove** — click an extension to select it, then click Remove.
- **Conflict detection** — if you try to add an extension that already exists in the Skipped list, AI Prowler warns you and blocks the add.

### Skipped Extensions (right panel)

The **🚫 Skipped Extensions** list contains types that are always ignored — compiled binaries, media, archives, etc. Same Add/Remove controls.

### Skipped Directories (bottom panel)

The **📂 Skipped Directories** list contains folder *names* (not full paths) that are skipped when walking any directory tree. Defaults include:

- Version control: `.git` `.svn` `.hg` `.bzr`
- Package managers: `node_modules` `vendor` `.nuget`
- Python: `__pycache__` `.venv` `venv` `site-packages`
- Build output: `build` `dist` `bin` `obj` `target`
- IDE folders: `.idea` `.vscode` `.vs`
- AI Prowler's own database: `rag_database`

Add project-specific folders (e.g. `backup`, `.cache`, `temp`) to exclude them from all future scans.

### Save and Reset

| Button | Effect |
|--------|--------|
| 💾 Save Changes | Explicitly saves (changes also auto-save as you edit) |
| ↩ Reset to Defaults | Restores all three lists to built-in defaults — asks for confirmation |

---

## ⚙️ Tab 6 — Settings

**Purpose:** Configure the AI model, GPU acceleration, Ollama server behaviour, voice input, query output format, and database tools.

### AI Model

**Select model** — choose from the full list of Ollama-compatible models. The change takes effect on the next query.

**Install Selected Model** — downloads the selected model via Ollama. Progress shows in the status bar. Can take several minutes for large models.

**Model families and trade-offs:**

| Family | Models | Best for |
|--------|--------|---------|
| Llama 3.2 | `llama3.2:1b` ⭐ `llama3.2:3b` | Default — fast and capable |
| Llama 3.1 | `llama3.1:8b` `70b` `405b` | High-quality answers |
| Llama 3 | `llama3:8b` `70b` | Proven quality |
| Qwen 2.5 | `0.5b` through `72b` | Multilingual content |
| Mistral | `mistral:7b` `mixtral:8x7b` `8x22b` | Code-heavy projects |
| Gemma | `gemma:2b` `7b` `gemma2:9b` `27b` | Google's models |

**Size vs. hardware guide:**

| Model size | Speed | Quality | Min RAM |
|-----------|-------|---------|---------|
| 0.5b–1b | ⚡⚡⚡ | ⭐ | 4 GB |
| 3b–7b | ⚡⚡ | ⭐⭐ | 8 GB |
| 8b–14b | ⚡ | ⭐⭐⭐ | 16 GB |
| 70b+ | 🐌 | ⭐⭐⭐⭐ | 32+ GB |

Start with `llama3.2:1b`. If answers feel shallow, upgrade to `llama3.2:3b` or `llama3.1:8b`.

### Database

| Button | Effect |
|--------|--------|
| View Statistics | Opens a dialog showing total chunks, unique files, and collection metadata |
| Clear Database | Permanently deletes all indexed content from ChromaDB — asks for confirmation. Does not affect the file-tracking database or email index. |

### Query Output

**Show source references** — when ON, the answer panel includes file paths, relevance scores, chunk counts, and query timing alongside the AI's answer. When OFF (default), only the clean answer is shown.

### Microphone / Speech Input

*(Only visible when faster-whisper, sounddevice, and numpy are installed)*

**Auto-stop after silence** — a slider from 1.0 to 8.0 seconds controlling how long Whisper waits after you stop speaking before ending the recording automatically.

- **Short (1–2s)** — snappy for short direct questions
- **Long (4–8s)** — better if you pause between phrases or speak slowly

The value is saved to config and persists across restarts.

### GPU Acceleration

Controls how many AI model layers Ollama offloads to your GPU. More layers on the GPU means faster query responses on systems with a dedicated graphics card.

| Value | Meaning |
|-------|---------|
| -1 (default) | **Auto** — Ollama decides how many layers fit in available VRAM |
| 0 | **CPU only** — use if GPU causes errors or VRAM is insufficient |
| 1–99 | **Partial offload** — fine-tune for laptops with limited VRAM |

**🔍 Detect GPU** — runs a background scan that identifies your GPU model, VRAM size, and suggests an optimal layers value. The suggestion is automatically populated in the spinbox.

**✅ Apply & Reload** — saves the layers value and reloads the Ollama configuration so it takes effect immediately on the next query — no app restart needed.

A scrollable status box below the controls shows the full detection output, including details that may be cut off in a plain label.

### Ollama Server

The **Ollama Server** section controls how AI Prowler manages the Ollama backend process.

**Auto-start Ollama server (opens separate CMD window)**

When this checkbox is **enabled**:
- AI Prowler checks on startup whether Ollama is already running
- If Ollama is not running, it launches `ollama serve` automatically in a separate CMD window
- When you close AI Prowler, the Ollama server window also closes
- The CMD window shows live Ollama server logs — you can minimise but do not close it manually while using AI Prowler

When this checkbox is **disabled** (default):
- AI Prowler does not start Ollama automatically
- You must start Ollama manually before using the query features — open a Command Prompt and run `ollama serve`, or start it from the Windows Start menu if installed as a service

> **Recommendation:** Enable auto-start if you only use Ollama through AI Prowler and want a one-click experience. Leave it disabled if you run other Ollama-based tools and want the server to stay running independently of AI Prowler.

The setting is saved immediately and persists across restarts.

---

## 💻 Command Line (Advanced)

All core functions are available without the GUI:

```bash
# Index a directory (recursive by default)
python rag_preprocessor.py index C:\Users\YourName\Documents

# Ask a question
python rag_preprocessor.py query "What is in my documents?"

# List indexed files
python rag_preprocessor.py list

# Show database statistics
python rag_preprocessor.py stats

# Scan a directory for changes without updating
python rag_preprocessor.py check C:\Users\YourName\Documents

# Update only changed files in a directory
python rag_preprocessor.py update C:\Users\YourName\Documents

# Auto-update all tracked directories
python rag_preprocessor.py auto-update

# Change the active AI model
python rag_preprocessor.py model llama3.1:8b

# Clear the entire database
python rag_preprocessor.py clear
```

---

## 🔧 System Requirements

### Minimum

| Component | Requirement |
|-----------|------------|
| OS | Windows 10 or Windows 11 (64-bit) |
| RAM | 8 GB |
| Storage | 6 GB free |
| CPU | Any modern 64-bit processor |
| Internet | Required for installation only |

### Recommended

| Component | Recommendation |
|-----------|---------------|
| RAM | 16 GB (enables 7b–8b models) |
| Storage | 15 GB (room for multiple models) |
| CPU | Modern quad-core or better |
| GPU | Optional — significantly speeds up 7b+ models |

### Download Sizes (One-Time, Installation Only)

| Component | Size |
|-----------|------|
| Python 3.11 | ~30 MB |
| Python packages (11 total) | ~600 MB |
| Ollama engine | ~400 MB |
| AI model — llama3.2:1b (default) | ~1.3 GB |
| Whisper speech model — large-v3-turbo | ~1.6 GB |
| **Total** | **~4 GB** |

After installation: 100% offline, no cloud connections, no data uploads ever.

---

## 📁 File Locations

### Installation Folder

```
C:\Users\YourName\AI Prowler\
├── rag_gui.py
├── rag_preprocessor.py
├── requirements.txt
├── RAG_RUN.bat
├── INSTALL.bat
├── UNINSTALL.bat
├── create_shortcut.py
├── rag_icon.ico
├── COMPLETE_USER_GUIDE.md
└── rag_database\               ← ChromaDB index (your indexed content)
    └── [ChromaDB files]
```

### User Data Files (Home Folder)

```
C:\Users\YourName\
├── .rag_config.json              ← All settings (model, GPU layers, silence threshold, auto-start, etc.)
├── .rag_auto_update_dirs.json    ← List of tracked directories
├── .rag_file_tracking.json       ← File modification baselines for change detection
├── .rag_email_index.json         ← Per-email Message-ID tracking for incremental indexing
├── .rag_license.key              ← License key (if applicable)
└── rag_auto_update.bat           ← Generated update script (created when you set a schedule)
```

### Speech Model Cache

```
C:\Users\YourName\.cache\huggingface\hub\
└── models--Systran--faster-whisper-large-v3-turbo\   ← ~1.6 GB
    (Only this sub-folder is touched by AI Prowler)
```

---

## 🔐 Privacy and Security

**AI Prowler makes zero network connections after installation.**

| What it does | What it does NOT do |
|--------------|-------------------|
| ✅ Runs 100% on your local machine | ❌ No cloud storage of any kind |
| ✅ All AI inference runs via local Ollama | ❌ No external API calls |
| ✅ No login or account required | ❌ No telemetry or analytics |
| ✅ No internet needed after install | ❌ No data collection |
| ✅ All data stays on your hard drive | ❌ No phone-home behaviour |

**Your documents, your questions, and your answers never leave your computer.**

---

## 🗑️ Uninstalling

### Option 1 — UNINSTALL.bat (recommended)

Double-click `UNINSTALL.bat`. It walks through 9 clearly labelled steps:

| Step | What is removed |
|------|----------------|
| 1/9 | Windows Task Scheduler task |
| 2/9 | Desktop shortcut (both "AI Prowler.lnk" and "RAG.lnk" if present) |
| 3/9 | AI Prowler entry from Windows PATH |
| 4/9 | Config files (`.rag_config.json`, `.rag_file_tracking.json`, `.rag_email_index.json`, etc.) |
| 5/9 | ChromaDB database (optional — confirms before deleting) |
| 6/9 | AI Prowler program files |
| 7/9 | Ollama engine |
| 8/9 | Whisper model cache — targets **only** the AI Prowler model folder, leaving other HuggingFace models untouched |
| 9/9 | Summary |

Python packages are intentionally kept to avoid breaking other programs. Remove Python separately via Settings → Apps if needed.

### Option 2 — Manual Removal

Delete:
- The AI Prowler installation folder
- From your home folder: `.rag_config.json`, `.rag_auto_update_dirs.json`, `.rag_file_tracking.json`, `.rag_email_index.json`, `.rag_license.key`, `rag_auto_update.bat`
- Desktop shortcut (`AI Prowler.lnk`)
- Task Scheduler task — open Task Scheduler from Start menu, find and delete the "RAG Auto-Update" task
- Whisper cache: `C:\Users\YourName\.cache\huggingface\hub\models--Systran--faster-whisper-large-v3-turbo\`

---

## 🚨 Troubleshooting

### Installation

| Problem | Solution |
|---------|---------|
| "Python not found" | Re-run INSTALL.bat — it installs Python 3.11 automatically |
| Package install failed | Check internet connection, re-run INSTALL.bat |
| "Ollama not found" | Download from [ollama.com/download/windows](https://ollama.com/download/windows) or re-run INSTALL.bat |
| Whisper download failed | Non-critical — model downloads on first mic button use |

### GUI

| Problem | Solution |
|---------|---------|
| GUI won't open | Run `python rag_gui.py` from Command Prompt to see the error message |
| "Could not import AI Prowler modules" | Ensure `rag_preprocessor.py` is in the same folder as `rag_gui.py` |
| Microphone button missing | Run `pip install faster-whisper sounddevice numpy`, then restart |
| Tab appears blank | Try launching via `RAG_RUN.bat` instead |
| Status indicator stays grey | Click **⚡ Load AI Model** or check that Ollama is running |

### Queries

| Problem | Solution |
|---------|---------|
| First query takes 2–3 minutes | Normal — the AI model is loading into memory for the first time. Use ⚡ Load AI Model beforehand to pre-warm |
| "Cannot connect to Ollama" | Enable Auto-start Ollama in Settings, or open Command Prompt and run `ollama serve` |
| Answers are vague | Try a larger model (Settings tab) or ask more specific questions |
| "No results" | Make sure the relevant documents have been indexed |

### Email Indexing

| Problem | Solution |
|---------|---------|
| Large .mbox import is slow | Normal for first import — per-message progress shows in the output panel. Use Stop/Resume to spread across multiple sessions |
| Stop button is slow to respond | Stop now responds after each individual message — if delayed, the current message is still being processed |
| Re-importing same .mbox re-indexes everything | Incremental indexing uses Message-ID tracking to skip known messages. If re-indexing still occurs, check that the archive file path hasn't changed |
| Yahoo/Outlook won't import | These formats need conversion first — see the Email chapter above |
| Apple Mail .mbox looks like a folder | On macOS it is a package. Copy it to Windows, it becomes a regular `.mbox` file |

### Ollama Server

| Problem | Solution |
|---------|---------|
| Ollama CMD window opens on startup unexpectedly | Auto-start is enabled — uncheck it in Settings → Ollama Server if you prefer to manage Ollama yourself |
| Ollama CMD window closed by accident | Re-enable auto-start and restart AI Prowler, or run `ollama serve` manually in a new Command Prompt |
| Auto-start isn't launching Ollama | Ensure `ollama` is in your PATH — re-run INSTALL.bat or install Ollama from ollama.com/download/windows |

### Scheduling

| Problem | Solution |
|---------|---------|
| Schedule not running | Check the Schedule tab shows "✅ Schedule Active" and verify Windows Task Scheduler is running |
| Can't create schedule | Run AI Prowler as Administrator (right-click → Run as administrator) |
| Schedule shows wrong time | Remove and recreate; check Windows time zone settings |

---

## 🎓 Tips and Best Practices

### Indexing

✅ Use Pre-scan first on any unfamiliar large folder  
✅ Start with one focused project folder to test, then expand  
✅ Use Pause/Stop freely — progress is always saved and resumable  
✅ For email, keep exported archives in a dedicated folder and re-export periodically  

❌ Don't index your entire C:\ drive  
❌ Don't index temp folders, Downloads, or the Recycle Bin  
❌ Don't run indexing and querying at the same time  

### Queries

✅ Use complete natural-language questions  
✅ Reference document names or dates when you know them  
✅ Increase context chunks for broad summarisation questions  
✅ Use voice input for longer or more natural questions  
✅ Click ⚡ Load AI Model when you open AI Prowler to pre-warm while you work  

❌ Don't use single keywords — the AI needs full context  
❌ Don't ask about content that hasn't been indexed  

### Email

✅ Export by label/folder from Gmail rather than "All Mail" if you only need specific content  
✅ Keep archive files at a stable path — the incremental indexer deduplicates by path + Message-ID  
✅ Schedule weekly re-imports for actively-used mailboxes  
✅ Use the per-message progress counter to estimate time for very large archives  

❌ Don't delete and recreate archive files unnecessarily — the incremental engine works best when the file path stays the same  

### Performance

✅ Use GPU layers = -1 (Auto) — Ollama optimises automatically  
✅ Schedule updates during off-hours (overnight, lunch)  
✅ Stick with `llama3.2:1b` unless you need higher answer quality  
✅ Enable Auto-start Ollama for a seamless one-click launch experience  

❌ Don't use 70b+ models unless you have 32+ GB RAM  
❌ Don't run multiple AI Prowler instances simultaneously  

---

## ❓ Frequently Asked Questions

**Q: Do I need an API key or account?**  
A: No. Everything runs locally with no accounts, keys, or registration of any kind.

**Q: Does this work offline?**  
A: Yes — 100% offline after the one-time installation.

**Q: Is my data private?**  
A: Completely. Nothing leaves your computer at any point.

**Q: How much does it cost?**  
A: Free.

**Q: Does it need a GPU?**  
A: No. The default model runs well on CPU-only hardware. A GPU speeds up larger models significantly.

**Q: How many documents can I index?**  
A: Thousands — limited only by available disk space and ChromaDB index capacity.

**Q: My Gmail export is 8 GB. Will AI Prowler handle it?**  
A: Yes. The incremental indexer processes messages one at a time with Stop/Resume support, so you can spread a large initial import over multiple sessions. Future re-imports only process new messages.

**Q: Can I query email from 10 years ago?**  
A: Yes, as long as those emails are in the exported archive and have been indexed.

**Q: Do I need to re-index everything when files change?**  
A: No — the Update Index tab re-indexes only new and changed files. For email archives, only new messages are processed.

**Q: What if my computer is off when a schedule is due?**  
A: Windows Task Scheduler runs the task the next time the computer is on and the trigger time is reached.

**Q: Can I use a different AI model?**  
A: Yes — any Ollama-compatible model works. Install it from the Settings tab or by running `ollama pull <model-name>`.

**Q: What does the Auto-start Ollama option do?**  
A: When enabled, AI Prowler automatically launches the Ollama server in a separate CMD window when you open AI Prowler. This means you never need to manually start Ollama — just open the app and it's ready. Disable it if you want to manage Ollama yourself or use it with other tools.

**Q: What is the ⚡ Load AI Model button for?**  
A: It manually triggers the model pre-warm so the AI is ready before you type your first question. The model loads automatically anyway when you switch to the Ask Questions tab, but clicking this button lets you start loading while you're still on another tab.

---

## 📝 Version History

### Version 1.9 (Current)

**New features:**
- 🟢 Auto-start Ollama — new "Ollama Server" section in Settings. When enabled, AI Prowler launches `ollama serve` automatically on startup and shuts it down on exit. Saves and restores across sessions.
- ⚡ Load AI Model button — manual pre-warm trigger in the Ask Questions tab. Start loading the model while you are still navigating other tabs.
- ⏹ Stop query button — cancel a running query without closing the application.
- 🔵 Model status indicator — coloured dot (grey/yellow/green) and text label in the Ask Questions tab shows real-time model load state.
- 🛠 UNINSTALL.bat PATH step rewritten — Step 3 now uses PowerShell exclusively, eliminating the hang caused by piping long PATH strings through CMD's `echo | find`.

**Fixes:**
- `ping_ollama` NameError on startup resolved — replaced with the correctly imported `check_ollama_available()` from `rag_preprocessor.py`.

---

### Version 1.8

**New features:**
- 🎤 Voice input with Whisper large-v3-turbo, auto-stop silence detection, adjustable threshold
- ⏸ Pause / Resume indexing — freeze mid-run and continue from exactly where you stopped
- 📬 Per-email incremental indexing for `.mbox`, `.rmail`, `.babyl`, `.mmdf` — Message-ID deduplication, near-instant Stop, automatic cleanup of deleted messages
- 🗂 Auto Scan Config tab — live editor for supported/skipped extensions and skipped directories
- 📁 Multi-folder queue with custom tree browser, Ctrl/Shift multi-select, mix of folders and individual files
- 🔍 Pre-scan mode — preview what will be indexed before committing
- ⚡ GPU acceleration controls — Detect GPU, set layers, Apply & Reload without restarting
- 🔄 Per-directory Remove with full vector and tracking cleanup
- 📊 Live elapsed timers on both the indexing and query progress bars
- 🎛 Named tab index constants — adding/reordering tabs no longer silently breaks prewarm

**Fixes:**
- Stop button now responds after each individual email message (was: waited for entire archive file)
- INSTALL.bat fallback `requirements.txt` generator now includes all 11 packages including speech
- UNINSTALL.bat Whisper removal targets only the AI Prowler model, not the entire HuggingFace cache
- UNINSTALL.bat step counter corrected (was mixed 1/7–9/9, now consistent 1/9–9/9)
- Version numbers synchronised between GUI and engine (both 1.8)

---

## 🎉 You're Ready!

You now know how to:

✅ Install AI Prowler completely  
✅ Index documents, code, and email from every major provider  
✅ Export email from Gmail, Apple Mail, Thunderbird, Yahoo, and Outlook  
✅ Ask questions with text or voice  
✅ Pre-warm the AI model with the Load AI Model button  
✅ Keep your index current with smart incremental updates  
✅ Schedule automatic background updates  
✅ Configure Ollama auto-start for a seamless one-click experience  
✅ Customise scan behaviour for your workflow  
✅ Tune GPU acceleration for your hardware  
✅ Troubleshoot every common issue  

**Start exploring your documents with AI!** 🚀

---

*AI Prowler v1.9 — Your Personal AI Knowledge Base*  
*100% Local &nbsp;•&nbsp; 100% Private &nbsp;•&nbsp; 100% Yours*
