#!/usr/bin/env python3
"""
AI Prowler GUI - Professional Graphical Interface
Modern GUI for AI Prowler Document Indexing and Querying
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import threading
import time
import subprocess
import json
import sys
from pathlib import Path
import queue
import os
from datetime import datetime

# ── Errno 22 / double-backslash HuggingFace path fix ─────────────────────────
# MUST be set before ANY import that could transitively pull in huggingface_hub
# (including faster_whisper, sentence_transformers, and transformers below).
# huggingface_hub reads HF_HUB_CACHE at module-import time and caches the
# resolved path as a constant for the lifetime of the process. On some Windows
# 10 machines the default home-directory path derivation produces a trailing
# backslash; os.path.join then appends another, giving "...\hash\filename"
# which Windows rejects as Errno 22 Invalid argument on every indexing attempt.
# pathlib.Path / operator never produces a trailing backslash, so this string
# is always clean regardless of OS version, locale, or registry state.
if not os.environ.get('HF_HUB_CACHE'):
    from pathlib import Path as _Path
    os.environ['HF_HUB_CACHE'] = str(
        _Path.home() / '.cache' / 'huggingface' / 'hub'
    )

import ctypes
import webbrowser

# Ensure script directory is on sys.path so rag_preprocessor.py is always found
# even when launched via desktop icon
sys.path.insert(0, str(Path(__file__).parent.resolve()))

# ── pythonw.exe stdout/stderr safety ──────────────────────────────────────
# pythonw.exe sets sys.stdout and sys.stderr to None, which causes print()
# and any logging to crash with AttributeError.  Redirect to devnull.
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

# ── Application version ──────────────────────────────────────────────────────
# Single source of truth for the app version. Bump this one line when releasing
# a new version; all UI labels, About dialogs, help text, and update checks
# read from here.
APP_VERSION = "6.0.0"

# ── Telemetry ────────────────────────────────────────────────────────────────
# Anonymous heartbeat phone-home. See cloudflare-worker/ for the receiver.
# The endpoint can be overridden in ~/.ai-prowler/config.json under the key
# "telemetry_endpoint". Telemetry can be turned off in Settings.
_TELEMETRY_DEFAULT_ENDPOINT = (
    "https://ai-prowler-telemetry.david-vavro1.workers.dev"
)
_TELEMETRY_HEARTBEAT_INTERVAL_SEC = 24 * 3600   # daily
_TELEMETRY_FIRST_DELAY_SEC = 5 * 60             # wait 5 min after launch
_TELEMETRY_RETRY_DELAY_SEC = 60 * 60            # 1h backoff on failure


# ── Optional speech-to-text packages ────────────────────────────────────────
# Both packages are optional — if missing the mic button is simply hidden.
# Install with: pip install faster-whisper sounddevice
SPEECH_AVAILABLE = False
_speech_import_error = ""
try:
    import numpy as np
    import sounddevice as sd
    from faster_whisper import WhisperModel
    SPEECH_AVAILABLE = True
except ImportError as _se:
    _speech_import_error = str(_se)

# Import AI Prowler functions with better error handling
RAG_AVAILABLE = False
try:
    from rag_preprocessor import (
        index_directory, index_file_list, scan_directory,
        rag_query, query_ollama, load_config, save_config,
        save_extension_config, load_full_extension_config,
        get_model_context_window, calculate_optimal_chunks,
        get_model_num_ctx,                        # ← new: for chunk-aware prewarm
        load_auto_update_list, add_to_auto_update_list,
        remove_directory_from_index,
        scan_directory_for_changes, save_tracking_database,
        normalise_path,
        MODEL_CONTEXT_WINDOWS, MODEL_INFO,
        EXTERNAL_PROVIDERS,
        get_provider_status, get_provider_timeout_str, set_provider_timeout,
        query_external_llm, test_provider_connection,
        check_license, prompt_for_license, LICENSE_REQUIRED,
        command_update, show_stats, clear_database,
        prewarm_ollama, prewarm_embeddings, invalidate_chroma_cache, check_ollama_available,
        detect_gpu, SUPPORTED_EXTENSIONS, SKIP_EXTENSIONS, SKIP_DIRECTORIES,
        TRACKING_DB, AUTO_UPDATE_LIST, CONFIG_FILE
    )
    import rag_preprocessor as _rag_engine
    _rag_engine.GUI_MODE = True   # disable terminal spinner — use GUI-safe progress output
    RAG_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import AI Prowler functions: {e}")
    print("Make sure rag_preprocessor.py is in the same directory")
    RAG_AVAILABLE = False
    _RAG_ERROR = str(e)
except Exception as e:
    print(f"Error loading AI Prowler module: {e}")
    print("Continuing with limited functionality...")
    RAG_AVAILABLE = False
    _RAG_ERROR = str(e)
    MODEL_INFO = {}
    MODEL_CONTEXT_WINDOWS = {"default": 8192}
    EXTERNAL_PROVIDERS = {}
else:
    _RAG_ERROR = ""

# ── Speech Recorder ──────────────────────────────────────────────────────────

class SpeechRecorder:
    """
    Manages microphone recording and Whisper transcription.

    Lifecycle:
      start()  — begins capturing audio from the default mic
      stop()   — stops capture and triggers transcription
      The on_result(text) callback is called on the calling thread via the
      provided tk_queue so Tkinter can update the UI safely.

    The faster-whisper 'large-v3-turbo' model (~1.6 GB) is downloaded once on first
    use and cached in ~/.cache/huggingface. Subsequent loads are instant.
    """

    SAMPLE_RATE   = 16000   # Hz — Whisper native sample rate
    CHANNELS      = 1
    DTYPE         = 'float32'
    SILENCE_DB    = -40     # dBFS threshold below which audio is considered silence
    SILENCE_SECS  = 3.0     # seconds of silence before auto-stopping (adjustable in Settings)
    MAX_SECS      = 60      # hard cap on recording length

    _whisper_model = None   # class-level cache — loaded once, reused forever
    _model_lock    = threading.Lock()

    def __init__(self, tk_queue: queue.Queue):
        self._tk_queue   = tk_queue
        self._frames     = []
        self._recording  = False
        self._stream     = None

    # ── Whisper model — lazy load, cached at class level ─────────────────────

    @classmethod
    def _get_model(cls):
        """Load the Whisper large-v3-turbo model once and cache it for the session.

        Tries CUDA first (faster), but automatically falls back to CPU if the
        CTranslate2 CUDA backend fails — a common mismatch even when PyTorch
        reports CUDA as available.
        """
        with cls._model_lock:
            if cls._whisper_model is None:
                # Determine preferred device
                try:
                    import torch
                    preferred_device = 'cuda' if torch.cuda.is_available() else 'cpu'
                except ImportError:
                    preferred_device = 'cpu'

                # Try preferred device first; fall back to CPU on any CUDA error
                for device, compute in [
                    (preferred_device, 'float16' if preferred_device == 'cuda' else 'int8'),
                    ('cpu', 'int8'),   # fallback -- always works
                ]:
                    try:
                        cls._whisper_model = WhisperModel(
                            'large-v3-turbo',
                            device=device,
                            compute_type=compute
                        )
                        break   # success -- stop trying
                    except Exception as cuda_err:
                        if device == 'cpu':
                            raise   # CPU also failed -- nothing more to try
                        # CUDA failed; log and retry with CPU
                        print(f"[Whisper] CUDA init failed ({cuda_err}), "
                              f"falling back to CPU transcription.")
            return cls._whisper_model

    # ── Recording control ─────────────────────────────────────────────────────

    def start(self):
        """Begin recording from the default microphone."""
        self._frames    = []
        self._recording = True
        self._silence_counter = 0

        def _audio_callback(indata, frames, time_info, status):
            if not self._recording:
                return
            chunk = indata.copy()
            self._frames.append(chunk)

            # Auto-stop on sustained silence
            rms = float(np.sqrt(np.mean(chunk ** 2)))
            db  = 20 * np.log10(rms + 1e-9)
            if db < self.SILENCE_DB:
                self._silence_counter += frames / self.SAMPLE_RATE
            else:
                self._silence_counter = 0

            # Stop if silence threshold reached or max length exceeded
            total_secs = len(self._frames) * frames / self.SAMPLE_RATE
            if (self._silence_counter >= self.SILENCE_SECS and total_secs > 1.0) \
                    or total_secs >= self.MAX_SECS:
                self._recording = False
                # Signal GUI that recording ended (auto-stop)
                self._tk_queue.put(('mic_auto_stop', None))

        self._stream = sd.InputStream(
            samplerate=self.SAMPLE_RATE,
            channels=self.CHANNELS,
            dtype=self.DTYPE,
            blocksize=int(self.SAMPLE_RATE * 0.1),   # 100 ms blocks
            callback=_audio_callback
        )
        self._stream.start()

    def stop(self):
        """Stop recording and transcribe on a background thread."""
        self._recording = False
        if self._stream:
            try:
                self._stream.stop()
                self._stream.close()
            except Exception:
                pass
            self._stream = None

        frames = self._frames[:]
        if not frames:
            self._tk_queue.put(('mic_result', ''))
            return

        threading.Thread(target=self._transcribe, args=(frames,), daemon=True).start()

    # ── Transcription ─────────────────────────────────────────────────────────

    def _transcribe(self, frames):
        """Run Whisper transcription on captured frames (background thread)."""
        try:
            self._tk_queue.put(('mic_transcribing', None))

            audio = np.concatenate(frames, axis=0).flatten()

            model = self._get_model()
            segments, _ = model.transcribe(
                audio,
                language='en',
                beam_size=5,
                vad_filter=True,          # skip silent sections
                vad_parameters=dict(min_silence_duration_ms=500)
            )
            text = ' '.join(seg.text.strip() for seg in segments).strip()
            self._tk_queue.put(('mic_result', text))

        except Exception as exc:
            self._tk_queue.put(('mic_error', str(exc)))



# ── Multi-folder picker dialog ─────────────────────────────────────────────────

class MultiFolderDialog:
    """
    Custom dialog that lets the user navigate the filesystem tree and
    select multiple files and/or folders using Ctrl-click and Shift-click, 
    then add them all to the index queue at once.

    Usage:
        dialog = MultiFolderDialog(parent)
        parent.wait_window(dialog.window)
        selected = dialog.result  # list of paths (files or folders), or [] if cancelled
    """

    def __init__(self, parent):
        self.result = []
        self.window = tk.Toplevel(parent)
        self.window.title("Select Files & Folders to Index")
        self.window.geometry("680x520")
        self.window.minsize(500, 380)
        self.window.transient(parent)
        self.window.grab_set()

        # ── Top: current path bar ──────────────────────────────────────────
        nav_frame = ttk.Frame(self.window)
        nav_frame.pack(fill='x', padx=10, pady=(8, 4))

        ttk.Button(nav_frame, text="⬆ Up",
                   command=self._go_up).pack(side='left', padx=(0, 6))

        self._loc_var = tk.StringVar()
        loc_entry = ttk.Entry(nav_frame, textvariable=self._loc_var,
                              font=('Arial', 9))
        loc_entry.pack(side='left', fill='x', expand=True)
        loc_entry.bind('<Return>', lambda e: self._navigate_to(self._loc_var.get()))

        # ── Middle: split pane — tree left, selected list right ────────────
        pane = ttk.PanedWindow(self.window, orient='horizontal')
        pane.pack(fill='both', expand=True, padx=10, pady=4)

        # Left: filesystem tree
        left = ttk.Frame(pane)
        pane.add(left, weight=3)

        ttk.Label(left, text="📂 Navigate  (double-click folders to open, "
                             "single-click to select files/folders)",
                  font=('Arial', 8), foreground='gray').pack(anchor='w')

        tree_scroll_y = ttk.Scrollbar(left, orient='vertical')
        tree_scroll_x = ttk.Scrollbar(left, orient='horizontal')
        self._tree = ttk.Treeview(left, selectmode='extended',
                                  yscrollcommand=tree_scroll_y.set,
                                  xscrollcommand=tree_scroll_x.set,
                                  show='tree')
        tree_scroll_y.config(command=self._tree.yview)
        tree_scroll_x.config(command=self._tree.xview)
        tree_scroll_y.pack(side='right', fill='y')
        tree_scroll_x.pack(side='bottom', fill='x')
        self._tree.pack(fill='both', expand=True)

        self._tree.bind('<Double-1>', self._on_double_click)
        self._tree.bind('<Return>',   self._on_enter_key)
        self._tree.bind('<<TreeviewOpen>>', self._on_tree_open)

        # Right: selection staging list
        right = ttk.Frame(pane)
        pane.add(right, weight=2)

        ttk.Label(right, text="✅ Selected for queue:",
                  font=('Arial', 8), foreground='gray').pack(anchor='w')

        sel_scroll = ttk.Scrollbar(right, orient='vertical')
        self._sel_listbox = tk.Listbox(right, font=('Courier', 8),
                                       selectmode=tk.EXTENDED,
                                       yscrollcommand=sel_scroll.set)
        sel_scroll.config(command=self._sel_listbox.yview)
        sel_scroll.pack(side='right', fill='y')
        self._sel_listbox.pack(fill='both', expand=True)

        # ── Middle buttons between panes ──────────────────────────────────
        mid_btn_frame = ttk.Frame(self.window)
        mid_btn_frame.pack(fill='x', padx=10, pady=2)

        ttk.Button(mid_btn_frame, text="➕ Add Selected Items →",
                   command=self._add_selected).pack(side='left', padx=(0, 8))
        ttk.Button(mid_btn_frame, text="❌ Remove from List",
                   command=self._remove_from_list).pack(side='left')

        self._count_var = tk.StringVar(value="0 items selected")
        ttk.Label(mid_btn_frame, textvariable=self._count_var,
                  font=('Arial', 9), foreground='gray').pack(side='right')

        # ── Bottom: OK / Cancel ────────────────────────────────────────────
        btn_frame = ttk.Frame(self.window)
        btn_frame.pack(fill='x', padx=10, pady=(4, 10))

        ttk.Button(btn_frame, text="✅ Add to Queue",
                   command=self._ok,
                   style='Accent.TButton').pack(side='right', padx=(6, 0))
        ttk.Button(btn_frame, text="Cancel",
                   command=self._cancel).pack(side='right')

        ttk.Label(btn_frame,
                  text="Ctrl-click or Shift-click to select multiple items",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        # ── Populate the tree starting from home or drives ─────────────────
        self._path_map = {}   # tree item id → full path
        self._populate_roots()

    # ── Tree helpers ───────────────────────────────────────────────────────

    def _populate_roots(self):
        """Fill tree with root locations: drives on Windows, / on Unix."""
        import os
        self._tree.delete(*self._tree.get_children())
        self._path_map.clear()

        if os.name == 'nt':
            # Windows — list available drive letters
            import string, ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drive = f"{letter}:\\"
                    if os.path.exists(drive):
                        iid = self._tree.insert('', tk.END,
                                                text=f"💾 {drive}",
                                                open=False)
                        self._path_map[iid] = drive
                        self._tree.insert(iid, tk.END, text="…")  # lazy placeholder
                bitmask >>= 1
        else:
            # Unix — start at /
            iid = self._tree.insert('', tk.END, text="📁 /", open=False)
            self._path_map[iid] = "/"
            self._tree.insert(iid, tk.END, text="…")

        # Also add home and common locations
        home = str(Path.home())
        home_iid = self._tree.insert('', 0, text=f"🏠 Home  ({home})", open=False)
        self._path_map[home_iid] = home
        self._tree.insert(home_iid, tk.END, text="…")

        self._loc_var.set(home)

    def _expand_node(self, iid):
        """Lazily load subdirectories and files for a tree node."""
        path = self._path_map.get(iid)
        if not path:
            return
        # Remove placeholder children
        for child in self._tree.get_children(iid):
            self._tree.delete(child)
        try:
            # Get all entries (files and folders)
            entries = list(os.scandir(path))
            
            # Separate folders and files, filter hidden items
            folders = sorted(
                [e for e in entries
                 if e.is_dir(follow_symlinks=False)
                 and not e.name.startswith('.')
                 and e.name not in {'$RECYCLE.BIN', 'System Volume Information'}],
                key=lambda e: e.name.lower()
            )
            
            files = sorted(
                [e for e in entries
                 if e.is_file(follow_symlinks=False)
                 and not e.name.startswith('.')],
                key=lambda e: e.name.lower()
            )
            
            # Insert folders first (with placeholder for lazy loading)
            for entry in folders:
                child_iid = self._tree.insert(iid, tk.END,
                                              text=f"📁 {entry.name}",
                                              open=False)
                self._path_map[child_iid] = entry.path
                self._tree.insert(child_iid, tk.END, text="…")  # lazy placeholder
            
            # Then insert files (no placeholder needed)
            for entry in files:
                child_iid = self._tree.insert(iid, tk.END,
                                              text=f"📄 {entry.name}")
                self._path_map[child_iid] = entry.path
                
        except PermissionError:
            pass
        self._loc_var.set(path)

    def _on_double_click(self, event):
        """Double-click: expand/navigate into folder (files do nothing)."""
        iid = self._tree.focus()
        if iid:
            path = self._path_map.get(iid)
            # Only expand if it's a directory
            if path and Path(path).is_dir():
                self._expand_node(iid)
                self._tree.item(iid, open=True)

    def _on_enter_key(self, event):
        """Enter key: same as double-click."""
        self._on_double_click(event)

    def _on_tree_open(self, event):
        """Fired when a tree node is expanded via the arrow toggle.

        Replaces the lazy '…' placeholder with actual folder/file entries
        so files are always visible when a folder is opened — whether by
        double-click, arrow click, or keyboard expand.
        """
        iid = self._tree.focus()
        if not iid:
            return
        # Check if children are still just the '…' placeholder
        children = self._tree.get_children(iid)
        if len(children) == 1 and self._tree.item(children[0], 'text') == '…':
            self._expand_node(iid)

    def _go_up(self):
        """Navigate to the parent of the currently focused tree node."""
        iid = self._tree.focus()
        if iid:
            parent_iid = self._tree.parent(iid)
            if parent_iid:
                self._tree.selection_set(parent_iid)
                self._tree.focus(parent_iid)
                self._tree.see(parent_iid)
                path = self._path_map.get(parent_iid)
                if path:
                    self._loc_var.set(path)

    def _navigate_to(self, path):
        """Type a path in the bar and press Enter to jump there."""
        path = path.strip()
        if not Path(path).is_dir():
            messagebox.showwarning("Not Found",
                                   f"Directory not found:\n{path}",
                                   parent=self.window)
            return
        # Add as a top-level entry and select it
        iid = self._tree.insert('', 0, text=f"📁 {Path(path).name or path}",
                                open=False)
        self._path_map[iid] = path
        self._expand_node(iid)
        self._tree.item(iid, open=True)
        self._tree.selection_set(iid)
        self._tree.see(iid)

    # ── Selection list helpers ─────────────────────────────────────────────

    def _add_selected(self):
        """Add all currently highlighted tree items to the right-hand list."""
        existing = set(self._sel_listbox.get(0, tk.END))
        for iid in self._tree.selection():
            path = self._path_map.get(iid)
            if path and path not in existing:
                self._sel_listbox.insert(tk.END, path)
                existing.add(path)
        self._update_count()

    def _remove_from_list(self):
        """Remove highlighted items from the right-hand staging list."""
        for idx in reversed(self._sel_listbox.curselection()):
            self._sel_listbox.delete(idx)
        self._update_count()

    def _update_count(self):
        n = self._sel_listbox.size()
        self._count_var.set(f"{n} folder{'s' if n != 1 else ''} selected")

    # ── Dialog close ──────────────────────────────────────────────────────

    def _ok(self):
        self.result = list(self._sel_listbox.get(0, tk.END))
        self.window.destroy()

    def _cancel(self):
        self.result = []
        self.window.destroy()


# ── Main GUI ──────────────────────────────────────────────────────────────────

class RAGGui:
    def __init__(self, root):
        self.root = root
        self.root.title(f"AI-Prowler — Agentic RAG Knowledge Base v{APP_VERSION}")
        self.root.geometry("1200x980")
        
        # Set icon (if available)
        try:
            _icon_path = Path(__file__).parent / 'rag_icon.ico'
            if _icon_path.exists():
                self.root.iconbitmap(str(_icon_path))
        except Exception:
            pass
        
        # Set up window close handler to stop Ollama if we started it
        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
        
        # Output queue for threading
        self.output_queue = queue.Queue()
        
        # Current model
        self.current_model = tk.StringVar(value="llama3.2:1b")
        
        # Model loading state
        self._prewarm_done       = False   # True once a successful prewarm has run
        self._prewarm_in_progress = False  # prevents duplicate prewarm calls
        self._prewarm_cancel     = False   # set True to abort any running prewarm
        
        # Warmup state - simplified: grey (loading) → green (ready after test query)
        self._warmup_done        = False  # True = model warmed with test query, ready for use
        self._warmup_test_running = False  # True while "Hi" test query is running
        self._warmup_timer_id    = None    # Timer handle for warmup waiting counter
        self._warmup_start_time  = None    # When warmup test started
        
        # Debug output checkbox var
        self.debug_output_var    = tk.BooleanVar(value=False)
        # Debug View — show DOS/console windows in foreground (default: hidden)
        self.debug_view_var      = tk.BooleanVar(value=False)
        # OCR debug — log full OCR text during indexing (default: off)
        self.ocr_debug_var       = tk.BooleanVar(value=False)

        # ── Ollama status ────────────────────────────────────────────────────
        self._ollama_ready       = False   # True = model loaded and warmed
        self._ollama_loading     = False   # True = load in progress
        self._query_running      = False   # True while a query thread is active
        
        # Query output mode — mirrors SHOW_SOURCES in rag_preprocessor
        self.show_sources_var = tk.BooleanVar(value=False)

        # GPU layers for Ollama (-1 = auto, 0 = CPU only, N = partial)
        self.gpu_layers_var = tk.IntVar(value=-1)
        
        # Auto-start Ollama server on startup
        self.auto_start_ollama_var = tk.BooleanVar(value=True)
        self._ollama_process   = None  # Track if we started Ollama
        self._http_server_proc = None  # HTTP MCP server subprocess
        self._cloudflared_proc = None  # cloudflared tunnel subprocess

        # Microphone / speech-to-text state
        self._mic_recorder  = None
        self._mic_recording = False
        self.mic_silence_var = tk.DoubleVar(value=3.0)
        # Mic insertion mode: True = append to existing text, False = replace (clear first)
        self.mic_mode_append = tk.BooleanVar(value=True)

        # File attachments for questions (images + text files)
        self._attached_files = []   # list of dicts: {path, name, type}
        # File output mode — tells LLM to tag output files for auto-detection
        self.file_output_mode_var = tk.BooleanVar(value=True)   # ON by default

        # Index queue — list of (directory_path, recursive) tuples
        self._index_queue = []

        # Stop / pause control for index worker
        self._index_stop_event  = threading.Event()   # set = stop requested
        self._index_pause_event = threading.Event()   # set = paused
        self._index_running     = False
        # Resume state — where to continue after a stop
        self._index_resume_dirs  = []   # remaining dirs at time of stop
        self._index_resume_file  = 0    # file index within first remaining dir

        # Index elapsed-time timer
        self._index_timer_id    = None  # .after() handle
        self._index_start_time  = None  # float timestamp when indexing started
        
        # Load config
        self.load_configuration()

        # Sync provider dropdown to saved active_provider
        if RAG_AVAILABLE and hasattr(self, '_provider_ids'):
            try:
                saved = _rag_engine.ACTIVE_PROVIDER
                if saved in self._provider_ids:
                    idx = self._provider_ids.index(saved)
                    self._provider_combo.current(idx)
                    self._provider_var.set(self._provider_labels[idx])
            except Exception:
                pass
        
        # Check if AI Prowler engine is available
        if not RAG_AVAILABLE:
            messagebox.showerror(
                "Module Error",
                "Could not load AI Prowler engine module.\n\n"
                "Please ensure:\n"
                "1. rag_preprocessor.py is in the same directory\n"
                "2. All required packages are installed:\n"
                "   pip install chromadb sentence-transformers pdfplumber python-docx pypdf extract-msg requests\n\n"
                "The GUI will now close."
            )
            sys.exit(1)
            sys.exit(1)
        
        # Check license if required
        try:
            if LICENSE_REQUIRED and not check_license():
                if not prompt_for_license():
                    messagebox.showerror("License Required", "Valid license required to run AI Prowler.")
                    sys.exit(1)
        except Exception as e:
            print(f"Warning: License check failed: {e}")
        
        # Create GUI
        self.create_widgets()
        
        # Start output processor
        self.process_output_queue()
        
        # Bind tab-change event — prewarm Ollama when user switches to Ask Questions
        self.notebook.bind('<<NotebookTabChanged>>', self._on_tab_changed)
        
        # Check and auto-start Ollama if enabled (before prewarm)
        self.root.after(500, self._check_and_start_ollama)
        
        # Startup prewarm — load model into memory after a 3-second delay so
        # the window finishes drawing first. Silent background thread.
        self.root.after(3000, self._trigger_prewarm)

        # MCP status bar indicator — check once on startup
        self.root.after(2000, self._refresh_mcp_status_bar)
        
    def load_configuration(self):
        """Load saved configuration"""
        try:
            if RAG_AVAILABLE:
                config = load_config()
                if config and isinstance(config, dict):
                    if 'model' in config:
                        self.current_model.set(config['model'])
                    else:
                        self.current_model.set("llama3.2:1b")
                    # Load show_sources — default False (clean answer-only mode)
                    show_sources = config.get('show_sources', False)
                    self.show_sources_var.set(show_sources)
                    if RAG_AVAILABLE:
                        _rag_engine.SHOW_SOURCES = show_sources
                    debug_output = config.get('debug_output', False)
                    self.debug_output_var.set(debug_output)
                    if RAG_AVAILABLE:
                        _rag_engine.DEBUG_OUTPUT = debug_output
                    # Load debug_view — default False (background/hidden windows)
                    debug_view = config.get('debug_view', False)
                    self.debug_view_var.set(debug_view)
                    # Load ocr_debug — default False
                    ocr_debug = config.get('ocr_debug', False)
                    self.ocr_debug_var.set(ocr_debug)
                    if RAG_AVAILABLE:
                        _rag_engine.OCR_DEBUG = ocr_debug
                    # Load gpu_layers — default -1 (auto)
                    gpu_layers = config.get('gpu_layers', -1)
                    self.gpu_layers_var.set(gpu_layers)
                    if RAG_AVAILABLE:
                        _rag_engine.GPU_LAYERS = gpu_layers
                    # Load auto_start_ollama — default False (manual start)
                    auto_start = config.get('auto_start_ollama', True)
                    self.auto_start_ollama_var.set(auto_start)
                    print(f"[CONFIG] Loaded auto_start_ollama: {auto_start}")
                    # Load mic silence timeout — default 3.0 seconds
                    silence_secs = config.get('mic_silence_secs', 3.0)
                    self.mic_silence_var.set(silence_secs)
                    if SPEECH_AVAILABLE:
                        SpeechRecorder.SILENCE_SECS = silence_secs
                    # Load active provider — default 'local'
                    active_provider = config.get('active_provider', 'local')
                    _rag_engine.ACTIVE_PROVIDER = active_provider
                else:
                    self.current_model.set("llama3.2:1b")
            else:
                self.current_model.set("llama3.2:1b")
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
            self.current_model.set("llama3.2:1b")
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="🚪 Exit AI-Prowler",
                              command=self._on_window_close)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        help_menu.add_command(label="📖 User Guide", command=self.show_user_guide)
        help_menu.add_command(label="🚀 Quick Start", command=self.show_quick_start)
        help_menu.add_separator()
        help_menu.add_command(label="☁️ Cloudflare Tunnel Setup",
                              command=self.show_cloudflare_setup_guide)
        help_menu.add_command(label="🔌 Connect Claude.ai",
                              command=self.show_claude_connector_guide)
        help_menu.add_separator()
        help_menu.add_command(label="🔔 Notifications Status",
                              command=self.show_notifications_status)
        help_menu.add_separator()
        help_menu.add_command(label="ℹ️ About AI Prowler", command=self.show_about)
    
    def show_user_guide(self):
        """Show user guide in new window"""
        self.show_help_window("User Guide", self.get_user_guide_content())
    
    def show_quick_start(self):
        """Show quick start guide"""
        self.show_help_window("Quick Start", self.get_quick_start_content())
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""AI-Prowler — Agentic RAG Knowledge Base
Version {APP_VERSION}

Your personal AI assistant that answers questions about YOUR documents.

Core Features:
• Agentic RAG with Claude Desktop & Claude.ai (13 MCP tools)
• 65+ file types: PDF, Word (.docx), Excel (.xlsx/.xls), PowerPoint, HTML, RTF, ODT, CSV, email, images & more
• Smart chunking — full Column: Value context for spreadsheet and tabular data
• .docx tables fully extracted (financial tables, schedules, grids)
• Automatic OCR for scanned PDFs and image files
• Incremental indexing — only changed files reprocessed
• Auto-purge deleted files from ChromaDB on every update run
• Email support (.eml, .msg, .mbox) with deduplication
• Voice input via local Whisper model
• Remote access via Cloudflare Tunnel + OAuth 2.0
• Auto-start after Windows reboot via Task Scheduler

Small Business Service Tools (🏢 tab):
• Route optimization & tap-to-navigate links (free)
• Weather forecasts for job scheduling (free)
• QuickBooks Online invoicing (OAuth)
• QuickBooks Desktop invoicing (COM)
• Job spreadsheet updater (.xlsx)

⚠  .doc and .xls (legacy OLE binary) are NOT supported — convert to .docx / .xlsx first.

100% Local • 100% Private • 100% Yours

Built with Python, ChromaDB, and Claude"""
        
        messagebox.showinfo("About AI Prowler", about_text)

    def show_notifications_status(self):
        """Display a diagnostic popup with cached notifications, dismissed
        IDs, and source URL — plus refresh / clear-dismissed buttons.

        This is a status / debugging tool, not a normal user feature.
        Useful for verifying that the notification fetch is working and
        for un-dismissing test banners.
        """
        win = tk.Toplevel(self.root)
        win.title("Notifications Status")
        win.geometry("820x620")

        text_widget = scrolledtext.ScrolledText(
            win, wrap=tk.WORD, font=('Consolas', 9))
        text_widget.pack(fill='both', expand=True, padx=10, pady=(10, 6))

        # Configure text tags for color-coded sections
        text_widget.tag_configure('header',
                                   font=('Consolas', 11, 'bold'),
                                   foreground='#003366')
        text_widget.tag_configure('label',
                                   font=('Consolas', 9, 'bold'))
        text_widget.tag_configure('ok', foreground='#006600')
        text_widget.tag_configure('warn', foreground='#aa6600')
        text_widget.tag_configure('err', foreground='#aa0000')
        text_widget.tag_configure('dim', foreground='#666666')

        def _render():
            """Build the popup contents from current files on disk."""
            text_widget.config(state='normal')
            text_widget.delete('1.0', tk.END)

            # ── Source URL ────────────────────────────────────────
            text_widget.insert(tk.END, "Source\n", 'header')
            text_widget.insert(tk.END, "  URL:   ", 'label')
            text_widget.insert(tk.END,
                f"{getattr(self, '_notif_url', '(not set)')}\n")
            text_widget.insert(tk.END, "  Cache: ", 'label')
            text_widget.insert(tk.END, f"{self._notif_cache_path}\n")
            text_widget.insert(tk.END, "  Dismissed: ", 'label')
            text_widget.insert(tk.END, f"{self._dismissed_path}\n\n")

            # ── Cache file status ────────────────────────────────
            text_widget.insert(tk.END, "Cache File\n", 'header')
            cache_data = None
            if self._notif_cache_path.exists():
                try:
                    mtime = datetime.fromtimestamp(
                        self._notif_cache_path.stat().st_mtime)
                    age_sec = (datetime.now() - mtime).total_seconds()
                    if age_sec < 60:
                        age_str = f"{int(age_sec)}s ago"
                    elif age_sec < 3600:
                        age_str = f"{int(age_sec / 60)}m ago"
                    elif age_sec < 86400:
                        age_str = f"{int(age_sec / 3600)}h ago"
                    else:
                        age_str = f"{int(age_sec / 86400)}d ago"

                    text_widget.insert(tk.END, "  Last fetch: ", 'label')
                    text_widget.insert(tk.END,
                        f"{mtime.strftime('%Y-%m-%d %H:%M:%S')} "
                        f"({age_str})\n", 'ok')

                    with open(self._notif_cache_path, 'r',
                              encoding='utf-8') as f:
                        cache_data = json.load(f)

                    text_widget.insert(tk.END, "  Size: ", 'label')
                    text_widget.insert(tk.END,
                        f"{self._notif_cache_path.stat().st_size} bytes\n")

                    latest_v = cache_data.get('latest_version', '')
                    if latest_v:
                        text_widget.insert(tk.END,
                            "  Latest version (from server): ", 'label')
                        # Highlight if newer than running version
                        try:
                            from packaging.version import Version
                            is_newer = (
                                Version(latest_v) > Version(APP_VERSION))
                        except Exception:
                            is_newer = latest_v != APP_VERSION
                        tag = 'warn' if is_newer else 'ok'
                        suffix = (
                            f"  (running: v{APP_VERSION}"
                            f"{' — UPDATE AVAILABLE' if is_newer else ''})")
                        text_widget.insert(tk.END,
                            f"v{latest_v}{suffix}\n", tag)
                except Exception as e:
                    text_widget.insert(tk.END,
                        f"  ERROR reading cache: {e}\n", 'err')
            else:
                text_widget.insert(tk.END,
                    "  (no cache file — fetch has never succeeded)\n",
                    'warn')
            text_widget.insert(tk.END, "\n")

            # ── Dismissed list ───────────────────────────────────
            text_widget.insert(tk.END, "Dismissed Notifications\n",
                                'header')
            dismissed = set()
            if self._dismissed_path.exists():
                try:
                    dismissed = set(json.loads(
                        self._dismissed_path.read_text(encoding='utf-8')))
                except Exception as e:
                    text_widget.insert(tk.END,
                        f"  ERROR reading dismissed list: {e}\n", 'err')
            if dismissed:
                for d_id in sorted(dismissed):
                    text_widget.insert(tk.END, f"  • {d_id}\n", 'dim')
            else:
                text_widget.insert(tk.END, "  (none)\n", 'dim')
            text_widget.insert(tk.END, "\n")

            # ── Notifications in cache ───────────────────────────
            text_widget.insert(tk.END, "Cached Notifications\n", 'header')
            if not cache_data:
                text_widget.insert(tk.END,
                    "  (no cache available)\n", 'dim')
            else:
                notifs = cache_data.get('notifications', [])
                if not notifs:
                    text_widget.insert(tk.END,
                        "  (cache file present but no notifications)\n",
                        'dim')
                else:
                    today_str = datetime.now().strftime('%Y-%m-%d')
                    for i, n in enumerate(notifs, 1):
                        nid = n.get('id', '(no id)')
                        title = n.get('title', '(no title)')
                        body = n.get('body', '')
                        # Accept both schemas — start_date/end_date (current)
                        # and show_after/show_until (legacy)
                        start = (n.get('start_date', '')
                                 or n.get('show_after', ''))
                        end = (n.get('end_date', '')
                               or n.get('show_until', ''))
                        show_once = n.get('show_once', False)

                        # Determine current display state
                        states = []
                        if nid in dismissed:
                            states.append(('dismissed', 'dim'))
                        if start and today_str < start:
                            states.append(('not-yet-active', 'warn'))
                        if end and today_str > end:
                            states.append(('expired', 'dim'))
                        if not states:
                            states.append(('SHOWING', 'ok'))

                        text_widget.insert(tk.END,
                            f"  [{i}] {title}\n", 'label')
                        text_widget.insert(tk.END, f"      id:     ",
                                            'dim')
                        text_widget.insert(tk.END, f"{nid}\n")
                        if body:
                            text_widget.insert(tk.END, f"      body:   ",
                                                'dim')
                            text_widget.insert(tk.END, f"{body}\n")
                        text_widget.insert(tk.END, f"      dates:  ",
                                            'dim')
                        text_widget.insert(tk.END,
                            f"{start or '(open)'} → {end or '(open)'}"
                            f"   show_once={show_once}\n")
                        text_widget.insert(tk.END, f"      state:  ",
                                            'dim')
                        for label, tag in states:
                            text_widget.insert(tk.END, f"{label} ", tag)
                        text_widget.insert(tk.END, "\n\n")

            text_widget.config(state='disabled')

        def _refresh_now():
            """Trigger a fresh fetch and re-render after a brief delay."""
            try:
                self._refresh_welcome_ad()
                # Give the daemon thread ~1.5s to write the cache, then
                # re-render. The fetch is async, so this isn't perfect,
                # but it's close enough for a manual debug tool.
                win.after(1500, _render)
            except Exception as e:
                messagebox.showerror("Refresh failed", str(e), parent=win)

        def _clear_dismissed():
            """Wipe the dismissed-IDs file so all banners reappear."""
            if not messagebox.askyesno(
                    "Clear dismissed list?",
                    "Reset the dismissed-notifications list?\n\n"
                    "All banners you've dismissed with the X button "
                    "will reappear on the Welcome tab.",
                    parent=win):
                return
            try:
                if self._dismissed_path.exists():
                    self._dismissed_path.unlink()
                # Re-display from cache so the Welcome tab updates too
                if self._notif_cache_path.exists():
                    with open(self._notif_cache_path, 'r',
                              encoding='utf-8') as f:
                        self._display_notifications(json.load(f))
                _render()
            except Exception as e:
                messagebox.showerror("Clear failed", str(e), parent=win)

        # ── Button row ─────────────────────────────────────────────
        btn_row = ttk.Frame(win)
        btn_row.pack(fill='x', padx=10, pady=(0, 10))

        ttk.Button(btn_row, text="🔄 Refresh Now",
                   command=_refresh_now).pack(side='left')
        ttk.Button(btn_row, text="🗑 Clear Dismissed",
                   command=_clear_dismissed).pack(side='left', padx=(8, 0))
        ttk.Button(btn_row, text="Close",
                   command=win.destroy).pack(side='right')

        _render()

    # ════════════════════════════════════════════════════════════════════════
    # Visual setup guides — Cloudflare Tunnel + Claude.ai Connector
    # ════════════════════════════════════════════════════════════════════════

    def _open_guide_window(self, title, sections, deep_links=None,
                           extra_buttons=None, width=820, height=640):
        """Generic guide-window factory used by both Cloudflare and Claude
        connector guides.

        sections: list of (heading, body_lines) tuples — body_lines is a list
                  of strings, where strings starting with a digit + '.' are
                  rendered as numbered steps.
        deep_links: list of (label, url) tuples — rendered as buttons that
                    open in the user's default browser.
        extra_buttons: list of (label, callable) tuples — additional helper
                       buttons (e.g. "Copy Bearer Token").
        """
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry(f"{width}x{height}")

        text_widget = scrolledtext.ScrolledText(
            win, wrap=tk.WORD, font=('Arial', 10), padx=8, pady=8)
        text_widget.pack(fill='both', expand=True, padx=10, pady=(10, 6))

        # Style tags
        text_widget.tag_configure('title',
                                   font=('Arial', 12, 'bold'),
                                   foreground='#003366',
                                   spacing3=8)
        text_widget.tag_configure('heading',
                                   font=('Arial', 10, 'bold'),
                                   foreground='#004488',
                                   spacing1=10, spacing3=4)
        text_widget.tag_configure('step',
                                   font=('Arial', 10),
                                   lmargin1=20, lmargin2=40,
                                   spacing3=4)
        text_widget.tag_configure('note',
                                   font=('Arial', 9, 'italic'),
                                   foreground='#666666',
                                   lmargin1=20, lmargin2=20,
                                   spacing3=6)
        text_widget.tag_configure('mono',
                                   font=('Consolas', 9),
                                   background='#f0f0f0')
        text_widget.tag_configure('warn',
                                   font=('Arial', 9, 'bold'),
                                   foreground='#aa6600',
                                   lmargin1=20, lmargin2=20)

        # Render sections
        text_widget.insert(tk.END, f"{title}\n", 'title')
        for heading, body_lines in sections:
            text_widget.insert(tk.END, f"\n{heading}\n", 'heading')
            for line in body_lines:
                stripped = line.lstrip()
                if stripped.startswith('NOTE:'):
                    text_widget.insert(tk.END,
                        stripped[5:].lstrip() + "\n", 'note')
                elif stripped.startswith('WARN:'):
                    text_widget.insert(tk.END,
                        "⚠  " + stripped[5:].lstrip() + "\n", 'warn')
                else:
                    text_widget.insert(tk.END, line + "\n", 'step')

        text_widget.config(state='disabled')

        # Deep-link buttons row (above bottom buttons)
        if deep_links:
            link_row = ttk.Frame(win)
            link_row.pack(fill='x', padx=10, pady=(0, 4))
            ttk.Label(link_row, text="Open in browser:",
                      font=('Arial', 9, 'bold')
                      ).pack(side='left', padx=(0, 8))
            for label, url in deep_links:
                ttk.Button(link_row, text=label,
                           command=lambda u=url: webbrowser.open(u)
                           ).pack(side='left', padx=(0, 6))

        # Bottom button row (helpers + close)
        btn_row = ttk.Frame(win)
        btn_row.pack(fill='x', padx=10, pady=(4, 10))

        if extra_buttons:
            for label, cmd in extra_buttons:
                ttk.Button(btn_row, text=label,
                           command=cmd).pack(side='left', padx=(0, 6))

        ttk.Button(btn_row, text="Close",
                   command=win.destroy).pack(side='right')

        return win

    def show_cloudflare_setup_guide(self):
        """Visual guide for creating a free Cloudflare account + Named Tunnel
        and obtaining the public hostname + tunnel token to paste into the
        Settings tab."""

        sections = [
            ("Why Named Tunnels?", [
                "A Named Tunnel gives you a permanent URL like",
                "    https://ai-prowler.yourdomain.com/mcp",
                "that survives restarts. Quick Tunnel URLs change every time.",
                "",
                "NOTE: Free Cloudflare accounts and free tier tunnels are sufficient.",
                "NOTE: You will need a domain name. Cloudflare Registrar sells",
                "      domains at cost (~$10/year for .com), or you can transfer",
                "      an existing domain.",
            ]),

            ("Step 1 — Create a Cloudflare account (free)", [
                "1. Open dash.cloudflare.com (button below).",
                "2. Click 'Sign Up' and create a free account with email + password.",
                "3. Verify your email.",
            ]),

            ("Step 2 — Add or register a domain", [
                "1. After login, click 'Add a site' on the dashboard.",
                "2. Enter a domain you own — or click 'Register a domain' to buy",
                "   one from Cloudflare Registrar at cost.",
                "3. Choose the Free plan when prompted.",
                "4. If you brought an existing domain, follow Cloudflare's",
                "   instructions to update your nameservers at your registrar.",
                "   Cloudflare emails you when DNS propagates (usually <1 hour).",
                "",
                "NOTE: You can skip this step if you don't want a custom domain —",
                "      use the Quick Tunnel option in Settings instead.",
            ]),

            ("Step 3 — Open Cloudflare Zero Trust", [
                "1. From the main Cloudflare dashboard, click 'Zero Trust' in the",
                "   left sidebar (or open one.dash.cloudflare.com directly).",
                "2. If prompted, choose the Free plan and enter a team name",
                "   (any name; this is just for your dashboard).",
                "3. You may be asked for a payment method — Cloudflare Zero Trust",
                "   Free tier supports up to 50 users at $0/month, but a card",
                "   on file is required to confirm you're not a bot.",
            ]),

            ("Step 4 — Create a tunnel", [
                "1. In Zero Trust, click 'Networks' → 'Tunnels' in the left menu.",
                "2. Click 'Create a tunnel'.",
                "3. Choose connector type: 'Cloudflared'.",
                "4. Name your tunnel (e.g. 'ai-prowler-' + your name).",
                "5. Click 'Save tunnel'.",
            ]),

            ("Step 5 — Copy the tunnel token", [
                "1. On the 'Install and run a connector' screen, find the",
                "   command that looks like:",
                "       cloudflared.exe service install eyJ...long-string...",
                "2. The long string after 'install' is your TUNNEL TOKEN.",
                "3. Copy ONLY that string (not the whole command).",
                "4. Paste it into the Settings tab → 'Tunnel token' field in",
                "   AI-Prowler.",
                "",
                "WARN: Treat this token like a password. Anyone with it can",
                "      impersonate your tunnel.",
            ]),

            ("Step 6 — Configure the public hostname", [
                "1. Click 'Next' on the connector screen.",
                "2. Under 'Public Hostname', set:",
                "       Subdomain:  ai-prowler  (or any name you like)",
                "       Domain:     yourdomain.com  (the one from Step 2)",
                "       Path:       (leave blank)",
                "3. Under 'Service', set:",
                "       Type:  HTTP",
                "       URL:   localhost:8080  (or whatever port AI-Prowler",
                "                               uses — check Settings tab)",
                "4. Click 'Save tunnel'.",
                "5. Your full hostname is now: ai-prowler.yourdomain.com",
                "6. Paste this into the Settings tab → 'Public hostname' field",
                "   in AI-Prowler.",
            ]),

            ("Step 7 — Activate in AI-Prowler", [
                "1. Back in AI-Prowler Settings → Remote Access:",
                "   • Public hostname: ai-prowler.yourdomain.com",
                "   • Tunnel token:    eyJ...your-token...",
                "2. Click 'Activate' to install cloudflared as a Windows service.",
                "   (You'll see a UAC prompt — this is normal.)",
                "3. The status indicator should turn green.",
                "4. Now click 'How to Connect Claude →' to finish the setup",
                "   on Claude.ai.",
            ]),
        ]

        deep_links = [
            ("Cloudflare Dashboard",
             "https://dash.cloudflare.com/sign-up"),
            ("Zero Trust",
             "https://one.dash.cloudflare.com/"),
            ("Tunnels",
             "https://one.dash.cloudflare.com/?to=/:account/networks/tunnels"),
        ]

        extra_buttons = [
            ("📖 Next: Connect Claude.ai →",
             self.show_claude_connector_guide),
        ]

        self._open_guide_window(
            "Cloudflare Tunnel Setup Guide",
            sections, deep_links=deep_links,
            extra_buttons=extra_buttons,
            width=860, height=680)

    def show_claude_connector_guide(self):
        """Visual guide for adding the AI-Prowler MCP connector to Claude.ai
        — uses the saved tunnel hostname and bearer token from config to
        offer one-click copy."""

        # Load current config to surface the URL + token
        url = ""
        token = ""
        try:
            cfg_path = Path.home() / '.ai-prowler' / 'config.json'
            if cfg_path.exists():
                cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
                domain = cfg.get('tunnel_domain', '').strip()
                if domain:
                    # Strip protocol/path if user pasted full URL
                    domain = domain.replace('https://', '').replace(
                        'http://', '').rstrip('/')
                    url = f"https://{domain}/mcp"
                token = cfg.get('remote_token', '')
        except Exception:
            pass

        # Body that adapts based on what's configured
        url_line = url if url else "(not yet configured — see Step 1 below)"
        token_status = "✓ saved" if token else "✗ not yet set"

        sections = [
            ("Your connection details", [
                f"URL:           {url_line}",
                f"Bearer Token:  {token_status}",
                "",
                "NOTE: Use the buttons at the bottom to copy URL and token to",
                "      your clipboard right before pasting into Claude.ai.",
            ]),

            ("Step 0 — Prerequisites", [
                "Before connecting Claude, make sure:",
                "1. AI-Prowler HTTP server is running (Settings → Start HTTP Server).",
                "2. A tunnel is active — either Quick Tunnel or Named Tunnel.",
                "3. Your Bearer Token is saved (Settings → Bearer Token field).",
                "",
                "NOTE: If you haven't set up a tunnel yet, click",
                "      'Setup Cloudflare Tunnel' in Settings first.",
            ]),

            ("Step 1 — Open Claude.ai settings", [
                "1. Click 'Open Claude.ai' below — it takes you to the right page.",
                "2. Sign in with your Claude Pro account.",
                "3. Look for 'Connectors' in the left sidebar of Settings.",
                "",
                "NOTE: Claude Pro ($20/month) is required for MCP connectors.",
                "      Free Claude accounts cannot use custom connectors.",
            ]),

            ("Step 2 — Add a custom connector", [
                "1. Scroll to the bottom of the Connectors list.",
                "2. Click 'Add custom connector'  (or 'Add MCP server' depending",
                "   on the Claude.ai version).",
                "3. A dialog will open asking for connector details.",
            ]),

            ("Step 3 — Fill in the connector form", [
                "Name:           AI-Prowler",
                "Description:    My personal knowledge base",
                "MCP Server URL: (click 'Copy URL' below, then paste)",
                "",
                "When prompted for authentication:",
                "  Authentication type:  Bearer Token  (or 'API Key')",
                "  Token:                (click 'Copy Bearer Token' below,",
                "                         then paste)",
                "",
                "WARN: The token is sent to Claude's servers. This is normal",
                "      and required for Claude to authenticate with your tunnel.",
            ]),

            ("Step 4 — Save and verify", [
                "1. Click 'Save' or 'Connect'.",
                "2. Claude will attempt to connect to your tunnel.",
                "3. If successful, you'll see 'Connected' or a green indicator.",
                "4. The 22 AI-Prowler tools will be listed (search_documents,",
                "   add_and_index_directory, get_route_optimization, etc.).",
            ]),

            ("Step 5 — Test it", [
                "Open a new chat with Claude and try one of these:",
                "",
                "  • 'What documents do I have indexed in AI-Prowler?'",
                "  • 'Search my documents for [topic].'",
                "  • 'Show me the chunks containing [keyword].'",
                "",
                "Claude should respond using your local knowledge base.",
            ]),

            ("Troubleshooting", [
                "Connection fails / 401 Unauthorized:",
                "  → Bearer token mismatch. Re-copy from AI-Prowler Settings.",
                "",
                "Connection fails / 502 Bad Gateway:",
                "  → Tunnel running but HTTP server not started, or tunnel",
                "    pointing to wrong port. Check Settings → Server Status.",
                "",
                "Connection fails / DNS error:",
                "  → Named Tunnel hostname not yet propagated (wait 5 min)",
                "    or typo in hostname. For Quick Tunnel, the URL changes",
                "    every restart — re-copy it.",
                "",
                "Claude doesn't see the connector:",
                "  → MCP connectors require Claude Pro. Free accounts don't",
                "    have this feature.",
            ]),
        ]

        deep_links = [
            ("Open Claude.ai", "https://claude.ai/"),
            ("Claude Settings", "https://claude.ai/settings/connectors"),
        ]

        # Helper buttons that copy to clipboard with feedback
        def _copy_to_clipboard(text, label):
            if not text:
                messagebox.showwarning(
                    f"{label} not set",
                    f"No {label.lower()} is configured yet.\n\n"
                    "Set it up in Settings tab first.")
                return
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                self.root.update()  # required on Windows for clipboard to stick
                self.status_var.set(f"{label} copied to clipboard")
                self.root.after(3000,
                                lambda: self.status_var.set("Ready"))
            except Exception as e:
                messagebox.showerror("Copy failed", str(e))

        extra_buttons = [
            ("📋 Copy URL",
             lambda: _copy_to_clipboard(url, "URL")),
            ("📋 Copy Bearer Token",
             lambda: _copy_to_clipboard(token, "Bearer Token")),
        ]

        self._open_guide_window(
            "Connect Claude.ai to AI-Prowler",
            sections, deep_links=deep_links,
            extra_buttons=extra_buttons,
            width=860, height=680)

    def show_help_window(self, title, content):
        """Show help content in new window"""
        help_window = tk.Toplevel(self.root)
        help_window.title(title)
        help_window.geometry("800x600")
        
        # Add scrolled text widget
        text_widget = scrolledtext.ScrolledText(help_window, wrap=tk.WORD,
                                                 font=('Arial', 10))
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Insert content
        text_widget.insert('1.0', content)
        text_widget.config(state='disabled')  # Make read-only
        
        # Add close button
        close_btn = ttk.Button(help_window, text="Close", 
                              command=help_window.destroy)
        close_btn.pack(pady=5)
    
    def get_quick_start_content(self):
        """Get quick start guide content"""
        return f"""AI-PROWLER QUICK START GUIDE
Version {APP_VERSION}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ⭐  RECOMMENDED: AGENTIC RAG WITH CLAUDE DESKTOP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AI-Prowler is designed around Agentic RAG — letting Claude
actively research your documents using its full intelligence.
Claude Desktop (free) is the easiest way to get started.

STEP 1: Index Your Documents
─────────────────────────────
1. Click the "📚 Index Documents" tab
2. Click "Add Directory" and select your Documents folder
3. Check "Include Subfolders" if needed
4. Click "Start Indexing" — wait for "INDEXING COMPLETE"

What gets indexed:
  • PDFs, Word, Excel, PowerPoint
  • Text files, code files, emails (.eml, .msg, .mbox)
  • Scanned documents and images (OCR via Tesseract)
  • 65+ file types in total

Tip: Indexing is incremental — only changed files are
re-processed on subsequent runs. No need to start over.


STEP 2: Connect Claude Desktop (Primary Interface)
───────────────────────────────────────────────────
Claude Desktop connects to AI-Prowler via MCP (Model Context
Protocol) and gets 13 tools to actively research your documents.

  1. Click "🚀 Launch Claude Desktop" on this screen
     (or use Settings → Claude Desktop MCP → Auto-configure)
  2. In Claude Desktop, start a NEW conversation
  3. Ask any research question about your documents:

     "Summarize the key risks in my Q3 contracts"
     "What does my insurance policy say about flooding?"
     "Find everything related to Project Alpha"

Claude will automatically call multiple search tools, follow
leads, expand context, and synthesize a comprehensive answer.
You don't need to direct it — the agentic loop runs on its own.

  ✅ No HTTP server needed for Claude Desktop
  ✅ Works with free Claude account
  ✅ Completely local — no internet required for the connection


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📱  OPTION 2: MOBILE & WEB ACCESS (Claude.ai)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Access your knowledge base from your phone, tablet, or any
browser using Claude.ai — with the same full agentic RAG
capability as Claude Desktop.

Requirements:
  • Active Mobile Access subscription ($10/month Individual)
  • Claude Pro or Team plan on Claude.ai

Setup Steps:
  1. Go to Settings → Remote Access
  2. Enter a Bearer token (your password — make it strong)
  3. Click "▶ Start HTTP Server"
  4. Click "▶ Start Tunnel" (Cloudflare Tunnel)
  5. Open Claude.ai → Settings → Connectors → Add connector
  6. Enter your tunnel URL (e.g. https://your-tunnel.com/mcp)
  7. Authorize with your Bearer token when prompted

Then click "🌐 Open Claude.ai" on this screen to open Claude.ai
in your browser and start chatting from any device.

  ⚠  Important: The HTTP server and Cloudflare Tunnel must be
     running on your PC for Claude.ai to reach your knowledge base.

Subscription info: Help → User Guide → Section 8
Or email: david.vavro1@gmail.com


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  💬  OPTION 3: DESKTOP ASK QUESTIONS TAB (Local)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The Ask Questions tab is a standalone chat mode that works
with local Ollama models or cloud API keys — no Claude
subscription required. Best for fully offline use.

  1. Install Ollama from Settings → Browse & Install Model
     (or add an API key for ChatGPT, Gemini, etc.)
  2. Click "🔍 Ask Questions" tab
  3. Type your question and press Enter

Note: This mode does NOT use the Agentic RAG tools. It does
a single retrieval pass and sends chunks to the local model.
For best results, use Claude Desktop (Option 1 above).


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔄  KEEPING YOUR INDEX CURRENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• Click "🔄 Update Index" → "Update All" after adding files
• Or ask Claude: "Update my knowledge base" — it will call
  the update_tracked_directories() tool automatically
• Set up auto-scheduling in Settings → Schedule (runs at 2 AM)


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📞  NEED MORE HELP?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Full documentation:  Help → 📖 User Guide
MCP diagnostics:     Settings → Claude Desktop MCP → 🔬 Run MCP Diagnostics
Support email:       david.vavro1@gmail.com
"""
    
    def get_user_guide_content(self):
        """Get complete user guide content"""
        # Try to load from file first
        guide_path = Path("COMPLETE_USER_GUIDE.md")
        if guide_path.exists():
            try:
                with open(guide_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except:
                pass
        
        # Fallback to embedded content
        return """AI PROWLER - PERSONAL AI KNOWLEDGE BASE
Complete User Guide (v1.8)

For the complete guide, please open:
COMPLETE_USER_GUIDE.md

This file contains:
• What is AI Prowler and how it works
• Complete installation guide
• Detailed instructions for all features
• Model selection guide
• Troubleshooting section
• FAQs and glossary

Quick Start:
1. Index Documents tab → Browse → Select folder → Start Indexing
2. Ask Questions tab → Type question → Press Enter
3. Update Index tab → Update All (weekly)
4. Settings tab → Choose different AI models

For detailed help, open COMPLETE_USER_GUIDE.md in your text editor
or from the Help menu."""
    
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs — ORDER MATTERS: _TAB_INDEX_* constants must match insertion order
        self.create_welcome_tab()          # 0  ← Welcome / Info / Ad Space
        self.create_query_tab()            # 1  ← Ask Questions (prewarmed on switch)
        self.create_index_tab()            # 2
        self.create_update_tab()           # 3
        self.create_scan_config_tab()      # 4
        self.create_scheduling_tab()       # 5
        self.create_settings_tab()         # 6
        self.create_small_business_tab()   # 7  ← Small Business Service Tools

        # Named tab index constants — change here if tabs are ever reordered
        self._TAB_INDEX_WELCOME      = 0   # Welcome / Info / Ad Space
        self._TAB_INDEX_QUERY        = 1   # Ask Questions tab — triggers Ollama prewarm
        self._TAB_INDEX_INDEX        = 2
        self._TAB_INDEX_UPDATE       = 3
        self._TAB_INDEX_SCAN         = 4
        self._TAB_INDEX_SCHEDULE     = 5
        self._TAB_INDEX_SETTINGS     = 6
        self._TAB_INDEX_SMALL_BIZ    = 7   # Small Business Service Tools
        
        # Status bar
        self.create_status_bar()
    
    def _make_scrollable_tab(self, outer_frame):
        """Wrap outer_frame in a canvas + scrollbar and return the inner content frame.

        Uses grid layout on outer_frame so both the canvas and the scrollbar are
        anchored to the frame edges — this means they resize correctly when the
        application window is resized by the user.
        """
        # Grid the outer frame so column 0 (canvas) stretches and column 1
        # (scrollbar) stays fixed-width.
        outer_frame.columnconfigure(0, weight=1)
        outer_frame.rowconfigure(0, weight=1)

        canvas = tk.Canvas(outer_frame, highlightthickness=0)
        vsb    = ttk.Scrollbar(outer_frame, orient='vertical', command=canvas.yview)
        inner  = ttk.Frame(canvas)

        win_id = canvas.create_window((0, 0), window=inner, anchor='nw')
        canvas.configure(yscrollcommand=vsb.set)

        # Keep inner frame width locked to canvas width (fill='x' widgets expand),
        # and height to max(content, canvas) so expand=True widgets fill the
        # window when content is shorter than the visible area.
        def _sync_canvas(e, wid=win_id):
            content_h = inner.winfo_reqheight()
            new_h     = max(content_h, e.height)
            canvas.itemconfig(wid, width=e.width, height=new_h)
            canvas.configure(scrollregion=canvas.bbox('all'))

        # Update scrollregion whenever child content changes height.
        def _sync_scrollregion(e):
            content_h  = inner.winfo_reqheight()
            canvas_h   = canvas.winfo_height()
            new_h      = max(content_h, canvas_h)
            canvas.itemconfig(win_id, height=new_h)
            canvas.configure(scrollregion=canvas.bbox('all'))

        canvas.bind('<Configure>', _sync_canvas)
        inner.bind('<Configure>',  _sync_scrollregion)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')
        canvas.bind('<Enter>',  lambda e: canvas.bind_all('<MouseWheel>', _on_mousewheel))
        canvas.bind('<Leave>',  lambda e: canvas.unbind_all('<MouseWheel>'))

        # Use grid (not pack) so outer_frame's weight config takes effect.
        canvas.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        return inner

    def create_welcome_tab(self):
        """Create the Welcome / Home tab with large icon, branding, and ad space.

        Ad content is refreshed:
          - Immediately on startup (background thread)
          - Once every 24 hours while AI-Prowler is running (configurable)

        When fresh content arrives from GitHub, the Welcome tab updates
        live — no restart needed.

        Ad content loading priority:
          1. GitHub raw URL (fetched in background)
          2. Local cache (~/.ai-prowler/welcome_ad_cache.json)
          3. Local override (~/.ai-prowler/welcome_config.json)
          4. Built-in defaults
        """
        import json as _json

        welcome_frame = ttk.Frame(self.notebook)
        self.notebook.add(welcome_frame, text="🏠 Home")

        # ── Default ad content ────────────────────────────────────────────────
        self._ad_defaults = {
            'headline':  'Welcome to AI-Prowler',
            'body': (
                'Your Professional Agentic RAG Knowledge Base for Claude.\n\n'
                'AI-Prowler indexes your local documents and makes them '
                'searchable through Claude — on desktop, web, and mobile.\n\n'
                '• Index documents from any folder on your PC\n'
                '• Search with full provenance tracking\n'
                '• Connect via Claude Desktop (local) or Claude.ai (remote)\n'
                '• Smart scan skips binaries and system files automatically\n\n'
                'Get started: click the Index Docs tab to add your first folder.'
            ),
            'link_text': 'Visit AI-Prowler on GitHub',
            'link_url':  'https://github.com/dvavro/AI-Prowler',
            'footer':    'AI-Prowler — Free for personal use',
        }

        # Paths
        self._ad_cache_path = Path.home() / '.ai-prowler' / 'welcome_ad_cache.json'
        self._ad_local_path = Path.home() / '.ai-prowler' / 'welcome_config.json'
        self._ad_url = (
            "https://raw.githubusercontent.com/"
            "dvavro/ai-prowler-public/main/welcome_ad.json"
        )

        # ── Load initial ad content from cache/local/defaults ─────────────────
        ad = self._load_ad_content()

        # Write default local config if it doesn't exist
        if not self._ad_local_path.exists():
            try:
                self._ad_local_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._ad_local_path, 'w', encoding='utf-8') as f:
                    _json.dump(self._ad_defaults, f, indent=2)
            except Exception:
                pass

        # ── Build the Welcome tab layout ──────────────────────────────────────
        container = ttk.Frame(welcome_frame, padding=(30, 15))
        container.pack(fill='both', expand=True)

        # ── Large Icon — centered at top ──────────────────────────────────────
        icon_frame = ttk.Frame(container)
        icon_frame.pack(fill='x', pady=(10, 5))

        self._welcome_icon_ref = None
        try:
            _icon_path = Path(__file__).parent / 'rag_icon.ico'
            if _icon_path.exists():
                from PIL import Image, ImageTk
                img = Image.open(str(_icon_path))
                img = img.resize((256, 256), Image.LANCZOS)
                self._welcome_icon_ref = ImageTk.PhotoImage(img)
                icon_label = ttk.Label(icon_frame,
                                       image=self._welcome_icon_ref)
                icon_label.pack(anchor='center')
        except Exception:
            ttk.Label(icon_frame, text="🔍",
                      font=('Arial', 56)).pack(anchor='center')

        ttk.Separator(container, orient='horizontal').pack(fill='x', pady=(12, 12))

        # ── Notification banner area (populated by _refresh_notifications) ────
        self._notif_frame = ttk.Frame(container)
        self._notif_frame.pack(fill='x', pady=(0, 6))
        self._notif_widgets = []  # track notification widgets for clearing

        # Debug label — hidden by default, only shown if notification
        # fetch fails. Helper methods _show_notif_debug / _hide_notif_debug
        # control visibility.
        self._notif_debug_var = tk.StringVar(value="")
        self._notif_debug_label = ttk.Label(container,
                                             textvariable=self._notif_debug_var,
                                             font=('Arial', 8),
                                             foreground='red')
        # Note: NOT packed — stays hidden until _show_notif_debug() is called

        # ── Generate install_id on first launch (anonymous tracking) ──────────
        self._install_id_path = Path.home() / '.ai-prowler' / 'install_id'
        if not self._install_id_path.exists():
            try:
                import uuid, hashlib
                _raw_id = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:16]
                self._install_id_path.parent.mkdir(parents=True, exist_ok=True)
                self._install_id_path.write_text(_raw_id, encoding='utf-8')
            except Exception:
                pass

        # ── Telemetry state ───────────────────────────────────────────────────
        # tools_called_24h is incremented by MCP server on each tool call,
        # via the local counter file. Reset to 0 after each successful POST.
        self._telemetry_counter_path = (
            Path.home() / '.ai-prowler' / 'telemetry_counter.json')
        self._telemetry_last_path = (
            Path.home() / '.ai-prowler' / 'telemetry_last_success.txt')
        self._telemetry_lock_path = (
            Path.home() / '.ai-prowler' / 'telemetry_lock.txt')
        # Schedule the first heartbeat after mainloop is up. After that the
        # method reschedules itself.
        self.root.after(_TELEMETRY_FIRST_DELAY_SEC * 1000,
                        self._telemetry_tick)

        # ── Dismissed notifications tracking ──────────────────────────────────
        self._dismissed_path = Path.home() / '.ai-prowler' / 'dismissed_notifications.json'
        self._notif_cache_path = Path.home() / '.ai-prowler' / 'notifications_cache.json'
        self._notif_url = (
            "https://raw.githubusercontent.com/"
            "dvavro/ai-prowler-public/main/notifications.json"
        )

        # ── Ad / Promo content area (labels stored for live update) ───────────
        ad_frame = ttk.LabelFrame(container, text="", padding=(24, 16))
        ad_frame.pack(fill='both', expand=True)

        self._ad_headline_label = ttk.Label(ad_frame, text=ad['headline'],
                                             font=('Arial', 14, 'bold'))
        self._ad_headline_label.pack(anchor='w', pady=(0, 8))

        body_text = ad['body'].replace('\\n', '\n')
        self._ad_body_label = ttk.Label(ad_frame, text=body_text,
                                         font=('Arial', 10), wraplength=800,
                                         justify='left')
        self._ad_body_label.pack(anchor='w', fill='x', pady=(0, 10))

        self._ad_link_frame = ttk.Frame(ad_frame)
        self._ad_link_frame.pack(anchor='w', pady=(4, 0))
        if ad.get('link_url'):
            self._ad_link_btn = ttk.Button(
                self._ad_link_frame,
                text=f"🔗 {ad.get('link_text', 'Learn More')}",
                command=lambda url=ad['link_url']: webbrowser.open(url)
            )
            self._ad_link_btn.pack(side='left')
        else:
            self._ad_link_btn = None

        self._ad_footer_label = ttk.Label(container, text=ad.get('footer', ''),
                                           font=('Arial', 8), foreground='gray')
        self._ad_footer_label.pack(anchor='center', pady=(10, 0))

        # Store current ad data and link URL for updates
        self._current_ad = dict(ad)

        # ── Fetch ad + notifications from GitHub, schedule daily refresh ────
        # Defer the first fetch until after mainloop() is running. Calling
        # _refresh_welcome_ad() directly here means the daemon thread spawns
        # while the main thread is still synchronously building tabs; its
        # root.after(0, ...) callbacks can race with widget construction and
        # silently fail to deliver, leaving the Welcome tab empty until the
        # user manually triggers a refresh. Scheduling via after() guarantees
        # the call runs from the Tk event loop, after all tabs exist.
        self.root.after(150, self._refresh_welcome_ad)
        self._schedule_ad_refresh()

    def _load_ad_content(self) -> dict:
        """Load ad content from local defaults → GitHub cache (cache wins)."""
        import json as _json
        ad = dict(self._ad_defaults)

        # Load local config first (lowest priority after defaults)
        try:
            if self._ad_local_path.exists():
                with open(self._ad_local_path, 'r', encoding='utf-8') as f:
                    local_cfg = _json.load(f)
                for key in self._ad_defaults:
                    if key in local_cfg and local_cfg[key]:
                        ad[key] = local_cfg[key]
        except Exception:
            pass

        # GitHub cache overrides local config (highest priority)
        try:
            if self._ad_cache_path.exists():
                with open(self._ad_cache_path, 'r', encoding='utf-8') as f:
                    cached = _json.load(f)
                for key in self._ad_defaults:
                    if key in cached and cached[key]:
                        ad[key] = cached[key]
        except Exception:
            pass

        return ad

    # ════════════════════════════════════════════════════════════════════════
    # Telemetry — anonymous daily heartbeat
    # ════════════════════════════════════════════════════════════════════════

    def _telemetry_load_config(self):
        """Read telemetry-related settings from ~/.ai-prowler/config.json.

        Returns a dict with keys: enabled (bool), endpoint (str).
        Defaults to enabled=True and the baked-in endpoint.
        """
        cfg = {
            'enabled': True,
            'endpoint': _TELEMETRY_DEFAULT_ENDPOINT,
        }
        try:
            cfg_path = Path.home() / '.ai-prowler' / 'config.json'
            if cfg_path.exists():
                data = json.loads(cfg_path.read_text(encoding='utf-8'))
                if 'telemetry_enabled' in data:
                    cfg['enabled'] = bool(data['telemetry_enabled'])
                if data.get('telemetry_endpoint'):
                    cfg['endpoint'] = str(data['telemetry_endpoint'])
        except Exception:
            pass
        return cfg

    def _telemetry_save_config(self, *, enabled=None, endpoint=None):
        """Write enabled/endpoint into config.json. Either field optional."""
        try:
            cfg_path = Path.home() / '.ai-prowler' / 'config.json'
            cfg_path.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            if cfg_path.exists():
                try:
                    data = json.loads(cfg_path.read_text(encoding='utf-8'))
                except Exception:
                    data = {}
            if enabled is not None:
                data['telemetry_enabled'] = bool(enabled)
            if endpoint is not None:
                data['telemetry_endpoint'] = str(endpoint)
            cfg_path.write_text(
                json.dumps(data, indent=2), encoding='utf-8')
        except Exception:
            pass

    def _telemetry_get_counter(self):
        """Return per-tool call counter as a dict {tool_name: count}.
        Handles v2 (dict) format and the legacy v1 (single int) format —
        v1 data isn't recoverable as per-tool buckets so it's discarded."""
        try:
            if self._telemetry_counter_path.exists():
                d = json.loads(
                    self._telemetry_counter_path.read_text(encoding='utf-8'))
                if isinstance(d, dict):
                    tc = d.get('tool_calls')
                    if isinstance(tc, dict):
                        out = {}
                        for k, v in tc.items():
                            try:
                                out[str(k)] = int(v)
                            except (ValueError, TypeError):
                                pass
                        return out
        except Exception:
            pass
        return {}

    def _telemetry_get_counter_total(self):
        """Sum of all per-tool counters (used for the legacy
        tools_called_24h integer field in the heartbeat payload)."""
        try:
            return sum(self._telemetry_get_counter().values())
        except Exception:
            return 0

    def _telemetry_reset_counter(self):
        """Reset counter (clear the per-tool dict) after a successful
        heartbeat."""
        try:
            self._telemetry_counter_path.parent.mkdir(
                parents=True, exist_ok=True)
            self._telemetry_counter_path.write_text(
                json.dumps({'tool_calls': {}}), encoding='utf-8')
        except Exception:
            pass

    def _telemetry_count_chunks(self):
        """Best-effort count of chunks indexed in the active collection.
        Returns 0 if anything fails — never raises into the heartbeat path."""
        try:
            if hasattr(self, 'collection') and self.collection is not None:
                return int(self.collection.count())
        except Exception:
            pass
        return 0

    def _telemetry_compose_payload(self):
        """Build the heartbeat dict. No PII. Returns None if install_id
        can't be read (something is wrong with the user's home dir)."""
        try:
            install_id = self._install_id_path.read_text(
                encoding='utf-8').strip()
        except Exception:
            return None
        if not install_id:
            return None

        # OS string — match the worker's allowed prefixes
        os_str = "unknown"
        try:
            import platform
            sys_name = platform.system()
            release = platform.release()
            if sys_name and release:
                os_str = f"{sys_name}-{release}"[:50]
        except Exception:
            pass

        tool_calls = self._telemetry_get_counter()
        # Total is derived as sum of per-tool counts. The Worker still
        # accepts tools_called_24h as a flat integer for backwards
        # compatibility with the existing aggregations.
        total = sum(tool_calls.values()) if tool_calls else 0

        return {
            'install_id': install_id,
            'version': APP_VERSION,
            'edition': 'home',
            'os': os_str,
            'chunks_indexed': self._telemetry_count_chunks(),
            'tools_called_24h': total,
            # New: per-tool breakdown (v2 schema)
            'tool_calls': tool_calls,
        }

    def _telemetry_tick(self):
        """Tk-thread entry point. Decides whether to fire a heartbeat right
        now, fires it on a daemon thread, and reschedules itself."""
        try:
            cfg = self._telemetry_load_config()
            if not cfg['enabled']:
                # Honoured immediately. Reschedule a check in case the user
                # toggles it back on later.
                self.root.after(_TELEMETRY_HEARTBEAT_INTERVAL_SEC * 1000,
                                self._telemetry_tick)
                return

            # Cheap dedup — multiple AI-Prowler instances running on the
            # same machine shouldn't all phone home. Whoever wins the
            # 60-second lock window goes first.
            if self._telemetry_lock_active():
                self.root.after(_TELEMETRY_RETRY_DELAY_SEC * 1000,
                                self._telemetry_tick)
                return

            payload = self._telemetry_compose_payload()
            if payload is None:
                self.root.after(_TELEMETRY_RETRY_DELAY_SEC * 1000,
                                self._telemetry_tick)
                return

            threading.Thread(
                target=self._telemetry_send,
                args=(payload, cfg['endpoint']),
                daemon=True
            ).start()
        except Exception as e:
            print(f"[telemetry] tick error: {e}", flush=True)
        finally:
            # Always reschedule, even if we fired one.
            self.root.after(_TELEMETRY_HEARTBEAT_INTERVAL_SEC * 1000,
                            self._telemetry_tick)

    def _telemetry_lock_active(self):
        """Return True if another instance phoned home in the last 60s
        (prevents thundering-herd from multiple GUIs on the same box)."""
        try:
            if self._telemetry_lock_path.exists():
                ts = float(
                    self._telemetry_lock_path.read_text(encoding='utf-8'))
                return (time.time() - ts) < 60
        except Exception:
            pass
        return False

    def _telemetry_set_lock(self):
        try:
            self._telemetry_lock_path.parent.mkdir(
                parents=True, exist_ok=True)
            self._telemetry_lock_path.write_text(
                str(time.time()), encoding='utf-8')
        except Exception:
            pass

    def _telemetry_send(self, payload, endpoint, force=False):
        """Daemon-thread network call. Failure is silent — telemetry must
        never be visible to the user as a problem.

        If force=True, append ?force=true and an admin bearer header to
        bypass the Worker's 12h throttle. The bearer must match the
        Worker's ADMIN_TOKEN. The token comes from
        ~/.ai-prowler/config.json under 'telemetry_admin_token' if set.
        Without a valid token, force=true requests are rejected (401)
        and we fall through silently — no harm done.
        """
        import urllib.request, urllib.error
        self._telemetry_set_lock()
        url = endpoint.rstrip('/') + '/heartbeat'
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'AI-Prowler/{APP_VERSION}',
        }

        if force:
            url = url + '?force=true'
            # Pull admin token from config.json if available
            try:
                cfg_path = Path.home() / '.ai-prowler' / 'config.json'
                if cfg_path.exists():
                    cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
                    tok = cfg.get('telemetry_admin_token', '')
                    if tok:
                        headers['Authorization'] = f'Bearer {tok}'
            except Exception:
                pass

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode('utf-8'),
                headers=headers,
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode('utf-8', errors='replace')
                # Parse the response so we can distinguish "row written"
                # from "throttled, ignored". We only reset the local
                # counter if the row was actually written — otherwise the
                # tool counts would be lost without ever reaching D1.
                throttled = False
                try:
                    data = json.loads(raw)
                    throttled = bool(data.get('throttled', False))
                except Exception:
                    pass

                if resp.status == 200 and not throttled:
                    self._telemetry_reset_counter()
                    try:
                        self._telemetry_last_path.write_text(
                            datetime.utcnow().isoformat() + 'Z',
                            encoding='utf-8')
                    except Exception:
                        pass
                    print(f"[telemetry] heartbeat written: {url}",
                          flush=True)
                elif resp.status == 200 and throttled:
                    # Worker accepted the request but didn't write — local
                    # counter stays intact so tool counts will be sent on
                    # the next non-throttled heartbeat.
                    print(f"[telemetry] heartbeat throttled (12h window) "
                          f"— counter preserved", flush=True)
        except urllib.error.HTTPError as e:
            print(f"[telemetry] HTTP {e.code}: {e.reason}", flush=True)
        except Exception as e:
            print(f"[telemetry] send failed: "
                  f"{type(e).__name__}: {e}", flush=True)

    def _show_notif_debug(self, msg: str):
        """Show the red notification debug label with the given message.
        Called only when something goes wrong with notification fetch."""
        try:
            self._notif_debug_var.set(msg)
            # pack_info() returns {} if not currently packed
            if not self._notif_debug_label.pack_info():
                self._notif_debug_label.pack(anchor='w', pady=(0, 4))
        except Exception:
            pass

    def _hide_notif_debug(self):
        """Hide the debug label (used when fetch succeeds)."""
        try:
            self._notif_debug_label.pack_forget()
            self._notif_debug_var.set("")
        except Exception:
            pass

    def _refresh_welcome_ad(self):
        """Fetch latest ad AND notifications from GitHub in one thread."""

        def _fetch_and_update():
            import urllib.request
            import traceback
            try:
                # ── Fetch welcome ad ──────────────────────────────
                try:
                    req = urllib.request.Request(
                        self._ad_url,
                        headers={
                            "User-Agent": "AI-Prowler/6.0",
                            "Cache-Control": "no-cache",
                        }
                    )
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        raw = resp.read().decode("utf-8")
                        data = json.loads(raw)

                    self._ad_cache_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(self._ad_cache_path, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2)

                    self.root.after(0, self._update_welcome_labels, data)
                except Exception as ad_err:
                    print(f"[notif] ad fetch failed: "
                          f"{type(ad_err).__name__}: {ad_err}", flush=True)

                # ── Fetch notifications (same thread, same urllib) ────
                try:
                    req2 = urllib.request.Request(
                        self._notif_url,
                        headers={
                            "User-Agent": "AI-Prowler/6.0",
                            "Cache-Control": "no-cache",
                        }
                    )
                    with urllib.request.urlopen(req2, timeout=10) as resp2:
                        raw2 = resp2.read().decode("utf-8")
                        notif_data = json.loads(raw2)

                    self._notif_cache_path.parent.mkdir(
                        parents=True, exist_ok=True)
                    with open(self._notif_cache_path, 'w',
                              encoding='utf-8') as f:
                        json.dump(notif_data, f, indent=2)

                    try:
                        self._check_for_update(notif_data)
                    except Exception:
                        pass

                    n = len(notif_data.get('notifications', []))
                    print(f"[notif] {n} notifications fetched OK", flush=True)
                    # Success — make sure the debug label stays hidden
                    self.root.after(0, self._hide_notif_debug)
                    self.root.after(0, self._display_notifications, notif_data)
                    return
                except Exception as fetch_err:
                    err_msg = f"{type(fetch_err).__name__}: {fetch_err}"
                    print(f"[notif] fetch failed: {err_msg}", flush=True)
                    # Surface the error on-screen so the user can see what's wrong
                    self.root.after(0, self._show_notif_debug,
                                    f"[Notifications: {err_msg}]")

                # ── Fallback: try cached notifications ────────────────
                try:
                    if self._notif_cache_path.exists():
                        with open(self._notif_cache_path, 'r',
                                  encoding='utf-8') as f:
                            notif_data = json.load(f)
                        self.root.after(0, self._display_notifications,
                                        notif_data)
                        self.root.after(0, self._show_notif_debug,
                                        "[Notifications: using cache]")
                        return
                except Exception as cache_err:
                    print(f"[notif] cache read failed: "
                          f"{type(cache_err).__name__}: {cache_err}",
                          flush=True)

                self.root.after(0, self._show_notif_debug,
                                "[Notifications: fetch failed, no cache]")

            except Exception as outer:
                # Catches early crashes (missing attributes, etc.) so the
                # daemon thread doesn't die silently.
                traceback.print_exc()
                msg = f"{type(outer).__name__}: {outer}"
                try:
                    self.root.after(0, self._show_notif_debug,
                                    f"[Notifications: CRASH {msg}]")
                except Exception:
                    pass

        threading.Thread(target=_fetch_and_update, daemon=True).start()

    def _check_for_update(self, notif_data):
        """Check if a newer version is available and offer to download."""
        latest = notif_data.get("latest_version", "")
        update_url = notif_data.get("update_url", "")
        update_notes = notif_data.get("update_notes", "")

        if not latest or not update_url:
            return

        # Compare versions — try packaging.version first, fall back to
        # simple tuple comparison
        is_newer = False
        try:
            from packaging.version import Version
            is_newer = Version(latest) > Version(APP_VERSION)
        except ImportError:
            # packaging not installed — compare as tuples of ints
            try:
                _latest = tuple(int(x) for x in latest.split('.'))
                _current = tuple(int(x) for x in APP_VERSION.split('.'))
                is_newer = _latest > _current
            except (ValueError, AttributeError):
                pass

        if is_newer:
            self.root.after(0, self._show_update_banner,
                            latest, update_url, update_notes)

    def _show_update_banner(self, version, url, notes):
        """Display an update available banner at the top of notifications."""
        update_frame = tk.Frame(self._notif_frame, bg='#d4edda',
                                relief='ridge', bd=1)
        update_frame.pack(fill='x', pady=(0, 4))

        tk.Label(update_frame,
                 text=f"🆕 AI-Prowler™ v{version} is available!",
                 bg='#d4edda', fg='#155724',
                 font=('Arial', 10, 'bold')).pack(side='left', padx=(10, 6),
                                                    pady=6)
        if notes:
            tk.Label(update_frame, text=notes, bg='#d4edda', fg='#155724',
                     font=('Arial', 9)).pack(side='left', padx=(0, 10), pady=6)

        ttk.Button(update_frame, text="📥 Download Update",
                   command=lambda u=url: self._download_update(u, version)
                   ).pack(side='right', padx=(6, 10), pady=4)
        ttk.Button(update_frame, text="🔗 View Release",
                   command=lambda u=url: webbrowser.open(u)
                   ).pack(side='right', padx=(0, 4), pady=4)

        self._notif_widgets.append(update_frame)

    def _download_update(self, url, version):
        """Download update files from GitHub release and stage them for install.

        Files are downloaded to %LOCALAPPDATA%/AI-Prowler/pending_update/.
        A flag file update_ready.txt is written when complete.
        On next launch, RAG_RUN.bat applies the update before starting.
        """
        import json as _json

        staging_dir = Path.home().parent.parent / 'AppData' / 'Local' / 'AI-Prowler' / 'pending_update'
        # Use the proper LOCALAPPDATA path
        _local_app = os.environ.get('LOCALAPPDATA',
                                     str(Path.home() / 'AppData' / 'Local'))
        staging_dir = Path(_local_app) / 'AI-Prowler' / 'pending_update'
        flag_file = Path(_local_app) / 'AI-Prowler' / 'update_ready.txt'

        answer = messagebox.askyesno(
            "Download Update",
            f"AI-Prowler™ v{version} is available.\n\n"
            f"Download now? The update will be applied\n"
            f"automatically the next time you start AI-Prowler."
        )
        if not answer:
            return

        def _do_download():
            try:
                self.status_var.set(f"Downloading AI-Prowler v{version}...")

                # For GitHub releases, the URL points to the release page.
                # We need to fetch the release API to get asset download URLs.
                # For simplicity, download the source files directly from the
                # repo's main branch (same files that are in the release).
                _base = ("https://raw.githubusercontent.com/"
                         "dvavro/AI-Prowler/main/")
                _files = [
                    'rag_gui.py',
                    'rag_preprocessor.py',
                    'ai_prowler_mcp.py',
                    'RAG_RUN.bat',
                    'mcp_diagnostics.py',
                ]

                staging_dir.mkdir(parents=True, exist_ok=True)

                import urllib.request
                downloaded = 0
                for fname in _files:
                    try:
                        _url = f"{_base}{fname}"
                        req = urllib.request.Request(
                            _url,
                            headers={"User-Agent": "AI-Prowler/6.0"})
                        with urllib.request.urlopen(req, timeout=30) as resp:
                            content = resp.read()
                        out_path = staging_dir / fname
                        out_path.write_bytes(content)
                        downloaded += 1
                        print(f"[UPDATE] Downloaded: {fname}")
                    except Exception as exc:
                        print(f"[UPDATE] Failed to download {fname}: {exc}")

                if downloaded > 0:
                    # Write the flag file so RAG_RUN.bat knows to apply
                    flag_file.write_text(
                        f"AI-Prowler update v{version}\n"
                        f"Downloaded: {downloaded} files\n"
                        f"Date: {datetime.now().isoformat()}\n",
                        encoding='utf-8'
                    )
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Update Downloaded",
                        f"AI-Prowler™ v{version} downloaded successfully.\n\n"
                        f"{downloaded} file(s) staged for install.\n\n"
                        f"The update will be applied automatically\n"
                        f"the next time you start AI-Prowler.\n\n"
                        f"Go to File → Exit to restart now."
                    ))
                    self.root.after(0, lambda: self.status_var.set(
                        f"✅ Update v{version} ready — restart to apply"))
                else:
                    self.root.after(0, lambda: messagebox.showwarning(
                        "Download Failed",
                        "No files could be downloaded.\n"
                        "Check your internet connection and try again."
                    ))
                    self.root.after(0, lambda: self.status_var.set("Ready"))

            except Exception as exc:
                print(f"[UPDATE] Download error: {exc}")
                self.root.after(0, lambda: self.status_var.set("Ready"))

        threading.Thread(target=_do_download, daemon=True).start()

    def _display_notifications(self, data):
        """Display active notification banners on the Welcome tab."""
        import json as _json

        # Load dismissed notifications
        dismissed = set()
        try:
            if self._dismissed_path.exists():
                dismissed = set(_json.loads(
                    self._dismissed_path.read_text(encoding='utf-8')))
        except Exception:
            pass

        # Clear existing notification widgets
        for w in self._notif_widgets:
            try:
                w.destroy()
            except Exception:
                pass
        self._notif_widgets.clear()

        notifications = data.get('notifications', [])
        today = datetime.now().strftime('%Y-%m-%d')

        shown_count = 0
        skipped_reasons = []

        for notif in notifications:
            nid = notif.get('id', '')
            if not nid:
                skipped_reasons.append("no-id")
                continue

            # Skip dismissed show_once notifications
            if notif.get('show_once') and nid in dismissed:
                skipped_reasons.append(f"{nid}:dismissed")
                continue

            # Check date range
            # Accept both naming conventions: start_date/end_date (current
            # notifications.json schema) and show_after/show_until (legacy).
            # Whichever is set, use it; if both are set, start_date wins.
            show_after = (notif.get('start_date', '')
                          or notif.get('show_after', ''))
            show_until = (notif.get('end_date', '')
                          or notif.get('show_until', ''))
            if show_after and today < show_after:
                skipped_reasons.append(
                    f"{nid}:before-start({show_after})")
                continue
            if show_until and today > show_until:
                skipped_reasons.append(
                    f"{nid}:after-end({show_until})")
                continue

            # Determine banner color based on type
            ntype = notif.get('type', 'info')
            priority = notif.get('priority', 'normal')
            if ntype == 'upsell':
                bg, fg = '#cce5ff', '#004085'
            elif ntype == 'release':
                bg, fg = '#d4edda', '#155724'
            elif priority == 'high':
                bg, fg = '#fff3cd', '#856404'
            else:
                bg, fg = '#e2e3e5', '#383d41'

            # Build banner
            banner = tk.Frame(self._notif_frame, bg=bg, relief='ridge', bd=1)
            banner.pack(fill='x', pady=(0, 4))

            title = notif.get('title', '')
            body = notif.get('body', '')
            link_text = notif.get('link_text', '')
            link_url = notif.get('link_url', '')

            tk.Label(banner, text=f"📢 {title}", bg=bg, fg=fg,
                     font=('Arial', 9, 'bold')).pack(side='left',
                                                       padx=(10, 6), pady=4)
            if body:
                tk.Label(banner, text=body, bg=bg, fg=fg,
                         font=('Arial', 8)).pack(side='left',
                                                   padx=(0, 10), pady=4)

            if link_url:
                ttk.Button(banner, text=f"🔗 {link_text or 'Learn More'}",
                           command=lambda u=link_url: webbrowser.open(u)
                           ).pack(side='right', padx=(0, 10), pady=2)

            # Dismiss button for show_once notifications
            if notif.get('show_once'):
                def _dismiss(n_id=nid, b=banner):
                    b.destroy()
                    self._notif_widgets.remove(b)
                    dismissed.add(n_id)
                    try:
                        self._dismissed_path.parent.mkdir(
                            parents=True, exist_ok=True)
                        self._dismissed_path.write_text(
                            _json.dumps(list(dismissed)), encoding='utf-8')
                    except Exception:
                        pass

                ttk.Button(banner, text="✕",
                           command=_dismiss, width=3
                           ).pack(side='right', padx=(0, 4), pady=2)

            self._notif_widgets.append(banner)
            shown_count += 1

        # Debug summary — to console only, not on-screen
        print(
            f"[notif] {len(notifications)} total, {shown_count} shown, "
            f"{len(skipped_reasons)} skipped: "
            f"{', '.join(skipped_reasons) or 'none'}  "
            f"today={today}  dismissed={list(dismissed)}",
            flush=True
        )

    def _update_welcome_labels(self, ad: dict):
        """Update the Welcome tab labels with new ad content (runs on main thread)."""
        try:
            if ad.get('headline'):
                self._ad_headline_label.config(text=ad['headline'])

            if ad.get('body'):
                body_text = ad['body'].replace('\\n', '\n')
                self._ad_body_label.config(text=body_text)

            # Update link button
            if ad.get('link_url'):
                # Remove old button if it exists
                if self._ad_link_btn:
                    self._ad_link_btn.destroy()
                url = ad['link_url']
                self._ad_link_btn = ttk.Button(
                    self._ad_link_frame,
                    text=f"🔗 {ad.get('link_text', 'Learn More')}",
                    command=lambda u=url: webbrowser.open(u)
                )
                self._ad_link_btn.pack(side='left')

            if ad.get('footer'):
                self._ad_footer_label.config(text=ad['footer'])

            self._current_ad = dict(ad)
        except Exception:
            pass  # GUI widget may have been destroyed during shutdown

    def _schedule_ad_refresh(self):
        """Schedule the next ad refresh — every 24 hours (86,400,000 ms)."""
        _REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000  # 24 hours in milliseconds
        try:
            self.root.after(_REFRESH_INTERVAL_MS, self._ad_refresh_tick)
        except Exception:
            pass

    def _ad_refresh_tick(self):
        """Called by the timer — refresh ad + notifications and reschedule."""
        self._refresh_welcome_ad()
        self._schedule_ad_refresh()

    def create_index_tab(self):
        """Create indexing tab with multi-directory queue and smart scan mode."""
        index_frame = ttk.Frame(self.notebook)
        self.notebook.add(index_frame, text="📚 Index Docs")
        f = self._make_scrollable_tab(index_frame)

        # Title
        ttk.Label(f, text="Index Your Documents",
                  font=('Arial', 16, 'bold')).pack(pady=10)

        # ── Directory queue ───────────────────────────────────────────────────
        queue_frame = ttk.LabelFrame(f, text="Directory Queue", padding=10)
        queue_frame.pack(fill='x', padx=20, pady=(0, 5))

        # Entry row — manual path entry + multi-select browse buttons
        entry_row = ttk.Frame(queue_frame)
        entry_row.pack(fill='x', pady=(0, 6))

        self.index_dir_var = tk.StringVar()
        dir_entry = ttk.Entry(entry_row, textvariable=self.index_dir_var, font=('Arial', 10))
        dir_entry.pack(side='left', fill='x', expand=True, padx=(0, 6))
        dir_entry.bind('<Return>', lambda e: self._queue_add_directory())

        # Browse buttons — two clear options, no dropdown menu needed
        ttk.Button(entry_row, text="📂 Browse Files...",
                   command=self.browse_all).pack(side='left', padx=(0, 4))
        ttk.Button(entry_row, text="📁 Add Folder...",
                   command=self.browse_folder_single).pack(side='left', padx=(0, 6))
        
        ttk.Button(entry_row, text="➕ Add to Queue",
                   command=self._queue_add_directory).pack(side='left')

        # Hint label
        hint_label = ttk.Label(queue_frame, 
                              text="💡 Type folder path above, or use Browse for files/folders",
                              font=('Arial', 8), foreground='gray')
        hint_label.pack(anchor='w', pady=(2, 6))

        # Queue listbox
        list_row = ttk.Frame(queue_frame)
        list_row.pack(fill='x')

        self.queue_listbox = tk.Listbox(list_row, height=5, font=('Courier', 9),
                                        selectmode=tk.SINGLE, activestyle='dotbox')
        queue_scroll = ttk.Scrollbar(list_row, orient='vertical',
                                     command=self.queue_listbox.yview)
        self.queue_listbox.configure(yscrollcommand=queue_scroll.set)
        self.queue_listbox.pack(side='left', fill='x', expand=True)
        queue_scroll.pack(side='left', fill='y')

        # Queue control buttons
        qbtn_row = ttk.Frame(queue_frame)
        qbtn_row.pack(fill='x', pady=(6, 0))

        ttk.Button(qbtn_row, text="❌ Remove Selected",
                   command=self._queue_remove_selected).pack(side='left', padx=(0, 6))
        ttk.Button(qbtn_row, text="🗑 Clear Queue",
                   command=self._queue_clear).pack(side='left', padx=(0, 20))

        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(qbtn_row, text="Include subdirectories",
                        variable=self.recursive_var).pack(side='left')

        self.queue_count_var = tk.StringVar(value="Queue: 0 directories")
        ttk.Label(qbtn_row, textvariable=self.queue_count_var,
                  font=('Arial', 9), foreground='gray').pack(side='right')

        # ── Options ───────────────────────────────────────────────────────────
        opt_frame = ttk.LabelFrame(f, text="Options", padding=(10, 6))
        opt_frame.pack(fill='x', padx=20, pady=(0, 5))

        self.scan_mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame,
                        text="Smart scan — skip binaries, executables and system files  "
                             "(recommended)",
                        variable=self.scan_mode_var).pack(anchor='w')


        # ── Action buttons ────────────────────────────────────────────────────
        btn_row = ttk.Frame(f)
        btn_row.pack(pady=8)

        self.index_start_btn = ttk.Button(btn_row, text="▶ Start Indexing Queue",
                                          command=self.start_indexing,
                                          style='Accent.TButton')
        self.index_start_btn.pack(side='left', padx=(0, 6))

        self.index_pause_btn = ttk.Button(btn_row, text="⏸ Pause",
                                          command=self._index_pause_resume,
                                          state='disabled')
        self.index_pause_btn.pack(side='left', padx=(0, 6))

        self.index_stop_btn = ttk.Button(btn_row, text="⏹ Stop & Save Position",
                                         command=self._index_stop,
                                         state='disabled')
        self.index_stop_btn.pack(side='left', padx=(0, 16))

        self.index_scan_btn = ttk.Button(btn_row, text="🔍 Scan Queue",
                                         command=self._run_prescan)
        self.index_scan_btn.pack(side='left')

        # Clarify the difference between Pause and Stop for the user
        ttk.Label(f,
                  text="⏸ Pause = suspend instantly, click again to resume  |  "
                       "⏹ Stop = save position & exit — use ▶ Resume Indexing to continue later",
                  font=('Arial', 8), foreground='gray').pack(anchor='w', padx=20, pady=(0, 4))

        # Progress
        prog_row = ttk.Frame(f)
        prog_row.pack(fill='x', padx=20, pady=(0, 4))

        self.index_progress = ttk.Progressbar(prog_row, mode='indeterminate')
        self.index_progress.pack(side='left', fill='x', expand=True)

        self.index_elapsed_var = tk.StringVar(value="")
        ttk.Label(prog_row, textvariable=self.index_elapsed_var,
                  font=('Arial', 9), foreground='gray',
                  width=14, anchor='e').pack(side='right', padx=(8, 0))

        self.index_progress_var = tk.StringVar(value="")
        ttk.Label(prog_row, textvariable=self.index_progress_var,
                  font=('Arial', 9), foreground='gray',
                  width=32, anchor='e').pack(side='right', padx=(8, 0))

        # Output — fill='both' + expand=True so it grows when window is resized
        ttk.Label(f, text="Output:").pack(anchor='w', padx=20)
        self.index_output = scrolledtext.ScrolledText(f, height=14,
                                                      wrap=tk.WORD)
        self.index_output.pack(fill='both', expand=True, padx=20, pady=(0, 10))
    
    def create_query_tab(self):
        """Create query tab — fully scrollable pane."""
        # ── Outer tab frame holds the canvas + scrollbar ──────────────────────
        outer = ttk.Frame(self.notebook)
        self.notebook.add(outer, text="🔍 Ask Questions")

        vscroll = ttk.Scrollbar(outer, orient='vertical')
        vscroll.pack(side='right', fill='y')

        self._query_canvas = tk.Canvas(outer, highlightthickness=0,
                                       yscrollcommand=vscroll.set)
        self._query_canvas.pack(side='left', fill='both', expand=True)
        vscroll.configure(command=self._query_canvas.yview)

        # Inner frame — all content lives here
        query_frame = ttk.Frame(self._query_canvas)
        _qf_win = self._query_canvas.create_window((0, 0), window=query_frame,
                                                    anchor='nw')

        # Keep inner frame width equal to canvas width
        def _on_canvas_resize(e):
            self._query_canvas.itemconfig(_qf_win, width=e.width)
        self._query_canvas.bind('<Configure>', _on_canvas_resize)

        # Update scrollregion whenever inner content changes size
        def _on_frame_resize(e):
            self._query_canvas.configure(
                scrollregion=self._query_canvas.bbox('all'))
        query_frame.bind('<Configure>', _on_frame_resize)

        # Mouse-wheel scrolling (Windows & macOS)
        # Use bind_all so scrolling works wherever the cursor is on this tab,
        # consistent with all other tabs. The answer box manages its own
        # internal scroll via Enter/Leave bindings below.
        def _on_mousewheel(e):
            self._query_canvas.yview_scroll(int(-1 * (e.delta / 120)), 'units')
        self._query_canvas.bind('<Enter>',
            lambda e: self._query_canvas.bind_all('<MouseWheel>', _on_mousewheel))
        self._query_canvas.bind('<Leave>',
            lambda e: self._query_canvas.unbind_all('<MouseWheel>'))
        self._query_scroll_cmd = _on_mousewheel

        # Title
        ttk.Label(query_frame, text="Ask Your AI Questions",
                  font=('Arial', 16, 'bold')).pack(pady=10)

        # ── Recommended: Claude Desktop Agentic RAG banner ────────────────────
        _claude_banner = tk.Frame(query_frame, bg='#0f3460',
                                  highlightthickness=1,
                                  highlightbackground='#1a5276')
        _claude_banner.pack(fill='x', padx=20, pady=(0, 8))

        _banner_inner = tk.Frame(_claude_banner, bg='#0f3460')
        _banner_inner.pack(fill='x', padx=14, pady=10)

        # Left side — star badge + text
        _badge_col = tk.Frame(_banner_inner, bg='#0f3460')
        _badge_col.pack(side='left', fill='y')
        tk.Label(_badge_col, text="⭐ RECOMMENDED",
                 bg='#1a5c9a', fg='#ffffff',
                 font=('Arial', 7, 'bold'),
                 padx=6, pady=2).pack(anchor='w')

        _text_col = tk.Frame(_banner_inner, bg='#0f3460')
        _text_col.pack(side='left', fill='both', expand=True, padx=(10, 0))
        tk.Label(_text_col,
                 text="AI Agent Smart Guided Questions & Answers",
                 bg='#0f3460', fg='#ffffff',
                 font=('Arial', 11, 'bold'),
                 anchor='w').pack(anchor='w')
        tk.Label(_text_col,
                 text="Claude Desktop Uses all AI-Prowler tools to actively research your "
                      "knowledge base — multiple searches, follow-up queries, and full document "
                      "reading — producing far superior answers compared to the basic Ask tab below.",
                 bg='#0f3460', fg='#aaccee',
                 font=('Arial', 8),
                 wraplength=520, justify='left',
                 anchor='w').pack(anchor='w', pady=(2, 0))

        # Right side — Launch button
        def _launch_claude_desktop():
            """Launch Claude Desktop using confirmed working AUMID command."""
            if sys.platform == 'win32':
                try:
                    # Confirmed working command on this machine:
                    # start shell:AppsFolder\Claude_pzs8sxrjxfjjc!Claude
                    # Run via cmd so 'start' shell command works correctly
                    subprocess.Popen(
                        ['cmd', '/C', 'start',
                         'shell:AppsFolder\\Claude_pzs8sxrjxfjjc!Claude'],
                        creationflags=subprocess.CREATE_NO_WINDOW)
                    self.status_var.set("Claude Desktop launched")
                    return
                except Exception:
                    pass

                # Fallback: PowerShell dynamic lookup (works after Claude updates)
                try:
                    ps = (
                        '$pkg = Get-AppxPackage | '
                        'Where-Object {$_.Name -like "*Claude*"} | '
                        'Select-Object -First 1; '
                        'if ($pkg) { '
                        '  $xml = [xml](Get-Content '
                        '    (Join-Path $pkg.InstallLocation "AppxManifest.xml")); '
                        '  $id = $xml.Package.Applications.Application[0].Id; '
                        '  Start-Process ('
                        '    "shell:AppsFolder\\" + $pkg.PackageFamilyName + "!" + $id); '
                        '  exit 0 } else { exit 1 }'
                    )
                    result = subprocess.run(
                        ['powershell', '-NoProfile', '-WindowStyle', 'Hidden',
                         '-Command', ps],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10)
                    if result.returncode == 0:
                        self.status_var.set("Claude Desktop launched")
                        return
                except Exception:
                    pass

                messagebox.showerror(
                    "Could Not Launch Claude Desktop",
                    "Claude Desktop could not be found on this machine.\n\n"
                    "Click '⬇ Download Claude Desktop' to install it.")

            elif sys.platform == 'darwin':
                try:
                    subprocess.Popen(['open', '-a', 'Claude'])
                    self.status_var.set("Claude Desktop launched")
                except Exception:
                    messagebox.showerror("Not Found",
                        "Claude Desktop not found.\n"
                        "Click '⬇ Download Claude Desktop' to install it.")

        def _download_claude_desktop():
            """Open the Claude Desktop download page in the browser."""
            import webbrowser as _wb
            _wb.open('https://claude.ai/download')
            self.status_var.set("Browser opened — claude.ai/download")


        # Right side buttons — stacked vertically
        _btn_col = tk.Frame(_banner_inner, bg='#0f3460')
        _btn_col.pack(side='right', padx=(12, 0))

        tk.Button(_btn_col,
                  text="🚀  Launch Claude Desktop",
                  bg='#2980b9', fg='white',
                  activebackground='#3498db', activeforeground='white',
                  font=('Arial', 10, 'bold'),
                  relief='flat', padx=16, pady=5,
                  cursor='hand2',
                  command=_launch_claude_desktop).pack(fill='x', pady=(0, 4))

        def _open_claude_ai_web():
            """Open Claude.ai in the default browser (HTTP / mobile access)."""
            import webbrowser as _wb
            _wb.open('https://claude.ai')
            self.status_var.set("Browser opened — claude.ai")

        tk.Button(_btn_col,
                  text="🌐  Open Claude.ai (Web / Mobile)",
                  bg='#1a7a4a', fg='white',
                  activebackground='#239c5e', activeforeground='white',
                  font=('Arial', 9, 'bold'),
                  relief='flat', padx=16, pady=4,
                  cursor='hand2',
                  command=_open_claude_ai_web).pack(fill='x', pady=(0, 4))

        tk.Button(_btn_col,
                  text="⬇  Download Claude Desktop",
                  bg='#1a5276', fg='#aaccee',
                  activebackground='#21618c', activeforeground='white',
                  font=('Arial', 8),
                  relief='flat', padx=16, pady=3,
                  cursor='hand2',
                  command=_download_claude_desktop).pack(fill='x')

        # Divider under the banner
        ttk.Separator(query_frame, orient='horizontal').pack(
            fill='x', padx=20, pady=(0, 6))
        question_frame = ttk.LabelFrame(query_frame, text="Your Question", padding=10)
        question_frame.pack(fill='x', padx=20, pady=10)

        text_frame = ttk.Frame(question_frame)
        text_frame.pack(fill='x', padx=5, pady=(5, 0))

        self.question_text = tk.Text(text_frame, height=4, font=('Arial', 12),
                                     wrap=tk.WORD, relief='sunken', bd=1)
        q_scrollbar = ttk.Scrollbar(text_frame, orient='vertical',
                                    command=self.question_text.yview)
        self.question_text.configure(yscrollcommand=q_scrollbar.set)
        self.question_text.pack(side='left', fill='x', expand=True)
        q_scrollbar.pack(side='left', fill='y')

        self.question_text.bind('<Control-Return>', lambda e: self.start_query())
        self.question_text.bind('<Control-KP_Enter>', lambda e: self.start_query())

        # ── Inline spell checker ──────────────────────────────────────────────
        # Uses pyspellchecker (pip install pyspellchecker) if available.
        # Red underline on misspelled words; right-click shows suggestions.
        self._spell_checker = None
        try:
            from spellchecker import SpellChecker as _SC
            self._spell_checker = _SC()
            self.question_text.tag_configure(
                'misspelled', underline=True, foreground='red')

            def _spell_check_text(event=None):
                """Re-scan the question box and underline misspelled words."""
                if self._spell_checker is None:
                    return
                self.question_text.tag_remove('misspelled', '1.0', tk.END)
                content = self.question_text.get('1.0', 'end-1c')
                import re as _re
                for m in _re.finditer(r"\b[a-zA-Z']+\b", content):
                    word = m.group()
                    if word.lower() not in self._spell_checker:
                        start = f"1.0 + {m.start()} chars"
                        end   = f"1.0 + {m.end()} chars"
                        self.question_text.tag_add('misspelled', start, end)

            def _spell_popup(event):
                """Right-click on a misspelled word to get correction suggestions."""
                if self._spell_checker is None:
                    return
                # Identify the word under the cursor
                try:
                    idx = self.question_text.index(f"@{event.x},{event.y}")
                    # Expand selection to word boundaries
                    word_start = self.question_text.index(f"{idx} wordstart")
                    word_end   = self.question_text.index(f"{idx} wordend")
                    word = self.question_text.get(word_start, word_end).strip("'\".,!?;:")
                except tk.TclError:
                    return
                if not word:
                    return
                suggestions = list(self._spell_checker.candidates(word) or [])[:8]
                menu = tk.Menu(self.question_text, tearoff=0)
                if suggestions:
                    menu.add_command(
                        label=f"Misspelled: '{word}'", state='disabled',
                        font=('Arial', 9, 'italic'))
                    menu.add_separator()
                    for sug in sorted(suggestions):
                        def _replace(s=sug, ws=word_start, we=word_end):
                            self.question_text.delete(ws, we)
                            self.question_text.insert(ws, s)
                            _spell_check_text()
                        menu.add_command(label=sug, command=_replace)
                else:
                    menu.add_command(label=f"No suggestions for '{word}'",
                                     state='disabled')
                menu.add_separator()
                menu.add_command(label="Ignore (add to session)",
                                 command=lambda w=word: (
                                     self._spell_checker.word_frequency.load_words([w.lower()]),
                                     _spell_check_text()))
                try:
                    menu.tk_popup(event.x_root, event.y_root)
                finally:
                    menu.grab_release()

            # Trigger spell check after each word (space/enter/punctuation)
            self.question_text.bind('<space>',
                lambda e: self.root.after(60, _spell_check_text))
            self.question_text.bind('<Return>',
                lambda e: self.root.after(60, _spell_check_text))
            self.question_text.bind('<KeyRelease>',
                lambda e: self.root.after(300, _spell_check_text))
            self.question_text.bind('<Button-3>', _spell_popup)
            self._spell_check_text = _spell_check_text

        except ImportError:
            self._spell_check_text = lambda: None  # no-op if package missing

        ttk.Label(question_frame,
                  text="Tip: press Ctrl+Enter to submit  |  Enter adds a new line",
                  font=('Arial', 8), foreground='gray').pack(anchor='w', padx=6, pady=(1, 0))

        # Mic row (only if faster-whisper + sounddevice installed)
        if SPEECH_AVAILABLE:
            mic_row = ttk.Frame(question_frame)
            mic_row.pack(fill='x', padx=5, pady=(4, 2))

            self._mic_btn_text = tk.StringVar(value="🎤")
            self._mic_btn = tk.Button(
                mic_row, textvariable=self._mic_btn_text,
                font=('Arial', 13), width=3, relief='flat',
                bg='#e8e8e8', activebackground='#d0d0d0',
                cursor='hand2', command=self._toggle_mic)
            self._mic_btn.pack(side='left', padx=(0, 8))

            ttk.Checkbutton(mic_row, text="Append (add to existing text)",
                            variable=self.mic_mode_append).pack(side='left', padx=(0, 12))
            ttk.Button(mic_row, text="🗑 Clear Question",
                       command=self._clear_question).pack(side='left')

            self._mic_status_var = tk.StringVar(value="")
            ttk.Label(question_frame, textvariable=self._mic_status_var,
                      font=('Arial', 9), foreground='gray').pack(anchor='w', padx=6)

        # ── Attachments area ──────────────────────────────────────────────────
        attach_lf = ttk.LabelFrame(query_frame,
                                   text="📎 Attachments  (images, code, text files)",
                                   padding=(8, 4))
        attach_lf.pack(fill='x', padx=20, pady=(0, 6))

        attach_btn_row = ttk.Frame(attach_lf)
        attach_btn_row.pack(fill='x')
        ttk.Button(attach_btn_row, text="📎 Attach Files…",
                   command=self._attach_files).pack(side='left', padx=(0, 8))
        ttk.Button(attach_btn_row, text="🗑 Clear All",
                   command=self._clear_attachments).pack(side='left', padx=(0, 16))

        fom_row = ttk.Frame(attach_lf)
        fom_row.pack(fill='x', pady=(6, 2))
        self._fom_check = ttk.Checkbutton(fom_row, text="📄 File Output Mode",
                                          variable=self.file_output_mode_var)
        self._fom_check.pack(side='left', padx=(0, 8))
        ttk.Label(fom_row,
                  text="When ticked: AI will label every code/script it writes with a filename "
                       "so a 💾 Save button appears automatically — no copy/paste needed.",
                  font=('Arial', 8), foreground='#555555',
                  wraplength=620, justify='left').pack(side='left')

        self._attach_display = ttk.Frame(attach_lf)
        self._attach_display.pack(fill='x', pady=(4, 0))
        self._attach_hint_var = tk.StringVar(
            value="No files attached  •  Attach images or files to include them in your question")
        ttk.Label(attach_lf, textvariable=self._attach_hint_var,
                  font=('Arial', 8), foreground='gray').pack(anchor='w', pady=(2, 0))

        # ── Context chunks + provider selector ───────────────────────────────
        options_frame = ttk.Frame(query_frame)
        options_frame.pack(fill='x', padx=20, pady=5)

        ttk.Label(options_frame, text="Context chunks:").pack(side='left', padx=5)
        self.chunks_var = tk.StringVar(value="Auto (3)")
        chunks_combo = ttk.Combobox(options_frame, textvariable=self.chunks_var,
                                    values=["Auto (3)", "1", "2", "3", "4", "5", "6",
                                            "7 ⚠reload", "10 ⚠reload",
                                            "15 ⚠reload", "20 ⚠reload"],
                                    width=14, state='readonly')
        chunks_combo.pack(side='left', padx=5)
        chunks_combo.bind('<<ComboboxSelected>>', self._on_chunks_changed)

        provider_frame = ttk.Frame(options_frame)
        provider_frame.pack(side='left', padx=(12, 0))
        ttk.Label(provider_frame, text="AI Provider:").pack(side='left', padx=(0, 4))

        self._prov_light_canvas = tk.Canvas(provider_frame, width=14, height=14,
                                            highlightthickness=0,
                                            bg=self.root.cget('bg'))
        self._prov_light_canvas.pack(side='left', padx=(0, 3))
        self._prov_light = self._prov_light_canvas.create_oval(
            1, 1, 13, 13, fill='#aaaaaa', outline='#888888', width=1)

        # Build provider list: one entry per installed Ollama model, then cloud providers
        self._provider_ids    = []
        self._provider_labels = []
        self._rebuild_local_provider_entries()   # populates _provider_ids/_labels for local models

        # Append cloud providers after local ones
        if RAG_AVAILABLE:
            for pid, p in EXTERNAL_PROVIDERS.items():
                if pid != 'local':
                    self._provider_ids.append(pid)
                    self._provider_labels.append(f"{p['name']}  ({p['maker']})")

        # Default to first local model (or first entry)
        current_model = self.current_model.get()
        default_idx = next((i for i, pid in enumerate(self._provider_ids)
                            if pid == f'local:{current_model}'), 0)

        self._provider_var = tk.StringVar(value=self._provider_labels[default_idx] if self._provider_labels else '')
        self._provider_combo = ttk.Combobox(provider_frame,
                                            textvariable=self._provider_var,
                                            values=self._provider_labels,
                                            width=30, state='readonly')
        self._provider_combo.pack(side='left')
        self._provider_combo.current(default_idx)
        self._provider_combo.bind('<<ComboboxSelected>>', self._on_provider_changed)

        self._provider_status_var = tk.StringVar(value="")
        ttk.Label(provider_frame, textvariable=self._provider_status_var,
                  font=('Arial', 8), foreground='gray').pack(side='left', padx=(4, 0))

        self.root.after(500, self._refresh_provider_light)

        # ── Action row ───────────────────────────────────────────────────────
        action_row = ttk.Frame(query_frame)
        action_row.pack(fill='x', padx=20, pady=(8, 4))

        query_btn = ttk.Button(action_row, text="Ask Question",
                               command=self.start_query, style='Accent.TButton')
        query_btn.pack(side='left', padx=(0, 6))

        self._stop_query_btn = ttk.Button(action_row, text="⏹ Stop",
                                          command=self._stop_query, state='disabled')
        self._stop_query_btn.pack(side='left', padx=(0, 12))

        ttk.Button(action_row, text="💾 Save Answer",
                   command=self._save_answer).pack(side='left', padx=(0, 8))

        self._load_model_btn = ttk.Button(action_row, text="⚡ Load AI Model",
                                          command=self._load_ollama_manual)
        self._load_model_btn.pack(side='left', padx=(0, 10))

        self._ollama_light_canvas = tk.Canvas(action_row, width=18, height=18,
                                              highlightthickness=0,
                                              bg=self.root.cget('bg'))
        self._ollama_light_canvas.pack(side='left', padx=(0, 4))
        self._ollama_light = self._ollama_light_canvas.create_oval(
            2, 2, 16, 16, fill='#aaaaaa', outline='#888888', width=1)

        self._ollama_status_var = tk.StringVar(value="● Model not loaded")
        self._ollama_status_lbl = ttk.Label(action_row,
                                            textvariable=self._ollama_status_var,
                                            font=('Arial', 9), foreground='#888888')
        self._ollama_status_lbl.pack(side='left')

        # ── Progress bar + elapsed timer ──────────────────────────────────────
        progress_row = ttk.Frame(query_frame)
        progress_row.pack(fill='x', padx=20, pady=(5, 0))

        self.query_progress = ttk.Progressbar(progress_row, mode='indeterminate')
        self.query_progress.pack(side='left', fill='x', expand=True)

        self.query_elapsed_var = tk.StringVar(value="")
        ttk.Label(progress_row, textvariable=self.query_elapsed_var,
                  font=('Arial', 9), foreground='gray', width=14,
                  anchor='e').pack(side='left', padx=(8, 0))

        self._query_timer_id   = None
        self._query_start_time = None

        # ── Detected files panel ──────────────────────────────────────────────
        # Container is ALWAYS packed here — never moved.
        # Only the LabelFrame inside is shown/hidden so pack order is preserved.
        self._detected_files_container = ttk.Frame(query_frame)
        self._detected_files_container.pack(fill='x', padx=20)

        self._detected_files_frame = ttk.LabelFrame(
            self._detected_files_container,
            text="📁 Files in Answer", padding=8)
        # NOT packed yet — shown by _show_detected_files()

        _df_header = ttk.Frame(self._detected_files_frame)
        _df_header.pack(fill='x', pady=(0, 4))
        ttk.Label(_df_header, text="Click 💾 Save to download each file.",
                  font=('Arial', 8), foreground='#555555').pack(side='left')
        ttk.Button(_df_header, text="✕ Clear",
                   command=self._clear_detected_files).pack(side='right')

        self._detected_files_inner = ttk.Frame(self._detected_files_frame)
        self._detected_files_inner.pack(fill='x')

        # ── Answer box ────────────────────────────────────────────────────────
        # Fixed height (scrollable internally); outer canvas scrolls the whole tab
        ttk.Label(query_frame, text="Answer:").pack(anchor='w', padx=20)
        self.answer_output = scrolledtext.ScrolledText(query_frame, height=22,
                                                       wrap=tk.WORD,
                                                       font=('Arial', 11))
        self.answer_output.pack(fill='x', padx=20, pady=5)

        # When mouse enters the answer box, let it scroll internally (unbind canvas).
        # When mouse leaves, restore canvas bind_all scrolling.
        def _bind_answer_scroll(e):
            self._query_canvas.unbind_all('<MouseWheel>')
        def _unbind_answer_scroll(e):
            self._query_canvas.bind_all('<MouseWheel>', self._query_scroll_cmd)
        self.answer_output.bind('<Enter>', _bind_answer_scroll)
        self.answer_output.bind('<Leave>', _unbind_answer_scroll)


    def create_update_tab(self):
        """Create update tab"""
        update_frame = ttk.Frame(self.notebook)
        self.notebook.add(update_frame, text="🔄 Update Index")
        f = self._make_scrollable_tab(update_frame)

        # Title
        ttk.Label(f, text="Keep Your Index Current",
                  font=('Arial', 16, 'bold')).pack(pady=10)

        # Storage locations info bar
        if RAG_AVAILABLE:
            tracking_path   = str(TRACKING_DB)
            update_list_path = str(AUTO_UPDATE_LIST)
        else:
            tracking_path    = "~/.rag_file_tracking.json"
            update_list_path = "~/.rag_auto_update_dirs.json"

        info_frame = ttk.LabelFrame(f,
                                    text="ℹ️  Tracking data location  "
                                         "(separate from rag_database — survives DB wipe)",
                                    padding=(10, 4))
        info_frame.pack(fill='x', padx=20, pady=(0, 6))
        ttk.Label(info_frame,
                  text=f"Directory list:    {update_list_path}",
                  font=('Courier', 8), foreground='gray').pack(anchor='w')
        ttk.Label(info_frame,
                  text=f"File timestamps:  {tracking_path}",
                  font=('Courier', 8), foreground='gray').pack(anchor='w')

        # Tracked directories
        tracked_frame = ttk.LabelFrame(f,
                                       text="Tracked Directories", padding=10)
        tracked_frame.pack(fill='x', padx=20, pady=(0, 6))

        # Listbox with scrollbar
        list_frame = ttk.Frame(tracked_frame)
        list_frame.pack(fill='both', expand=True)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side='right', fill='y')

        self.tracked_listbox = tk.Listbox(list_frame, height=8,
                                          font=('Courier', 9),
                                          yscrollcommand=scrollbar.set,
                                          selectmode=tk.SINGLE,
                                          activestyle='dotbox')
        self.tracked_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.tracked_listbox.yview)

        # Buttons row: refresh + remove
        tracked_btn_row = ttk.Frame(tracked_frame)
        tracked_btn_row.pack(fill='x', pady=(6, 0))

        ttk.Button(tracked_btn_row, text="🔄 Reload List",
                   command=self.refresh_tracked_dirs).pack(side='left', padx=(0, 8))
        ttk.Label(tracked_btn_row,
                  text="(re-reads the saved directory list from disk — use if you indexed from another session)",
                  font=('Arial', 8), foreground='gray').pack(side='left', padx=(0, 6))

        self.remove_tracked_btn = ttk.Button(
            tracked_btn_row,
            text="🗑 Remove Selected  (untrack + delete its vectors)",
            command=self._remove_tracked_directory
        )
        self.remove_tracked_btn.pack(side='left')

        # Update buttons
        buttons_frame = ttk.Frame(f)
        buttons_frame.pack(fill='x', padx=20, pady=(0, 6))

        ttk.Button(buttons_frame, text="Update Selected",
                   command=self.update_selected).pack(side='left', padx=(0, 6))

        ttk.Button(buttons_frame, text="Update All",
                   command=self.update_all,
                   style='Accent.TButton').pack(side='left')

        # Progress
        self.update_progress = ttk.Progressbar(f, mode='indeterminate')
        self.update_progress.pack(fill='x', padx=20, pady=(0, 6))

        # Output — fill='both' + expand=True so it grows when window is resized
        ttk.Label(f, text="Output:").pack(anchor='w', padx=20)
        self.update_output = scrolledtext.ScrolledText(f, height=10,
                                                       wrap=tk.WORD)
        self.update_output.pack(fill='both', expand=True, padx=20, pady=(0, 10))

        # Load tracked directories
        self.refresh_tracked_dirs()
    
    def create_scheduling_tab(self):
        """Create scheduling tab — scrollable, day-checkbox based."""
        schedule_frame = ttk.Frame(self.notebook)
        self.notebook.add(schedule_frame, text="⏰ Schedule")
        f = self._make_scrollable_tab(schedule_frame)

        ttk.Label(f, text="Schedule Automatic Updates",
                  font=('Arial', 14, 'bold')).pack(pady=10)
        ttk.Label(f,
                  text="Configure automatic updates to keep your knowledge base current.\n"
                       "Updates will re-index all tracked directories at the specified time.",
                  justify=tk.CENTER).pack(pady=(0, 8))

        # ── Current schedule status ───────────────────────────────────────────
        current_frame = ttk.LabelFrame(f, text="Current Schedule", padding=15)
        current_frame.pack(fill=tk.X, padx=40, pady=(0, 10))
        self.schedule_status = tk.StringVar(value="Checking...")
        ttk.Label(current_frame, textvariable=self.schedule_status,
                  justify=tk.LEFT).pack(anchor='w')

        # ── Schedule setup ────────────────────────────────────────────────────
        setup_frame = ttk.LabelFrame(f, text="Schedule Setup", padding=15)
        setup_frame.pack(fill=tk.X, padx=40, pady=(0, 10))

        # Time row
        time_row = ttk.Frame(setup_frame)
        time_row.pack(fill='x', pady=(0, 12))
        ttk.Label(time_row, text="Run time:").pack(side='left', padx=(0, 8))
        self.custom_time = tk.StringVar(value="08:00")
        ttk.Entry(time_row, textvariable=self.custom_time, width=8).pack(side='left', padx=(0, 6))
        ttk.Label(time_row, text="24-hour format  (e.g. 08:00 = 8 AM,  14:30 = 2:30 PM,  23:00 = 11 PM)",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        # Day-of-week checkboxes
        ttk.Label(setup_frame, text="Run on these days:",
                  font=('Arial', 9)).pack(anchor='w', pady=(0, 6))
        days_row = ttk.Frame(setup_frame)
        days_row.pack(fill='x', pady=(0, 4))

        self._day_vars = {}
        day_defs = [
            ('Mon', 'MON'), ('Tue', 'TUE'), ('Wed', 'WED'),
            ('Thu', 'THU'), ('Fri', 'FRI'), ('Sat', 'SAT'), ('Sun', 'SUN'),
        ]
        for label, key in day_defs:
            var = tk.BooleanVar(value=key in ('MON', 'TUE', 'WED', 'THU', 'FRI'))
            self._day_vars[key] = var
            ttk.Checkbutton(days_row, text=label, variable=var).pack(side='left', padx=6)

        # Quick-select helpers
        quick_row = ttk.Frame(setup_frame)
        quick_row.pack(fill='x', pady=(0, 14))
        ttk.Label(quick_row, text="Quick select:",
                  font=('Arial', 8), foreground='gray').pack(side='left', padx=(0, 8))
        def _sel_weekdays():
            for k, v in self._day_vars.items():
                v.set(k in ('MON', 'TUE', 'WED', 'THU', 'FRI'))
        def _sel_everyday():
            for v in self._day_vars.values():
                v.set(True)
        ttk.Button(quick_row, text="Weekdays", command=_sel_weekdays).pack(side='left', padx=4)
        ttk.Button(quick_row, text="Every day", command=_sel_everyday).pack(side='left', padx=4)

        ttk.Button(setup_frame, text="✅ Set Schedule",
                   command=self.set_custom_schedule,
                   style='Accent.TButton').pack(anchor='w')

        # ── Schedule control ──────────────────────────────────────────────────
        control_frame = ttk.LabelFrame(f, text="Schedule Control", padding=15)
        control_frame.pack(fill=tk.X, padx=40, pady=(0, 10))
        ctrl_row = ttk.Frame(control_frame)
        ctrl_row.pack()
        ttk.Button(ctrl_row, text="Disable Schedule",
                   command=self.disable_schedule).pack(side='left', padx=6)
        ttk.Button(ctrl_row, text="Remove Schedule",
                   command=self.remove_schedule).pack(side='left', padx=6)
        ttk.Button(ctrl_row, text="Refresh Status",
                   command=self.refresh_schedule_status).pack(side='left', padx=6)

        # ── Info ──────────────────────────────────────────────────────────────
        info_frame = ttk.LabelFrame(f, text="How It Works", padding=10)
        info_frame.pack(fill=tk.X, padx=40, pady=(0, 20))
        ttk.Label(info_frame, justify='left', font=('Arial', 9), foreground='#444',
                  text=(
                      "1. The scheduler runs at your specified time on the selected days\n"
                      "2. It re-indexes all directories in the Update Index tab\n"
                      "3. Your knowledge base stays current with new/changed files\n\n"
                      "Requirements:\n"
                      "  • At least one directory tracked (see Update Index tab)\n"
                      "  • Windows Task Scheduler enabled\n"
                      "  • AI Prowler files in a permanent location\n\n"
                      "The schedule uses Windows Task Scheduler and runs\n"
                      "even when this application is closed."
                  )).pack(anchor='w')

        self.refresh_schedule_status()

    def set_schedule(self, time_str, days):
        """Create a Windows Task Scheduler entry for the given days."""
        try:
            script_path = Path.home() / "AI-Prowler" / "rag_auto_update.bat"
            all_days    = {'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'}
            days_str    = ",".join(days)
            if set(days) == all_days:
                cmd = f'schtasks /create /tn "AI Prowler Auto-Update" /tr "{script_path}" /sc daily /st {time_str} /f'
                day_label = "every day"
            else:
                cmd = f'schtasks /create /tn "AI Prowler Auto-Update" /tr "{script_path}" /sc weekly /d {days_str} /st {time_str} /f'
                day_label = days_str
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Success",
                                    f"Schedule set!\n\nRuns {day_label} at {time_str}")
                self.refresh_schedule_status()
            else:
                messagebox.showerror("Error",
                                     f"Failed to create schedule.\n\nError: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set schedule: {str(e)}")
    
    def set_custom_schedule(self):
        """Set schedule from the day-checkbox UI."""
        time_str = self.custom_time.get().strip()
        if not self.validate_time(time_str):
            messagebox.showerror("Invalid Time",
                                 "Please enter time in HH:MM format\n"
                                 "Examples: 08:00, 12:00, 18:30")
            return
        selected_days = [k for k, v in self._day_vars.items() if v.get()]
        if not selected_days:
            messagebox.showerror("No Days Selected",
                                 "Please tick at least one day.")
            return
        self.set_schedule(time_str, selected_days)
    
    def validate_time(self, time_str):
        """Validate time format HH:MM"""
        try:
            parts = time_str.split(':')
            if len(parts) != 2:
                return False
            
            hour = int(parts[0])
            minute = int(parts[1])
            
            if hour < 0 or hour > 23:
                return False
            if minute < 0 or minute > 59:
                return False
            
            return True
        except:
            return False
    
    def disable_schedule(self):
        """Disable the schedule temporarily"""
        try:
            cmd = 'schtasks /change /tn "AI Prowler Auto-Update" /disable'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                messagebox.showinfo("Success", "Schedule disabled successfully!")
                self.refresh_schedule_status()
            else:
                messagebox.showwarning("Not Found",
                                      "No schedule found to disable.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to disable schedule: {str(e)}")
    
    def remove_schedule(self):
        """Remove the schedule completely"""
        if not messagebox.askyesno("Confirm",
                                   "Remove automatic update schedule?\n\n"
                                   "You can always create a new schedule later."):
            return
        
        try:
            cmd = 'schtasks /delete /tn "AI Prowler Auto-Update" /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                messagebox.showinfo("Success", "Schedule removed successfully!")
                self.refresh_schedule_status()
            else:
                messagebox.showwarning("Not Found",
                                      "No schedule found to remove.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove schedule: {str(e)}")
    
    def refresh_schedule_status(self):
        """Query Windows Task Scheduler and show full schedule + last-run details."""
        try:
            cmd    = 'schtasks /query /tn "AI Prowler Auto-Update" /fo list'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                output   = result.stdout
                status   = "Unknown"
                next_run = "N/A"
                last_run = "Never"
                schedule = "N/A"

                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith('Status:'):
                        status = line.split(':', 1)[1].strip()
                    elif line.startswith('Next Run Time:'):
                        next_run = line.split(':', 1)[1].strip()
                    elif line.startswith('Last Run Time:'):
                        last_run = line.split(':', 1)[1].strip()
                    elif line.startswith('Schedule Type:') or line.startswith('Days:'):
                        schedule += f"  {line}"

                # Also show when AI Prowler itself last completed an index run
                app_last = getattr(self, '_last_index_time', None)
                app_line = (f"AI Prowler last indexed:  {app_last}"
                            if app_last else
                            "AI Prowler last indexed:  not yet this session")

                self.schedule_status.set(
                    f"✅ Schedule Active\n"
                    f"  Task status:   {status}\n"
                    f"  Last run:      {last_run}\n"
                    f"  Next run:      {next_run}\n"
                    f"  {app_line}"
                )
            else:
                app_last = getattr(self, '_last_index_time', None)
                app_line = (f"AI Prowler last indexed:  {app_last}"
                            if app_last else
                            "AI Prowler last indexed:  not yet this session")
                self.schedule_status.set(
                    f"❌ No schedule set\n"
                    f"  Use Schedule Setup above to create one.\n"
                    f"  {app_line}"
                )
        except Exception as e:
            self.schedule_status.set(f"⚠️ Error checking status: {str(e)}")
    
    # ─────────────────────────────────────────────────────────────────────────
    def create_scan_config_tab(self):
        """Smart Scan Configuration — edit supported/skipped extensions and dirs."""
        scan_cfg_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_cfg_frame, text="🗂 Smart Scan")
        f = self._make_scrollable_tab(scan_cfg_frame)

        ttk.Label(f, text="Smart Scan Configuration",
                  font=('Arial', 16, 'bold')).pack(pady=(10, 2))
        ttk.Label(f,
                  text="Customise which file types are indexed and which are skipped "
                       "during smart scan.\nChanges are saved immediately and apply "
                       "to all future scans.",
                  font=('Arial', 9), foreground='gray',
                  justify='center').pack(pady=(0, 8))

        # Load current live sets
        if RAG_AVAILABLE:
            sup, skp, dirs = load_full_extension_config()
        else:
            sup  = {'.txt', '.md', '.pdf', '.docx'}
            skp  = {'.exe', '.dll', '.zip'}
            dirs = {'node_modules', '__pycache__', '.git'}

        # ── Top two-column panel: Supported | Skipped extensions ─────────────
        cols_frame = ttk.Frame(f)
        cols_frame.pack(fill='x', padx=20, pady=(0, 6))
        cols_frame.columnconfigure(0, weight=1)
        cols_frame.columnconfigure(1, weight=1)

        # ── LEFT — Supported Extensions ──────────────────────────────────────
        sup_frame = ttk.LabelFrame(cols_frame,
                                   text="✅ Supported Extensions  (will be indexed)",
                                   padding=8)
        sup_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 6))

        self.sup_listbox = self._make_ext_listbox(sup_frame, sorted(sup))

        sup_add_row = ttk.Frame(sup_frame)
        sup_add_row.pack(fill='x', pady=(6, 0))
        self.sup_add_var = tk.StringVar()
        sup_entry = ttk.Entry(sup_add_row, textvariable=self.sup_add_var, width=12)
        sup_entry.pack(side='left', padx=(0, 4))
        sup_entry.bind('<Return>', lambda e: self._ext_add(
            self.sup_listbox, self.sup_add_var, 'supported'))
        ttk.Button(sup_add_row, text="➕ Add",
                   command=lambda: self._ext_add(
                       self.sup_listbox, self.sup_add_var, 'supported')
                   ).pack(side='left', padx=(0, 4))
        ttk.Button(sup_add_row, text="❌ Remove",
                   command=lambda: self._ext_remove(
                       self.sup_listbox, 'supported')
                   ).pack(side='left')

        ttk.Label(sup_frame,
                  text="e.g. .log  .nfo  .tex",
                  font=('Arial', 8), foreground='gray').pack(anchor='w', pady=(4, 0))

        # ── RIGHT — Skipped Extensions ────────────────────────────────────────
        skp_frame = ttk.LabelFrame(cols_frame,
                                   text="🚫 Skipped Extensions  (never indexed)",
                                   padding=8)
        skp_frame.grid(row=0, column=1, sticky='nsew', padx=(6, 0))

        self.skp_listbox = self._make_ext_listbox(skp_frame, sorted(skp))

        skp_add_row = ttk.Frame(skp_frame)
        skp_add_row.pack(fill='x', pady=(6, 0))
        self.skp_add_var = tk.StringVar()
        skp_entry = ttk.Entry(skp_add_row, textvariable=self.skp_add_var, width=12)
        skp_entry.pack(side='left', padx=(0, 4))
        skp_entry.bind('<Return>', lambda e: self._ext_add(
            self.skp_listbox, self.skp_add_var, 'skipped'))
        ttk.Button(skp_add_row, text="➕ Add",
                   command=lambda: self._ext_add(
                       self.skp_listbox, self.skp_add_var, 'skipped')
                   ).pack(side='left', padx=(0, 4))
        ttk.Button(skp_add_row, text="❌ Remove",
                   command=lambda: self._ext_remove(
                       self.skp_listbox, 'skipped')
                   ).pack(side='left')

        ttk.Label(skp_frame,
                  text="e.g. .iso  .vmdk  .bak",
                  font=('Arial', 8), foreground='gray').pack(anchor='w', pady=(4, 0))

        # ── Bottom action bar — packed first with side='bottom' so the
        # Skipped Directories frame fills all remaining space above it ─────────
        action_row = ttk.Frame(f)
        action_row.pack(side='bottom', fill='x', padx=20, pady=(4, 16))

        # ── Bottom panel — Skip Directories ──────────────────────────────────
        # expand=True + fill='both' lets this frame grow in both axes when the
        # main window is resized; side='bottom' in action_row ensures it stays
        # visually anchored at the bottom of the scrollable tab.
        dir_frame = ttk.LabelFrame(f,
                                   text="📂 Skipped Directories  (entire folder ignored)",
                                   padding=8)
        dir_frame.pack(fill='both', expand=True, padx=20, pady=(0, 6))

        # Listbox row — expand=True so it stretches horizontally with the window.
        # Scrollbar packed first with side='right' so it doesn't get squeezed out
        # when the listbox claims remaining width via fill='both', expand=True.
        dir_list_row = ttk.Frame(dir_frame)
        dir_list_row.pack(fill='both', expand=True)

        dir_scroll = ttk.Scrollbar(dir_list_row, orient='vertical')
        dir_scroll.pack(side='right', fill='y')

        self.dir_listbox = tk.Listbox(dir_list_row, height=4,
                                      font=('Courier', 9),
                                      selectmode=tk.SINGLE,
                                      activestyle='dotbox',
                                      yscrollcommand=dir_scroll.set)
        dir_scroll.configure(command=self.dir_listbox.yview)
        self.dir_listbox.pack(side='left', fill='both', expand=True)

        for d in sorted(dirs):
            self.dir_listbox.insert(tk.END, d)

        dir_add_row = ttk.Frame(dir_frame)
        dir_add_row.pack(fill='x', pady=(6, 0))
        self.dir_add_var = tk.StringVar()
        dir_entry = ttk.Entry(dir_add_row, textvariable=self.dir_add_var, width=24)
        dir_entry.pack(side='left', padx=(0, 4))
        dir_entry.bind('<Return>', lambda e: self._dir_add())
        ttk.Button(dir_add_row, text="➕ Add Name",
                   command=self._dir_add).pack(side='left', padx=(0, 4))
        ttk.Button(dir_add_row, text="📂 Browse Folder…",
                   command=self._dir_browse_folder).pack(side='left', padx=(0, 4))
        ttk.Button(dir_add_row, text="❌ Remove Selected",
                   command=self._dir_remove).pack(side='left', padx=(0, 16))
        ttk.Label(dir_add_row,
                  text="Type a folder name (e.g. temp) or browse for a full path",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        ttk.Button(action_row, text="💾 Save Changes",
                   command=self._scan_cfg_save,
                   style='Accent.TButton').pack(side='left', padx=(0, 10))

        ttk.Button(action_row, text="↩ Reset to Defaults",
                   command=self._scan_cfg_reset).pack(side='left', padx=(0, 20))

        self.scan_cfg_status_var = tk.StringVar(value="")
        ttk.Label(action_row, textvariable=self.scan_cfg_status_var,
                  font=('Arial', 9), foreground='gray').pack(side='left')

    # ── Scan config helpers ───────────────────────────────────────────────────

    def _make_ext_listbox(self, parent, items):
        """Create a scrollable listbox pre-filled with items, packed into parent."""
        lb_frame = ttk.Frame(parent)
        lb_frame.pack(fill='both', expand=True)

        lb = tk.Listbox(lb_frame, height=14, font=('Courier', 9),
                        selectmode=tk.SINGLE, activestyle='dotbox',
                        exportselection=False)
        sb = ttk.Scrollbar(lb_frame, orient='vertical', command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        lb.pack(side='left', fill='both', expand=True)
        sb.pack(side='left', fill='y')

        for item in items:
            lb.insert(tk.END, item)
        return lb

    def _ext_add(self, listbox, var, side):
        """Add an extension to a listbox and sync to preprocessor."""
        raw = var.get().strip().lower()
        if not raw:
            return
        # Normalise — ensure leading dot
        ext = raw if raw.startswith('.') else '.' + raw
        # Reject if already in this list
        existing = list(listbox.get(0, tk.END))
        if ext in existing:
            self.scan_cfg_status_var.set(f"{ext} is already in the list")
            return
        # Warn if it's in the OTHER list (conflict)
        other_lb = self.skp_listbox if side == 'supported' else self.sup_listbox
        if ext in list(other_lb.get(0, tk.END)):
            self.scan_cfg_status_var.set(
                f"⚠️  {ext} is in the {'skipped' if side == 'supported' else 'supported'} "
                f"list — remove it there first")
            return
        # Insert in sorted position
        items = existing + [ext]
        items.sort()
        pos = items.index(ext)
        listbox.insert(pos, ext)
        var.set("")
        self._sync_ext_sets()
        self._scan_cfg_autosave()

    def _ext_remove(self, listbox, side):
        """Remove selected extension from listbox and sync."""
        sel = listbox.curselection()
        if not sel:
            return
        ext = listbox.get(sel[0])
        listbox.delete(sel[0])
        self._sync_ext_sets()
        self._scan_cfg_autosave()
        self.scan_cfg_status_var.set(f"Removed {ext}")

    def _dir_add(self):
        """Add a directory name to the skip-dirs listbox."""
        name = self.dir_add_var.get().strip()
        if not name:
            return
        existing = list(self.dir_listbox.get(0, tk.END))
        if name in existing:
            self.scan_cfg_status_var.set(f"{name} is already in the list")
            return
        items = sorted(existing + [name])
        pos = items.index(name)
        self.dir_listbox.insert(pos, name)
        self.dir_add_var.set("")
        self._sync_ext_sets()
        self._scan_cfg_autosave()

    def _dir_remove(self):
        """Remove selected directory from the skip-dirs listbox."""
        sel = self.dir_listbox.curselection()
        if not sel:
            return
        name = self.dir_listbox.get(sel[0])
        self.dir_listbox.delete(sel[0])
        self._sync_ext_sets()
        self._scan_cfg_autosave()
        self.scan_cfg_status_var.set(f"Removed {name}")

    def _dir_browse_folder(self):
        """Open a folder-picker dialog and add the chosen path to the skip list.

        The native folder dialog opens so the user can navigate and select any
        folder on disk.  The full path is stored so that entire real directory
        trees (not just name fragments) can be excluded from indexing.
        """
        path = filedialog.askdirectory(
            title="Select a folder to exclude from indexing",
            mustexist=True)
        if not path:
            return
        # Normalise separators
        path = str(Path(path))
        existing = list(self.dir_listbox.get(0, tk.END))
        if path in existing:
            self.scan_cfg_status_var.set(f"Already in list: {path}")
            return
        # Insert in sorted position
        items = sorted(existing + [path])
        pos = items.index(path)
        self.dir_listbox.insert(pos, path)
        self._sync_ext_sets()
        self._scan_cfg_autosave()
        self.scan_cfg_status_var.set(f"✅ Added: {path}")

    def _sync_ext_sets(self):
        """Push listbox contents into the live preprocessor sets immediately."""
        if not RAG_AVAILABLE:
            return
        _rag_engine.SUPPORTED_EXTENSIONS = set(self.sup_listbox.get(0, tk.END))
        _rag_engine.SKIP_EXTENSIONS      = set(self.skp_listbox.get(0, tk.END))
        _rag_engine.SKIP_DIRECTORIES     = set(self.dir_listbox.get(0, tk.END))

    def _scan_cfg_autosave(self):
        """Save current sets to config and show a brief status confirmation."""
        if not RAG_AVAILABLE:
            return
        save_extension_config(
            _rag_engine.SUPPORTED_EXTENSIONS,
            _rag_engine.SKIP_EXTENSIONS,
            _rag_engine.SKIP_DIRECTORIES,
        )
        self.scan_cfg_status_var.set("✅ Saved")
        self.root.after(2500, lambda: self.scan_cfg_status_var.set(""))

    def _scan_cfg_save(self):
        """Manual save button — sync and save."""
        self._sync_ext_sets()
        self._scan_cfg_autosave()

    def _scan_cfg_reset(self):
        """Reset all three listboxes to the built-in defaults."""
        if not messagebox.askyesno(
                "Reset to Defaults",
                "This will discard all your custom extension changes and restore "
                "the built-in defaults.\n\nContinue?"):
            return

        # Re-import the module to get pristine default sets
        import importlib
        import rag_preprocessor as _rp_fresh
        importlib.reload(_rp_fresh)

        sup_default  = sorted(_rp_fresh.SUPPORTED_EXTENSIONS)
        skp_default  = sorted(_rp_fresh.SKIP_EXTENSIONS)
        dirs_default = sorted(_rp_fresh.SKIP_DIRECTORIES)

        for lb, items in [(self.sup_listbox,  sup_default),
                          (self.skp_listbox,  skp_default),
                          (self.dir_listbox,  dirs_default)]:
            lb.delete(0, tk.END)
            for item in items:
                lb.insert(tk.END, item)

        self._sync_ext_sets()
        self._scan_cfg_autosave()
        self.scan_cfg_status_var.set("↩ Reset to defaults and saved")

    # ─────────────────────────────────────────────────────────────────────────
    def create_settings_tab(self):
        """Create settings tab with scrolling support"""
        # Outer frame added to notebook
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Create canvas and scrollbar for scrolling
        canvas = tk.Canvas(settings_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(settings_frame, orient="vertical", command=canvas.yview)
        
        # Inner frame to hold all content
        scrollable_frame = ttk.Frame(canvas)
        
        # Configure canvas scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Stretch the inner frame to fill the canvas width whenever canvas resizes
        def _on_canvas_resize(event):
            canvas.itemconfig(canvas.find_withtag("all")[0], width=event.width)
        canvas.bind("<Configure>", _on_canvas_resize)

        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Enable mousewheel scrolling anywhere inside the Settings tab
        # (canvas AND inner frame both activate the scroll binding on hover)
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")

        def _bind_scroll(e):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)

        def _unbind_scroll(e):
            canvas.unbind_all("<MouseWheel>")

        canvas.bind("<Enter>",           _bind_scroll)
        canvas.bind("<Leave>",           _unbind_scroll)
        scrollable_frame.bind("<Enter>", _bind_scroll)
        scrollable_frame.bind("<Leave>", _unbind_scroll)
        
        # Title
        title = ttk.Label(scrollable_frame, text="Configuration", 
                         font=('Arial', 16, 'bold'))
        title.pack(pady=10)
        
        # Model selection
        model_frame = ttk.LabelFrame(scrollable_frame, text="AI Model", padding=10)
        model_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(model_frame,
                  text="Active model  (switches which already-installed model Ollama uses):",
                  font=('Arial', 9)).pack(anchor='w', pady=(5, 2))
        
        # Detect system RAM (Windows)
        try:
            class _MEMSTATUS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            ms = _MEMSTATUS()
            ms.dwLength = ctypes.sizeof(_MEMSTATUS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            self._system_ram_gb = ms.ullTotalPhys / (1024 ** 3)
        except Exception:
            self._system_ram_gb = 0  # unknown

        # Build model list from INSTALLED Ollama models only
        # Falls back to current active model if Ollama isn't running yet
        def _get_installed_models():
            installed = []
            try:
                r = requests.get("http://localhost:11434/api/tags", timeout=3,
                                 proxies={"http": None, "https": None})
                if r.status_code == 200:
                    installed = [m.get('name','') for m in r.json().get('models',[]) if m.get('name')]
            except Exception:
                pass
            if not installed:
                # Ollama not running — show at least the currently configured model
                installed = [self.current_model.get()]
            # Sort: active model first, then alphabetical
            active = self.current_model.get()
            installed.sort(key=lambda m: (0 if m == active else 1, m))
            return installed

        def _display_name(m):
            info   = MODEL_INFO.get(m, {})
            size   = info.get("size_gb", 0)
            needed = info.get("min_ram_gb", 0)
            sys_ram = self._system_ram_gb
            if sys_ram > 0 and needed:
                badge = "✅" if needed <= sys_ram else "⚠️"
            else:
                badge = "✅"   # installed = always show checkmark
            size_str = f"{size:.1f} GB dl | {needed} GB RAM" if (size or needed) else "installed"
            return f"{badge} {m}  [{size_str}]"

        # Merge catalogue + any Ollama extras (not just installed) for _get_all_models()
        # but show only installed in the combobox
        models = _get_installed_models()
        self._model_names = models

        display_names = [_display_name(m) for m in models]
        self._model_display_map = dict(zip(display_names, models))
        self._model_reverse_map = dict(zip(models, display_names))

        # Use a StringVar that holds the display name for the combobox
        self._model_display_var = tk.StringVar()
        current = self.current_model.get()
        self._model_display_var.set(self._model_reverse_map.get(current, display_names[0] if display_names else ""))

        model_combo = ttk.Combobox(model_frame, textvariable=self._model_display_var,
                                   values=display_names, width=55, state='readonly')
        model_combo.pack(fill='x', pady=5)
        model_combo.bind('<<ComboboxSelected>>', self.on_model_change)
        self._model_combo_widget = model_combo   # ref for _rebuild_model_combo
        # Background poller starts at app launch — list is always fresh
        self.root.after(500, self._start_model_poller)

        if self._system_ram_gb > 0:
            ram_lbl = ttk.Label(model_frame,
                text=f"Your PC has {self._system_ram_gb:.1f} GB RAM  |  ✅ = fits in RAM  ⚠️ = may be slow  "
                     f"(only downloaded models shown — use Browse & Install to add more)",
                font=('Arial', 9), foreground='gray')
            ram_lbl.pack(anchor='w')

        # Model info
        self.model_info_label = ttk.Label(model_frame, text="",
                                          font=('Arial', 10))
        self.model_info_label.pack(anchor='w', pady=5)
        self.update_model_info()

        # Install model button
        install_btn = ttk.Button(model_frame, text="Browse & Install Model…",
                                command=self.show_model_picker)
        install_btn.pack(pady=5)

        # ── External AI APIs ──────────────────────────────────────────────────
        ext_frame = ttk.LabelFrame(scrollable_frame, text="External AI APIs", padding=10)
        ext_frame.pack(fill='x', padx=20, pady=10)

        ttk.Label(ext_frame,
                  text="Enter API keys to use cloud AI providers. Keys are stored locally in ~/.rag_config.json",
                  font=('Arial', 9), foreground='gray').pack(anchor='w', pady=(0, 6))

        self._api_key_vars = {}   # {provider_id: tk.StringVar}
        self._api_key_dots = {}   # {provider_id: canvas item ref}
        self._api_key_canvases = {}

        ext_providers = [(pid, p) for pid, p in EXTERNAL_PROVIDERS.items() if pid != 'local'] if RAG_AVAILABLE else []

        # Free-tier notes per provider
        _free_tier = {
            'openai':    'Pay-per-use',
            'anthropic': '$5 free credit',
            'google':    '✅ Free tier',
            'xai':       'Limited free',
            'meta':      '✅ Free tier',
            'mistral':   'Limited free',
        }

        for pid, prov in ext_providers:
            row = ttk.Frame(ext_frame)
            row.pack(fill='x', pady=2)

            # Status dot
            dot_canvas = tk.Canvas(row, width=12, height=12,
                                   highlightthickness=0, bg=self.root.cget('bg'))
            dot_canvas.pack(side='left', padx=(0, 4))
            dot = dot_canvas.create_oval(1, 1, 11, 11, fill='#aaaaaa', outline='#888888')
            self._api_key_dots[pid]    = dot
            self._api_key_canvases[pid]= dot_canvas

            # Label: "ChatGPT (OpenAI)"
            ttk.Label(row, text=f"{prov['name']} ({prov['maker']}):",
                      width=22, anchor='w').pack(side='left')

            # Key entry
            existing_key = _rag_engine.PROVIDER_API_KEYS.get(pid, '') if RAG_AVAILABLE else ''
            var = tk.StringVar(value=existing_key)
            self._api_key_vars[pid] = var

            entry = ttk.Entry(row, textvariable=var, width=42, show='*')
            entry.pack(side='left', padx=(0, 4))

            # Toggle show/hide
            def _make_toggle(e=entry):
                def _toggle():
                    e.config(show='' if e.cget('show') == '*' else '*')
                return _toggle
            ttk.Button(row, text="👁", width=3, command=_make_toggle()).pack(side='left', padx=(0, 4))

            # Save button
            def _make_save(p=pid, v=var):
                def _save():
                    key = v.get().strip()
                    _rag_engine.PROVIDER_API_KEYS[p] = key
                    save_config(provider_api_keys=_rag_engine.PROVIDER_API_KEYS)
                    self._update_api_dot(p)
                    self._build_provider_display_list()
                    self.status_var.set(f"✅ {EXTERNAL_PROVIDERS[p]['name']} API key saved.")
                return _save
            ttk.Button(row, text="Save", command=_make_save()).pack(side='left', padx=(0, 4))

            # Test button — fires a live ping and shows a detailed result popup
            def _make_test(p=pid, v=var):
                def _test():
                    key = v.get().strip()
                    if not key:
                        messagebox.showwarning("No Key",
                            "Enter an API key first, then click Test.",
                            parent=self.root)
                        return
                    self.status_var.set(f"🔌 Testing {EXTERNAL_PROVIDERS[p]['name']}…")
                    self.root.update_idletasks()
                    def _run():
                        result = test_provider_connection(p, api_key=key)
                        self.output_queue.put(('provider_test_result', result))
                    threading.Thread(target=_run, daemon=True).start()
                return _test
            ttk.Button(row, text="🔌 Test",
                       command=_make_test()).pack(side='left', padx=(0, 6))

            # Get Key button — opens browser directly to the provider's API key page
            key_url = prov.get('key_url')
            if key_url:
                free_note = _free_tier.get(pid, '')
                btn_text  = f"🔑 Get Key  {free_note}".strip()
                def _make_get_key(u=key_url):
                    return lambda: webbrowser.open(u)
                ttk.Button(row, text=btn_text,
                           command=_make_get_key()).pack(side='left')

        # Fallback toggle
        fb_row = ttk.Frame(ext_frame)
        fb_row.pack(fill='x', pady=(8, 2))
        self._fallback_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(fb_row,
                        text="Auto-fallback to Local Ollama if external provider fails or is rate-limited",
                        variable=self._fallback_var,
                        command=self._on_fallback_change).pack(anchor='w')

        # Initial dot colours
        for pid in self._api_key_dots:
            self._update_api_dot(pid)

        # Database info
        db_frame = ttk.LabelFrame(scrollable_frame, text="Database", padding=10)
        db_frame.pack(fill='x', padx=20, pady=10)
        
        stats_btn = ttk.Button(db_frame, text="View Statistics",
                              command=self.show_stats)
        stats_btn.pack(side='left', padx=5)
        
        clear_btn = ttk.Button(db_frame, text="Clear Database",
                              command=self.clear_database)
        clear_btn.pack(side='left', padx=5)

        # ── Query Output ──────────────────────────────────────────────────────
        output_frame = ttk.LabelFrame(scrollable_frame, text="Query Output", padding=(10, 6))
        output_frame.pack(fill='x', padx=20, pady=(10, 5))

        # Two checkboxes side-by-side: Show Sources  |  Enable Debug
        checks_row = ttk.Frame(output_frame)
        checks_row.pack(fill='x')

        sources_check = ttk.Checkbutton(
            checks_row,
            text="Show source references"
                 "  (ON = file paths, scores, timing)",
            variable=self.show_sources_var,
            command=self._on_show_sources_change
        )
        sources_check.pack(side='left', anchor='w')

        ttk.Separator(checks_row, orient='vertical').pack(
            side='left', padx=(16, 12), fill='y', pady=2)

        debug_check = ttk.Checkbutton(
            checks_row,
            text="Enable debug output"
                 "  (ON = ⏱ timing + 🔬 debug + DOS test command)",
            variable=self.debug_output_var,
            command=self._on_debug_output_change
        )
        debug_check.pack(side='left', anchor='w')

        # Debug View checkbox — on its own row so it doesn't get cramped
        debug_view_row = ttk.Frame(output_frame)
        debug_view_row.pack(fill='x', pady=(4, 0))
        debug_view_check = ttk.Checkbutton(
            debug_view_row,
            text="Debug View  (view DOS windows in foreground — uncheck to hide them in background)",
            variable=self.debug_view_var,
            command=self._on_debug_view_change
        )
        debug_view_check.pack(side='left', anchor='w')

        # ── Microphone Settings ───────────────────────────────────────────────
        if SPEECH_AVAILABLE:
            mic_frame = ttk.LabelFrame(scrollable_frame, text="Microphone / Speech Input", padding=(10, 6))
            mic_frame.pack(fill='x', padx=20, pady=(5, 5))

            silence_row = ttk.Frame(mic_frame)
            silence_row.pack(fill='x')

            ttk.Label(silence_row, text="Auto-stop after silence:").pack(side='left')

            silence_slider = ttk.Scale(
                silence_row,
                from_=1.0, to=8.0,
                orient='horizontal',
                variable=self.mic_silence_var,
                command=self._on_silence_change,
                length=180
            )
            silence_slider.pack(side='left', padx=(10, 6))

            self.mic_silence_label_var = tk.StringVar(value="")
            ttk.Label(silence_row, textvariable=self.mic_silence_label_var,
                      font=('Arial', 9), width=10).pack(side='left')

            ttk.Label(mic_frame,
                      text="Short (1-2s) = fast response  •  Long (4-8s) = more time to pause between words",
                      foreground='gray', font=('Arial', 9)).pack(anchor='w', pady=(4, 0))

            self._refresh_silence_label()

        # ── GPU Acceleration ──────────────────────────────────────────────────
        gpu_frame = ttk.LabelFrame(scrollable_frame, text="GPU Acceleration", padding=(10, 6))
        gpu_frame.pack(fill='x', padx=20, pady=(5, 10))

        # Top row: spinbox + buttons all in one line so buttons are always visible
        ctrl_row = ttk.Frame(gpu_frame)
        ctrl_row.pack(fill='x', pady=(0, 6))

        ttk.Label(ctrl_row, text="GPU layers:").pack(side='left')

        layers_spin = ttk.Spinbox(ctrl_row, from_=-1, to=99,
                                  textvariable=self.gpu_layers_var,
                                  width=5, command=self._on_gpu_layers_change)
        layers_spin.pack(side='left', padx=(6, 0))
        layers_spin.bind('<FocusOut>', self._on_gpu_layers_change)
        layers_spin.bind('<Return>', self._on_gpu_layers_change)

        self.gpu_layers_desc_var = tk.StringVar(value="")
        ttk.Label(ctrl_row, textvariable=self.gpu_layers_desc_var,
                  font=('Arial', 9), foreground='gray').pack(side='left', padx=(8, 16))

        detect_btn = ttk.Button(ctrl_row, text="🔍 Detect GPU",
                                command=self._run_gpu_detect)
        detect_btn.pack(side='left', padx=(0, 6))

        apply_btn = ttk.Button(ctrl_row, text="✅ Apply & Reload",
                               command=self._apply_gpu_settings)
        apply_btn.pack(side='left')

        # Hint line and status below controls
        ttk.Label(gpu_frame,
                  text="-1 = auto (recommended)  •  0 = CPU only  •  1-99 = partial offload",
                  foreground='gray', font=('Arial', 9)).pack(anchor='w', pady=(0, 4))

        # Scrollable GPU status output box — replaces the plain label so long
        # detection results can be read in full without being cut off
        self.gpu_status_text = scrolledtext.ScrolledText(
            gpu_frame,
            height=6,
            font=('Courier', 9),
            wrap=tk.WORD,
            state='disabled',
            relief='sunken',
            background='#f5f5f5'
        )
        self.gpu_status_text.pack(fill='x', pady=(0, 4))
        self._gpu_status_set("Click '🔍 Detect GPU' to check GPU status")

        # Update the layers description label for the currently loaded value
        self._refresh_gpu_layers_desc()
        
        # ── OCR — Scanned PDF & Image Indexing ───────────────────────────────
        ocr_frame = ttk.LabelFrame(scrollable_frame,
                                   text="📄 OCR — Scanned PDFs & Image Files",
                                   padding=(10, 8))
        ocr_frame.pack(fill='x', padx=20, pady=(5, 10))

        # Determine live status
        _ocr_ready = RAG_AVAILABLE and getattr(_rag_engine, 'pytesseract', None) is not None
        try:
            import pytesseract as _pt
            _pt.get_tesseract_version()   # will throw if binary missing
            _ocr_ready = True
        except Exception:
            _ocr_ready = False

        _ocr_color = '#27ae60' if _ocr_ready else '#c0392b'
        _ocr_label = ("✅ OCR active  —  Tesseract detected"
                      if _ocr_ready else
                      "⚠️  Tesseract binary not found  —  reinstall AI Prowler to fix")
        ttk.Label(ocr_frame, text=_ocr_label,
                  font=('Arial', 9, 'bold'), foreground=_ocr_color).pack(anchor='w', pady=(0, 6))

        ttk.Label(ocr_frame, justify='left', font=('Arial', 9),
                  text="OCR is always enabled.  AI Prowler automatically detects and indexes:\n"
                       "  •  Scanned PDFs  (living trusts, contracts, court docs, old manuals)\n"
                       "  •  Standalone image files  (.jpg  .png  .tiff  .bmp  .gif)\n\n"
                       "How it works:  pdfplumber first tries to extract a text layer.  If fewer\n"
                       "than 150 characters are found the document is treated as image-only and\n"
                       "each page is rendered at 300 DPI then passed to Tesseract OCR."
                  ).pack(anchor='w')

        # ── OCR Debug controls ────────────────────────────────────────────────
        ocr_sep = ttk.Separator(ocr_frame, orient='horizontal')
        ocr_sep.pack(fill='x', pady=(10, 6))

        ttk.Label(ocr_frame, text="🔬 Debug",
                  font=('Arial', 9, 'bold')).pack(anchor='w', pady=(0, 4))

        ocr_debug_row = ttk.Frame(ocr_frame)
        ocr_debug_row.pack(fill='x', pady=(0, 4))

        self.ocr_debug_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            ocr_debug_row,
            text="Log full OCR text to Index Output tab while indexing",
            variable=self.ocr_debug_var,
            command=self._on_ocr_debug_change
        ).pack(side='left')

        ttk.Label(ocr_debug_row,
                  text="  (enables per-page OCR text in output — useful for checking accuracy)",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        ocr_log_row = ttk.Frame(ocr_frame)
        ocr_log_row.pack(fill='x', pady=(2, 0))

        ttk.Button(ocr_log_row, text="📋 View Last OCR Output",
                   command=self._show_ocr_log).pack(side='left', padx=(0, 8))

        ttk.Label(ocr_log_row,
                  text="Shows the raw text extracted from the last OCR'd PDF or image",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        # ── Ollama Server ─────────────────────────────────────────────────────
        ollama_frame = ttk.LabelFrame(scrollable_frame, text="Ollama Server", padding=(10, 6))
        ollama_frame.pack(fill='x', padx=20, pady=(5, 10))

        # ── Status light + Start / Stop / Refresh / Install buttons ───────────
        ollama_ctrl_row = ttk.Frame(ollama_frame)
        ollama_ctrl_row.pack(fill='x', pady=(2, 6))

        _ollama_dot_canvas = tk.Canvas(ollama_ctrl_row, width=14, height=14,
                                       bg=self.root.cget('bg'), highlightthickness=0)
        _ollama_dot_canvas.pack(side='left', padx=(0, 4))
        _ollama_dot = _ollama_dot_canvas.create_oval(2, 2, 12, 12,
                                                     fill='#aaaaaa', outline='')
        _ollama_status_var = tk.StringVar(value="⬤ Checking…")
        _ollama_status_lbl = ttk.Label(ollama_ctrl_row,
                                       textvariable=_ollama_status_var,
                                       font=('Arial', 9, 'bold'),
                                       foreground='gray')
        _ollama_status_lbl.pack(side='left', padx=(0, 16))

        def _update_ollama_light():
            """Check port 11434 synchronously and update dot + label immediately."""
            import socket as _sk
            # Show orange "checking" first so user sees instant feedback
            _ollama_dot_canvas.itemconfig(_ollama_dot, fill='#e67e00')
            _ollama_status_var.set('⬤ Checking…')
            _ollama_status_lbl.configure(foreground='#e67e00')
            self.root.update_idletasks()   # force orange to render before probe

            try:
                with _sk.create_connection(('127.0.0.1', 11434), timeout=0.5):
                    running = True
            except OSError:
                running = False

            colour = '#27ae60' if running else '#cc0000'
            text   = '⬤ Running'  if running else '⬤ Stopped'
            _ollama_dot_canvas.itemconfig(_ollama_dot, fill=colour)
            _ollama_status_var.set(text)
            _ollama_status_lbl.configure(foreground=colour)

        def _find_ollama_exe_local():
            """Return path to ollama.exe or None."""
            import shutil as _sh, os as _os
            local_app = _os.environ.get('LOCALAPPDATA', '')
            if local_app:
                cand = _os.path.join(local_app, 'Programs', 'Ollama', 'ollama.exe')
                if _os.path.isfile(cand):
                    return cand
            return _sh.which('ollama')

        def _start_ollama_manual():
            """Start the Ollama server manually."""
            import socket as _sk2
            try:
                with _sk2.create_connection(('127.0.0.1', 11434), timeout=0.5):
                    already_running = True
            except OSError:
                already_running = False

            if already_running:
                _update_ollama_light()
                self.status_var.set('Ollama is already running')
                return

            exe = _find_ollama_exe_local()
            if not exe:
                messagebox.showerror(
                    'Ollama Not Found',
                    'Ollama is not installed.\n\n'
                    "Click '\u2b07 Install Ollama' to download and install it,\n"
                    "then click Start Ollama here.")
                return

            _ollama_dot_canvas.itemconfig(_ollama_dot, fill='#e67e00')
            _ollama_status_var.set('\u2b24 Starting\u2026')
            _ollama_status_lbl.configure(foreground='#e67e00')
            self.status_var.set('Starting Ollama server\u2026')
            self.root.update_idletasks()

            try:
                if sys.platform == 'win32':
                    # Re-enable the service start type in case Stop previously
                    # set it to 'demand' — allows sc start to work again
                    subprocess.run('sc config ollama start= auto',
                                   shell=True,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
                    _si = subprocess.STARTUPINFO()
                    _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    _si.wShowWindow = 0
                    self._ollama_process = subprocess.Popen(
                        [exe, 'serve'], startupinfo=_si,
                        creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    self._ollama_process = subprocess.Popen(
                        [exe, 'serve'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                def _poll(attempts=0):
                    import socket as _sk3
                    try:
                        with _sk3.create_connection(('127.0.0.1', 11434), timeout=0.5):
                            alive = True
                    except OSError:
                        alive = False
                    if alive:
                        _update_ollama_light()
                        self.status_var.set(
                            f'Ollama started (PID: {self._ollama_process.pid})')
                    elif attempts < 16:
                        self.root.after(500, lambda: _poll(attempts + 1))
                    else:
                        _ollama_dot_canvas.itemconfig(_ollama_dot, fill='#cc0000')
                        _ollama_status_var.set('\u2b24 Start timeout')
                        _ollama_status_lbl.configure(foreground='#cc0000')
                        self.status_var.set('Ollama did not respond \u2014 check install')

                self.root.after(1000, _poll)

            except Exception as exc:
                messagebox.showerror('Start Failed', f'Could not start Ollama:\n{exc}')
                _update_ollama_light()

        def _stop_ollama_manual():
            """Stop Ollama completely and prevent Windows SCM from restarting it.

            Root cause of restart loop: Ollama registers as a Windows service with
            failure-action auto-restart. Killing the process alone is not enough —
            Windows SCM relaunches it immediately. The fix is to change the service
            start type to 'demand' (manual) BEFORE stopping, so SCM won't restart it.
            """
            _ollama_dot_canvas.itemconfig(_ollama_dot, fill='#e67e00')
            _ollama_status_var.set('\u2b24 Stopping\u2026')
            _ollama_status_lbl.configure(foreground='#e67e00')
            self.root.update_idletasks()

            # Terminate our own managed process if any
            if hasattr(self, '_ollama_process') and self._ollama_process:
                try:
                    self._ollama_process.terminate()
                    self._ollama_process.wait(timeout=3)
                except Exception:
                    try:
                        self._ollama_process.kill()
                    except Exception:
                        pass
                self._ollama_process = None

            if sys.platform == 'win32':
                import time as _time

                # CRITICAL: Change service to manual start BEFORE stopping.
                # This prevents Windows SCM from auto-restarting ollama.exe.
                subprocess.run('sc config ollama start= demand',
                               shell=True,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

                # Graceful service stop via SCM
                subprocess.run('sc stop ollama',
                               shell=True,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                _time.sleep(0.8)

                # Kill tray app so it cannot relaunch the server
                for tray_name in ('"ollama app.exe"', 'ollama_app.exe'):
                    subprocess.run(
                        f'taskkill /F /T /IM {tray_name}',
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)

                # Force-kill all ollama.exe processes (entire process tree)
                subprocess.run('taskkill /F /T /IM ollama.exe',
                               shell=True,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

            else:
                subprocess.run(['pkill', '-f', 'ollama'],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

            self.status_var.set('Ollama server stopped')
            self.root.after(2000, _update_ollama_light)

        def _install_ollama_server():
            """Open the Ollama download page in the browser."""
            import webbrowser
            webbrowser.open('https://ollama.com/download')
            messagebox.showinfo(
                "Install Ollama",
                "Your browser will open the Ollama download page.\n\n"
                "Steps:\n"
                "  1. Download and run OllamaSetup.exe\n"
                "  2. Wait for installation to complete\n"
                "  3. Click '▶ Start Ollama' above to start the server\n"
                "  4. Go to Browse & Install Model to download an AI model\n\n"
                "Recommended starter: llama3.2:3b  (~2 GB, good quality)"
            )

        # Buttons row
        ttk.Button(ollama_ctrl_row, text="▶ Start Ollama",
                   command=_start_ollama_manual).pack(side='left', padx=(0, 6))
        ttk.Button(ollama_ctrl_row, text="■ Stop",
                   command=_stop_ollama_manual).pack(side='left', padx=(0, 6))
        ttk.Button(ollama_ctrl_row, text="🔄 Refresh",
                   command=_update_ollama_light).pack(side='left', padx=(0, 16))
        ttk.Separator(ollama_ctrl_row, orient='vertical').pack(
            side='left', fill='y', pady=3, padx=(0, 12))
        ttk.Button(ollama_ctrl_row, text="⬇ Install Ollama",
                   command=_install_ollama_server).pack(side='left')

        # Auto-start checkbox
        auto_start_cb = ttk.Checkbutton(
            ollama_frame,
            text="Auto-start Ollama server when AI-Prowler opens",
            variable=self.auto_start_ollama_var,
            command=self._save_auto_start_setting
        )
        auto_start_cb.pack(anchor='w', pady=(2, 4))

        ttk.Label(ollama_frame,
                  text="• If enabled: AI Prowler starts Ollama automatically and closes it on exit\n"
                       "• If disabled: Use the Start/Stop buttons above or run 'ollama serve' manually",
                  foreground='gray', font=('Arial', 9), justify='left').pack(anchor='w')

        # Initial status check after UI settles
        self.root.after(1200, _update_ollama_light)
        
        # ── MCP — Claude Desktop Integration ─────────────────────────────────
        mcp_frame = ttk.LabelFrame(scrollable_frame,
                                   text="🔌 MCP — Claude Desktop Integration",
                                   padding=(10, 8))
        mcp_frame.pack(fill='x', padx=20, pady=(5, 10))

        # Status row: dot + label + Refresh button
        mcp_top_row = ttk.Frame(mcp_frame)
        mcp_top_row.pack(fill='x', pady=(0, 6))

        self._mcp_settings_dot_canvas = tk.Canvas(mcp_top_row, width=14, height=14,
                                                   highlightthickness=0,
                                                   bg=self.root.cget('bg'))
        self._mcp_settings_dot_canvas.pack(side='left', padx=(0, 5))
        self._mcp_settings_dot = self._mcp_settings_dot_canvas.create_oval(
            1, 1, 13, 13, fill='#aaaaaa', outline='#888888', width=1)

        self._mcp_detail_var = tk.StringVar(value="Click Refresh to check MCP status…")
        ttk.Label(mcp_top_row, textvariable=self._mcp_detail_var,
                  font=('Courier', 9), justify='left',
                  foreground='#333333').pack(side='left', padx=(0, 10))

        def _refresh_mcp_settings():
            info = self._check_mcp_status()
            self._mcp_detail_var.set(info['detail'])
            for canvas, dot in [
                (self._mcp_settings_dot_canvas, self._mcp_settings_dot),
                (self._mcp_dot_canvas,           self._mcp_dot),
            ]:
                canvas.itemconfig(dot, fill=info['dot_color'],
                                  outline=info['dot_color'])
            self._mcp_status_var.set(info['label'])
            self._mcp_status_lbl.configure(foreground=info['dot_color'])

        ttk.Button(mcp_top_row, text="🔄 Refresh",
                   command=_refresh_mcp_settings).pack(side='right')

        ttk.Separator(mcp_frame, orient='horizontal').pack(fill='x', pady=(4, 8))

        # ── Transport explanation ─────────────────────────────────────────────
        transport_frame = tk.Frame(mcp_frame, bg='#e8f4e8', relief='solid', bd=1)
        transport_frame.pack(fill='x', pady=(0, 8))
        tk.Label(transport_frame, justify='left', font=('Arial', 9),
                 bg='#e8f4e8', fg='#1a5c1a', padx=8, pady=6,
                 text=(
                     "🖥  Claude Desktop  →  uses STDIO (local process, no internet required, no Bearer token needed)\n"
                     "📱  Claude.ai web/mobile  →  uses HTTP via Cloudflare Tunnel (requires HTTP server + tunnel + Bearer token)\n\n"
                     "⚠️  If Claude Desktop only works when the HTTP server is ON, your config is wrong.\n"
                     "     Click 'Auto-configure Claude Desktop' below to fix it."
                 )).pack(anchor='w')

        mcp_btn_row = ttk.Frame(mcp_frame)
        mcp_btn_row.pack(fill='x', pady=(0, 6))

        def _auto_configure_claude_desktop():
            """
            Write the correct STDIO entry for AI-Prowler into claude_desktop_config.json.

            This is the ONLY correct way to configure Claude Desktop — it launches
            ai_prowler_mcp.py as a local subprocess over stdin/stdout (stdio transport).
            No HTTP server, no internet, no tunnel required.

            Also removes 'AI-Prowler-Remote' if present (HTTP URL entry — wrong for Desktop).
            """
            info = self._check_mcp_status()
            cp   = info.get('config_path')
            if cp is None:
                messagebox.showerror("Config Path Unknown",
                                     "Could not determine the Claude Desktop config path.")
                return

            # ── Resolve python.exe — NEVER pythonw.exe ───────────────────────
            # sys.executable may return pythonw.exe when AI-Prowler is launched
            # via a shortcut or file-association.  pythonw.exe redirects stdout
            # to NUL which completely destroys the stdio MCP JSON-RPC pipe.
            # Claude Desktop needs stdout as its communication channel.
            # Always force python.exe for the MCP server entry.
            py_exe = sys.executable
            if sys.platform == 'win32':
                import re as _re
                py_exe = _re.sub(r'(?i)pythonw\.exe$', 'python.exe', py_exe)

            mcp_script = str(Path(__file__).parent / 'ai_prowler_mcp.py')

            # Build the correct stdio entry
            stdio_entry = {
                "command": py_exe,
                "args":    [mcp_script],
                "env": {
                    "PYTHONNOUSERSITE":  "1",
                    "PYTHONIOENCODING":  "utf-8",
                    "PYTHONUNBUFFERED":  "1",
                    "PYTHONWARNINGS":    "ignore"
                }
            }

            # Load existing config (or start fresh)
            import json as _jcfg
            try:
                if cp.exists():
                    cfg = _jcfg.loads(cp.read_text(encoding='utf-8-sig'))
                else:
                    cfg = {}
            except Exception as _e:
                messagebox.showerror("Parse Error",
                                     f"Could not read existing config:\n{_e}\n\n"
                                     f"Path: {cp}")
                return

            servers = cfg.setdefault('mcpServers', {})

            # Detect and warn about the wrong HTTP entry
            removed_remote = False
            if 'AI-Prowler-Remote' in servers:
                removed_remote = True
                del servers['AI-Prowler-Remote']

            already_correct = (
                servers.get('AI-Prowler', {}).get('command') == py_exe and
                servers.get('AI-Prowler', {}).get('args') == [mcp_script] and
                'url' not in servers.get('AI-Prowler', {})
            )

            servers['AI-Prowler'] = stdio_entry

            # Write back with pretty formatting
            try:
                cp.parent.mkdir(parents=True, exist_ok=True)
                cp.write_text(
                    _jcfg.dumps(cfg, indent=2, ensure_ascii=False),
                    encoding='utf-8'
                )
            except Exception as _e:
                messagebox.showerror("Write Error",
                                     f"Could not write config file:\n{_e}\n\nPath: {cp}")
                return

            # Compose result message
            notes = []
            if removed_remote:
                notes.append("• Removed 'AI-Prowler-Remote' (HTTP entry — wrong for Desktop)")
            # Warn if we had to correct pythonw → python
            raw_exe = sys.executable
            if sys.platform == 'win32' and py_exe.lower() != raw_exe.lower():
                notes.append(f"• Fixed: pythonw.exe → python.exe (pythonw breaks stdio MCP)")
            if already_correct:
                notes.append("• Entry was already correct — refreshed to ensure it's up to date")
            else:
                notes.append("• Added correct stdio entry for Claude Desktop")
            notes.append(f"\nPython: {py_exe}")
            notes.append(f"Script: {mcp_script}")
            notes.append(f"\nConfig path:\n{cp}")
            notes.append("\nRestart Claude Desktop now to apply the change.")

            messagebox.showinfo("✅ Claude Desktop Configured",
                                "\n".join(notes))

            _refresh_mcp_settings()

            # Offer to restart Claude Desktop — must kill existing instance first
            if messagebox.askyesno("Restart Claude Desktop?",
                                   "Restart Claude Desktop now to apply the new configuration?\n\n"
                                   "(The existing Claude Desktop window will be closed first.)"):
                try:
                    if sys.platform == 'win32':
                        # Kill existing Claude Desktop process before relaunching
                        subprocess.run(
                            'taskkill /F /IM claude.exe',
                            shell=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        import time as _t; _t.sleep(1.5)
                        subprocess.Popen(
                            'start shell:AppsFolder\\Claude_pzs8sxrjxfjjc!Claude',
                            shell=True)
                    elif sys.platform == 'darwin':
                        subprocess.run(['pkill', '-x', 'Claude'],
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
                        import time as _t; _t.sleep(1.5)
                        subprocess.Popen(['open', '-a', 'Claude'])
                except Exception:
                    messagebox.showinfo("Manual Restart Needed",
                                       "Please close and reopen Claude Desktop manually.")

        def _open_claude_config():
            """Open Claude Desktop config in Notepad (or default editor)."""
            info = self._check_mcp_status()
            cp = info.get('config_path')
            if cp is None:
                messagebox.showinfo("Config Path Unknown",
                                    "Could not determine the Claude Desktop config path\n"
                                    "for your platform.")
                return
            # Create the file with a skeleton if it doesn't exist yet
            if not cp.exists():
                try:
                    cp.parent.mkdir(parents=True, exist_ok=True)
                    cp.write_text('{\n  "mcpServers": {}\n}\n', encoding='utf-8')
                    messagebox.showinfo("Config Created",
                                        f"Created a new config file at:\n{cp}\n\n"
                                        f"Click 'Auto-configure Claude Desktop' to write the\n"
                                        f"correct entry automatically.")
                except Exception as e:
                    messagebox.showerror("Error", f"Could not create config file:\n{e}")
                    return
            try:
                if sys.platform == 'win32':
                    import subprocess as _sp
                    _sp.Popen(['notepad.exe', str(cp)])
                elif sys.platform == 'darwin':
                    import subprocess as _sp
                    _sp.Popen(['open', str(cp)])
                else:
                    import subprocess as _sp
                    _sp.Popen(['xdg-open', str(cp)])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open editor:\n{e}\n\nPath: {cp}")

        def _open_example_config():
            """Open claude_desktop_config_example.json in Notepad."""
            example = Path(__file__).parent / 'claude_desktop_config_example.json'
            if not example.exists():
                messagebox.showwarning("File Not Found",
                                       f"claude_desktop_config_example.json not found in:\n"
                                       f"{Path(__file__).parent}")
                return
            try:
                if sys.platform == 'win32':
                    import subprocess as _sp
                    _sp.Popen(['notepad.exe', str(example)])
                else:
                    import subprocess as _sp
                    _sp.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', str(example)])
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file:\n{e}")

        def _copy_config_path():
            """Copy the Claude Desktop config path to clipboard."""
            info = self._check_mcp_status()
            cp = info.get('config_path')
            if cp:
                self.root.clipboard_clear()
                self.root.clipboard_append(str(cp))
                self.status_var.set(f"📋 Copied: {cp}")
                self.root.after(3000, lambda: self.status_var.set("Ready"))

        # Primary action: auto-configure (prominent, first)
        ttk.Button(mcp_btn_row, text="⚙️ Auto-configure Claude Desktop",
                   command=_auto_configure_claude_desktop).pack(side='left', padx=(0, 8))

        # Secondary actions
        mcp_btn_row2 = ttk.Frame(mcp_frame)
        mcp_btn_row2.pack(fill='x', pady=(0, 4))
        ttk.Button(mcp_btn_row2, text="📂 Open Config File",
                   command=_open_claude_config).pack(side='left', padx=(0, 8))
        ttk.Button(mcp_btn_row2, text="📋 View Example Config",
                   command=_open_example_config).pack(side='left', padx=(0, 8))
        ttk.Button(mcp_btn_row2, text="📌 Copy Config Path",
                   command=_copy_config_path).pack(side='left', padx=(0, 8))
        ttk.Button(mcp_btn_row2, text="🔬 Run MCP Diagnostics",
                   command=self._run_mcp_diagnostics).pack(side='left')

        # Trigger an initial status check
        self.root.after(1500, _refresh_mcp_settings)

        # ── Remote Access ─────────────────────────────────────────────────────
        remote_frame = ttk.LabelFrame(scrollable_frame,
                                      text="📡 Remote Access — Claude on Mobile",
                                      padding=(10, 8))
        remote_frame.pack(fill='x', padx=20, pady=(5, 10))

        # Intro
        ttk.Label(remote_frame, justify='left', font=('Arial', 9),
                  text=("Query AI-Prowler from Claude on your phone via a Cloudflare Tunnel.\n"
                        "The HTTP server runs locally on this laptop; Cloudflare provides the secure public URL."),
                  foreground='gray').pack(anchor='w', pady=(0, 8))

        ttk.Separator(remote_frame, orient='horizontal').pack(fill='x', pady=(0, 8))

        # ── Token ─────────────────────────────────────────────────────────────
        ttk.Label(remote_frame, text="Bearer Token  (required — you choose the value):",
                  font=('Arial', 9, 'bold')).pack(anchor='w')
        ttk.Label(remote_frame, font=('Arial', 8), foreground='gray',
                  text="Paste this token into Claude mobile's MCP config. Anyone with this token can query your knowledge base.").pack(anchor='w', pady=(0, 4))

        token_row = ttk.Frame(remote_frame)
        token_row.pack(fill='x', pady=(0, 8))

        _remote_token_var = tk.StringVar()
        # Load saved token from config
        try:
            import json as _jmod
            _cfg_path = Path.home() / '.ai-prowler' / 'config.json'
            if _cfg_path.exists():
                _cfg_data = _jmod.loads(_cfg_path.read_text(encoding='utf-8'))
                _remote_token_var.set(_cfg_data.get('remote_token', ''))
        except Exception:
            pass

        _token_show_var = tk.BooleanVar(value=False)
        _token_entry = ttk.Entry(token_row, textvariable=_remote_token_var,
                                 show='●', width=42)
        _token_entry.pack(side='left', padx=(0, 6))

        def _toggle_token_show():
            _token_entry.configure(show='' if _token_show_var.get() else '●')
        ttk.Checkbutton(token_row, text="Show", variable=_token_show_var,
                        command=_toggle_token_show).pack(side='left', padx=(0, 10))

        def _save_remote_token():
            tok = _remote_token_var.get().strip()
            if not tok:
                messagebox.showwarning("Empty Token",
                                       "Token cannot be empty. Choose any string — e.g. MySecretToken123")
                return
            try:
                import json as _jmod
                _cfg_p = Path.home() / '.ai-prowler' / 'config.json'
                _cfg_p.parent.mkdir(parents=True, exist_ok=True)
                _cfg_d = {}
                if _cfg_p.exists():
                    try:
                        _cfg_d = _jmod.loads(_cfg_p.read_text(encoding='utf-8'))
                    except Exception:
                        pass
                _cfg_d['remote_token'] = tok
                _cfg_p.write_text(_jmod.dumps(_cfg_d, indent=2), encoding='utf-8')
                self.status_var.set("✅ Token saved")
                self.root.after(3000, lambda: self.status_var.set("Ready"))
            except Exception as _e:
                messagebox.showerror("Save Error", str(_e))

        ttk.Button(token_row, text="💾 Save Token",
                   command=_save_remote_token).pack(side='left')

        ttk.Separator(remote_frame, orient='horizontal').pack(fill='x', pady=(4, 8))

        # ── HTTP MCP Server ────────────────────────────────────────────────────
        # Header row with internet + subscription indicators
        http_hdr_row = ttk.Frame(remote_frame)
        http_hdr_row.pack(fill='x', pady=(0, 2))

        ttk.Label(http_hdr_row, text="HTTP MCP Server  (listens on localhost only):",
                  font=('Arial', 9, 'bold')).pack(side='left')

        # ── Internet status light ──────────────────────────────────────────────
        ttk.Label(http_hdr_row, text="  Internet:", font=('Arial', 8),
                  foreground='gray').pack(side='left', padx=(16, 2))
        _inet_canvas = tk.Canvas(http_hdr_row, width=14, height=14,
                                 bg=self.root.cget('bg'), highlightthickness=0)
        _inet_canvas.pack(side='left', padx=(0, 2))
        _inet_dot = _inet_canvas.create_oval(2, 2, 12, 12, fill='gray', outline='')
        _inet_lbl = ttk.Label(http_hdr_row, text="Checking…",
                              font=('Arial', 8), foreground='gray')
        _inet_lbl.pack(side='left', padx=(0, 12))

        # ── Subscription status light ──────────────────────────────────────────
        ttk.Label(http_hdr_row, text="Subscription:", font=('Arial', 8),
                  foreground='gray').pack(side='left', padx=(0, 2))
        _sub_canvas = tk.Canvas(http_hdr_row, width=14, height=14,
                                bg=self.root.cget('bg'), highlightthickness=0)
        _sub_canvas.pack(side='left', padx=(0, 2))
        _sub_dot = _sub_canvas.create_oval(2, 2, 12, 12, fill='gray', outline='')
        _sub_lbl = ttk.Label(http_hdr_row, text="Unknown",
                             font=('Arial', 8), foreground='gray')
        _sub_lbl.pack(side='left')

        # ── Shared subscription + internet check logic ─────────────────────────
        _SUBS_URL   = "https://raw.githubusercontent.com/dvavro/ai-prowler-subs/main/subs.json"
        _SUBS_CACHE = Path.home() / "AppData" / "Local" / "AI-Prowler" / "subs_cache.json"

        import hashlib as _hashlib, json as _json

        def _token_key(tok):
            return _hashlib.sha256(tok.encode()).hexdigest()[:16]

        def _check_internet() -> bool:
            """Quick connectivity check — tries to reach GitHub."""
            import urllib.request as _ur
            try:
                _ur.urlopen("https://github.com", timeout=4)
                return True
            except Exception:
                return False

        def _fetch_subs_gui() -> dict | None:
            """
            Fetch subs.json from the public GitHub registry.
            No authentication needed — repo is public (read-only for everyone,
            writable only by the repo owner via GitHub credentials).
            Saves successful fetches to a local cache for offline resilience.
            """
            import urllib.request as _ur
            try:
                req = _ur.Request(
                    _SUBS_URL,
                    headers={"User-Agent":    "AI-Prowler-GUI/1.0",
                             "Cache-Control": "no-cache"})
                with _ur.urlopen(req, timeout=8) as resp:
                    result = _json.loads(resp.read())
                    # Save to local cache for offline resilience
                    try:
                        _SUBS_CACHE.parent.mkdir(parents=True, exist_ok=True)
                        payload = {
                            "cached_at": __import__("datetime").date.today().isoformat(),
                            "data": result
                        }
                        _SUBS_CACHE.write_text(
                            _json.dumps(payload, indent=2), encoding="utf-8")
                    except Exception:
                        pass
                    return result
            except Exception:
                pass
            # Fallback to local cache if network unavailable
            try:
                if _SUBS_CACHE.exists():
                    raw = _json.loads(_SUBS_CACHE.read_text(encoding='utf-8'))
                    return raw.get('data')
            except Exception:
                pass
            return None
        def _check_subscription_gui(tok, subs_data) -> dict:
            """
            Returns dict with keys: status, name, days_left, message
            status: 'ok' | 'warning' | 'blocked' | 'unmanaged'
            """
            if not subs_data:
                return {'status': 'unmanaged', 'name': None, 'days_left': None,
                        'message': 'No registry — unmanaged/local mode'}
            key  = _token_key(tok)
            subs = subs_data.get('subscribers', {})
            if key not in subs:
                return {'status': 'unmanaged', 'name': None, 'days_left': None,
                        'message': 'Token not in managed registry — local mode'}
            entry    = subs[key]
            name     = entry.get('name', 'Subscriber')
            exp_str  = entry.get('expires', '')
            try:
                import datetime as _dt
                expiry    = _dt.date.fromisoformat(exp_str)
                today     = _dt.date.today()
                days_left = (expiry - today).days
            except ValueError:
                return {'status': 'unmanaged', 'name': name, 'days_left': None,
                        'message': f'Invalid expiry in registry for {name}'}

            _WARN_DAYS  = 30
            _GRACE_DAYS = 30
            if days_left >= 0:
                if days_left <= _WARN_DAYS:
                    return {'status': 'warning', 'name': name,
                            'days_left': days_left,
                            'message': f"Subscription expires in {days_left} day(s) — renewal recommended"}
                return {'status': 'ok', 'name': name, 'days_left': days_left,
                        'message': f'Active — {days_left} day(s) remaining'}
            days_over = -days_left
            if days_over <= _GRACE_DAYS:
                return {'status': 'warning', 'name': name, 'days_left': days_left,
                        'message': (f"Subscription EXPIRED {days_over} day(s) ago — "
                                    f"{_GRACE_DAYS - days_over} day(s) grace period remaining")}
            return {'status': 'blocked', 'name': name, 'days_left': days_left,
                    'message': (f"Remote access BLOCKED — subscription expired "
                                f"{days_over} day(s) ago and grace period has elapsed")}

        def _show_subscription_popup(sub_result):
            """Show a subscription info popup, reading instructions from file."""
            # Read instruction text
            instr_path = Path(__file__).parent / 'subscription_instructions.txt'
            try:
                instr_text = instr_path.read_text(encoding='utf-8')
            except Exception:
                instr_text = ("Contact david.vavro1@gmail.com to subscribe or renew.\n"
                              "Subscription instructions file not found in install folder.")

            status   = sub_result.get('status', 'unknown')
            name     = sub_result.get('name') or 'Unknown'
            msg      = sub_result.get('message', '')
            days_left = sub_result.get('days_left')

            # Choose title and header colour
            if status == 'blocked':
                title      = "🔒 Remote Access Blocked"
                hdr_colour = '#cc0000'
                hdr_text   = "Remote access is currently blocked."
            elif status == 'warning':
                title      = "⚠️  Subscription Expiring"
                hdr_colour = '#e67e00'
                hdr_text   = "Your subscription needs attention."
            else:
                title      = "ℹ️  Subscription Information"
                hdr_colour = '#27ae60'
                hdr_text   = "Subscription & Remote Access Information"

            win = tk.Toplevel(self.root)
            win.title(title)
            win.geometry("580x540")
            win.resizable(True, True)
            win.grab_set()

            # Status banner
            banner = tk.Frame(win, bg=hdr_colour)
            banner.pack(fill='x')
            tk.Label(banner, text=hdr_text, bg=hdr_colour, fg='white',
                     font=('Arial', 10, 'bold'), pady=8, padx=16).pack(anchor='w')
            if msg:
                tk.Label(banner, text=msg, bg=hdr_colour, fg='#ffe0e0',
                         font=('Arial', 8), pady=4, padx=16,
                         wraplength=540, justify='left').pack(anchor='w')

            # Instructions text area
            import tkinter.scrolledtext as _st
            txt = _st.ScrolledText(win, wrap='word', font=('Consolas', 9),
                                   bg='#1a1a1a', fg='#e0e0e0',
                                   padx=12, pady=10, relief='flat', bd=0)
            txt.pack(fill='both', expand=True, padx=0, pady=0)
            txt.insert('1.0', instr_text)
            txt.config(state='disabled')

            # Bottom buttons
            btn_row = tk.Frame(win, bg=win.cget('bg'))
            btn_row.pack(fill='x', pady=8, padx=16)
            tk.Button(btn_row, text="Close", width=10,
                      command=win.destroy).pack(side='right')
            def _open_email():
                import subprocess as _sp
                _sp.Popen(['start', 'mailto:david.vavro1@gmail.com'], shell=True)
            tk.Button(btn_row, text="📧  Email to Subscribe",
                      command=_open_email,
                      bg='#0f3460', fg='white',
                      relief='flat', padx=12).pack(side='right', padx=(0, 8))

        def _update_internet_light(online: bool):
            colour = '#27ae60' if online else '#cc0000'
            text   = 'Online' if online else 'Offline'
            _inet_canvas.itemconfig(_inet_dot, fill=colour)
            _inet_lbl.config(text=text, foreground=colour)

        def _update_sub_light(sub_result: dict):
            status    = sub_result.get('status', 'unmanaged')
            days_left = sub_result.get('days_left')

            if status == 'ok':
                # Paid and active — green
                colour = '#27ae60'
                text   = 'Active'

            elif status == 'warning':
                # Yellow — expiring soon (pre-expiry) or in 30-day grace countdown
                colour = '#d4ac0d'
                if days_left is not None and days_left < 0:
                    days_over = -days_left
                    _GRACE_DAYS = 30
                    remaining  = _GRACE_DAYS - days_over
                    text = f'Unpaid — {remaining}d left'
                elif days_left is not None:
                    text = f'Expiring in {days_left}d'
                else:
                    text = 'Expiring Soon'

            elif status == 'blocked':
                # Red — grace period elapsed, access denied
                colour = '#cc0000'
                text   = 'Access Blocked'

            else:
                # unmanaged — self-hosted / token not in managed registry — allow through
                colour = '#27ae60'
                text   = 'Self-hosted'

            _sub_canvas.itemconfig(_sub_dot, fill=colour)
            _sub_lbl.config(text=text, foreground=colour)

        _current_sub_result = [{'status': 'unmanaged', 'name': None,
                                  'days_left': None, 'message': 'Not yet checked'}]

        def _run_status_check():
            """Background thread: check internet + subscription, update lights."""
            def _worker():
                online = _check_internet()
                self.root.after(0, lambda: _update_internet_light(online))
                tok = _remote_token_var.get().strip()
                if tok:
                    subs_data  = _fetch_subs_gui()
                    sub_result = _check_subscription_gui(tok, subs_data)
                    _current_sub_result[0] = sub_result
                    self.root.after(0, lambda: _update_sub_light(sub_result))
                else:
                    # No token set — no mobile subscription configured
                    self.root.after(0, lambda: (
                        _sub_canvas.itemconfig(_sub_dot, fill='#cc0000'),
                        _sub_lbl.config(text='Not Subscribed', foreground='#cc0000')
                    ))
            threading.Thread(target=_worker, daemon=True).start()

        # Run an initial check after the UI has settled
        self.root.after(1500, _run_status_check)

        # Re-check every 5 minutes in the background
        def _schedule_recheck():
            _run_status_check()
            self.root.after(300_000, _schedule_recheck)
        self.root.after(300_000, _schedule_recheck)

        # ── HTTP server controls ───────────────────────────────────────────────
        http_ctrl_row = ttk.Frame(remote_frame)
        http_ctrl_row.pack(fill='x', pady=(4, 0))

        ttk.Label(http_ctrl_row, text="Port:").pack(side='left')
        _http_port_var = tk.StringVar(value='8000')
        ttk.Entry(http_ctrl_row, textvariable=_http_port_var, width=6).pack(side='left', padx=(4, 12))

        _http_status_var = tk.StringVar(value="⬤ Stopped")
        _http_status_lbl = ttk.Label(http_ctrl_row, textvariable=_http_status_var,
                                     foreground='#cc0000', font=('Arial', 9, 'bold'))
        _http_status_lbl.pack(side='left', padx=(0, 12))

        def _start_http_server():
            tok = _remote_token_var.get().strip()
            if not tok:
                messagebox.showwarning("No Token", "Save a Bearer token first.")
                return
            if self._http_server_proc is not None and self._http_server_proc.poll() is None:
                messagebox.showinfo("Already Running", "HTTP server is already running.")
                return

            # ── Subscription check before starting ────────────────────────────
            # Run in background to avoid freezing the UI during network check.
            # Subscription gate before starting the HTTP server:
            #   ok        → green,  start server
            #   warning   → yellow, show popup, start server (grace countdown)
            #   blocked   → red,    show popup, block server start
            #   unmanaged → red,    show popup, block server start
            #                       (token not in registry = no active subscription)
            def _pre_start_check():
                online     = _check_internet()
                subs_data  = _fetch_subs_gui() if online else None
                sub_result = _check_subscription_gui(tok, subs_data)
                _current_sub_result[0] = sub_result

                def _on_check_done():
                    _update_internet_light(online)
                    _update_sub_light(sub_result)
                    status = sub_result.get('status', 'unmanaged')

                    if status == 'blocked':
                        # Red light — subscription explicitly blocked, prevent server start
                        _http_status_var.set("⬤ Access Blocked")
                        _http_status_lbl.configure(foreground='#cc0000')
                        _show_subscription_popup(sub_result)
                        return

                    if status == 'warning':
                        # Yellow — show renewal reminder but allow server start
                        _show_subscription_popup(sub_result)

                    # ok or warning — proceed with server start
                    _do_start_server(tok)

                self.root.after(0, _on_check_done)

            _http_status_var.set("⬤ Checking…")
            _http_status_lbl.configure(foreground='#e67e00')
            threading.Thread(target=_pre_start_check, daemon=True).start()

        def _do_start_server(tok):
            """Actually launch the HTTP server subprocess after checks pass."""
            port = _http_port_var.get().strip()
            try:
                port = int(port)
            except ValueError:
                messagebox.showerror("Bad Port", f"Port must be a number, got: {port}")
                return
            import sys as _sys
            py_exe  = _sys.executable
            mcp_script = str(Path(__file__).parent / 'ai_prowler_mcp.py')
            try:
                import os as _os
                _env = _os.environ.copy()
                _env['PYTHONUNBUFFERED'] = '1'
                _env['PYTHONIOENCODING'] = 'utf-8'
                # Resolve the public base URL from the saved tunnel_domain
                _pub_base = ''
                try:
                    import json as _jlaunch
                    _cfg_p = Path.home() / '.ai-prowler' / 'config.json'
                    if _cfg_p.exists():
                        _cfg_d = _jlaunch.loads(_cfg_p.read_text(encoding='utf-8'))
                        _dom   = _cfg_d.get('tunnel_domain', '').strip()
                        if _dom:
                            _pub_base = _dom if _dom.startswith('http') else f'https://{_dom}'
                except Exception:
                    pass
                # Also check the live GUI field (may differ from saved config)
                _gui_domain = _tun_domain_var.get().strip()
                if _gui_domain and _gui_domain not in ('mcp.yourdomain.com',):
                    _pub_base = (_gui_domain if _gui_domain.startswith('http')
                                 else f'https://{_gui_domain}')

                _launch_args = [py_exe, '-u', mcp_script, '--transport', 'http',
                                '--port', str(port), '--token', tok]
                if _pub_base:
                    _launch_args += ['--public-base', _pub_base]

                self._http_server_proc = subprocess.Popen(
                    _launch_args,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1, env=_env,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                )
                _http_status_var.set("⬤ Starting…")
                _http_status_lbl.configure(foreground='#e67e00')

                # --- Primary method: poll after 3 seconds ---
                # If the process is still alive after 3s the server started OK.
                # This is more reliable than keyword scanning because uvicorn may
                # buffer output differently when stdout is a pipe.
                _proc_ref = self._http_server_proc
                def _poll_after_start():
                    if _proc_ref.poll() is None:   # still running = success
                        _http_status_var.set("⬤ Running")
                        _http_status_lbl.configure(foreground='#27ae60')
                        # Prevent Windows sleep while the MCP server is live
                        self._set_sleep_prevention(True)
                    # else — process died quickly; _watch_http will set Stopped/error
                self.root.after(3000, _poll_after_start)

                # --- Fallback method: scan stdout for keywords ---
                # Also watches for port-in-use errors and process exit.
                def _watch_http():
                    port_in_use = False
                    for line in _proc_ref.stdout:
                        line = line.rstrip()
                        # Immediately turn green if we see a ready marker
                        if any(kw in line for kw in
                               ('ready', 'Ready', 'running', 'Running',
                                'started', 'Started', 'StreamableHTTP',
                                'Application startup', 'Uvicorn running')):
                            self.root.after(0, lambda: (
                                _http_status_var.set("⬤ Running"),
                                _http_status_lbl.configure(foreground='#27ae60')
                            ))
                        # Detect port already in use
                        if ('address already in use' in line.lower() or
                                'only one usage of each socket' in line.lower() or
                                'error while attempting to bind' in line.lower()):
                            port_in_use = True
                    # Process exited — only update if we didn't already set Running
                    if port_in_use:
                        def _show_port_err():
                            _http_status_var.set("⬤ Port in use — close old server first")
                            _http_status_lbl.configure(foreground='#cc0000')
                            messagebox.showerror(
                                "Port Already In Use",
                                f"Port {_http_port_var.get()} is already in use.\n\n"
                                "If you started the server manually in a Command Prompt,\n"
                                "close that window first, then click Start HTTP Server again.")
                        self.root.after(0, _show_port_err)
                    else:
                        self.root.after(0, lambda: (
                            _http_status_var.set("⬤ Stopped"),
                            _http_status_lbl.configure(foreground='#cc0000')
                        ))
                threading.Thread(target=_watch_http, daemon=True).start()
            except Exception as _e:
                messagebox.showerror("Launch Error", str(_e))

        def _stop_http_server():
            if self._http_server_proc is None or self._http_server_proc.poll() is not None:
                _http_status_var.set("⬤ Stopped")
                _http_status_lbl.configure(foreground='#cc0000')
                self._set_sleep_prevention(False)   # ensure sleep is re-enabled
                return
            try:
                self._http_server_proc.terminate()
                self._http_server_proc.wait(timeout=5)
            except Exception:
                try:
                    self._http_server_proc.kill()
                except Exception:
                    pass
            self._http_server_proc = None
            _http_status_var.set("⬤ Stopped")
            _http_status_lbl.configure(foreground='#cc0000')
            # Restore normal Windows sleep/power management
            self._set_sleep_prevention(False)

        http_btn_row = ttk.Frame(remote_frame)
        http_btn_row.pack(fill='x', pady=(4, 8))
        ttk.Button(http_btn_row, text="▶ Start HTTP Server",
                   command=_start_http_server).pack(side='left', padx=(0, 6))
        ttk.Button(http_btn_row, text="■ Stop",
                   command=_stop_http_server).pack(side='left')

        ttk.Separator(remote_frame, orient='horizontal').pack(fill='x', pady=(0, 8))

        # ── cloudflared executable path helper ────────────────────────────────
        def _cf_exe():
            return str(Path(__file__).parent / 'cloudflared.exe')

        # ══════════════════════════════════════════════════════════════════════
        # Quick Tunnel  (Free, No Account Needed)
        # ══════════════════════════════════════════════════════════════════════
        qt_frame = ttk.LabelFrame(remote_frame,
                                   text="🚀 Quick Tunnel  (free, no Cloudflare account needed)",
                                   padding=(10, 8))
        qt_frame.pack(fill='x', pady=(0, 8))

        ttk.Label(qt_frame, font=('Arial', 8), foreground='gray', justify='left',
                  text=("One-click remote access — generates a temporary public URL.\n"
                        "URL changes each time you restart, but setup takes seconds. Great for testing or casual use.")
                  ).pack(anchor='w', pady=(0, 6))

        # Quick Tunnel controls row
        qt_ctrl_row = ttk.Frame(qt_frame)
        qt_ctrl_row.pack(fill='x', pady=(0, 4))

        _qt_status_var = tk.StringVar(value="⬤ Stopped")
        _qt_status_lbl = ttk.Label(qt_ctrl_row, textvariable=_qt_status_var,
                                    foreground='#cc0000', font=('Arial', 9, 'bold'))
        _qt_status_lbl.pack(side='left', padx=(0, 12))

        def _start_quick_tunnel():
            """Start a cloudflared Quick Tunnel pointing at the HTTP server.

            When the Quick Tunnel URL is captured, the HTTP server is
            automatically restarted with the tunnel URL as --public-base
            so the OAuth authorization endpoint matches what Claude sees.
            """
            # Check HTTP server is running
            if self._http_server_proc is None or self._http_server_proc.poll() is not None:
                messagebox.showwarning("HTTP Server Not Running",
                    "Start the HTTP server first (above), then click Quick Tunnel.")
                return
            # Check cloudflared exists
            cf_path = _cf_exe()
            if not Path(cf_path).exists():
                messagebox.showerror("cloudflared not found",
                    f"cloudflared.exe not found at:\n{cf_path}\n\n"
                    "Re-run the AI-Prowler installer or download cloudflared.exe\n"
                    "from https://developers.cloudflare.com/cloudflare-one/"
                    "connections/connect-apps/install-and-setup/installation/")
                return
            # Kill any existing quick tunnel
            if self._cloudflared_proc is not None and self._cloudflared_proc.poll() is None:
                try:
                    self._cloudflared_proc.terminate()
                    self._cloudflared_proc.wait(timeout=5)
                except Exception:
                    pass

            port = _http_port_var.get().strip() or '8000'
            _qt_status_var.set("⬤ Starting…")
            _qt_status_lbl.configure(foreground='#e67e00')
            _qt_url_var.set("Waiting for Cloudflare to assign URL…")

            def _run_quick_tunnel():
                try:
                    import os as _os
                    _env = _os.environ.copy()
                    self._cloudflared_proc = subprocess.Popen(
                        [cf_path, 'tunnel', '--url', f'http://localhost:{port}',
                         '--no-autoupdate', '--config', ''],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1, env=_env,
                        creationflags=(subprocess.CREATE_NO_WINDOW
                                       if sys.platform == 'win32' else 0)
                    )
                    # Scan output for the generated URL
                    url_found = False
                    for line in self._cloudflared_proc.stdout:
                        line = line.strip()
                        # cloudflared prints the URL like:
                        #   | https://random-words.trycloudflare.com |
                        if ('trycloudflare.com' in line
                                or '.cfargotunnel.com' in line):
                            import re
                            url_match = re.search(
                                r'(https://[a-zA-Z0-9\-]+\.trycloudflare\.com)',
                                line)
                            if not url_match:
                                url_match = re.search(
                                    r'(https://[a-zA-Z0-9\-]+\.cfargotunnel\.com)',
                                    line)
                            if url_match:
                                tunnel_url = url_match.group(1)
                                mcp_url = f"{tunnel_url}/mcp"
                                url_found = True
                                self.root.after(0, lambda u=mcp_url: (
                                    _qt_url_var.set(u),
                                    _qt_status_var.set("⬤ Running"),
                                    _qt_status_lbl.configure(
                                        foreground='#27ae60'),
                                ))
                        if self._cloudflared_proc.poll() is not None:
                            break

                    if not url_found:
                        self.root.after(0, lambda: (
                            _qt_status_var.set("⬤ Failed"),
                            _qt_status_lbl.configure(foreground='#cc0000'),
                            _qt_url_var.set(
                                "Quick Tunnel failed to start. "
                                "Check internet connection."),
                        ))
                    else:
                        self._cloudflared_proc.wait()
                        self.root.after(0, lambda: (
                            _qt_status_var.set("⬤ Stopped"),
                            _qt_status_lbl.configure(foreground='#cc0000'),
                            _qt_url_var.set("Quick Tunnel stopped."),
                        ))
                except Exception as exc:
                    self.root.after(0, lambda e=str(exc): (
                        _qt_status_var.set("⬤ Error"),
                        _qt_status_lbl.configure(foreground='#cc0000'),
                        _qt_url_var.set(f"Error: {e}"),
                    ))

            threading.Thread(target=_run_quick_tunnel, daemon=True).start()

        def _stop_quick_tunnel():
            """Stop the Quick Tunnel and restore the HTTP server's public-base
            to the Named Tunnel domain so switching back works seamlessly."""
            if (self._cloudflared_proc is None
                    or self._cloudflared_proc.poll() is not None):
                _qt_status_var.set("⬤ Stopped")
                _qt_status_lbl.configure(foreground='#cc0000')
                return
            try:
                self._cloudflared_proc.terminate()
                self._cloudflared_proc.wait(timeout=5)
            except Exception:
                try:
                    self._cloudflared_proc.kill()
                except Exception:
                    pass
            _qt_status_var.set("⬤ Stopped")
            _qt_status_lbl.configure(foreground='#cc0000')
            _qt_url_var.set("Quick Tunnel stopped.")

        ttk.Button(qt_ctrl_row, text="▶ Start Quick Tunnel",
                   command=_start_quick_tunnel).pack(side='left', padx=(0, 6))
        ttk.Button(qt_ctrl_row, text="⏹ Stop",
                   command=_stop_quick_tunnel).pack(side='left', padx=(0, 6))

        # URL display + copy button
        qt_url_frame = ttk.Frame(qt_frame)
        qt_url_frame.pack(fill='x', pady=(4, 2))

        ttk.Label(qt_url_frame, text="Your MCP URL:",
                  font=('Arial', 9, 'bold')).pack(side='left', padx=(0, 6))

        _qt_url_var = tk.StringVar(value="Not started")
        _qt_url_entry = ttk.Entry(qt_url_frame, textvariable=_qt_url_var,
                                   width=55, state='readonly')
        _qt_url_entry.pack(side='left', padx=(0, 6))

        def _copy_qt_url():
            url = _qt_url_var.get()
            if url and url.startswith('https://'):
                self.root.clipboard_clear()
                self.root.clipboard_append(url)
                self.status_var.set("✅ MCP URL copied to clipboard")
                self.root.after(3000, lambda: self.status_var.set("Ready"))
            else:
                messagebox.showinfo("Not Ready",
                                    "Start the Quick Tunnel first.")

        ttk.Button(qt_url_frame, text="📋 Copy URL",
                   command=_copy_qt_url).pack(side='left', padx=(0, 6))

        # Instructions + visual guide button
        instructions_row = ttk.Frame(qt_frame)
        instructions_row.pack(fill='x', pady=(4, 0))
        ttk.Label(instructions_row, font=('Arial', 8), foreground='gray',
                  justify='left',
                  text=("Steps: 1) Save Bearer Token above  "
                        "2) Start HTTP Server  3) Start Quick Tunnel\n"
                        "4) Copy URL  5) Paste into Claude.ai → Settings → "
                        "Connectors → Add MCP")
                  ).pack(side='left')
        ttk.Button(instructions_row,
                   text="📖 Connect Claude.ai →",
                   command=self.show_claude_connector_guide
                   ).pack(side='right', padx=(8, 0))

        ttk.Separator(remote_frame, orient='horizontal').pack(fill='x',
                                                               pady=(4, 8))

        # ══════════════════════════════════════════════════════════════════════
        # Named Tunnel  (Persistent URL, Requires Cloudflare Account)
        # ══════════════════════════════════════════════════════════════════════
        ttk.Label(remote_frame,
                  text="Named Tunnel  (persistent URL, requires Cloudflare account):",
                  font=('Arial', 9, 'bold')).pack(anchor='w')
        ttk.Label(remote_frame, font=('Arial', 8), foreground='gray',
                  text=("Create a free Cloudflare Zero Trust tunnel at "
                        "dash.cloudflare.com → Networks → Tunnels.\n"
                        "Enter your tunnel's public hostname and token below, "
                        "then click Activate.")
                  ).pack(anchor='w', pady=(0, 4))

        # ── Visual setup guides — text walkthroughs with deep links ──────────
        guide_row = ttk.Frame(remote_frame)
        guide_row.pack(fill='x', pady=(0, 6))
        ttk.Button(guide_row,
                   text="📖 Setup Cloudflare Tunnel  (step-by-step)",
                   command=self.show_cloudflare_setup_guide
                   ).pack(side='left', padx=(0, 6))
        ttk.Button(guide_row,
                   text="📖 Connect Claude.ai  (after tunnel is active)",
                   command=self.show_claude_connector_guide
                   ).pack(side='left')

        # ── Load saved tunnel settings ─────────────────────────────────────────
        _tun_name_var   = tk.StringVar(value='')
        _tun_domain_var = tk.StringVar(value='')
        try:
            import json as _jmod_rc
            _rc_path = Path.home() / '.ai-prowler' / 'config.json'
            if _rc_path.exists():
                _rc_data = _jmod_rc.loads(_rc_path.read_text(encoding='utf-8'))
                _tun_name_var.set(_rc_data.get('tunnel_name', ''))
                _tun_domain_var.set(_rc_data.get('tunnel_domain', ''))
        except Exception:
            pass

        # ── Activation frame ──────────────────────────────────────────────────
        act_frame = ttk.LabelFrame(remote_frame,
                                   text="One-Time Activation  (run once per machine)",
                                   padding=6)
        act_frame.pack(fill='x', pady=(0, 6))

        # Public hostname row
        host_row = ttk.Frame(act_frame)
        host_row.pack(fill='x', pady=(0, 4))
        ttk.Label(host_row, text="Public hostname:", width=18, anchor='w').pack(side='left')
        ttk.Entry(host_row, textvariable=_tun_domain_var, width=36).pack(side='left', padx=(4, 6))
        ttk.Label(host_row, text="(e.g. myname.mydomain.com)",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        # Tunnel token row
        _tun_token_var  = tk.StringVar()
        _tun_tok_show   = tk.BooleanVar(value=False)
        # Load saved tunnel token from config
        try:
            import json as _jmod_tt
            _tt_path = Path.home() / '.ai-prowler' / 'config.json'
            if _tt_path.exists():
                _tt_data = _jmod_tt.loads(_tt_path.read_text(encoding='utf-8'))
                _tun_token_var.set(_tt_data.get('tunnel_token', ''))
        except Exception:
            pass

        tok_row = ttk.Frame(act_frame)
        tok_row.pack(fill='x', pady=(0, 6))
        ttk.Label(tok_row, text="Tunnel token:", width=18, anchor='w').pack(side='left')
        _tun_tok_entry = ttk.Entry(tok_row, textvariable=_tun_token_var,
                                   show='●', width=36)
        _tun_tok_entry.pack(side='left', padx=(4, 6))
        def _toggle_tun_tok():
            _tun_tok_entry.configure(show='' if _tun_tok_show.get() else '●')
        ttk.Checkbutton(tok_row, text="Show", variable=_tun_tok_show,
                        command=_toggle_tun_tok).pack(side='left', padx=(0, 8))
        ttk.Label(tok_row, text="(from Cloudflare Zero Trust dashboard → Networks → Tunnels)",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        # Activate / Uninstall buttons + status
        act_btn_row = ttk.Frame(act_frame)
        act_btn_row.pack(fill='x', pady=(2, 0))

        _act_status_var = tk.StringVar(value="")
        _act_status_lbl = ttk.Label(act_frame, textvariable=_act_status_var,
                                    font=('Arial', 8), foreground='gray')
        _act_status_lbl.pack(anchor='w', pady=(4, 0))

        def _save_tunnel_settings(domain, tok):
            """Persist public hostname and tunnel token to AI-Prowler config."""
            try:
                import json as _jmod_sc
                _sc_path = Path.home() / '.ai-prowler' / 'config.json'
                _sc_path.parent.mkdir(parents=True, exist_ok=True)
                _sc_d = {}
                if _sc_path.exists():
                    try:
                        _sc_d = _jmod_sc.loads(_sc_path.read_text(encoding='utf-8'))
                    except Exception:
                        pass
                _sc_d['tunnel_domain'] = domain
                _sc_d['tunnel_token']  = tok
                _sc_path.write_text(_jmod_sc.dumps(_sc_d, indent=2), encoding='utf-8')
            except Exception:
                pass

        # ── Elevation helper ───────────────────────────────────────────────────
        def _run_elevated(exe: str, args_str: str, wait_secs: float = 5.0) -> bool:
            """
            Launch a command with UAC elevation using ShellExecuteW 'runas'.

            Windows Service Control Manager operations (service install/uninstall,
            net start/stop) always require Administrator privileges.  Calling them
            directly from a non-elevated process yields:
              "Cannot establish a connection to the service control manager: Access is denied."

            This helper triggers a UAC prompt so the user approves elevation once
            per operation.  Output cannot be captured from an elevated child process,
            so success/failure is determined afterwards by polling sc query.

            Returns True if the UAC launch was accepted, False if cancelled.
            wait_secs: how long to sleep while the elevated child runs.
            """
            import ctypes, time as _t
            ret = ctypes.windll.shell32.ShellExecuteW(
                None,     # parent hwnd
                "runas",  # verb — triggers UAC elevation prompt
                exe,      # executable
                args_str, # arguments
                None,     # working directory (inherit)
                0         # SW_HIDE — no extra console window
            )
            if ret <= 32:
                # User cancelled UAC or launch error (codes <= 32 are errors)
                return False
            _t.sleep(wait_secs)   # wait for the elevated child to finish
            return True

        def _activate_tunnel():
            """Install cloudflared as a Windows service using the tunnel token."""
            exe    = _cf_exe()
            domain = _tun_domain_var.get().strip()
            tok    = _tun_token_var.get().strip()

            if not domain:
                messagebox.showwarning("Missing Hostname",
                                       "Enter the public hostname for your Cloudflare tunnel\n"
                                       "(e.g. myname.mydomain.com)")
                return
            if not tok:
                messagebox.showwarning("Missing Token",
                                       "Paste your Cloudflare tunnel token.\n\n"
                                       "Get this from: Cloudflare Zero Trust dashboard\n"
                                       "→ Networks → Tunnels → your tunnel → Configure → Token")
                return
            if not Path(exe).exists():
                messagebox.showerror("cloudflared not found",
                                     f"cloudflared.exe not found at:\n{exe}\n\n"
                                     "Re-run the AI-Prowler installer.")
                return

            _act_status_var.set("⏳ Installing tunnel service…")
            _act_status_lbl.configure(foreground='#e67e00')

            def _do_activate():
                try:
                    import time as _t

                    # Step 1: If service already exists, stop and uninstall it first
                    # (sc query does NOT need elevation — read-only)
                    svc_check = subprocess.run(
                        ['sc', 'query', 'cloudflared'],
                        capture_output=True, text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    )
                    if svc_check.returncode == 0 and 'cloudflared' in svc_check.stdout.lower():
                        self.root.after(0, lambda: _act_status_var.set(
                            "⏳ Stopping existing service… (approve UAC if prompted)"))
                        # net stop requires elevation — use cmd.exe via runas
                        _run_elevated("cmd.exe", '/c "net stop cloudflared"', wait_secs=4)
                        self.root.after(0, lambda: _act_status_var.set(
                            "⏳ Removing old service… (approve UAC if prompted)"))
                        # cloudflared service uninstall requires elevation
                        _run_elevated(exe, 'service uninstall', wait_secs=3)

                    # Step 2: Fresh install — cloudflared service install requires elevation
                    self.root.after(0, lambda: _act_status_var.set(
                        "⏳ Installing tunnel service… (approve UAC if prompted)"))
                    launched = _run_elevated(exe, f'service install "{tok}"', wait_secs=6)

                    if not launched:
                        self.root.after(0, lambda: (
                            _act_status_var.set("❌ Activation cancelled — UAC prompt was denied"),
                            _act_status_lbl.configure(foreground='#cc0000')
                        ))
                        return

                    # Check result by polling sc query (no elevation needed)
                    svc_result = subprocess.run(
                        ['sc', 'query', 'cloudflared'],
                        capture_output=True, text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    )
                    if svc_result.returncode == 0:
                        _save_tunnel_settings(domain, tok)
                        self.root.after(0, lambda: (
                            _act_status_var.set("✅ Tunnel service installed successfully"),
                            _act_status_lbl.configure(foreground='#27ae60'),
                            _check_cf_service(),
                            _refresh_snippet()
                        ))
                    else:
                        self.root.after(0, lambda: (
                            _act_status_var.set("❌ Activation failed — service not found after install"),
                            _act_status_lbl.configure(foreground='#cc0000')
                        ))
                except Exception as _e:
                    self.root.after(0, lambda ex=_e: (
                        _act_status_var.set(f"❌ Error: {str(ex)[:80]}"),
                        _act_status_lbl.configure(foreground='#cc0000')
                    ))

            threading.Thread(target=_do_activate, daemon=True).start()

        def _uninstall_tunnel():
            """Remove the cloudflared Windows service."""
            exe = _cf_exe()
            if not Path(exe).exists():
                messagebox.showerror("cloudflared not found",
                                     f"cloudflared.exe not found:\n{exe}")
                return
            if not messagebox.askyesno("Uninstall Tunnel Service",
                                       "Remove the AI-Prowler tunnel service?\n\n"
                                       "You will be prompted to approve administrator access.\n"
                                       "You can re-activate it any time."):
                return
            def _do_uninstall():
                try:
                    # Stop the service first (requires elevation)
                    _act_status_var_local = _act_status_var
                    self.root.after(0, lambda: (
                        _act_status_var_local.set("⏳ Stopping service… (approve UAC if prompted)"),
                        _act_status_lbl.configure(foreground='#e67e00')
                    ))
                    _run_elevated("cmd.exe", '/c "net stop cloudflared"', wait_secs=4)

                    # Uninstall (requires elevation)
                    self.root.after(0, lambda: _act_status_var_local.set(
                        "⏳ Removing service… (approve UAC if prompted)"))
                    launched = _run_elevated(exe, 'service uninstall', wait_secs=4)

                    if not launched:
                        self.root.after(0, lambda: (
                            _act_status_var_local.set("❌ Uninstall cancelled — UAC prompt was denied"),
                            _act_status_lbl.configure(foreground='#cc0000')
                        ))
                        return

                    # Verify by polling sc query
                    svc_result = subprocess.run(
                        ['sc', 'query', 'cloudflared'],
                        capture_output=True, text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                    )
                    if svc_result.returncode != 0:  # non-zero = service not found = success
                        self.root.after(0, lambda: (
                            _act_status_var_local.set("🔌 Tunnel service removed"),
                            _act_status_lbl.configure(foreground='gray'),
                            _check_cf_service()
                        ))
                    else:
                        self.root.after(0, lambda: (
                            _act_status_var_local.set("⚠️ Service may still exist — check sc query cloudflared"),
                            _act_status_lbl.configure(foreground='#e67e00'),
                            _check_cf_service()
                        ))
                except Exception as _e:
                    self.root.after(0, lambda ex=_e: (
                        _act_status_var.set(f"❌ Uninstall error: {str(ex)[:80]}"),
                        _act_status_lbl.configure(foreground='#cc0000')
                    ))
            threading.Thread(target=_do_uninstall, daemon=True).start()

        ttk.Button(act_btn_row, text="⚡ Activate Tunnel Service",
                   command=_activate_tunnel).pack(side='left', padx=(0, 8))
        ttk.Button(act_btn_row, text="🔌 Uninstall Service",
                   command=_uninstall_tunnel).pack(side='left')

        # Tunnel start / stop
        tun_ctrl_row = ttk.Frame(remote_frame)
        tun_ctrl_row.pack(fill='x', pady=(4, 0))

        _tun_status_var = tk.StringVar(value="⬤ Tunnel stopped")
        _tun_status_lbl = ttk.Label(tun_ctrl_row, textvariable=_tun_status_var,
                                    foreground='#cc0000', font=('Arial', 9, 'bold'))
        _tun_status_lbl.pack(side='left', padx=(0, 12))

        # Check if cloudflared is already running as a Windows service
        # (installed via "cloudflared.exe service install" — runs automatically)
        def _check_cf_service():
            try:
                result = subprocess.run(
                    ['sc', 'query', 'cloudflared'],
                    capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                )
                if 'RUNNING' in result.stdout:
                    _tun_status_var.set("⬤ Tunnel active (Windows service)")
                    _tun_status_lbl.configure(foreground='#27ae60')
                else:
                    # Service stopped, not found, or query failed
                    _tun_status_var.set("⬤ Tunnel stopped")
                    _tun_status_lbl.configure(foreground='#cc0000')
            except Exception:
                pass
        # Check service status after GUI loads
        self.root.after(1000, _check_cf_service)

        # Poll every 30s to keep status current
        def _poll_cf_service():
            _check_cf_service()
            self.root.after(30000, _poll_cf_service)
        self.root.after(5000, _poll_cf_service)

        def _start_tunnel():
            """Start the cloudflared Windows service (requires elevation)."""
            def _do_start():
                launched = _run_elevated("cmd.exe", '/c "net start cloudflared"', wait_secs=5)
                if not launched:
                    self.root.after(0, lambda: (
                        _tun_status_var.set("⬤ Start cancelled"),
                        _tun_status_lbl.configure(foreground='#cc0000')
                    ))
                    return
                self.root.after(0, _check_cf_service)
            _tun_status_var.set("⬤ Starting… (approve UAC if prompted)")
            _tun_status_lbl.configure(foreground='#e67e00')
            threading.Thread(target=_do_start, daemon=True).start()

        def _stop_tunnel():
            """Stop the cloudflared Windows service (requires elevation)."""
            def _do_stop():
                launched = _run_elevated("cmd.exe", '/c "net stop cloudflared"', wait_secs=5)
                if not launched:
                    self.root.after(0, lambda: (
                        _tun_status_var.set("⬤ Stop cancelled"),
                        _tun_status_lbl.configure(foreground='#cc0000')
                    ))
                    return
                self.root.after(0, _check_cf_service)
            _tun_status_var.set("⬤ Stopping… (approve UAC if prompted)")
            _tun_status_lbl.configure(foreground='#e67e00')
            threading.Thread(target=_do_stop, daemon=True).start()

        tun_btn_row = ttk.Frame(remote_frame)
        tun_btn_row.pack(fill='x', pady=(4, 8))
        ttk.Button(tun_btn_row, text="▶ Start Tunnel",
                   command=_start_tunnel).pack(side='left', padx=(0, 6))
        ttk.Button(tun_btn_row, text="■ Stop Tunnel",
                   command=_stop_tunnel).pack(side='left')

        ttk.Separator(remote_frame, orient='horizontal').pack(fill='x', pady=(0, 8))

        # ── Claude Mobile Config snippet ───────────────────────────────────────
        ttk.Label(remote_frame, text="Claude.ai Web / Mobile Config Snippet:",
                  font=('Arial', 9, 'bold')).pack(anchor='w')
        ttk.Label(remote_frame, font=('Arial', 8), foreground='gray',
                  text=("For Claude.ai web or mobile ONLY — NOT for Claude Desktop.\n"
                        "In Claude.ai: Settings → MCP Servers → Add Server → paste URL and token.")
                  ).pack(anchor='w', pady=(0, 4))

        _snippet_text = tk.Text(remote_frame, height=8, font=('Courier', 8),
                                wrap='none', state='disabled')
        _snippet_text.pack(fill='x', pady=(0, 4))

        def _refresh_snippet():
            domain = _tun_domain_var.get().strip()
            tok    = _remote_token_var.get().strip() or '<your-token>'
            lines = [
                "{",
                '  "mcpServers": {',
                '    "AI-Prowler-Remote": {',
                f'      "url": "https://{domain}/mcp",',
                '      "headers": {',
                f'        "Authorization": "Bearer {tok}"',
                '      }',
                '    }',
                '  }',
                "}",
            ]
            snippet = "\n".join(lines)
            _snippet_text.configure(state='normal')
            _snippet_text.delete('1.0', tk.END)
            _snippet_text.insert('1.0', snippet)
            _snippet_text.configure(state='disabled')

        _refresh_snippet()

        snippet_btn_row = ttk.Frame(remote_frame)
        snippet_btn_row.pack(fill='x', pady=(0, 4))
        ttk.Button(snippet_btn_row, text="🔄 Refresh Snippet",
                   command=_refresh_snippet).pack(side='left', padx=(0, 8))

        def _copy_snippet():
            self.root.clipboard_clear()
            self.root.clipboard_append(_snippet_text.get('1.0', 'end-1c'))
            self.status_var.set("📋 Config snippet copied to clipboard")
            self.root.after(3000, lambda: self.status_var.set("Ready"))

        ttk.Button(snippet_btn_row, text="📋 Copy Snippet",
                   command=_copy_snippet).pack(side='left')

        # ══════════════════════════════════════════════════════════════════════
        # Privacy & Analytics — anonymous heartbeat opt-out toggle
        # ══════════════════════════════════════════════════════════════════════
        privacy_frame = ttk.LabelFrame(scrollable_frame,
                                       text="Privacy & Analytics",
                                       padding=10)
        privacy_frame.pack(fill='x', padx=20, pady=10)

        ttk.Label(privacy_frame, justify='left',
                  text=(
                    "AI-Prowler sends an anonymous daily heartbeat so I can "
                    "see how many people are using it and which versions are "
                    "in the wild.\n\n"
                    "What's sent: a random install ID, the AI-Prowler version, "
                    "your OS (e.g. 'Windows-11'), how many chunks are indexed, "
                    "and how many MCP tool calls happened in the last day.\n\n"
                    "What's NEVER sent: your name, email, IP, document content, "
                    "queries, file paths, anything identifying.\n\n"
                    "You can turn this off below. AI-Prowler keeps working "
                    "the same either way."
                  ),
                  wraplength=900,
                  font=('Arial', 9), foreground='#444444'
                  ).pack(anchor='w', pady=(0, 8))

        # Load current state
        _tel_cfg = self._telemetry_load_config()
        _tel_enabled_var = tk.BooleanVar(value=_tel_cfg['enabled'])

        def _on_tel_toggle():
            self._telemetry_save_config(enabled=_tel_enabled_var.get())
            _tel_status_var.set(
                "✓ Saved." if _tel_enabled_var.get()
                else "✗ Disabled. No heartbeats will be sent.")

        ttk.Checkbutton(privacy_frame,
                        text="Send anonymous usage heartbeat (recommended)",
                        variable=_tel_enabled_var,
                        command=_on_tel_toggle
                        ).pack(anchor='w')

        # Endpoint row — read-only display unless user clicks Edit
        ep_row = ttk.Frame(privacy_frame)
        ep_row.pack(fill='x', pady=(8, 4))
        ttk.Label(ep_row, text="Endpoint:", width=10, anchor='w'
                  ).pack(side='left')
        _tel_ep_var = tk.StringVar(value=_tel_cfg['endpoint'])
        _tel_ep_entry = ttk.Entry(ep_row, textvariable=_tel_ep_var,
                                   state='readonly', width=70)
        _tel_ep_entry.pack(side='left', padx=(4, 6))

        def _edit_endpoint():
            new = simpledialog.askstring(
                "Telemetry endpoint",
                "Cloudflare Worker URL (no trailing slash):",
                initialvalue=_tel_ep_var.get(),
                parent=self.root)
            if new and new.strip():
                _tel_ep_var.set(new.strip())
                self._telemetry_save_config(endpoint=new.strip())
                _tel_status_var.set("✓ Endpoint updated.")

        ttk.Button(ep_row, text="Edit", command=_edit_endpoint
                   ).pack(side='left')

        # Last-success indicator + Send Now (debug)
        info_row = ttk.Frame(privacy_frame)
        info_row.pack(fill='x', pady=(4, 4))

        _tel_last_var = tk.StringVar()
        def _refresh_tel_last():
            try:
                if self._telemetry_last_path.exists():
                    ts = self._telemetry_last_path.read_text(
                        encoding='utf-8').strip()
                    _tel_last_var.set(f"Last successful heartbeat: {ts}")
                else:
                    _tel_last_var.set("Last successful heartbeat: never")
            except Exception:
                _tel_last_var.set("Last successful heartbeat: unknown")
        _refresh_tel_last()
        ttk.Label(info_row, textvariable=_tel_last_var,
                  font=('Arial', 8), foreground='#666666'
                  ).pack(side='left')

        def _send_now():
            cfg = self._telemetry_load_config()
            if not cfg['enabled']:
                messagebox.showinfo(
                    "Telemetry disabled",
                    "Enable the checkbox above first.")
                return
            payload = self._telemetry_compose_payload()
            if payload is None:
                messagebox.showerror(
                    "Cannot send",
                    "install_id not available. Restart AI-Prowler "
                    "and try again.")
                return
            # If the user has set telemetry_admin_token in config, use
            # ?force=true to bypass the Worker's 12h throttle. Otherwise
            # send normally — the Worker will silently throttle if needed
            # and the local counter will be preserved.
            try:
                cfg_path = Path.home() / '.ai-prowler' / 'config.json'
                has_admin = False
                if cfg_path.exists():
                    full_cfg = json.loads(cfg_path.read_text(encoding='utf-8'))
                    has_admin = bool(full_cfg.get('telemetry_admin_token'))
            except Exception:
                has_admin = False

            threading.Thread(
                target=self._telemetry_send,
                args=(payload, cfg['endpoint']),
                kwargs={'force': has_admin},
                daemon=True).start()
            self.root.after(2000, _refresh_tel_last)
            if has_admin:
                _tel_status_var.set(
                    "Sent (force=true; throttle bypassed). "
                    "Check console for the result.")
            else:
                _tel_status_var.set(
                    "Sent. (Throttle may apply; set "
                    "'telemetry_admin_token' in config.json to bypass.) "
                    "Check console for the result.")

        ttk.Button(info_row, text="📡 Send Heartbeat Now",
                   command=_send_now
                   ).pack(side='right')

        _tel_status_var = tk.StringVar()
        ttk.Label(privacy_frame, textvariable=_tel_status_var,
                  font=('Arial', 8), foreground='#006600'
                  ).pack(anchor='w', pady=(2, 0))

        # About
        about_frame = ttk.LabelFrame(scrollable_frame, text="About", padding=10)
        about_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        about_text = f"""AI-Prowler — Agentic RAG Knowledge Base
Version {APP_VERSION}

Core:
• Agentic RAG — 13 MCP tools for Claude Desktop & Claude.ai
• 65+ file types: PDF, Word (.docx), Excel (.xlsx/.xls), PPTX, HTML, RTF, ODT, CSV, email, images
• Smart chunking — Column: Value context for all tabular data
• .docx tables fully extracted (was silently dropped in v4)
• Auto-purge deleted files from ChromaDB on every update run
• Automatic OCR for scanned PDFs and images
• Email indexing with deduplication
• Auto-start after Windows reboot (Task Scheduler)

Small Business (🏢 tab):
• 8 action tools: weather, routing, maps, QBO/QBD invoicing, spreadsheet updater
• Job Tracker spreadsheet pre-installed in Documents\AI-Prowler\

⚠  .doc / legacy .xls not supported — convert to .docx / .xlsx

Built with Python, ChromaDB, and Claude"""
        
        about_label = ttk.Label(about_frame, text=about_text, justify='left')
        about_label.pack(pady=10)

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 6 — SMALL BUSINESS SERVICE TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    def create_small_business_tab(self):
        """
        Dedicated tab for the 8 Small Business / Field Service MCP action tools.

        Sections (in order):
          1. Overview banner — what these tools do and how to invoke them
          2. Free Tools panel — weather, geocode, route, maps URL (no setup)
          3. QuickBooks Online panel — OAuth config, status light, save/test
          4. QuickBooks Desktop panel — pywin32 status, default item, test
          5. Job Spreadsheet Updater panel — usage guide + open-file shortcut
          6. Route & Navigation panel — OSRM/Nominatim notes + open Google Maps

        Configuration is read from / written to:
            ~/.ai-prowler/config.json
        (same file as the Settings tab uses for QBO tokens)
        """
        import json as _json

        outer = ttk.Frame(self.notebook)
        self.notebook.add(outer, text="🏢 Small Business")
        f = self._make_scrollable_tab(outer)

        # ── Config helpers (shared across all sub-panels) ─────────────────────
        _cfg_path = (
            __import__('pathlib').Path.home() / '.ai-prowler' / 'config.json'
        )

        def _load_cfg() -> dict:
            try:
                if _cfg_path.exists():
                    return _json.loads(_cfg_path.read_text(encoding='utf-8'))
            except Exception:
                pass
            return {}

        def _save_cfg(updates: dict):
            _cfg_path.parent.mkdir(parents=True, exist_ok=True)
            d = _load_cfg()
            d.update(updates)
            _cfg_path.write_text(_json.dumps(d, indent=2), encoding='utf-8')

        # ── 1. OVERVIEW BANNER ────────────────────────────────────────────────
        banner = ttk.LabelFrame(f, text="🔧 Small Business Service Tools — Overview",
                                padding=(12, 8))
        banner.pack(fill='x', padx=16, pady=(10, 6))

        ttk.Label(banner, justify='left', font=('Arial', 9),
                  text=(
                      "8 MCP tools that let Claude act as your field-service assistant.\n"
                      "Ask Claude in a conversation — no forms to fill out, no menus to navigate.\n\n"
                      "Free tools (weather, routing, maps) work immediately — no setup.\n"
                      "QuickBooks tools need one-time configuration in the panels below."
                  )).pack(anchor='w')

        # Claude prompt examples
        ex_frame = ttk.LabelFrame(banner, text="Example prompts to use with Claude",
                                  padding=(8, 4))
        ex_frame.pack(fill='x', pady=(8, 0))

        examples = [
            ("🌤  Weather",      '"What is the weather forecast for New Smyrna Beach for the next 3 days?"'),
            ("🗺  Route",        '"Optimize my route for these 6 jobs today and give me a Google Maps link."'),
            ("🧾  QBO Invoice",  '"Create a QuickBooks invoice for Miller Windows, window washing, $312, today."'),
            ("🖥  QB Desktop",   '"Create a QB Desktop invoice for Sam Cronin, pressure washing, $215, today."'),
            ("📊  Spreadsheet",  '"Mark the Miller Windows job complete in my jobs.xlsx and record invoice #1048."'),
            ("🔍  Status check", '"Call get_action_tools_status() and tell me what is ready to use."'),
        ]
        for icon_label, prompt in examples:
            row = ttk.Frame(ex_frame)
            row.pack(fill='x', pady=1)
            ttk.Label(row, text=icon_label, font=('Arial', 8, 'bold'),
                      width=16, anchor='w').pack(side='left')
            ttk.Label(row, text=prompt, font=('Arial', 8),
                      foreground='#555555', anchor='w').pack(side='left')

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 2. FREE TOOLS PANEL ───────────────────────────────────────────────
        free_frame = ttk.LabelFrame(f,
                                    text="✅ Free Tools — No API Key or Setup Required",
                                    padding=(12, 8))
        free_frame.pack(fill='x', padx=16, pady=(0, 6))

        free_tools = [
            ("get_weather(location, days)",
             "Current conditions + multi-day forecast via Open-Meteo.\n"
             "Flags rain ≥ 50 % with ⚠️. Use before scheduling outdoor jobs.",
             "Open-Meteo + Nominatim — free, no key"),

            ("geocode_address(address)",
             "Convert a street address to GPS coordinates (lat/lon).\n"
             "Useful for verifying job addresses before route planning.",
             "Nominatim / OpenStreetMap — free, no key"),

            ("get_route_optimization(stops, origin, …)",
             "Traveling Salesman solver — reorders your stops into the fastest\n"
             "driving sequence with estimated arrival times per stop.\n"
             "Geocodes ~20 addresses in ~6 s (0.35 s/address courtesy delay).",
             "OSRM public server + Nominatim — free, no key"),

            ("build_maps_url(stops, origin, app)",
             "Tap-to-navigate Google Maps (or Apple Maps) URL.\n"
             "Auto-splits routes > 9 stops into legs.\n"
             "Works on iPhone, Android, CarPlay, Android Auto.",
             "Google/Apple Maps URL scheme — free, no key"),
        ]

        for tool_name, description, backend in free_tools:
            tool_row = ttk.Frame(free_frame)
            tool_row.pack(fill='x', pady=(0, 8))
            ttk.Label(tool_row, text=f"✅  {tool_name}",
                      font=('Courier New', 9, 'bold'), foreground='#1a7a1a'
                      ).pack(anchor='w')
            ttk.Label(tool_row, text=description,
                      font=('Arial', 8), justify='left', foreground='#333333'
                      ).pack(anchor='w', padx=(20, 0))
            ttk.Label(tool_row, text=f"  {backend}",
                      font=('Arial', 8), foreground='gray'
                      ).pack(anchor='w', padx=(20, 0))

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 3. QUICKBOOKS ONLINE ──────────────────────────────────────────────
        qbo_outer = ttk.LabelFrame(f,
                                   text="🧾 QuickBooks Online  —  create_quickbooks_online_invoice()",
                                   padding=(12, 8))
        qbo_outer.pack(fill='x', padx=16, pady=(0, 6))

        ttk.Label(qbo_outer, justify='left', font=('Arial', 8), foreground='gray',
                  text=("One-time OAuth 2.0 setup — after connecting, tokens refresh automatically.\n"
                        "Requires an active QuickBooks Online subscription.")
                  ).pack(anchor='w', pady=(0, 6))

        # Status light row
        qbo_status_row = ttk.Frame(qbo_outer)
        qbo_status_row.pack(fill='x', pady=(0, 6))
        ttk.Label(qbo_status_row, text="Connection status:",
                  font=('Arial', 9)).pack(side='left')
        _qbo_dot_cv = tk.Canvas(qbo_status_row, width=14, height=14,
                                bg=self.root.cget('bg'), highlightthickness=0)
        _qbo_dot_cv.pack(side='left', padx=(8, 4))
        _qbo_dot = _qbo_dot_cv.create_oval(2, 2, 12, 12, fill='gray', outline='')
        _qbo_status_lbl = ttk.Label(qbo_status_row, text="Not configured",
                                    font=('Arial', 9), foreground='gray')
        _qbo_status_lbl.pack(side='left')

        def _refresh_qbo_status():
            cfg = _load_cfg()
            tok = cfg.get('qbo_access_token', '').strip()
            rid = cfg.get('qbo_realm_id',     '').strip()
            if tok and rid:
                _qbo_dot_cv.itemconfig(_qbo_dot, fill='#2ecc71')
                _qbo_status_lbl.config(text="✅  Connected", foreground='#2ecc71')
                _qbo_realm_var.set(rid)
            else:
                _qbo_dot_cv.itemconfig(_qbo_dot, fill='gray')
                _qbo_status_lbl.config(text="Not configured", foreground='gray')

        # Company (Realm) ID
        realm_row = ttk.Frame(qbo_outer)
        realm_row.pack(fill='x', pady=(0, 4))
        ttk.Label(realm_row, text="Company ID (Realm ID):",
                  font=('Arial', 9), width=24, anchor='w').pack(side='left')
        _qbo_realm_var = tk.StringVar()
        ttk.Entry(realm_row, textvariable=_qbo_realm_var, width=30
                  ).pack(side='left', padx=4)
        ttk.Label(realm_row, text="Found in your QBO URL after /app/",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        # Access token
        token_row = ttk.Frame(qbo_outer)
        token_row.pack(fill='x', pady=(0, 4))
        ttk.Label(token_row, text="OAuth Access Token:",
                  font=('Arial', 9), width=24, anchor='w').pack(side='left')
        _qbo_tok_var = tk.StringVar()
        _qbo_tok_entry = ttk.Entry(token_row, textvariable=_qbo_tok_var,
                                   width=44, show='●')
        _qbo_tok_entry.pack(side='left', padx=4)
        _qbo_show_var = tk.BooleanVar(value=False)
        def _toggle_qbo():
            _qbo_tok_entry.configure(show='' if _qbo_show_var.get() else '●')
        ttk.Checkbutton(token_row, text="Show",
                        variable=_qbo_show_var,
                        command=_toggle_qbo).pack(side='left')

        # Refresh token
        ref_row = ttk.Frame(qbo_outer)
        ref_row.pack(fill='x', pady=(0, 4))
        ttk.Label(ref_row, text="OAuth Refresh Token:",
                  font=('Arial', 9), width=24, anchor='w').pack(side='left')
        _qbo_ref_var = tk.StringVar()
        _qbo_ref_entry = ttk.Entry(ref_row, textvariable=_qbo_ref_var,
                                   width=44, show='●')
        _qbo_ref_entry.pack(side='left', padx=4)
        _qbo_ref_show = tk.BooleanVar(value=False)
        def _toggle_ref():
            _qbo_ref_entry.configure(show='' if _qbo_ref_show.get() else '●')
        ttk.Checkbutton(ref_row, text="Show",
                        variable=_qbo_ref_show,
                        command=_toggle_ref).pack(side='left')

        # Populate from saved config
        _init_cfg = _load_cfg()
        _qbo_realm_var.set(_init_cfg.get('qbo_realm_id',      ''))
        _qbo_tok_var.set(  _init_cfg.get('qbo_access_token',  ''))
        _qbo_ref_var.set(  _init_cfg.get('qbo_refresh_token', ''))

        def _save_qbo():
            tok = _qbo_tok_var.get().strip()
            rid = _qbo_realm_var.get().strip()
            ref = _qbo_ref_var.get().strip()
            if not (tok and rid):
                messagebox.showwarning(
                    "Missing Fields",
                    "Company ID and Access Token are both required.\n\n"
                    "Company ID:   found in your QuickBooks Online URL\n"
                    "              e.g. https://app.qbo.intuit.com/app/homepage\n"
                    "              → the number after /company/ is your Realm ID\n\n"
                    "Access Token: generated in the Intuit Developer portal\n"
                    "              (OAuth 2.0 — expires every 60 minutes)"
                )
                return
            _save_cfg({'qbo_access_token':  tok,
                       'qbo_realm_id':      rid,
                       'qbo_refresh_token': ref})
            _refresh_qbo_status()
            self.status_var.set("✅  QuickBooks Online credentials saved")
            self.root.after(3000, lambda: self.status_var.set("Ready"))

        def _clear_qbo():
            if messagebox.askyesno("Clear QBO Credentials",
                                   "Remove saved QuickBooks Online tokens?"):
                _save_cfg({'qbo_access_token': '', 'qbo_realm_id': '',
                           'qbo_refresh_token': ''})
                _qbo_realm_var.set('')
                _qbo_tok_var.set('')
                _qbo_ref_var.set('')
                _refresh_qbo_status()
                self.status_var.set("QBO credentials cleared")
                self.root.after(3000, lambda: self.status_var.set("Ready"))

        qbo_btn_row = ttk.Frame(qbo_outer)
        qbo_btn_row.pack(fill='x', pady=(8, 0))
        ttk.Button(qbo_btn_row, text="💾  Save QBO Credentials",
                   command=_save_qbo).pack(side='left', padx=(0, 8))
        ttk.Button(qbo_btn_row, text="🗑  Clear Credentials",
                   command=_clear_qbo).pack(side='left', padx=(0, 8))
        ttk.Button(qbo_btn_row, text="🌐  Open QuickBooks Online",
                   command=lambda: webbrowser.open("https://app.qbo.intuit.com")
                   ).pack(side='left')

        ttk.Label(qbo_outer, font=('Arial', 8), foreground='gray',
                  justify='left',
                  text=("\nHow to get your tokens:\n"
                        "  1. Sign in to developer.intuit.com\n"
                        "  2. Create an app → OAuth 2.0 → Generate tokens\n"
                        "  3. Paste the access token above (valid 60 min — use refresh token for auto-renewal)\n"
                        "  4. Company ID is the number in your QBO URL: .../company/12345678/...")
                  ).pack(anchor='w', pady=(4, 0))

        _refresh_qbo_status()

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 4. QUICKBOOKS DESKTOP ─────────────────────────────────────────────
        qbd_outer = ttk.LabelFrame(f,
                                   text="🖥  QuickBooks Desktop  —  create_quickbooks_desktop_invoice()",
                                   padding=(12, 8))
        qbd_outer.pack(fill='x', padx=16, pady=(0, 6))

        ttk.Label(qbd_outer, justify='left', font=('Arial', 8), foreground='gray',
                  text=("Uses Windows COM automation (QBSDK) — no internet or OAuth needed.\n"
                        "QuickBooks Desktop must be open with a company file loaded when invoicing.")
                  ).pack(anchor='w', pady=(0, 6))

        # pywin32 status
        try:
            import win32com.client as _test_win32  # noqa: F401
            _win32_ok = True
        except ImportError:
            _win32_ok = False

        qbd_status_row = ttk.Frame(qbd_outer)
        qbd_status_row.pack(fill='x', pady=(0, 6))
        _qbd_dot_cv = tk.Canvas(qbd_status_row, width=14, height=14,
                                bg=self.root.cget('bg'), highlightthickness=0)
        _qbd_dot_cv.pack(side='left', padx=(0, 4))
        _qbd_dot_cv.create_oval(2, 2, 12, 12,
                                fill='#2ecc71' if _win32_ok else '#e74c3c',
                                outline='')
        ttk.Label(qbd_status_row,
                  text=("✅  pywin32 installed — ready for QuickBooks Desktop"
                        if _win32_ok else
                        "❌  pywin32 not installed — run:  pip install pywin32"),
                  font=('Arial', 9),
                  foreground='#2ecc71' if _win32_ok else '#e74c3c'
                  ).pack(side='left')

        # Default service item name
        item_row = ttk.Frame(qbd_outer)
        item_row.pack(fill='x', pady=(0, 4))
        ttk.Label(item_row, text="Default service item name:",
                  font=('Arial', 9), width=26, anchor='w').pack(side='left')
        _qbd_item_var = tk.StringVar()
        _qbd_item_var.set(_load_cfg().get('qbd_default_item', 'Services'))
        ttk.Entry(item_row, textvariable=_qbd_item_var, width=24
                  ).pack(side='left', padx=4)
        ttk.Label(item_row, text="Must exist in your QuickBooks item list",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        def _save_qbd():
            _save_cfg({'qbd_default_item': _qbd_item_var.get().strip() or 'Services'})
            self.status_var.set("✅  QuickBooks Desktop settings saved")
            self.root.after(3000, lambda: self.status_var.set("Ready"))

        def _test_qbd():
            if not _win32_ok:
                messagebox.showerror(
                    "pywin32 Required",
                    "Install pywin32 first:\n\n"
                    "  pip install pywin32\n\n"
                    "Then restart AI-Prowler."
                )
                return
            try:
                import win32com.client as _w32
                qb     = _w32.Dispatch("QBXMLRP2.RequestProcessor")
                qb.OpenConnection("", "AI-Prowler Test")
                ticket = qb.BeginSession("", 1)
                qb.EndSession(ticket)
                qb.CloseConnection()
                messagebox.showinfo(
                    "QB Desktop Connected ✅",
                    "Successfully connected to QuickBooks Desktop.\n"
                    "AI-Prowler can create invoices automatically."
                )
            except Exception as exc:
                messagebox.showerror(
                    "QB Desktop Connection Failed",
                    f"{exc}\n\n"
                    "Make sure:\n"
                    "  1. QuickBooks Desktop is open\n"
                    "  2. A company file is loaded\n"
                    "  3. Allow AI-Prowler access in the QB confirmation dialog"
                )

        qbd_btn_row = ttk.Frame(qbd_outer)
        qbd_btn_row.pack(fill='x', pady=(8, 0))
        ttk.Button(qbd_btn_row, text="💾  Save Settings",
                   command=_save_qbd).pack(side='left', padx=(0, 8))
        ttk.Button(qbd_btn_row, text="🔗  Test QB Desktop Connection",
                   command=_test_qbd).pack(side='left', padx=(0, 8))

        if not _win32_ok:
            def _install_pywin32():
                import subprocess as _sp
                from pathlib import Path as _P
                py = str(_P.home() / "AppData" / "Local" / "Programs"
                         / "Python" / "Python311" / "python.exe")
                try:
                    _sp.Popen([py, "-m", "pip", "install", "pywin32>=306"],
                              creationflags=_sp.CREATE_NEW_CONSOLE)
                    messagebox.showinfo(
                        "Installing pywin32",
                        "pip install is running in a new window.\n"
                        "Restart AI-Prowler when it completes."
                    )
                except Exception as exc:
                    messagebox.showerror("Install Failed", str(exc))
            ttk.Button(qbd_btn_row, text="⬇️  Install pywin32 Now",
                       command=_install_pywin32).pack(side='left')

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 5. JOB SPREADSHEET UPDATER ────────────────────────────────────────
        xl_outer = ttk.LabelFrame(f,
                                  text="📊 Job Spreadsheet Updater  —  update_job_spreadsheet()",
                                  padding=(12, 8))
        xl_outer.pack(fill='x', padx=16, pady=(0, 6))

        ttk.Label(xl_outer, justify='left', font=('Arial', 8), foreground='gray',
                  text=("Finds a customer row in your .xlsx job tracker by name and writes new\n"
                        "values to any columns (status, invoice #, amount, last service date, etc.).\n"
                        "Uses openpyxl — already installed, no extra packages needed.")
                  ).pack(anchor='w', pady=(0, 6))

        # Usage example
        usage_frame = ttk.LabelFrame(xl_outer, text="Example Claude prompt", padding=(8, 4))
        usage_frame.pack(fill='x', pady=(0, 6))
        usage_text = (
            '"Update my jobs spreadsheet C:/Users/Dave/Documents/jobs.xlsx:\n'
            ' Find the Miller Windows row and set Status = Complete,\n'
            ' Last Service = 2026-03-30, Invoice # = 1048, Amount = 312.00"'
        )
        ttk.Label(usage_frame, text=usage_text, font=('Arial', 8),
                  foreground='#444444', justify='left').pack(anchor='w')

        # Default spreadsheet path config
        xl_path_row = ttk.Frame(xl_outer)
        xl_path_row.pack(fill='x', pady=(4, 0))
        ttk.Label(xl_path_row, text="Default spreadsheet path:",
                  font=('Arial', 9), width=26, anchor='w').pack(side='left')
        _xl_path_var = tk.StringVar()
        _xl_path_var.set(_load_cfg().get('default_spreadsheet_path', ''))
        ttk.Entry(xl_path_row, textvariable=_xl_path_var, width=44
                  ).pack(side='left', padx=4)

        def _browse_xl():
            from tkinter import filedialog as _fd
            path = _fd.askopenfilename(
                title="Select default job spreadsheet",
                filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")]
            )
            if path:
                _xl_path_var.set(path.replace('/', '\\'))

        ttk.Button(xl_path_row, text="Browse…",
                   command=_browse_xl).pack(side='left')

        xl_hint = ttk.Label(xl_outer,
                            text="Setting a default path lets you just say 'update my jobs spreadsheet' without specifying the full path.",
                            font=('Arial', 8), foreground='gray', justify='left')
        xl_hint.pack(anchor='w', pady=(2, 0))

        def _save_xl():
            _save_cfg({'default_spreadsheet_path': _xl_path_var.get().strip()})
            self.status_var.set("✅  Default spreadsheet path saved")
            self.root.after(3000, lambda: self.status_var.set("Ready"))

        def _open_xl():
            path = _xl_path_var.get().strip()
            if path and __import__('os').path.exists(path):
                __import__('os').startfile(path)
            else:
                messagebox.showinfo("No Spreadsheet",
                                    "Set and save a default spreadsheet path first,\n"
                                    "or open your spreadsheet manually from File Explorer.")

        xl_btn_row = ttk.Frame(xl_outer)
        xl_btn_row.pack(fill='x', pady=(8, 0))
        ttk.Button(xl_btn_row, text="💾  Save Default Path",
                   command=_save_xl).pack(side='left', padx=(0, 8))
        ttk.Button(xl_btn_row, text="📂  Open Spreadsheet Now",
                   command=_open_xl).pack(side='left')

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 6. ROUTE & NAVIGATION NOTES ──────────────────────────────────────
        route_outer = ttk.LabelFrame(f,
                                     text="🗺  Route Optimization & Navigation  —  Free, No Key",
                                     padding=(12, 8))
        route_outer.pack(fill='x', padx=16, pady=(0, 10))

        route_info = (
            "get_route_optimization(stops, origin, optimize_for, departure_hour, return_to_origin)\n"
            "  • Geocoding:   Nominatim / OpenStreetMap  (0.35 s/address courtesy delay)\n"
            "  • TSP solver:  OSRM public /trip endpoint — real street routing, free, no key\n"
            "  • Returns:     optimised stop order with estimated arrival time per stop\n"
            "  • Tip: 20 stops takes ~7 seconds to geocode — this is normal, not a bug\n\n"
            "build_maps_url(stops, origin, app='google')\n"
            "  • Generates a Google Maps URL with all stops pre-loaded in optimised order\n"
            "  • Auto-splits routes > 9 stops into legs (Google Maps URL limit)\n"
            "  • Works on iPhone (Google Maps app), Android, CarPlay, Android Auto\n"
            "  • Pass app='apple' for Apple Maps — iPhone/iPad only\n\n"
            "Typical workflow:\n"
            "  1. Tell Claude: \"Optimize my route for today's jobs\"\n"
            "  2. Claude calls get_route_optimization() → get optimised order\n"
            "  3. Claude calls build_maps_url() → tap-to-navigate link\n"
            "  4. Tap the link on your phone — Google Maps opens in navigation mode"
        )
        ttk.Label(route_outer, text=route_info, font=('Arial', 8),
                  foreground='#333333', justify='left').pack(anchor='w')

        route_btn_row = ttk.Frame(route_outer)
        route_btn_row.pack(fill='x', pady=(10, 0))
        ttk.Button(route_btn_row, text="🌐  Open Google Maps",
                   command=lambda: webbrowser.open("https://maps.google.com")
                   ).pack(side='left', padx=(0, 8))
        ttk.Button(route_btn_row, text="🍎  Open Apple Maps",
                   command=lambda: webbrowser.open("https://maps.apple.com")
                   ).pack(side='left')

    def create_status_bar(self):
        """Create status bar with MCP indicator."""
        status_frame = ttk.Frame(self.root, relief='sunken')
        status_frame.pack(side='bottom', fill='x')

        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                 anchor='w')
        status_label.pack(side='left', fill='x', expand=True, padx=5)

        # ── MCP status indicator (right side of status bar) ───────────────────
        mcp_sep = ttk.Separator(status_frame, orient='vertical')
        mcp_sep.pack(side='right', fill='y', padx=(4, 0))

        self._mcp_status_var = tk.StringVar(value="MCP: checking…")
        self._mcp_status_lbl = ttk.Label(status_frame,
                                         textvariable=self._mcp_status_var,
                                         font=('Arial', 9), foreground='#888888',
                                         cursor='hand2')
        self._mcp_status_lbl.pack(side='right', padx=(0, 6))
        self._mcp_status_lbl.bind('<Button-1>', lambda e: self._scroll_to_mcp_settings())

        self._mcp_dot_canvas = tk.Canvas(status_frame, width=12, height=12,
                                         highlightthickness=0,
                                         bg=self.root.cget('bg'))
        self._mcp_dot_canvas.pack(side='right', padx=(4, 0))
        self._mcp_dot = self._mcp_dot_canvas.create_oval(
            1, 1, 11, 11, fill='#aaaaaa', outline='#888888', width=1)

    # ── MCP status helpers ────────────────────────────────────────────────────

    def _check_mcp_status(self):
        """Return a dict describing MCP readiness.

        Checks (in order):
          1. ai_prowler_mcp.py exists alongside rag_gui.py
          2. 'mcp' Python package is importable
          3. Claude Desktop config file exists and references AI-Prowler

        Returns dict:
          state      : 'ready' | 'partial' | 'not_configured'
          dot_color  : hex colour for the indicator dot
          label      : short text for status bar
          detail     : multiline text for the Settings panel
          config_path: path to Claude Desktop config (may be None)
        """
        script_dir   = Path(__file__).parent.resolve()
        mcp_script   = script_dir / 'ai_prowler_mcp.py'

        # ── Check 1: MCP script present ──────────────────────────────────────
        script_ok = mcp_script.exists()

        # ── Check 2: mcp package importable ──────────────────────────────────
        pkg_ok = False
        try:
            import importlib
            importlib.util.find_spec('mcp')
            pkg_ok = True
        except Exception:
            pass

        # ── Check 3: Claude Desktop config ───────────────────────────────────
        config_path = None
        config_ok   = False
        config_note = ''
        if sys.platform == 'win32':
            appdata = os.environ.get('APPDATA', '')
            if appdata:
                config_path = Path(appdata) / 'Claude' / 'claude_desktop_config.json'
        elif sys.platform == 'darwin':
            config_path = Path.home() / 'Library' / 'Application Support' / 'Claude' / 'claude_desktop_config.json'
        else:
            config_path = Path.home() / '.config' / 'Claude' / 'claude_desktop_config.json'

        if config_path and config_path.exists():
            try:
                import json as _j
                cfg = _j.loads(config_path.read_text(encoding='utf-8-sig'))
                servers = cfg.get('mcpServers', {})
                if 'AI-Prowler' in servers:
                    entry = servers['AI-Prowler']
                    if 'url' in entry:
                        # HTTP URL entry — wrong for Claude Desktop
                        config_ok   = False
                        config_note = (
                            '❌ "AI-Prowler" entry uses HTTP URL (wrong for Desktop)\n'
                            '   This causes Claude Desktop to require the HTTP server.\n'
                            '   Click "Auto-configure Claude Desktop" to fix this now.'
                        )
                    elif 'command' in entry:
                        cmd = entry.get('command', '')
                        if 'pythonw' in cmd.lower():
                            config_ok   = False
                            config_note = (
                                '❌ "AI-Prowler" entry uses pythonw.exe (breaks stdio MCP)\n'
                                '   pythonw redirects stdout to NUL — MCP pipe is destroyed.\n'
                                '   Click "Auto-configure Claude Desktop" to fix this now.'
                            )
                        else:
                            config_ok   = True
                            config_note = '✅ "AI-Prowler" stdio entry found in Claude Desktop config'
                    else:
                        config_ok   = False
                        config_note = (
                            '⚠️  "AI-Prowler" entry is incomplete (no command or url)\n'
                            '   Click "Auto-configure Claude Desktop" to write the correct entry.'
                        )
                else:
                    config_note = (
                        '⚠️  Config file exists but no "AI-Prowler" entry yet\n'
                        '   Click "Auto-configure Claude Desktop" to add it automatically.'
                    )
            except Exception as _ce:
                config_note = f'⚠️  Could not parse Claude Desktop config: {_ce}'
        elif config_path:
            config_note = ('⚠️  Claude Desktop config file not found\n'
                           f'   Expected: {config_path}\n'
                           '   Install Claude Desktop, then click "Auto-configure Claude Desktop"')
        else:
            config_note = '⚠️  Unsupported platform for auto-detection'

        # ── Determine overall state ───────────────────────────────────────────
        if script_ok and pkg_ok and config_ok:
            state     = 'ready'
            dot_color = '#27ae60'   # green
            label     = 'MCP: Ready ●'
        elif script_ok and pkg_ok and 'HTTP URL' in config_note:
            state     = 'misconfigured'
            dot_color = '#e74c3c'   # red
            label     = 'MCP: Wrong config (HTTP) ●'
        elif script_ok and pkg_ok and 'pythonw' in config_note:
            state     = 'misconfigured'
            dot_color = '#e74c3c'   # red
            label     = 'MCP: Wrong config (pythonw) ●'
        elif script_ok and pkg_ok:
            state     = 'partial'
            dot_color = '#f5a623'   # amber
            label     = 'MCP: Not configured ●'
        else:
            state     = 'not_configured'
            dot_color = '#e74c3c'   # red
            label     = 'MCP: Not installed ●'

        script_note = ('✅ ai_prowler_mcp.py found' if script_ok
                       else f'❌ ai_prowler_mcp.py NOT found in {script_dir}')
        pkg_note    = ('✅ mcp Python package installed'
                       if pkg_ok else '❌ mcp package not installed — run: pip install mcp')

        detail = '\n'.join([script_note, pkg_note, config_note])
        return dict(state=state, dot_color=dot_color, label=label,
                    detail=detail, config_path=config_path)

    def _refresh_mcp_status_bar(self):
        """Update the MCP dot + label in the status bar (called once on startup)."""
        try:
            info = self._check_mcp_status()
            self._mcp_dot_canvas.itemconfig(self._mcp_dot,
                                            fill=info['dot_color'],
                                            outline=info['dot_color'])
            self._mcp_status_var.set(info['label'])
            fg = info['dot_color']
            self._mcp_status_lbl.configure(foreground=fg)
            # Also refresh the Settings panel detail text if it exists
            if hasattr(self, '_mcp_detail_var'):
                self._mcp_detail_var.set(info['detail'])
        except Exception:
            pass

    def _scroll_to_mcp_settings(self):
        """Switch to the Settings tab when the user clicks the MCP status label."""
        try:
            self.notebook.select(self._TAB_INDEX_SETTINGS)
        except Exception:
            pass
    
    # ── Ollama Prewarming ────────────────────────────────────────────────────

    def _on_chunks_changed(self, event=None):
        """User changed the Context Chunks dropdown — re-prewarm at the right size.

        The Context Chunks setting controls how many document chunks are stuffed
        into the prompt.  More chunks = larger prompt = larger num_ctx needed.

        Chunk count → worst-case tokens (× 2.0 calibrated) → num_ctx required
        ───────────────────────────────────────────────────────────────────────
        CALIBRATED from live Ollama data: actual ratio ~1.94 tokens/word.
        Using × 2.0 + 512 buffer to stay safely above the measured ratio.

        1b–8b  models: baseline 8,192  → max 3 chunks before reload
        14b–70b models: baseline 16,384 → max 9 chunks before reload

        Chunks  Tokens(×2.0)  num_ctx     Notes
        ──────  ────────────  ────────    ──────────────────────────────
        1       ~2,012        8,192       no reload ✅
        2       ~3,512        8,192       no reload ✅
        3       ~5,012        8,192       no reload ✅
        4       ~6,512        8,192       no reload ✅
        5       ~8,012        8,192       no reload ✅ (just fits!)
        6       ~9,512        10,240      ⚠ reload ~2min on CPU
        7       ~11,012       11,264      ⚠ reload ~3min on CPU
        10      ~15,512       16,384      ⚠ reload ~5min on CPU
        15      ~22,512       23,552      ⚠ reload ~8min on CPU
        20      ~29,512       30,720      ⚠ reload ~12min on CPU

        By re-prewarming here the model is ready at the right size
        when Ask Question fires — no surprise mid-query reload.
        """
        if not RAG_AVAILABLE:
            return

        chunks_str = self.chunks_var.get()
        if chunks_str.startswith("Auto"):
            n_chunks = 3   # conservative: always fits 8192 without reload
        else:
            # Strip warning suffix e.g. "7 ⚠reload" → 7
            try:
                n_chunks = int(chunks_str.split()[0])
            except (ValueError, IndexError):
                return

        # Calibrated estimate: 750 words/chunk × 2.0 tokens/word + 512 buffer + 300 response
        # Matches measured Ollama ratio of ~1.94 tokens/word with safety margin.
        import math
        estimated_tokens = (n_chunks * 750 * 2) + 512 + 300
        needed_ctx = max(8192, math.ceil(estimated_tokens / 1024) * 1024)
        default_ctx = get_model_num_ctx(self.current_model.get()) if RAG_AVAILABLE else 8192

        # Status messages for chunk changes suppressed — prewarm runs silently

        # Reset warmup — new chunk count means the model will reload
        self._warmup_reset()
        # Force a re-prewarm at the required context size
        self._prewarm_done = False
        self._prewarm_in_progress = False
        self._trigger_prewarm(num_ctx=needed_ctx)

    def _on_tab_changed(self, event=None):
        """Handle tab switches."""
        try:
            selected = self.notebook.index(self.notebook.select())
            if selected == self._TAB_INDEX_QUERY:
                self._trigger_prewarm()
            # Settings tab: no synchronous refresh — background poller keeps list current
        except Exception:
            pass

    def _check_and_start_ollama(self):
        """Check if Ollama is running, and start it if auto-start is enabled."""
        # Only proceed if auto-start is enabled
        if not self.auto_start_ollama_var.get():
            print("Auto-start Ollama: DISABLED (checkbox not checked)")
            return
        
        print("Auto-start Ollama: ENABLED - checking if Ollama is running...")
        self.status_var.set("Checking for Ollama server...")
        
        # Check if Ollama is already running
        if RAG_AVAILABLE and check_ollama_available():
            print("✓ Ollama is already running (not started by AI Prowler)")
            self.status_var.set("Ollama already running")
            return
        
        # Ollama not running and auto-start enabled - start it
        print("✓ Auto-starting Ollama server...")
        self.status_var.set("Starting Ollama server...")
        
        try:
            import subprocess
            import sys
            
            # Start Ollama in a new CMD window
            # CREATE_NEW_CONSOLE opens a separate window
            # The window stays open so user can see server logs
            if sys.platform == 'win32':
                if self.debug_view_var.get():
                    # Debug View ON — visible CMD window for server log inspection
                    print("  → Creating visible CMD window (Debug View mode)...")
                    self._ollama_process = subprocess.Popen(
                        ['ollama', 'serve'],
                        creationflags=subprocess.CREATE_NEW_CONSOLE
                    )
                    print("  → CMD window visible on desktop.")
                else:
                    # Debug View OFF — completely hidden, no CMD window on desktop
                    print("  → Starting Ollama silently in background...")
                    _si = subprocess.STARTUPINFO()
                    _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    _si.wShowWindow = 0   # SW_HIDE
                    self._ollama_process = subprocess.Popen(
                        ['ollama', 'serve'],
                        startupinfo=_si,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    print("  → Ollama running silently (no CMD window).")
            else:
                # Linux/Mac — always background
                self._ollama_process = subprocess.Popen(
                    ['ollama', 'serve'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            
            print(f"✓ Ollama server started (PID: {self._ollama_process.pid})")
            print("  → CMD window will close automatically when AI Prowler exits")
            self.status_var.set(f"Ollama server started (PID: {self._ollama_process.pid})")
            
            # Give Ollama a few seconds to start up
            import time
            time.sleep(3)
            
        except FileNotFoundError:
            print("ERROR: 'ollama' command not found!")
            print("Please install Ollama or add it to your PATH")
            messagebox.showerror(
                "Ollama Not Found",
                "Could not find 'ollama' command.\n\n"
                "Please install Ollama or add it to your system PATH.\n\n"
                "You can disable auto-start in Settings."
            )
        except Exception as e:
            print(f"ERROR starting Ollama: {e}")
            messagebox.showerror(
                "Ollama Start Failed",
                f"Failed to start Ollama server:\n{e}\n\n"
                "You can disable auto-start in Settings."
            )

    def _trigger_prewarm(self, num_ctx: int = None):
        """Start a background prewarm if one isn't already running or done.

        Args:
            num_ctx: If provided, prewarm the model at this context size.
                     Pass the value returned by safe_num_ctx_for_prompt() when
                     the user has selected a large chunk count (10/15/20) so the
                     model is ready at exactly the right size before querying.
                     None = calculate for Auto mode (3 chunks = 8192 context).
        """
        if self._prewarm_in_progress:
            return
        if self._prewarm_done and num_ctx is None:
            return   # already warm at default ctx, nothing to do
        if not RAG_AVAILABLE:
            return
        
        # If num_ctx not specified, calculate for Auto mode (3 chunks)
        if num_ctx is None:
            import math
            n_chunks = 3  # Auto mode default
            estimated_tokens = (n_chunks * 750 * 2) + 512 + 300
            num_ctx = max(8192, math.ceil(estimated_tokens / 1024) * 1024)
        
        self._prewarm_in_progress = True
        self._prewarm_done   = False
        self._ollama_loading = True
        self._ollama_ready   = False
        self.output_queue.put(('ollama_status', 'loading'))
        self.status_var.set("⚡ Loading AI model into memory...")
        thread = threading.Thread(target=self._prewarm_worker,
                                  kwargs={'num_ctx': num_ctx}, daemon=True)
        thread.start()

    def _prewarm_worker(self, num_ctx: int = None):
        """
        Background thread: prewarm BOTH the embedding model and Ollama in parallel,
        then send a test query to warm the KV cache.

        - Embedding model (all-MiniLM-L6-v2): loaded via get_chroma_client() and
          cached — all subsequent searches return instantly.
        - Ollama LLM: loaded via an empty /api/generate call with keep_alive=0 
          (no auto-unload - model stays loaded until exit).
          num_ctx is passed through so the model is loaded at exactly the right
          context size for the current chunk count selection.
        - Test query: After loading, send a simple test question to warm the KV cache.
          When response completes, turn warmup indicator green.

        Both embedding and Ollama load simultaneously so time = max(embed_time, ollama_time).
        Then the test query runs to fully warm the system.
        """
        embedding_result = {'ok': False}
        ollama_result    = {'ok': False}

        def _load_embeddings():
            try:
                embedding_result['ok'] = prewarm_embeddings()
            except Exception:
                embedding_result['ok'] = False

        def _load_ollama():
            try:
                # Bail out immediately if a real query has started —
                # sending a prewarm while Ollama is handling a query
                # queues them sequentially and adds minutes of delay.
                if self._prewarm_cancel:
                    print("⚡ prewarm_worker: cancelled (query in progress)")
                    ollama_result['ok'] = self._ollama_ready  # keep current state
                    return
                # Pass num_ctx so the model loads at the right context size.
                # When num_ctx is None, prewarm_ollama uses the model default.
                ollama_result['ok'] = prewarm_ollama(num_ctx=num_ctx)
            except Exception:
                ollama_result['ok'] = False

        t_emb = threading.Thread(target=_load_embeddings, daemon=True)
        t_llm = threading.Thread(target=_load_ollama,     daemon=True)
        t_emb.start(); t_llm.start()
        t_emb.join();  t_llm.join()

        self._ollama_loading = False
        
        # If model loaded successfully, mark as ready
        if ollama_result['ok']:
            self._prewarm_done  = True
            self._ollama_ready  = ollama_result['ok']
            self.output_queue.put(('ollama_status', 'ready'))
            self.output_queue.put(('prewarm_ok', None))
            self.output_queue.put(('status', 'Model ready'))
        else:
            self._ollama_ready = False
            self.output_queue.put(('ollama_status', 'offline'))
            self.output_queue.put(('prewarm_fail', None))

        self._prewarm_in_progress = False

    # ── Directory browsing ───────────────────────────────────────────────────

    def browse_directory(self):
        """Browse for a single directory and populate the entry box (legacy)."""
        directory = filedialog.askdirectory()
        if directory:
            self.index_dir_var.set(directory)

    def browse_all(self):
        """Open the native file browser showing all files — Ctrl/Shift for multi-select.

        This is the primary browse option.  The native Windows file dialog
        shows files AND folders.  The user can navigate into any folder to
        see its contents, then either:
          - Select individual files (Ctrl-click / Shift-click for multiple)
          - Copy the folder path from the address bar and paste it into the
            path entry box to add the whole folder to the queue.

        Supported file types are shown by default; 'All files' is also available.
        """
        if RAG_AVAILABLE:
            exts = sorted(_rag_engine.SUPPORTED_EXTENSIONS)
            ext_str = ' '.join(f'*{e}' for e in exts)
            filetypes = [
                ('Supported files', ext_str),
                ('All files', '*.*'),
            ]
        else:
            filetypes = [('All files', '*.*')]

        files = filedialog.askopenfilenames(
            title='Select files to index  (Ctrl/Shift for multiple)',
            filetypes=filetypes
        )
        if files:
            self._queue_add_paths(list(files))

    def browse_folder_single(self):
        """Open the native Windows folder picker to add a whole folder to the queue."""
        directory = filedialog.askdirectory(
            title='Select a folder to index'
        )
        if directory:
            self._queue_add_paths([directory])

    def browse_directories_multi(self):
        """Open a custom multi-folder picker. Ctrl/Shift-click to select many."""
        dialog = MultiFolderDialog(self.root)
        self.root.wait_window(dialog.window)
        if dialog.result:
            self._queue_add_paths(dialog.result)

    def browse_files_multi(self):
        """Open native file browser — Ctrl/Shift selects multiple files."""
        # Build extension filter from SUPPORTED_EXTENSIONS if available
        if RAG_AVAILABLE:
            exts = sorted(_rag_engine.SUPPORTED_EXTENSIONS)
            ext_str = ' '.join(f'*{e}' for e in exts)
            filetypes = [
                ('Supported files', ext_str),
                ('All files', '*.*'),
            ]
        else:
            filetypes = [('All files', '*.*')]

        files = filedialog.askopenfilenames(
            title='Select files to index  (Ctrl/Shift for multiple)',
            filetypes=filetypes
        )
        if files:
            self._queue_add_paths(list(files))

    def _queue_add_paths(self, paths: list):
        """Add a list of file or directory paths to the queue, skipping duplicates."""
        existing  = set(self.queue_listbox.get(0, tk.END))
        added     = 0
        skipped   = 0
        not_found = 0

        for path in paths:
            path = path.strip()
            if not path:
                continue
            if not Path(path).exists():
                not_found += 1
                continue
            if path in existing:
                skipped += 1
                continue
            self.queue_listbox.insert(tk.END, path)
            self._index_queue.append(path)
            existing.add(path)
            added += 1

        self._update_queue_count()

        # Brief status feedback
        parts = []
        if added:    parts.append(f"{added} added")
        if skipped:  parts.append(f"{skipped} already queued")
        if not_found: parts.append(f"{not_found} not found")
        if parts:
            self.status_var.set("Queue: " + ", ".join(parts))

    # ── Index queue management ────────────────────────────────────────────────

    def _queue_add_directory(self):
        """Add the directory in the entry box to the queue listbox."""
        directory = self.index_dir_var.get().strip()
        if not directory:
            messagebox.showwarning("No Directory", "Please enter or browse a directory first.")
            return
        if not Path(directory).exists():
            messagebox.showerror("Invalid Directory", f"Directory not found:\n{directory}")
            return
        # Avoid duplicates
        existing = list(self.queue_listbox.get(0, tk.END))
        if directory in existing:
            messagebox.showinfo("Already Queued", "That directory is already in the queue.")
            return
        self.queue_listbox.insert(tk.END, directory)
        self._index_queue.append(directory)
        self._update_queue_count()
        self.index_dir_var.set("")   # clear entry ready for next directory

    def _queue_remove_selected(self):
        """Remove the selected item from the queue."""
        sel = self.queue_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        self.queue_listbox.delete(idx)
        if idx < len(self._index_queue):
            self._index_queue.pop(idx)
        self._update_queue_count()

    def _queue_clear(self):
        """Clear the entire queue."""
        self.queue_listbox.delete(0, tk.END)
        self._index_queue.clear()
        self._update_queue_count()

    def _update_queue_count(self):
        n = self.queue_listbox.size()
        self.queue_count_var.set(f"Queue: {n} director{'y' if n == 1 else 'ies'}")

    # ── Scan-only mode ────────────────────────────────────────────────────────

    def _run_prescan(self):
        """Scan all queued directories and report what would be indexed."""
        dirs = list(self.queue_listbox.get(0, tk.END))
        if not dirs:
            messagebox.showwarning("Empty Queue", "Add at least one directory to the queue first.")
            return
        self.index_output.delete('1.0', tk.END)
        self.index_progress.start()
        self._index_set_buttons('running')
        self._cancel_index_timer()
        self.index_elapsed_var.set("")   # no time shown during pre-scan
        self.status_var.set("Scanning…")
        thread = threading.Thread(target=self._prescan_worker,
                                  args=(dirs, self.recursive_var.get()), daemon=True)
        thread.start()

    def _prescan_worker(self, directories, recursive):
        """Background thread: scan dirs and print a report without indexing."""
        old_stdout = sys.stdout
        sys.stdout = TextRedirector(self.output_queue, 'index')
        try:
            total_to_index = 0
            total_skip_bin = 0
            total_unsup    = 0

            print(f"{'='*60}")
            print(f"🔍 PRE-SCAN REPORT")
            print(f"{'='*60}\n")

            for d in directories:
                print(f"📁 {d}")
                result = scan_directory(d, recursive=recursive)
                n_idx  = len(result['to_index'])
                n_bin  = len(result['skipped_bin'])
                n_uns  = len(result['unsupported'])
                n_dirs = len(result['skipped_dir'])
                print(f"   ✅ Will index:      {n_idx:>6,} files")
                print(f"   ⏭  Skip (binary):  {n_bin:>6,} files")
                print(f"   ❓ Unknown type:   {n_uns:>6,} files")
                print(f"   📂 Dirs skipped:   {n_dirs:>6}")
                if n_uns and n_uns <= 20:
                    exts = sorted({e for _, e in result['unsupported']})
                    print(f"      Unknown exts: {', '.join(exts)}")
                print()
                total_to_index += n_idx
                total_skip_bin += n_bin
                total_unsup    += n_uns

            print(f"{'='*60}")
            print(f"TOTALS ACROSS ALL DIRECTORIES")
            print(f"  Will index:    {total_to_index:,} files")
            print(f"  Skip binary:   {total_skip_bin:,} files")
            print(f"  Unknown type:  {total_unsup:,} files")
            print(f"{'='*60}")
            print(f"\nClick '▶ Start Indexing Queue' to begin.\n")

            self.output_queue.put(('status', 'Pre-scan complete'))
            self.output_queue.put(('done', 'index'))
        except Exception as e:
            self.output_queue.put(('error', str(e)))
            self.output_queue.put(('done', 'index'))
        finally:
            sys.stdout = old_stdout

    # ── Indexing ──────────────────────────────────────────────────────────────

    def _purge_skipped_extensions(self):
        """Remove from ChromaDB any chunks whose file extension is now in SKIP_EXTENSIONS.

        Called at the start of every index run so that extensions the user just
        added to the 'Skipped' list are cleaned out before new files are indexed.
        Also removes their tracking records so a re-scan won't see them as unchanged.
        """
        if not RAG_AVAILABLE:
            return
        skip = _rag_engine.SKIP_EXTENSIONS
        if not skip:
            return
        try:
            from rag_preprocessor import get_chroma_client, create_or_get_collection
            client, emb_fn = get_chroma_client()
            col = create_or_get_collection(client, emb_fn)
            result = col.get(include=['metadatas'])
            ids_to_del = []
            for doc_id, meta in zip(result.get('ids', []), result.get('metadatas', [])):
                src = meta.get('source', meta.get('filepath', ''))
                if Path(src).suffix.lower() in skip:
                    ids_to_del.append(doc_id)
            if ids_to_del:
                col.delete(ids=ids_to_del)
                print(f"[Purge] Removed {len(ids_to_del):,} chunks for "
                      f"newly-skipped extensions: "
                      f"{', '.join(sorted(skip))}")
            # Also remove those files from the tracking DB so they fully re-index
            # if they are ever moved back to 'Supported' in the future.
            if TRACKING_DB.exists():
                import json as _json
                try:
                    tracking = _json.loads(TRACKING_DB.read_text(encoding='utf-8'))
                    changed = False
                    for dir_key, dir_data in tracking.items():
                        files = dir_data.get('files', {})
                        to_del = [fp for fp in files
                                  if Path(fp).suffix.lower() in skip]
                        for fp in to_del:
                            del files[fp]
                            changed = True
                    if changed:
                        TRACKING_DB.write_text(
                            _json.dumps(tracking, indent=2), encoding='utf-8')
                except Exception:
                    pass
        except Exception as e:
            print(f"[Purge] Warning: {e}")

    def start_indexing(self, resume=False):
        """Start (or resume) the full indexing queue in a background thread."""
        if not resume:
            dirs = list(self.queue_listbox.get(0, tk.END))
            if not dirs:
                messagebox.showwarning("Empty Queue",
                                       "Add at least one directory to the queue first.")
                return
            # Fresh start — clear any previous resume state
            self._index_resume_dirs = dirs
            self._index_resume_file = 0
            self.index_output.delete('1.0', tk.END)
        else:
            # Resume — use saved state
            if not self._index_resume_dirs:
                messagebox.showinfo("Nothing to Resume",
                                    "No stopped index to resume. Start a new index first.")
                return

        # Reset events for this run
        self._index_stop_event.clear()
        self._index_pause_event.clear()
        self._index_running = True

        # Purge any chunks whose extension was added to the skip list since last run
        self._purge_skipped_extensions()

        self.index_progress.start()
        self.index_progress_var.set("")
        self.status_var.set("Indexing…")
        self._index_set_buttons('running')
        self._start_index_timer()

        thread = threading.Thread(
            target=self.index_worker,
            args=(self._index_resume_dirs,
                  self.recursive_var.get(),
                  self.scan_mode_var.get(),
                  self._index_resume_file,
                  resume),
            daemon=True
        )
        thread.start()

    def _index_pause_resume(self):
        """Toggle pause/resume on the running index worker."""
        if self._index_pause_event.is_set():
            # Currently paused → resume (timer resumes ticking)
            self._index_pause_event.clear()
            self.index_pause_btn.configure(text="⏸ Pause")
            self.index_progress.start()
            self.status_var.set("Indexing resumed…")
            # Restart ticker (was cancelled on pause)
            self._index_timer_id = self.root.after(1000, self._tick_index_timer)
        else:
            # Currently running → pause (freeze the display)
            self._index_pause_event.set()
            self.index_pause_btn.configure(text="▶ Resume")
            self.index_progress.stop()
            self.status_var.set("⏸ Indexing paused — click Resume to continue")
            self._cancel_index_timer()   # freeze display at current time

    def _index_stop(self):
        """Signal the worker to stop after the current file."""
        self._index_stop_event.set()
        self._index_pause_event.clear()   # unblock if paused so it can see the stop
        self.index_stop_btn.configure(state='disabled')
        self.index_pause_btn.configure(state='disabled')
        self.status_var.set("⏹ Stopping after current file…")

    def _register_directory_for_tracking(self, directory: str, recursive: bool):
        """
        Register a directory in the auto-update tracking list and establish
        the file-change baseline. Called after smart-scan index_file_list completes.

        Crucially: populates tracking_db[dir_key]['files'] with current file
        timestamps BEFORE saving, so the next Update All correctly sees all
        files as UNCHANGED and only re-indexes genuinely new/modified ones.
        """
        try:
            added = add_to_auto_update_list(directory)
            if added:
                print(f"   ✅ Added to Update Index tracking list")
            else:
                print(f"   ℹ️  Already in tracking list")

            # scan_directory_for_changes returns results + tracking_db, but
            # tracking_db[dir_key]['files'] is still empty — it is only filled
            # by command_update after a real update run. We need to fill it here
            # ourselves with the current file timestamps so the baseline is set.
            result = scan_directory_for_changes(directory, recursive, quiet=True)
            if result:
                results, tracking_db, dir_key = result

                # Write current file timestamps into the tracking baseline
                # Use normalise_path so keys match what was stored in ChromaDB
                tracking_db[dir_key]['files'] = {}
                for file_info in results['all_files']:
                    tracking_db[dir_key]['files'][_rag_engine.normalise_path(file_info['path'])] = {
                        'modified':       file_info['modified'],
                        'modified_human': file_info['modified_human'],
                        'size':           file_info['size'],
                    }
                tracking_db[dir_key]['last_scan'] = results['scan_time']

                save_tracking_database(tracking_db)
                print(f"   ✅ Tracking baseline set ({len(tracking_db[dir_key]['files'])} files)")
        except Exception as _te:
            print(f"   ⚠️  Could not register for tracking: {_te}")

    def _index_set_buttons(self, state: str):
        """
        Switch the button bar between states:
          'idle'    — Start + Scan active, Pause/Stop disabled
          'running' — Pause + Stop active, Start/Scan disabled
          'stopped' — Start (labelled Resume) + Scan active, Pause/Stop disabled
        """
        if state == 'idle':
            self.index_start_btn.configure(text="▶ Start Indexing Queue",
                                           state='normal',
                                           command=self.start_indexing)
            self.index_pause_btn.configure(state='disabled', text="⏸ Pause")
            self.index_stop_btn.configure(state='disabled')
            self.index_scan_btn.configure(state='normal')

        elif state == 'running':
            self.index_start_btn.configure(state='disabled')
            self.index_pause_btn.configure(state='normal', text="⏸ Pause")
            self.index_stop_btn.configure(state='normal')
            self.index_scan_btn.configure(state='disabled')

        elif state == 'stopped':
            self.index_start_btn.configure(text="▶ Resume Indexing",
                                           state='normal',
                                           command=lambda: self.start_indexing(resume=True))
            self.index_pause_btn.configure(state='disabled', text="⏸ Pause")
            self.index_stop_btn.configure(state='disabled')
            self.index_scan_btn.configure(state='normal')

    def index_worker(self, directories, recursive, smart_scan,
                     resume_file: int = 0, is_resume: bool = False):
        """
        Worker thread: index every directory in the queue sequentially.
        Supports stop (saves position) and pause/resume mid-file-list.
        """
        old_stdout = sys.stdout
        sys.stdout = TextRedirector(self.output_queue, 'index')
        try:
            n_dirs = len(directories)
            grand_processed = grand_skipped = grand_chunks = grand_words = 0

            if is_resume:
                print(f"\n▶  RESUMING from directory 1/{n_dirs}, "
                      f"file {resume_file + 1}\n")
            else:
                n_files_queued = sum(1 for d in directories if os.path.isfile(d))
                n_dirs_queued  = n_dirs - n_files_queued
                items_desc = []
                if n_dirs_queued:
                    items_desc.append(f"{n_dirs_queued} director{'y' if n_dirs_queued == 1 else 'ies'}")
                if n_files_queued:
                    items_desc.append(f"{n_files_queued} file{'s' if n_files_queued != 1 else ''}")
                print(f"{'='*60}")
                print(f"🚀 AI PROWLER — BATCH INDEXING")
                print(f"   {', '.join(items_desc)} queued")
                print(f"   Smart scan: {'ON' if smart_scan else 'OFF'}")
                print(f"   Recursive:  {'YES' if recursive else 'NO'}")
                # Show which device the embedding model will run on
                try:
                    _gpu_info = detect_gpu()
                    _dev = _gpu_info.get('embedding_device', 'cpu').upper()
                    if _dev == 'CUDA':
                        _gpu_name = _gpu_info.get('cuda_device_name') or 'NVIDIA GPU'
                        _vram     = _gpu_info.get('cuda_vram_gb')
                        _vram_str = f'  ({_vram} GB VRAM)' if _vram else ''
                        print(f"   Embeddings: GPU ⚡ {_gpu_name}{_vram_str}")
                    elif _dev == 'MPS':
                        print(f"   Embeddings: GPU ⚡ Apple MPS")
                    else:
                        print(f"   Embeddings: CPU  (no compatible GPU detected)")
                except Exception:
                    pass
                print(f"{'='*60}\n")

            stopped = False

            for dir_idx, directory in enumerate(directories, 1):
                is_file = os.path.isfile(directory)
                label   = Path(directory).name
                icon    = "📄" if is_file else "📁"

                self.output_queue.put((
                    'index_progress',
                    f"{'File' if is_file else 'Dir'} {dir_idx}/{n_dirs}: {directory}"
                ))

                print(f"{'─'*60}")
                print(f"[{dir_idx}/{n_dirs}] {icon} {directory}")
                print(f"{'─'*60}")

                # start_from only applies to the first item on a resume
                start_from = resume_file if (dir_idx == 1 and is_resume) else 0

                if smart_scan:
                    if is_file:
                        print(f"📄 Single file — checking if supported…")
                    else:
                        print("🔍 Scanning for indexable files…")
                    scan = scan_directory(directory, recursive=recursive)
                    file_paths = [fp for fp, _ in scan['to_index']]
                    n_bin = len(scan['skipped_bin'])
                    n_uns = len(scan['unsupported'])
                    print(f"   Found {len(file_paths):,} file{'s' if len(file_paths) != 1 else ''} to index")
                    if n_bin:
                        print(f"   Skipped {n_bin:,} binary/executable file{'s' if n_bin != 1 else ''}")
                    if n_uns:
                        ext_list = ', '.join(set(e for _, e in scan['unsupported']))
                        print(f"   Skipped {n_uns:,} unsupported file{'s' if n_uns != 1 else ''} ({ext_list})")
                    print()

                    if not file_paths:
                        print(f"   ⚠️  No supported files found — skipping\n")
                        continue

                    stats = index_file_list(
                        file_paths,
                        label=f"{dir_idx}/{n_dirs}",
                        stop_event=self._index_stop_event,
                        pause_event=self._index_pause_event,
                        start_from=start_from,
                        root_directory=str(Path(directory).parent) if is_file else directory,
                    )

                    # Register for tracking — use parent dir when a single file
                    # was queued directly so the whole folder gets watched.
                    stopped_mid = stats.get('stopped_at', 0) > 0
                    if not stopped_mid:
                        track_path = str(Path(directory).parent) if is_file else directory
                        self._register_directory_for_tracking(track_path, recursive)
                else:
                    if is_file:
                        # Non-smart-scan: index the single file directly
                        stats = index_file_list(
                            [normalise_path(directory)],
                            label=f"{dir_idx}/{n_dirs}",
                            stop_event=self._index_stop_event,
                            pause_event=self._index_pause_event,
                            root_directory=str(Path(directory).parent),
                        )
                    else:
                        index_directory(directory, recursive=recursive, quiet=False)
                        stats = {'processed': 0, 'skipped': 0,
                                 'chunks': 0, 'words': 0, 'stopped_at': 0}

                grand_processed += stats.get('processed', 0)
                grand_skipped   += stats.get('skipped',   0)
                grand_chunks    += stats.get('chunks',    0)
                grand_words     += stats.get('words',     0)
                print()

                # Check if the worker was stopped mid-directory
                if stats.get('stopped_at', 0) > 0:
                    # Save resume position: remaining dirs start from current
                    self._index_resume_dirs = directories[dir_idx - 1:]
                    self._index_resume_file = stats['stopped_at'] - 1
                    stopped = True
                    break

                if self._index_stop_event.is_set():
                    # Stopped cleanly between directories
                    self._index_resume_dirs = directories[dir_idx:]
                    self._index_resume_file = 0
                    stopped = True
                    break

            if stopped:
                print(f"\n{'='*60}")
                print(f"⏹  INDEXING STOPPED")
                print(f"   Files indexed this run:  {grand_processed:,}")
                print(f"   Click '▶ Resume Indexing' to continue")
                print(f"{'='*60}\n")
                self.output_queue.put(('index_progress', '⏹ Stopped — click Resume'))
                self.output_queue.put(('status', '⏹ Stopped — click ▶ Resume Indexing to continue'))
                self.output_queue.put(('done', 'index_stopped'))
            else:
                # All directories completed
                self._index_resume_dirs = []
                self._index_resume_file = 0
                print(f"\n{'='*60}")
                print(f"🏁 ALL DIRECTORIES COMPLETE")
                print(f"{'='*60}")
                if smart_scan:
                    print(f"   Files indexed:  {grand_processed:,}")
                    print(f"   Files skipped:  {grand_skipped:,}"
                          f"  ← load failed (unreadable, empty, or unsupported format)")
                    if grand_skipped > 0 and grand_processed == 0:
                        print(f"   💡 Tip: click 'Scan Queue' to see exactly which files")
                        print(f"          and what extensions are in the directory.")
                    print(f"   Total chunks:   {grand_chunks:,}")
                    print(f"   Total words:    {grand_words:,}")
                print(f"   Directories:    {n_dirs}")
                print(f"{'='*60}\n")
                self.output_queue.put(('index_progress', ''))
                self.output_queue.put(('status', f'✅ Indexing complete — {n_dirs} directories done'))
                self.output_queue.put(('done', 'index'))

        except Exception as e:
            self.output_queue.put(('error', f"Indexing error: {e}"))
            self.output_queue.put(('done', 'index'))
        finally:
            self._index_running = False
            sys.stdout = old_stdout
    
    # ── Microphone / Speech-to-Text ──────────────────────────────────────────

    def _toggle_mic(self):
        """Press once to start recording, press again to stop early."""
        if self._mic_recording:
            self._mic_stop()
        else:
            self._mic_start()

    def _mic_start(self):
        """Begin microphone recording."""
        if not SPEECH_AVAILABLE:
            return
        self._mic_recording = True
        self._mic_recorder   = SpeechRecorder(self.output_queue)

        # Visual feedback — red pulsing button
        self._mic_btn_text.set("🔴")
        self._mic_btn.configure(bg='#ffcccc', activebackground='#ffaaaa')
        self._mic_status_var.set("🎙 Recording… speak your question, then click 🔴 or pause")
        self.status_var.set("Microphone active — listening…")

        try:
            self._mic_recorder.start()
        except Exception as exc:
            self._mic_recording = False
            self._mic_btn_text.set("🎤")
            self._mic_btn.configure(bg='#e8e8e8', activebackground='#d0d0d0')
            self._mic_status_var.set(f"❌ Mic error: {exc}")
            self.status_var.set("Ready")

    def _mic_stop(self):
        """Stop recording (manual button press)."""
        self._mic_recording = False
        self._mic_btn_text.set("⏳")
        self._mic_btn.configure(bg='#fff3cc', activebackground='#ffe799',
                                state='disabled')
        self._mic_status_var.set("⏳ Transcribing speech…")
        self.status_var.set("Transcribing…")
        if self._mic_recorder:
            self._mic_recorder.stop()

    def _mic_reset_button(self):
        """Restore mic button to idle state."""
        self._mic_recording = False
        if SPEECH_AVAILABLE:
            self._mic_btn_text.set("🎤")
            self._mic_btn.configure(bg='#e8e8e8', activebackground='#d0d0d0',
                                    state='normal')

    def _mic_handle_model_loading(self):
        """Called on first-ever use — Whisper model needs to download (~75 MB)."""
        self._mic_status_var.set(
            "⬇️  Downloading Whisper large-v3-turbo model (~1.6 GB) — one-time only…"
        )

    # ── Index timer ───────────────────────────────────────────────────────────

    def _tick_index_timer(self):
        """Update the index elapsed-time label every second while indexing runs."""
        if self._index_start_time is None:
            return
        elapsed = int(time.time() - self._index_start_time)
        hrs,  rem  = divmod(elapsed, 3600)
        mins, secs = divmod(rem, 60)
        if hrs > 0:
            self.index_elapsed_var.set(f"⏱ {hrs}h {mins:02d}m {secs:02d}s")
        elif mins > 0:
            self.index_elapsed_var.set(f"⏱ {mins}m {secs:02d}s")
        else:
            self.index_elapsed_var.set(f"⏱ {secs}s")
        self._index_timer_id = self.root.after(1000, self._tick_index_timer)

    def _start_index_timer(self):
        """Start (or restart) the index elapsed-time ticker."""
        self._cancel_index_timer()
        self._index_start_time = time.time()
        self.index_elapsed_var.set("⏱ 0s")
        self._index_timer_id = self.root.after(1000, self._tick_index_timer)

    def _cancel_index_timer(self):
        """Stop the ticker without clearing the displayed time."""
        if self._index_timer_id is not None:
            self.root.after_cancel(self._index_timer_id)
            self._index_timer_id = None

    def _stop_index_timer(self, final_label: str = ""):
        """
        Stop the ticker and replace the running time with a final summary.
        If final_label is empty, compute it from the elapsed time automatically.
        """
        self._cancel_index_timer()
        if final_label:
            self.index_elapsed_var.set(final_label)
        elif self._index_start_time is not None:
            elapsed = int(time.time() - self._index_start_time)
            hrs,  rem  = divmod(elapsed, 3600)
            mins, secs = divmod(rem, 60)
            if hrs > 0:
                self.index_elapsed_var.set(f"✅ {hrs}h {mins:02d}m {secs:02d}s")
            elif mins > 0:
                self.index_elapsed_var.set(f"✅ {mins}m {secs:02d}s")
            else:
                self.index_elapsed_var.set(f"✅ {secs}s")
        self._index_start_time = None

    # ── Warmup timer ─────────────────────────────────────────────────────────

    def _tick_warmup_timer(self):
        """Update waiting counter in answer box while warmup test is running."""
        if self._warmup_start_time is None:
            return
        elapsed = int(time.time() - self._warmup_start_time)
        mins, secs = divmod(elapsed, 60)
        if mins > 0:
            wait_msg = f"⏳ Waiting for response... {mins}m {secs:02d}s\n"
        else:
            wait_msg = f"⏳ Waiting for response... {secs}s\n"
        # Update the last line if it starts with ⏳ (replace), otherwise append
        self.output_queue.put(('warmup_timer_tick', wait_msg))
        self._warmup_timer_id = self.root.after(1000, self._tick_warmup_timer)

    # ── Query timer ───────────────────────────────────────────────────────────

    def _tick_query_timer(self):
        """Update the elapsed time label every second while a query is running."""
        if self._query_start_time is None:
            return
        elapsed = int(time.time() - self._query_start_time)
        mins, secs = divmod(elapsed, 60)
        if mins > 0:
            self.query_elapsed_var.set(f"⏱ {mins}m {secs:02d}s elapsed")
        else:
            self.query_elapsed_var.set(f"⏱ {secs}s elapsed")
        self._query_timer_id = self.root.after(1000, self._tick_query_timer)

    def start_query(self):
        """Start query — auto-loads Ollama if not ready."""
        question = self.question_text.get('1.0', 'end-1c').strip()

        if not question:
            messagebox.showwarning("No Question", "Please enter a question")
            return

        # Cancel any in-progress prewarm immediately — if prewarm is running
        # it blocks Ollama and the real query queues behind it for minutes.
        # The query itself will load the model if needed.
        self._prewarm_cancel = True

        # If model is still loading, tell the user rather than double-firing
        if self._ollama_loading:
            messagebox.showinfo("Loading Model",
                                "The AI model is still loading — please wait a moment and try again.")
            return
        
        # If warmup test is still running, inform user their query will queue
        if self._warmup_test_running:
            self.answer_output.delete('1.0', tk.END)
            self.answer_output.insert(tk.END,
                "⏳ Cache warmup test is still running...\n"
                "Your question will start as soon as warmup completes.\n"
                "This only happens on first startup.\n\n")
            # Let it proceed - query will queue behind warmup test at Ollama

        # Auto-load Ollama if not ready, then re-fire the query once loaded
        if not self._ollama_ready:
            self._load_ollama_then_query(question)
            return

        # Clear output only if warmup test is not running
        if not self._warmup_test_running:
            self.answer_output.delete('1.0', tk.END)

        # Start progress bar and elapsed timer
        self.query_progress.start()
        self._query_start_time = time.time()
        self.query_elapsed_var.set("⏱ 0s elapsed")
        self._tick_query_timer()
        self.status_var.set("Querying...")

        # Get chunk count
        chunks_str = self.chunks_var.get()
        if chunks_str.startswith("Auto"):
            n_contexts = None
        else:
            # Strip warning suffix e.g. "7 ⚠reload" → 7
            n_contexts = int(chunks_str.split()[0])

        # ── Build final question: embed text-file contents + file-output instructions ──
        final_question = question
        images_b64 = []
        text_attachments = []
        for f in self._attached_files:
            if f['type'] == 'image':
                try:
                    import base64
                    with open(f['path'], 'rb') as fh:
                        images_b64.append(base64.b64encode(fh.read()).decode('utf-8'))
                except Exception as e:
                    self.status_var.set(f"⚠ Could not read image {f['name']}: {e}")
            else:  # text / code / PDF text
                try:
                    text = Path(f['path']).read_text(encoding='utf-8', errors='replace')
                    text_attachments.append(f"\n\n--- Attached file: {f['name']} ---\n{text}\n--- End of {f['name']} ---")
                except Exception as e:
                    self.status_var.set(f"⚠ Could not read {f['name']}: {e}")
        if text_attachments:
            final_question = question + ''.join(text_attachments)
        if images_b64 and not text_attachments:
            final_question = question + '\n\n[User has attached image(s) — please analyse and describe them.]'
        # File Output Mode: when ticked, prepend filename-tagging instructions
        # so the LLM wraps every output file in a named code fence.
        # AI Prowler then detects those fences and shows a Save button per file.
        if self.file_output_mode_var.get():
            final_question = (
                "IMPORTANT: When producing any code, scripts, or files in your answer, "
                "wrap EACH file in a markdown code fence with its filename on the opening line, "
                "like this:\n"
                "```python my_script.py\n"
                "# code here\n"
                "```\n"
                "Always include the filename so it can be auto-detected and saved.\n\n"
            ) + final_question

        # Clear detected files panel completely before each new query
        for w in self._detected_files_inner.winfo_children():
            w.destroy()
        self._detected_files_frame.pack_forget()
        # Collapse container to zero height — restored when new files are detected
        self._detected_files_container.configure(height=1)
        self._detected_files_container.pack_propagate(False)

        # Reset cancel so future idle prewarming works again after query finishes
        self._prewarm_cancel = False
        # Reset stop flag and mark query as running — enables Stop button
        if RAG_AVAILABLE:
            _rag_engine.QUERY_STOP = False
        self._query_running = True
        self._stop_query_btn.configure(state='normal')
        thread = threading.Thread(target=self.query_worker,
                                  args=(final_question, n_contexts, images_b64), daemon=True)
        thread.start()

    def _stop_query(self):
        """Stop button — abort the current streaming query immediately."""
        if not self._query_running:
            return
        # Set the global flag — query_ollama() checks it on every token
        if RAG_AVAILABLE:
            _rag_engine.QUERY_STOP = True
        self._stop_query_btn.configure(state='disabled')
        self.status_var.set("⏹ Stopping query…")

    def _load_ollama_then_query(self, question):
        """Auto-load Ollama then fire the queued question once ready."""
        self.answer_output.delete('1.0', tk.END)
        self.answer_output.insert(tk.END,
            "\u26a1 AI model not loaded \u2014 starting Ollama automatically\u2026\n"
            "Your question will run as soon as the model is ready.\n")

        def _worker():
            self._ollama_loading = True
            self._ollama_ready   = False
            self.output_queue.put(('ollama_status', 'loading'))

            ok = False
            try:
                ok = prewarm_ollama()
            except Exception:
                pass

            self._ollama_loading = False
            if ok:
                self._ollama_ready = True
                self._prewarm_done = True
                self.output_queue.put(('ollama_status', 'ready'))
                self.output_queue.put(('ollama_autoquery', question))
            else:
                self._ollama_ready = False
                self.output_queue.put(('ollama_status', 'offline'))
                self.output_queue.put(('query',
                    "\u274c Could not connect to Ollama.\n\n"
                    "Please make sure Ollama is installed and running:\n"
                    "  1. Open a terminal and run:  ollama serve\n"
                    "  2. Then click Ask Question again.\n"))
                self.output_queue.put(('done', 'query'))

        threading.Thread(target=_worker, daemon=True).start()
    
    def query_worker(self, question, n_contexts, images_b64=None):
        """Worker thread for querying"""
        old_stdout = sys.stdout
        try:
            # Redirect output
            sys.stdout = TextRedirector(self.output_queue, 'query')
            
            # Query — pass images if attached
            rag_query(question, n_contexts=n_contexts, verbose=True,
                      images_b64=images_b64 if images_b64 else None)
            
            self.output_queue.put(('status', 'Query complete!'))
            self.output_queue.put(('done', 'query'))
            
        except Exception as e:
            self.output_queue.put(('error', f"Error: {str(e)}"))
            self.output_queue.put(('done', 'query'))
        finally:
            sys.stdout = old_stdout

    # ── Provider selector ───────────────────────────────────────────────────

    def _on_provider_changed(self, event=None):
        """User picked a different provider from the dropdown."""
        if not RAG_AVAILABLE:
            return
        idx = self._provider_combo.current()
        pid = self._provider_ids[idx]

        if pid.startswith('local:'):
            # Switch both the active provider and the active model
            model = pid[len('local:'):]
            self.current_model.set(model)
            _rag_engine.ACTIVE_PROVIDER = 'local'
            save_config(active_provider='local', model=model)
            # Sync the Settings model combobox
            self._rebuild_model_combo()
            self.update_model_info()
            # Reset prewarm for new model
            invalidate_chroma_cache()
            self._prewarm_done = False
            self._prewarm_in_progress = False
            self._warmup_reset()
            self._warmup_first_fired = False
            self._trigger_prewarm()
        else:
            _rag_engine.ACTIVE_PROVIDER = pid
            save_config(active_provider=pid)
        self._refresh_provider_light()

    def _sync_local_provider_label(self):
        """Legacy shim — rebuilds local entries so the combobox stays current."""
        self._rebuild_local_provider_entries(rebuild_combo=True)

    def _rebuild_local_provider_entries(self, rebuild_combo=False):
        """Query Ollama for installed models and (re)build the local provider slots.

        Creates one entry per installed model: pid='local:modelname'.
        Falls back to current_model if Ollama is unreachable.
        After a fresh download call with rebuild_combo=True to push changes to the widget.
        """
        if not RAG_AVAILABLE:
            return

        # Get installed models from Ollama
        installed = []
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=3,
                             proxies={"http": None, "https": None})
            if r.status_code == 200:
                installed = [m.get('name', '') for m in r.json().get('models', []) if m.get('name')]
        except Exception:
            pass

        # Fall back to catalogue models that are in use, plus current active model
        if not installed:
            installed = [self.current_model.get()]

        # Sort: active model first, then alphabetical
        current = self.current_model.get()
        installed.sort(key=lambda m: (0 if m == current else 1, m))

        new_local_ids    = [f'local:{m}' for m in installed]
        new_local_labels = [f"Local Ollama  [{m}]" for m in installed]

        if not hasattr(self, '_provider_ids') or not rebuild_combo:
            # Called during construction — just set the lists
            self._provider_ids    = new_local_ids
            self._provider_labels = new_local_labels
            return

        # Called after download — splice updated local entries into existing lists
        # Remove old local:* entries, keep cloud providers
        cloud_ids    = [pid for pid in self._provider_ids    if not pid.startswith('local:')]
        cloud_labels = [lbl for pid, lbl in zip(self._provider_ids, self._provider_labels)
                        if not pid.startswith('local:')]

        self._provider_ids    = new_local_ids    + cloud_ids
        self._provider_labels = new_local_labels + cloud_labels

        if hasattr(self, '_provider_combo'):
            self._provider_combo.configure(values=self._provider_labels)
            # Reselect current model
            target = f'local:{self.current_model.get()}'
            idx = next((i for i, pid in enumerate(self._provider_ids) if pid == target), 0)
            self._provider_combo.current(idx)
            self._provider_var.set(self._provider_labels[idx])

    def _refresh_provider_light(self):
        """Update the coloured dot and status note for the currently selected provider."""
        if not RAG_AVAILABLE or not hasattr(self, '_provider_ids'):
            return
        try:
            idx = self._provider_combo.current()
            if idx < 0:
                idx = 0
            pid = self._provider_ids[idx]
            status = get_provider_status(pid if not pid.startswith('local:') else 'local')

            # dot colour
            if pid.startswith('local:') or pid == 'local':
                # Reflect Ollama readiness
                dot_color = '#27ae60' if self._ollama_ready else '#aaaaaa'
                note = ''
            elif status == 'ready':
                dot_color = '#27ae60'   # green
                note = '● Ready'
            elif status == 'timeout':
                dot_color = '#e74c3c'   # red
                note = f"● Rate-limited {get_provider_timeout_str(pid)}"
            else:  # no_key
                dot_color = '#aaaaaa'   # grey
                note = '● No API key — add in Settings'

            self._prov_light_canvas.itemconfig(self._prov_light,
                                               fill=dot_color, outline=dot_color)
            self._provider_status_var.set(note)
        except Exception:
            pass

        # Re-schedule — check every 30 s so timeouts expire visually
        self.root.after(30_000, self._refresh_provider_light)

    def _update_api_dot(self, provider_id: str):
        """Update the coloured dot beside an API key entry in Settings."""
        if not RAG_AVAILABLE:
            return
        status = get_provider_status(provider_id)
        colours = {
            'ready':   ('#27ae60', '#1a7a40'),
            'timeout': ('#e74c3c', '#a93226'),
            'no_key':  ('#aaaaaa', '#888888'),
        }
        fill, outline = colours.get(status, colours['no_key'])
        self._update_api_dot_color(provider_id, fill, outline)

    def _update_api_dot_color(self, provider_id_or_name: str,
                              fill: str, outline: str = None):
        """Set dot colour directly — used by test result handler."""
        if outline is None:
            outline = fill
        # Accept either provider_id ('google') or display name ('Gemini')
        pid = provider_id_or_name
        if pid not in self._api_key_dots:
            # Try to match by display name
            for p, prov in EXTERNAL_PROVIDERS.items():
                if prov.get('name') == provider_id_or_name:
                    pid = p
                    break
        try:
            dot    = self._api_key_dots[pid]
            canvas = self._api_key_canvases[pid]
            canvas.itemconfig(dot, fill=fill, outline=outline)
        except Exception:
            pass

    def _on_fallback_change(self):
        """Toggle fallback-to-local setting."""
        if RAG_AVAILABLE:
            _rag_engine.FALLBACK_TO_LOCAL = self._fallback_var.get()

    def _build_provider_display_list(self):
        """Rebuild the combobox values — call after API keys change."""
        if not RAG_AVAILABLE or not hasattr(self, '_provider_combo'):
            return
        self._sync_local_provider_label()
        self._provider_combo.configure(values=self._provider_labels)
        self._refresh_provider_light()
    
    # ── Ollama status light ─────────────────────────────────────────────────

    def _ollama_set_status(self, state: str):
        """Update the coloured indicator light and label text.

        States:
          loading  — yellow,  "⏳ Loading model…"
          ready    — green,   "● AI Model Ready"
          offline  — red,     "● Model not loaded — click Load AI Model"
          idle     — grey,    "● Model not loaded"
        """
        colours = {
            'loading': ('#f5a623', '#c07d10', '⏳ Loading model…',                        '#c07d10'),
            'ready':   ('#27ae60', '#1a7a40', '● AI Model Ready',                         '#27ae60'),
            'offline': ('#e74c3c', '#a93226', '● Model not loaded — click Load AI Model', '#e74c3c'),
            'idle':    ('#aaaaaa', '#888888', '● Model not loaded',                        '#888888'),
        }
        fill, outline, text, fg = colours.get(state, colours['idle'])
        try:
            self._ollama_light_canvas.itemconfig(self._ollama_light,
                                                 fill=fill, outline=outline)
            self._ollama_status_var.set(text)
            self._ollama_status_lbl.configure(foreground=fg)
        except Exception:
            pass   # widget may not exist on very first startup call

    def _load_ollama_manual(self):
        """⚡ Load AI Model button handler."""
        if self._ollama_loading:
            return
        if self._ollama_ready:
            self.status_var.set("✅ AI model is already loaded and ready")
            self.root.after(3000, lambda: self.status_var.set("Ready"))
            return

        self._ollama_loading = True
        self._ollama_ready   = False
        self._ollama_set_status('loading')
        self.status_var.set("⚡ Loading AI model into memory…")

        def _worker():
            ok = False
            try:
                ok = prewarm_ollama()
            except Exception:
                pass
            self._ollama_loading = False
            if ok:
                self._ollama_ready = True
                self._prewarm_done = True
                self.output_queue.put(('ollama_status', 'ready'))
                self.output_queue.put(('prewarm_ok', None))
            else:
                self._ollama_ready = False
                self.output_queue.put(('ollama_status', 'offline'))
                self.output_queue.put(('prewarm_fail', None))

        threading.Thread(target=_worker, daemon=True).start()

    def refresh_tracked_dirs(self):
        """Refresh tracked directories list from the auto-update tracking file."""
        self.tracked_listbox.delete(0, tk.END)

        if not RAG_AVAILABLE:
            self.tracked_listbox.insert(tk.END, "(AI Prowler engine not available)")
            return

        try:
            dirs = load_auto_update_list()
            if dirs:
                for directory in dirs:
                    self.tracked_listbox.insert(tk.END, directory)
            else:
                self.tracked_listbox.insert(
                    tk.END,
                    "(No tracked directories yet — index a directory first)"
                )
        except Exception as e:
            self.tracked_listbox.insert(tk.END, f"(Error loading list: {e})")

    def _remove_tracked_directory(self):
        """Remove selected directory from tracking and delete all its vectors."""
        sel = self.tracked_listbox.curselection()
        if not sel:
            messagebox.showwarning("No Selection",
                                   "Select a directory in the list first.")
            return

        directory = self.tracked_listbox.get(sel[0])
        if directory.startswith("("):
            return

        if not messagebox.askyesno(
                "Remove Directory from Tracking",
                f"Remove this directory from tracking?\n\n"
                f"{directory}\n\n"
                f"This will:\n"
                f"  • Remove it from the tracked list\n"
                f"  • Delete all its indexed chunks and vectors from ChromaDB\n"
                f"  • Remove its file-change history\n\n"
                f"The actual files on disk are NOT touched.\n"
                f"You can re-index this directory later if needed."):
            return

        self.update_output.delete("1.0", tk.END)
        self.update_progress.start()
        self.remove_tracked_btn.configure(state="disabled")
        self.status_var.set("Removing directory from index…")

        thread = threading.Thread(
            target=self._remove_tracked_worker,
            args=(directory,), daemon=True
        )
        thread.start()

    def _remove_tracked_worker(self, directory):
        """Background thread: untrack directory and purge its ChromaDB vectors."""
        old_stdout = sys.stdout
        sys.stdout = TextRedirector(self.output_queue, "update")
        try:
            print(f"🗑  Removing directory from index:")
            print(f"   {directory}\n")

            result = remove_directory_from_index(directory)
            chunks = result.get("chunks_removed", 0)
            errors = result.get("errors", [])

            if chunks > 0:
                print(f"✅ Removed {chunks:,} chunk(s) from ChromaDB")
            else:
                print(f"ℹ️  No chunks found in ChromaDB for this directory")
                print(f"   (may have been wiped when you cleared the database)")

            print(f"✅ Removed from tracked directory list")
            print(f"✅ Removed from file-change history")

            if errors:
                for err in errors:
                    print(f"⚠️  {err}")

            print(f"\n✅ Done — directory is no longer tracked.")

            self.output_queue.put(("status", "Directory removed from tracking"))
            self.output_queue.put(("done", "remove_tracked"))

        except Exception as e:
            self.output_queue.put(("error", f"Error removing directory: {e}"))
            self.output_queue.put(("done", "remove_tracked"))
        finally:
            sys.stdout = old_stdout

    def update_selected(self):
        """Update selected directory"""
        selection = self.tracked_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a directory")
            return
        
        directory = self.tracked_listbox.get(selection[0])
        
        self.update_output.delete('1.0', tk.END)
        self.update_progress.start()
        self.status_var.set("Updating index + purging deleted...")
        
        thread = threading.Thread(target=self.update_directory_worker,
                                  args=(directory,))
        thread.daemon = True
        thread.start()
    
    def update_all(self):
        """Update all tracked directories"""
        self.update_output.delete('1.0', tk.END)
        self.update_progress.start()
        self.status_var.set("Updating all + purging deleted...")
        
        thread = threading.Thread(target=self.update_all_worker)
        thread.daemon = True
        thread.start()
    
    def update_directory_worker(self, directory):
        """Worker thread: update a single directory using Python functions directly"""
        old_stdout = sys.stdout
        try:
            sys.stdout = TextRedirector(self.output_queue, 'update')
            command_update(directory, recursive=True, auto_confirm=True)
            self.output_queue.put(('status', 'Update complete — index synced & stale chunks purged'))
            self.output_queue.put(('done', 'update'))
        except Exception as e:
            self.output_queue.put(('error', f"Error: {str(e)}"))
            self.output_queue.put(('done', 'update'))
        finally:
            sys.stdout = old_stdout
    
    def update_all_worker(self):
        """Worker thread: update all tracked directories using Python functions directly"""
        old_stdout = sys.stdout
        try:
            sys.stdout = TextRedirector(self.output_queue, 'update')
            dirs = load_auto_update_list()
            if not dirs:
                self.output_queue.put(('update', "No tracked directories found.\n"
                                                 "Index a directory first to start tracking it.\n"))
            else:
                for i, directory in enumerate(dirs, 1):
                    dir_name = Path(directory).name or directory
                    self.output_queue.put(('update', f"\n[{i}/{len(dirs)}] Updating: {dir_name}\n"))
                    command_update(directory, recursive=True, auto_confirm=True)
                self.output_queue.put(('update', "\n✅ All directories updated.\n"))
            self.output_queue.put(('status', 'Update complete — index synced & stale chunks purged'))
            self.output_queue.put(('done', 'update'))
        except Exception as e:
            self.output_queue.put(('error', f"Error: {str(e)}"))
            self.output_queue.put(('done', 'update'))
        finally:
            sys.stdout = old_stdout
    
    def _gpu_status_set(self, text):
        """Write text into the scrollable GPU status box."""
        self.gpu_status_text.configure(state='normal')
        self.gpu_status_text.delete('1.0', tk.END)
        self.gpu_status_text.insert(tk.END, text)
        self.gpu_status_text.configure(state='disabled')
        # Scroll to top so first line is always visible
        self.gpu_status_text.see('1.0')

    # ── Attachment management ─────────────────────────────────────────────────

    def _attach_files(self):
        """Open file dialog and add selected files to the attachment list."""
        paths = filedialog.askopenfilenames(
            title="Attach files to your question",
            filetypes=[("All files", "*.*")]
        )
        image_exts = {'.png','.jpg','.jpeg','.gif','.bmp','.webp','.tiff'}
        for p in paths:
            path = Path(p)
            ftype = 'image' if path.suffix.lower() in image_exts else 'text'
            # Avoid duplicates
            if not any(f['path'] == str(path) for f in self._attached_files):
                self._attached_files.append({'path': str(path), 'name': path.name, 'type': ftype})
        self._refresh_attach_display()

    def _clear_attachments(self):
        """Remove all attached files."""
        self._attached_files.clear()
        self._refresh_attach_display()

    def _remove_attachment(self, idx):
        """Remove a single attached file by index."""
        if 0 <= idx < len(self._attached_files):
            self._attached_files.pop(idx)
        self._refresh_attach_display()

    def _refresh_attach_display(self):
        """Rebuild the attachment chip display row."""
        for w in self._attach_display.winfo_children():
            w.destroy()
        if not self._attached_files:
            self._attach_hint_var.set(
                "No files attached  •  Attach images or files to include them in your question")
            return
        n = len(self._attached_files)
        self._attach_hint_var.set(f"{n} file{'s' if n != 1 else ''} attached:")
        for i, f in enumerate(self._attached_files):
            icon = "🖼" if f['type'] == 'image' else "📄"
            chip = ttk.Frame(self._attach_display, relief='groove', padding=(4, 2))
            chip.pack(side='left', padx=(0, 6), pady=2)
            ttk.Label(chip, text=f"{icon} {f['name']}",
                      font=('Arial', 9)).pack(side='left', padx=(0, 4))
            ttk.Button(chip, text="✕", width=2,
                       command=lambda i=i: self._remove_attachment(i)).pack(side='left')

    # ── File output detection ─────────────────────────────────────────────────

    def _scan_answer_for_files(self):
        """Scan the answer box for fenced code blocks that include a filename.

        Matches patterns like:
          ```python my_script.py      <- language + filename (most common)
          ```my_script.py             <- filename only (no language)
          ### FILE: name.ext ###      <- explicit file marker

        Two separate patterns are used so that command-line examples such as:
            ```
            python hello_world.py
            ```
        are NOT falsely detected as files (no spaces allowed in filenames).

        Returns list of (filename, content) tuples, deduped by filename.
        """
        import re
        answer = self.answer_output.get('1.0', 'end-1c')
        found = []
        seen  = set()

        # Pattern A: ```<language> <filename.ext>\n code ```
        # Requires a language word before the filename — no spaces in filename.
        # This correctly rejects  ```\npython hello_world.py\n```  (command example).
        pA = re.compile(
            r'```[\w+\-#.]+\s+([\w.\-]+\.\w+)\s*\n(.*?)```',
            re.DOTALL)
        for m in pA.finditer(answer):
            fname   = m.group(1).strip()
            content = m.group(2)
            # Must have actual code content, not just whitespace
            if fname not in seen and content.strip():
                found.append((fname, content))
                seen.add(fname)

        # Pattern B: ```<filename.ext>\n code ```
        # Filename-only fence (no language prefix).
        pB = re.compile(
            r'```([\w.\-]+\.\w+)\s*\n(.*?)```',
            re.DOTALL)
        for m in pB.finditer(answer):
            fname   = m.group(1).strip()
            content = m.group(2)
            if fname not in seen and content.strip():
                found.append((fname, content))
                seen.add(fname)

        # Pattern C: ### FILE: name.ext ### ... ### END FILE ###
        pC = re.compile(
            r'###\s*FILE:\s*([\w.\-/\\ ]+\.\w+)\s*###\n?(.*?)###\s*END\s*FILE\s*###',
            re.DOTALL | re.IGNORECASE)
        for m in pC.finditer(answer):
            fname   = m.group(1).strip()
            content = m.group(2)
            if fname not in seen:
                found.append((fname, content))
                seen.add(fname)

        return found

    def _show_detected_files(self, files):
        """Populate and show the detected-files panel; hide it if no files found."""
        for w in self._detected_files_inner.winfo_children():
            w.destroy()

        if not files:
            self._detected_files_frame.pack_forget()
            # Collapse container to zero height so no gap appears
            self._detected_files_container.configure(height=1)
            self._detected_files_container.pack_propagate(False)
            return

        ICONS = {'.py':'🐍', '.js':'📜', '.ts':'📜', '.html':'🌐', '.css':'🎨',
                 '.json':'{}', '.md':'📝', '.txt':'📄', '.sql':'🗄',
                 '.sh':'⚙', '.bat':'⚙', '.csv':'📊', '.yaml':'⚙', '.yml':'⚙',
                 '.xml':'📋', '.jsx':'📜', '.tsx':'📜', '.vue':'📜',
                 '.rb':'💎', '.go':'🐹', '.rs':'🦀', '.cpp':'⚙', '.c':'⚙',
                 '.java':'☕', '.kt':'📱', '.swift':'🍎', '.ps1':'⚙'}

        for fname, content in files:
            ext  = Path(fname).suffix.lower()
            icon = ICONS.get(ext, '📄')
            row  = ttk.Frame(self._detected_files_inner)
            row.pack(fill='x', pady=3)

            ttk.Label(row, text=f"{icon} {fname}",
                      font=('Arial', 10, 'bold')).pack(side='left', padx=(0, 10))
            lines = len(content.splitlines())
            ttk.Label(row, text=f"({lines} line{'s' if lines != 1 else ''})",
                      font=('Arial', 9), foreground='gray').pack(side='left', padx=(0, 12))

            _f, _c = fname, content   # capture for lambdas
            ttk.Button(row, text="💾 Save File",
                       command=lambda f=_f, c=_c: self._save_detected_file(f, c)
                       ).pack(side='left', padx=(0, 6))

        # Restore container auto-sizing then pack the LabelFrame inside it
        self._detected_files_container.pack_propagate(True)
        self._detected_files_frame.pack(fill='x')

    def _clear_detected_files(self):
        """Manually clear all entries from the detected files panel."""
        for w in self._detected_files_inner.winfo_children():
            w.destroy()
        self._detected_files_frame.pack_forget()
        # Collapse container to zero height so the gap disappears instantly
        self._detected_files_container.configure(height=1)
        self._detected_files_container.pack_propagate(False)
        self.root.update_idletasks()

    def _save_detected_file(self, filename, content):
        """Save a detected file to disk via a Save-As dialog."""
        ext = Path(filename).suffix or '.txt'
        ext_types = {
            '.py':   [("Python",     "*.py")],
            '.js':   [("JavaScript", "*.js")],
            '.ts':   [("TypeScript", "*.ts")],
            '.html': [("HTML",       "*.html")],
            '.css':  [("CSS",        "*.css")],
            '.json': [("JSON",       "*.json")],
            '.md':   [("Markdown",   "*.md")],
            '.txt':  [("Text",       "*.txt")],
            '.sql':  [("SQL",        "*.sql")],
            '.sh':   [("Shell",      "*.sh")],
            '.bat':  [("Batch",      "*.bat")],
            '.csv':  [("CSV",        "*.csv")],
        }
        ftypes = ext_types.get(ext, [(f"{ext.lstrip('.')} files", f"*{ext}")]) + [("All files", "*.*")]
        save_path = filedialog.asksaveasfilename(
            title=f"Save {filename}",
            initialfile=filename,
            defaultextension=ext,
            filetypes=ftypes
        )
        if save_path:
            try:
                Path(save_path).write_text(content, encoding='utf-8')
                self.status_var.set(f"✅ Saved: {Path(save_path).name}")
                self.root.after(3000, lambda: self.status_var.set("Ready"))
            except Exception as e:
                messagebox.showerror("Save Failed", f"Could not save {filename}:\n{e}")

    def _copy_to_clipboard(self, text):
        """Copy text to the system clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("📋 Copied to clipboard")
        self.root.after(2000, lambda: self.status_var.set("Ready"))

    def _save_answer(self):
        """Save the full answer text to a file."""
        answer = self.answer_output.get('1.0', 'end-1c').strip()
        if not answer:
            messagebox.showwarning("Nothing to Save", "The answer box is empty.")
            return
        save_path = filedialog.asksaveasfilename(
            title="Save Answer",
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("Markdown", "*.md"), ("All files", "*.*")]
        )
        if save_path:
            try:
                Path(save_path).write_text(answer, encoding='utf-8')
                self.status_var.set(f"✅ Saved: {Path(save_path).name}")
                self.root.after(3000, lambda: self.status_var.set("Ready"))
            except Exception as e:
                messagebox.showerror("Save Failed", f"Could not save answer:\n{e}")

    def _clear_question(self):
        """Clear the question text box."""
    def _clear_question(self):
        """Clear the question text box."""
        self.question_text.delete('1.0', tk.END)
        if SPEECH_AVAILABLE:
            self._mic_status_var.set("")

    def _refresh_silence_label(self):
        """Update the silence timeout display label."""
        val = self.mic_silence_var.get()
        self.mic_silence_label_var.set(f"{val:.1f} seconds")

    def _on_silence_change(self, event=None):
        """Slider moved — round to 0.5s steps, update label, save, apply live."""
        raw = self.mic_silence_var.get()
        # Snap to nearest 0.5s increment for clean values
        snapped = round(raw * 2) / 2
        self.mic_silence_var.set(snapped)
        self._refresh_silence_label()
        # Apply immediately to SpeechRecorder so next recording uses new value
        if SPEECH_AVAILABLE:
            SpeechRecorder.SILENCE_SECS = snapped
        save_config(mic_silence_secs=snapped)

    def _refresh_gpu_layers_desc(self):
        """Update the inline description next to the GPU layers spinbox."""
        val = self.gpu_layers_var.get()
        if val == -1:
            self.gpu_layers_desc_var.set("(auto — Ollama decides)")
        elif val == 0:
            self.gpu_layers_desc_var.set("(CPU only — GPU disabled)")
        else:
            self.gpu_layers_desc_var.set(f"({val} layers on GPU)")

    def _on_gpu_layers_change(self, event=None):
        """Spinbox changed — update description label only (don't apply yet)."""
        try:
            self._refresh_gpu_layers_desc()
        except Exception:
            pass

    def _run_gpu_detect(self):
        """Run GPU detection in a background thread and update the status label."""
        self._gpu_status_set("🔍 Detecting GPU hardware...")
        self.status_var.set("Detecting GPU...")
        thread = threading.Thread(target=self._gpu_detect_worker, daemon=True)
        thread.start()

    def _gpu_detect_worker(self):
        """Background thread: call detect_gpu() and format results for the label."""
        try:
            info = detect_gpu()
            lines = []

            # Embedding model device
            dev = info['embedding_device'].upper()
            if info['cuda_available']:
                gpu_name = info['cuda_device_name'] or 'NVIDIA GPU'
                vram = f" — {info['cuda_vram_gb']} GB VRAM" if info['cuda_vram_gb'] else ""
                lines.append(f"✅ CUDA GPU detected: {gpu_name}{vram}")
                lines.append(f"✅ Embedding model will use: {dev} (GPU accelerated)")
            elif info['mps_available']:
                lines.append("✅ Apple MPS detected (Apple Silicon GPU)")
                lines.append(f"✅ Embedding model will use: {dev} (GPU accelerated)")
            else:
                lines.append("⚠️  No CUDA or MPS GPU detected — embedding model using CPU")
                lines.append("    (Install PyTorch with CUDA support to enable GPU embeddings)")

            # Ollama GPU status
            note = info['ollama_gpu_note']
            if note:
                if 'CPU only' in note or '0 bytes' in note:
                    lines.append(f"⚠️  Ollama LLM: {note}")
                    lines.append("    → Set GPU layers to -1 and click 'Apply & Reload'")
                elif 'VRAM' in note:
                    lines.append(f"✅ Ollama LLM: {note}")
                else:
                    lines.append(f"ℹ️  Ollama LLM: {note}")

            # Auto-suggest best GPU layers value
            if info['cuda_available'] and info['cuda_vram_gb']:
                vram = info['cuda_vram_gb']
                if vram < 4:
                    suggested = 10
                    reason = f"(limited VRAM: {vram} GB — partial offload recommended)"
                elif vram < 6:
                    suggested = 20
                    reason = f"({vram} GB VRAM — partial offload)"
                else:
                    suggested = -1
                    reason = f"({vram} GB VRAM — full GPU recommended)"
                lines.append(f"💡 Suggested GPU layers: {suggested} {reason}")
                # Auto-set the spinbox to the suggestion
                self.output_queue.put(('gpu_suggest', suggested))

            self.output_queue.put(('gpu_status', '\n'.join(lines)))
            self.output_queue.put(('status', 'GPU detection complete'))
        except Exception as e:
            self.output_queue.put(('gpu_status', f"❌ GPU detection failed: {e}"))
            self.output_queue.put(('status', 'Ready'))

    def _run_mcp_diagnostics(self):
        """
        Run mcp_diagnostics.py in a background thread and display the
        full output in a scrollable popup window.
        The diagnostics script checks:
          - mcp package version and instructions= support
          - FastMCP constructor parameters
          - All agentic RAG tools present in ai_prowler_mcp.py
          - Claude Desktop config validity
          - Subscription cache status
          - MCP server log tail
          - rag_preprocessor import and ChromaDB path
        """
        import subprocess as _sp, threading as _th
        import tkinter.scrolledtext as _st

        # ── Build the popup window immediately so user sees feedback ─────────
        win = tk.Toplevel(self.root)
        win.title("🔬 MCP Diagnostics")
        win.geometry("720x560")
        win.resizable(True, True)

        # Header banner
        banner = tk.Frame(win, bg='#0f3460')
        banner.pack(fill='x')
        tk.Label(banner,
                 text="AI-Prowler MCP Diagnostics",
                 bg='#0f3460', fg='white',
                 font=('Arial', 10, 'bold'),
                 pady=8, padx=16).pack(anchor='w')
        tk.Label(banner,
                 text="Checking MCP configuration, tools, Claude Desktop config and subscription status…",
                 bg='#0f3460', fg='#aaccee',
                 font=('Arial', 8),
                 pady=2, padx=16).pack(anchor='w')

        # Status label shown while running
        status_var = tk.StringVar(value="⏳  Running diagnostics…")
        status_lbl = tk.Label(win, textvariable=status_var,
                              font=('Arial', 9), fg='#e67e00',
                              anchor='w', padx=16, pady=4)
        status_lbl.pack(fill='x')

        # Scrollable output area
        txt = _st.ScrolledText(win,
                               wrap='word',
                               font=('Consolas', 9),
                               bg='#1a1a1a', fg='#e0e0e0',
                               padx=12, pady=10,
                               relief='flat', bd=0,
                               state='disabled')
        txt.pack(fill='both', expand=True, padx=0, pady=0)

        # Bottom button row
        btn_row = tk.Frame(win, bg=win.cget('bg'))
        btn_row.pack(fill='x', pady=6, padx=16)

        def _copy_output():
            self.root.clipboard_clear()
            self.root.clipboard_append(txt.get('1.0', tk.END))
            status_var.set("📋  Output copied to clipboard")
            win.after(2500, lambda: status_var.set("✅  Diagnostics complete"))

        tk.Button(btn_row, text="📋  Copy Output",
                  command=_copy_output,
                  bg='#0f3460', fg='white',
                  relief='flat', padx=12).pack(side='left')
        tk.Button(btn_row, text="Close",
                  width=10,
                  command=win.destroy).pack(side='right')

        def _append(text):
            """Append text to the output box — called from main thread via after()."""
            txt.configure(state='normal')
            txt.insert(tk.END, text)
            txt.see(tk.END)
            txt.configure(state='disabled')

        def _worker():
            """Background thread: run mcp_diagnostics.py and stream output."""
            diag_script = Path(__file__).parent / 'mcp_diagnostics.py'

            if not diag_script.exists():
                self.root.after(0, lambda: _append(
                    "❌  mcp_diagnostics.py not found in:\n"
                    f"    {diag_script.parent}\n\n"
                    "Download it from the AI-Prowler releases page or\n"
                    "ask support for the latest copy."
                ))
                self.root.after(0, lambda: status_var.set("❌  Diagnostics script not found"))
                return

            try:
                import re as _re
                py_exe = sys.executable
                # Always use python.exe not pythonw.exe — pythonw breaks stdout pipe
                if sys.platform == 'win32':
                    py_exe = _re.sub(r'(?i)pythonw\.exe$', 'python.exe', py_exe)

                # Force UTF-8 output from the child process
                _diag_env = os.environ.copy()
                _diag_env['PYTHONUTF8']       = '1'
                _diag_env['PYTHONIOENCODING'] = 'utf-8'

                proc = _sp.Popen(
                    [py_exe, str(diag_script)],
                    stdout=_sp.PIPE,
                    stderr=_sp.STDOUT,
                    encoding='utf-8',   # read child output as UTF-8 not cp1252
                    errors='replace',   # replace undecodable bytes instead of crashing
                    bufsize=1,
                    env=_diag_env,
                    creationflags=_sp.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                )

                # Filter noisy but harmless mcp-package telemetry lines
                _FILTER = (
                    'Failed to send telemetry',
                    'capture() takes',
                    'ClientStartEvent',
                )

                for line in proc.stdout:
                    if any(f in line for f in _FILTER):
                        continue
                    captured = line
                    self.root.after(0, lambda l=captured: _append(l))

                proc.wait()

                if proc.returncode == 0:
                    self.root.after(0, lambda: status_var.set(
                        "[OK] Diagnostics complete"))
                else:
                    self.root.after(0, lambda: status_var.set(
                        f"[WARN] Diagnostics finished with exit code {proc.returncode}"))

            except Exception as exc:
                err = str(exc)
                self.root.after(0, lambda e=err: _append(f"\n[ERR] Failed to run diagnostics: {e}\n"))
                self.root.after(0, lambda: status_var.set("[ERR] Run failed -- see output"))

        _th.Thread(target=_worker, daemon=True).start()

    def _apply_gpu_settings(self):
        """Save GPU layers to config, invalidate cache, retrigger prewarm."""
        try:
            val = self.gpu_layers_var.get()
        except Exception:
            messagebox.showerror("Invalid Value",
                                 "GPU layers must be a number (-1, 0, or 1-99)")
            return

        if RAG_AVAILABLE:
            _rag_engine.GPU_LAYERS = val
        save_config(gpu_layers=val)
        self._refresh_gpu_layers_desc()

        # Invalidate cached embedding client so it reloads with new device setting
        if RAG_AVAILABLE:
            invalidate_chroma_cache()

        # Reset prewarm so both models reload with the new GPU setting
        self._prewarm_done = False
        self._prewarm_in_progress = False
        self._trigger_prewarm()

        label = "auto" if val == -1 else ("CPU only" if val == 0 else f"{val} layers")
        self.status_var.set(f"GPU settings applied ({label}) — reloading models...")

    def _save_auto_start_setting(self):
        """Save auto-start Ollama preference to config."""
        auto_start = self.auto_start_ollama_var.get()
        status_text = "enabled" if auto_start else "disabled"
        
        print(f"\n{'='*50}")
        print(f"Saving auto-start Ollama setting: {status_text}")
        
        try:
            # Save to config
            save_config(auto_start_ollama=auto_start)
            print(f"✓ save_config() called successfully")
            
            # Verify the save by reading it back
            if RAG_AVAILABLE:
                config = load_config()
                if config:
                    saved_value = config.get('auto_start_ollama', None)
                    print(f"✓ Config file location: {CONFIG_FILE}")
                    print(f"✓ Verified saved value: {saved_value}")
                    
                    if saved_value == auto_start:
                        print(f"✓ Save successful! Setting persisted correctly.")
                        self.status_var.set(f"Auto-start Ollama: {status_text}")
                    else:
                        print(f"⚠ WARNING: Saved value ({saved_value}) doesn't match checkbox ({auto_start})")
                        self.status_var.set(f"Warning: Auto-start setting may not have saved")
                else:
                    print(f"⚠ WARNING: Could not load config to verify save")
            
        except Exception as e:
            print(f"✗ ERROR saving auto-start setting: {e}")
            import traceback
            traceback.print_exc()
            self.status_var.set(f"Error: Could not save auto-start setting")
            messagebox.showerror(
                "Save Failed",
                f"Could not save auto-start setting:\n{e}\n\nCheck console for details."
            )
        
        print(f"{'='*50}\n")

    def _on_show_sources_change(self):
        """Save show_sources toggle to config and apply immediately."""
        value = self.show_sources_var.get()
        if RAG_AVAILABLE:
            _rag_engine.SHOW_SOURCES = value
        save_config(show_sources=value)
        label = "ON — source details will be shown" if value else "OFF — clean answer-only mode"
        self.status_var.set(f"Source references: {label}")
        self.root.after(3000, lambda: self.status_var.set("Ready"))

    def _on_debug_output_change(self):
        """Save debug_output toggle to config and apply immediately."""
        value = self.debug_output_var.get()
        if RAG_AVAILABLE:
            _rag_engine.DEBUG_OUTPUT = value
        save_config(debug_output=value)
        label = "ON — timing/debug printed to answer box" if value else "OFF — clean answer only"
        self.status_var.set(f"Debug output: {label}")
        self.root.after(3000, lambda: self.status_var.set("Ready"))

    def _on_debug_view_change(self):
        """Save debug_view toggle to config. Takes effect next time Ollama starts."""
        value = self.debug_view_var.get()
        save_config(debug_view=value)
        if value:
            msg = ("Debug View ON — DOS windows will be visible next time Ollama starts. "
                   "Restart AI Prowler to apply.")
        else:
            msg = ("Debug View OFF — DOS windows will be hidden in background. "
                   "Restart AI Prowler to apply.")
        self.status_var.set(msg)
        self.root.after(5000, lambda: self.status_var.set("Ready"))

    def _on_ocr_debug_change(self):
        """Toggle OCR debug logging in the preprocessor and save to config."""
        value = self.ocr_debug_var.get()
        if RAG_AVAILABLE:
            _rag_engine.OCR_DEBUG = value
        save_config(ocr_debug=value)
        label = "ON — OCR text will be logged to Index Output" if value else "OFF"
        self.status_var.set(f"OCR debug: {label}")
        self.root.after(3000, lambda: self.status_var.set("Ready"))

    def _show_ocr_log(self):
        """Open a window showing the last OCR text captured from the preprocessor."""
        last_ocr = getattr(_rag_engine, '_last_ocr_text', '') if RAG_AVAILABLE else ''
        last_src = getattr(_rag_engine, '_last_ocr_source', '') if RAG_AVAILABLE else ''

        win = tk.Toplevel(self.root)
        win.title("Last OCR Output")
        win.geometry("780x560")
        win.minsize(500, 300)

        hdr = ttk.Frame(win)
        hdr.pack(fill='x', padx=10, pady=(8, 4))
        ttk.Label(hdr, text="Last OCR'd file:", font=('Arial', 9, 'bold')).pack(side='left')
        ttk.Label(hdr, text=last_src or "(none yet — index a scanned PDF or image first)",
                  font=('Arial', 9), foreground='gray').pack(side='left', padx=(6, 0))

        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=('Courier', 9))
        txt.pack(fill='both', expand=True, padx=10, pady=(0, 4))
        txt.insert('1.0', last_ocr if last_ocr else
                   "No OCR output captured yet.\n\n"
                   "Enable 'Log full OCR text' above, then index a scanned PDF or image.\n"
                   "The raw text Tesseract extracted will appear here.")
        txt.config(state='disabled')

        btn_row = ttk.Frame(win)
        btn_row.pack(fill='x', padx=10, pady=(0, 8))
        ttk.Button(btn_row, text="📋 Copy to Clipboard",
                   command=lambda: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(last_ocr))).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row, text="Close", command=win.destroy).pack(side='left')

    # ── Warmup indicator ────────────────────────────────────────────────────

    def _warmup_complete(self):
        """Warmup test removed - this handler is now a no-op."""
        pass

    def _warmup_reset(self):
        """Warmup test removed - this handler is now a no-op."""
        pass
        try:
            self._warmup_canvas.itemconfig(
                self._warmup_dot, fill='#aaaaaa', outline='#888888')
            self._warmup_var.set("")
            self._warmup_lbl.configure(foreground='#888888')
        except Exception:
            pass

    def _query_ollama_models_bg(self):
        """Blocking call — run in a background thread, never on the main thread.

        Tries HTTP /api/tags first; falls back to `ollama list` subprocess.
        Returns list of model name strings.
        """
        # HTTP attempt (proxy bypass)
        try:
            import requests as _req
            r = _req.get("http://localhost:11434/api/tags", timeout=3,
                         proxies={"http": None, "https": None})
            if r.status_code == 200:
                names = [m.get('name', '') for m in r.json().get('models', [])
                         if m.get('name')]
                if names:
                    return names
        except Exception:
            pass

        # Subprocess fallback — same as typing `ollama list` in DOS
        try:
            import subprocess, os, shutil
            exe = shutil.which('ollama')
            if not exe:
                exe = os.path.join(os.environ.get('LOCALAPPDATA', ''),
                                   'Programs', 'Ollama', 'ollama.exe')
            if exe and os.path.exists(exe):
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                result = subprocess.run(
                    [exe, 'list'],
                    capture_output=True, text=True, timeout=8,
                    startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW
                )
                names = [line.split()[0] for line in result.stdout.splitlines()[1:]
                         if line.strip()]
                if names:
                    return names
        except Exception:
            pass

        return []

    def _apply_model_list(self, installed):
        """Update the combo widget on the main thread — always called via root.after."""
        if not hasattr(self, '_model_combo_widget'):
            return
        if not installed:
            installed = [self.current_model.get()]

        active = self.current_model.get()
        installed.sort(key=lambda m: (0 if m == active else 1, m))
        sys_ram = getattr(self, '_system_ram_gb', 0)

        def _disp(m):
            info   = MODEL_INFO.get(m, {}) if RAG_AVAILABLE else {}
            size   = info.get('size_gb', 0)
            needed = info.get('min_ram_gb', 0)
            badge  = ('✅' if needed <= sys_ram else '⚠️') if (sys_ram > 0 and needed) else '✅'
            size_str = f"{size:.1f} GB | {needed} GB RAM" if (size or needed) else "installed"
            return f"{badge} {m}  [{size_str}]"

        display_names = [_disp(m) for m in installed]
        self._model_names       = installed
        self._model_display_map = dict(zip(display_names, installed))
        self._model_reverse_map = dict(zip(installed, display_names))
        self._model_combo_widget.configure(values=display_names)
        disp = self._model_reverse_map.get(active, display_names[0] if display_names else '')
        self._model_display_var.set(disp)

    def _rebuild_model_combo(self):
        """Trigger a non-blocking background refresh of the Active Model dropdown."""
        import threading
        def _worker():
            names = self._query_ollama_models_bg()
            self.root.after(0, lambda: self._apply_model_list(names))
        threading.Thread(target=_worker, daemon=True).start()

    def _start_model_poller(self):
        """Start the background poller that keeps the model list fresh every 10s."""
        def _poll():
            import threading
            def _worker():
                names = self._query_ollama_models_bg()
                self.root.after(0, lambda: self._apply_model_list(names))
            threading.Thread(target=_worker, daemon=True).start()
            self.root.after(10000, _poll)   # repeat every 10 seconds
        _poll()

    def on_model_change(self, event=None):
        """Handle model selection change"""
        # Resolve display name (with badges/sizes) back to real model name
        display = self._model_display_var.get() if hasattr(self, '_model_display_var') else self.current_model.get()
        model = getattr(self, '_model_display_map', {}).get(display, display)
        self.current_model.set(model)

        # Save configuration
        save_config(model=model)
        
        # Update info
        self.update_model_info()
        
        self.status_var.set(f"Model changed to {model}")
        self._sync_local_provider_label()
        
        # Reset prewarm — new model needs to be loaded into memory.
        # Also invalidate the embedding cache so the next prewarm does a
        # clean reload (guards against future embedding model changes too).
        invalidate_chroma_cache()
        self._prewarm_done = False
        self._prewarm_in_progress = False
        self._warmup_reset()          # new model → warmup must start over
        self._warmup_first_fired = False
        self._trigger_prewarm()
    
    def update_model_info(self):
        """Update model info label"""
        model = self.current_model.get()
        context = get_model_context_window(model)
        chunks = calculate_optimal_chunks(model)
        info_data = MODEL_INFO.get(model, {}) if RAG_AVAILABLE else {}
        size_gb  = info_data.get("size_gb", None)
        ram_gb   = info_data.get("min_ram_gb", None)
        maker    = info_data.get("maker", "")
        desc     = info_data.get("description", "")
        sys_ram  = getattr(self, '_system_ram_gb', 0)

        parts = [f"Context: {context:,} tokens | Optimal chunks: {chunks}"]
        if size_gb:
            parts.append(f"Download: {size_gb:.1f} GB")
        if ram_gb:
            fit = "" if sys_ram == 0 else ("  ✅ fits your RAM" if ram_gb <= sys_ram else "  ⚠️ exceeds your RAM")
            parts.append(f"Min RAM: {ram_gb} GB{fit}")
        line2_parts = []
        if maker:
            line2_parts.append(f"By {maker}")
        if desc:
            line2_parts.append(desc)
        line2 = "  |  ".join(line2_parts)
        self.model_info_label.config(text="  |  ".join(parts[:3]) + (f"\n{line2}" if line2 else ""))
    
    def show_model_picker(self):
        """Show a custom model browser dialog that closes when clicking outside."""
        picker = tk.Toplevel(self.root)
        picker.title("Browse & Install Model")
        picker.resizable(True, True)
        picker.minsize(820, 380)
        picker.transient(self.root)

        self.root.update_idletasks()
        rx, ry = self.root.winfo_rootx(), self.root.winfo_rooty()
        rw, rh = self.root.winfo_width(), self.root.winfo_height()
        pw, ph = 860, 560
        picker.geometry(f"{pw}x{ph}+{rx + rw//2 - pw//2}+{ry + rh//2 - ph//2}")

        picker.columnconfigure(0, weight=1)
        picker.rowconfigure(2, weight=1)  # listbox row expands

        sys_ram = getattr(self, '_system_ram_gb', 0)

        # ── Check if Ollama is installed (even if not running) ────────────────
        import shutil as _shutil, os as _os
        _local_app      = _os.environ.get('LOCALAPPDATA', '')
        _ollama_exe_path = (_os.path.join(_local_app, 'Programs', 'Ollama', 'ollama.exe')
                            if _local_app else None)
        ollama_installed = (
            (_ollama_exe_path and _os.path.isfile(_ollama_exe_path))
            or bool(_shutil.which('ollama'))
        )

        # ── Query Ollama for already-downloaded models ─────────────────────────
        installed_names = set()
        installed_sizes = {}   # name → size_on_disk bytes
        ollama_running  = False
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=3,
                             proxies={"http": None, "https": None})
            if r.status_code == 200:
                ollama_running = True
                for m in r.json().get('models', []):
                    raw_name = m.get('name', '')
                    # Normalise: "llama3.1:8b" and "llama3.1:8b-instruct-q4_0" both
                    # match the catalogue entry "llama3.1:8b"
                    installed_names.add(raw_name)
                    installed_sizes[raw_name] = m.get('size', 0)
        except Exception:
            pass   # Ollama not running — fall through to filesystem scan

        # ── Filesystem fallback: detect downloaded models without Ollama running ──
        # Ollama stores manifests at:
        #   %USERPROFILE%\.ollama\models\manifests\registry.ollama.ai\library\<name>\<tag>
        # Each manifest file = one downloaded model variant.
        if not installed_names:
            try:
                _manifests_root = _os.path.join(
                    _os.environ.get('USERPROFILE', ''),
                    '.ollama', 'models', 'manifests',
                    'registry.ollama.ai', 'library'
                )
                if _os.path.isdir(_manifests_root):
                    for _model_dir in _os.scandir(_manifests_root):
                        if not _model_dir.is_dir():
                            continue
                        for _tag_file in _os.scandir(_model_dir.path):
                            if _tag_file.is_file():
                                _name = f"{_model_dir.name}:{_tag_file.name}"
                                installed_names.add(_name)
            except Exception:
                pass  # filesystem scan failed — silently ignore

        def is_installed(model_name):
            """True if model_name (or a variant with extra tags) is in Ollama.
            Matches exactly OR if an installed name is a more-specific variant of
            the catalogue name (e.g. 'llama3.1:8b-instruct-q4_0' matches 'llama3.1:8b').
            Does NOT cross-match different tags (e.g. 'llama3.2:3b' does NOT match 'llama3.2:1b').
            """
            if model_name in installed_names:
                return True
            # Match only if an installed name STARTS WITH the full catalogue name
            # e.g. 'llama3.1:8b-instruct-q4_0' starts with 'llama3.1:8b'
            return any(n.startswith(model_name) for n in installed_names)

        # ── Header ─────────────────────────────────────────────────────────────
        hdr = ttk.Frame(picker, padding=(12, 8))
        hdr.grid(row=0, column=0, sticky='ew')
        ttk.Label(hdr, text="Browse & Install AI Models",
                  font=('Arial', 13, 'bold')).pack(side='left')
        ram_text = f"  Your RAM: {sys_ram:.0f} GB" if sys_ram > 0 else ""

        if ollama_running and installed_names:
            ollama_status_text = f"✅ Ollama running — {len(installed_names)} model(s) installed"
            ollama_status_colour = '#27ae60'
        elif ollama_running and not installed_names:
            ollama_status_text = "✅ Ollama running — no models installed yet"
            ollama_status_colour = '#27ae60'
        elif ollama_installed and not ollama_running:
            ollama_status_text = "⚠️ Ollama installed but not running"
            ollama_status_colour = '#e67e00'
        else:
            ollama_status_text = "❌ Ollama not installed — use button below to install"
            ollama_status_colour = '#cc0000'

        # RAM label (left side)
        if ram_text:
            ttk.Label(hdr, text=ram_text,
                      font=('Arial', 9), foreground='gray').pack(side='left', padx=(8, 0))
            ttk.Label(hdr, text="  |  ",
                      font=('Arial', 9), foreground='gray').pack(side='left')

        # ── Two live indicator lights: Installed + Running ─────────────────────
        # Use ttk.Label so theme handles bg — avoids silent TclError that kills polling.
        # Prefix labels make each light's meaning unambiguous.
        ttk.Label(hdr, text="Ollama:",
                  font=('Arial', 9), foreground='gray').pack(side='left', padx=(4, 2))
        _inst_var = tk.StringVar(value='● Installed' if ollama_installed else '● Not installed')
        _inst_lbl = ttk.Label(hdr, textvariable=_inst_var, font=('Arial', 9, 'bold'),
                              foreground='#27ae60' if ollama_installed else '#cc0000')
        _inst_lbl.pack(side='left')

        ttk.Label(hdr, text="  |  Server:",
                  font=('Arial', 9), foreground='gray').pack(side='left', padx=(4, 2))
        _run_var  = tk.StringVar(value='● Running' if ollama_running else '● Not running')
        _run_lbl  = ttk.Label(hdr, textvariable=_run_var, font=('Arial', 9, 'bold'),
                              foreground='#27ae60' if ollama_running else '#e67e00')
        _run_lbl.pack(side='left', padx=(0, 8))

        def _refresh_ollama_lights():
            """Check Ollama state in a background thread; update UI on main thread.
            Uses a raw socket check for the running state — more reliable than
            requests.get() in a background thread context."""
            import threading as _threading, socket as _socket
            def _check():
                # Installed check (fast filesystem op)
                _lo_app   = _os.environ.get('LOCALAPPDATA', '')
                _lo_exe   = (_os.path.join(_lo_app, 'Programs', 'Ollama', 'ollama.exe')
                             if _lo_app else None)
                _now_inst = ((_lo_exe and _os.path.isfile(_lo_exe))
                             or bool(_shutil.which('ollama')))
                # Running check via raw TCP socket — avoids requests/proxy issues
                _now_run = False
                try:
                    with _socket.create_connection(('127.0.0.1', 11434), timeout=1):
                        _now_run = True
                except Exception:
                    pass
                # Schedule UI update back on the main thread
                def _update():
                    try:
                        _inst_var.set('● Installed'  if _now_inst else '● Not installed')
                        _run_var.set ('● Running'     if _now_run  else '● Not running')
                        _inst_lbl.configure(foreground='#27ae60' if _now_inst else '#cc0000')
                        _run_lbl.configure (foreground='#27ae60' if _now_run  else '#e67e00')
                        picker.after(3000, _refresh_ollama_lights)
                    except tk.TclError:
                        pass  # picker closed — stop polling
                try:
                    picker.after(0, _update)
                except tk.TclError:
                    pass  # picker closed before thread finished
            _threading.Thread(target=_check, daemon=True).start()

        # Poll at 500 ms so lights are live from the moment the popup opens
        picker.after(500, _refresh_ollama_lights)

        # ── Ollama not installed banner ────────────────────────────────────────
        if not ollama_installed:
            banner = tk.Frame(picker, bg='#1a3a5c', pady=0)
            banner.grid(row=1, column=0, sticky='ew')
            banner_inner = tk.Frame(banner, bg='#1a3a5c')
            banner_inner.pack(fill='x', padx=12, pady=8)

            tk.Label(banner_inner,
                     text="⚠️  Ollama is not installed",
                     bg='#1a3a5c', fg='white',
                     font=('Arial', 10, 'bold')).pack(side='left')
            tk.Label(banner_inner,
                     text="   Ollama is required to download and run local AI models.",
                     bg='#1a3a5c', fg='#aaccee',
                     font=('Arial', 9)).pack(side='left')

            def _install_ollama():
                import webbrowser
                webbrowser.open('https://ollama.com/download')
                messagebox.showinfo(
                    "Installing Ollama",
                    "Your browser will open the Ollama download page.\n\n"
                    "Steps:\n"
                    "  1. Download and run OllamaSetup.exe\n"
                    "  2. Wait for installation to complete\n"
                    "  3. Close and reopen this Browse & Install window\n"
                    "  4. Select and install a model\n\n"
                    "Recommended starter model: llama3.2:3b (~2 GB)",
                    parent=picker
                )

            tk.Button(banner_inner,
                      text="⬇  Download & Install Ollama",
                      bg='#2980b9', fg='white',
                      activebackground='#3498db', activeforeground='white',
                      relief='flat', padx=12, pady=3,
                      font=('Arial', 9, 'bold'),
                      command=_install_ollama).pack(side='right')

            ttk.Separator(picker, orient='horizontal').grid(row=2, column=0, sticky='ew')
            # Shift list_frame and buttons down one row to make room for banner
            picker.rowconfigure(3, weight=1)
            _list_row, _sep_row, _desc_row, _sep2_row, _btn_row = 3, 4, 5, 6, 7
        else:
            ttk.Separator(picker, orient='horizontal').grid(row=1, column=0, sticky='ew')
            picker.rowconfigure(2, weight=1)
            _list_row, _sep_row, _desc_row, _sep2_row, _btn_row = 2, 3, 4, 5, 6

        # ── Listbox ─────────────────────────────────────────────────────────────
        list_frame = ttk.Frame(picker, padding=(8, 6))
        list_frame.grid(row=_list_row, column=0, sticky='nsew')
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        sb = ttk.Scrollbar(list_frame, orient='vertical')
        listbox = tk.Listbox(list_frame, yscrollcommand=sb.set,
                             font=('Courier New', 10), selectmode='single',
                             activestyle='dotbox')
        sb.config(command=listbox.yview)
        listbox.grid(row=0, column=0, sticky='nsew')
        sb.grid(row=0, column=1, sticky='ns')

        # Populate — installed models first, then by RAM fit, then by size
        picker_models = [m for m in MODEL_CONTEXT_WINDOWS.keys() if m != 'default']
        def _sort_key(m):
            info   = MODEL_INFO.get(m, {})
            needed = info.get("min_ram_gb", 999)
            fits   = needed <= sys_ram if sys_ram > 0 else True
            return (0 if is_installed(m) else 1, 0 if fits else 1, info.get("size_gb", 0))
        picker_models.sort(key=_sort_key)

        for m in picker_models:
            info  = MODEL_INFO.get(m, {})
            size  = info.get("size_gb", 0)
            ram   = info.get("min_ram_gb", 0)
            maker = info.get("maker", "")
            desc  = info.get("description", "")

            inst = is_installed(m)
            if inst:
                status_badge = "📦"   # already on disk
            elif sys_ram > 0 and ram > sys_ram:
                status_badge = "⚠️"   # too big for RAM
            else:
                status_badge = "  "   # available to download

            ram_badge = "✅" if (sys_ram > 0 and ram <= sys_ram) else ("⚠️" if sys_ram > 0 else "  ")
            inst_tag  = " [installed]" if inst else ""
            line = f"{status_badge} {m:<22} {size:>5.1f} GB  {ram:>3} GB RAM  {maker:<10}{inst_tag}"
            listbox.insert('end', line)

            if inst:
                listbox.itemconfig('end', foreground='#44bb44')
            elif sys_ram > 0 and ram > sys_ram:
                listbox.itemconfig('end', foreground='#888888')

        # Pre-select active model
        current = self.current_model.get()
        if current in picker_models:
            idx = picker_models.index(current)
            listbox.selection_set(idx)
            listbox.see(idx)

        # ── Description label ──────────────────────────────────────────────────
        ttk.Separator(picker, orient='horizontal').grid(row=_sep_row, column=0, sticky='ew')
        desc_var = tk.StringVar(value="Select a model above to see details.")
        desc_lbl = ttk.Label(picker, textvariable=desc_var, font=('Arial', 9),
                             padding=(10, 6), wraplength=pw - 20, anchor='w', justify='left')
        desc_lbl.grid(row=_desc_row, column=0, sticky='ew')

        def on_select(event=None):
            sel = listbox.curselection()
            if not sel:
                return
            m    = picker_models[sel[0]]
            info = MODEL_INFO.get(m, {})
            size  = info.get("size_gb", 0)
            ram   = info.get("min_ram_gb", 0)
            maker = info.get("maker", "")
            desc  = info.get("description", "")
            ctx   = MODEL_CONTEXT_WINDOWS.get(m, 0)

            inst = is_installed(m)
            inst_line = ""
            if inst:
                # Show actual disk size from Ollama if available
                disk_bytes = next((installed_sizes[n] for n in installed_names
                                   if n == m or n.startswith(m.split(':')[0] + ':')), 0)
                disk_str = f"{disk_bytes/1_073_741_824:.2f} GB on disk" if disk_bytes else "installed"
                inst_line = f"  ✅ Already installed ({disk_str})"
            ram_warn = f"  ⚠️ Needs {ram} GB RAM — you have {sys_ram:.0f} GB."                        if sys_ram > 0 and ram > sys_ram else ""
            maker_str = f"By {maker}  |  " if maker else ""
            active_str = "  ← active" if m == current else ""
            desc_var.set(
                f"{m}{active_str}\n"
                + f"{maker_str}{size:.1f} GB download  |  {ram} GB RAM min  |  {ctx:,} token context\n"
                + f"{desc}{inst_line}{ram_warn}"
            )
            # Update action button label based on install status
            if inst:
                action_btn.config(text=f"✅  Switch to {m}" if m != current else "✅  Already active model")
            else:
                action_btn.config(text=f"⬇  Download & Install {m}")

        listbox.bind('<<ListboxSelect>>', on_select)

        # ── Buttons ─────────────────────────────────────────────────────────────
        ttk.Separator(picker, orient='horizontal').grid(row=_sep2_row, column=0, sticky='ew')
        btn_frame = ttk.Frame(picker, padding=(8, 6))
        btn_frame.grid(row=_btn_row, column=0, sticky='ew')

        def do_action():
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("No Selection", "Please select a model first.", parent=picker)
                return
            m    = picker_models[sel[0]]
            info = MODEL_INFO.get(m, {})
            ram  = info.get("min_ram_gb", 0)
            size = info.get("size_gb", 0)

            if is_installed(m):
                # Already on disk — just switch the active model
                picker.destroy()
                self.current_model.set(m)
                self.status_var.set(f"Switched active model to {m}")
            else:
                # Need to download
                warn = ""
                if sys_ram > 0 and ram > sys_ram:
                    warn = f"\n\n⚠️ Warning: {m} needs {ram} GB RAM but your PC has {sys_ram:.0f} GB.\nIt will run on CPU and be very slow."
                if messagebox.askyesno("Download Model",
                        f"Download and install {m}?\n\nSize: ~{size:.1f} GB\nMin RAM: {ram} GB{warn}\n\nThis may take several minutes.",
                        parent=picker):
                    picker.destroy()
                    self.status_var.set(f"Downloading {m}...")
                    self._launch_install_progress_window(m)

        action_btn = ttk.Button(btn_frame, text="⬇  Download & Install", command=do_action)
        action_btn.pack(side='left', padx=4)

        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=picker.destroy)
        cancel_btn.pack(side='left', padx=4)

        # ── Install Ollama button — only shown when Ollama is not installed ───
        if not ollama_installed:
            ttk.Separator(btn_frame, orient='vertical').pack(side='left', fill='y',
                                                             padx=8, pady=4)
            def _open_ollama_download():
                import webbrowser
                webbrowser.open('https://ollama.com/download')
                messagebox.showinfo(
                    "Installing Ollama",
                    "Your browser will open the Ollama download page.\n\n"
                    "Steps:\n"
                    "  1. Download and run OllamaSetup.exe\n"
                    "  2. Wait for installation to complete\n"
                    "  3. Close and reopen this Browse & Install window\n"
                    "  4. Select and install a model\n\n"
                    "Recommended starter: llama3.2:3b (~2 GB, good quality)",
                    parent=picker
                )
            ttk.Button(btn_frame,
                       text="⬇  Install Ollama First",
                       command=_open_ollama_download).pack(side='left', padx=4)

        # Legend
        ttk.Label(btn_frame, text="  📦 = installed   ✅ = fits your RAM   ⚠️ = needs more RAM",
                  font=('Arial', 8), foreground='gray').pack(side='right', padx=8)

        def _on_picker_resize(event):
            if event.widget is picker:
                desc_lbl.config(wraplength=max(100, event.width - 20))
        picker.bind('<Configure>', _on_picker_resize)
        picker.bind('<Escape>', lambda e: picker.destroy())

        picker.grab_set()
        picker.focus_force()

        # Trigger description update for pre-selected model
        if current in picker_models:
            on_select()

    def install_model(self):
        """Install selected model (legacy — called directly for backward compat)"""
        self.show_model_picker()
    
    @staticmethod
    def _find_ollama_exe():
        """Resolve the full path to ollama.exe.

        On Windows, Ollama installs to %LOCALAPPDATA%/Programs/Ollama/ollama.exe
        but the GUI process may not have that on its PATH (especially when launched
        via a shortcut or RAG_RUN.bat). We check the known install location first,
        then fall back to shutil.which so it also works on Linux/Mac.
        """
        import shutil, os
        # Known Windows install location
        local_app = os.environ.get('LOCALAPPDATA', '')
        if local_app:
            candidate = os.path.join(local_app, 'Programs', 'Ollama', 'ollama.exe')
            if os.path.isfile(candidate):
                return candidate
        # Fall back to PATH search (works if Ollama added itself to PATH, or on Linux/Mac)
        found = shutil.which('ollama')
        if found:
            return found
        return None   # not found anywhere

    def install_model_worker(self, model, dl_queue, abort_event):
        """Background thread: pull model via Ollama REST API.

        Messages put onto dl_queue:
          ('line',    str)  — new line of text
          ('bar',     str)  — overwrite last line (progress update)
          ('done',    str)  — finished OK
          ('failed',  str)  — error detail
          ('aborted', '')   — user aborted
        """
        import json as _json, time as _time, subprocess as _sp, os as _os, shutil as _sh, sys as _sys, requests as requests

        OLLAMA_BASE = "http://localhost:11434"

        def put(kind, data=""):
            dl_queue.put((kind, data))

        # ── Step 1: locate ollama.exe ─────────────────────────────────────────
        local_app   = _os.environ.get('LOCALAPPDATA', '')
        ollama_exe  = None
        if local_app:
            cand = _os.path.join(local_app, 'Programs', 'Ollama', 'ollama.exe')
            if _os.path.isfile(cand):
                ollama_exe = cand
        if not ollama_exe:
            ollama_exe = _sh.which('ollama')

        if ollama_exe:
            put('line', f"Found ollama: {ollama_exe}\n")
        else:
            put('failed',
                "Cannot find ollama.exe.\n"
                "Expected: %LOCALAPPDATA%\\Programs\\Ollama\\ollama.exe\n"
                "Install Ollama from https://ollama.com and try again.")
            return

        # ── Step 2: ensure Ollama server is running ─────────────────────────
        # Use TCP port check — works even before Ollama's HTTP layer is ready,
        # and bypasses Windows proxy settings that break requests.get().
        import socket as _sock

        def port_open():
            try:
                with _sock.create_connection(('127.0.0.1', 11434), timeout=2):
                    return True
            except OSError:
                return False

        def is_up():
            """HTTP check with explicit proxy bypass for Windows."""
            try:
                r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=3,
                                 proxies={"http": None, "https": None})
                return r.status_code == 200
            except Exception:
                return False

        if port_open():
            put('line', "Ollama server: port 11434 is open ✓\n")
            # Even when the port is open, Ollama may not have finished
            # initialising — specifically, it writes an Ed25519 identity
            # key to ~/.ollama/id_ed25519 on first run.  If that file is
            # missing (e.g. the .ollama folder was cleared by a previous
            # uninstall) Ollama must be restarted to regenerate it;
            # otherwise every 'ollama pull' fails with:
            #   'open ...id_ed25519: The system cannot find the file'
            user_profile  = _os.environ.get('USERPROFILE', _os.path.expanduser('~'))
            ollama_key    = _os.path.join(user_profile, '.ollama', 'id_ed25519')
            if not _os.path.isfile(ollama_key):
                put('line', "⚠️  Ollama identity key missing — restarting Ollama to regenerate it...\n")
                # Kill the running Ollama process so serve can restart cleanly
                try:
                    if _sys.platform == 'win32':
                        _sp.run(['taskkill', '/F', '/IM', 'ollama.exe'],
                                capture_output=True)
                    else:
                        _sp.run(['pkill', '-f', 'ollama serve'],
                                capture_output=True)
                except Exception:
                    pass
                _time.sleep(2)  # brief pause so the port is released
                # Fall through to the 'else' branch below to start serve
                # and wait for the port — reuse the same startup logic.
                try:
                    if _sys.platform == 'win32':
                        _si = _sp.STARTUPINFO()
                        _si.dwFlags |= _sp.STARTF_USESHOWWINDOW
                        _si.wShowWindow = 0
                        srv_proc = _sp.Popen(
                            [ollama_exe, 'serve'],
                            startupinfo=_si,
                            creationflags=_sp.CREATE_NO_WINDOW,
                            stdout=_sp.PIPE, stderr=_sp.STDOUT
                        )
                    else:
                        srv_proc = _sp.Popen(
                            [ollama_exe, 'serve'],
                            stdout=_sp.PIPE, stderr=_sp.STDOUT
                        )
                    self._ollama_process = srv_proc
                    # Wait for port to reopen and key file to appear
                    put('line', "Waiting for Ollama to reinitialise")
                    deadline2 = _time.time() + 60
                    dots2 = 0
                    while _time.time() < deadline2:
                        if abort_event.is_set():
                            srv_proc.kill()
                            put('aborted')
                            return
                        if port_open() and _os.path.isfile(ollama_key):
                            put('line', f" ready after ~{dots2}s ✓\n")
                            break
                        dots2 += 1
                        put('bar', f"Waiting for Ollama to reinitialise {'.' * (dots2 % 6 + 1)}")
                        _time.sleep(1)
                    else:
                        put('failed',
                            "Ollama did not reinitialise within 60 seconds.\n"
                            "Try: quit Ollama from the system tray, relaunch it, then try again.")
                        return
                except Exception as e:
                    put('failed', f"Failed to restart Ollama: {e}")
                    return
        else:
            put('line', "Ollama not running — starting it now...\n")
            try:
                if _sys.platform == 'win32':
                    _si = _sp.STARTUPINFO()
                    _si.dwFlags |= _sp.STARTF_USESHOWWINDOW
                    _si.wShowWindow = 0
                    srv_proc = _sp.Popen(
                        [ollama_exe, 'serve'],
                        startupinfo=_si,
                        creationflags=_sp.CREATE_NO_WINDOW,
                        stdout=_sp.PIPE,
                        stderr=_sp.STDOUT
                    )
                else:
                    srv_proc = _sp.Popen(
                        [ollama_exe, 'serve'],
                        stdout=_sp.PIPE, stderr=_sp.STDOUT
                    )
                put('line', f"Ollama process started (PID {srv_proc.pid})\n")
                self._ollama_process = srv_proc
            except Exception as e:
                put('failed', f"Failed to launch ollama serve: {e}")
                return

            # Wait up to 90s for TCP port to open
            put('line', "Waiting for Ollama port 11434")
            deadline = _time.time() + 90
            dots = 0
            while _time.time() < deadline:
                if abort_event.is_set():
                    srv_proc.kill()
                    put('aborted')
                    return
                rc = srv_proc.poll()
                if rc is not None:
                    try:
                        out_text = srv_proc.stdout.read(4000).decode('utf-8', errors='replace').strip()
                    except Exception:
                        out_text = ""
                    # "address in use" = another Ollama already running — not an error
                    addr_in_use = ('address already in use' in out_text.lower() or
                                   'only one usage of each socket' in out_text.lower())
                    if addr_in_use:
                        put('line', "\nOllama already running on port 11434 ✓\n")
                        break
                    detail = f"\n\n{out_text}" if out_text else ""
                    put('failed', f"Ollama exited immediately (code {rc}).{detail}\n\nTry: ollama serve")
                    return
                if port_open():
                    put('line', f" opened after ~{dots}s ✓\n")
                    break
                dots += 1
                put('bar', f"Waiting for Ollama port 11434 {'.' * (dots % 6 + 1)}")
                _time.sleep(1)
            else:
                srv_proc.kill()
                put('failed', "Ollama did not open port 11434 within 90 seconds.\nTry: ollama serve")
                return

        put('line', "Proceeding to pull model...\n")

        # ── Step 3: stream the pull via REST API ──────────────────────────────
        put('line', f"\nPulling {model} — this may take several minutes...\n")
        try:
            resp = requests.post(
                f"{OLLAMA_BASE}/api/pull",
                json={"name": model, "stream": True},
                stream=True,
                timeout=None,
                proxies={"http": None, "https": None}
            )
            resp.raise_for_status()

            for raw in resp.iter_lines():
                if abort_event.is_set():
                    resp.close()
                    put('aborted')
                    return
                if not raw:
                    continue
                try:
                    evt = _json.loads(raw)
                except Exception:
                    continue

                status    = evt.get('status',    '')
                total     = evt.get('total',     0)
                completed = evt.get('completed', 0)
                digest    = evt.get('digest',    '')
                error     = evt.get('error',     '')

                if error:
                    put('failed', f"Ollama error: {error}")
                    return

                if total and completed:
                    pct      = completed / total * 100
                    done_mb  = completed / 1_048_576
                    tot_mb   = total     / 1_048_576
                    layer    = digest[-12:] if digest else ''
                    filled   = int(pct / 5)
                    bar      = '█' * filled + '░' * (20 - filled)
                    put('bar', f"{status:<22} [{bar}] {pct:5.1f}%  {done_mb:,.0f}/{tot_mb:,.0f} MB  {layer}")
                elif status:
                    put('line', status + "\n")

            put('done', f"✅  {model} downloaded successfully!")

        except Exception as e:
            put('failed', f"REST API error: {e}")
    def _launch_install_progress_window(self, model):
        """Open progress window, write initial text immediately, start worker."""
        import threading as _threading
        import queue    as _queue

        dl_queue    = _queue.Queue()
        abort_event = _threading.Event()

        win = tk.Toplevel(self.root)
        win.title(f"Downloading {model}")
        win.resizable(True, True)
        win.minsize(560, 360)
        win.transient(self.root)

        self.root.update_idletasks()
        rx, ry = self.root.winfo_rootx(), self.root.winfo_rooty()
        rw, rh = self.root.winfo_width(), self.root.winfo_height()
        pw, ph = 620, 420
        win.geometry(f"{pw}x{ph}+{rx + rw//2 - pw//2}+{ry + rh//2 - ph//2}")
        win.columnconfigure(0, weight=1)
        win.rowconfigure(1, weight=1)

        # Header
        hdr = ttk.Frame(win, padding=(12, 8))
        hdr.grid(row=0, column=0, sticky='ew')
        ttk.Label(hdr, text=f"⬇  Downloading {model}",
                  font=('Arial', 12, 'bold')).pack(side='left')

        # Terminal
        txt_frame = ttk.Frame(win, padding=(8, 0, 8, 0))
        txt_frame.grid(row=1, column=0, sticky='nsew')
        txt_frame.columnconfigure(0, weight=1)
        txt_frame.rowconfigure(0, weight=1)

        sb  = ttk.Scrollbar(txt_frame, orient='vertical')
        out = tk.Text(txt_frame, wrap='char', font=('Courier New', 9),
                      yscrollcommand=sb.set, background='#1e1e1e',
                      foreground='#d4d4d4', insertbackground='white')
        sb.config(command=out.yview)
        out.grid(row=0, column=0, sticky='nsew')
        sb.grid(row=0, column=1, sticky='ns')

        # Status bar
        sf = ttk.Frame(win, padding=(8, 6))
        sf.grid(row=2, column=0, sticky='ew')
        status_var = tk.StringVar(value="Initialising...")
        status_lbl = ttk.Label(sf, textvariable=status_var,
                               font=('Arial', 9), foreground='gray')
        status_lbl.pack(side='left', fill='x', expand=True)

        close_btn = ttk.Button(sf, text="Close", command=win.destroy, state='disabled')
        close_btn.pack(side='right', padx=(4, 0))

        def do_abort():
            abort_event.set()
            abort_btn.config(state='disabled', text="Aborting…")
            status_var.set("⏹  Aborting — please wait...")
            status_lbl.config(foreground='orange')

        abort_btn = ttk.Button(sf, text="⏹  Abort", command=do_abort)
        abort_btn.pack(side='right', padx=(0, 4))

        def _on_close():
            if abort_event.is_set() or close_btn['state'] == 'normal':
                win.destroy()
            elif messagebox.askyesno("Abort?",
                    f"Download of {model} is still in progress.\n\nAbort and close?",
                    parent=win):
                do_abort()
        win.protocol("WM_DELETE_WINDOW", _on_close)

        # ── Write helpers (main thread only) ─────────────────────────────────
        def write(text):
            out.insert('end', text)
            out.see('end')

        def overwrite_last(text):
            out.delete('end-1l linestart', 'end-1c')
            out.insert('end', text)
            out.see('end')

        # Write first line IMMEDIATELY so user knows the widget is alive
        write(f"Starting download of {model}...\n")
        win.update_idletasks()   # force tkinter to render it now

        # ── Queue poller — fires every 50 ms on main thread ──────────────────
        def poll():
            try:
                while True:
                    kind, data = dl_queue.get_nowait()
                    if kind == 'line':
                        write(data)
                        status_var.set(data.strip()[:100] or status_var.get())
                    elif kind == 'bar':
                        overwrite_last(data)
                        status_var.set(data[:100])
                    elif kind == 'done':
                        write("\n" + data + "\n")
                        status_var.set(data)
                        status_lbl.config(foreground='green')
                        self.status_var.set(f"✅ {model} installed — select it in Settings → Active model.")
                        self._rebuild_model_combo()   # refresh Active Model dropdown
                        self._rebuild_model_combo()   # add new model to Settings dropdown
                        self._rebuild_local_provider_entries(rebuild_combo=True)   # add to provider dropdown
                        abort_btn.config(state='disabled')
                        close_btn.config(state='normal')
                        return   # stop polling
                    elif kind == 'failed':
                        write("\n❌ FAILED: " + data + "\n")
                        status_var.set("❌ Download failed — see details above.")
                        status_lbl.config(foreground='red')
                        self.status_var.set(f"❌ Failed to install {model}.")
                        abort_btn.config(state='disabled')
                        close_btn.config(state='normal')
                        return
                    elif kind == 'aborted':
                        write("\n⏹  Download cancelled.\n")
                        status_var.set("⏹  Download cancelled.")
                        status_lbl.config(foreground='orange')
                        self.status_var.set(f"Download of {model} cancelled.")
                        abort_btn.config(state='disabled')
                        close_btn.config(state='normal')
                        return
            except Exception:
                pass
            try:
                win.after(50, poll)   # keep polling while window alive
            except Exception:
                pass

        win.after(50, poll)

        _threading.Thread(
            target=self.install_model_worker,
            args=(model, dl_queue, abort_event),
            daemon=True
        ).start()
    def show_stats(self):
        """Show database statistics"""
        old_stdout = sys.stdout
        try:
            import io
            captured = io.StringIO()
            sys.stdout = captured
            show_stats()
            sys.stdout = old_stdout
            output = captured.getvalue()
            messagebox.showinfo("Database Statistics", output if output.strip() else "No statistics available.")
        except Exception as e:
            sys.stdout = old_stdout
            messagebox.showerror("Error", f"Could not retrieve statistics: {e}")
    
    def clear_database(self):
        """Clear ChromaDB vectors AND the file-tracking database so all files re-index."""
        if messagebox.askyesno(
                "Clear Database",
                "This will delete ALL indexed data:\n\n"
                "  • ChromaDB vector store  (all document embeddings)\n"
                "  • File-tracking timestamps  (so every file re-indexes on next scan)\n\n"
                "This cannot be undone.\n\nContinue?"):
            errors = []
            # 1. Clear the ChromaDB vector store
            try:
                clear_database(confirm=True)
            except Exception as e:
                errors.append(f"ChromaDB: {e}")

            # 2. Wipe the tracking database so no file appears 'unchanged'
            try:
                if RAG_AVAILABLE and TRACKING_DB.exists():
                    import json as _json
                    TRACKING_DB.write_text('{}', encoding='utf-8')
            except Exception as e:
                errors.append(f"Tracking DB: {e}")

            if errors:
                messagebox.showerror("Partial Error",
                                     "Database cleared with errors:\n\n" +
                                     "\n".join(errors))
            else:
                messagebox.showinfo(
                    "Database Cleared",
                    "✅ Vector store cleared.\n"
                    "✅ File-tracking timestamps reset.\n\n"
                    "All files will be fully re-indexed on the next scan.")
            self.refresh_tracked_dirs()
    
    def process_output_queue(self):
        """Process output queue from worker threads"""
        try:
            while True:
                msg_type, msg_data = self.output_queue.get_nowait()
                
                if msg_type == 'index':
                    self.index_output.insert(tk.END, msg_data)
                    self.index_output.see(tk.END)
                    
                elif msg_type == 'query':
                    self.answer_output.insert(tk.END, msg_data)
                    self.answer_output.see(tk.END)
                    
                elif msg_type == 'update':
                    self.update_output.insert(tk.END, msg_data)
                    self.update_output.see(tk.END)
                    
                elif msg_type == 'status':
                    self.status_var.set(msg_data)

                elif msg_type == 'mic_auto_stop':
                    # Silence detector fired — same as manual stop press
                    if self._mic_recording:
                        self._mic_stop()

                elif msg_type == 'mic_transcribing':
                    # Whisper is working — button already shows ⏳ from _mic_stop
                    self._mic_status_var.set("⏳ Transcribing…")

                elif msg_type == 'mic_result':
                    text = msg_data.strip()
                    self._mic_reset_button()
                    if text:
                        if self.mic_mode_append.get():
                            # Append mode — add to whatever is already in the box
                            existing = self.question_text.get('1.0', 'end-1c').strip()
                            new_text = (existing + ' ' + text).strip() if existing else text
                        else:
                            # Replace mode — clear the box first
                            new_text = text
                        self.question_text.delete('1.0', tk.END)
                        self.question_text.insert('1.0', new_text)
                        self._mic_status_var.set("✅ Transcription complete — review and press Ask Question")
                        self.status_var.set("Speech transcribed")
                    else:
                        self._mic_status_var.set("⚠️  No speech detected — try again")
                        self.status_var.set("Ready")

                elif msg_type == 'mic_error':
                    self._mic_reset_button()
                    self._mic_status_var.set(f"❌ {msg_data}")
                    self.status_var.set("Ready")

                elif msg_type == 'gpu_status':
                    self._gpu_status_set(msg_data)

                elif msg_type == 'gpu_suggest':
                    # Auto-populate the layers spinbox with the suggested value
                    self.gpu_layers_var.set(msg_data)
                    self._refresh_gpu_layers_desc()
                    
                elif msg_type == 'prewarm_ok':
                    self.status_var.set("AI model loaded — running test query to warm cache...")
                    # Note: warmup will go green automatically when test query completes

                elif msg_type == 'warmup_complete':
                    # Test query completed - turn warmup indicator green
                    self._warmup_complete()
                    self.root.after(4000, lambda: self.status_var.set("Ready"))

                elif msg_type == 'warmup_timer_start':
                    # Start the warmup waiting timer
                    self._warmup_start_time = time.time()
                    self.answer_output.insert(tk.END, "⏳ Waiting for response... 0s\n")
                    self.answer_output.see(tk.END)
                    self._tick_warmup_timer()

                elif msg_type == 'warmup_timer_stop':
                    # Stop the warmup waiting timer
                    if self._warmup_timer_id is not None:
                        self.root.after_cancel(self._warmup_timer_id)
                        self._warmup_timer_id = None
                    self._warmup_start_time = None

                elif msg_type == 'warmup_timer_tick':
                    # Update the waiting message in place without scrolling
                    try:
                        # Find the line that starts with the hourglass emoji
                        start_pos = self.answer_output.search("⏳ Waiting", "1.0", tk.END)
                        if start_pos:
                            # Get the line end position
                            end_pos = f"{start_pos} lineend"
                            # Delete the old timer text
                            self.answer_output.delete(start_pos, end_pos)
                            # Insert new timer text at the same position
                            self.answer_output.insert(start_pos, msg_data.strip())
                            # DON'T call see() - let scroll position stay where it is
                    except Exception:
                        pass  # If search fails, just skip the update

                elif msg_type == 'prewarm_fail':
                    self.status_var.set("Ready")  # fail silently — not critical

                elif msg_type == 'ollama_status':
                    self._ollama_set_status(msg_data)

                elif msg_type == 'ollama_autoquery':
                    # Model finished auto-loading — fire the queued question now
                    question   = msg_data
                    self.answer_output.delete('1.0', tk.END)
                    self.query_progress.start()
                    self._query_start_time = time.time()
                    self.query_elapsed_var.set("⏱ 0s elapsed")
                    self._tick_query_timer()
                    self.status_var.set("Querying...")
                    # Reset cancel so future idle prewarming works again after query finishes
                    self._prewarm_cancel = False
                    # Reset stop flag and mark query as running — enables Stop button
                    if RAG_AVAILABLE:
                        _rag_engine.QUERY_STOP = False
                    self._query_running = True
                    self._stop_query_btn.configure(state='normal')
                    chunks_str = self.chunks_var.get()
                    n_contexts = None if chunks_str.startswith("Auto") else int(chunks_str.split()[0])
                    threading.Thread(target=self.query_worker,
                                     args=(question, n_contexts, []), daemon=True).start()
                    
                elif msg_type == 'provider_test_result':
                    r = msg_data
                    # Update status bar
                    self.status_var.set(r['message'])
                    # Update the dot for this provider
                    if r.get('ok'):
                        self._update_api_dot_color(r.get('provider',''), '#27ae60')
                    # Show a clear popup with full diagnostics
                    title  = f"Connection Test — {r['provider']}"
                    body   = (f"{r['message']}\n\n"
                              f"{'─'*48}\n"
                              f"{r.get('detail','')}\n\n"
                              f"Model: {r.get('model','')}\n"
                              f"HTTP status: {r.get('status', 'n/a')}")
                    if r.get('ok'):
                        messagebox.showinfo(title, body)
                    else:
                        messagebox.showwarning(title, body)

                elif msg_type == 'error':
                    messagebox.showerror("Error", msg_data)
                    
                elif msg_type == 'info':
                    messagebox.showinfo("Information", msg_data)
                    
                elif msg_type == 'index_progress':
                    self.index_progress_var.set(msg_data)

                elif msg_type == 'done':
                    if msg_data == 'index':
                        self.index_progress.stop()
                        self.index_progress_var.set("")
                        self._stop_index_timer()        # show final ✅ time
                        self._index_set_buttons('idle')
                        self.refresh_tracked_dirs()
                        import datetime as _dt
                        self._last_index_time = _dt.datetime.now().strftime('%Y-%m-%d  %H:%M:%S')
                    elif msg_data == 'index_stopped':
                        self.index_progress.stop()
                        self._cancel_index_timer()      # freeze at stopped time
                        self._index_set_buttons('stopped')
                        self.refresh_tracked_dirs()  # show dirs completed before stop
                    elif msg_data == 'query':
                        self.query_progress.stop()
                        # Disable Stop button — query is finished
                        self._query_running = False
                        self._stop_query_btn.configure(state='disabled')
                        if RAG_AVAILABLE:
                            _rag_engine.QUERY_STOP = False
                        # Stop elapsed timer and show final time
                        if self._query_timer_id is not None:
                            self.root.after_cancel(self._query_timer_id)
                            self._query_timer_id = None
                        if self._query_start_time is not None:
                            elapsed = int(time.time() - self._query_start_time)
                            mins, secs = divmod(elapsed, 60)
                            # Show stopped vs completed message
                            if RAG_AVAILABLE and getattr(_rag_engine, 'QUERY_STOP', False):
                                self.query_elapsed_var.set(f"⏹ Stopped at {mins}m {secs:02d}s" if mins else f"⏹ Stopped at {secs}s")
                            else:
                                time_str = f"{mins}m {secs:02d}s" if mins > 0 else f"{secs}s"
                                self.query_elapsed_var.set(f"✅ Done in {time_str}")
                            self._query_start_time = None
                        # Scan answer for downloadable files and show Save buttons
                        detected = self._scan_answer_for_files()
                        self._show_detected_files(detected)
                    elif msg_data == 'update':
                        self.update_progress.stop()
                        self.refresh_tracked_dirs()
                        import datetime as _dt
                        self._last_index_time = _dt.datetime.now().strftime('%Y-%m-%d  %H:%M:%S')
                    elif msg_data == 'remove_tracked':
                        self.update_progress.stop()
                        self.remove_tracked_btn.configure(state='normal')
                        self.refresh_tracked_dirs()
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_output_queue)
    
    # ── Sleep prevention ──────────────────────────────────────────────────────
    def _set_sleep_prevention(self, prevent: bool):
        """
        Block or restore Windows sleep / screen-off while the HTTP MCP server
        is running.  Uses SetThreadExecutionState — a standard Windows API
        available on all modern Windows versions with no extra packages.

        prevent=True  → tell Windows "this thread needs the system awake"
                        (prevents sleep AND hibernation; does not keep screen on)
        prevent=False → clear the flag, restoring normal power-management
        """
        if sys.platform != 'win32':
            return  # no-op on non-Windows
        import ctypes
        ES_CONTINUOUS      = 0x80000000
        ES_SYSTEM_REQUIRED = 0x00000001   # prevents sleep/hibernate
        if prevent:
            flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED
            ctypes.windll.kernel32.SetThreadExecutionState(flags)
        else:
            # ES_CONTINUOUS alone clears all previous flags → normal sleep allowed
            ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)

    def _on_window_close(self):
        """Handle window close event - stop Ollama if we started it."""
        # Stop Ollama if we started it
        if self._ollama_process is not None:
            print("Stopping Ollama server (started by AI Prowler)...")
            try:
                self._ollama_process.terminate()
                # Wait a moment for graceful shutdown
                import time
                time.sleep(1)
                # Force kill if still running
                if self._ollama_process.poll() is None:
                    self._ollama_process.kill()
                print("Ollama server stopped")
            except Exception as e:
                print(f"Error stopping Ollama: {e}")
        
        # Stop HTTP MCP server if running — also restore sleep prevention
        if self._http_server_proc is not None:
            try:
                self._http_server_proc.terminate()
                self._http_server_proc.wait(timeout=3)
            except Exception:
                pass
            self._set_sleep_prevention(False)   # always restore on exit
        # Stop cloudflared tunnel if running
        if self._cloudflared_proc is not None:
            try:
                self._cloudflared_proc.terminate()
                self._cloudflared_proc.wait(timeout=3)
            except Exception:
                pass
        # Close the window and terminate the process (including the CMD window)
        self.root.destroy()
        # os._exit() terminates the Python process immediately, which also
        # kills the parent CMD/batch window that launched AI-Prowler.
        # Without this, the DOS prompt stays open after the GUI closes.
        import os as _os
        _os._exit(0)

class FilteredTextRedirector:
    """
    Text redirector that filters out specific unwanted messages.
    Used for warmup test to suppress unhelpful default responses.
    """
    def __init__(self, queue, tag, filter_phrases=None):
        self.queue = queue
        self.tag = tag
        self.filter_phrases = filter_phrases or []

    def write(self, text):
        if not text:
            return
        # Check if this text contains any filtered phrases
        for phrase in self.filter_phrases:
            if phrase in text:
                return  # Skip this output entirely
        # Convert \r-only overwrites to newline-based updates for the GUI
        text = text.replace('\r', '\n')
        # Collapse runs of multiple newlines
        import re
        text = re.sub(r'\n{3,}', '\n\n', text)
        if text.strip() or text == '\n':
            self.queue.put((self.tag, text))

    def flush(self):
        pass

    def isatty(self):
        return False

    def readable(self):
        return False

    def writable(self):
        return True


class TextRedirector:
    """
    Redirect sys.stdout to a Tkinter queue for display in a ScrolledText widget.

    Handles terminal-style \\r (carriage-return) output: when a line starts with
    \\r it signals 'overwrite the current line', which we convert to a plain
    newline so the GUI shows each update on its own line cleanly instead of
    jamming everything onto one line or corrupting the display.
    """
    def __init__(self, queue, tag):
        self.queue = queue
        self.tag = tag

    def write(self, text):
        if not text:
            return
        # Convert \r-only overwrites to newline-based updates for the GUI.
        # Terminal spinners use \r to overwrite; in a text widget we just
        # want each update on its own line.
        text = text.replace('\r', '\n')
        # Collapse runs of multiple newlines down to one to avoid blank-line spam
        import re
        text = re.sub(r'\n{3,}', '\n\n', text)
        if text.strip() or text == '\n':
            self.queue.put((self.tag, text))

    def flush(self):
        pass

    def isatty(self):
        return False

    def readable(self):
        return False

    def writable(self):
        return True

def main():
    """Main entry point"""

    # ── Hide the Python console window (2nd DOS window) when Debug View is OFF ──
    # AI Prowler is launched with python.exe which always creates a CMD console.
    # We hide it here unless the saved config has debug_view=True.
    if sys.platform == 'win32':
        try:
            import json as _json
            _cfg_path = Path.home() / '.rag_config.json'
            _debug_view = False
            if _cfg_path.exists():
                with open(_cfg_path, 'r') as _f:
                    _cfg = _json.load(_f)
                _debug_view = _cfg.get('debug_view', False)
            if not _debug_view:
                # Hide the console window without closing it
                _hwnd = ctypes.windll.kernel32.GetConsoleWindow()
                if _hwnd:
                    ctypes.windll.user32.ShowWindow(_hwnd, 0)  # SW_HIDE
        except Exception:
            pass   # Never crash startup over window-hiding

    if not RAG_AVAILABLE:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("AI Prowler Engine Not Found",
                           f"Could not import AI Prowler modules.\n\n"
                           f"Error: {_RAG_ERROR}\n\n"
                           f"Script dir: {str(Path(__file__).parent)}")
        return
    
    root = tk.Tk()
    
    # Try to set theme
    try:
        style = ttk.Style()
        style.theme_use('clam')  # or 'alt', 'default', 'classic'
        
        # Custom accent button
        style.configure('Accent.TButton',
                       font=('Arial', 10, 'bold'))
    except:
        pass
    
    app = RAGGui(root)
    root.mainloop()

if __name__ == "__main__":
    main()
