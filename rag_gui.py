#!/usr/bin/env python3
"""
AI Prowler GUI - Professional Graphical Interface
Modern GUI for AI Prowler Document Indexing and Querying
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import time
import subprocess
import json
import sys
from pathlib import Path
import queue
import os
import ctypes

# Ensure script directory is on sys.path so rag_preprocessor.py is always found
# even when launched via desktop icon
sys.path.insert(0, str(Path(__file__).parent.resolve()))

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
        """Load the Whisper large-v3-turbo model once and cache it for the session."""
        with cls._model_lock:
            if cls._whisper_model is None:
                # Use GPU if available, otherwise CPU with int8 quantisation
                try:
                    import torch
                    device = 'cuda' if torch.cuda.is_available() else 'cpu'
                except ImportError:
                    device = 'cpu'
                compute = 'float16' if device == 'cuda' else 'int8'
                cls._whisper_model = WhisperModel(
                    'large-v3-turbo',
                    device=device,
                    compute_type=compute
                )
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
        self.root.title("AI Prowler - Personal AI Knowledge Base")
        self.root.geometry("1000x700")
        
        # Set icon (if available)
        try:
            # self.root.iconbitmap('icon.ico')
            pass
        except:
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

        # ── Ollama status ────────────────────────────────────────────────────
        self._ollama_ready       = False   # True = model loaded and warmed
        self._ollama_loading     = False   # True = load in progress
        self._query_running      = False   # True while a query thread is active
        
        # Query output mode — mirrors SHOW_SOURCES in rag_preprocessor
        self.show_sources_var = tk.BooleanVar(value=False)

        # GPU layers for Ollama (-1 = auto, 0 = CPU only, N = partial)
        self.gpu_layers_var = tk.IntVar(value=-1)
        
        # Auto-start Ollama server on startup
        self.auto_start_ollama_var = tk.BooleanVar(value=False)
        self._ollama_process = None  # Track if we started Ollama

        # Microphone / speech-to-text state
        self._mic_recorder  = None
        self._mic_recording = False
        self.mic_silence_var = tk.DoubleVar(value=3.0)

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
                    # Load gpu_layers — default -1 (auto)
                    gpu_layers = config.get('gpu_layers', -1)
                    self.gpu_layers_var.set(gpu_layers)
                    if RAG_AVAILABLE:
                        _rag_engine.GPU_LAYERS = gpu_layers
                    # Load auto_start_ollama — default False (manual start)
                    auto_start = config.get('auto_start_ollama', False)
                    self.auto_start_ollama_var.set(auto_start)
                    print(f"[CONFIG] Loaded auto_start_ollama: {auto_start}")
                    # Load mic silence timeout — default 3.0 seconds
                    silence_secs = config.get('mic_silence_secs', 3.0)
                    self.mic_silence_var.set(silence_secs)
                    if SPEECH_AVAILABLE:
                        SpeechRecorder.SILENCE_SECS = silence_secs
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
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        help_menu.add_command(label="📖 User Guide", command=self.show_user_guide)
        help_menu.add_command(label="🚀 Quick Start", command=self.show_quick_start)
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
        about_text = """AI Prowler - Personal AI Knowledge Base
Version 1.8

Your personal AI assistant that answers questions about YOUR documents.

Features:
• Multi-model support (15+ AI models)
• Smart chunking optimization
• Automatic file tracking
• Email support (.eml, .msg, .mbox)
• Intelligent auto-updates
• Professional GUI interface

100% Local • 100% Private • 100% Yours

Built with Python, ChromaDB, and Ollama"""
        
        messagebox.showinfo("About AI Prowler", about_text)
    
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
        return """AI PROWLER QUICK START GUIDE

🚀 Getting Started in 4 Steps
================================

STEP 1: Index Your Documents
-----------------------------
1. Click "📚 Index Documents" tab
2. Click "Browse..." button
3. Select your Documents folder
4. Click "Start Indexing"
5. Wait for "INDEXING COMPLETE"

What gets indexed:
• PDFs, Word documents
• Text files, code files
• Emails (.eml, .msg, .mbox)
• And 50+ more file types!

Time: 2-5 minutes for typical Documents folder


STEP 2: Ask Questions
----------------------
1. Click "🔍 Ask Questions" tab
2. Type your question
3. Press Enter
4. Read the AI's answer

Example questions:
• "What projects am I working on?"
• "Find my flight confirmation"
• "Summarize my meeting notes from last week"

Time: 10-20 seconds per question


STEP 3: Keep Updated
---------------------
1. Click "🔄 Update Index" tab
2. Click "Update All" button
3. Only changed files are re-indexed

Do this weekly or after adding files.

Time: 10-30 seconds (much faster than re-indexing!)


STEP 4: Customize (Optional)
-----------------------------
1. Click "⚙️ Settings" tab
2. Choose different AI model from dropdown
3. Click "Install Selected Model"
4. Future queries use new model

Models to try:
• llama3.2:1b (default, balanced)
• llama3.1:8b (better quality)
• qwen2.5:0.5b (ultra-fast)


📋 Tips & Best Practices
=========================

✅ DO:
• Index organized folders (Documents, Projects)
• Use natural language in questions
• Start with "Auto (3)" chunk setting
• Update weekly for active projects

❌ DON'T:
• Index entire C: drive (too much!)
• Close window during indexing
• Use command syntax in questions
• Re-index from scratch (use Update instead!)


🚨 Troubleshooting
==================

Problem: No documents found
Solution: Index documents first (Tab 1)

Problem: Slow queries
Solution: Switch to faster model (Settings tab)

Problem: GUI won't start
Solution: Run INSTALL.bat again


📞 Need More Help?
==================

Read the complete guide:
Help → User Guide

Or open: COMPLETE_USER_GUIDE.md


That's it! You're ready to use RAG!
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
        self.create_query_tab()       # 0  ← Ask Questions (prewarmed on switch)
        self.create_index_tab()       # 1
        self.create_update_tab()      # 2
        self.create_scan_config_tab() # 3
        self.create_scheduling_tab()  # 4
        self.create_settings_tab()    # 5

        # Named tab index constants — change here if tabs are ever reordered
        self._TAB_INDEX_QUERY    = 0   # Ask Questions tab — triggers Ollama prewarm
        self._TAB_INDEX_INDEX    = 1
        self._TAB_INDEX_UPDATE   = 2
        self._TAB_INDEX_SCAN     = 3
        self._TAB_INDEX_SCHEDULE = 4
        self._TAB_INDEX_SETTINGS = 5
        
        # Status bar
        self.create_status_bar()
    
    def create_index_tab(self):
        """Create indexing tab with multi-directory queue and smart scan mode."""
        index_frame = ttk.Frame(self.notebook)
        self.notebook.add(index_frame, text="📚 Index Documents")

        # Title
        ttk.Label(index_frame, text="Index Your Documents",
                  font=('Arial', 16, 'bold')).pack(pady=10)

        # ── Directory queue ───────────────────────────────────────────────────
        queue_frame = ttk.LabelFrame(index_frame, text="Directory Queue", padding=10)
        queue_frame.pack(fill='x', padx=20, pady=(0, 5))

        # Entry row — manual path entry + multi-select browse buttons
        entry_row = ttk.Frame(queue_frame)
        entry_row.pack(fill='x', pady=(0, 6))

        self.index_dir_var = tk.StringVar()
        dir_entry = ttk.Entry(entry_row, textvariable=self.index_dir_var, font=('Arial', 10))
        dir_entry.pack(side='left', fill='x', expand=True, padx=(0, 6))
        dir_entry.bind('<Return>', lambda e: self._queue_add_directory())

        # Create a menu for the browse button
        self.browse_menu = tk.Menu(entry_row, tearoff=0)
        self.browse_menu.add_command(label="📄 Browse Files (multi-select)...", 
                                      command=self.browse_files_multi)
        self.browse_menu.add_command(label="📁 Browse Folder...", 
                                      command=self.browse_folder_single)
        
        browse_btn = ttk.Button(entry_row, text="📂 Browse... ▼",
                               command=lambda: self.browse_menu.post(
                                   browse_btn.winfo_rootx(),
                                   browse_btn.winfo_rooty() + browse_btn.winfo_height()))
        browse_btn.pack(side='left', padx=(0, 6))
        
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
        opt_frame = ttk.LabelFrame(index_frame, text="Options", padding=(10, 6))
        opt_frame.pack(fill='x', padx=20, pady=(0, 5))

        self.scan_mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame,
                        text="Smart scan — skip binaries, executables and system files  "
                             "(recommended)",
                        variable=self.scan_mode_var).pack(anchor='w')

        self.prescan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt_frame,
                        text="Pre-scan only — show what will be indexed without indexing",
                        variable=self.prescan_var).pack(anchor='w')

        # ── Action buttons ────────────────────────────────────────────────────
        btn_row = ttk.Frame(index_frame)
        btn_row.pack(pady=8)

        self.index_start_btn = ttk.Button(btn_row, text="▶ Start Indexing Queue",
                                          command=self.start_indexing,
                                          style='Accent.TButton')
        self.index_start_btn.pack(side='left', padx=(0, 6))

        self.index_pause_btn = ttk.Button(btn_row, text="⏸ Pause",
                                          command=self._index_pause_resume,
                                          state='disabled')
        self.index_pause_btn.pack(side='left', padx=(0, 6))

        self.index_stop_btn = ttk.Button(btn_row, text="⏹ Stop",
                                         command=self._index_stop,
                                         state='disabled')
        self.index_stop_btn.pack(side='left', padx=(0, 16))

        self.index_scan_btn = ttk.Button(btn_row, text="🔍 Scan Queue",
                                         command=self._run_prescan)
        self.index_scan_btn.pack(side='left')

        # Progress
        prog_row = ttk.Frame(index_frame)
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

        # Output
        ttk.Label(index_frame, text="Output:").pack(anchor='w', padx=20)
        self.index_output = scrolledtext.ScrolledText(index_frame, height=14,
                                                      wrap=tk.WORD)
        self.index_output.pack(fill='both', expand=True, padx=20, pady=(0, 5))
    
    def create_query_tab(self):
        """Create query tab"""
        query_frame = ttk.Frame(self.notebook)
        self.notebook.add(query_frame, text="🔍 Ask Questions")
        
        # Title
        title = ttk.Label(query_frame, text="Ask Your AI Questions", 
                         font=('Arial', 16, 'bold'))
        title.pack(pady=10)
        
        # Question input
        question_frame = ttk.LabelFrame(query_frame, text="Your Question", padding=10)
        question_frame.pack(fill='x', padx=20, pady=10)

        # Entry + mic button on same row
        entry_row = ttk.Frame(question_frame)
        entry_row.pack(fill='x', padx=5, pady=5)

        self.question_var = tk.StringVar()
        question_entry = ttk.Entry(entry_row, textvariable=self.question_var,
                                   font=('Arial', 12))
        question_entry.pack(side='left', fill='x', expand=True)
        question_entry.bind('<Return>', lambda e: self.start_query())

        # Mic button — only shown if faster-whisper + sounddevice are installed
        if SPEECH_AVAILABLE:
            self._mic_btn_text = tk.StringVar(value="🎤")
            self._mic_btn = tk.Button(
                entry_row,
                textvariable=self._mic_btn_text,
                font=('Arial', 13),
                width=3,
                relief='flat',
                bg='#e8e8e8',
                activebackground='#d0d0d0',
                cursor='hand2',
                command=self._toggle_mic
            )
            self._mic_btn.pack(side='left', padx=(6, 0))
            self._mic_status_var = tk.StringVar(value="")
            ttk.Label(question_frame, textvariable=self._mic_status_var,
                      font=('Arial', 9), foreground='gray').pack(anchor='w', padx=5)
        
        # Query options
        options_frame = ttk.Frame(query_frame)
        options_frame.pack(fill='x', padx=20, pady=5)
        
        ttk.Label(options_frame, text="Context chunks:").pack(side='left', padx=5)
        
        self.chunks_var = tk.StringVar(value="Auto (3)")
        chunks_combo = ttk.Combobox(options_frame, textvariable=self.chunks_var,
                                    values=[
                                        "Auto (3)",
                                        "1", "2", "3", "4", "5", "6",
                                        "7 ⚠reload", "10 ⚠reload",
                                        "15 ⚠reload", "20 ⚠reload",
                                    ],
                                    width=14, state='readonly')
        chunks_combo.pack(side='left', padx=5)
        # Re-prewarm whenever the user changes chunk count — ensures the model
        # is loaded at the right num_ctx before the next query.
        chunks_combo.bind('<<ComboboxSelected>>', self._on_chunks_changed)
        
        # Model info
        model_info = ttk.Label(options_frame, 
                              text=f"Model: {self.current_model.get()}")
        model_info.pack(side='left', padx=20)
        
        # ── Action row: Ask + Load button + status light ─────────────────────
        action_row = ttk.Frame(query_frame)
        action_row.pack(fill='x', padx=20, pady=(8, 4))

        query_btn = ttk.Button(action_row, text="Ask Question",
                               command=self.start_query,
                               style='Accent.TButton')
        query_btn.pack(side='left', padx=(0, 6))

        self._stop_query_btn = ttk.Button(action_row, text="⏹ Stop",
                                          command=self._stop_query,
                                          state='disabled')
        self._stop_query_btn.pack(side='left', padx=(0, 12))

        self._load_model_btn = ttk.Button(action_row, text="⚡ Load AI Model",
                                          command=self._load_ollama_manual)
        self._load_model_btn.pack(side='left', padx=(0, 10))

        # Status indicator — coloured circle canvas
        self._ollama_light_canvas = tk.Canvas(action_row, width=18, height=18,
                                              highlightthickness=0,
                                              bg=self.root.cget('bg'))
        self._ollama_light_canvas.pack(side='left', padx=(0, 4))
        self._ollama_light = self._ollama_light_canvas.create_oval(
            2, 2, 16, 16, fill='#aaaaaa', outline='#888888', width=1
        )

        self._ollama_status_var = tk.StringVar(value="● Model not loaded")
        self._ollama_status_lbl = ttk.Label(action_row,
                                            textvariable=self._ollama_status_var,
                                            font=('Arial', 9),
                                            foreground='#888888')
        self._ollama_status_lbl.pack(side='left')

        # Progress bar + elapsed time label side by side
        progress_row = ttk.Frame(query_frame)
        progress_row.pack(fill='x', padx=20, pady=(5, 0))
        
        self.query_progress = ttk.Progressbar(progress_row, mode='indeterminate')
        self.query_progress.pack(side='left', fill='x', expand=True)
        
        self.query_elapsed_var = tk.StringVar(value="")
        elapsed_label = ttk.Label(progress_row, textvariable=self.query_elapsed_var,
                                  font=('Arial', 9), foreground='gray', width=14,
                                  anchor='e')
        elapsed_label.pack(side='left', padx=(8, 0))
        
        self._query_timer_id = None   # holds the .after() handle
        self._query_start_time = None
        
        # Answer
        answer_label = ttk.Label(query_frame, text="Answer:")
        answer_label.pack(anchor='w', padx=20)
        
        self.answer_output = scrolledtext.ScrolledText(query_frame, height=18, 
                                                       wrap=tk.WORD,
                                                       font=('Arial', 11))
        self.answer_output.pack(fill='both', expand=True, padx=20, pady=5)
    
    def create_update_tab(self):
        """Create update tab"""
        update_frame = ttk.Frame(self.notebook)
        self.notebook.add(update_frame, text="🔄 Update Index")

        # Title
        ttk.Label(update_frame, text="Keep Your Index Current",
                  font=('Arial', 16, 'bold')).pack(pady=10)

        # Storage locations info bar
        if RAG_AVAILABLE:
            tracking_path   = str(TRACKING_DB)
            update_list_path = str(AUTO_UPDATE_LIST)
        else:
            tracking_path    = "~/.rag_file_tracking.json"
            update_list_path = "~/.rag_auto_update_dirs.json"

        info_frame = ttk.LabelFrame(update_frame,
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
        tracked_frame = ttk.LabelFrame(update_frame,
                                       text="Tracked Directories", padding=10)
        tracked_frame.pack(fill='both', expand=True, padx=20, pady=(0, 6))

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

        ttk.Button(tracked_btn_row, text="🔄 Refresh List",
                   command=self.refresh_tracked_dirs).pack(side='left', padx=(0, 8))

        self.remove_tracked_btn = ttk.Button(
            tracked_btn_row,
            text="🗑 Remove Selected  (untrack + delete its vectors)",
            command=self._remove_tracked_directory
        )
        self.remove_tracked_btn.pack(side='left')

        # Update buttons
        buttons_frame = ttk.Frame(update_frame)
        buttons_frame.pack(fill='x', padx=20, pady=(0, 6))

        ttk.Button(buttons_frame, text="Update Selected",
                   command=self.update_selected).pack(side='left', padx=(0, 6))

        ttk.Button(buttons_frame, text="Update All",
                   command=self.update_all,
                   style='Accent.TButton').pack(side='left')

        # Progress
        self.update_progress = ttk.Progressbar(update_frame, mode='indeterminate')
        self.update_progress.pack(fill='x', padx=20, pady=(0, 6))

        # Output
        ttk.Label(update_frame, text="Output:").pack(anchor='w', padx=20)
        self.update_output = scrolledtext.ScrolledText(update_frame, height=10,
                                                       wrap=tk.WORD)
        self.update_output.pack(fill='both', expand=True, padx=20, pady=(0, 5))

        # Load tracked directories
        self.refresh_tracked_dirs()
    
    def create_scheduling_tab(self):
        """Create scheduling tab for automatic updates"""
        schedule_frame = ttk.Frame(self.notebook)
        self.notebook.add(schedule_frame, text="⏰ Schedule")
        
        # Title
        title_label = ttk.Label(schedule_frame, text="Schedule Automatic Updates",
                               font=('Arial', 14, 'bold'))
        title_label.pack(pady=10)
        
        # Description
        desc_text = ("Configure automatic updates to keep your knowledge base current.\n"
                    "Updates will re-index tracked directories at the specified time.")
        desc_label = ttk.Label(schedule_frame, text=desc_text, justify=tk.CENTER)
        desc_label.pack(pady=5)
        
        # Current schedule frame
        current_frame = ttk.LabelFrame(schedule_frame, text="Current Schedule", 
                                      padding=20)
        current_frame.pack(fill=tk.X, padx=50, pady=10)
        
        self.schedule_status = tk.StringVar(value="Checking...")
        status_label = ttk.Label(current_frame, textvariable=self.schedule_status)
        status_label.pack(pady=5)
        
        # Quick schedule buttons frame
        quick_frame = ttk.LabelFrame(schedule_frame, text="Quick Schedule Options",
                                     padding=20)
        quick_frame.pack(fill=tk.X, padx=50, pady=10)
        
        quick_desc = ttk.Label(quick_frame, 
                              text="Choose a preset schedule time:")
        quick_desc.pack(anchor=tk.W, pady=5)
        
        btn_frame = ttk.Frame(quick_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Daily at 8:00 AM",
                  command=lambda: self.set_schedule("08:00", "DAILY")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Daily at 9:00 AM",
                  command=lambda: self.set_schedule("09:00", "DAILY")).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Weekdays at 8:00 AM",
                  command=lambda: self.set_schedule("08:00", "WEEKDAYS")).pack(side=tk.LEFT, padx=5)
        
        # Custom schedule frame
        custom_frame = ttk.LabelFrame(schedule_frame, text="Custom Schedule",
                                     padding=20)
        custom_frame.pack(fill=tk.X, padx=50, pady=10)
        
        custom_desc = ttk.Label(custom_frame,
                               text="Set a custom time for automatic updates:")
        custom_desc.pack(anchor=tk.W, pady=5)
        
        time_frame = ttk.Frame(custom_frame)
        time_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(time_frame, text="Time (HH:MM):").pack(side=tk.LEFT, padx=5)
        self.custom_time = tk.StringVar(value="12:00")
        time_entry = ttk.Entry(time_frame, textvariable=self.custom_time, width=10)
        time_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(time_frame, text="Frequency:").pack(side=tk.LEFT, padx=(20,5))
        self.custom_freq = tk.StringVar(value="DAILY")
        freq_combo = ttk.Combobox(time_frame, textvariable=self.custom_freq,
                                 values=["DAILY", "WEEKDAYS"], width=12, state='readonly')
        freq_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(time_frame, text="Set Schedule",
                  command=self.set_custom_schedule).pack(side=tk.LEFT, padx=10)
        
        # Disable/Remove schedule frame
        control_frame = ttk.LabelFrame(schedule_frame, text="Schedule Control",
                                      padding=20)
        control_frame.pack(fill=tk.X, padx=50, pady=10)
        
        control_btn_frame = ttk.Frame(control_frame)
        control_btn_frame.pack(pady=10)
        
        ttk.Button(control_btn_frame, text="Disable Schedule",
                  command=self.disable_schedule).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_btn_frame, text="Remove Schedule",
                  command=self.remove_schedule).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_btn_frame, text="Refresh Status",
                  command=self.refresh_schedule_status).pack(side=tk.LEFT, padx=5)
        
        # Info text
        info_text = scrolledtext.ScrolledText(schedule_frame, height=8, width=70,
                                              wrap=tk.WORD)
        info_text.pack(fill=tk.BOTH, expand=True, padx=50, pady=10)
        
        info_content = """How Automatic Updates Work:

1. The scheduler runs at your specified time
2. It re-indexes all directories in the Update Index tab
3. Your knowledge base stays current with new/changed files
4. Runs in the background - you don't need to do anything

Requirements:
• At least one directory tracked (see Update Index tab)
• Windows Task Scheduler enabled
• AI Prowler files in a permanent location

The schedule uses Windows Task Scheduler, so it will run even when
this application is closed."""
        
        info_text.insert('1.0', info_content)
        info_text.config(state='disabled')
        
        # Load current schedule status
        self.refresh_schedule_status()
    
    def set_schedule(self, time_str, frequency):
        """Set a quick schedule"""
        try:
            # Create the schedule using schtasks
            script_path = Path.home() / "rag_auto_update.bat"
            
            # Determine schedule type
            if frequency == "WEEKDAYS":
                # Schedule for Monday-Friday
                cmd = f'schtasks /create /tn "AI Prowler Auto-Update" /tr "{script_path}" /sc weekly /d MON,TUE,WED,THU,FRI /st {time_str} /f'
            else:
                # Schedule daily
                cmd = f'schtasks /create /tn "AI Prowler Auto-Update" /tr "{script_path}" /sc daily /st {time_str} /f'
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                messagebox.showinfo("Success",
                                   f"Schedule set successfully!\n\n"
                                   f"Updates will run {frequency.lower()} at {time_str}")
                self.refresh_schedule_status()
            else:
                messagebox.showerror("Error",
                                    f"Failed to create schedule.\n\n"
                                    f"Error: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to set schedule: {str(e)}")
    
    def set_custom_schedule(self):
        """Set a custom schedule"""
        time_str = self.custom_time.get().strip()
        frequency = self.custom_freq.get()
        
        # Validate time format
        if not self.validate_time(time_str):
            messagebox.showerror("Invalid Time",
                                "Please enter time in HH:MM format\n"
                                "Examples: 08:00, 12:00, 18:30")
            return
        
        self.set_schedule(time_str, frequency)
    
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
        """Refresh the current schedule status"""
        try:
            # Query the scheduled task
            cmd = 'schtasks /query /tn "AI Prowler Auto-Update" /fo list'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse the output to get schedule details
                output = result.stdout
                
                # Extract status and time
                status = "Unknown"
                next_run = "Unknown"
                
                for line in output.split('\n'):
                    if 'Status:' in line:
                        status = line.split('Status:')[1].strip()
                    elif 'Next Run Time:' in line:
                        next_run = line.split('Next Run Time:')[1].strip()
                
                self.schedule_status.set(
                    f"✅ Schedule Active\n"
                    f"Status: {status}\n"
                    f"Next Run: {next_run}"
                )
            else:
                self.schedule_status.set(
                    "❌ No Schedule Set\n"
                    "Use the options above to create a schedule"
                )
        except Exception as e:
            self.schedule_status.set(f"⚠️ Error checking status: {str(e)}")
    
    # ─────────────────────────────────────────────────────────────────────────
    def create_scan_config_tab(self):
        """Smart Scan Configuration — edit supported/skipped extensions and dirs."""
        scan_cfg_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_cfg_frame, text="🗂 Smart Scan")

        ttk.Label(scan_cfg_frame, text="Smart Scan Configuration",
                  font=('Arial', 16, 'bold')).pack(pady=(10, 2))
        ttk.Label(scan_cfg_frame,
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
        cols_frame = ttk.Frame(scan_cfg_frame)
        cols_frame.pack(fill='both', expand=True, padx=20, pady=(0, 6))
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

        # ── Bottom panel — Skip Directories ──────────────────────────────────
        dir_frame = ttk.LabelFrame(scan_cfg_frame,
                                   text="📂 Skipped Directories  (entire folder ignored)",
                                   padding=8)
        dir_frame.pack(fill='x', padx=20, pady=(0, 6))

        # Horizontal listbox (2 rows tall, scrollable)
        dir_list_row = ttk.Frame(dir_frame)
        dir_list_row.pack(fill='x')

        self.dir_listbox = tk.Listbox(dir_list_row, height=4,
                                      font=('Courier', 9),
                                      selectmode=tk.SINGLE,
                                      activestyle='dotbox')
        dir_scroll = ttk.Scrollbar(dir_list_row, orient='vertical',
                                   command=self.dir_listbox.yview)
        self.dir_listbox.configure(yscrollcommand=dir_scroll.set)
        self.dir_listbox.pack(side='left', fill='x', expand=True)
        dir_scroll.pack(side='left', fill='y')

        for d in sorted(dirs):
            self.dir_listbox.insert(tk.END, d)

        dir_add_row = ttk.Frame(dir_frame)
        dir_add_row.pack(fill='x', pady=(6, 0))
        self.dir_add_var = tk.StringVar()
        dir_entry = ttk.Entry(dir_add_row, textvariable=self.dir_add_var, width=24)
        dir_entry.pack(side='left', padx=(0, 4))
        dir_entry.bind('<Return>', lambda e: self._dir_add())
        ttk.Button(dir_add_row, text="➕ Add",
                   command=self._dir_add).pack(side='left', padx=(0, 4))
        ttk.Button(dir_add_row, text="❌ Remove Selected",
                   command=self._dir_remove).pack(side='left', padx=(0, 16))
        ttk.Label(dir_add_row,
                  text="e.g. .cache  temp  backup",
                  font=('Arial', 8), foreground='gray').pack(side='left')

        # ── Bottom action bar ─────────────────────────────────────────────────
        action_row = ttk.Frame(scan_cfg_frame)
        action_row.pack(fill='x', padx=20, pady=(4, 10))

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
        
        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Title
        title = ttk.Label(scrollable_frame, text="Configuration", 
                         font=('Arial', 16, 'bold'))
        title.pack(pady=10)
        
        # Model selection
        model_frame = ttk.LabelFrame(scrollable_frame, text="AI Model", padding=10)
        model_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(model_frame, text="Select model:").pack(anchor='w', pady=5)
        
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

        # Build model list sorted by recommended first, then by size
        def _model_sort_key(m):
            info = MODEL_INFO.get(m, {})
            needed = info.get("min_ram_gb", 999)
            fits = needed <= self._system_ram_gb if self._system_ram_gb > 0 else True
            return (0 if fits else 1, info.get("size_gb", 0))

        models = [m for m in MODEL_CONTEXT_WINDOWS.keys() if m != 'default']
        models.sort(key=_model_sort_key)
        self._model_names = models  # plain names for actual use

        # Display names shown in combobox include size + RAM badge
        def _display_name(m):
            info = MODEL_INFO.get(m, {})
            size = info.get("size_gb", 0)
            needed = info.get("min_ram_gb", 0)
            if self._system_ram_gb > 0:
                badge = "✅" if needed <= self._system_ram_gb else "⚠️"
            else:
                badge = ""
            return f"{badge} {m}  [{size:.1f} GB dl | {needed} GB RAM]"

        display_names = [_display_name(m) for m in models]
        self._model_display_map = dict(zip(display_names, models))
        self._model_reverse_map = dict(zip(models, display_names))

        # Use a StringVar that holds the display name for the combobox
        self._model_display_var = tk.StringVar()
        current = self.current_model.get()
        self._model_display_var.set(self._model_reverse_map.get(current, display_names[0] if display_names else ""))

        model_combo = ttk.Combobox(model_frame, textvariable=self._model_display_var,
                                   values=display_names, width=45, state='readonly')
        model_combo.pack(fill='x', pady=5)
        model_combo.bind('<<ComboboxSelected>>', self.on_model_change)

        if self._system_ram_gb > 0:
            ram_lbl = ttk.Label(model_frame,
                text=f"Your PC has {self._system_ram_gb:.1f} GB RAM  |  ✅ = fits in RAM   ⚠️ = may be slow",
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
        
        # ── Ollama Server ─────────────────────────────────────────────────────
        ollama_frame = ttk.LabelFrame(scrollable_frame, text="Ollama Server", padding=(10, 6))
        ollama_frame.pack(fill='x', padx=20, pady=(5, 10))
        
        auto_start_cb = ttk.Checkbutton(
            ollama_frame,
            text="Auto-start Ollama server (opens separate CMD window)",
            variable=self.auto_start_ollama_var,
            command=self._save_auto_start_setting
        )
        auto_start_cb.pack(anchor='w', pady=(2, 4))
        
        ttk.Label(ollama_frame,
                  text="• If enabled: AI Prowler starts Ollama automatically and closes it on exit\n"
                       "• If disabled: You must start 'ollama serve' manually before using AI Prowler",
                  foreground='gray', font=('Arial', 9), justify='left').pack(anchor='w')
        
        # About
        about_frame = ttk.LabelFrame(scrollable_frame, text="About", padding=10)
        about_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        about_text = """AI Prowler - Personal AI Knowledge Base
Version 1.8

Features:
• Multi-model support (15+ AI models)
• Smart chunking optimization
• Automatic file tracking
• Email support (.eml, .msg, .mbox)
• Intelligent auto-updates

Built with Python, ChromaDB, and Ollama"""
        
        about_label = ttk.Label(about_frame, text=about_text, justify='left')
        about_label.pack(pady=10)
    
    def create_status_bar(self):
        """Create status bar"""
        status_frame = ttk.Frame(self.root, relief='sunken')
        status_frame.pack(side='bottom', fill='x')
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                anchor='w')
        status_label.pack(side='left', fill='x', expand=True, padx=5)
    
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

        if needed_ctx != default_ctx:
            self.status_var.set(
                f"⚠️  {n_chunks} chunks needs num_ctx={needed_ctx} — "
                f"reloading model (CPU: ~2-5 min) — wait for green light"
            )
        else:
            self.status_var.set(
                f"✅ {n_chunks} chunks fits in num_ctx={default_ctx} — loading model…"
            )

        # Reset warmup — new chunk count means the model will reload
        self._warmup_reset()
        # Force a re-prewarm at the required context size
        self._prewarm_done = False
        self._prewarm_in_progress = False
        self._trigger_prewarm(num_ctx=needed_ctx)

    def _on_tab_changed(self, event=None):
        """Prewarm Ollama whenever the user switches to the Ask Questions tab."""
        try:
            selected = self.notebook.index(self.notebook.select())
            if selected == self._TAB_INDEX_QUERY:
                self._trigger_prewarm()
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
                print("  → Creating new CMD window...")
                self._ollama_process = subprocess.Popen(
                    ['ollama', 'serve'],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
                print(f"  → CMD window created!")
            else:
                # For Linux/Mac, start in background
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

    def browse_folder_single(self):
        """Open native Windows folder browser and add selected folder to queue."""
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
                print(f"{'='*60}\n")

            stopped = False

            for dir_idx, directory in enumerate(directories, 1):
                is_file = os.path.isfile(directory)
                label   = Path(directory).name
                icon    = "📄" if is_file else "📁"

                self.output_queue.put((
                    'index_progress',
                    f"{'File' if is_file else 'Dir'} {dir_idx}/{n_dirs}: {label}"
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
                        start_from=start_from
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
                    print(f"   Files skipped:  {grand_skipped:,}")
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
        question = self.question_var.get().strip()

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

        # Reset cancel so future idle prewarming works again after query finishes
        self._prewarm_cancel = False
        # Reset stop flag and mark query as running — enables Stop button
        if RAG_AVAILABLE:
            _rag_engine.QUERY_STOP = False
        self._query_running = True
        self._stop_query_btn.configure(state='normal')
        thread = threading.Thread(target=self.query_worker,
                                  args=(question, n_contexts), daemon=True)
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
    
    def query_worker(self, question, n_contexts):
        """Worker thread for querying"""
        old_stdout = sys.stdout
        try:
            # Redirect output
            sys.stdout = TextRedirector(self.output_queue, 'query')
            
            # Query
            rag_query(question, n_contexts=n_contexts, verbose=True)
            
            self.output_queue.put(('status', 'Query complete!'))
            self.output_queue.put(('done', 'query'))
            
        except Exception as e:
            self.output_queue.put(('error', f"Error: {str(e)}"))
            self.output_queue.put(('done', 'query'))
        finally:
            sys.stdout = old_stdout
    
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
        self.status_var.set("Updating...")
        
        thread = threading.Thread(target=self.update_directory_worker,
                                  args=(directory,))
        thread.daemon = True
        thread.start()
    
    def update_all(self):
        """Update all tracked directories"""
        self.update_output.delete('1.0', tk.END)
        self.update_progress.start()
        self.status_var.set("Updating all...")
        
        thread = threading.Thread(target=self.update_all_worker)
        thread.daemon = True
        thread.start()
    
    def update_directory_worker(self, directory):
        """Worker thread: update a single directory using Python functions directly"""
        old_stdout = sys.stdout
        try:
            sys.stdout = TextRedirector(self.output_queue, 'update')
            command_update(directory, recursive=True, auto_confirm=True)
            self.output_queue.put(('status', 'Update complete!'))
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
            self.output_queue.put(('status', 'Update complete!'))
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
        desc     = info_data.get("description", "")
        sys_ram  = getattr(self, '_system_ram_gb', 0)

        parts = [f"Context: {context:,} tokens | Optimal chunks: {chunks}"]
        if size_gb:
            parts.append(f"Download: {size_gb:.1f} GB")
        if ram_gb:
            fit = "" if sys_ram == 0 else ("  ✅ fits your RAM" if ram_gb <= sys_ram else "  ⚠️ exceeds your RAM")
            parts.append(f"Min RAM: {ram_gb} GB{fit}")
        if desc:
            parts.append(desc)
        self.model_info_label.config(text="  |  ".join(parts[:3]) + (f"\n{parts[3]}" if len(parts) > 3 else ""))
    
    def show_model_picker(self):
        """Show a custom model browser dialog that closes when clicking outside."""
        picker = tk.Toplevel(self.root)
        picker.title("Browse & Install Model")
        picker.resizable(True, True)
        picker.minsize(620, 380)
        picker.transient(self.root)

        # Position near center of main window
        self.root.update_idletasks()
        rx, ry = self.root.winfo_rootx(), self.root.winfo_rooty()
        rw, rh = self.root.winfo_width(), self.root.winfo_height()
        pw, ph = 680, 520
        picker.geometry(f"{pw}x{ph}+{rx + rw//2 - pw//2}+{ry + rh//2 - ph//2}")

        # Configure grid so the listbox row expands
        picker.columnconfigure(0, weight=1)
        picker.rowconfigure(1, weight=1)  # row 1 = list_frame

        sys_ram = getattr(self, '_system_ram_gb', 0)

        # ── Header ────────────────────────────────────────────────────────────
        hdr = ttk.Frame(picker, padding=(12, 8))
        hdr.grid(row=0, column=0, sticky='ew')
        ttk.Label(hdr, text="Install an AI Model", font=('Arial', 13, 'bold')).pack(side='left')
        if sys_ram > 0:
            ttk.Label(hdr, text=f"  Your RAM: {sys_ram:.0f} GB   ✅ fits   ⚠️ may be slow",
                      font=('Arial', 9), foreground='gray').pack(side='left', padx=8)

        ttk.Separator(picker, orient='horizontal').grid(row=1, column=0, sticky='ew')

        # ── Listbox ───────────────────────────────────────────────────────────
        list_frame = ttk.Frame(picker, padding=(8, 6))
        list_frame.grid(row=2, column=0, sticky='nsew')
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        picker.rowconfigure(2, weight=1)  # list_frame row expands

        scrollbar = ttk.Scrollbar(list_frame, orient='vertical')
        listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set,
                             font=('Courier New', 10), selectmode='single',
                             activestyle='dotbox')
        scrollbar.config(command=listbox.yview)
        listbox.grid(row=0, column=0, sticky='nsew')
        scrollbar.grid(row=0, column=1, sticky='ns')

        # Populate listbox
        picker_models = [m for m in MODEL_CONTEXT_WINDOWS.keys() if m != 'default']
        def _sort_key(m):
            info = MODEL_INFO.get(m, {})
            needed = info.get("min_ram_gb", 999)
            fits = needed <= sys_ram if sys_ram > 0 else True
            return (0 if fits else 1, info.get("size_gb", 0))
        picker_models.sort(key=_sort_key)

        for m in picker_models:
            info = MODEL_INFO.get(m, {})
            size  = info.get("size_gb", 0)
            ram   = info.get("min_ram_gb", 0)
            desc  = info.get("description", "")
            if sys_ram > 0:
                badge = "✅" if ram <= sys_ram else "⚠️"
            else:
                badge = "  "
            line = f"{badge} {m:<20} {size:>5.1f} GB dl  {ram:>3} GB RAM   {desc}"
            listbox.insert('end', line)
            # Gray out models that exceed RAM
            if sys_ram > 0 and ram > sys_ram:
                listbox.itemconfig('end', foreground='#888888')

        # Pre-select currently active model
        current = self.current_model.get()
        if current in picker_models:
            idx = picker_models.index(current)
            listbox.selection_set(idx)
            listbox.see(idx)

        # ── Description label ─────────────────────────────────────────────────
        ttk.Separator(picker, orient='horizontal').grid(row=3, column=0, sticky='ew')
        desc_var = tk.StringVar(value="Select a model above to see details.")
        desc_lbl = ttk.Label(picker, textvariable=desc_var, font=('Arial', 9),
                             padding=(10, 4), wraplength=pw - 20, anchor='w')
        desc_lbl.grid(row=4, column=0, sticky='ew')

        def on_select(event=None):
            sel = listbox.curselection()
            if sel:
                m = picker_models[sel[0]]
                info = MODEL_INFO.get(m, {})
                size = info.get("size_gb", 0)
                ram  = info.get("min_ram_gb", 0)
                desc = info.get("description", "")
                ctx  = MODEL_CONTEXT_WINDOWS.get(m, 0)
                warn = ""
                if sys_ram > 0 and ram > sys_ram:
                    warn = f"  ⚠️ Needs {ram} GB RAM — you have {sys_ram:.0f} GB."
                desc_var.set(f"{m}  ▸  {size:.1f} GB download  |  {ram} GB RAM  |  {ctx:,} token context  |  {desc}{warn}")
        listbox.bind('<<ListboxSelect>>', on_select)

        # ── Buttons ───────────────────────────────────────────────────────────
        ttk.Separator(picker, orient='horizontal').grid(row=5, column=0, sticky='ew')
        btn_frame = ttk.Frame(picker, padding=(8, 6))
        btn_frame.grid(row=6, column=0, sticky='ew')

        def do_install():
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("No Selection", "Please select a model first.", parent=picker)
                return
            m = picker_models[sel[0]]
            info = MODEL_INFO.get(m, {})
            ram  = info.get("min_ram_gb", 0)
            size = info.get("size_gb", 0)
            warn = ""
            if sys_ram > 0 and ram > sys_ram:
                warn = f"\n\n⚠️ Warning: {m} needs {ram} GB RAM but your PC has {sys_ram:.0f} GB.\nIt will be very slow on CPU."
            if messagebox.askyesno("Install Model",
                    f"Install {m}?\n\nDownload size: ~{size:.1f} GB\nMin RAM: {ram} GB{warn}\n\nThis may take several minutes.",
                    parent=picker):
                picker.destroy()
                self.status_var.set(f"Installing {m}...")
                thread = threading.Thread(target=self.install_model_worker, args=(m,))
                thread.daemon = True
                thread.start()

        install_btn = ttk.Button(btn_frame, text="⬇  Install Selected Model", command=do_install)
        install_btn.pack(side='left', padx=4)

        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=picker.destroy)
        cancel_btn.pack(side='left', padx=4)

        # Update desc wraplength when picker is resized
        def _on_picker_resize(event):
            desc_lbl.config(wraplength=event.width - 20)
        picker.bind('<Configure>', _on_picker_resize)

        # ── Close on click outside ────────────────────────────────────────────
        def _on_focus_out(event):
            # Only close if focus moved to a widget outside the picker window
            try:
                focused = picker.focus_get()
            except Exception:
                focused = None
            if focused is None:
                picker.destroy()

        picker.bind('<FocusOut>', _on_focus_out)

        # Also close on Escape
        picker.bind('<Escape>', lambda e: picker.destroy())

        picker.focus_force()
        picker.grab_set()

    def install_model(self):
        """Install selected model (legacy — called directly for backward compat)"""
        self.show_model_picker()
    
    def install_model_worker(self, model):
        """Worker thread for model installation — streams progress output to status bar"""
        try:
            process = subprocess.Popen(
                f"ollama pull {model}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            for line in process.stdout:
                line = line.strip()
                if line:
                    self.output_queue.put(('status', f"Installing {model}: {line}"))
            process.wait()
            if process.returncode == 0:
                self.output_queue.put(('status', f'{model} installed successfully!'))
                self.output_queue.put(('info', f'✅ {model} is now ready to use.\n\nSwitch to it in the Settings tab.'))
            else:
                self.output_queue.put(('error', f'Failed to install {model}.\nCheck that Ollama is running: ollama serve'))
        except Exception as e:
            self.output_queue.put(('error', f'Failed to install {model}: {e}'))
    
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
        """Clear database"""
        if messagebox.askyesno("Clear Database",
                              "Are you sure you want to clear the entire database?\n\n"
                              "This will delete all indexed documents and cannot be undone."):
            try:
                clear_database(confirm=True)
                messagebox.showinfo("Success", "Database cleared")
                self.refresh_tracked_dirs()
            except Exception as e:
                messagebox.showerror("Error", f"Could not clear database: {e}")
    
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
                        # Append to any existing text in the box (allows multi-sentence)
                        existing = self.question_var.get().strip()
                        self.question_var.set((existing + ' ' + text).strip())
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
                                     args=(question, n_contexts), daemon=True).start()
                    
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
                    elif msg_data == 'update':
                        self.update_progress.stop()
                        self.refresh_tracked_dirs()
                    elif msg_data == 'remove_tracked':
                        self.update_progress.stop()
                        self.remove_tracked_btn.configure(state='normal')
                        self.refresh_tracked_dirs()
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_output_queue)
    
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
        
        # Close the window
        self.root.destroy()

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
