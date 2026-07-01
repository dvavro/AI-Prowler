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

# ── Bulletproof stdout/stderr UTF-8 fix ──────────────────────────────────────
# Tkinter apps on Windows can have stdout/stderr in any of three broken states:
#   1. None        — when launched via pythonw.exe (no console)
#   2. cp1252      — default Windows codepage; crashes on emoji / em-dashes
#   3. proxy       — some launchers wrap the stream and break reconfigure()
#
# A simple sys.stdout.reconfigure() only handles case 2. The earlier version
# of this fix silently failed on cases 1 and 3 because of the try/except: pass
# wrapper, which is what allowed cp1252 errors to surface in the GUI delete
# path. This implementation falls through several strategies and never crashes.
def _make_safe_text_stream(name):
    import io as _io
    cur = getattr(sys, name, None)
    if cur is None:
        return _io.TextIOWrapper(_io.BytesIO(), encoding="utf-8",
                                 errors="replace", write_through=True)
    enc = (getattr(cur, "encoding", "") or "").lower().replace("-", "")
    if enc in ("utf8", "utf8sig"):
        return cur
    if hasattr(cur, "reconfigure"):
        try:
            cur.reconfigure(encoding="utf-8", errors="replace")
            return cur
        except Exception:
            pass
    buf = getattr(cur, "buffer", None)
    if buf is not None:
        try:
            return _io.TextIOWrapper(buf, encoding="utf-8",
                                     errors="replace", write_through=True)
        except Exception:
            pass
    return _io.TextIOWrapper(_io.BytesIO(), encoding="utf-8",
                             errors="replace", write_through=True)

try:
    sys.stdout = _make_safe_text_stream("stdout")
    sys.stderr = _make_safe_text_stream("stderr")
except Exception:
    pass

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
APP_VERSION = "8.0.0"

# ── UI feature flags ─────────────────────────────────────────────────────────
# Toggle visibility of advanced/legacy GUI sections without removing any
# underlying functionality. The Python functions, MCP integration, telemetry,
# OCR, speech, and Ollama-LLM code paths are all still present and callable —
# these flags just hide their UI surfaces for the average user.
#
# Flip to True (and restart the GUI) to expose:
#
#   SUPPORT_LOCAL_HW_LLM — local-hardware LLM features:
#     • Quick Links tab: Your-Question input box, attachments, Ask Question
#       button, microphone button. (Smart Guided Questions panel always shown.)
#     • Settings tab:      AI Model section, External AI APIs section,
#                          Microphone / Speech Input section, Ollama Server
#                          section.
#
#   DEBUG_EN — power-user / field-debug surfaces:
#     • Settings tab:      Query Output section, OCR scanned-PDF debug display,
#                          MCP Claude Desktop Integration section + auto-config
#                          buttons, claude.ai Web/Mobile config snippet,
#                          Privacy & Analytics section.
#
# Defaults (False) target the typical AI-Prowler user whose workflow is
# Claude Desktop / claude.ai → MCP → AI-Prowler RAG. No knobs, no clutter.
SUPPORT_LOCAL_HW_LLM = False
DEBUG_EN             = False

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
        command_update, show_stats, clear_database, clear_database_only,
        prewarm_ollama, prewarm_embeddings, invalidate_chroma_cache, check_ollama_available,
        generate_auto_update_script,
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

# ── Self-Learning engine import ──────────────────────────────────────────────
SELF_LEARNING_AVAILABLE = False
try:
    import self_learning as _sl_engine
    SELF_LEARNING_AVAILABLE = True
except ImportError:
    print("Note: self_learning.py not found — Learnings tab will be view-only")
except Exception as _sl_e:
    print(f"Warning: self_learning import error: {_sl_e}")

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

        # ── Hide window during construction to prevent the small-then-resize flicker ──
        # Tk creates the window at a default small size before geometry() is called.
        # Withdrawing it immediately keeps it invisible until we have calculated the
        # correct size, built all widgets, and are ready to show it fully formed.
        # deiconify() is called after create_widgets() completes below.
        #
        # _we_withdrew tracks whether THIS __init__ call is the one that hid the
        # window. If an external caller (e.g. the test suite's _tk_root fixture)
        # already withdrew the root before constructing RAGGui, we must NOT call
        # deiconify() — that would pop the window visible during automated tests.
        _was_already_withdrawn = (self.root.state() == 'withdrawn')
        self.root.withdraw()
        _we_withdrew = not _was_already_withdrawn

        # ── Match Tk scaling to Windows DPI ──────────────────────────────────
        # Now that we declared DPI awareness in main(), Windows stops bitmap-
        # upscaling our window. Without telling Tk about the scale factor,
        # all fonts and ttk widgets would render at their literal point size
        # on a 150% display — i.e. uncomfortably small. Tk's scaling property
        # is in pixels-per-point; default is 1.333 (= 96 DPI / 72). We bump
        # it proportionally to whatever scale the user has configured.
        try:
            if sys.platform == 'win32':
                _dpi = ctypes.windll.user32.GetDpiForSystem()
                _scale = _dpi / 96.0
                self.root.tk.call('tk', 'scaling', 1.333 * _scale)
        except Exception:
            pass   # Stick with Tk default scaling if anything goes wrong

        # ── Adaptive window sizing ────────────────────────────────────────────
        # Hardcoding 1200x980 caused the window to hang off the bottom of the
        # screen on common 1366x768 / 1920x1080 Win 11 laptops, hiding the
        # status bar with the MCP Ready indicator. Now we measure the screen
        # and cap the window to fit, leaving room for the Windows taskbar.
        # We also scale the desired dimensions by the OS DPI so the window
        # stays the same physical-on-screen size regardless of display scaling.
        try:
            _screen_w = self.root.winfo_screenwidth()
            _screen_h = self.root.winfo_screenheight()
            # Determine DPI scale (1.0 at 100%, 1.5 at 150%, etc.)
            try:
                if sys.platform == 'win32':
                    _dpi_scale = ctypes.windll.user32.GetDpiForSystem() / 96.0
                else:
                    _dpi_scale = 1.0
            except Exception:
                _dpi_scale = 1.0
            _desired_w = int(1200 * _dpi_scale)
            _desired_h = int(980 * _dpi_scale)
            # Leave ~80px (scaled) for the Windows taskbar and window decorations
            _avail_h   = max(int(600 * _dpi_scale), _screen_h - int(80 * _dpi_scale))
            _avail_w   = max(int(800 * _dpi_scale), _screen_w - int(40 * _dpi_scale))
            _win_w     = min(_desired_w, _avail_w)
            _win_h     = min(_desired_h, _avail_h)
            # Center the window on screen
            _pos_x     = max(0, (_screen_w - _win_w) // 2)
            _pos_y     = max(0, (_screen_h - _win_h) // 2 - 20)
            self.root.geometry(f"{_win_w}x{_win_h}+{_pos_x}+{_pos_y}")
        except Exception:
            # Fall back to a safe size that fits on a 1366x768 laptop
            self.root.geometry("1200x680")

        # Enforce a minimum size so the user can't shrink the window so far
        # that critical controls become unreachable. 800x600 is the smallest
        # the Notebook can render all tabs without horizontal clipping.
        # Scale the minimum too so it remains usable at high DPI.
        try:
            _min_scale = (ctypes.windll.user32.GetDpiForSystem() / 96.0
                          if sys.platform == 'win32' else 1.0)
        except Exception:
            _min_scale = 1.0
        self.root.minsize(int(800 * _min_scale), int(600 * _min_scale))
        
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
        self._index_cancelled   = False               # True = stop was a cancel, not a save
        self._embedding_ready    = False               # True once embedding model is loaded
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

        # ── Reveal the window now that it is fully built and correctly sized ──
        # Only deiconify if WE are the caller who withdrew it. If the window was
        # already withdrawn before __init__ ran (e.g. test suite's _tk_root
        # fixture calls root.withdraw() to keep tests headless), leave it hidden.
        self.root.update_idletasks()
        if _we_withdrew:
            self.root.deiconify()
        
        # Start output processor
        self.process_output_queue()
        
        # Bind tab-change event — prewarm Ollama when user switches to Quick Links
        self.notebook.bind('<<NotebookTabChanged>>', self._on_tab_changed)
        
        # ── Startup Ollama actions — gated on the local-LLM feature flag ──────
        # Since v6.0 the local Q&A box is hidden by default (SUPPORT_LOCAL_HW_LLM
        # = False) and Claude Desktop / Claude.ai are the supported interfaces.
        # Loading the Ollama model at startup is wasted work in that case, and
        # the "⚡ Loading AI model into memory..." status message in the footer
        # confuses users who don't know what Ollama is. We suppress both the
        # auto-start and the prewarm at launch. The underlying logic is fully
        # intact and re-activates automatically if SUPPORT_LOCAL_HW_LLM=True.
        if SUPPORT_LOCAL_HW_LLM:
            # Check and auto-start Ollama if enabled (before prewarm)
            self.root.after(500, self._check_and_start_ollama)

            # Startup prewarm — load model into memory after a 3-second delay so
            # the window finishes drawing first. Silent background thread.
            self.root.after(3000, self._trigger_prewarm)
        else:
            # Local-LLM mode is OFF — Claude MCP is the only AI interface.
            # Ensure the Ollama Windows Service cannot auto-start on reboot:
            # a previous session with SUPPORT_LOCAL_HW_LLM=True may have set
            # the service to 'auto'. Silently correct that in the background.
            self.root.after(2000, self._ensure_ollama_disabled)

        # ── Embedding model prewarm — UNCONDITIONAL ──────────────────────────
        # The sentence-transformers embedding model (all-MiniLM-L6-v2) must be
        # downloaded and cached before ANY indexing or update operation can run.
        # On a fresh install the model is not in the HuggingFace cache yet, so
        # the first call to get_chroma_client() hangs the GUI thread if it
        # happens in response to a user action (e.g. Update All).
        #
        # This after() fires 4 s after startup — enough for the window to draw
        # and the MCP server to start — then downloads the model in a background
        # thread. Update All / Update Selected are disabled until it completes.
        # On subsequent launches the model is already cached and this returns in
        # milliseconds, so the cost is negligible.
        if RAG_AVAILABLE:
            self.root.after(4000, self._prewarm_embedding_model)

        # MCP status bar indicator — check once on startup
        self.root.after(2000, self._refresh_mcp_status_bar)

        # Auto-start HTTP MCP server after UI has settled —
        # silently starts the server if a Bearer token is configured.
        # This is optional — only needed for mobile/web access via Claude.ai.
        # Delay of 6s allows the Settings tab to finish building and
        # the subscription status check to complete first.
        self.root.after(6000, self._auto_start_http_server)

        # ----- Code Tools write-side: approval-queue poll -----
        # The Code Tools write-side tools (create_file, write_file,
        # str_replace_in_file, etc.) queue write-approval requests to
        # ~/.rag_writable_pending.json when Claude tries to write to a
        # directory that's not yet in the writable allowlist. This
        # background poll picks them up and shows a modal dialog so the
        # user can grant or deny access. Poll runs every 5 seconds.
        self.root.after(5000, self._schedule_write_approval_poll)

    # ====== Code Tools write-side: approval-queue dialog ======
    # These two methods support the write-side filesystem tools added in
    # ai_prowler_mcp.py (create_file, write_file, str_replace_in_file, etc).
    # The tools queue approval requests; this dialog grants the access.

    def _check_write_approval_queue(self):
        """Poll the write-approval queue and show a dialog for any pending
        requests. See ai_prowler_mcp.py _resolve_writable_path for the
        producer side. Approved paths are persisted to
        ~/.rag_writable_dirs.json so future writes succeed without prompting.
        """
        from pathlib import Path as _Path
        pending_path = _Path.home() / ".rag_writable_pending.json"
        writable_path = _Path.home() / ".rag_writable_dirs.json"
        try:
            if not pending_path.exists():
                return
            with open(pending_path, "r", encoding="utf-8") as f:
                pending = json.load(f)
            if not isinstance(pending, list) or not pending:
                return
        except Exception:
            return

        # Load current writable allowlist
        try:
            with open(writable_path, "r", encoding="utf-8") as f:
                writable = json.load(f)
            if not isinstance(writable, list):
                writable = []
        except Exception:
            writable = []

        for req in pending:
            try:
                path = req.get("path", "") if isinstance(req, dict) else ""
                if not path:
                    continue
                # Grant target is the parent directory (covers this file
                # AND siblings, which is what the user usually wants).
                parent = str(_Path(path).parent)
                msg = (
                    f"AI-Prowler is requesting permission to WRITE to:\n\n"
                    f"  {path}\n\n"
                    f"Grant write access to the parent directory?\n"
                    f"  {parent}\n\n"
                    f"This is a one-time approval. Future writes anywhere\n"
                    f"under this directory will succeed without prompting.\n\n"
                    f"Click YES to approve, NO to deny."
                )
                approved = messagebox.askyesno(
                    "AI-Prowler \u2014 Approve Write Access?",
                    msg,
                    parent=self.root,
                )
                if approved and parent not in writable:
                    writable.append(parent)
            except Exception:
                continue

        # Save updated writable allowlist
        try:
            writable_path.parent.mkdir(parents=True, exist_ok=True)
            with open(writable_path, "w", encoding="utf-8") as f:
                json.dump(sorted(set(writable)), f, indent=2)
        except Exception as exc:
            try:
                messagebox.showerror(
                    "AI-Prowler",
                    f"Could not save writable allowlist: {exc}",
                    parent=self.root,
                )
            except Exception:
                pass

        # Clear the pending queue (user has now responded to each request)
        try:
            with open(pending_path, "w", encoding="utf-8") as f:
                json.dump([], f)
        except Exception:
            pass

    def _schedule_write_approval_poll(self):
        """Run the approval-queue check and reschedule for 5s from now."""
        try:
            self._check_write_approval_queue()
        except Exception:
            pass
        try:
            self.root.after(5000, self._schedule_write_approval_poll)
        except Exception:
            pass

    def _auto_start_http_server(self):
        """
        Silently start the HTTP MCP server on launch if a Bearer token
        is configured.  Called via root.after() from __init__ with a 5-second
        delay so the Settings tab is fully built first.

        Unlike the manual Start button, this does NOT show messageboxes
        on failure (no token, subscription issues, etc.) — it just logs
        to the status bar and lets the user start manually if needed.
        """
        # Guard: _start_http_server_fn is set during Settings tab creation.
        # If the Settings tab hasn't built yet (shouldn't happen with 5s delay),
        # silently skip.
        fn = getattr(self, '_start_http_server_fn', None)
        if fn is None:
            return

        # Only auto-start if a Bearer token is saved in config.
        # Exception: Business server mode uses per-user tokens from users.json,
        # so there is no single remote_token — skip the token check in that mode.
        try:
            from pathlib import Path as _P
            import json as _j
            cfg_path = _P.home() / '.ai-prowler' / 'config.json'
            if cfg_path.exists():
                cfg = _j.loads(cfg_path.read_text(encoding='utf-8-sig'))
                _is_srv = (str(cfg.get('edition', '')).lower() == 'business'
                           and str(cfg.get('mode', '')).lower() == 'server')
                token = cfg.get('remote_token', '').strip()
                if not token and not _is_srv:
                    self.status_var.set(
                        "HTTP auto-start skipped — no Bearer token configured")
                    # Clear hint so footer doesn't hang on it
                    self.root.after(5000, lambda: self.status_var.set("Ready"))
                    return
            else:
                return
        except Exception:
            return

        # Don't auto-start if already running
        if (self._http_server_proc is not None
                and self._http_server_proc.poll() is None):
            return

        # Call the same function the Start button uses
        try:
            self.status_var.set("Auto-starting HTTP MCP server...")
            fn()
            # Clear the footer message after a few seconds. The actual server
            # status is reflected by the ⬤ indicator on the Settings → Remote
            # Access page; the footer is just a transient hint. Without this
            # clear-out the footer would hang on "Auto-starting HTTP MCP
            # server..." indefinitely because _start_http_server() updates a
            # different StringVar (_http_status_var) rather than self.status_var.
            self.root.after(4000, lambda: self.status_var.set("Ready"))
        except Exception as exc:
            self.status_var.set(f"HTTP auto-start failed: {exc}")
        
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

Your AI-powered knowledge assistant. Index your documents once,
then ask Claude questions from your desktop or phone.

─────────────────────────────────────────────────
 KNOWLEDGE BASE (RAG)
─────────────────────────────────────────────────
• 85 MCP tools across 12 categories
• 65+ file types: PDF, Word, Excel, PowerPoint, HTML,
• Automatic OCR for scanned PDFs and images
• Incremental indexing — only changed files reprocessed
• Auto-purge deleted files from ChromaDB on every update

─────────────────────────────────────────────────
 REMOTE ACCESS
─────────────────────────────────────────────────
• One-click subscription — Personal ($10/mo) or Business ($20/mo)
• One-click Configure Mobile Access — tunnel auto-provisioned
• Auto Connect Claude.ai button — opens connector form with URL copied
• Bearer-token authentication
• Auto-start after reboot via Windows service
• Server uptime displayed in Settings → Remote Access

─────────────────────────────────────────────────
 CODE TOOLS
─────────────────────────────────────────────────
• Create, edit, and manage files in tracked directories
• str_replace, fuzzy_replace, line_replace, backup/restore
• Lint, syntax check, compile check, and script runner

─────────────────────────────────────────────────
 SELF-LEARNING (🧠 tab)
─────────────────────────────────────────────────
• Claude remembers facts across sessions
• Record, retrieve, update, delete, and export learnings
• Conflict detection and supersession chains

─────────────────────────────────────────────────
 SMALL BUSINESS (🏢 tab)
─────────────────────────────────────────────────
• Route optimization, weather, geocoding (free, no API key)
• Job tracker spreadsheet — read and update from Claude
• Invoicing, recurring jobs, time tracking, AR aging
• QuickBooks-aware analysis — detects QB MCP automatically
• Square payment integration via Claude MCP connector

─────────────────────────────────────────────────
 COMMON BUSINESS AI ANALYSIS
─────────────────────────────────────────────────
• 5 one-click analysis buttons (Quick Links tab)
• Schedule recurring analyses — weekly, monthly, quarterly
• QuickBooks-aware: uses QB if connected, Job Tracker if not
• Queue multiple analyses, run all with one Ctrl+V paste

─────────────────────────────────────────────────
 PROACTIVE ALERTS SCHEDULER
─────────────────────────────────────────────────
• Background email alerts — no Claude session needed
• Zero API cost — calls AI-Prowler tools directly
• 6 configurable jobs: briefing, invoices, weather & more
• Personal mode only — hidden in server mode

─────────────────────────────────────────────────
 JOB IMAGE STORAGE
─────────────────────────────────────────────────
• Save job photos from Claude chat to local storage
• 15 formats: JPEG, HEIC, PNG, WebP, DNG, RAW & more
• iPhone (HEIC) and Android (WebP/DNG) fully supported
• Metadata index per job — searchable without pixel data

─────────────────────────────────────────────────
 EMAIL, SMS & WHATSAPP
─────────────────────────────────────────────────
• Send emails, alerts, file attachments, learnings reports
• Gmail, iCloud, Outlook, or any SMTP provider
• Text or WhatsApp anyone via Twilio, SignalWire, or Vonage
• Reply checking with per-user attribution in server mode

⚠  .doc and legacy .xls not supported — convert to .docx / .xlsx

100% Local  •  100% Private  •  100% Yours

Built with Python, ChromaDB, FastMCP, and Claude"""

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
                "that survives restarts and never needs to be re-copied.",
                "",
                "NOTE: Free Cloudflare accounts and free tier tunnels are sufficient.",
                "NOTE: You will need a domain name. Cloudflare Registrar sells",
                "      domains at cost (~$10/year for .com), or you can transfer",
                "      an existing domain. A Named Tunnel requires this one-time",
                "      setup step.",
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
                "1. In Zero Trust, click 'Networks' → 'Tunnels' in the left",
                "   menu.  (In the newer Cloudflare UI this may be labeled",
                "   'Networks' → 'Connectors'.)",
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
                "       URL:   localhost:8000  (or whatever port AI-Prowler",
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
                cfg = json.loads(cfg_path.read_text(encoding='utf-8-sig'))
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
                "2. Your Named Tunnel is active (Settings → Remote Access).",
                "3. Your Bearer Token is saved (Settings → Bearer Token field).",
                "",
                "NOTE: If you haven't set up a tunnel yet, click",
                "      'Setup Cloudflare Tunnel' in Settings first.",
            ]),

            ("Step 1 — Open Claude.ai settings", [
                "1. Click 'Open Claude.ai' below — it takes you to the right page.",
                "2. Sign in with your Claude Pro account.",
                "3. Look for 'Connectors' in the left sidebar of Settings.",
                "   OR: click your Name Initials at the bottom-left of Claude.ai",
                "   → Settings → Connectors → Customize → + (Add custom connector)",
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
                "Advanced settings — OAuth fields:",
                "  OAuth Client ID:     (leave blank — not required)",
                "  OAuth Client Secret: (leave blank — not required)",
                "",
                "AI-Prowler uses Bearer Token auth, not OAuth.",
                "Leaving the OAuth fields empty is correct.",
                "",
                "When prompted for authentication after clicking Connect:",
                "  Enter your Bearer Token (click 'Copy Bearer Token' below)",
                "  in the login page that opens in your browser.",
            ]),

            ("Step 4 — Save and verify", [
                "1. Click 'Save' or 'Connect'.",
                "2. Claude will attempt to connect to your tunnel.",
                "3. If successful, you'll see 'Connected' or a green indicator.",
                "4. AI-Prowler tools will be listed in the connector.",
                "",
                "IMPORTANT — Enable tools after connecting:",
                "  In the connector panel, click 'Always allow' on the",
                "  tool permissions section to enable all AI-Prowler tools.",
                "  Without this, Claude will ask permission for every tool call.",
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
                "    or typo in hostname. Check Settings → Remote Access.",
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
        """Show help content in a navigable window with a clickable Table of
        Contents sidebar and section-jump capability.

        The TOC is built by scanning for lines that start with '## ' (top-level
        sections).  Clicking a TOC entry scrolls the main text pane to that
        heading.  Markdown headings are rendered bold/larger; code blocks get a
        monospace font. The raw markdown escape sequences used in the .md file
        (\\--- , \\*, \\[, etc.) are stripped for readability.
        """
        import re as _re

        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("1060x720")
        win.minsize(700, 480)

        # ── Top-level layout: sidebar (TOC) + main text pane ─────────────────
        paned = tk.PanedWindow(win, orient='horizontal', sashrelief='raised',
                               sashwidth=5, bg='#cccccc')
        paned.pack(fill='both', expand=True, padx=6, pady=(6, 0))

        # ── Left: TOC listbox ─────────────────────────────────────────────────
        toc_frame = tk.Frame(paned, width=220, bg='#f5f5f5')
        toc_frame.pack_propagate(False)
        paned.add(toc_frame, minsize=160)

        tk.Label(toc_frame, text="Contents", font=('Segoe UI', 10, 'bold'),
                 bg='#f5f5f5', anchor='w').pack(fill='x', padx=6, pady=(6, 2))

        toc_scroll = tk.Scrollbar(toc_frame, orient='vertical')
        toc_list = tk.Listbox(toc_frame, font=('Segoe UI', 9),
                              yscrollcommand=toc_scroll.set,
                              selectbackground='#0078d4', selectforeground='white',
                              activestyle='none', bd=0, highlightthickness=0,
                              bg='#f5f5f5')
        toc_scroll.config(command=toc_list.yview)
        toc_list.pack(side='left', fill='both', expand=True, padx=(4, 0), pady=(0, 4))
        toc_scroll.pack(side='right', fill='y', pady=(0, 4))

        # ── Right: main text pane ─────────────────────────────────────────────
        text_frame = tk.Frame(paned)
        paned.add(text_frame, minsize=400)

        txt_scroll = tk.Scrollbar(text_frame, orient='vertical')
        txt = tk.Text(text_frame, wrap=tk.WORD, font=('Segoe UI', 10),
                      yscrollcommand=txt_scroll.set,
                      padx=14, pady=10, bd=0, highlightthickness=0,
                      state='normal', cursor='arrow')
        txt_scroll.config(command=txt.yview)
        txt.pack(side='left', fill='both', expand=True)
        txt_scroll.pack(side='right', fill='y')

        # ── Text tags ─────────────────────────────────────────────────────────
        txt.tag_configure('h1',   font=('Segoe UI', 15, 'bold'), spacing3=4,
                          foreground='#003580')
        txt.tag_configure('h2',   font=('Segoe UI', 13, 'bold'), spacing3=3,
                          foreground='#005a9e')
        txt.tag_configure('h3',   font=('Segoe UI', 11, 'bold'), spacing3=2,
                          foreground='#1a6096')
        txt.tag_configure('h4',   font=('Segoe UI', 10, 'bold'), spacing3=1,
                          foreground='#2a7ab5')
        txt.tag_configure('code', font=('Consolas', 9),
                          background='#f0f0f0', foreground='#333333')
        txt.tag_configure('hr',   font=('Segoe UI', 1),
                          foreground='#cccccc', spacing1=4, spacing3=4)
        txt.tag_configure('body', font=('Segoe UI', 10))

        # ── Table tags ────────────────────────────────────────────────────────
        # Tables are rendered with box-drawing characters in a monospace font
        # so columns align perfectly regardless of content width.
        txt.tag_configure('tbl_border',
                          font=('Consolas', 9), foreground='#999999')
        txt.tag_configure('tbl_head',
                          font=('Consolas', 9, 'bold'),
                          background='#dce8f7', foreground='#00336e')
        txt.tag_configure('tbl_row',
                          font=('Consolas', 9), background='#ffffff')
        txt.tag_configure('tbl_row_alt',
                          font=('Consolas', 9), background='#f4f8ff')

        # ── Parse and render markdown ─────────────────────────────────────────
        # Maps TOC entry index → text index string so clicking jumps correctly.
        toc_entries   = []   # list of (display_label, mark_name)
        section_marks = {}   # mark_name → inserted mark in txt widget
        in_code_block = False
        code_buf      = []
        table_buf     = []   # accumulates consecutive | lines

        def _flush_table(rows):
            """Render a markdown table as an embedded tk.Frame grid.
            Each cell is a tk.Label with wraplength set to its column width,
            so content wraps downward inside the cell — the table never needs
            horizontal scrolling and the window never needs to be widened."""
            if not rows:
                return
            import re as _re2

            # ── Parse rows into cell lists ───────────────────────────────
            parsed = []
            for r in rows:
                stripped = r.strip()
                if stripped.startswith('|'):
                    stripped = stripped[1:]
                if stripped.endswith('|'):
                    stripped = stripped[:-1]
                cells = [c.strip() for c in stripped.split('|')]
                parsed.append(cells)

            # ── Remove the separator row (---|---|---) ───────────────────
            data_rows = []
            for row in parsed:
                if all(_re2.match(r'^:?-+:?$', c.strip() or '-') for c in row):
                    continue
                data_rows.append(row)

            if not data_rows:
                return

            # ── Normalise column count ───────────────────────────────────
            ncols = max(len(r) for r in data_rows)
            for r in data_rows:
                while len(r) < ncols:
                    r.append('')

            # ── Build embedded frame grid ────────────────────────────────
            # outer frame provides the table border colour as a background
            BORDER  = '#b0b8c8'
            HEAD_BG = '#dce8f7'
            HEAD_FG = '#00336e'
            ROW_BG  = ('#ffffff', '#f0f4fb')   # alternating even/odd

            outer = tk.Frame(txt, bg=BORDER, padx=1, pady=1)
            inner = tk.Frame(outer, bg=BORDER)
            inner.pack(fill='both', expand=True)

            # ── Scroll-forward helper ────────────────────────────────────
            # Embedded frames/labels absorb <MouseWheel> and stop it
            # reaching the Text widget. Bind every table widget to forward
            # the event so the user can scroll while hovering over a table.
            def _fwd(e):
                txt.yview_scroll(int(-1 * (e.delta / 120)), 'units')

            def _bind_scroll(w):
                w.bind('<MouseWheel>', _fwd, add='+')

            _bind_scroll(outer)
            _bind_scroll(inner)

            # Track every label so we can update wraplength on resize
            _labels_by_col = [[] for _ in range(ncols)]

            for row_idx, row in enumerate(data_rows):
                is_head = (row_idx == 0)
                row_bg  = HEAD_BG if is_head else ROW_BG[(row_idx - 1) % 2]

                for col_idx, cell_text in enumerate(row):
                    cell_frame = tk.Frame(inner, bg=row_bg, bd=0)
                    cell_frame.grid(row=row_idx, column=col_idx,
                                    sticky='nsew', padx=1, pady=1)
                    _bind_scroll(cell_frame)

                    lbl = tk.Label(
                        cell_frame,
                        text=cell_text,
                        font=('Segoe UI', 9, 'bold') if is_head
                             else ('Segoe UI', 9),
                        bg=row_bg,
                        fg=HEAD_FG if is_head else '#1a1a1a',
                        padx=8, pady=5,
                        anchor='nw', justify='left',
                        wraplength=160    # updated dynamically below
                    )
                    lbl.pack(fill='both', expand=True, anchor='nw')
                    _bind_scroll(lbl)
                    _labels_by_col[col_idx].append(lbl)

            for col_idx in range(ncols):
                inner.columnconfigure(col_idx, weight=1)

            # ── Dynamic wraplength — recalculate on every window resize ──
            # Subtract borders, scrollbar, TOC sidebar, and cell padding
            # then divide evenly across columns.
            def _update_wrap(event=None):
                try:
                    w = txt.winfo_width()
                    if w < 80:
                        return
                    col_px = max(60, (w - 40) // ncols - 16)
                    for col_labels in _labels_by_col:
                        for lbl in col_labels:
                            lbl.configure(wraplength=col_px)
                except Exception:
                    pass

            txt.bind('<Configure>', lambda e: _update_wrap(), add='+')
            txt.after(80, _update_wrap)   # initial pass after layout settles

            txt.window_create(tk.END, window=outer)
            txt.insert(tk.END, '\n\n')

        def _clean(line):
            """Strip common markdown escapes used in the .md file."""
            # Remove backslash escapes: \--- \* \[ etc.
            line = _re.sub(r'\\([*\[\]_`#\-|])', r'\1', line)
            # Remove stray leading backslashes before --- separators
            line = _re.sub(r'^\\+(-{3,})\s*$', r'\1', line)
            return line

        def _flush_code(buf):
            if buf:
                txt.insert(tk.END, '\n'.join(buf) + '\n', 'code')
                txt.insert(tk.END, '\n')
            buf.clear()

        lines = content.splitlines()
        for raw_line in lines:
            line = raw_line

            # Code fence toggle
            if line.strip().startswith('```'):
                # Flush any pending table first
                if table_buf:
                    _flush_table(table_buf)
                    table_buf.clear()
                if in_code_block:
                    _flush_code(code_buf)
                    in_code_block = False
                else:
                    in_code_block = True
                continue

            if in_code_block:
                code_buf.append(line)
                continue

            # ── Table row detection ───────────────────────────────────────
            # Buffer consecutive lines that look like markdown table rows
            # (start with optional whitespace then '|').
            # A blank line or any non-table line flushes the buffer.
            if line.strip().startswith('|'):
                table_buf.append(line)
                continue
            else:
                if table_buf:
                    _flush_table(table_buf)
                    table_buf.clear()

            line = _clean(line)

            # Horizontal rules
            if _re.match(r'^-{3,}\s*$', line):
                txt.insert(tk.END, '─' * 80 + '\n', 'hr')
                continue

            # ATX headings
            h_match = _re.match(r'^(#{1,4})\s+(.*)', line)
            if h_match:
                level  = len(h_match.group(1))
                text_  = h_match.group(2).strip()
                # Strip trailing \  escapes / markdown link syntax
                text_  = _re.sub(r'\\$', '', text_).strip()
                # Strip inline markdown like **bold** or `code`
                text_  = _re.sub(r'[`*]', '', text_)
                tag    = f'h{level}'

                # Insert the heading text first, THEN place the mark at the
                # start of the heading line so txt.see(mark) lands correctly.
                txt.insert(tk.END, text_ + '\n', tag)
                txt.insert(tk.END, '\n')
                mark = f'mark_{len(toc_entries)}'
                txt.mark_set(mark, f'end - 2 lines linestart')
                txt.mark_gravity(mark, tk.LEFT)

                # Only h2 sections go into the TOC (top-level numbered sections)
                if level == 2:
                    # Build a short label — strip trailing markdown link text
                    label = _re.sub(r'\[.*?\]', '', text_).strip()
                    toc_entries.append((label, mark))
                    toc_list.insert(tk.END, '  ' + label)
                elif level == 3:
                    toc_entries.append((text_, mark))
                    toc_list.insert(tk.END, '    › ' + text_)
                continue

            # Strip inline markdown (bold, italic, inline code for display)
            # Keep the text, drop the syntax characters
            display = _re.sub(r'\*\*(.+?)\*\*', r'\1', line)
            display = _re.sub(r'\*(.+?)\*',     r'\1', display)
            display = _re.sub(r'`(.+?)`',       r'\1', display)
            # Strip markdown link syntax [text](url) → text
            display = _re.sub(r'\[([^\]]+)\]\([^\)]*\)', r'\1', display)

            txt.insert(tk.END, display + '\n', 'body')

        if in_code_block:
            _flush_code(code_buf)
        if table_buf:
            _flush_table(table_buf)
            table_buf.clear()

        txt.config(state='disabled')

        # ── TOC click → jump to section ───────────────────────────────────────
        def _on_toc_select(event):
            sel = toc_list.curselection()
            if not sel:
                return
            idx = sel[0]
            if idx < len(toc_entries):
                _, mark = toc_entries[idx]
                try:
                    # Get the line number the mark sits on and scroll it
                    # to the top of the visible area using yview_scroll.
                    mark_index = txt.index(mark)          # e.g. "142.0"
                    txt.see(mark_index)                   # ensure it's visible
                    txt.update_idletasks()
                    # Now nudge so the heading sits near the top, not the middle
                    txt.yview_scroll(-10, 'units')        # scroll back up a bit
                    txt.see(mark_index)                   # re-anchor to heading
                except Exception:
                    pass

        toc_list.bind('<<ListboxSelect>>', _on_toc_select)
        toc_list.bind('<Double-Button-1>', _on_toc_select)

        # ── Highlight tag for search matches ──────────────────────────────────
        txt.tag_configure('find_match',
                          background='#ffee00', foreground='#000000')
        # Raise above other tags so yellow always shows on top
        txt.tag_raise('find_match')

        # ── Track which pane was last clicked ─────────────────────────────────
        _active_pane = ['txt']   # 'txt' or 'toc'
        toc_list.bind('<Button-1>',
                      lambda e: _active_pane.__setitem__(0, 'toc'), add='+')
        txt.bind('<Button-1>',
                 lambda e: _active_pane.__setitem__(0, 'txt'), add='+')

        # ── Bottom buttons ────────────────────────────────────────────────────
        btn_row = tk.Frame(win)
        btn_row.pack(fill='x', padx=6, pady=6)

        # Search bar
        tk.Label(btn_row, text="Find:",
                 font=('Segoe UI', 9)).pack(side='left')
        search_var = tk.StringVar()
        search_entry = ttk.Entry(btn_row, textvariable=search_var, width=22)
        search_entry.pack(side='left', padx=(2, 2))

        # ── Search state ──────────────────────────────────────────────────────
        _fwd_pos  = ['1.0']    # forward cursor in text widget
        _bwd_pos  = [tk.END]   # backward cursor in text widget
        _toc_idx  = [0]        # current TOC search index

        def _clear_highlights():
            txt.tag_remove('find_match', '1.0', tk.END)

        def _on_query_change(*_):
            """Reset positions whenever the search string changes."""
            _clear_highlights()
            _fwd_pos[0] = '1.0'
            _bwd_pos[0] = tk.END
            _toc_idx[0] = 0

        search_var.trace_add('write', _on_query_change)

        def _search_toc(direction):
            """Search TOC entries; select matching entry and jump to its
            section in the text pane."""
            query = search_var.get().strip().lower()
            if not query or not toc_entries:
                return
            n   = len(toc_entries)
            cur = _toc_idx[0]

            # Build a search order: from cur+direction, then wrap
            order = []
            i = cur + direction
            while 0 <= i < n:
                order.append(i)
                i += direction
            # Wrap-around portion
            if direction > 0:
                i = 0
                while i <= cur:
                    order.append(i)
                    i += 1
            else:
                i = n - 1
                while i >= cur:
                    order.append(i)
                    i -= 1

            for idx in order:
                label, mark = toc_entries[idx]
                if query in label.lower():
                    _toc_idx[0] = idx
                    toc_list.selection_clear(0, tk.END)
                    toc_list.selection_set(idx)
                    toc_list.see(idx)
                    # Jump to the section in the text pane as well
                    try:
                        mark_index = txt.index(mark)
                        txt.see(mark_index)
                        txt.update_idletasks()
                        txt.yview_scroll(-5, 'units')
                        txt.see(mark_index)
                    except Exception:
                        pass
                    return

        def _search_text(direction):
            """Find next (direction=+1) or previous (direction=-1) match in
            the text pane, highlight it in yellow, and scroll it into view."""
            query = search_var.get().strip()
            if not query:
                return
            _clear_highlights()

            if direction > 0:
                start = _fwd_pos[0] or '1.0'
                pos = txt.search(query, start, nocase=True, stopindex=tk.END)
                if not pos:  # wrap around
                    pos = txt.search(query, '1.0', nocase=True,
                                     stopindex=tk.END)
            else:
                start = _bwd_pos[0] or tk.END
                pos = txt.search(query, start, nocase=True,
                                 stopindex='1.0', backwards=True)
                if not pos:  # wrap around
                    pos = txt.search(query, tk.END, nocase=True,
                                     stopindex='1.0', backwards=True)

            if pos:
                end_pos = f'{pos}+{len(query)}c'
                txt.tag_add('find_match', pos, end_pos)
                txt.see(pos)
                # Advance cursors for next call
                _fwd_pos[0] = end_pos
                _bwd_pos[0] = pos
            else:
                # Nothing found — reset so next search starts fresh
                _fwd_pos[0] = '1.0'
                _bwd_pos[0] = tk.END

        def _do_search(direction=1):
            """Route search to the pane that was last clicked."""
            if _active_pane[0] == 'toc':
                _search_toc(direction)
            else:
                _search_text(direction)

        # Bind Enter → find down, Shift+Enter → find up
        search_entry.bind('<Return>',       lambda e: _do_search(1))
        search_entry.bind('<Shift-Return>', lambda e: _do_search(-1))

        ttk.Button(btn_row, text="▲ Prev",
                   command=lambda: _do_search(-1),
                   width=7).pack(side='left', padx=(0, 2))
        ttk.Button(btn_row, text="▼ Next",
                   command=lambda: _do_search(1),
                   width=7).pack(side='left', padx=(0, 12))

        ttk.Button(btn_row, text="Close",
                   command=win.destroy,
                   width=8).pack(side='right')
    
    def get_quick_start_content(self):
        """Get quick start guide content"""
        return f"""AI-PROWLER QUICK START GUIDE
Version {APP_VERSION}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AI-Prowler is an Agentic RAG platform — it gives Claude
powerful MCP tools to search, cross-reference, and synthesize
answers from your own documents. You ask a question;
Claude researches your knowledge base and answers it.

Two ways to talk to Claude:

  📱  Claude.ai (web or mobile app)  — PREFERRED
      Works on phone, tablet, and desktop browsers.
      Requires an active AI-Prowler Mobile Access subscription.
      Subscribe and configure in one click from Settings.

  💻  Claude Desktop  — desktop-only alternative
      Connects locally via stdio. No tunnel needed.
      Free to install alongside Claude.ai.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  STEP 1: INDEX YOUR DOCUMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  STEP 2 — OPTION A: CLAUDE.AI (PREFERRED)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Access your knowledge base from your phone, tablet, or
any browser — with full agentic RAG capability.

Requirements:
  • Claude Pro plan on Claude.ai
  • Active AI-Prowler Mobile Access subscription

Setup (one time — everything is automated):
  1. Go to Settings → 📡 Remote Access
  2. Enter a Bearer token and click Save Token
  3. Click ▶ Start HTTP Server
  4. Click Subscribe — Personal (or Business)
     → complete Stripe checkout
     → check email for activation code
  5. Paste activation code → click ⚡ Configure Mobile Access
     → tunnel is provisioned and started automatically
  6. Click the red 📖 Connect Claude.ai (auto) button
     → reads instructions → click OK
     → Claude.ai opens with connector form
     → paste URL → name it AI-Prowler → click Add
     → enter Bearer token when prompted
     → set Always Allow for all tools

Daily use — the server and tunnel auto-start on login.

Subscription info:  Help → User Guide → Section 8
Support:            david.vavro1@gmail.com


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  STEP 2 — OPTION B: CLAUDE DESKTOP (DESKTOP ONLY)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Good alternative when you only need access from this PC.
No Cloudflare Tunnel needed, no subscription beyond
a free Claude account.

  1. Open the 🔗 Quick Links tab
  2. Click "🚀 Launch Claude Desktop"
     • First time? Click "⬇ Install Claude Desktop" first
  3. Start a NEW conversation and ask a research question:

     "Summarize the key risks in my Q3 contracts"
     "What does my insurance policy say about flooding?"
     "Find everything related to Project Alpha"

Claude calls multiple search tools, follows leads, and
synthesizes a comprehensive answer automatically.

  ✅ No HTTP server needed for Claude Desktop
  ✅ Works with a free Claude account
  ✅ Completely local — no internet required for the RAG connection

Note: The installer registers AI-Prowler with Claude
Desktop automatically. No config files to edit.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🧠  SELF-LEARNING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AI-Prowler remembers what you tell it across sessions.

  "Remember: Client Alpha prefers email over phone calls"
  "Remember: HVAC permits in this county take 10 business days"
  "What do we know about Client Alpha?"  → finds it instantly

Manage saved learnings from the 🧠 Learnings tab — browse,
filter, archive, or delete. See Help → User Guide → Section 20.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📧  EMAIL, SMS & WHATSAPP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Configure once in Settings → Email Configuration (Gmail,
iCloud, or any SMTP provider) and Settings → SMS / Text
Messaging (Twilio, SignalWire, or Vonage), then ask Claude
to text, WhatsApp, or email anyone — by name if they're in
your job spreadsheet or saved as a contact.

  "Text Karen that we're 20 minutes away"
  "Send me an alert — the Johnson job is running late"
  "Email the job tracker spreadsheet to myself"
  "WhatsApp Torres a reminder about tomorrow's appointment"
  "Did anyone reply to my texts today?"


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔄  KEEPING YOUR INDEX CURRENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• Click "🔄 Update Index" tab → "Update All" after
  adding or changing files in tracked directories
• Or ask Claude: "Update my knowledge base" — it calls
  update_tracked_directories() automatically
• Set up auto-scheduling in the ⏰ Schedule tab
  (default: once a day at 2:00 AM)


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📞  NEED MORE HELP?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Full documentation:  Help → 📖 User Guide
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
2. Quick Links tab → Launch Claude Desktop
3. Update Index tab → Update All (weekly)
4. Settings tab → adjust scheduling and tracked directories

For detailed help, open COMPLETE_USER_GUIDE.md in your text editor
or from the Help menu."""
    
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # Create menu bar
        self.create_menu_bar()

        # Status bar — pack BEFORE the notebook so the bottom-anchored bar
        # always reserves its space first. If the notebook packs first with
        # expand=True it can steal all available height on small screens and
        # push the status bar (with the MCP Ready indicator) off the bottom.
        self.create_status_bar()

        # Create notebook (tabs) — packs into the remaining space above the
        # status bar.
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tabs — ORDER MATTERS: _TAB_INDEX_* constants must match insertion order
        self.create_welcome_tab()          # 0  ← Welcome / Info / Ad Space
        self.create_query_tab()            # 1  ← Quick Links (prewarmed on switch)
        self.create_index_tab()            # 2
        self.create_update_tab()           # 3
        self.create_scan_config_tab()      # 4
        self.create_scheduling_tab()       # 5
        self.create_settings_tab()         # 6
        self.create_small_business_tab()   # 7  ← Small Business Service Tools
        self.create_learnings_tab()        # 8  ← Self-Learning Knowledge Base

        # 9 (conditional) ← Admin tab: ONLY in Business server mode. Appended
        # LAST so it never shifts the fixed _TAB_INDEX_* constants above.
        # NOTE: read the RUNTIME config (~/.ai-prowler/config.json) — that's
        # where 'edition' and 'mode' live. The engine's load_config() reads a
        # DIFFERENT file (~/.rag_config.json, legacy GUI settings) and would
        # always miss these keys.
        self._TAB_INDEX_ADMIN = None
        try:
            import json as _json
            from pathlib import Path as _Path
            _rt_path = _Path.home() / ".ai-prowler" / "config.json"
            _cfg = {}
            if _rt_path.exists():
                try:
                    _cfg = _json.loads(_rt_path.read_text(encoding="utf-8-sig")) or {}
                except Exception as _je:
                    print(f"[admin tab] could not parse {_rt_path}: {_je}")
                    _cfg = {}
            if (str(_cfg.get("edition", "")).lower() == "business"
                    and str(_cfg.get("mode", "")).lower() == "server"):
                self.create_admin_tab()
                self._TAB_INDEX_ADMIN = self.notebook.index('end') - 1
                print(f"[admin tab] enabled (edition=business, mode=server)")
            else:
                # Helpful diagnostic in dev — silent in normal Home use because
                # the file simply isn't present.
                if _rt_path.exists():
                    print(f"[admin tab] not enabled — runtime config has "
                          f"edition={_cfg.get('edition')!r} mode={_cfg.get('mode')!r}; "
                          f"need edition='business' and mode='server'")
        except Exception as _admin_e:
            # Never let an Admin-tab problem block the rest of the GUI.
            try:
                print(f"[admin tab] skipped: {_admin_e}")
            except Exception:
                pass

        # Named tab index constants — change here if tabs are ever reordered
        self._TAB_INDEX_WELCOME      = 0   # Welcome / Info / Ad Space
        self._TAB_INDEX_QUERY        = 1   # Quick Links tab — triggers Ollama prewarm
        self._TAB_INDEX_INDEX        = 2
        self._TAB_INDEX_UPDATE       = 3
        self._TAB_INDEX_SCAN         = 4
        self._TAB_INDEX_SCHEDULE     = 5
        self._TAB_INDEX_SETTINGS     = 6
        self._TAB_INDEX_SMALL_BIZ    = 7   # Small Business Service Tools
        self._TAB_INDEX_LEARNINGS    = 8   # Self-Learning Knowledge Base
    
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

    def _create_server_status_tab(self):
        """Build a minimal Server Status tab for Business Server mode.

        Replaces the full Home/welcome tab so the GUI is clean and
        purpose-built for a server environment. No ad content, no
        notification banners, no outbound GitHub fetches.

        Shows: edition/mode badge, version, database path, chunk count,
        tracked directory count, and a manual Refresh button.
        """
        server_frame = ttk.Frame(self.notebook)
        self.notebook.add(server_frame, text="🖥️ Server")

        # Stub out ad/notification attributes so any shared code that
        # references them doesn't crash (e.g. _display_notifications).
        self._notif_frame         = ttk.Frame(server_frame)
        self._notif_widgets       = []
        self._update_banner_widget = None
        self._update_available    = False
        self._notif_debug_var     = tk.StringVar(value="")
        self._dismissed_path      = Path.home() / '.ai-prowler' / 'dismissed_notifications.json'
        self._notif_cache_path    = Path.home() / '.ai-prowler' / 'notifications_cache.json'
        self._ad_cache_path       = Path.home() / '.ai-prowler' / 'welcome_ad_cache.json'
        self._ad_local_path       = Path.home() / '.ai-prowler' / 'welcome_config.json'
        self._notif_url           = ""
        self._ad_url              = ""
        self._install_id_path     = Path.home() / '.ai-prowler' / 'install_id'
        self._telemetry_counter_path = Path.home() / '.ai-prowler' / 'telemetry_counter.json'
        self._telemetry_last_path    = Path.home() / '.ai-prowler' / 'telemetry_last_success.txt'
        self._telemetry_lock_path    = Path.home() / '.ai-prowler' / 'telemetry_lock.txt'

        # Schedule telemetry tick (same as Home mode — server still phones home)
        self.root.after(_TELEMETRY_FIRST_DELAY_SEC * 1000, self._telemetry_tick)

        # ── Layout ────────────────────────────────────────────────────────────
        container = ttk.Frame(server_frame, padding=(40, 30))
        container.pack(fill='both', expand=True)

        # Icon
        try:
            _icon_path = Path(__file__).parent / 'rag_icon.ico'
            if _icon_path.exists():
                from PIL import Image, ImageTk
                img = Image.open(str(_icon_path))
                img = img.resize((128, 128), Image.LANCZOS)
                self._server_icon_ref = ImageTk.PhotoImage(img)
                ttk.Label(container, image=self._server_icon_ref).pack(anchor='center', pady=(0, 10))
        except Exception:
            ttk.Label(container, text="🖥️", font=('Arial', 48)).pack(anchor='center', pady=(0, 10))

        # Title + edition badge
        ttk.Label(container,
                  text="AI-Prowler  —  Business Server",
                  font=('Arial', 16, 'bold')).pack(anchor='center')
        ttk.Label(container,
                  text=f"v{APP_VERSION}",
                  font=('Arial', 10), foreground='gray').pack(anchor='center', pady=(2, 16))

        ttk.Separator(container, orient='horizontal').pack(fill='x', pady=(0, 16))

        # Status grid
        status_frame = ttk.LabelFrame(container, text="Server Status", padding=(20, 12))
        status_frame.pack(fill='x', pady=(0, 16))

        self._srv_status_vars = {}

        def _add_row(label, key, value="—"):
            row = ttk.Frame(status_frame)
            row.pack(fill='x', pady=3)
            ttk.Label(row, text=f"{label}:", font=('Arial', 10, 'bold'),
                      width=20, anchor='w').pack(side='left')
            var = tk.StringVar(value=value)
            self._srv_status_vars[key] = var
            ttk.Label(row, textvariable=var, font=('Arial', 10),
                      anchor='w').pack(side='left', fill='x', expand=True)

        _add_row("Edition / Mode",  "edition",   "Business / Server")
        _add_row("Database path",   "db_path",   "—")
        _add_row("Total chunks",    "chunks",    "—")
        _add_row("Documents",       "docs",      "—")
        _add_row("Tracked folders", "tracked",   "—")

        # Refresh button
        ttk.Button(
            container,
            text="↻  Refresh Status",
            command=self._refresh_server_status
        ).pack(anchor='center', pady=(8, 0))

        # Initial populate after mainloop starts
        self.root.after(500, self._refresh_server_status)

    def _refresh_server_status(self):
        """Populate / refresh the Server Status tab fields from live data."""
        try:
            import rag_preprocessor as _rp
            client, emb = _rp.get_chroma_client()
            all_cols = client.list_collections()
            chunks = sum(
                client.get_collection(name=c.name, embedding_function=emb).count()
                for c in all_cols
            )
            # Unique document count via metadata scan
            docs = set()
            for c in all_cols:
                col = client.get_collection(name=c.name, embedding_function=emb)
                n = col.count()
                if n:
                    sample = col.get(limit=min(5000, n), include=["metadatas"])
                    for m in sample.get("metadatas", []):
                        fp = m.get("filepath", "")
                        if fp:
                            docs.add(fp)

            self._srv_status_vars["db_path"].set(str(_rp.CHROMA_DB_PATH))
            self._srv_status_vars["chunks"].set(f"{chunks:,}")
            self._srv_status_vars["docs"].set(str(len(docs)))
        except Exception as e:
            self._srv_status_vars["chunks"].set(f"error: {e}")

        try:
            from rag_preprocessor import load_auto_update_list
            tracked = load_auto_update_list()
            self._srv_status_vars["tracked"].set(str(len(tracked)))
        except Exception:
            pass

    def create_welcome_tab(self):
        """Create the Welcome / Home tab.

        In Business Server mode: shows a minimal Server Status panel —
        no ad content, no notifications, no GitHub fetches. The server
        runs headless so these features are irrelevant and the outbound
        traffic is undesirable.

        In Home (personal) mode: shows the full welcome page with icon,
        ad/promo content, and notification banners refreshed from GitHub.

        Ad content loading priority (Home mode only):
          1. GitHub raw URL (fetched in background)
          2. Local cache (~/.ai-prowler/welcome_ad_cache.json)
          3. Local override (~/.ai-prowler/welcome_config.json)
          4. Built-in defaults
        """
        import json as _json

        # ── Detect server mode ────────────────────────────────────────────────
        _is_server_mode = self._is_business_server_mode()

        if _is_server_mode:
            self._create_server_status_tab()
            return

        welcome_frame = ttk.Frame(self.notebook)
        self.notebook.add(welcome_frame, text="🏠 Home")

        # ── Default ad content ────────────────────────────────────────────────
        self._ad_defaults = {
            'headline':  'Welcome to AI-Prowler v8.0.0',
            'body': (
                'Your Personal Agentic AI Knowledge Base for Claude.\n\n'
                'AI-Prowler™ Home v8.0.0 for Windows 11 — index your local documents '
                'and put 85 AI-powered tools at Claude\'s fingertips, on desktop, web, and mobile.\n\n'
                '★ Index local and OneDrive documents from any folder — 65+ file formats '
                'supported including scanned PDFs and images with full OCR text extraction.\n\n'
                '★ ChromaDB vector database with semantic search — Claude queries '
                'intelligently across 10,000+ files with provenance-aware results.\n\n'
                '★ 85 MCP tools across 12 categories: Agentic RAG, Code Tools, '
                'Self-Learning, Action Tools, Email, SMS, Scheduling, Dev Tools, '
                'Indexing, Job Tracking, Analysis, and Health checks.\n\n'
                '★ Code Tools — Claude can create, edit, back up, and restore files '
                'in pre-authorized directories with a double-lock security model and '
                'per-session circuit breaker.\n\n'
                '★ Self-Learning system — Claude records business lessons, corrections, '
                'and insights into a persistent knowledge base and applies them '
                'automatically in future sessions.\n\n'
                '★ Connect via Claude Desktop (local/stdio) or Claude.ai and the '
                'Claude mobile app — one-click subscription, one-click tunnel setup, '
                'auto Connect Claude.ai button.\n\n'
                '★ AI-Prowler™ Home is free for desktop use with Claude Desktop.\n\n'
                '★ AI-Prowler™ Mobile Access — subscribe from the Settings tab for '
                '$10/month (Personal) or $20/month (Business). Tunnel provisioned '
                'automatically — no Cloudflare account needed.\n\n'
                '★ AI-Prowler™ Business — multi-user server mode with role-based '
                'access, per-user document isolation, and admin panel.\n\n'
                'Get started: click the Index Docs tab to add your first folder.'
            ),
            'link_text': 'Visit AI-Prowler.com',
            'link_url':  'https://ai-prowler.com',
            'footer':    'AI-Prowler v8.0.0 — Free for personal desktop use',
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
        # Wrap in a scrollable region so the full Home page is reachable on
        # smaller display windows (the welcome icon, ad space, and footer can
        # all end up below the fold otherwise).
        _welcome_scroll = self._make_scrollable_tab(welcome_frame)
        container = ttk.Frame(_welcome_scroll, padding=(30, 15))
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
        # The update banner ("Download Update" button) is tracked separately
        # from _notif_widgets so that _display_notifications — which clears
        # and rebuilds _notif_widgets on every refresh — does not destroy it.
        # Without this, the update banner created by _check_for_update is
        # wiped milliseconds later by the notification render (an after(0,...)
        # ordering race). See _show_update_banner.
        self._update_banner_widget = None
        # Tracks whether an in-app update is available (set by _check_for_update).
        # Used by _display_notifications to suppress full-installer notification
        # cards while the in-place updater can do the upgrade.
        self._update_available = False

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

        # ── First-launch index reconcile (v7.0.0) ────────────────────────────
        # Index any tracked path that has no chunks in ChromaDB yet — e.g. the
        # COMPLETE_USER_GUIDE.md seeded into the tracking list by the installer,
        # which was previously tracked but never actually indexed. Runs once,
        # shortly after the window is up, in a background thread. Purely
        # ADDITIVE: indexes only missing files one at a time via index_file_list
        # (which scopes its delete to each file's own chunks). Never purges or
        # resets the collection, so the existing database is left intact.
        # _reconcile_tracked_index runs inside _prewarm_embedding_model worker

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
                data = json.loads(cfg_path.read_text(encoding='utf-8-sig'))
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
                    data = json.loads(cfg_path.read_text(encoding='utf-8-sig'))
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
        #
        # Windows-11 detection note: platform.release() returns "10" on BOTH
        # Windows 10 AND Windows 11, because Microsoft kept the NT major
        # version at 10 across both releases. The actual differentiator is
        # the build number in platform.version() (formatted as "10.0.BUILD"):
        #   build  < 22000  →  Windows 10
        #   build >= 22000  →  Windows 11
        # Without this override, every Win11 install reports as "Windows-10"
        # in the heartbeat — a known wart of Python's platform module, not
        # a bug here. The fix below patches the report at the source.
        os_str = "unknown"
        try:
            import platform
            sys_name = platform.system()
            release = platform.release()
            if sys_name == "Windows" and release == "10":
                # Try to read the build number to disambiguate Win10 vs Win11
                try:
                    ver = platform.version()  # e.g. "10.0.22631"
                    build = int(ver.split('.')[2])
                    if build >= 22000:
                        release = "11"
                except (ValueError, IndexError):
                    pass  # fall back to "10" if the version string is odd
            if sys_name and release:
                os_str = f"{sys_name}-{release}"[:50]
        except Exception:
            pass

        tool_calls = self._telemetry_get_counter()
        # Total is derived as sum of per-tool counts. The Worker still
        # accepts tools_called_24h as a flat integer for backwards
        # compatibility with the existing aggregations.
        total = sum(tool_calls.values()) if tool_calls else 0

        # v7.0.1: Read actual edition and mode from the runtime config instead
        # of hardcoding 'home'. The runtime config is ~/.ai-prowler/config.json.
        # NOTE: do NOT use CONFIG_FILE here — that is the legacy ~/.rag_config.json
        # (engine settings) which never contains 'edition' or 'mode' keys.
        _edition = 'home'
        _mode    = 'personal'
        try:
            _rt_cfg_path = Path.home() / '.ai-prowler' / 'config.json'
            if _rt_cfg_path.exists():
                import json as _tj
                _rt_cfg  = _tj.loads(
                    _rt_cfg_path.read_text(encoding='utf-8-sig'))
                _edition = (str(_rt_cfg.get('edition', 'home'))
                            .strip().lower()) or 'home'
                _mode    = (str(_rt_cfg.get('mode', 'personal'))
                            .strip().lower()) or 'personal'
        except Exception:
            pass   # config unreadable — fall back to 'home' / 'personal'

        return {
            'install_id': install_id,
            'version': APP_VERSION,
            'edition': _edition,
            'mode':    _mode,
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
            # Record that an in-app update is available so _display_notifications
            # can suppress any notification that points at the FULL INSTALLER
            # exe. Showing both the green "Download Update" (in-place) banner
            # AND a yellow "Install vX" (full-installer) card to an existing
            # user invites a double-install: the installer path may require an
            # uninstall first, after which the in-app updater is gone. For a
            # running install, the in-place updater is always the correct path.
            #
            # Note: in the normal fetch sequence, _check_for_update runs just
            # BEFORE _display_notifications, so setting this flag here is enough
            # — the notification render that follows will see it. No re-render
            # is triggered from here (that would double-render).
            self._update_available = True
            self.root.after(0, self._show_update_banner,
                            latest, update_url, update_notes)
        else:
            self._update_available = False
            # Not newer (client is current or ahead) — remove any stale
            # update banner left over from a previous refresh, so the banner
            # disappears once the user has actually upgraded.
            self.root.after(0, self._clear_update_banner)

    def _clear_update_banner(self):
        """Destroy the update banner if present. Safe to call when absent."""
        if getattr(self, '_update_banner_widget', None) is not None:
            try:
                self._update_banner_widget.destroy()
            except Exception:
                pass
            self._update_banner_widget = None

    def _show_update_banner(self, version, url, notes):
        """Display an update available banner at the top of notifications.

        The banner is tracked in self._update_banner_widget (NOT in
        _notif_widgets) so that _display_notifications cannot destroy it
        when it clears and rebuilds the notification cards. Any previously
        shown update banner is destroyed first, so repeated refreshes don't
        stack duplicate banners.
        """
        # Remove a prior update banner if one exists (idempotent refresh)
        if getattr(self, '_update_banner_widget', None) is not None:
            try:
                self._update_banner_widget.destroy()
            except Exception:
                pass
            self._update_banner_widget = None

        update_frame = tk.Frame(self._notif_frame, bg='#d4edda',
                                relief='ridge', bd=1)
        # Pack at the TOP of the notification frame so the update banner sits
        # above the regular notification cards. side='top' is the pack default,
        # but we state it explicitly for clarity since other widgets share
        # this frame.
        update_frame.pack(side='top', fill='x', pady=(0, 4))

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

        self._update_banner_widget = update_frame

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

                # Tag-based fetching — pin to the released git tag so that
                # ongoing development on `main` never bleeds into an
                # in-flight user update.
                #
                # Release workflow:
                #   1. Finish v{N} on main, bump APP_VERSION, commit, push.
                #   2. git tag v{N} && git push origin v{N}
                #   3. Push the notification via the Subscription Manager.
                #
                # The notification's `latest_version` field MUST match an
                # existing git tag (with a leading 'v'). If the tag is
                # missing for any reason, we fall back to `main` so a typo
                # or forgotten tag-push doesn't brick the update path for
                # users.
                _tag_base = (f"https://raw.githubusercontent.com/"
                             f"dvavro/AI-Prowler/v{version}/")
                _main_base = ("https://raw.githubusercontent.com/"
                              "dvavro/AI-Prowler/main/")
                # The list of files to update is no longer hardcoded. Each
                # release ships an update_manifest.json listing every file
                # that belongs in an install (code, launcher, user guide,
                # icons, etc.). We fetch the manifest first and use its
                # "files" array. If the manifest is missing (older releases,
                # or a forgotten manifest in the release build), we fall back
                # to this minimal hardcoded list so the update path never
                # bricks — but the fallback is intentionally minimal and the
                # manifest is the supported mechanism.
                _fallback_files = [
                    'rag_gui.py',
                    'rag_preprocessor.py',
                    'ai_prowler_mcp.py',
                    'RAG_RUN.bat',
                    'mcp_diagnostics.py',
                ]
                _files = _fallback_files

                staging_dir.mkdir(parents=True, exist_ok=True)

                import urllib.request
                import urllib.error

                # Probe the tag once before committing to it. If the tag
                # doesn't exist on GitHub, fall back to main.
                _base = _tag_base
                try:
                    _probe_url = f"{_tag_base}{_files[0]}"
                    _probe_req = urllib.request.Request(
                        _probe_url,
                        headers={"User-Agent": f"AI-Prowler/{APP_VERSION}"})
                    with urllib.request.urlopen(_probe_req,
                                                  timeout=15) as _probe:
                        if _probe.status == 200:
                            print(f"[UPDATE] Using tag v{version}")
                except urllib.error.HTTPError as _http_exc:
                    if _http_exc.code == 404:
                        print(f"[UPDATE] Tag v{version} not found on "
                              f"GitHub — falling back to main branch.")
                        _base = _main_base
                    else:
                        # Other HTTP errors (rate limit, 5xx) — still try
                        # the tag; the per-file loop will surface real
                        # download failures.
                        print(f"[UPDATE] Tag probe returned HTTP "
                              f"{_http_exc.code} — proceeding with tag.")
                except Exception as _probe_exc:
                    # Network glitch on the probe — proceed with tag and
                    # let the per-file loop handle real failures.
                    print(f"[UPDATE] Tag probe failed ({_probe_exc}) — "
                          f"proceeding with tag.")

                # ── Fetch the update manifest from the resolved base ──────
                # update_manifest.json lists every file that belongs in an
                # install. If present, it REPLACES the fallback list. This
                # is what lets a release ship the user guide, icons, and any
                # new modules without editing this code each time.
                try:
                    _manifest_url = f"{_base}update_manifest.json"
                    _man_req = urllib.request.Request(
                        _manifest_url,
                        headers={"User-Agent": f"AI-Prowler/{APP_VERSION}"})
                    with urllib.request.urlopen(_man_req, timeout=15) as _mr:
                        _manifest = _json.loads(_mr.read().decode("utf-8"))
                    _man_files = _manifest.get("files", [])
                    if isinstance(_man_files, list) and _man_files:
                        # Manifest entries may be plain strings or objects
                        # with a "path" key (for future SHA support). Accept
                        # both.
                        _resolved = []
                        for _entry in _man_files:
                            if isinstance(_entry, str):
                                _resolved.append(_entry)
                            elif isinstance(_entry, dict) and _entry.get("path"):
                                _resolved.append(_entry["path"])
                        if _resolved:
                            _files = _resolved
                            print(f"[UPDATE] Manifest loaded — "
                                  f"{len(_files)} file(s) to update.")
                except Exception as _man_exc:
                    print(f"[UPDATE] No manifest ({_man_exc}) — using "
                          f"fallback list of {len(_fallback_files)} files.")

                downloaded = 0
                for fname in _files:
                    try:
                        _url = f"{_base}{fname}"
                        req = urllib.request.Request(
                            _url,
                            headers={"User-Agent": f"AI-Prowler/{APP_VERSION}"})
                        with urllib.request.urlopen(req, timeout=30) as resp:
                            content = resp.read()
                        out_path = staging_dir / fname
                        # Manifest entries may include subdirectories
                        # (e.g. "skills/foo.md"). Ensure the parent exists
                        # before writing.
                        out_path.parent.mkdir(parents=True, exist_ok=True)
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

            # Suppress full-installer notifications when an in-app update is
            # available. A notification flagged "suppress_when_update_available"
            # points at the full installer exe — showing it alongside the green
            # in-place "Download Update" banner invites a double-install. When
            # the in-place updater can handle the upgrade, it is the only path
            # the running client should offer. (New users who lack AI-Prowler
            # entirely reach the installer from the GitHub release page, not
            # from inside a running copy.)
            if (notif.get('suppress_when_update_available')
                    and getattr(self, '_update_available', False)):
                skipped_reasons.append(f"{nid}:suppressed-update-available")
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

        # Browse buttons — both use the unified MultiFolderDialog which shows
        # files AND folders and supports Ctrl/Shift multi-select (v7.0.0 fix).
        ttk.Button(entry_row, text="📂 Browse Files...",
                   command=self.browse_directories_multi).pack(side='left', padx=(0, 4))
        ttk.Button(entry_row, text="📁 Add Folder...",
                   command=self.browse_directories_multi).pack(side='left', padx=(0, 6))
        
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
        self.index_stop_btn.pack(side='left', padx=(0, 6))

        self.index_cancel_btn = ttk.Button(btn_row, text="✕ Cancel & Discard",
                                           command=self._index_cancel,
                                           state='disabled')
        self.index_cancel_btn.pack(side='left', padx=(0, 16))

        self.index_scan_btn = ttk.Button(btn_row, text="🔍 Scan Queue",
                                         command=self._run_prescan)
        self.index_scan_btn.pack(side='left')

        # Clarify the difference between Pause and Stop for the user
        ttk.Label(f,
                  text="⏸ Pause = suspend instantly, click again to resume  |  "
                       "⏹ Stop = save position, use ▶ Resume to continue later  |  "
                       "✕ Cancel = discard stop & return to idle (queue unchanged)",
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
        self.notebook.add(outer, text="🔗 Links & Analysis")

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
        ttk.Label(query_frame, text="Quick Links — Connect to Claude",
                  font=('Arial', 16, 'bold')).pack(pady=10)

        # ── Claude connection panel (formerly the "RECOMMENDED" banner) ──────
        # Redesigned in v6.0: dropped the ⭐ RECOMMENDED badge because Claude is
        # now the only supported AI. Rewrote the body text to give clear
        # desktop-vs-mobile guidance, and reordered the action buttons so the
        # preferred path (Claude.ai mobile/web) is on top.
        _claude_banner = tk.Frame(query_frame, bg='#0f3460',
                                  highlightthickness=1,
                                  highlightbackground='#1a5276')
        _claude_banner.pack(fill='x', padx=20, pady=(0, 8))

        _banner_inner = tk.Frame(_claude_banner, bg='#0f3460')
        _banner_inner.pack(fill='x', padx=14, pady=10)

        # ─ Left side — heading + desktop/mobile guidance text ────────────────
        _text_col = tk.Frame(_banner_inner, bg='#0f3460')
        _text_col.pack(side='left', fill='both', expand=True, padx=(0, 12))

        tk.Label(_text_col,
                 text="AI Agent Smart Guided Questions & Answers",
                 bg='#0f3460', fg='#ffffff',
                 font=('Arial', 11, 'bold'),
                 anchor='w').pack(anchor='w')

        tk.Label(_text_col,
                 text="Claude uses all AI-Prowler tools to actively research your knowledge "
                      "base — multiple searches, follow-up queries, and full document reading.",
                 bg='#0f3460', fg='#aaccee',
                 font=('Arial', 8),
                 wraplength=520, justify='left',
                 anchor='w').pack(anchor='w', pady=(2, 6))

        # Two-line guidance — desktop-only vs mobile/web
        tk.Label(_text_col,
                 text="📱  Mobile (or any device):  Claude.ai web or mobile app — preferred, "
                      "works on phone, tablet, and desktop browsers.",
                 bg='#0f3460', fg='#d8e8ff',
                 font=('Arial', 8, 'bold'),
                 wraplength=520, justify='left',
                 anchor='w').pack(anchor='w', pady=(0, 2))

        tk.Label(_text_col,
                 text="💻  Desktop only:  Claude Desktop is fully supported as an alternative "
                      "when you're at your PC.",
                 bg='#0f3460', fg='#d8e8ff',
                 font=('Arial', 8, 'bold'),
                 wraplength=520, justify='left',
                 anchor='w').pack(anchor='w')

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

        def _open_claude_ai_web():
            """Open Claude.ai in the default browser (HTTP / mobile access)."""
            import webbrowser as _wb
            _wb.open('https://claude.ai')
            self.status_var.set("Browser opened — claude.ai")

        # ─ Right side buttons — stacked vertically ────────────────────────────
        # Order matters: preferred path (Claude.ai) on top, alternative path
        # (Claude Desktop) second, install action (Download) at bottom.
        _btn_col = tk.Frame(_banner_inner, bg='#0f3460')
        _btn_col.pack(side='right', padx=(12, 0))

        # 1️⃣  Preferred: Claude.ai (web/mobile) — biggest, brightest button
        tk.Button(_btn_col,
                  text="🌐  Open Claude.ai (Preferred)",
                  bg='#1a7a4a', fg='white',
                  activebackground='#239c5e', activeforeground='white',
                  font=('Arial', 10, 'bold'),
                  relief='flat', padx=16, pady=5,
                  cursor='hand2',
                  command=_open_claude_ai_web).pack(fill='x', pady=(0, 4))

        # 2️⃣  Alternative: Claude Desktop (desktop-only use)
        tk.Button(_btn_col,
                  text="🚀  Launch Claude Desktop",
                  bg='#2980b9', fg='white',
                  activebackground='#3498db', activeforeground='white',
                  font=('Arial', 9, 'bold'),
                  relief='flat', padx=16, pady=4,
                  cursor='hand2',
                  command=_launch_claude_desktop).pack(fill='x', pady=(0, 4))

        # 3️⃣  Install action: only needed once, smallest button
        tk.Button(_btn_col,
                  text="⬇  Install Claude Desktop",
                  bg='#1a5276', fg='#aaccee',
                  activebackground='#21618c', activeforeground='white',
                  font=('Arial', 8),
                  relief='flat', padx=16, pady=3,
                  cursor='hand2',
                  command=_download_claude_desktop).pack(fill='x')

        # ── Initial connection test panel ────────────────────────────────────
        # A copy-to-clipboard helper for the recommended first prompt of every
        # new Claude chat. Paste this in once per chat to (a) verify the MCP
        # link is live and (b) prime Claude to check learnings before answering.
        _conntest_banner = tk.Frame(query_frame, bg='#2c3e50',
                                    highlightthickness=1,
                                    highlightbackground='#3a5066')
        _conntest_banner.pack(fill='x', padx=20, pady=(8, 8))

        _conntest_inner = tk.Frame(_conntest_banner, bg='#2c3e50')
        _conntest_inner.pack(fill='x', padx=14, pady=10)

        # Left side — heading + explanation
        _ct_text_col = tk.Frame(_conntest_inner, bg='#2c3e50')
        _ct_text_col.pack(side='left', fill='both', expand=True, padx=(0, 12))

        tk.Label(_ct_text_col,
                 text="✅  Initial Connection Test (recommended at start of every chat)",
                 bg='#2c3e50', fg='#ffffff',
                 font=('Arial', 11, 'bold'),
                 anchor='w').pack(anchor='w')

        tk.Label(_ct_text_col,
                 text="For best results and initial connection test, copy this command "
                      "into every new Claude chat once — it verifies the MCP link is "
                      "live and primes Claude to list all available AI-Prowler tools.",
                 bg='#2c3e50', fg='#aaccee',
                 font=('Arial', 8),
                 wraplength=520, justify='left',
                 anchor='w').pack(anchor='w', pady=(2, 6))

        # The exact command text shown in a read-only entry for transparency
        _CONN_TEST_CMD = ("Check the status of AI-Prowler and "
                          "list all the tools.")

        _cmd_entry = tk.Entry(_ct_text_col,
                              font=('Consolas', 9),
                              bg='#1a2530', fg='#d8e8ff',
                              insertbackground='#d8e8ff',
                              readonlybackground='#1a2530',
                              relief='flat', bd=2)
        _cmd_entry.insert(0, _CONN_TEST_CMD)
        _cmd_entry.configure(state='readonly')
        _cmd_entry.pack(fill='x', pady=(0, 2))

        # Right side — Copy button
        _ct_btn_col = tk.Frame(_conntest_inner, bg='#2c3e50')
        _ct_btn_col.pack(side='right', padx=(12, 0))

        def _copy_conn_test_cmd():
            """Copy the initial connection test command to the system clipboard."""
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(_CONN_TEST_CMD)
                # Force clipboard to persist after window close
                self.root.update()
                self.status_var.set(
                    "Copied connection test command to clipboard")
                # Brief visual feedback on the button itself
                _copy_btn.configure(text="✓  Copied!", bg='#1a7a4a')
                self.root.after(1500, lambda: _copy_btn.configure(
                    text="📋  Copy Command", bg='#2980b9'))
            except Exception as _e:
                self.status_var.set(f"Clipboard copy failed: {_e}")

        _copy_btn = tk.Button(_ct_btn_col,
                              text="📋  Copy Command",
                              bg='#2980b9', fg='white',
                              activebackground='#3498db',
                              activeforeground='white',
                              font=('Arial', 10, 'bold'),
                              relief='flat', padx=16, pady=8,
                              cursor='hand2',
                              command=_copy_conn_test_cmd)
        _copy_btn.pack(fill='x')

        # Divider under the banner
        ttk.Separator(query_frame, orient='horizontal').pack(
            fill='x', padx=20, pady=(0, 6))

        # ── Server-mode detection for Quick Links tab ────────────────────────
        # AI Analysis and Custom Analyses are personal-mode-only features.
        # They require local file access (pending_tasks.json, reports folder)
        # and the MCP tools that are suppressed in server mode. In server mode
        # these sections are skipped entirely — no widgets are created.
        def _is_server_mode_gui() -> bool:
            """Return True if config.json has mode=server. Never raises."""
            try:
                from pathlib import Path as _P
                import json as _jcfg
                _cp = _P.home() / ".ai-prowler" / "config.json"
                if not _cp.exists():
                    return False
                _cfg = _jcfg.loads(_cp.read_text(encoding="utf-8-sig")) or {}
                return (str(_cfg.get("edition", "")).strip().lower() == "business"
                        and str(_cfg.get("mode", "")).strip().lower() == "server")
            except Exception:
                return False

        _in_server_mode = _is_server_mode_gui()

        # ── AI Analysis section ──────────────────────────────────────────────
        # Five one-click analysis commands. Each button:
        #   1. Opens a scope-directory picker (optional)
        #   2. Writes a task record to ~/.ai-prowler/pending_tasks.json
        #      with any selected scope_dirs included in the task record
        #   3. Copies the run-queue command to the clipboard
        #   4. User pastes into Claude → Claude calls get_pending_analysis_tasks()
        #      → executes the analysis → records findings as learnings
        #      → calls complete_analysis_task() to mark done.
        # Not available in server mode (GUI-suppressed).
        # No API key required. Works entirely within the MCP architecture.
        if _in_server_mode:
            tk.Label(query_frame,
                     text="🔒  AI Analysis & Custom Analyses are not available in Server mode.",
                     bg='#1a1a1a', fg='#6a6a6a',
                     font=('Arial', 8, 'italic')).pack(anchor='w', padx=24, pady=4)
            # Nothing else to build — skip the rest of Quick Links UI
            query_frame.update_idletasks()
            return

        _analysis_banner = tk.Frame(query_frame, bg='#1a2530',
                                    highlightthickness=1,
                                    highlightbackground='#2e4a62')
        _analysis_banner.pack(fill='x', padx=20, pady=(0, 8))

        _an_inner = tk.Frame(_analysis_banner, bg='#1a2530')
        _an_inner.pack(fill='x', padx=14, pady=10)

        # Header row
        _an_hdr = tk.Frame(_an_inner, bg='#1a2530')
        _an_hdr.pack(fill='x', pady=(0, 4))

        tk.Label(_an_hdr,
                 text="🧠  Common Business AI Analysis",
                 bg='#1a2530', fg='#ffffff',
                 font=('Arial', 11, 'bold'),
                 anchor='w').pack(side='left')

        tk.Label(_an_hdr,
                 text="Click a button → queues task & copies command  ·  Paste into Claude to run ALL queued tasks",
                 bg='#1a2530', fg='#6a8fa8',
                 font=('Arial', 8),
                 wraplength=340, justify='right',
                 anchor='e').pack(side='right')

        # Analysis task definitions
        # Each entry includes a "description" shown in the popup so the user
        # knows exactly what will happen before they click Queue Analysis.
        # Analysis task definitions
        # Each entry includes a "description" shown in the popup so the user
        # knows exactly what will happen before they click Queue Analysis.
        # Prompts are QuickBooks-aware: if the QB MCP connector is active,
        # Claude uses it as the primary financial data source; otherwise falls
        # back to read_job_spreadsheet() and get_ar_aging_report().
        _ANALYSIS_TASKS = [
            {
                "type":    "run_pending",
                "label":   "🧠 Run Pending Analysis",
                "color":   "#8e44ad",
                "hover":   "#9b59b6",
                "description": (
                    "Runs every task currently sitting in the queue — in one shot.\n"
                    "Each queued task has its own prompt, scope, and output settings.\n"
                    "Use this after queueing one or more analyses below, or after\n"
                    "clicking Save & Queue in My Custom Analyses."
                ),
                "prompt":  (
                    "Call get_pending_analysis_tasks() and for each pending task: "
                    "execute the full analysis described in the task's prompt field "
                    "using all available AI-Prowler tools, record any significant "
                    "findings as learnings via record_learning(), then call "
                    "complete_analysis_task(task_id) with a one-sentence summary "
                    "of what was found."
                ),
            },
            {
                "type":    "analyze_business",
                "label":   "📊 Analyze My Business",
                "color":   "#1a5276",
                "hover":   "#21618c",
                "description": (
                    "Full business health check. Reads your Job Tracker spreadsheet\n"
                    "(or QuickBooks if connected) for jobs, invoices, AR aging, and\n"
                    "customers. Searches indexed documents and reviews learnings.\n"
                    "Records 3–5 actionable 'business_insight' learnings."
                ),
                "prompt":  (
                    "QUICKBOOKS INTEGRATION: First, check whether QuickBooks tools are available by looking for tools whose names contain 'quickbooks' or 'qbo' in your tool list. If QuickBooks is connected, prefer its data (invoices, payments, customers, P&L, balance sheet, cash flow) over the AI-Prowler Job Tracker spreadsheet wherever the data overlaps — QuickBooks is the authoritative financial source. If QuickBooks is NOT connected, fall back to read_job_spreadsheet() and get_ar_aging_report() as described below.\n\n"
                    "Analyze my business data comprehensively using all available tools:\n"
                    "IF QuickBooks is connected:\n"
                    "  1. Query QuickBooks for: open invoices, payments received this month,\n"
                    "     customer list with balances, Profit & Loss summary (current quarter\n"
                    "     vs prior quarter), top 10 customers by revenue, and AR aging report.\n"
                    "  2. Note which services or items drive the most revenue in QuickBooks.\n"
                    "IF QuickBooks is NOT connected:\n"
                    "  1. Call read_job_spreadsheet() for Jobs_Schedule, Invoices, Customers.\n"
                    "  2. Call get_ar_aging_report() for invoice aging buckets.\n"
                    "BOTH PATHS:\n"
                    "  3. Call search_documents() for indexed contracts, proposals, agreements.\n"
                    "  4. Call search_learnings() for recent business insights or known issues.\n"
                    "  5. Identify: top 3 customers by revenue, most profitable services,\n"
                    "     any invoices overdue 30+ days, jobs over estimate, recurring patterns.\n"
                    "  6. Record 3-5 actionable findings as learnings with category 'business_insight'.\n"
                    "  7. Call complete_analysis_task(task_id) with a one-sentence summary."
                ),
            },
            {
                "type":    "weekly_advisor",
                "label":   "💡 Weekly Business Advisor",
                "color":   "#1a6b3a",
                "hover":   "#1e8449",
                "description": (
                    "Your end-of-week debrief. Reviews this week's completed jobs,\n"
                    "time entries (actual vs estimated hours), outstanding invoices\n"
                    "(from QuickBooks if connected, otherwise Job Tracker), new customer\n"
                    "activity, weather patterns for scheduling, and any learnings added\n"
                    "this week. Gives a performance summary and 2–3 priorities for next week."
                ),
                "prompt":  (
                    "QUICKBOOKS INTEGRATION: First, check whether QuickBooks tools are available by looking for tools whose names contain 'quickbooks' or 'qbo' in your tool list. If QuickBooks is connected, prefer its data (invoices, payments, customers, P&L, balance sheet, cash flow) over the AI-Prowler Job Tracker spreadsheet wherever the data overlaps — QuickBooks is the authoritative financial source. If QuickBooks is NOT connected, fall back to read_job_spreadsheet() and get_ar_aging_report() as described below.\n\n"
                    "Act as my weekly business advisor using all available tools:\n"
                    "IF QuickBooks is connected:\n"
                    "  1. Query QuickBooks for: invoices created this week, payments received\n"
                    "     this week, any invoices that became overdue this week, and expenses\n"
                    "     posted this week. Compare cash in vs cash out for the week.\n"
                    "  2. Pull QuickBooks P&L for the current week vs last week if available.\n"
                    "IF QuickBooks is NOT connected:\n"
                    "  1. Call read_job_spreadsheet() for Jobs_Schedule and Invoices —\n"
                    "     focus on jobs updated or invoices created in the last 7 days.\n"
                    "  2. Call get_ar_aging_report() to flag any invoices that became overdue.\n"
                    "BOTH PATHS:\n"
                    "  3. Call search_learnings() for learnings added this week.\n"
                    "  4. Call search_documents() for new contracts or correspondence this week.\n"
                    "  5. Call get_weather() for my area for next week's scheduling outlook.\n"
                    "  6. Summarize: jobs completed vs scheduled, actual vs estimated hours,\n"
                    "     invoices sent and paid, any new problems or wins this week.\n"
                    "  7. Suggest 2-3 specific priorities for next week.\n"
                    "  8. Record key findings as learnings with category 'weekly_review'.\n"
                    "  9. Call complete_analysis_task(task_id) with a one-sentence summary."
                ),
            },
            {
                "type":    "find_problems",
                "label":   "⚠️ Find Problems",
                "color":   "#7d3c00",
                "hover":   "#a04000",
                "description": (
                    "Scans all your data for things needing attention: overdue invoices\n"
                    "(by aging bucket, from QuickBooks if connected), jobs over budget,\n"
                    "unanswered SMS from customers, unresolved expense anomalies, and\n"
                    "recurring patterns that signal risk. Each finding recorded as a\n"
                    "'problem_flag' learning."
                ),
                "prompt":  (
                    "QUICKBOOKS INTEGRATION: First, check whether QuickBooks tools are available by looking for tools whose names contain 'quickbooks' or 'qbo' in your tool list. If QuickBooks is connected, prefer its data (invoices, payments, customers, P&L, balance sheet, cash flow) over the AI-Prowler Job Tracker spreadsheet wherever the data overlaps — QuickBooks is the authoritative financial source. If QuickBooks is NOT connected, fall back to read_job_spreadsheet() and get_ar_aging_report() as described below.\n\n"
                    "Scan all my data for problems that need attention:\n"
                    "IF QuickBooks is connected:\n"
                    "  1. Query QuickBooks AR aging — flag every invoice 31-60, 61-90,\n"
                    "     and 90+ days overdue as a separate problem.\n"
                    "  2. Query QuickBooks for unpaid vendor bills overdue (AP aging).\n"
                    "  3. Query QuickBooks expenses for any unusual or duplicate charges.\n"
                    "  4. Check QuickBooks for customers with credit limits exceeded.\n"
                    "IF QuickBooks is NOT connected:\n"
                    "  1. Call get_ar_aging_report() — flag every invoice in 31-60,\n"
                    "     61-90, and 90+ day buckets as a separate problem.\n"
                    "  2. Call read_job_spreadsheet() for Jobs_Schedule — identify jobs\n"
                    "     where actual hours or cost exceeded estimate by more than 20%%.\n"
                    "BOTH PATHS:\n"
                    "  3. Call check_sms_replies() or list_sms_contacts_with_replies()\n"
                    "     for unanswered customer messages older than 24 hours.\n"
                    "  4. Call search_learnings(category='problem_flag') to review\n"
                    "     previously flagged issues — check if any are still unresolved.\n"
                    "  5. Call search_documents() for complaints, disputes, or unresolved\n"
                    "     issues mentioned in indexed documents.\n"
                    "  6. Look for recurring patterns: same customer or job type appearing\n"
                    "     in multiple problem categories.\n"
                    "  7. Record each distinct problem as a learning with category\n"
                    "     'problem_flag' and outcome 'negative'.\n"
                    "  8. Call complete_analysis_task(task_id) with a count of problems found."
                ),
            },
            {
                "type":    "growth_opportunities",
                "label":   "📈 Growth Opportunities",
                "color":   "#1a4a6b",
                "hover":   "#1f5c85",
                "description": (
                    "Mines your job history and financial data (QuickBooks if connected)\n"
                    "for growth signals: most profitable services, best-paying customers,\n"
                    "geographic clustering, seasonal patterns, and upsell opportunities.\n"
                    "QuickBooks adds P&L by service type, expense ratios, and true net\n"
                    "margin per job type. Records 3–5 'growth_opportunity' learnings."
                ),
                "prompt":  (
                    "QUICKBOOKS INTEGRATION: First, check whether QuickBooks tools are available by looking for tools whose names contain 'quickbooks' or 'qbo' in your tool list. If QuickBooks is connected, prefer its data (invoices, payments, customers, P&L, balance sheet, cash flow) over the AI-Prowler Job Tracker spreadsheet wherever the data overlaps — QuickBooks is the authoritative financial source. If QuickBooks is NOT connected, fall back to read_job_spreadsheet() and get_ar_aging_report() as described below.\n\n"
                    "Analyze my business data to identify growth opportunities:\n"
                    "IF QuickBooks is connected:\n"
                    "  1. Query QuickBooks P&L by service/product line — identify which\n"
                    "     services have highest revenue AND best net margin (revenue minus\n"
                    "     associated expenses/COGS). High margin = priority growth target.\n"
                    "  2. Query QuickBooks customer list sorted by total revenue —\n"
                    "     identify top 10 customers and their payment speed.\n"
                    "  3. Query QuickBooks for seasonal revenue pattern — compare monthly\n"
                    "     revenue for the past 12 months to identify peaks and troughs.\n"
                    "  4. Check QuickBooks for services with growing vs declining revenue\n"
                    "     trend over the last 3 quarters.\n"
                    "IF QuickBooks is NOT connected:\n"
                    "  1. Call read_job_spreadsheet() for Jobs_Schedule, Invoices, Customers.\n"
                    "  2. Call get_ar_aging_report() — fast payers are best clients.\n"
                    "  3. Call geocode_address() on top customer addresses to identify\n"
                    "     geographic clusters for route efficiency.\n"
                    "BOTH PATHS:\n"
                    "  4. Call search_documents() for proposals, pricing sheets, market data.\n"
                    "  5. Call search_learnings(category='growth_opportunity') for prior leads.\n"
                    "  6. Identify: (a) most profitable services, (b) highest-value customers,\n"
                    "     (c) geographic revenue clusters, (d) seasonal patterns,\n"
                    "     (e) service upsell pairs, (f) re-engagement targets (60+ day lapse).\n"
                    "  7. Record 3-5 specific actionable insights as learnings with category\n"
                    "     'growth_opportunity'.\n"
                    "  8. Call complete_analysis_task(task_id) with a one-sentence summary."
                ),
            },
        ]

        # Helper — load tracked dirs from ~/.rag_auto_update_dirs.json
        # The file format is {"directories": [...], "last_updated": "..."}
        # Fall back gracefully if the format is a flat dict or plain list.
        def _load_tracked_dirs_for_scope():
            try:
                from pathlib import Path as _P2
                import json as _j2, os as _o2
                _df = _P2.home() / ".rag_auto_update_dirs.json"
                if not _df.exists():
                    return []
                _raw = _j2.loads(_df.read_text(encoding="utf-8"))
                # Primary format: {"directories": [...], "last_updated": "..."}
                if isinstance(_raw, dict):
                    _dirs = _raw.get("directories", [])
                    if isinstance(_dirs, list):
                        return [k for k in _dirs if isinstance(k, str) and
                                (_o2.path.isabs(k) or k.startswith("\\\\") or k.startswith("//"))]
                    # Legacy flat-dict format: keys are paths
                    return [k for k in _raw.keys()
                            if _o2.path.isabs(k) or k.startswith("\\\\") or k.startswith("//")]
                elif isinstance(_raw, list):
                    return [k for k in _raw if isinstance(k, str) and
                            (_o2.path.isabs(k) or k.startswith("\\\\") or k.startswith("//"))]
                return []
            except Exception:
                return []

        # Helper — show full analysis options popup for ALL built-in analysis buttons
        # EXCEPT run_pending, which just copies the queue command immediately.
        # Name and Prompt are auto-filled (read-only); user configures scope,
        # output format, and report folder before queuing.
        def _queue_and_copy(task_def, btn_widget):
            import json as _json
            import datetime as _dt
            from pathlib import Path as _Path
            import custom_tasks_manager as _ctm_q

            # ── Run Pending: no popup — just copy the command ─────────────────
            # Each queued task already has its own scope baked in when it was
            # created. Run Pending simply executes the queue as-is.
            if task_def.get("type") == "run_pending":
                _cmd = (
                    "Call get_pending_analysis_tasks() and for each pending task: "
                    "execute the full analysis described in the task's prompt field "
                    "using all available AI-Prowler tools, record any significant "
                    "findings as learnings via record_learning(), then call "
                    "complete_analysis_task(task_id) with a one-sentence summary "
                    "of what was found."
                )
                try:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(_cmd)
                    self.root.update()
                except Exception:
                    pass

                # Show a brief info popup explaining what to do next
                from tkinter import messagebox as _mb_rp
                _mb_rp.showinfo(
                    "Queue Command Copied",
                    "✅  The Run Pending Analysis command has been copied to your clipboard.\n\n"
                    "Each queued task already has its own scope and output settings\n"
                    "from when it was originally created — no additional configuration needed.\n\n"
                    "👉  Open a new Claude chat and press  Ctrl+V  (or paste)\n"
                    "    to run all pending tasks in sequence."
                )
                orig_text  = btn_widget.cget("text")
                orig_color = btn_widget.cget("bg")
                btn_widget.configure(text="✓ Copied! Paste into Claude", bg='#1a7a4a')
                self.status_var.set(
                    "✅ Run Pending command copied — open Claude and press Ctrl+V to run all queued tasks")
                self.root.after(3000, lambda: btn_widget.configure(
                    text=orig_text, bg=orig_color))
                self.root.after(5000, lambda: self.status_var.set("Ready"))
                return

            tracked_dirs = _load_tracked_dirs_for_scope()

            # ── Full options popup (806×754 = 620×580 +30%) ───────────────────
            _win = tk.Toplevel(self.root)
            _win.title(f"Configure: {task_def['label']}")
            _win.geometry("806x980")
            _win.resizable(True, True)
            _win.grab_set()
            _win.focus_set()

            # Scrollable wrapper so all fields are always reachable
            _win_canvas = tk.Canvas(_win, highlightthickness=0)
            _win_vsb    = ttk.Scrollbar(_win, orient='vertical', command=_win_canvas.yview)
            _win_vsb.pack(side='right', fill='y')
            _win_canvas.pack(side='left', fill='both', expand=True)
            _win_canvas.configure(yscrollcommand=_win_vsb.set)
            _pad = tk.Frame(_win_canvas, padx=16, pady=12)
            _pad_id = _win_canvas.create_window((0, 0), window=_pad, anchor='nw')
            def _win_cfg(e):
                _win_canvas.configure(scrollregion=_win_canvas.bbox('all'))
                _win_canvas.itemconfig(_pad_id, width=_win_canvas.winfo_width())
            _pad.bind('<Configure>', _win_cfg)
            def _win_mw(e):
                _win_canvas.yview_scroll(int(-1*(e.delta/120)), 'units')
            _win_canvas.bind('<MouseWheel>', _win_mw)
            _pad.bind('<MouseWheel>', _win_mw)

            # ── Read-only Name ────────────────────────────────────────────────
            tk.Label(_pad, text="Analysis:", font=('Arial', 9, 'bold'),
                     anchor='w').pack(anchor='w')
            tk.Label(_pad, text=task_def['label'],
                     font=('Arial', 10), anchor='w').pack(anchor='w', pady=(0, 4))

            # ── What this does (description) ──────────────────────────────────
            _desc_frame = tk.Frame(_pad, bg='#e8f4e8', bd=1, relief='solid')
            _desc_frame.pack(fill='x', pady=(0, 8))
            tk.Label(_desc_frame,
                     text="What this does:",
                     font=('Arial', 8, 'bold'), bg='#e8f4e8', fg='#1a4a1a',
                     anchor='w').pack(anchor='w', padx=8, pady=(6, 2))
            tk.Label(_desc_frame,
                     text=task_def.get('description', ''),
                     font=('Arial', 8), bg='#e8f4e8', fg='#1a3a1a',
                     anchor='w', justify='left',
                     wraplength=728).pack(anchor='w', padx=8, pady=(0, 6))

            # ── Collapsible read-only Prompt ──────────────────────────────────
            _prompt_hdr = tk.Frame(_pad)
            _prompt_hdr.pack(fill='x')
            tk.Label(_prompt_hdr, text="Prompt (auto):",
                     font=('Arial', 9, 'bold'), anchor='w').pack(side='left')
            _prompt_toggle_lbl = tk.StringVar(value="▶ Show prompt")
            _prompt_box = tk.Text(_pad, height=5, width=60, wrap='word',
                                  font=('Arial', 8), fg='gray',
                                  state='disabled', bg='#f0f0f0')
            _prompt_box.configure(state='normal')
            _prompt_box.insert('1.0', task_def['prompt'])
            _prompt_box.configure(state='disabled')

            def _toggle_prompt():
                if _prompt_box.winfo_ismapped():
                    _prompt_box.pack_forget()
                    _prompt_toggle_lbl.set("▶ Show prompt")
                else:
                    _prompt_box.pack(fill='x', pady=(2, 6))
                    _prompt_toggle_lbl.set("▼ Hide prompt")

            ttk.Button(_prompt_hdr, textvariable=_prompt_toggle_lbl,
                       command=_toggle_prompt,
                       width=14).pack(side='left', padx=(8, 0))

            # ── Scope directories (scrollable) ────────────────────────────────────
            tk.Label(_pad, text="Scope directories (optional):",
                     font=('Arial', 9, 'bold'), anchor='w').pack(anchor='w', pady=(8, 0))
            tk.Label(_pad,
                     text="Check directories to focus this analysis on.  "
                          "Leave all unchecked to search everything.",
                     font=('Arial', 8), fg='gray',
                     wraplength=728, justify='left').pack(anchor='w')

            # Scrollable canvas — capped at 150px, auto-sizes for short lists
            _scope_outer = tk.Frame(_pad, bd=1, relief='sunken')
            _scope_outer.pack(fill='x', pady=(2, 8))
            _scope_canvas = tk.Canvas(_scope_outer, highlightthickness=0, bg='white')
            _scope_vsb    = ttk.Scrollbar(_scope_outer, orient='vertical',
                                          command=_scope_canvas.yview)
            _scope_inner  = tk.Frame(_scope_canvas, bg='white')
            _scope_inner_id = _scope_canvas.create_window(
                (0, 0), window=_scope_inner, anchor='nw')

            def _scope_on_configure(e):
                _scope_canvas.configure(scrollregion=_scope_canvas.bbox('all'))
                _scope_canvas.itemconfig(_scope_inner_id,
                                         width=_scope_canvas.winfo_width())
            _scope_inner.bind('<Configure>', _scope_on_configure)

            _scope_canvas.configure(yscrollcommand=_scope_vsb.set)
            _scope_vsb.pack(side='right', fill='y')
            _scope_canvas.pack(side='left', fill='both', expand=True)

            def _scope_mousewheel(e):
                _scope_canvas.yview_scroll(int(-1 * (e.delta / 120)), 'units')
            _scope_canvas.bind('<MouseWheel>', _scope_mousewheel)
            _scope_inner.bind('<MouseWheel>', _scope_mousewheel)

            _scope_vars = {}
            if tracked_dirs:
                for _d in tracked_dirs:
                    _sv = tk.BooleanVar(value=False)
                    _scope_vars[_d] = _sv
                    _cb = ttk.Checkbutton(_scope_inner, text=_d, variable=_sv)
                    _cb.pack(anchor='w', padx=4, pady=1)
                    _cb.bind('<MouseWheel>', _scope_mousewheel)
                # Height: fit content up to 150px max
                _scope_canvas.update_idletasks()
                _content_h = _scope_inner.winfo_reqheight()
                _scope_canvas.configure(height=min(_content_h + 4, 150))
            else:
                tk.Label(_scope_inner,
                         text="No indexed directories found. Index some documents first.",
                         font=('Arial', 8), fg='gray', bg='white').pack(padx=4, pady=4)
                _scope_canvas.configure(height=30)

            # ── Output options ────────────────────────────────────────────────
            tk.Label(_pad, text="Output:", font=('Arial', 9, 'bold'),
                     anchor='w').pack(anchor='w')
            _out_row = tk.Frame(_pad)
            _out_row.pack(anchor='w', pady=(2, 4))

            _learn_var  = tk.BooleanVar(value=True)
            _report_var = tk.BooleanVar(value=False)

            ttk.Checkbutton(_out_row,
                            text="💡 Save key insights to Learnings",
                            variable=_learn_var).pack(anchor='w')
            ttk.Checkbutton(_out_row,
                            text="📄 Save full analysis as Word document (.docx)",
                            variable=_report_var).pack(anchor='w')

            # ── Schedule / Recurrence ─────────────────────────────────
            tk.Label(_pad, text='Schedule:', font=('Arial', 9, 'bold'),
                     anchor='w').pack(anchor='w', pady=(8, 0))
            tk.Label(_pad,
                     text='One shot = run once now.  '
                          'Choose a schedule to repeat automatically — '
                          'AI-Prowler detects when it is due and surfaces it.',
                     font=('Arial', 8), fg='gray',
                     wraplength=728, justify='left').pack(anchor='w')

            _sched_row = tk.Frame(_pad)
            _sched_row.pack(fill='x', pady=(4, 2))

            _sched_lbl_to_key = {v: k for k, v in _ctm_q.SCHEDULE_LABELS.items()}
            _sched_var = tk.StringVar(value='Manual only')
            _sched_combo = ttk.Combobox(
                _sched_row, textvariable=_sched_var,
                values=list(_ctm_q.SCHEDULE_LABELS.values()),
                state='readonly', width=16)
            _sched_combo.set('Manual only')
            _sched_combo.pack(side='left')

            tk.Label(_sched_row, text='  First due date:',
                     font=('Arial', 9, 'bold')).pack(side='left')
            _due_var   = tk.StringVar(value='')
            _due_entry = ttk.Entry(_sched_row, textvariable=_due_var, width=12)
            _due_entry.pack(side='left', padx=(4, 0))
            tk.Label(_sched_row, text='YYYY-MM-DD  (blank = today)',
                     font=('Arial', 7), fg='gray').pack(side='left', padx=(6, 0))

            def _on_sched_change(e=None):
                  _k = _sched_lbl_to_key.get(_sched_var.get(), 'none')
                  if _k == 'none':
                        _due_entry.configure(state='disabled')
                        _due_var.set('')
                  else:
                        _due_entry.configure(state='normal')
                        if not _due_var.get():
                              import datetime as _dt2
                              _due_var.set(_dt2.date.today().isoformat())
            _sched_combo.bind('<<ComboboxSelected>>', _on_sched_change)
            _due_entry.configure(state='disabled')  # starts disabled

            # ── Report folder ─────────────────────────────────────────────────
            _folder_frame = tk.Frame(_pad)
            _folder_frame.pack(fill='x', pady=(0, 8))
            tk.Label(_folder_frame, text="Report folder:",
                     font=('Arial', 9, 'bold')).pack(side='left')
            _folder_var = tk.StringVar(value=_ctm_q.DEFAULT_REPORT_FOLDER)
            ttk.Entry(_folder_frame, textvariable=_folder_var,
                      width=52).pack(side='left', padx=(6, 4))

            def _browse_report_folder():
                import tkinter.filedialog as _fd
                d = _fd.askdirectory(
                    initialdir=_folder_var.get() or str(_Path.home()))
                if d:
                    _folder_var.set(d)

            ttk.Button(_folder_frame, text="Browse…",
                       command=_browse_report_folder).pack(side='left')

            # ── Paste reminder ────────────────────────────────────────────────
            tk.Label(_pad,
                     text="After clicking Queue Analysis →  open a new Claude chat and press  Ctrl+V  to run all queued tasks.",
                     font=('Arial', 8, 'italic'), fg='#4a6a82',
                     wraplength=728, justify='left').pack(anchor='w', pady=(0, 4))

            # ── Action buttons ────────────────────────────────────────────────
            _confirmed = tk.BooleanVar(value=False)

            def _confirm():
                _confirmed.set(True)
                _win.destroy()

            _btn_row = tk.Frame(_pad)
            _btn_row.pack(fill='x', pady=(8, 0))
            ttk.Button(_btn_row, text="Cancel",
                       command=_win.destroy).pack(side='left', padx=(0, 8))
            ttk.Button(_btn_row, text="Queue Analysis →",
                       command=_confirm).pack(side='left')

            self.root.wait_window(_win)

            if not _confirmed.get():
                return  # user cancelled

            # ── Collect choices ───────────────────────────────────────────────
            # ── Collect choices ──────────────────────────────────────────
            scope_dirs    = [d for d, v in _scope_vars.items() if v.get()]
            out_learnings = _learn_var.get()
            out_report    = _report_var.get()
            report_folder = _folder_var.get().strip() or _ctm_q.DEFAULT_REPORT_FOLDER
            schedule_key  = _sched_lbl_to_key.get(_sched_var.get(), 'none')
            first_due_val = _due_var.get().strip() or None
            import datetime as _dt3
            next_due_val  = (first_due_val or _dt3.date.today().isoformat()) \
                            if schedule_key != 'none' else None

            # ── Write task to pending_tasks.json ──────────────────────────────
            tasks_path = _Path.home() / ".ai-prowler" / "pending_tasks.json"
            try:
                existing = []
                if tasks_path.exists():
                    try:
                        existing = _json.loads(
                            tasks_path.read_text(encoding="utf-8")) or []
                        if not isinstance(existing, list):
                            existing = []
                    except Exception:
                        existing = []

                ts = _dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")

                # Build prompt: scope + output instructions appended
                prompt = task_def["prompt"].rstrip()

                if scope_dirs:
                    prompt += (
                        f"\n\nScope restriction: focus your analysis only on "
                        f"these indexed directories: {', '.join(scope_dirs)}. "
                        f"Use search_within_directory() for each scope directory "
                        f"rather than search_documents() across the full index."
                    )

                if out_learnings and out_report:
                    prompt += (
                        f"\n\nOutput: (1) Record key insights as learnings via "
                        f"record_learning() with category 'business_insight'. "
                        f"(2) Save the full analysis as a Word document via "
                        f"save_analysis_report() to folder '{report_folder}'."
                    )
                elif out_report:
                    prompt += (
                        f"\n\nOutput: Save the full analysis as a Word document "
                        f"via save_analysis_report() to folder '{report_folder}'."
                    )
                elif out_learnings:
                    prompt += (
                        "\n\nOutput: Record key insights as learnings via "
                        "record_learning() with category 'business_insight'."
                    )

                task = {
                    "task_id":          f"{task_def['type']}_{ts}",
                    "type":             task_def["type"],
                    "label":            task_def["label"],
                    "prompt":           prompt,
                    "scope_dirs":       scope_dirs,
                    "output_learnings": out_learnings,
                    "output_report":    out_report,
                    "report_folder":    report_folder,
                    "schedule":         schedule_key,
                    "first_due":        first_due_val,
                    "next_due":         next_due_val,
                    "created_at":       _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "status":           "pending",
                }
                existing.append(task)
                tasks_path.parent.mkdir(parents=True, exist_ok=True)
                tasks_path.write_text(
                    _json.dumps(existing, indent=2, ensure_ascii=False),
                    encoding="utf-8")

            except Exception as _e:
                self.status_var.set(f"Task queue error: {_e}")
                return

            # ── Copy run-all-pending command to clipboard ─────────────────────
            _cmd = (
                "Call get_pending_analysis_tasks() and for each pending task: "
                "execute the full analysis described in the task's prompt field "
                "using all available AI-Prowler tools, record any significant "
                "findings as learnings via record_learning(), then call "
                "complete_analysis_task(task_id) with a one-sentence summary "
                "of what was found."
            )
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(_cmd)
                self.root.update()
            except Exception:
                pass

            # Visual feedback
            orig_text  = btn_widget.cget("text")
            orig_color = btn_widget.cget("bg")
            scope_note = (f" ({len(scope_dirs)} dir{'s' if len(scope_dirs) != 1 else ''})"
                          if scope_dirs else "")
            out_note   = " 💡" if out_learnings else ""
            out_note  += " 📄" if out_report else ""
            btn_widget.configure(text="✓ Queued & Copied!", bg='#1a7a4a')
            self.status_var.set(
                f"✅ {task_def['label']}{scope_note}{out_note} queued "
                f"— paste into Claude to run ALL tasks")
            self.root.after(2000, lambda: btn_widget.configure(
                text=orig_text, bg=orig_color))
            self.root.after(4000, lambda: self.status_var.set("Ready"))

        # Button grid — 2 columns
        _btn_grid = tk.Frame(_an_inner, bg='#1a2530')
        _btn_grid.pack(fill='x', pady=(4, 0))

        for _idx, _task in enumerate(_ANALYSIS_TASKS):
            _col = _idx % 2
            _row = _idx // 2
            _f   = tk.Frame(_btn_grid, bg='#1a2530')
            _f.grid(row=_row, column=_col, sticky='ew', padx=(0, 6 if _col == 0 else 0),
                    pady=3)
            _btn_grid.columnconfigure(_col, weight=1)

            _b = tk.Button(_f,
                           text=_task["label"],
                           bg=_task["color"],
                           fg='white',
                           activebackground=_task["hover"],
                           activeforeground='white',
                           font=('Arial', 9, 'bold'),
                           relief='flat',
                           padx=10, pady=6,
                           cursor='hand2')
            # Capture loop variable correctly
            _b.configure(command=lambda _t=_task, _bw=_b: _queue_and_copy(_t, _bw))
            _b.pack(fill='x')
            # Hover tooltip — show first line of description in status bar
            _tip = _task.get("description", "").split("\n")[0]
            _b.bind("<Enter>", lambda e, _s=_tip: self.status_var.set(_s))
            _b.bind("<Leave>", lambda e: self.status_var.set("Ready"))

        # Hint label
        tk.Label(_an_inner,
                 text="Each button queues one task. The copied command runs ALL pending tasks when pasted into Claude.",
                 bg='#1a2530', fg='#4a6a82',
                 font=('Arial', 7),
                 anchor='w').pack(anchor='w', pady=(6, 0))

        # Divider after analysis section
        ttk.Separator(query_frame, orient='horizontal').pack(
            fill='x', padx=20, pady=(4, 6))

        # ── Queue Panel ───────────────────────────────────────────────────────
        # Collapsible panel showing all items currently in pending_tasks.json.
        # User can see what's waiting and clear individual items.

        _queue_outer = tk.Frame(query_frame, bg='#12181f',
                                highlightthickness=1,
                                highlightbackground='#2a3a4a')
        _queue_outer.pack(fill='x', padx=20, pady=(0, 6))

        _queue_hdr = tk.Frame(_queue_outer, bg='#12181f')
        _queue_hdr.pack(fill='x', padx=10, pady=6)

        _queue_count_var = tk.StringVar(value="▶ Show Queue (0)")
        _queue_expanded  = tk.BooleanVar(value=False)
        _queue_list_frame = tk.Frame(_queue_outer, bg='#12181f')

        def _refresh_queue_count():
            import json as _json
            from pathlib import Path as _Path
            p = _Path.home() / ".ai-prowler" / "pending_tasks.json"
            try:
                tasks = _json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
                pending = [t for t in tasks if t.get("status") == "pending"]
                n = len(pending)
            except Exception:
                n = 0
            _queue_count_var.set(
                f"{'▼' if _queue_expanded.get() else '▶'} Show Queue ({n})"
            )
            return n

        def _refresh_queue_list():
            import json as _json
            import datetime as _dt
            from pathlib import Path as _Path
            # Clear existing widgets
            for w in _queue_list_frame.winfo_children():
                w.destroy()
            p = _Path.home() / ".ai-prowler" / "pending_tasks.json"
            try:
                tasks = _json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
                pending = [t for t in tasks if t.get("status") == "pending"]
            except Exception:
                pending = []

            if not pending:
                tk.Label(_queue_list_frame,
                         text="Queue is empty.",
                         bg='#12181f', fg='#4a6a82',
                         font=('Arial', 8)).pack(anchor='w', padx=10, pady=4)
                return

            now = _dt.datetime.utcnow()
            for t in pending:
                try:
                    created = _dt.datetime.strptime(
                        t.get("created_at", ""), "%Y-%m-%dT%H:%M:%SZ")
                    age_mins = int((now - created).total_seconds() / 60)
                    if age_mins < 60:
                        age = f"{age_mins}m ago"
                    elif age_mins < 1440:
                        age = f"{age_mins // 60}h ago"
                    else:
                        age = f"{age_mins // 1440}d ago"
                except Exception:
                    age = ""

                row = tk.Frame(_queue_list_frame, bg='#12181f')
                row.pack(fill='x', padx=8, pady=1)

                tk.Label(row,
                         text=f"• {t.get('label', t.get('task_id','?'))}",
                         bg='#12181f', fg='#c0d0e0',
                         font=('Arial', 8),
                         anchor='w').pack(side='left')
                tk.Label(row,
                         text=age,
                         bg='#12181f', fg='#4a6a82',
                         font=('Arial', 7)).pack(side='left', padx=(6, 0))

                def _remove(tid=t.get("task_id")):
                    try:
                        import json as _j
                        from pathlib import Path as _P
                        _p = _P.home() / ".ai-prowler" / "pending_tasks.json"
                        _tasks = _j.loads(_p.read_text(encoding="utf-8")) if _p.exists() else []
                        _tasks = [x for x in _tasks if x.get("task_id") != tid]
                        _p.write_text(_j.dumps(_tasks, indent=2), encoding="utf-8")
                    except Exception:
                        pass
                    _refresh_queue_list()
                    _refresh_queue_count()

                tk.Button(row, text="✕", bg='#12181f', fg='#cc4444',
                          font=('Arial', 7), relief='flat', cursor='hand2',
                          command=_remove).pack(side='right')

            # Clear all button
            sep = ttk.Separator(_queue_list_frame, orient='horizontal')
            sep.pack(fill='x', padx=8, pady=(4, 2))
            btn_row = tk.Frame(_queue_list_frame, bg='#12181f')
            btn_row.pack(fill='x', padx=8, pady=(2, 6))

            def _clear_all():
                try:
                    import json as _j
                    from pathlib import Path as _P
                    _p = _P.home() / ".ai-prowler" / "pending_tasks.json"
                    _tasks = _j.loads(_p.read_text(encoding="utf-8")) if _p.exists() else []
                    _tasks = [x for x in _tasks if x.get("status") != "pending"]
                    _p.write_text(_j.dumps(_tasks, indent=2), encoding="utf-8")
                except Exception:
                    pass
                _refresh_queue_list()
                _refresh_queue_count()

            tk.Button(btn_row, text="🗑 Clear Queue",
                      bg='#2a1a1a', fg='#cc4444',
                      font=('Arial', 8), relief='flat', cursor='hand2',
                      command=_clear_all).pack(side='right')

        def _toggle_queue():
            _queue_expanded.set(not _queue_expanded.get())
            if _queue_expanded.get():
                _refresh_queue_list()
                _queue_list_frame.pack(fill='x', pady=(0, 6))
            else:
                _queue_list_frame.pack_forget()
            _refresh_queue_count()

        _queue_toggle_btn = tk.Button(
            _queue_hdr,
            textvariable=_queue_count_var,
            bg='#12181f', fg='#6a9fbf',
            font=('Arial', 8, 'bold'),
            relief='flat', cursor='hand2',
            command=_toggle_queue)
        _queue_toggle_btn.pack(side='left')

        tk.Button(_queue_hdr, text="↻",
                  bg='#12181f', fg='#4a6a82',
                  font=('Arial', 9), relief='flat', cursor='hand2',
                  command=lambda: (_refresh_queue_count(),
                                   _refresh_queue_list() if _queue_expanded.get() else None)
                  ).pack(side='right')

        # Initial count
        _refresh_queue_count()

        # ── My Custom Analyses ────────────────────────────────────────────────
        # User-defined analysis tasks with schedule, scope, and output config.

        _custom_outer = tk.Frame(query_frame, bg='#0d1a26',
                                 highlightthickness=1,
                                 highlightbackground='#1e3a52')
        _custom_outer.pack(fill='x', padx=20, pady=(0, 8))

        _custom_hdr_row = tk.Frame(_custom_outer, bg='#0d1a26')
        _custom_hdr_row.pack(fill='x', padx=12, pady=(8, 4))

        tk.Label(_custom_hdr_row,
                 text="📋  My Custom Analyses",
                 bg='#0d1a26', fg='#ffffff',
                 font=('Arial', 10, 'bold')).pack(side='left')

        _custom_count_var = tk.StringVar(value="0 / 10")
        tk.Label(_custom_hdr_row,
                 textvariable=_custom_count_var,
                 bg='#0d1a26', fg='#4a6a82',
                 font=('Arial', 8)).pack(side='right')

        # Task list container
        _custom_list_frame = tk.Frame(_custom_outer, bg='#0d1a26')
        _custom_list_frame.pack(fill='x', padx=10, pady=(0, 4))

        def _refresh_custom_list():
            """Rebuild the custom task list UI."""
            for w in _custom_list_frame.winfo_children():
                w.destroy()

            try:
                import sys as _sys, os as _os
                _app_dir = _os.path.dirname(_os.path.abspath(__file__))
                if _app_dir not in _sys.path:
                    _sys.path.insert(0, _app_dir)
                import custom_tasks_manager as _ctm
                tasks = _ctm.load_custom_tasks()
            except Exception as _e:
                tk.Label(_custom_list_frame,
                         text=f"Error loading tasks: {_e}",
                         bg='#0d1a26', fg='#cc4444',
                         font=('Arial', 8)).pack(anchor='w', padx=4)
                return

            _custom_count_var.set(f"{len(tasks)} / 10")

            if not tasks:
                tk.Label(_custom_list_frame,
                         text="No custom tasks yet. Click '+ New' to create one.",
                         bg='#0d1a26', fg='#4a6a82',
                         font=('Arial', 8)).pack(anchor='w', padx=4, pady=4)
                return

            for t in tasks:
                _draw_task_row(t, tasks, _ctm)

        def _draw_task_row(task, all_tasks, _ctm):
            """Draw one task row with Queue / Edit / Delete buttons."""
            row = tk.Frame(_custom_list_frame,
                           bg='#0d1a26',
                           highlightthickness=1,
                           highlightbackground='#1e3a52')
            row.pack(fill='x', pady=2)

            info = tk.Frame(row, bg='#0d1a26')
            info.pack(side='left', fill='both', expand=True, padx=6, pady=4)

            # Label + schedule badge
            lbl_row = tk.Frame(info, bg='#0d1a26')
            lbl_row.pack(anchor='w')
            tk.Label(lbl_row,
                     text=task.get("label", "Unnamed"),
                     bg='#0d1a26', fg='#d0e8ff',
                     font=('Arial', 9, 'bold')).pack(side='left')

            sched = task.get("schedule", "none")
            if sched != "none":
                import custom_tasks_manager as _ctm2
                badge = _ctm2.SCHEDULE_LABELS.get(sched, sched)
                tk.Label(lbl_row,
                         text=f"  {badge}",
                         bg='#0d1a26', fg='#4a8fa8',
                         font=('Arial', 7)).pack(side='left')

            # Due status
            try:
                import custom_tasks_manager as _ctm3
                status_txt = _ctm3.due_status_label(task)
            except Exception:
                status_txt = ""
            if status_txt and status_txt != "Manual only":
                color = '#cc4444' if '⚠' in status_txt else \
                        '#22c55e' if 'today' in status_txt.lower() else '#6a9fbf'
                tk.Label(info,
                         text=status_txt,
                         bg='#0d1a26', fg=color,
                         font=('Arial', 7)).pack(anchor='w')

            # Output badges
            out_txt = []
            if task.get("output_learnings", True):
                out_txt.append("💡 Learnings")
            if task.get("output_report", False):
                out_txt.append("📄 Report")
            if out_txt:
                tk.Label(info,
                         text="  ".join(out_txt),
                         bg='#0d1a26', fg='#4a6a5a',
                         font=('Arial', 7)).pack(anchor='w')

            # Action buttons
            btn_col = tk.Frame(row, bg='#0d1a26')
            btn_col.pack(side='right', padx=4, pady=4)

            def _queue_task(t=task):
                try:
                    import custom_tasks_manager as _ctmq
                    entries = _ctmq.tasks_to_queue_entries([t])
                    import json as _j
                    from pathlib import Path as _P
                    p = _P.home() / ".ai-prowler" / "pending_tasks.json"
                    existing = []
                    if p.exists():
                        try:
                            existing = _j.loads(p.read_text(encoding="utf-8"))
                            if not isinstance(existing, list):
                                existing = []
                        except Exception:
                            existing = []
                    existing.extend(entries)
                    p.write_text(_j.dumps(existing, indent=2), encoding="utf-8")

                    # Copy run command to clipboard
                    _cmd = (
                        "Call get_pending_analysis_tasks() and for each pending "
                        "task: execute the full analysis described in the prompt, "
                        "save reports and record learnings as configured, then "
                        "call complete_analysis_task(task_id, summary)."
                    )
                    self.root.clipboard_clear()
                    self.root.clipboard_append(_cmd)
                    self.root.update()
                    self.status_var.set(f"\u2705 '{t['label']}' queued \u2014 paste into Claude to run ALL tasks")
                    self.root.after(3000, lambda: self.status_var.set("Ready"))
                    _refresh_queue_count()
                    if _queue_expanded.get():
                        _refresh_queue_list()
                except Exception as _e:
                    self.status_var.set(f"Queue error: {_e}")

            tk.Button(btn_col, text="▶ Queue",
                      bg='#1a3a5a', fg='white',
                      font=('Arial', 7, 'bold'),
                      relief='flat', cursor='hand2',
                      command=_queue_task).pack(fill='x', pady=1)

            def _edit_task(t=task):
                _open_task_editor(t)

            tk.Button(btn_col, text="✎ Edit",
                      bg='#1a2a1a', fg='#88cc88',
                      font=('Arial', 7),
                      relief='flat', cursor='hand2',
                      command=_edit_task).pack(fill='x', pady=1)

            def _delete_task(t=task):
                from tkinter import messagebox as _mb
                if _mb.askyesno("Delete Task",
                                f"Delete '{t['label']}'?\nThis cannot be undone."):
                    try:
                        import custom_tasks_manager as _ctmd
                        tasks = _ctmd.load_custom_tasks()
                        _ctmd.delete_task(tasks, t["task_id"])
                        _ctmd.save_custom_tasks(tasks)
                        _refresh_custom_list()
                    except Exception as _e:
                        self.status_var.set(f"Delete error: {_e}")

            tk.Button(btn_col, text="🗑",
                      bg='#2a1a1a', fg='#cc4444',
                      font=('Arial', 7),
                      relief='flat', cursor='hand2',
                      command=_delete_task).pack(fill='x', pady=1)

        def _open_task_editor(existing_task=None):
            """Open the custom task editor dialog."""
            import custom_tasks_manager as _ctm
            import tkinter.simpledialog as _sd
            from tkinter import messagebox as _mb

            win = tk.Toplevel(self.root)
            win.title("Edit Custom Analysis" if existing_task else "New Custom Analysis")
            win.geometry("806x884")
            win.resizable(True, True)
            win.grab_set()

            # Scrollable window — all content in a canvas so nothing gets hidden
            _win_canvas = tk.Canvas(win, highlightthickness=0)
            _win_vsb    = ttk.Scrollbar(win, orient='vertical', command=_win_canvas.yview)
            _win_vsb.pack(side='right', fill='y')
            _win_canvas.pack(side='left', fill='both', expand=True)
            _win_canvas.configure(yscrollcommand=_win_vsb.set)
            pad = tk.Frame(_win_canvas, padx=16, pady=12)
            _pad_id = _win_canvas.create_window((0, 0), window=pad, anchor='nw')
            def _win_configure(e):
                _win_canvas.configure(scrollregion=_win_canvas.bbox('all'))
                _win_canvas.itemconfig(_pad_id, width=_win_canvas.winfo_width())
            pad.bind('<Configure>', _win_configure)
            def _win_mousewheel(e):
                _win_canvas.yview_scroll(int(-1*(e.delta/120)), 'units')
            _win_canvas.bind('<MouseWheel>', _win_mousewheel)
            pad.bind('<MouseWheel>', _win_mousewheel)

            # Name
            tk.Label(pad, text="Name:", font=('Arial', 9, 'bold'),
                     anchor='w').pack(anchor='w')
            name_var = tk.StringVar(value=existing_task.get("label", "") if existing_task else "")
            ttk.Entry(pad, textvariable=name_var, width=60).pack(
                fill='x', pady=(2, 8))

            # Prompt
            tk.Label(pad, text="Prompt:", font=('Arial', 9, 'bold'),
                     anchor='w').pack(anchor='w')
            tk.Label(pad, text="Describe what Claude should analyze and report on.",
                     font=('Arial', 8), fg='gray', anchor='w').pack(anchor='w')
            prompt_box = tk.Text(pad, height=6, width=60, wrap='word',
                                 font=('Arial', 9))
            prompt_box.pack(fill='x', pady=(2, 8))
            if existing_task:
                prompt_box.insert('1.0', existing_task.get("prompt", ""))

            # Scope directories
            tk.Label(pad, text="Scope directories (optional):",
                     font=('Arial', 9, 'bold'), anchor='w').pack(anchor='w')
            tk.Label(pad,
                     text="Check directories to focus analysis on. Leave all unchecked to search everything.",
                     font=('Arial', 8), fg='gray', anchor='w',
                     wraplength=728, justify='left').pack(anchor='w')

            # Scrollable scope directories — capped at 150px
            scope_outer = tk.Frame(pad, bd=1, relief='sunken')
            scope_outer.pack(fill='x', pady=(2, 8))
            scope_canvas = tk.Canvas(scope_outer, highlightthickness=0, bg='white')
            scope_vsb    = ttk.Scrollbar(scope_outer, orient='vertical',
                                         command=scope_canvas.yview)
            scope_inner  = tk.Frame(scope_canvas, bg='white')
            scope_inner_id = scope_canvas.create_window((0, 0), window=scope_inner, anchor='nw')

            def _edit_scope_configure(e):
                scope_canvas.configure(scrollregion=scope_canvas.bbox('all'))
                scope_canvas.itemconfig(scope_inner_id, width=scope_canvas.winfo_width())
            scope_inner.bind('<Configure>', _edit_scope_configure)

            scope_canvas.configure(yscrollcommand=scope_vsb.set)
            scope_vsb.pack(side='right', fill='y')
            scope_canvas.pack(side='left', fill='both', expand=False)

            def _edit_scope_mousewheel(e):
                scope_canvas.yview_scroll(int(-1 * (e.delta / 120)), 'units')
            scope_canvas.bind('<MouseWheel>', _edit_scope_mousewheel)
            scope_inner.bind('<MouseWheel>', _edit_scope_mousewheel)

            existing_scope = (existing_task.get('scope_dirs') or []) if existing_task else []
            scope_vars = {}
            # Load tracked dirs fresh (don't rely on outer-scope 'tracked' variable)
            try:
                from pathlib import Path as _Pt
                import json as _jt, os as _ot
                _df_t = _Pt.home() / '.rag_auto_update_dirs.json'
                if _df_t.exists():
                    _raw_t = _jt.loads(_df_t.read_text(encoding='utf-8'))
                    if isinstance(_raw_t, dict):
                        _dl_t = _raw_t.get('directories', [])
                        tracked = [k for k in _dl_t if isinstance(k, str) and
                                   (_ot.path.isabs(k) or k.startswith('\\\\') or k.startswith('//'))] \
                                  if isinstance(_dl_t, list) else []
                    elif isinstance(_raw_t, list):
                        tracked = [k for k in _raw_t if isinstance(k, str) and
                                   (_ot.path.isabs(k) or k.startswith('\\\\') or k.startswith('//'))] 
                    else:
                        tracked = []
                else:
                    tracked = []
            except Exception:
                tracked = []
            if tracked:
                for d in tracked:
                    var = tk.BooleanVar(value=d in existing_scope)
                    scope_vars[d] = var
                    cb = ttk.Checkbutton(scope_inner, text=d, variable=var)
                    cb.pack(anchor='w', padx=4, pady=1)
                    cb.bind('<MouseWheel>', _edit_scope_mousewheel)
                scope_canvas.update_idletasks()
                scope_canvas.configure(height=min(scope_inner.winfo_reqheight() + 4, 150))
            else:
                tk.Label(scope_inner,
                         text='No indexed directories found. Index some documents first.',
                         font=('Arial', 8), fg='gray', bg='white').pack(padx=4, pady=4)
                scope_canvas.configure(height=30)

            # Schedule
            sched_row = tk.Frame(pad)
            sched_row.pack(fill='x', pady=(0, 8))
            tk.Label(sched_row, text="Schedule:",
                     font=('Arial', 9, 'bold')).pack(side='left')
            sched_var = tk.StringVar(
                value=existing_task.get("schedule", "none") if existing_task else "none")
            sched_combo = ttk.Combobox(
                sched_row,
                textvariable=sched_var,
                values=list(_ctm.SCHEDULE_LABELS.values()),
                state='readonly', width=16)
            # Map display labels to keys
            _sched_label_to_key = {v: k for k, v in _ctm.SCHEDULE_LABELS.items()}
            if existing_task:
                sched_combo.set(
                    _ctm.SCHEDULE_LABELS.get(existing_task.get("schedule", "none"),
                                              "Manual only"))
            else:
                sched_combo.set("Manual only")
            sched_combo.pack(side='left', padx=(8, 16))

            tk.Label(sched_row, text="First due date:",
                     font=('Arial', 9, 'bold')).pack(side='left')
            due_var = tk.StringVar(
                value=existing_task.get("first_due", "") if existing_task else "")
            ttk.Entry(sched_row, textvariable=due_var, width=12).pack(
                side='left', padx=(4, 0))
            tk.Label(sched_row, text="YYYY-MM-DD",
                     font=('Arial', 7), fg='gray').pack(side='left', padx=(4, 0))

            # Output options
            tk.Label(pad, text="Output:", font=('Arial', 9, 'bold'),
                     anchor='w').pack(anchor='w')
            out_row = tk.Frame(pad)
            out_row.pack(anchor='w', pady=(2, 4))

            learn_var = tk.BooleanVar(
                value=existing_task.get("output_learnings", True) if existing_task else True)
            report_var = tk.BooleanVar(
                value=existing_task.get("output_report", False) if existing_task else False)

            ttk.Checkbutton(out_row, text="💡 Save key insights to Learnings",
                            variable=learn_var).pack(anchor='w')
            ttk.Checkbutton(out_row, text="📄 Save full analysis as Word document (.docx)",
                            variable=report_var).pack(anchor='w')

            # Report folder
            folder_frame = tk.Frame(pad)
            folder_frame.pack(fill='x', pady=(0, 8))
            tk.Label(folder_frame, text="Report folder:",
                     font=('Arial', 9, 'bold')).pack(side='left')
            folder_var = tk.StringVar(
                value=existing_task.get("report_folder",
                                        _ctm.DEFAULT_REPORT_FOLDER) if existing_task
                else _ctm.DEFAULT_REPORT_FOLDER)
            ttk.Entry(folder_frame, textvariable=folder_var, width=42).pack(
                side='left', padx=(6, 4))

            def _browse_folder():
                import tkinter.filedialog as _fd
                d = _fd.askdirectory(initialdir=folder_var.get() or str(
                    __import__('pathlib').Path.home()))
                if d:
                    folder_var.set(d)

            ttk.Button(folder_frame, text="Browse…",
                       command=_browse_folder).pack(side='left')

            # Buttons
            btn_row = tk.Frame(pad)
            btn_row.pack(fill='x', pady=(8, 0))

            def _save(queue_after=False):
                label   = name_var.get().strip()
                prompt  = prompt_box.get('1.0', 'end-1c').strip()
                scope   = [d for d, v in scope_vars.items() if v.get()]
                sched_key = _sched_label_to_key.get(sched_combo.get(), "none")
                first_due = due_var.get().strip() or None

                try:
                    import custom_tasks_manager as _ctm2
                    tasks = _ctm2.load_custom_tasks()

                    if existing_task:
                        _ctm2.update_task(
                            tasks, existing_task["task_id"],
                            label=label, prompt=prompt,
                            scope_dirs=scope,
                            schedule=sched_key,
                            first_due=first_due,
                            output_learnings=learn_var.get(),
                            output_report=report_var.get(),
                            report_folder=folder_var.get().strip()
                        )
                    else:
                        if len(tasks) >= _ctm2.MAX_CUSTOM_TASKS:
                            from tkinter import messagebox as _mb2
                            _mb2.showwarning(
                                "Limit Reached",
                                f"Maximum {_ctm2.MAX_CUSTOM_TASKS} custom tasks allowed.\n"
                                "Delete an existing task to add a new one.")
                            return
                        new_task = _ctm2.create_task(
                            label=label, prompt=prompt,
                            scope_dirs=scope,
                            schedule=sched_key,
                            first_due=first_due,
                            output_learnings=learn_var.get(),
                            output_report=report_var.get(),
                            report_folder=folder_var.get().strip()
                        )
                        tasks.append(new_task)

                    _ctm2.save_custom_tasks(tasks)
                    _refresh_custom_list()

                    if queue_after:
                        # Find the task we just saved and queue it
                        tasks_updated = _ctm2.load_custom_tasks()
                        target = tasks_updated[-1] if not existing_task else \
                            next((t for t in tasks_updated
                                  if t["task_id"] == existing_task["task_id"]), None)
                        if target:
                            entries = _ctm2.tasks_to_queue_entries([target])
                            import json as _j
                            from pathlib import Path as _P
                            p = _P.home() / ".ai-prowler" / "pending_tasks.json"
                            existing_q = []
                            if p.exists():
                                try:
                                    existing_q = _j.loads(
                                        p.read_text(encoding="utf-8"))
                                except Exception:
                                    existing_q = []
                            existing_q.extend(entries)
                            p.write_text(_j.dumps(existing_q, indent=2),
                                         encoding="utf-8")
                            _cmd = (
                                "Call get_pending_analysis_tasks() and for each "
                                "pending task: execute the full analysis, save "
                                "reports and record learnings as configured, then "
                                "call complete_analysis_task(task_id, summary)."
                            )
                            self.root.clipboard_clear()
                            self.root.clipboard_append(_cmd)
                            self.root.update()
                            self.status_var.set(
                                  f"✅ '{label}' saved & queued — paste into Claude to run ALL tasks")
                            self.root.after(3000,
                                lambda: self.status_var.set("Ready"))
                            _refresh_queue_count()

                    win.destroy()
                    self.status_var.set(f"✅ Task '{label}' saved")
                    self.root.after(2500, lambda: self.status_var.set("Ready"))

                except ValueError as _ve:
                    from tkinter import messagebox as _mb3
                    _mb3.showwarning("Validation Error", str(_ve))

            ttk.Button(btn_row, text="Cancel",
                       command=win.destroy).pack(side='left', padx=(0, 8))
            ttk.Button(btn_row, text="Save",
                       command=lambda: _save(False)).pack(side='left', padx=(0, 8))
            ttk.Button(btn_row, text="Save & Queue",
                       command=lambda: _save(True)).pack(side='left')

        # + New Custom Analysis button
        _new_btn_row = tk.Frame(_custom_outer, bg='#0d1a26')
        _new_btn_row.pack(fill='x', padx=10, pady=(0, 8))

        tk.Button(_new_btn_row,
                  text="+ New Custom Analysis",
                  bg='#1a3a2a', fg='#88cc88',
                  font=('Arial', 9, 'bold'),
                  relief='flat', cursor='hand2',
                  command=lambda: _open_task_editor(None)).pack(side='left')

        # Run Due Tasks button — auto-queues all overdue custom tasks
        def _run_due_tasks():
            try:
                import custom_tasks_manager as _ctm
                import json as _j
                from pathlib import Path as _P
                tasks = _ctm.load_custom_tasks()
                due   = _ctm.get_due_tasks(tasks)
                if not due:
                    self.status_var.set("No tasks due — nothing to queue")
                    self.root.after(2500, lambda: self.status_var.set("Ready"))
                    return
                entries = _ctm.tasks_to_queue_entries(due)
                p = _P.home() / ".ai-prowler" / "pending_tasks.json"
                existing = []
                if p.exists():
                    try:
                        existing = _j.loads(p.read_text(encoding="utf-8"))
                        if not isinstance(existing, list):
                            existing = []
                    except Exception:
                        existing = []
                existing.extend(entries)
                p.write_text(_j.dumps(existing, indent=2), encoding="utf-8")
                _cmd = (
                    "Call get_pending_analysis_tasks() and for each pending "
                    "task: execute the full analysis, save reports and record "
                    "learnings as configured, then call "
                    "complete_analysis_task(task_id, summary)."
                )
                self.root.clipboard_clear()
                self.root.clipboard_append(_cmd)
                self.root.update()
                self.status_var.set(
                  f"✅ {len(due)} due task{'s' if len(due) != 1 else ''} queued — paste into Claude to run ALL tasks")
                self.root.after(3000, lambda: self.status_var.set("Ready"))
                _refresh_queue_count()
                if _queue_expanded.get():
                    _refresh_queue_list()
            except Exception as _e:
                self.status_var.set(f"Error: {_e}")

        tk.Button(_new_btn_row,
                  text="🧠 Run Due Tasks",
                  bg='#2a1a4a', fg='#9b88ee',
                  font=('Arial', 9, 'bold'),
                  relief='flat', cursor='hand2',
                  command=_run_due_tasks).pack(side='right')

        # Initial render
        _refresh_custom_list()

        ttk.Separator(query_frame, orient='horizontal').pack(
            fill='x', padx=20, pady=(4, 6))

        # ── ⏰ Proactive Alerts section ───────────────────────────────────────
        # Background scheduler: email briefings and alerts with zero API cost.
        # Not available in server mode — suppressed by the _in_server_mode
        # guard + return at the top of create_query_tab().
        # Config lives in ~/.ai-prowler/scheduler_config.json
        # Engine runs as a daemon thread started when AI-Prowler opens.
        try:
            import scheduler_engine as _sched_eng
            import scheduler_jobs   as _sched_jobs
            _sched_available = True
        except ImportError:
            _sched_available = False

        _alerts_banner = tk.Frame(query_frame, bg='#1a2e1a',
                                  highlightthickness=1,
                                  highlightbackground='#2e5a2e')
        _alerts_banner.pack(fill='x', padx=20, pady=(0, 8))

        _al_inner = tk.Frame(_alerts_banner, bg='#1a2e1a')
        _al_inner.pack(fill='x', padx=14, pady=10)

        # ── Header row ────────────────────────────────────────────────────────
        _al_hdr = tk.Frame(_al_inner, bg='#1a2e1a')
        _al_hdr.pack(fill='x', pady=(0, 6))

        tk.Label(_al_hdr,
                 text="⏰  Proactive Alerts",
                 bg='#1a2e1a', fg='#ffffff',
                 font=('Arial', 11, 'bold'),
                 anchor='w').pack(side='left')

        _al_status_var = tk.StringVar(value="")
        _al_status_lbl = tk.Label(_al_hdr, textvariable=_al_status_var,
                                   bg='#1a2e1a', fg='#6ab86a',
                                   font=('Arial', 8), anchor='e')
        _al_status_lbl.pack(side='right')

        tk.Label(_al_inner,
                 text="Email alerts pushed to you automatically — no Claude session needed. "
                      "Zero API cost. Sends via your configured email.",
                 bg='#1a2e1a', fg='#8ab88a',
                 font=('Arial', 8),
                 wraplength=680, justify='left').pack(anchor='w', pady=(0, 8))

        if not _sched_available:
            tk.Label(_al_inner,
                     text="⚠️  scheduler_jobs.py / scheduler_engine.py not found — "
                          "copy them to the AI-Prowler install directory.",
                     bg='#1a2e1a', fg='#cc8800',
                     font=('Arial', 8)).pack(anchor='w')
        else:
            # ── Master enable + email ─────────────────────────────────────────
            _cfg_now = _sched_eng.load_config()

            _al_top = tk.Frame(_al_inner, bg='#1a2e1a')
            _al_top.pack(fill='x', pady=(0, 6))

            _sched_enabled_var = tk.BooleanVar(
                value=_cfg_now.get("enabled", False))
            ttk.Checkbutton(_al_top,
                            text="Enable proactive alerts",
                            variable=_sched_enabled_var).pack(side='left')

            tk.Label(_al_top, text="  Email:", bg='#1a2e1a',
                     fg='#cccccc', font=('Arial', 8)).pack(side='left')
            _email_var = tk.StringVar(value=_cfg_now.get("email_to", ""))
            ttk.Entry(_al_top, textvariable=_email_var,
                      width=30).pack(side='left', padx=(4, 0))

            # ── Job list ──────────────────────────────────────────────────────
            _jobs_frame = tk.Frame(_al_inner, bg='#0e1e0e',
                                   bd=1, relief='sunken')
            _jobs_frame.pack(fill='x', pady=(4, 6))

            _job_enabled_vars: dict[str, tk.BooleanVar]  = {}
            _job_time_vars:    dict[str, tk.StringVar]   = {}
            _job_days_vars:    dict[str, tk.StringVar]   = {}

            DAYS_OPTIONS = ["daily", "weekdays", "weekends",
                            "monday", "tuesday", "wednesday",
                            "thursday", "friday", "saturday", "sunday"]

            _jobs_cfg = _cfg_now.get("jobs", {})

            for _jid, _jmeta in _sched_jobs.JOB_REGISTRY.items():
                _jcfg = _jobs_cfg.get(
                    _jid, _sched_eng.default_job_config(_jid))

                # Two-line card: top row = label + controls, bottom = description
                _card = tk.Frame(_jobs_frame, bg='#0e1e0e',
                                 bd=0, relief='flat')
                _card.pack(fill='x', padx=6, pady=(4, 0))

                _row_top = tk.Frame(_card, bg='#0e1e0e')
                _row_top.pack(fill='x')

                _ev = tk.BooleanVar(value=_jcfg.get("enabled", False))
                _job_enabled_vars[_jid] = _ev
                ttk.Checkbutton(_row_top, text=_jmeta["label"],
                                variable=_ev,
                                width=24).pack(side='left')

                tk.Label(_row_top, text="Time:", bg='#0e1e0e',
                         fg='#aaaaaa', font=('Arial', 7)).pack(side='left', padx=(4, 2))
                _tv = tk.StringVar(value=_jcfg.get("time",
                                   _jmeta.get("default_time", "08:00")))
                _job_time_vars[_jid] = _tv
                ttk.Entry(_row_top, textvariable=_tv, width=9).pack(side='left')

                tk.Label(_row_top, text="  Days:", bg='#0e1e0e',
                         fg='#aaaaaa', font=('Arial', 7)).pack(side='left', padx=(4, 2))
                _dv = tk.StringVar(value=_jcfg.get("days",
                                   _jmeta.get("default_days", "daily")))
                _job_days_vars[_jid] = _dv
                ttk.Combobox(_row_top, textvariable=_dv,
                             values=DAYS_OPTIONS,
                             state='readonly', width=10).pack(side='left')

                # Last run
                _last = _sched_eng.get_last_run(_jid)
                tk.Label(_row_top, text=f"  Last: {_last}",
                         bg='#0e1e0e', fg='#6a8a6a',
                         font=('Arial', 7)).pack(side='left', padx=(6, 0))

                # ▶ Now button
                def _make_run_now(jid=_jid):
                    def _run():
                        _al_status_var.set(f"Running {jid}…")
                        self.root.update()
                        res = _sched_eng.run_job_now(jid)
                        _al_status_var.set(res[:60])
                        self.root.after(5000, lambda: _al_status_var.set(
                            "● Running" if _sched_eng.is_running() else "● Stopped"))
                    return _run
                ttk.Button(_row_top, text="▶ Now",
                           command=_make_run_now(_jid),
                           width=6).pack(side='right', padx=(0, 4))

                # Description line — explains what the job sends and when
                _desc_text = _jmeta.get("description", "")
                # Append time-format hint for interval jobs
                _t_val = _jcfg.get("time", _jmeta.get("default_time", ""))
                if _t_val.lower().startswith("every_"):
                    _desc_text += f"  ·  Time field: use every_Nh or every_Nm (e.g. every_2h, every_30m)"
                else:
                    _desc_text += f"  ·  Time field: HH:MM (24-hour)"
                tk.Label(_card,
                         text=_desc_text,
                         bg='#0e1e0e', fg='#c8d8c8',
                         font=('Arial', 9),
                         anchor='w', justify='left',
                         wraplength=900).pack(anchor='w', padx=(28, 4), pady=(0, 3))

                # Thin separator between jobs
                tk.Frame(_jobs_frame, bg='#1a2e1a', height=1).pack(
                    fill='x', padx=6)

            # ── Save + Start/Stop controls ────────────────────────────────────
            _al_btn_row = tk.Frame(_al_inner, bg='#1a2e1a')
            _al_btn_row.pack(fill='x', pady=(4, 0))

            def _save_scheduler_config():
                cfg = _sched_eng.load_config()
                cfg["enabled"]  = _sched_enabled_var.get()
                cfg["email_to"] = _email_var.get().strip()
                jobs_out = {}
                for jid in _sched_jobs.JOB_REGISTRY:
                    jobs_out[jid] = {
                        "enabled": _job_enabled_vars[jid].get(),
                        "time":    _job_time_vars[jid].get().strip(),
                        "days":    _job_days_vars[jid].get().strip(),
                    }
                cfg["jobs"] = jobs_out
                _sched_eng.save_config(cfg)
                _al_status_var.set("✅ Config saved")
                self.root.after(3000, lambda: _al_status_var.set(
                    "● Running" if _sched_eng.is_running() else "● Stopped"))
                # Start/stop engine based on enabled flag
                if cfg["enabled"] and not _sched_eng.is_running():
                    _sched_eng.start()
                elif not cfg["enabled"] and _sched_eng.is_running():
                    _sched_eng.stop()
                _refresh_engine_status()

            def _refresh_engine_status():
                if _sched_eng.is_running():
                    _al_status_var.set("● Running")
                    _al_status_lbl.config(fg='#6ab86a')
                else:
                    _al_status_var.set("● Stopped")
                    _al_status_lbl.config(fg='#aa4444')

            def _toggle_engine():
                if _sched_eng.is_running():
                    _sched_eng.stop()
                    _al_status_var.set("● Stopped")
                    _al_status_lbl.config(fg='#aa4444')
                else:
                    _save_scheduler_config()
                    _sched_eng.start()
                    _al_status_var.set("● Running")
                    _al_status_lbl.config(fg='#6ab86a')

            def _view_log():
                _log_win = tk.Toplevel(self.root)
                _log_win.title("Scheduler Log")
                _log_win.geometry("700x450")
                import tkinter.scrolledtext as _st
                _lt = _st.ScrolledText(_log_win, font=('Courier', 8),
                                       wrap='word', bg='#0e0e0e', fg='#cccccc')
                _lt.pack(fill='both', expand=True, padx=8, pady=8)
                _lt.insert('1.0', _sched_eng.get_log_tail(200))
                _lt.configure(state='disabled')

            ttk.Button(_al_btn_row, text="💾 Save Config",
                       command=_save_scheduler_config).pack(side='left', padx=(0, 6))
            ttk.Button(_al_btn_row, text="▶/■ Start/Stop",
                       command=_toggle_engine).pack(side='left', padx=(0, 6))
            ttk.Button(_al_btn_row, text="📋 View Log",
                       command=_view_log).pack(side='left')

            # Auto-start if config says enabled
            if _cfg_now.get("enabled") and not _sched_eng.is_running():
                _sched_eng.start()
            _refresh_engine_status()
        # When SUPPORT_LOCAL_HW_LLM is False, all of the input/attachment/
        # provider/answer widgets below are constructed but never packed —
        # they live in an off-screen "hidden_root" Frame. Back-end code can
        # still reference self.question_text, self.answer_output, etc. without
        # AttributeError; the user just never sees them. Flip the constant at
        # the top of this file to expose the full Q&A workflow again.
        if SUPPORT_LOCAL_HW_LLM:
            _llm_parent = query_frame
        else:
            _llm_parent = tk.Frame(query_frame)   # built but never packed

        question_frame = ttk.LabelFrame(_llm_parent, text="Your Question", padding=10)
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
        attach_lf = ttk.LabelFrame(_llm_parent,
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
        options_frame = ttk.Frame(_llm_parent)
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
        action_row = ttk.Frame(_llm_parent)
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
        progress_row = ttk.Frame(_llm_parent)
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
        self._detected_files_container = ttk.Frame(_llm_parent)
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
        ttk.Label(_llm_parent, text="Answer:").pack(anchor='w', padx=20)
        self.answer_output = scrolledtext.ScrolledText(_llm_parent, height=22,
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


    def _is_business_server_mode(self):
        """True iff runtime config.json declares edition=business AND mode=server.
        Same gate that enables the Admin tab. In the desktop GUI there is no
        per-user login — the operator running the GUI on the server box is the
        owner/admin — so this is the correct gate for owner-only server-mode
        panels such as the scope-mapping controls."""
        try:
            import json as _json
            from pathlib import Path as _Path
            p = _Path.home() / ".ai-prowler" / "config.json"
            if not p.exists():
                return False
            cfg = _json.loads(p.read_text(encoding="utf-8-sig")) or {}
            return (str(cfg.get("edition", "")).lower() == "business"
                    and str(cfg.get("mode", "")).lower() == "server")
        except Exception:
            return False

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
                                       text="Tracked Directories & Files — "
                                            "Mobile Write Zones",
                                       padding=10)
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

        # Parallel list of raw paths indexed by listbox row. Populated by
        # refresh_tracked_dirs. Used by callers (remove, update, toggle)
        # to retrieve the underlying path without parsing the prefixed
        # display string. Placeholder/error rows store None.
        self._tracked_raw_paths: list = []

        # Double-click toggles a path's write permission (Mobile Write Zones).
        self.tracked_listbox.bind(
            "<Double-Button-1>",
            lambda _e: self._toggle_writable_for_selected()
        )

        # Legend explaining the row prefixes
        legend = ttk.Label(
            tracked_frame,
            text="[W]  writable — Claude can modify files in this path "
                 "(from desktop AND mobile).      "
                 "[W*] writable in a subdirectory only — double-click to widen.      "
                 "[R]  read-only — Claude can search but not edit.      "
                 "Double-click a row to toggle.",
            font=('Arial', 8),
            foreground='gray',
            wraplength=900,
            justify='left'
        )
        legend.pack(fill='x', pady=(4, 0))

        # ── Read-scope mapping (server mode, owner-only) ───────────────────────
        # Each tracked folder maps to ONE read scope via collection_map.rules in
        # users.json. Hidden entirely outside Business server mode — there are no
        # scopes in personal/home/mobile installs.
        if self._is_business_server_mode():
            scope_frame = ttk.LabelFrame(
                tracked_frame,
                text="Read Scope — who may search this folder (server mode)",
                padding=6)
            scope_frame.pack(fill='x', pady=(8, 0))
            self._scope_status_var = tk.StringVar(
                value="Select a folder above to see or set its read scope.")
            ttk.Label(scope_frame, textvariable=self._scope_status_var,
                      font=('Arial', 8), foreground='gray',
                      wraplength=900, justify='left').pack(anchor='w')
            scope_btn_row = ttk.Frame(scope_frame)
            scope_btn_row.pack(fill='x', pady=(4, 0))
            ttk.Button(scope_btn_row, text="🎯 Set Scope for Selected Folder",
                       command=self._set_scope_for_selected).pack(side='left')
            ttk.Label(scope_btn_row,
                      text="(one scope per folder; a subfolder can add its own "
                           "rule to override the parent)",
                      font=('Arial', 8), foreground='gray').pack(
                side='left', padx=(8, 0))
            self.tracked_listbox.bind(
                "<<ListboxSelect>>",
                lambda _e: self._refresh_selected_scope_label(), add="+")

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

        self.update_selected_btn = ttk.Button(buttons_frame, text="Update Selected",
                   command=self.update_selected)
        self.update_selected_btn.pack(side='left', padx=(0, 6))

        self.update_all_btn = ttk.Button(buttons_frame, text="Update All",
                   command=self.update_all,
                   style='Accent.TButton')
        self.update_all_btn.pack(side='left')

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
    
    def _selected_tracked_path(self):
        """Raw filesystem path for the selected tracked-list row, or None."""
        try:
            sel = self.tracked_listbox.curselection()
            if not sel:
                return None
            idx = sel[0]
            if 0 <= idx < len(self._tracked_raw_paths):
                return self._tracked_raw_paths[idx]
        except Exception:
            pass
        return None

    def _known_scopes(self):
        """Scopes already in use, for the assignment dropdown: every scope held
        by any user + every scope already mapped by a rule, plus 'shared'."""
        data = self._admin_load_users()
        found = set()
        for u in (data.get("users") or {}).values():
            if isinstance(u, dict):
                for s in (u.get("scopes") or []):
                    if str(s).strip():
                        found.add(str(s).strip())
        cm = data.get("collection_map") or {}
        for r in (cm.get("rules") or []):
            c = r.get("collection")
            if c:
                found.add(str(c).strip())
        found.add("shared")
        return sorted(found)

    def _resolve_scope_for_path(self, path, rules=None, default=None):
        """Show what scope a folder maps to, via the SAME pure resolver the
        engine uses (scope_resolver.resolve_collection_for_path), so the GUI can
        never drift from what is enforced at query time. DISPLAY only."""
        import scope_resolver
        if rules is None:
            data = self._admin_load_users()
            mapping = data.get("collection_map") or {}
        else:
            mapping = {"rules": rules or []}
            if default is not None:
                mapping["default_collection"] = default
        return scope_resolver.resolve_collection_for_path(path, mapping)

    def _refresh_selected_scope_label(self):
        """Update the scope status line to reflect the selected folder."""
        if not hasattr(self, "_scope_status_var"):
            return
        path = self._selected_tracked_path()
        if not path:
            self._scope_status_var.set(
                "Select a folder above to see or set its read scope.")
            return
        scope = self._resolve_scope_for_path(path)
        if scope == "documents":
            # No matching rule AND no default_collection: the engine routes an
            # unclassified folder to the INDEXER'S OWN private collection, never
            # to shared. Say so plainly instead of implying a shared scope.
            self._scope_status_var.set(
                f"\u201c{path}\u201d  \u2192  no scope rule "
                f"(defaults to the indexer\u2019s private collection)")
        else:
            self._scope_status_var.set(
                f"\u201c{path}\u201d  \u2192  read scope: {scope}")

    def _set_scope_for_selected(self):
        """Owner-only (server mode): assign ONE read scope to the selected tracked
        folder by upserting an exact-prefix rule in users.json's collection_map.
        One scope per folder by design — chunks live in one physical ChromaDB
        collection; a subfolder may add its own rule to override the parent."""
        import tkinter as tk
        from tkinter import ttk, messagebox

        path = self._selected_tracked_path()
        if not path:
            messagebox.showinfo("No folder selected",
                                "Select a tracked folder in the list above first.")
            return

        data = self._admin_load_users()
        cm = data.get("collection_map")
        if not isinstance(cm, dict):
            cm = {"rules": [], "default_collection": "shared"}
        rules = cm.get("rules")
        if not isinstance(rules, list):
            rules = []

        current = self._resolve_scope_for_path(
            path, rules, cm.get("default_collection", "shared"))
        options = self._known_scopes()

        dlg = tk.Toplevel(self.root)
        dlg.title("Set Read Scope")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill='both', expand=True)

        ttk.Label(frm, text="Folder:").grid(row=0, column=0, sticky='ne', padx=6, pady=4)
        ttk.Label(frm, text=str(path), font=('Courier', 8), wraplength=420,
                  justify='left').grid(row=0, column=1, sticky='w', padx=6, pady=4)

        ttk.Label(frm, text="Read scope:").grid(row=1, column=0, sticky='e', padx=6, pady=4)
        scope_var = tk.StringVar(value=current or "shared")
        ttk.Combobox(frm, textvariable=scope_var, width=34,
                     values=options).grid(row=1, column=1, sticky='w', padx=6, pady=4)
        ttk.Label(frm,
                  text="Pick an existing scope or type a new one (e.g. scope:sales).\n"
                       "Any user whose record holds this scope can search this folder.",
                  font=('Segoe UI', 8), foreground='gray').grid(
            row=2, column=1, sticky='w', padx=6)

        result = {"ok": False}

        def _save():
            new_scope = scope_var.get().strip()
            if not new_scope:
                messagebox.showwarning(
                    "Scope required",
                    "Enter a scope name or choose one from the list.")
                return
            result["ok"] = True
            result["scope"] = new_scope
            dlg.destroy()

        btns = ttk.Frame(frm)
        btns.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(btns, text="Save", command=_save,
                   style='Accent.TButton').pack(side='left', padx=4)
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side='left', padx=4)
        dlg.wait_window()

        if not result.get("ok"):
            return

        import scope_resolver
        cm["rules"] = scope_resolver.upsert_scope_rule(rules, path, result["scope"])
        cm.setdefault("default_collection", "shared")
        data["collection_map"] = cm
        self._admin_save_users(data)

        self._refresh_selected_scope_label()
        messagebox.showinfo(
            "Scope updated",
            f"This folder now maps to read scope:  {result['scope']}\n\n"
            "Already-indexed chunks stay in their old collection until you "
            "re-index — use \u201cUpdate Selected\u201d on this folder so its "
            "content moves into the new scope.")

    # ── Watchdog helpers ──────────────────────────────────────────────────────

    def _watchdog_is_running(self) -> bool:
        """Return True if file_watchdog.py daemon is currently running."""
        try:
            import file_watchdog
            return file_watchdog.is_running()
        except Exception:
            return False

    def _watchdog_refresh_status(self):
        """Update the watchdog status label, dot color, and toggle button text."""
        running = self._watchdog_is_running()
        if running:
            self._watchdog_status_var.set("Running — auto-indexing all tracked directories")
            self._watchdog_btn.config(text="Stop Watchdog")
            if hasattr(self, '_watchdog_dot_canvas'):
                self._watchdog_dot_canvas.itemconfig(
                    self._watchdog_dot, fill='#27ae60', outline='#27ae60')
        else:
            self._watchdog_status_var.set("Stopped")
            self._watchdog_btn.config(text="Start Watchdog")
            if hasattr(self, '_watchdog_dot_canvas'):
                self._watchdog_dot_canvas.itemconfig(
                    self._watchdog_dot, fill='#e74c3c', outline='#e74c3c')

    def _watchdog_auto_refresh(self):
        """Auto-refresh the watchdog status every 5 seconds using root.after().
        Runs on the main thread so no Tkinter cross-thread issues. Stops
        automatically if the root window is destroyed."""
        try:
            self._watchdog_refresh_status()
            self.root.after(5000, self._watchdog_auto_refresh)
        except Exception:
            pass  # window destroyed — stop polling silently

    def _watchdog_toggle(self):
        """Start or stop the file watchdog daemon."""
        import subprocess, sys as _sys
        watchdog_script = Path(__file__).parent / "file_watchdog.py"

        if self._watchdog_is_running():
            # ── Stop ──────────────────────────────────────────────────────────
            try:
                import file_watchdog
                ok, msg = file_watchdog.stop_daemon()
                if ok:
                    messagebox.showinfo("Watchdog", "File watchdog stopped.")
                else:
                    messagebox.showwarning("Watchdog", msg)
            except Exception as exc:
                messagebox.showerror("Watchdog", f"Could not stop watchdog:\n{exc}")
        else:
            # ── Start — check watchdog package is installed first ─────────────
            try:
                import watchdog  # noqa: F401
            except ImportError:
                answer = messagebox.askyesno(
                    "Install required",
                    "The 'watchdog' package is not installed.\n\n"
                    "Install it now?  (pip install watchdog)"
                )
                if not answer:
                    return
                result = subprocess.run(
                    [_sys.executable, "-m", "pip", "install", "watchdog",
                     "--break-system-packages"],
                    capture_output=True, text=True
                )
                if result.returncode != 0:
                    messagebox.showerror(
                        "Install failed",
                        f"pip install watchdog failed:\n\n{result.stderr}"
                    )
                    return
                messagebox.showinfo("Installed", "watchdog installed successfully.")

            # ── Launch daemon as a detached background process ────────────────
            try:
                # Always use python.exe not pythonw.exe — pythonw suppresses
                # stdout/stderr which breaks the watchdog's logging entirely.
                import re as _re
                py_exe = _sys.executable
                if _sys.platform == 'win32':
                    py_exe = _re.sub(r'(?i)pythonw\.exe$', 'python.exe', py_exe)

                subprocess.Popen(
                    [py_exe, str(watchdog_script)],
                    creationflags=subprocess.DETACHED_PROCESS
                    | subprocess.CREATE_NEW_PROCESS_GROUP,
                )
                # Poll for PID file in a background thread so the main thread
                # (and Tkinter) stays responsive. The thread calls back to the
                # main thread via root.after() for any messagebox calls —
                # messagebox MUST run on the main thread or Tkinter raises
                # "<class 'tkinter.messagebox.Message'> returned a result with
                # an exception set". On CPU-only machines startup takes 3-5s.
                import threading as _threading
                import time as _time

                def _poll_and_notify():
                    started = False
                    for _ in range(16):      # 16 × 0.5s = 8s max wait
                        _time.sleep(0.5)
                        if self._watchdog_is_running():
                            started = True
                            break
                    if started:
                        # No popup — the LED flipping green is confirmation enough
                        self.root.after(0, self._watchdog_refresh_status)
                    else:
                        self.root.after(0, lambda: (
                            messagebox.showwarning(
                                "Watchdog",
                                "Watchdog may not have started correctly.\n"
                                "Check: ~/AI-Prowler/logs/file_watchdog.log"
                            ),
                            self._watchdog_refresh_status()
                        ))

                _threading.Thread(target=_poll_and_notify, daemon=True).start()
                return   # status refresh happens inside the thread callback
            except Exception as exc:
                messagebox.showerror("Watchdog", f"Could not start watchdog:\n{exc}")

        self._watchdog_refresh_status()

    # ── Tab builder ───────────────────────────────────────────────────────────

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

        # ── File Watchdog section (always-on real-time indexing) ──────────────
        watchdog_frame = ttk.LabelFrame(f, text="🐾  File Watchdog — Real-Time Auto-Index",
                                        padding=15)
        watchdog_frame.pack(fill=tk.X, padx=40, pady=(0, 16))

        ttk.Label(watchdog_frame,
                  text="Watches all tracked directories continuously. "
                       "Any file added or changed is indexed automatically within a few seconds.",
                  font=('Arial', 9), foreground='#444', wraplength=620,
                  justify='left').pack(anchor='w', pady=(0, 8))

        self._watchdog_status_var = tk.StringVar(value="Checking...")
        self._watchdog_dot_var    = tk.StringVar(value="⬤")

        status_row = ttk.Frame(watchdog_frame)
        status_row.pack(anchor='w', pady=(0, 8))

        # Colored dot — Canvas oval matches the MCP dot style used elsewhere
        self._watchdog_dot_canvas = tk.Canvas(
            status_row, width=12, height=12,
            highlightthickness=0, bg=self.root.cget('bg')
        )
        self._watchdog_dot_canvas.pack(side='left', padx=(0, 6))
        self._watchdog_dot = self._watchdog_dot_canvas.create_oval(
            1, 1, 11, 11, fill='#aaaaaa', outline='#888888', width=1
        )

        ttk.Label(status_row, textvariable=self._watchdog_status_var,
                  font=('Arial', 10, 'bold')).pack(side='left')

        btn_row = ttk.Frame(watchdog_frame)
        btn_row.pack(anchor='w')
        self._watchdog_btn = ttk.Button(btn_row, text="Start Watchdog",
                                        command=self._watchdog_toggle,
                                        style='Accent.TButton')
        self._watchdog_btn.pack(side='left', padx=(0, 8))

        ttk.Label(watchdog_frame,
                  text="Log: ~/AI-Prowler/logs/file_watchdog.log",
                  font=('Arial', 8), foreground='gray').pack(anchor='w', pady=(6, 0))

        # Populate status immediately then auto-refresh every 5 seconds
        self._watchdog_refresh_status()
        self._watchdog_auto_refresh()

        # ── Current schedule status ───────────────────────────────────────────
        current_frame = ttk.LabelFrame(f, text="Current Schedule", padding=15)
        current_frame.pack(fill=tk.X, padx=40, pady=(0, 10))

        sched_dot_row = ttk.Frame(current_frame)
        sched_dot_row.pack(anchor='w', pady=(0, 4))
        self._sched_dot_canvas = tk.Canvas(
            sched_dot_row, width=12, height=12,
            highlightthickness=0, bg=self.root.cget('bg')
        )
        self._sched_dot_canvas.pack(side='left', padx=(0, 6))
        self._sched_dot = self._sched_dot_canvas.create_oval(
            1, 1, 11, 11, fill='#aaaaaa', outline='#888888', width=1
        )
        self._sched_active_var = tk.StringVar(value="Checking...")
        ttk.Label(sched_dot_row, textvariable=self._sched_active_var,
                  font=('Arial', 10, 'bold')).pack(side='left')

        self.schedule_status = tk.StringVar(value="")
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
            # Refresh the batch script content from the current tracked list
            generate_auto_update_script()
            
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
                    f"  Task status:   {status}\n"
                    f"  Last run:      {last_run}\n"
                    f"  Next run:      {next_run}\n"
                    f"  {app_line}"
                )
                if hasattr(self, '_sched_dot_canvas'):
                    self._sched_active_var.set("Schedule Active")
                    self._sched_dot_canvas.itemconfig(
                        self._sched_dot, fill='#27ae60', outline='#27ae60')
            else:
                app_last = getattr(self, '_last_index_time', None)
                app_line = (f"AI Prowler last indexed:  {app_last}"
                            if app_last else
                            "AI Prowler last indexed:  not yet this session")
                self.schedule_status.set(
                    f"  Use Schedule Setup above to create one.\n"
                    f"  {app_line}"
                )
                if hasattr(self, '_sched_dot_canvas'):
                    self._sched_active_var.set("No Schedule Set")
                    self._sched_dot_canvas.itemconfig(
                        self._sched_dot, fill='#e74c3c', outline='#e74c3c')
        except Exception as e:
            self.schedule_status.set(f"Error checking status: {str(e)}")
            if hasattr(self, '_sched_dot_canvas'):
                self._sched_active_var.set("Error")
                self._sched_dot_canvas.itemconfig(
                    self._sched_dot, fill='#f5a623', outline='#f5a623')
    
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

        # Resolve server-mode flag once at the top of the function so it is
        # available everywhere in create_settings_tab() regardless of order.
        _settings_is_server_mode = self._is_business_server_mode()

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

        # ── Owner Name (personal mode only) ──────────────────────────────────
        # Shown as the `source` field in learnings recorded by the owner on a
        # personal install. In server mode each user's identity comes from their
        # bearer token (set in the Admin tab) — this panel is not needed there.
        if not _settings_is_server_mode:
            owner_frame = ttk.LabelFrame(scrollable_frame, text="👤 Owner Name", padding=10)
            owner_frame.pack(fill='x', padx=20, pady=(0, 10))

            ttk.Label(owner_frame,
                      text="Your name as it will appear in the Learnings tab Source column "
                           "when you record a learning on a personal install.",
                      font=('Arial', 9), foreground='gray', wraplength=600,
                      justify='left').pack(anchor='w', pady=(0, 6))

            _owner_row = ttk.Frame(owner_frame)
            _owner_row.pack(fill='x')
            ttk.Label(_owner_row, text="Full name:").pack(side='left', padx=(0, 6))

            _owner_name_var = tk.StringVar(
                value=_rag_engine.OWNER_NAME if RAG_AVAILABLE else "")
            _owner_entry = ttk.Entry(_owner_row, textvariable=_owner_name_var, width=30)
            _owner_entry.pack(side='left')

            def _save_owner_name():
                name = _owner_name_var.get().strip()
                if RAG_AVAILABLE:
                    _rag_engine.OWNER_NAME = name
                    save_config(owner_name=name)
                self.status_var.set(
                    f"✅ Owner name saved: '{name}'" if name else "✅ Owner name cleared")
                self.root.after(3000, lambda: self.status_var.set("Ready"))

            ttk.Button(_owner_row, text="💾 Save",
                       command=_save_owner_name).pack(side='left', padx=(8, 0))
            ttk.Label(owner_frame,
                      text="Leave blank to show 'operator' in the Source column instead.",
                      font=('Arial', 8), foreground='gray').pack(anchor='w', pady=(4, 0))

        # ── Visibility-controlled parent frames ──────────────────────────────
        # Sections that are hidden when their feature flag is off get parented
        # to a Frame that's never packed onto the canvas. The widgets are still
        # created (so callbacks, vars, and .configure() calls don't break), but
        # the user never sees them. Flip the flags at the top of this file to
        # make the sections reappear without code changes.
        _llm_settings_parent   = (scrollable_frame if SUPPORT_LOCAL_HW_LLM
                                  else tk.Frame(scrollable_frame))
        _debug_settings_parent = (scrollable_frame if DEBUG_EN
                                  else tk.Frame(scrollable_frame))

        # Model selection
        model_frame = ttk.LabelFrame(_llm_settings_parent, text="AI Model", padding=10)
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
        ext_frame = ttk.LabelFrame(_llm_settings_parent, text="External AI APIs", padding=10)
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

        clear_only_btn = ttk.Button(db_frame, text="Clear Database only",
                                    command=self.clear_database_only_cmd)
        clear_only_btn.pack(side='left', padx=5)

        clear_full_btn = ttk.Button(db_frame, text="Clear Database + Database list",
                                    command=self.clear_database)
        clear_full_btn.pack(side='left', padx=5)

        # ── Email Configuration ────────────────────────────────────────────
        # Shown in BOTH personal and server mode, but serves different purposes:
        #
        # Personal mode: this is YOUR email account. Claude uses send_email /
        #   send_alert to send from it. configure_email() MCP tool is also
        #   available for Claude to set this from conversation.
        #
        # Server mode: this is the COMPANY'S shared SMTP account. Field crew
        #   members cannot configure email themselves (configure_email() is
        #   Tier A suppressed). All outbound email uses this account, but
        #   AI-Prowler personalises each message using the employee's name and
        #   personal email from the Admin tab:
        #     From display:  "Jake Smith via ABC Window Cleaning"
        #     Reply-To:      jake.smith@gmail.com  (from user record)
        #   So the customer's Reply goes directly to the field tech's phone.
        _email_section_title = (
            '\U0001f4e7 Email Configuration  '
            '(company SMTP — field crew identity set in Admin tab)'
            if _settings_is_server_mode else
            '\U0001f4e7 Email Configuration  '
            '(your personal SMTP — used by send_email / send_alert tools)'
        )
        email_cfg_frame = ttk.LabelFrame(
            scrollable_frame,
            text=_email_section_title,
            padding=10)
        email_cfg_frame.pack(fill='x', padx=20, pady=(0, 10))

        # Context hint — different message for each mode
        if _settings_is_server_mode:
            ttk.Label(email_cfg_frame, justify='left',
                      font=('Segoe UI', 8), foreground='gray',
                      text=(
                          "Server mode: configure the company SMTP account here.\n"
                          "Field crew send_email / send_alert use this account to send,\n"
                          "but each message is personalised with the employee's name and\n"
                          "Reply-To from their user record in the Admin tab."
                      )).grid(row=0, column=0, columnspan=3, sticky='w', padx=6, pady=(0, 6))
            _email_row_start = 1
        else:
            ttk.Label(email_cfg_frame, justify='left',
                      font=('Segoe UI', 8), foreground='gray',
                      text=(
                          "Personal mode: configure your own email account here.\n"
                          "Claude can also set this by telling it your email and app password\n"
                          "in a conversation (configure_email() MCP tool)."
                      )).grid(row=0, column=0, columnspan=3, sticky='w', padx=6, pady=(0, 6))
            _email_row_start = 1

        _ep = {'padx': 6, 'pady': 3}
        ttk.Label(email_cfg_frame, text='Your Email Address:').grid(
            row=_email_row_start+0, column=0, sticky='e', **_ep)
        _smtp_user_var = tk.StringVar()
        ttk.Entry(email_cfg_frame, textvariable=_smtp_user_var,
                  width=34).grid(row=_email_row_start+0, column=1, **_ep)
        ttk.Label(email_cfg_frame,
                  text='This is also your SMTP login',
                  font=('Segoe UI', 8)).grid(row=_email_row_start+0, column=2, sticky='w')

        ttk.Label(email_cfg_frame, text='SMTP host:').grid(
            row=_email_row_start+1, column=0, sticky='e', **_ep)
        _smtp_host_var = tk.StringVar()
        ttk.Entry(email_cfg_frame, textvariable=_smtp_host_var,
                  width=34).grid(row=_email_row_start+1, column=1, **_ep)
        ttk.Label(email_cfg_frame,
                  text='Auto-filled from your email address above',
                  font=('Segoe UI', 8)).grid(row=_email_row_start+1, column=2, sticky='w')

        ttk.Label(email_cfg_frame, text='Port:').grid(
            row=_email_row_start+2, column=0, sticky='e', **_ep)
        _smtp_port_var = tk.StringVar(value='587')
        ttk.Entry(email_cfg_frame, textvariable=_smtp_port_var,
                  width=8).grid(row=_email_row_start+2, column=1, sticky='w', **_ep)
        ttk.Label(email_cfg_frame,
                  text='587 = STARTTLS (most common)  /  465 = SMTPS',
                  font=('Segoe UI', 8)).grid(row=_email_row_start+2, column=2, sticky='w')

        ttk.Label(email_cfg_frame, text='Password:').grid(
            row=_email_row_start+3, column=0, sticky='e', **_ep)
        _smtp_pass_var = tk.StringVar()
        _smtp_pass_entry = ttk.Entry(email_cfg_frame,
                                     textvariable=_smtp_pass_var,
                                     show='\u25cf', width=34)
        _smtp_pass_entry.grid(row=_email_row_start+3, column=1, **_ep)
        _smtp_show_var = tk.BooleanVar(value=False)
        def _toggle_smtp_pass():
            _smtp_pass_entry.configure(
                show='' if _smtp_show_var.get() else '\u25cf')
        ttk.Checkbutton(email_cfg_frame, text='Show',
                        variable=_smtp_show_var,
                        command=_toggle_smtp_pass).grid(
            row=_email_row_start+3, column=2, sticky='w')

        # ── Provider info: SMTP host/port + app-password link, keyed by domain ──
        # SMTP hosts/ports verified against each provider's official docs:
        #   Gmail:    smtp.gmail.com:587 (STARTTLS) / 465 (SSL)
        #   Outlook.com: smtp-mail.outlook.com:587 (STARTTLS) — NOT smtp.outlook.com
        #   Microsoft 365: smtp.office365.com:587 (STARTTLS)
        #   Yahoo/Ymail: smtp.mail.yahoo.com:587
        #   AOL:      smtp.aol.com:587 (STARTTLS) / 465 (SSL)
        #   iCloud:   smtp.mail.me.com:587 (STARTTLS) — NOT smtp.icloud.com
        #   Zoho:     smtp.zoho.com:587 (STARTTLS) / 465 (SSL)
        #   GMX:      mail.gmx.com:587 (no app password needed as of 2026)
        #   ProtonMail: requires Proton Mail Bridge running locally; no direct
        #               public SMTP host — left without auto-fill, link only.
        _PROVIDER_INFO = {
            'gmail.com':      {'host': 'smtp.gmail.com', 'port': '587',
                                'label': 'Google App Passwords',
                                'url': 'https://myaccount.google.com/apppasswords'},
            'googlemail.com': {'host': 'smtp.gmail.com', 'port': '587',
                                'label': 'Google App Passwords',
                                'url': 'https://myaccount.google.com/apppasswords'},
            'outlook.com':    {'host': 'smtp-mail.outlook.com', 'port': '587',
                                'label': 'Microsoft App Passwords',
                                'url': 'https://account.live.com/proofs/AppPassword'},
            'hotmail.com':    {'host': 'smtp-mail.outlook.com', 'port': '587',
                                'label': 'Microsoft App Passwords',
                                'url': 'https://account.live.com/proofs/AppPassword'},
            'live.com':       {'host': 'smtp-mail.outlook.com', 'port': '587',
                                'label': 'Microsoft App Passwords',
                                'url': 'https://account.live.com/proofs/AppPassword'},
            'msn.com':        {'host': 'smtp-mail.outlook.com', 'port': '587',
                                'label': 'Microsoft App Passwords',
                                'url': 'https://account.live.com/proofs/AppPassword'},
            'office365.com':  {'host': 'smtp.office365.com', 'port': '587',
                                'label': 'Microsoft 365 Security Info',
                                'url': 'https://mysignins.microsoft.com/security-info'},
            'yahoo.com':      {'host': 'smtp.mail.yahoo.com', 'port': '587',
                                'label': 'Yahoo App Passwords',
                                'url': 'https://login.yahoo.com/account/security/app-passwords'},
            'ymail.com':      {'host': 'smtp.mail.yahoo.com', 'port': '587',
                                'label': 'Yahoo App Passwords',
                                'url': 'https://login.yahoo.com/account/security/app-passwords'},
            'aol.com':        {'host': 'smtp.aol.com', 'port': '587',
                                'label': 'AOL App Passwords',
                                'url': 'https://login.aol.com/account/security/app-passwords'},
            'icloud.com':     {'host': 'smtp.mail.me.com', 'port': '587',
                                'label': 'Apple App-Specific Passwords',
                                'url': 'https://account.apple.com/account/manage'},
            'me.com':         {'host': 'smtp.mail.me.com', 'port': '587',
                                'label': 'Apple App-Specific Passwords',
                                'url': 'https://account.apple.com/account/manage'},
            'mac.com':        {'host': 'smtp.mail.me.com', 'port': '587',
                                'label': 'Apple App-Specific Passwords',
                                'url': 'https://account.apple.com/account/manage'},
            'zoho.com':       {'host': 'smtp.zoho.com', 'port': '587',
                                'label': 'Zoho App Passwords',
                                'url': 'https://accounts.zoho.com/home#security/app-passwords'},
            'gmx.com':        {'host': 'mail.gmx.com', 'port': '587',
                                'label': 'GMX Account (no app password needed)',
                                'url': 'https://www.gmx.com/mail/'},
            'protonmail.com': {'host': '', 'port': '',
                                'label': 'ProtonMail Bridge / SMTP Setup',
                                'url': 'https://proton.me/support/smtp-submission'},
            'proton.me':      {'host': '', 'port': '',
                                'label': 'ProtonMail Bridge / SMTP Setup',
                                'url': 'https://proton.me/support/smtp-submission'},
        }
        # Back-compat alias used by the app-password link block below
        _APP_PASSWORD_LINKS = {k: (v['label'], v['url'])
                                for k, v in _PROVIDER_INFO.items()}

        _app_pw_frame = ttk.Frame(email_cfg_frame)
        _app_pw_frame.grid(row=_email_row_start+3, column=3,
                           sticky='w', padx=(10, 0))

        # Tracks whether the host/port were auto-filled by domain detection,
        # so we don't clobber a value the user deliberately typed themselves.
        _host_autofilled = {'value': True}   # True until the user edits it manually
        _port_autofilled = {'value': True}

        def _on_host_edit(*_a):
            _host_autofilled['value'] = False
        def _on_port_edit(*_a):
            _port_autofilled['value'] = False

        def _update_app_pw_link(*_args):
            email = _smtp_user_var.get().strip().lower()
            domain = email.split('@')[-1] if '@' in email else ''
            info = _PROVIDER_INFO.get(domain)

            # Auto-fill SMTP host/port — but only if the user hasn't typed
            # their own value into those fields, so we never clobber a
            # deliberate custom entry (e.g. a company's own mail server).
            if info:
                if info['host'] and _host_autofilled['value']:
                    _smtp_host_var.set(info['host'])
                if info['port'] and _port_autofilled['value']:
                    _smtp_port_var.set(info['port'])
                # Re-arm the autofill flags since the programmatic .set()
                # above also fires the trace — without this, the next
                # keystroke would look like a "manual edit" even though
                # nothing else changed.
                _host_autofilled['value'] = True
                _port_autofilled['value'] = True

            for w in _app_pw_frame.winfo_children():
                w.destroy()
            if info:
                ttk.Button(
                    _app_pw_frame,
                    text=f"🔑 Get App Password ({info['label']})",
                    command=lambda u=info['url']: webbrowser.open(u)
                ).pack(side='left')
            elif domain:
                # Unknown provider — generic guidance, no broken link
                ttk.Label(
                    _app_pw_frame,
                    text=f"Check {domain}'s account security settings\nfor an \"App Password\" option.",
                    font=('Segoe UI', 7), foreground='gray',
                    justify='left'
                ).pack(side='left')

        _smtp_user_var.trace_add('write', _update_app_pw_link)
        _smtp_host_var.trace_add('write', _on_host_edit)
        _smtp_port_var.trace_add('write', _on_port_edit)

        ttk.Label(email_cfg_frame, text='From name:').grid(
            row=_email_row_start+4, column=0, sticky='e', **_ep)
        _smtp_from_var = tk.StringVar(value='AI-Prowler')
        ttk.Entry(email_cfg_frame, textvariable=_smtp_from_var,
                  width=34).grid(row=_email_row_start+4, column=1, **_ep)

        _email_cfg_status = tk.StringVar(value='')
        ttk.Label(email_cfg_frame, textvariable=_email_cfg_status,
                  font=('Segoe UI', 9)).grid(
            row=_email_row_start+5, column=0, columnspan=3, sticky='w', padx=6, pady=(4, 0))

        def _load_smtp_cfg():
            import json as _j, base64 as _b
            p = Path.home() / '.ai-prowler' / 'email_config.json'
            if not p.exists():
                # No saved config yet (first run) — leave the autofill flags
                # armed so typing an email address fills in host/port.
                return
            try:
                d = _j.loads(p.read_text(encoding='utf-8')) or {}
                saved_host = d.get('smtp_host', '')
                saved_port = str(d.get('smtp_port', 587))
                _smtp_host_var.set(saved_host)
                _smtp_port_var.set(saved_port)
                # A non-blank saved host/port means the user (or a prior
                # auto-fill) already settled on a value — treat it as
                # "manually set" so re-typing the same email doesn't
                # silently overwrite a deliberately customised host.
                # A blank saved value (older config, or never configured)
                # leaves autofill armed so it still works for this user.
                _host_autofilled['value'] = not bool(saved_host)
                _port_autofilled['value'] = not bool(saved_port)
                _smtp_user_var.set(d.get('username', ''))
                _smtp_from_var.set(d.get('from_name', 'AI-Prowler'))
                pw = ''
                if '_password_b64' in d:
                    try:
                        pw = _b.b64decode(d['_password_b64']).decode()
                    except Exception:
                        pass
                _smtp_pass_var.set(pw)
                _email_cfg_status.set('Loaded existing config.')
            except Exception as _e:
                _email_cfg_status.set(f'Could not load config: {_e}')

        def _save_smtp_cfg():
            import json as _j, base64 as _b
            host  = _smtp_host_var.get().strip()
            port_s = _smtp_port_var.get().strip()
            user  = _smtp_user_var.get().strip()
            pw    = _smtp_pass_var.get()
            if not host or not user:
                _email_cfg_status.set('SMTP host and username are required.')
                return
            try:
                port = int(port_s)
            except ValueError:
                _email_cfg_status.set('Port must be a number.')
                return
            cfg = {
                'smtp_host':     host,
                'smtp_port':     port,
                'username':      user,
                '_password_b64': _b.b64encode(pw.encode()).decode(),
                'from_name':     _smtp_from_var.get().strip() or 'AI-Prowler',
                'use_tls':       True,
            }
            p = Path.home() / '.ai-prowler' / 'email_config.json'
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(_j.dumps(cfg, indent=2), encoding='utf-8')
            _email_cfg_status.set('Email config saved.')

        def _test_smtp_cfg():
            _email_cfg_status.set('Sending test email...')
            scrollable_frame.update_idletasks()
            ok, msg = self._admin_send_email_direct(
                _smtp_user_var.get().strip(),
                'AI-Prowler SMTP Test',
                'This is a test email from AI-Prowler. '
                'If you received this, SMTP is configured correctly.')
            _email_cfg_status.set(
                'Test email sent.' if ok else f'Test failed: {msg}')

        _load_smtp_cfg()
        _smtp_btn_row = ttk.Frame(email_cfg_frame)
        _smtp_btn_row.grid(row=_email_row_start+6, column=0, columnspan=3,
                           pady=(8, 0), sticky='w', padx=6)
        ttk.Button(_smtp_btn_row, text='\U0001f4be Save Config',
                   command=_save_smtp_cfg).pack(side='left', padx=(0, 6))
        ttk.Button(_smtp_btn_row, text='\U0001f4e7 Test Connection',
                   command=_test_smtp_cfg).pack(side='left')


        # ── SMS / Text Messaging (V8 — Multi-Provider) ───────────────────────
        # Supports Twilio, SignalWire, Vonage + WhatsApp (Twilio).
        # Credentials stored in ~/.ai-prowler/config.json.
        _sms_providers = [
            ("Twilio  (most popular — trial credit available)",  "twilio"),
            ("SignalWire  (Twilio-compatible, lower cost)",       "signalwire"),
            ("Vonage / Nexmo  (good for international SMS)",      "vonage"),
        ]
        _sms_provider_var = tk.StringVar(value='twilio')
        _sp = {'padx': 6, 'pady': 3}

        sms_frame = ttk.LabelFrame(
            scrollable_frame,
            text='📱 SMS / Text Messaging',
            padding=10)
        sms_frame.pack(fill='x', padx=20, pady=(0, 10))

        # Provider selector
        _prov_row = ttk.Frame(sms_frame)
        _prov_row.grid(row=0, column=0, columnspan=3, sticky='w', **_sp)
        ttk.Label(_prov_row, text='Provider:').pack(side='left')
        _prov_combo = ttk.Combobox(
            _prov_row, textvariable=_sms_provider_var,
            values=[p[0] for p in _sms_providers],
            state='readonly', width=46)
        _prov_combo.pack(side='left', padx=6)

        # Enable toggle
        _sms_enabled_var = tk.BooleanVar(value=False)
        _enable_row = ttk.Frame(sms_frame)
        _enable_row.grid(row=1, column=0, columnspan=3, sticky='w', **_sp)
        ttk.Checkbutton(
            _enable_row, text='Enable SMS Messaging',
            variable=_sms_enabled_var,
            command=lambda: _toggle_sms_fields(),
        ).pack(side='left')

        # Collapsible credential block
        _sms_fields_frame = ttk.Frame(sms_frame)
        _sms_fields_frame.grid(row=2, column=0, columnspan=3, sticky='w')

        # Sign-up link row
        _sms_signup_row = ttk.Frame(_sms_fields_frame)
        _sms_signup_row.grid(row=0, column=0, columnspan=3, sticky='w', pady=(4,6))
        _sms_signup_btn = ttk.Button(
            _sms_signup_row, text='🔗 Sign Up / Console',
            command=lambda: __import__('webbrowser').open(_prov_signup_url()))
        _sms_signup_btn.pack(side='left')
        _sms_signup_lbl = ttk.Label(_sms_signup_row, text='',
            font=('Segoe UI', 8), foreground='gray')
        _sms_signup_lbl.pack(side='left', padx=6)

        def _prov_id():
            sel = _sms_provider_var.get()
            for label, pid in _sms_providers:
                if sel == label: return pid
            return 'twilio'

        def _prov_signup_url():
            return {'twilio': 'https://console.twilio.com/',
                    'signalwire': 'https://signalwire.com/',
                    'vonage': 'https://dashboard.nexmo.com/sign-up',
                    }.get(_prov_id(), 'https://console.twilio.com/')

        def _prov_hint():
            return {'twilio': 'Trial credit available — phone number + usage fees apply',
                    'signalwire': 'Twilio-compatible API — typically 30–50% cheaper',
                    'vonage': 'Good for international SMS — different auth model',
                    }.get(_prov_id(), '')

        # ── Twilio fields ──────────────────────────────────────────────────
        _tw_frame = ttk.Frame(_sms_fields_frame)
        _tw_frame.grid(row=1, column=0, columnspan=3, sticky='w')

        ttk.Label(_tw_frame, text='Account SID:').grid(row=0, column=0, sticky='e', **_sp)
        _sms_sid_var = tk.StringVar()
        ttk.Entry(_tw_frame, textvariable=_sms_sid_var, width=40).grid(row=0, column=1, **_sp)
        ttk.Label(_tw_frame, text='Starts with AC…  (from Twilio console)',
                  font=('Segoe UI', 8)).grid(row=0, column=2, sticky='w')

        ttk.Label(_tw_frame, text='Auth Token:').grid(row=1, column=0, sticky='e', **_sp)
        _sms_token_var = tk.StringVar()
        _sms_token_entry = ttk.Entry(_tw_frame, textvariable=_sms_token_var, show='●', width=40)
        _sms_token_entry.grid(row=1, column=1, **_sp)
        _sms_show_token_var = tk.BooleanVar(value=False)
        def _toggle_sms_token():
            _sms_token_entry.configure(show='' if _sms_show_token_var.get() else '●')
        ttk.Checkbutton(_tw_frame, text='Show', variable=_sms_show_token_var,
                        command=_toggle_sms_token).grid(row=1, column=2, sticky='w')

        ttk.Label(_tw_frame, text='From Number:').grid(row=2, column=0, sticky='e', **_sp)
        _sms_from_var = tk.StringVar()
        ttk.Entry(_tw_frame, textvariable=_sms_from_var, width=20).grid(row=2, column=1, sticky='w', **_sp)
        ttk.Label(_tw_frame, text='Your Twilio phone number  e.g. +13865550100',
                  font=('Segoe UI', 8)).grid(row=2, column=2, sticky='w')

        _wa_enabled_var = tk.BooleanVar(value=False)
        _wa_row = ttk.Frame(_tw_frame)
        _wa_row.grid(row=3, column=0, columnspan=3, sticky='w', pady=(4,0))
        ttk.Checkbutton(_wa_row,
            text='Enable WhatsApp  (same Twilio credentials — requires WhatsApp sandbox approval)',
            variable=_wa_enabled_var,
            command=lambda: _update_webhook_url()).pack(side='left')

        # ── SignalWire fields ──────────────────────────────────────────────
        _sw_frame = ttk.Frame(_sms_fields_frame)
        _sw_frame.grid(row=1, column=0, columnspan=3, sticky='w')
        _sw_frame.grid_remove()

        _sw_fields = []
        for _r, (_lbl, _hint) in enumerate([
            ('Project ID:', 'From SignalWire dashboard → API credentials'),
            ('Auth Token:', ''),
            ('Space URL:', 'e.g.  yourspace.signalwire.com'),
            ('From Number:', 'Your SignalWire phone number  e.g. +13865550100'),
        ]):
            ttk.Label(_sw_frame, text=_lbl).grid(row=_r, column=0, sticky='e', **_sp)
            _v = tk.StringVar()
            _e = ttk.Entry(_sw_frame, textvariable=_v,
                           show=('●' if 'Token' in _lbl else ''), width=40)
            _e.grid(row=_r, column=1, sticky='w', **_sp)
            ttk.Label(_sw_frame, text=_hint, font=('Segoe UI', 8)).grid(row=_r, column=2, sticky='w')
            _sw_fields.append(_v)
        _sw_project_var, _sw_token_var, _sw_space_var, _sw_from_var = _sw_fields

        # ── Vonage fields ──────────────────────────────────────────────────
        _vn_frame = ttk.Frame(_sms_fields_frame)
        _vn_frame.grid(row=1, column=0, columnspan=3, sticky='w')
        _vn_frame.grid_remove()

        _vn_fields = []
        for _r, (_lbl, _hint) in enumerate([
            ('API Key:', '8-digit key from Vonage dashboard'),
            ('API Secret:', ''),
            ('From:', 'Phone number or alphanumeric ID  e.g. AIProwler'),
        ]):
            ttk.Label(_vn_frame, text=_lbl).grid(row=_r, column=0, sticky='e', **_sp)
            _v = tk.StringVar()
            _e = ttk.Entry(_vn_frame, textvariable=_v,
                           show=('●' if 'Secret' in _lbl else ''), width=36)
            _e.grid(row=_r, column=1, sticky='w', **_sp)
            ttk.Label(_vn_frame, text=_hint, font=('Segoe UI', 8)).grid(row=_r, column=2, sticky='w')
            _vn_fields.append(_v)
        _vn_key_var, _vn_secret_var, _vn_from_var = _vn_fields

        # ── Shared fields ──────────────────────────────────────────────────
        _shared_frame = ttk.Frame(_sms_fields_frame)
        _shared_frame.grid(row=2, column=0, columnspan=3, sticky='w', pady=(8,0))

        ttk.Label(_shared_frame, text='Test recipient:').grid(row=0, column=0, sticky='e', **_sp)
        _sms_test_to_var = tk.StringVar()
        ttk.Entry(_shared_frame, textvariable=_sms_test_to_var, width=20).grid(row=0, column=1, sticky='w', **_sp)
        ttk.Label(_shared_frame, text='Your phone number to receive the test message',
                  font=('Segoe UI', 8)).grid(row=0, column=2, sticky='w')

        ttk.Label(_shared_frame, text='Callback signature:').grid(row=1, column=0, sticky='e', **_sp)
        _sms_sig_var = tk.StringVar()
        ttk.Entry(_shared_frame, textvariable=_sms_sig_var, width=40).grid(row=1, column=1, **_sp)
        ttk.Label(_shared_frame, text='Appended to every SMS so customers know your real number',
                  font=('Segoe UI', 8)).grid(row=1, column=2, sticky='w')
        ttk.Label(_shared_frame, text='e.g.  — Call/text Dave back: 386-555-0100',
                  font=('Segoe UI', 7), foreground='gray').grid(row=2, column=1, sticky='w', padx=6)

        # ── Webhook URL display ────────────────────────────────────────────
        _wh_lf = ttk.LabelFrame(_sms_fields_frame, text=' Inbound Webhook URL ', padding=(6,4))
        _wh_lf.grid(row=3, column=0, columnspan=3, sticky='w', pady=(10,0), padx=6)
        ttk.Label(_wh_lf, justify='left', font=('Segoe UI', 8), foreground='gray',
                  text=(
                      'Paste this URL into your SMS provider console so inbound\n'
                      'messages are delivered to AI-Prowler instantly (no API polling).\n'
                      'Twilio/SignalWire: Phone Numbers → Configure → \'A message comes in\'\n'
                      'WhatsApp: Twilio Console → Messaging → Try WhatsApp → Sandbox Settings'
                  )).pack(anchor='w')
        _wh_url_row = ttk.Frame(_wh_lf)
        _wh_url_row.pack(fill='x', pady=(4,0))
        _wh_url_var = tk.StringVar(value='Start the remote server to see your webhook URL')
        ttk.Entry(_wh_url_row, textvariable=_wh_url_var, state='readonly', width=56).pack(side='left')

        def _copy_webhook_url():
            sms_frame.clipboard_clear()
            sms_frame.clipboard_append(_wh_url_var.get())
            _sms_status_var.set('Webhook URL copied to clipboard.')
        ttk.Button(_wh_url_row, text='Copy', command=_copy_webhook_url).pack(side='left', padx=(6,0))

        def _update_webhook_url(*_):
            try:
                import json as _j
                p = Path.home() / '.ai-prowler' / 'config.json'
                cfg = _j.loads(p.read_text(encoding='utf-8')) if p.exists() else {}
                base = cfg.get('public_base', '').rstrip('/')
                if base:
                    path = '/whatsapp-webhook' if (_prov_id() == 'twilio' and _wa_enabled_var.get()) else '/sms-webhook'
                    _wh_url_var.set(f'{base}{path}')
                else:
                    _wh_url_var.set('Start the remote server to see your webhook URL')
            except Exception:
                _wh_url_var.set('Start the remote server to see your webhook URL')

        _sms_status_var = tk.StringVar(value='')
        ttk.Label(_sms_fields_frame, textvariable=_sms_status_var,
                  font=('Segoe UI', 9)).grid(row=4, column=0, columnspan=3, sticky='w', padx=6, pady=(4,0))

        def _on_provider_change(*_):
            pid = _prov_id()
            for f in (_tw_frame, _sw_frame, _vn_frame): f.grid_remove()
            {'twilio': _tw_frame, 'signalwire': _sw_frame, 'vonage': _vn_frame}.get(pid, _tw_frame).grid()
            _sms_signup_lbl.config(text=_prov_hint())
            _update_webhook_url()

        _prov_combo.bind('<<ComboboxSelected>>', _on_provider_change)

        def _toggle_sms_fields():
            if _sms_enabled_var.get():
                _sms_fields_frame.grid()
                _on_provider_change()
            else:
                _sms_fields_frame.grid_remove()

        def _load_sms_cfg():
            import json as _j
            p = Path.home() / '.ai-prowler' / 'config.json'
            if not p.exists(): _toggle_sms_fields(); return
            try:
                d = _j.loads(p.read_text(encoding='utf-8')) or {}
                pid = d.get('sms_provider', 'twilio').lower()
                for label, _pid in _sms_providers:
                    if _pid == pid: _sms_provider_var.set(label); break
                if pid in ('twilio', ''):
                    sid = d.get('twilio_account_sid', '')
                    if sid: _sms_enabled_var.set(True)
                    _sms_sid_var.set(sid)
                    _sms_token_var.set(d.get('twilio_auth_token', ''))
                    _sms_from_var.set(d.get('twilio_from_number', ''))
                    _wa_enabled_var.set(bool(d.get('whatsapp_enabled', False)))
                elif pid == 'signalwire':
                    proj = d.get('signalwire_project_id', '')
                    if proj: _sms_enabled_var.set(True)
                    _sw_project_var.set(proj)
                    _sw_token_var.set(d.get('signalwire_auth_token', ''))
                    _sw_space_var.set(d.get('signalwire_space_url', ''))
                    _sw_from_var.set(d.get('signalwire_from_number', ''))
                elif pid == 'vonage':
                    key = d.get('vonage_api_key', '')
                    if key: _sms_enabled_var.set(True)
                    _vn_key_var.set(key)
                    _vn_secret_var.set(d.get('vonage_api_secret', ''))
                    _vn_from_var.set(d.get('vonage_from_number', ''))
                _sms_sig_var.set(d.get('sms_callback_signature', ''))
                if _sms_enabled_var.get(): _sms_status_var.set(f'Loaded {pid.title()} config.')
            except Exception as _e:
                _sms_status_var.set(f'Could not load config: {_e}')
            _toggle_sms_fields()

        def _save_sms_cfg():
            import json as _j
            pid = _prov_id()
            p = Path.home() / '.ai-prowler' / 'config.json'
            p.parent.mkdir(parents=True, exist_ok=True)
            try: existing = _j.loads(p.read_text(encoding='utf-8')) if p.exists() else {}
            except Exception: existing = {}
            for k in ('twilio_account_sid','twilio_auth_token','twilio_from_number',
                      'twilio_sms_enabled','whatsapp_enabled',
                      'signalwire_project_id','signalwire_auth_token',
                      'signalwire_space_url','signalwire_from_number',
                      'vonage_api_key','vonage_api_secret','vonage_from_number',
                      'sms_provider','sms_callback_signature'):
                existing.pop(k, None)
            if _sms_enabled_var.get():
                existing['sms_provider'] = pid
                existing['sms_callback_signature'] = _sms_sig_var.get().strip()
                if pid == 'twilio':
                    sid=_sms_sid_var.get().strip(); tok=_sms_token_var.get().strip(); frm=_sms_from_var.get().strip()
                    if not (sid and tok and frm): _sms_status_var.set('Account SID, Auth Token, and From Number are required.'); return
                    if not sid.startswith('AC'): _sms_status_var.set('Account SID must start with "AC".'); return
                    if not frm.startswith('+'): frm='+1'+frm.replace('-','').replace(' ',''); _sms_from_var.set(frm)
                    existing.update({'twilio_account_sid':sid,'twilio_auth_token':tok,'twilio_from_number':frm,
                                     'twilio_sms_enabled':True,'whatsapp_enabled':_wa_enabled_var.get()})
                elif pid == 'signalwire':
                    proj=_sw_project_var.get().strip(); tok=_sw_token_var.get().strip()
                    sp=_sw_space_var.get().strip(); frm=_sw_from_var.get().strip()
                    if not (proj and tok and sp and frm): _sms_status_var.set('All SignalWire fields are required.'); return
                    existing.update({'signalwire_project_id':proj,'signalwire_auth_token':tok,
                                     'signalwire_space_url':sp,'signalwire_from_number':frm})
                elif pid == 'vonage':
                    key=_vn_key_var.get().strip(); sec=_vn_secret_var.get().strip(); frm=_vn_from_var.get().strip()
                    if not (key and sec and frm): _sms_status_var.set('API Key, Secret, and From are required.'); return
                    existing.update({'vonage_api_key':key,'vonage_api_secret':sec,'vonage_from_number':frm})
            p.write_text(_j.dumps(existing, indent=2), encoding='utf-8')
            _sms_status_var.set(f'SMS config saved ({pid.title()}).' if _sms_enabled_var.get() else 'SMS config cleared.')
            _update_webhook_url()

        def _test_sms_cfg():
            to = _sms_test_to_var.get().strip()
            if not to: _sms_status_var.set('Enter a test recipient number first.'); return
            _sms_status_var.set('Sending test SMS…'); sms_frame.update_idletasks()
            try:
                import sys as _sys
                _sys.path.insert(0, str(Path(__file__).parent))
                from sms_backends import get_sms_backend, load_sms_config
                ok, msg = get_sms_backend(load_sms_config()).send(
                    to, 'AI-Prowler SMS test — if you got this, your SMS provider is configured correctly!')
                _sms_status_var.set('✅ ' + msg if ok else msg)
            except Exception as _e:
                _sms_status_var.set(f'❌ Test failed: {_e}')

        def _clear_sms_cfg():
            if not messagebox.askyesno('Clear SMS Settings',
                    'Remove all saved SMS credentials from config.json?\n\nThis cannot be undone.'): return
            p = Path.home() / '.ai-prowler' / 'config.json'
            try:
                import json as _j
                ex = _j.loads(p.read_text(encoding='utf-8')) if p.exists() else {}
                for k in ('twilio_account_sid','twilio_auth_token','twilio_from_number',
                          'twilio_sms_enabled','whatsapp_enabled',
                          'signalwire_project_id','signalwire_auth_token',
                          'signalwire_space_url','signalwire_from_number',
                          'vonage_api_key','vonage_api_secret','vonage_from_number',
                          'sms_provider','sms_callback_signature'): ex.pop(k, None)
                p.write_text(_j.dumps(ex, indent=2), encoding='utf-8')
            except Exception as _e: _sms_status_var.set(f'❌ Could not clear: {_e}'); return
            for v in (_sms_sid_var,_sms_token_var,_sms_from_var,
                      _sw_project_var,_sw_token_var,_sw_space_var,_sw_from_var,
                      _vn_key_var,_vn_secret_var,_vn_from_var,
                      _sms_test_to_var,_sms_sig_var): v.set('')
            _sms_enabled_var.set(False); _wa_enabled_var.set(False)
            _toggle_sms_fields()
            _sms_status_var.set('✅ SMS settings cleared.')

        _load_sms_cfg()

        # Button row
        _sms_btn_row = ttk.Frame(_sms_fields_frame)
        _sms_btn_row.grid(row=5, column=0, columnspan=3, pady=(8,0), sticky='w', padx=6)
        ttk.Button(_sms_btn_row, text='💾 Save Config',
                   command=_save_sms_cfg).pack(side='left', padx=(0,6))
        ttk.Button(_sms_btn_row, text='📱 Send Test SMS',
                   command=_test_sms_cfg).pack(side='left', padx=(0,6))
        ttk.Button(_sms_btn_row, text='🗑️ Clear SMS Settings',
                   command=_clear_sms_cfg).pack(side='left')

        _on_provider_change()
        _update_webhook_url()

        # ── Query Output ──────────────────────────────────────────────────────
        output_frame = ttk.LabelFrame(_debug_settings_parent, text="Query Output", padding=(10, 6))
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
            mic_frame = ttk.LabelFrame(_llm_settings_parent, text="Microphone / Speech Input", padding=(10, 6))
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
        # Panel is constructed but NOT packed into the visible layout. All the
        # underlying logic still runs:
        #   • gpu_layers_var still drives prewarm + Ollama subprocess args
        #   • _run_gpu_detect() / _apply_gpu_settings() still callable from code
        #   • gpu_status_text receives detection output into an invisible buffer
        # To re-expose the panel, uncomment the gpu_frame.pack(...) line below.
        gpu_frame = ttk.LabelFrame(scrollable_frame, text="GPU Acceleration", padding=(10, 6))
        # gpu_frame.pack(fill='x', padx=20, pady=(5, 10))   # ← hidden from GUI (v6.0)

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
        ocr_frame = ttk.LabelFrame(_debug_settings_parent,
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
        ollama_frame = ttk.LabelFrame(_llm_settings_parent, text="Ollama Server", padding=(10, 6))
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
        mcp_frame = ttk.LabelFrame(_debug_settings_parent,
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

        # ── Keep It Running (sleep / reboot guidance) ─────────────────────────
        # Documents Bug v6.0.2 #2 (learning ec3f6feb): the MCP server goes
        # offline when the laptop sleeps. The fix is operator-side: set the
        # Windows power plan so the machine doesn't sleep when plugged in.
        # The good news (also from that learning): Windows Update auto-reboots
        # are SAFE — AI-Prowler restarts itself and reconnects the tunnel
        # automatically, so the only thing the operator has to worry about
        # is sleep, not reboots.
        # ── Detect mode once so the two sections below can gate on it ─────────
        _settings_is_server_mode = self._is_business_server_mode()

        # ── Token (personal/mobile mode only — hidden in Business server mode) ─
        # In server mode each user has their own bearer token managed via the
        # Admin tab; there is no single shared token to configure here.
        _remote_token_var = tk.StringVar()   # always created so later refs work
        if not _settings_is_server_mode:
            ttk.Label(remote_frame, text="Bearer Token  (required — you choose the value):",
                      font=('Arial', 9, 'bold')).pack(anchor='w')
            ttk.Label(remote_frame, font=('Arial', 8), foreground='gray',
                      text="Paste this token into Claude mobile's MCP config. "
                           "Anyone with this token can query your knowledge base."
                      ).pack(anchor='w', pady=(0, 4))

            token_row = ttk.Frame(remote_frame)
            token_row.pack(fill='x', pady=(0, 8))

            # Load saved token from config
            try:
                import json as _jmod
                _cfg_path = Path.home() / '.ai-prowler' / 'config.json'
                if _cfg_path.exists():
                    _cfg_data = _jmod.loads(_cfg_path.read_text(encoding='utf-8-sig'))
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
                                           "Token cannot be empty. "
                                           "Choose any string — e.g. MySecretToken123")
                    return
                try:
                    import json as _jmod
                    _cfg_p = Path.home() / '.ai-prowler' / 'config.json'
                    _cfg_p.parent.mkdir(parents=True, exist_ok=True)
                    _cfg_d = {}
                    if _cfg_p.exists():
                        try:
                            _cfg_d = _jmod.loads(_cfg_p.read_text(encoding='utf-8-sig'))
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

        # ── License Key / Parent Key ──────────────────────────────────────────
        # Personal/mobile mode: "License Key" — the single key that activates
        #   this installation's remote-access subscription.
        # Business server mode: "Parent License Key" — the server-level key
        #   that unlocks the seat pool. Individual user seats (child keys) are
        #   managed in the Admin tab, not here.
        _license_key_var = tk.StringVar()   # always created so later refs work
        if _settings_is_server_mode:
            ttk.Label(remote_frame,
                      text="Parent License Key  (server seat pool — provided by AI-Prowler):",
                      font=('Arial', 9, 'bold')).pack(anchor='w')
            ttk.Label(remote_frame, font=('Arial', 8), foreground='gray',
                      text="This is the server-level key that unlocks your seat pool. "
                           "Individual user seat keys (child keys) are assigned per-user "
                           "in the Admin tab — do not enter them here."
                      ).pack(anchor='w', pady=(0, 4))
        else:
            ttk.Label(remote_frame,
                      text="License Key  (provided by your AI-Prowler subscription):",
                      font=('Arial', 9, 'bold')).pack(anchor='w')
            ttk.Label(remote_frame, font=('Arial', 8), foreground='gray',
                      text="Enter the license key given to you by your AI-Prowler provider. "
                           "This controls remote access subscription status."
                      ).pack(anchor='w', pady=(0, 4))

        license_row = ttk.Frame(remote_frame)
        license_row.pack(fill='x', pady=(0, 8))

        # Load saved license key (same config.json key regardless of mode)
        try:
            import json as _jmod2
            _cfg_path2 = Path.home() / '.ai-prowler' / 'config.json'
            if _cfg_path2.exists():
                _cfg_data2 = _jmod2.loads(_cfg_path2.read_text(encoding='utf-8'))
                _license_key_var.set(_cfg_data2.get('license_key', ''))
        except Exception:
            pass

        _lk_entry = ttk.Entry(license_row, textvariable=_license_key_var, width=30)
        _lk_entry.pack(side='left', padx=(0, 6))

        def _save_license_key():
            lk = _license_key_var.get().strip()
            if not lk:
                messagebox.showwarning(
                    "Empty Key",
                    ("Parent License Key cannot be empty.\n"
                     "Enter the server key provided by your AI-Prowler subscription.")
                    if _settings_is_server_mode else
                    ("License key cannot be empty.\n"
                     "Enter the key provided by your AI-Prowler subscription provider."))
                return
            try:
                import json as _jmod2
                _cfg_p2 = Path.home() / '.ai-prowler' / 'config.json'
                _cfg_p2.parent.mkdir(parents=True, exist_ok=True)
                _cfg_d2 = {}
                if _cfg_p2.exists():
                    try:
                        _cfg_d2 = _jmod2.loads(_cfg_p2.read_text(encoding='utf-8-sig'))
                    except Exception:
                        pass
                _cfg_d2['license_key'] = lk
                _cfg_p2.write_text(_jmod2.dumps(_cfg_d2, indent=2), encoding='utf-8')
                self.status_var.set(
                    "✅ Parent License Key saved" if _settings_is_server_mode
                    else "✅ License key saved")
                self.root.after(3000, lambda: self.status_var.set("Ready"))
                # Re-run subscription check with new key
                self.root.after(500, _run_status_check)
            except Exception as _e:
                messagebox.showerror("Save Error", str(_e))

        ttk.Button(license_row,
                   text="💾 Save Key",
                   command=_save_license_key).pack(side='left')

        ttk.Separator(remote_frame, orient='horizontal').pack(fill='x', pady=(4, 8))

        # ── One-Button Subscribe & Activate (v8.0.0) ─────────────────────────
        # Personal/home mode only. Hidden in Business server mode.
        # Subscribe button  → opens Stripe Payment Link in the browser.
        # Activation code   → user pastes code from email, clicks Configure.
        # _activate_mobile() fetches payload from subscription worker,
        #   writes config files, and installs/restarts cloudflared service.
        if not _settings_is_server_mode:
            sub_outer = ttk.LabelFrame(remote_frame,
                                       text="Mobile Access Subscription",
                                       padding=(10, 6))
            sub_outer.pack(fill='x', pady=(0, 8))

            # ── Subscribe row ─────────────────────────────────────────────────
            sub_top_row = ttk.Frame(sub_outer)
            sub_top_row.pack(fill='x', pady=(0, 6))

            ttk.Label(sub_top_row,
                      text="New subscriber? Get your activation code:",
                      font=('Arial', 9)).pack(side='left')

            def _open_subscribe(plan):
                """Fetch a dynamic Stripe Checkout Session URL from the Worker
                and open it in the browser. Ensures allow_promotion_codes is
                always active — static Payment Links lose that setting."""
                import webbrowser, urllib.request, json as _json
                try:
                    req = urllib.request.Request(
                        f"https://api.ai-prowler.com/checkout/{plan}",
                        headers={"Accept": "application/json",
                                 "User-Agent": "AI-Prowler/8.0.0"},
                        method="GET")
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        data = _json.loads(resp.read().decode())
                    url = data.get("url", "")
                    if url:
                        webbrowser.open(url)
                    else:
                        messagebox.showerror("Subscribe",
                            "Could not get checkout URL. Please try again.")
                except Exception as ex:
                    messagebox.showerror("Subscribe",
                        f"Could not reach subscription server:\n{ex}\n\n"
                        "Check your internet connection and try again.")

            def _open_subscribe_personal():
                _open_subscribe("personal")

            def _open_subscribe_business():
                _open_subscribe("business")

            ttk.Button(sub_top_row,
                       text="🛒 Subscribe — Personal",
                       command=_open_subscribe_personal).pack(
                           side='left', padx=(12, 4))
            ttk.Button(sub_top_row,
                       text="🛒 Subscribe — Business",
                       command=_open_subscribe_business).pack(
                           side='left', padx=(0, 0))

            ttk.Separator(sub_outer, orient='horizontal').pack(
                fill='x', pady=(4, 8))

            # ── Activation code row ───────────────────────────────────────────
            ttk.Label(sub_outer,
                      text="Already subscribed? Enter your activation code:",
                      font=('Arial', 9, 'bold')).pack(anchor='w')
            ttk.Label(sub_outer, font=('Arial', 8), foreground='gray',
                      text="Check your email for a code in the format "
                           "APRO-XXXXXX-XXXXXX-XXXXXX  "
                           "then click Configure Mobile Access."
                      ).pack(anchor='w', pady=(0, 6))

            act_code_row = ttk.Frame(sub_outer)
            act_code_row.pack(fill='x', pady=(0, 4))

            _act_code_var = tk.StringVar()
            _act_code_entry = ttk.Entry(act_code_row,
                                        textvariable=_act_code_var,
                                        width=36,
                                        font=('Courier New', 10))
            _act_code_entry.pack(side='left', padx=(0, 8))
            _act_code_entry.insert(0, "APRO-")

            # Status LED (red = unconfigured, green = active)
            _sub_act_canvas = tk.Canvas(act_code_row, width=14, height=14,
                                        bg=self.root.cget('bg'),
                                        highlightthickness=0)
            _sub_act_canvas.pack(side='left', padx=(0, 4))

            # Load existing activation state to set initial LED colour
            _initial_led = 'gray'
            _initial_domain = ""
            try:
                import json as _jact
                _ra_path = Path.home() / '.ai-prowler' / 'remote_access.json'
                if _ra_path.exists():
                    _ra = _jact.loads(_ra_path.read_text(encoding='utf-8'))
                    if _ra.get('domain'):
                        _initial_led = '#22C55E'
                        _initial_domain = _ra.get('domain', '')
            except Exception:
                pass

            _sub_act_dot = _sub_act_canvas.create_oval(
                2, 2, 12, 12, fill=_initial_led, outline='')

            # Domain label (shown after successful activation)
            _act_domain_var = tk.StringVar(value=_initial_domain)
            _act_domain_lbl = ttk.Label(act_code_row,
                                        textvariable=_act_domain_var,
                                        font=('Arial', 8),
                                        foreground='#2E75B6')
            _act_domain_lbl.pack(side='left', padx=(4, 4))

            def _copy_domain():
                dom = _act_domain_var.get().strip()
                if dom:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(dom)
                    self.status_var.set("📋 Domain URL copied")
                    self.root.after(2500, lambda: self.status_var.set("Ready"))

            _copy_domain_btn = ttk.Button(act_code_row,
                                          text="📋",
                                          width=3,
                                          command=_copy_domain)
            _copy_domain_btn.pack(side='left', padx=(0, 0))
            if not _initial_domain:
                _copy_domain_btn.pack_forget()

            # ── Configure button ──────────────────────────────────────────────
            act_btn_row = ttk.Frame(sub_outer)
            act_btn_row.pack(fill='x', pady=(4, 2))

            _configure_btn = ttk.Button(act_btn_row,
                                        text="⚡ Configure Mobile Access",
                                        command=lambda: _activate_mobile())
            _configure_btn.pack(side='left', padx=(0, 10))

            _act_status_var = tk.StringVar(value="")
            _act_status_lbl = tk.Label(act_btn_row,
                                       textvariable=_act_status_var,
                                       font=('Arial', 9, 'bold'),
                                       foreground='gray',
                                       bg=self.root.cget('bg'))
            _act_status_lbl.pack(side='left')

            def _set_act_status(msg, color='gray'):
                _act_status_var.set(msg)
                _act_status_lbl.configure(foreground=color)



            # Manage Subscription link — opens the Stripe Customer Portal.
            # The SAME portal page handles cancellation, payment-method
            # updates, AND seat-quantity changes for Business plans (Stripe
            # calls this "Update quantities" in the portal config — must be
            # toggled on in the Stripe Dashboard: Settings > Billing >
            # Customer portal > Update quantities). One link covers:
            #   - Cancel subscription (no refund; access lapses over the
            #     existing 30-day grace ladder — see suspendLicense() in the
            #     Worker and _evaluate_license_grace() client-side)
            #   - Add/reduce Business seats (fires customer.subscription.
            #     updated -> updateSeatCount() in the Worker, which mints
            #     real child license keys for new seats automatically)
            #   - Update payment method, view invoice history
            #
            # Stripe's customer portal requires the CUSTOMER'S email/Stripe
            # Customer ID to open directly into THEIR subscription — there is
            # no one static URL that works for every customer. The login-link
            # flow (where the customer enters their own billing email and
            # gets a one-time passcode) is the simplest no-backend option and
            # is what's wired here. Create this link once in the Stripe
            # Dashboard (Settings > Billing > Customer portal > "Activate
            # link") and paste it below.
            # Read the Stripe Customer Portal URL from ~/.ai-prowler/config.json
            # (key: "stripe_portal_url"). Set it once via:
            #   python -c "import json,pathlib; p=pathlib.Path.home()/'.ai-prowler'/'config.json'; d=json.loads(p.read_text()); d['stripe_portal_url']='https://billing.stripe.com/p/login/YOUR_REAL_ID'; p.write_text(json.dumps(d,indent=2))"
            # or just open the file and add the key manually.
            def _load_stripe_portal_url():
                try:
                    import json as _j
                    _cfg = Path.home() / '.ai-prowler' / 'config.json'
                    if _cfg.exists():
                        return _j.loads(_cfg.read_text(encoding='utf-8')).get(
                            'stripe_portal_url', '')
                except Exception:
                    pass
                return ''
            _STRIPE_PORTAL_LOGIN_URL = _load_stripe_portal_url()

            def _open_stripe_portal():
                import webbrowser
                url = _load_stripe_portal_url()  # re-read each click so edits take effect
                if not url:
                    messagebox.showinfo(
                        "Stripe Portal Not Configured",
                        "The Stripe Customer Portal URL hasn't been saved yet.\n\n"
                        "Steps:\n"
                        "1. Stripe Dashboard → Settings → Billing → Customer portal\n"
                        "2. Click 'Activate link' and copy the URL\n"
                        "3. Add it to  ~/.ai-prowler/config.json  as:\n"
                        '   "stripe_portal_url": "https://billing.stripe.com/p/login/..."'
                        "\n\n"
                        "Also enable 'Update quantities' under Subscription management "
                        "so Business customers can add/reduce seats from this same page.")
                    return
                webbrowser.open(url)

            ttk.Button(sub_outer,
                       text="Manage Subscription →",
                       command=_open_stripe_portal).pack(
                           anchor='e', pady=(6, 0))
            ttk.Label(sub_outer, font=('Arial', 8), foreground='gray',
                      text="Cancel, update payment method, or change Business "
                           "seat count — all from one Stripe-hosted page."
                      ).pack(anchor='e')

            # ── _activate_mobile() ────────────────────────────────────────────
            def _activate_mobile():
                """
                Fetch activation payload from subscription worker,
                write config files, install cloudflared service.
                Runs the network + disk work on a background thread;
                updates the GUI via root.after() on the main thread.
                """
                code = _act_code_var.get().strip()
                if not code or code == "APRO-":
                    messagebox.showwarning(
                        "No Activation Code",
                        "Paste your activation code from the email "
                        "you received after subscribing.\n\n"
                        "Format: APRO-XXXXXX-XXXXXX-XXXXXX")
                    return

                # Quick format check before hitting the network
                try:
                    import sys as _sys
                    import os as _os
                    _app_dir = _os.path.dirname(_os.path.abspath(__file__))
                    if _app_dir not in _sys.path:
                        _sys.path.insert(0, _app_dir)
                    import subscription_client as _sc
                except ImportError as _ie:
                    messagebox.showerror(
                        "Module Error",
                        f"subscription_client.py not found.\n{_ie}\n\n"
                        "Please reinstall AI-Prowler.")
                    return

                valid, cleaned = _sc.validate_activation_code_format(code)
                if not valid:
                    messagebox.showwarning("Invalid Code Format", cleaned)
                    # Highlight entry in red briefly
                    _act_code_entry.configure(foreground='red')
                    self.root.after(2000,
                        lambda: _act_code_entry.configure(foreground=''))
                    return

                # Disable button and show progress
                _configure_btn.configure(
                    text="⏳ Configuring…", state='disabled')
                _act_status_var.set("Contacting activation server…")
                _sub_act_canvas.itemconfig(_sub_act_dot, fill='#E67E00')

                def _progress(msg):
                    """Called from background thread — schedule on main thread."""
                    self.root.after(0, lambda: _act_status_var.set(msg))

                def _worker():
                    try:
                        import mobile_activator as _ma
                        result = _ma.activate_from_code(
                            cleaned, progress_cb=_progress)

                        def _on_success():
                            _sub_act_canvas.itemconfig(
                                _sub_act_dot, fill='#22C55E')
                            _act_domain_var.set(result['domain'])
                            _copy_domain_btn.pack(side='left', padx=(0, 0))
                            _set_act_status("✅ Mobile access configured", '#22C55E')


                            _configure_btn.configure(
                                text="⚡ Configure Mobile Access",
                                state='normal')
                            # ── v8.0.0: auto-refresh all config fields ───────────────
                            _license_key_var.set(result.get('license_key', ''))
                            _tun_domain_var.set(result.get('domain', ''))
                            try:
                                import json as _jcfg_r
                                _cfgr = Path.home() / '.ai-prowler' / 'config.json'
                                if _cfgr.exists():
                                    _tok = _jcfg_r.loads(_cfgr.read_text(encoding='utf-8')).get('tunnel_token', '')
                                    if _tok:
                                        _tun_token_var.set(_tok)
                            except Exception:
                                pass
                            # ── v8.0.0: turn Connect Claude.ai button red ─────────────
                            # Alerts the user this is the next required step
                            try:
                                _connect_claude_btn.configure(
                                    background='#CC0000',
                                    foreground='white',
                                    text="📖 Connect Claude.ai  (auto) ← Click now to finish setup!")
                            except Exception:
                                pass
                            self.root.after(500, _run_status_check)
                            self.status_var.set(
                                f"✅ Mobile access activated — {result['domain']}")
                            self.root.after(
                                5000, lambda: self.status_var.set("Ready"))
                            messagebox.showinfo(
                                "Activation Successful",
                                f"Mobile access is now live!\n\n"
                                f"Domain:  {result['domain']}\n"
                                f"Plan:    {result['plan'].title()}\n"
                                f"License: {result['license_key']}\n\n"
                                "✅ Tunnel is active.\n\n"
                                "👉 Next step: click the red\n"
                                "   'Connect Claude.ai' button\n"
                                "   to add AI-Prowler to Claude.ai.")
                            _activate_tunnel()
                        self.root.after(0, _on_success)

                    except ValueError as _ve:
                        def _on_val_err(_ve=_ve):
                            _sub_act_canvas.itemconfig(
                                _sub_act_dot, fill='#CC0000')
                            _set_act_status("❌ Activation failed — see error", '#CC0000')
                            _configure_btn.configure(
                                text="⚡ Configure Mobile Access",
                                state='normal')
                            messagebox.showerror(
                                "Activation Failed", str(_ve),
                                parent=self.root)
                        self.root.after(0, _on_val_err)

                    except Exception as _ex:
                        def _on_err(_ex=_ex):
                            _sub_act_canvas.itemconfig(
                                _sub_act_dot, fill='#CC0000')
                            _set_act_status("❌ Error — check connection", '#CC0000')
                            _configure_btn.configure(
                                text="⚡ Configure Mobile Access",
                                state='normal')
                            messagebox.showerror(
                                "Activation Error",
                                f"An unexpected error occurred:\n{_ex}\n\n"
                                "Check your internet connection and try again. "
                                "If the problem persists contact support.",
                                parent=self.root)
                        self.root.after(0, _on_err)

                import threading as _th
                _th.Thread(target=_worker, daemon=True).start()


        # ── Server Mode: Subscribe + Auto-Configure (v8.1.0) ─────────────────
        # Mirrors the personal subscribe+activate flow but for business/server.
        # Shows ONLY in server mode. Hidden in personal/home mode.
        # Subscribe button  → opens Stripe Business checkout in the browser.
        # Activation code   → user pastes server code from email, clicks button.
        # _activate_server() fetches payload from subscription worker,
        #   writes config files, fills license key, installs cloudflared service.
        else:
            srv_sub_outer = ttk.LabelFrame(remote_frame,
                                           text="Business Subscription & Server Setup",
                                           padding=(10, 6))
            srv_sub_outer.pack(fill='x', pady=(0, 8))

            # ── Subscribe row ─────────────────────────────────────────────────
            srv_sub_top_row = ttk.Frame(srv_sub_outer)
            srv_sub_top_row.pack(fill='x', pady=(0, 6))

            ttk.Label(srv_sub_top_row,
                      text="New subscriber? Get your server activation code:",
                      font=('Arial', 9)).pack(side='left')

            def _open_subscribe_business_srv():
                import webbrowser, urllib.request, json as _json
                try:
                    req = urllib.request.Request(
                        "https://api.ai-prowler.com/checkout/business",
                        headers={"Accept": "application/json",
                                 "User-Agent": "AI-Prowler/8.1.0"},
                        method="GET")
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        data = _json.loads(resp.read().decode())
                    url = data.get("url", "")
                    if url:
                        webbrowser.open(url)
                    else:
                        messagebox.showerror("Subscribe",
                            "Could not get checkout URL. Please try again.")
                except Exception as ex:
                    messagebox.showerror("Subscribe",
                        f"Could not reach subscription server:\n{ex}\n\n"
                        "Check your internet connection and try again.")

            ttk.Button(srv_sub_top_row,
                       text="🛒 Subscribe — Business",
                       command=_open_subscribe_business_srv).pack(
                           side='left', padx=(12, 0))

            ttk.Separator(srv_sub_outer, orient='horizontal').pack(
                fill='x', pady=(4, 8))

            # ── Server Activation code row ────────────────────────────────────
            ttk.Label(srv_sub_outer,
                      text="Already subscribed? Enter your SERVER activation code:",
                      font=('Arial', 9, 'bold')).pack(anchor='w')
            ttk.Label(srv_sub_outer, font=('Arial', 8), foreground='gray',
                      text="Check your email for the subject "
                           "'AI-Prowler Business Server — Your Activation Code'.\n"
                           "Format: APRO-XXXXXX-XXXXXX-XXXXXX  "
                           "then click Auto-Configure Server."
                      ).pack(anchor='w', pady=(0, 6))

            srv_act_code_row = ttk.Frame(srv_sub_outer)
            srv_act_code_row.pack(fill='x', pady=(0, 4))

            _srv_act_code_var = tk.StringVar()
            _srv_act_code_entry = ttk.Entry(srv_act_code_row,
                                            textvariable=_srv_act_code_var,
                                            width=36,
                                            font=('Courier New', 10))
            _srv_act_code_entry.pack(side='left', padx=(0, 8))
            _srv_act_code_entry.insert(0, "APRO-")

            # Status LED
            _srv_act_canvas = tk.Canvas(srv_act_code_row, width=14, height=14,
                                        bg=self.root.cget('bg'),
                                        highlightthickness=0)
            _srv_act_canvas.pack(side='left', padx=(0, 4))

            # Initialise LED from saved state
            _srv_initial_led = 'gray'
            _srv_initial_domain = ""
            try:
                import json as _jsrv
                _srv_ra_path = Path.home() / '.ai-prowler' / 'remote_access.json'
                if _srv_ra_path.exists():
                    _srv_ra = _jsrv.loads(_srv_ra_path.read_text(encoding='utf-8'))
                    if _srv_ra.get('domain'):
                        _srv_initial_led = '#22C55E'
                        _srv_initial_domain = _srv_ra.get('domain', '')
            except Exception:
                pass

            _srv_act_dot = _srv_act_canvas.create_oval(
                2, 2, 12, 12, fill=_srv_initial_led, outline='')

            _srv_act_domain_var = tk.StringVar(value=_srv_initial_domain)
            _srv_act_domain_lbl = ttk.Label(srv_act_code_row,
                                            textvariable=_srv_act_domain_var,
                                            font=('Arial', 8),
                                            foreground='#2E75B6')
            _srv_act_domain_lbl.pack(side='left', padx=(4, 0))

            # ── Auto-Configure Server button ──────────────────────────────────
            srv_act_btn_row = ttk.Frame(srv_sub_outer)
            srv_act_btn_row.pack(fill='x', pady=(4, 2))

            _srv_configure_btn = ttk.Button(srv_act_btn_row,
                                            text="⚡ Auto-Configure Server",
                                            command=lambda: _activate_server())
            _srv_configure_btn.pack(side='left', padx=(0, 10))

            _srv_act_status_var = tk.StringVar(value="")
            ttk.Label(srv_act_btn_row,
                      textvariable=_srv_act_status_var,
                      font=('Arial', 8),
                      foreground='gray').pack(side='left')

            ttk.Button(srv_sub_outer,
                       text="Manage Subscription →",
                       command=lambda: _open_stripe_portal_srv()).pack(
                           anchor='e', pady=(6, 0))
            ttk.Label(srv_sub_outer, font=('Arial', 8), foreground='gray',
                      text="Cancel, update payment method, or change seat count — "
                           "all from one Stripe-hosted page."
                      ).pack(anchor='e')

            def _open_stripe_portal_srv():
                import webbrowser
                try:
                    import json as _j
                    _cfg = Path.home() / '.ai-prowler' / 'config.json'
                    url = _j.loads(_cfg.read_text(encoding='utf-8')).get(
                        'stripe_portal_url', '') if _cfg.exists() else ''
                except Exception:
                    url = ''
                if not url:
                    messagebox.showinfo("Stripe Portal Not Configured",
                        "The Stripe Customer Portal URL hasn't been saved yet.\n\n"
                        "Add it to ~/.ai-prowler/config.json as:\n"
                        '"stripe_portal_url": "https://billing.stripe.com/p/login/..."')
                    return
                webbrowser.open(url)

            # ── _activate_server() ────────────────────────────────────────────
            def _activate_server():
                """
                Same flow as _activate_mobile() (personal) but in server mode:
                  1. Validate APRO-... format
                  2. Call mobile_activator.activate_from_code() — identical worker
                  3. Auto-fill Parent License Key, domain, tunnel token fields
                  4. Install cloudflared service
                  5. Turn Connect Claude.ai button red
                """
                code = _srv_act_code_var.get().strip()
                if not code or code == "APRO-":
                    messagebox.showwarning(
                        "No Activation Code",
                        "Paste your SERVER activation code from the email "
                        "you received after subscribing.\n\n"
                        "Subject: 'AI-Prowler Business Server — Your Activation Code'\n"
                        "Format:  APRO-XXXXXX-XXXXXX-XXXXXX")
                    return

                try:
                    import sys as _sys, os as _os
                    _app_dir = _os.path.dirname(_os.path.abspath(__file__))
                    if _app_dir not in _sys.path:
                        _sys.path.insert(0, _app_dir)
                    import subscription_client as _sc
                except ImportError as _ie:
                    messagebox.showerror("Module Error",
                        f"subscription_client.py not found.\n{_ie}\n\n"
                        "Please reinstall AI-Prowler Server.")
                    return

                valid, cleaned = _sc.validate_activation_code_format(code)
                if not valid:
                    messagebox.showwarning("Invalid Code Format", cleaned)
                    _srv_act_code_entry.configure(foreground='red')
                    self.root.after(2000,
                        lambda: _srv_act_code_entry.configure(foreground=''))
                    return

                _srv_configure_btn.configure(
                    text="⏳ Configuring…", state='disabled')
                _srv_act_status_var.set("Contacting activation server…")
                _srv_act_canvas.itemconfig(_srv_act_dot, fill='#E67E00')

                def _progress(msg):
                    self.root.after(0, lambda: _srv_act_status_var.set(msg))

                def _worker():
                    try:
                        import mobile_activator as _ma
                        result = _ma.activate_from_code(
                            cleaned, progress_cb=_progress)

                        # Guard: reject a personal (AP-PERS-...) code pasted
                        # into the SERVER activation field. mobile_activator
                        # doesn't distinguish code types itself, so this is
                        # the safety net that stops a server install from
                        # silently becoming licensed as a personal seat.
                        _result_key = result.get('license_key', '')
                        if _result_key.startswith('AP-PERS-'):
                            def _on_wrong_code():
                                _srv_act_canvas.itemconfig(_srv_act_dot, fill='red')
                                _srv_act_status_var.set(
                                    "❌ That's a Personal code, not a Server code")
                                _srv_configure_btn.configure(
                                    text="⚡ Auto-Configure Server",
                                    state='normal')
                                messagebox.showerror(
                                    "Wrong Activation Code",
                                    f"The code you entered ({cleaned}) activated a "
                                    f"PERSONAL license ({_result_key}), not a Business "
                                    f"Server license.\n\n"
                                    "Check your email for the subject:\n"
                                    "  'AI-Prowler Business Server — Your Activation Code'\n\n"
                                    "That email contains the correct SERVER code — it's "
                                    "different from any 'AI-Prowler Personal' email you "
                                    "may have also received.")
                            self.root.after(0, _on_wrong_code)
                            return

                        def _on_success():
                            _srv_act_canvas.itemconfig(
                                _srv_act_dot, fill='#22C55E')
                            _srv_act_domain_var.set(result.get('domain', ''))
                            _srv_act_status_var.set("✅ Server configured")
                            _srv_configure_btn.configure(
                                text="⚡ Auto-Configure Server",
                                state='normal')
                            # Auto-fill Parent License Key, domain, tunnel token
                            _license_key_var.set(result.get('license_key', ''))
                            _tun_domain_var.set(result.get('domain', ''))
                            try:
                                import json as _jcfg
                                _cfgp = Path.home() / '.ai-prowler' / 'config.json'
                                _cfg_data = {}
                                if _cfgp.exists():
                                    _cfg_data = _jcfg.loads(
                                        _cfgp.read_text(encoding='utf-8'))
                                _tok = _cfg_data.get('tunnel_token', '')
                                if _tok:
                                    _tun_token_var.set(_tok)
                                # Persist license_key + tunnel_domain so the
                                # Admin tab and seat-lookup tools can find
                                # this server's parent license on next launch.
                                _cfg_data['license_key']   = result.get('license_key', '')
                                _cfg_data['tunnel_domain'] = result.get('domain', '')
                                _cfgp.write_text(
                                    _jcfg.dumps(_cfg_data), encoding='utf-8')
                            except Exception:
                                pass
                            self.root.after(500, _run_status_check)
                            messagebox.showinfo(
                                "Server Configured ✅",
                                f"AI-Prowler Server is ready.\n\n"
                                f"Server URL: {result.get('domain', '')}\n"
                                f"License: {result.get('license_key', '')}\n\n"
                                "✅ Tunnel is active.\n\n"
                                "👉 Next step: click '🌐 Test Server Connection'\n"
                                "   below to confirm employees can reach your\n"
                                "   server, then share the connector URL shown\n"
                                "   there with your team.\n\n"
                                "Your employees will each receive a separate email\n"
                                "with their personal AI-Prowler activation code\n"
                                "— forward those emails so they can set up their PCs.")
                        self.root.after(0, _on_success)

                    except ValueError as _ve:
                        def _on_val_err(_ve=_ve):
                            _srv_act_canvas.itemconfig(
                                _srv_act_dot, fill='red')
                            _srv_act_status_var.set(f"❌ {_ve}")
                            _srv_configure_btn.configure(
                                text="⚡ Auto-Configure Server",
                                state='normal')
                            messagebox.showerror(
                                "Activation Failed", str(_ve),
                                parent=self.root)
                        self.root.after(0, _on_val_err)
                    except Exception as _ex:
                        def _on_err(_ex=_ex):
                            _srv_act_canvas.itemconfig(
                                _srv_act_dot, fill='red')
                            _srv_act_status_var.set("❌ Configuration failed")
                            _srv_configure_btn.configure(
                                text="⚡ Auto-Configure Server",
                                state='normal')
                            messagebox.showerror(
                                "Configuration Error",
                                f"Server configuration failed:\n{_ex}\n\n"
                                "Check your internet connection and try again.\n"
                                "If the problem persists contact support.",
                                parent=self.root)
                        self.root.after(0, _on_err)


                import threading as _th2
                _th2.Thread(target=_worker, daemon=True).start()
        # ── Mobile Activation panel — REMOVED (v8.2.0) ─────────────────────────
        # The old "Check Activation" / "Transfer to This Machine" buttons
        # called the deprecated ai-prowler-telemetry Worker's
        # /license/activate + /license/release_install endpoints, which were
        # never wired to actual tunnel provisioning — a successful "transfer"
        # never gave the new machine a working tunnel_token/domain.
        #
        # One-machine-at-a-time enforcement now lives entirely in the
        # ai-prowler-subscription Worker (provision.js handleActivate +
        # handleLicenseValidate, license.active_install_id). Re-entering the
        # SAME activation code on a new machine via Configure Mobile Access
        # / Auto-Configure Server automatically transfers the binding and
        # provisions the new machine's tunnel in one step — no separate UI
        # needed. The old machine finds out it's been displaced on its next
        # periodic license validation check (displaced_to_another_device
        # flag) and the GUI surfaces that via the status banner.

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
            """Quick connectivity check -- tries to reach GitHub."""
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
        # ──────────────────────────────────────────────────────────────────────
        # v7-hook: Plan / seat-license forward-compatibility helpers
        # ──────────────────────────────────────────────────────────────────────
        # These two helpers are dormant in v6.0. They exist so that we can
        # start writing `plan`, `seats`, and `license_group` fields into
        # GitHub `subs.json` at any time WITHOUT breaking any v6.0 client.
        #
        # v6.0 behaviour:  reads the new fields, normalises them, surfaces
        #                  them on sub_result, and does NOTHING with the
        #                  values. The features-resolver returns {} so no
        #                  conditional behaviour is enabled.
        # v7.0 plan:       _resolve_plan_features grows a body that returns
        #                  the feature flags for each plan (admin tab,
        #                  multi-seat enablement, etc.). Adding that body
        #                  requires no further changes to _check_subscription_gui.
        #
        # Field semantics (when populated in subs.json):
        #   plan = "individual"      single-user license (default for v6 entries)
        #   plan = "business"        owner of a multi-seat license (Acme parent)
        #   plan = "business_seat"   one of the N employee seats under a parent
        #   seats                    integer; how many employee seats Acme has
        #                            paid for. Only meaningful when plan=business.
        #   license_group            string; ties a business owner to their N
        #                            business_seat entries (e.g. "acme-2026").
        #                            Same value on parent + all seats.
        #
        # Defaults below preserve full v6 backward compatibility: any entry
        # written before v7 launches reads as plan="individual", seats=1,
        # license_group=None, which is exactly correct for the existing
        # single-user customers.
        # ──────────────────────────────────────────────────────────────────────
        _VALID_PLANS = ("individual", "business", "business_seat")

        def _normalise_plan(raw) -> str:
            """Map any value (including missing/garbage) to a valid plan.

            v6 entries with no `plan` field default to 'individual' — the
            correct semantic for every existing customer.
            """
            if isinstance(raw, str):
                cleaned = raw.strip().lower()
                if cleaned in _VALID_PLANS:
                    return cleaned
            return "individual"

        def _resolve_plan_features(sub_result: dict) -> dict:
            """v7-hook: Map a plan to its feature flags.

            v6.0:  returns {} — no plan unlocks any features yet.
            v7.0:  will return something like:
                   { "show_rbac_tab": True,  "is_business_owner": True }
                   for plan='business', etc.

            Callers SHOULD use this rather than branching on plan directly,
            so when v7 ships there's exactly one place to add logic.
            """
            return {}

        def _check_subscription_gui(tok, subs_data) -> dict:
            """
            Returns dict with keys:
                status     'ok' | 'warning' | 'blocked' | 'unmanaged'
                name       subscriber name or None
                days_left  int or None
                message    human-readable status
                plan       v7-hook: 'individual' | 'business' | 'business_seat'
                seats      v7-hook: int, only meaningful when plan='business'
                license_group  v7-hook: str|None, ties business owners to seats
                features   v7-hook: dict of feature flags from _resolve_plan_features
            """
            if not subs_data:
                # v7-hook: even unmanaged mode carries the plan defaults
                out = {'status': 'unmanaged', 'name': None, 'days_left': None,
                       'message': 'No registry — unmanaged/local mode',
                       'plan': 'individual', 'seats': 1, 'license_group': None}
                out['features'] = _resolve_plan_features(out)
                return out
            key  = _token_key(tok)
            subs = subs_data.get('subscribers', {})
            if key not in subs:
                out = {'status': 'unmanaged', 'name': None, 'days_left': None,
                       'message': 'Token not in managed registry — local mode',
                       'plan': 'individual', 'seats': 1, 'license_group': None}
                out['features'] = _resolve_plan_features(out)
                return out
            entry    = subs[key]
            name     = entry.get('name', 'Subscriber')
            exp_str  = entry.get('expires', '')

            # v7-hook: read forward-compatible plan fields with safe defaults.
            # Any v6 entry missing these fields reads as a regular individual
            # subscription, which is correct for every existing customer.
            plan          = _normalise_plan(entry.get('plan'))
            seats         = entry.get('seats', 1)
            if not isinstance(seats, int) or seats < 1:
                seats = 1
            license_group = entry.get('license_group') or None

            try:
                import datetime as _dt
                expiry    = _dt.date.fromisoformat(exp_str)
                today     = _dt.date.today()
                days_left = (expiry - today).days
            except ValueError:
                out = {'status': 'unmanaged', 'name': name, 'days_left': None,
                       'message': f'Invalid expiry in registry for {name}',
                       'plan': plan, 'seats': seats,
                       'license_group': license_group}
                out['features'] = _resolve_plan_features(out)
                return out

            _WARN_DAYS  = 30
            _GRACE_DAYS = 30
            # Helper to build the result dict with the v7-hook fields baked in.
            # All result paths flow through this so we never forget a field.
            def _result(status, msg):
                out = {'status': status, 'name': name, 'days_left': days_left,
                       'message': msg,
                       'plan': plan, 'seats': seats,
                       'license_group': license_group}
                out['features'] = _resolve_plan_features(out)
                return out

            if days_left >= 0:
                if days_left <= _WARN_DAYS:
                    return _result('warning',
                        f"Subscription expires in {days_left} day(s) — renewal recommended")
                return _result('ok', f'Active — {days_left} day(s) remaining')
            days_over = -days_left
            if days_over <= _GRACE_DAYS:
                return _result('warning',
                    f"Subscription EXPIRED {days_over} day(s) ago — "
                    f"{_GRACE_DAYS - days_over} day(s) grace period remaining")
            return _result('blocked',
                f"Remote access BLOCKED — subscription expired "
                f"{days_over} day(s) ago and grace period has elapsed")

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

            # v7.0.0: the 2-active-install rule can disable remote access on
            # THIS machine even when the subscription itself is valid (the
            # license is in use on 2 other machines). Surface that distinctly,
            # taking precedence over the normal status, since the user's action
            # (release a machine) differs from a renewal.
            if sub_result.get('activation_rejected'):
                _sub_canvas.itemconfig(_sub_dot, fill='#d4ac0d')
                _sub_lbl.config(text='Mobile disabled — in use elsewhere',
                                foreground='#d4ac0d')
                return

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

        def _validate_license_worker(lk: str) -> dict:
            """
            Call the Subscription Worker's public /license/{key}/validate endpoint
            and translate the response into the sub_result dict shape that
            _update_sub_light() and _show_subscription_popup() expect.

            v8.0.0: replaces the old _fetch_subs_gui() / _check_subscription_gui()
            path that read from the retired GitHub subs.json registry. New Stripe
            licenses (AP-PERS-... / AP-BIZ-...) are never in subs.json, so the old
            path always returned 'unmanaged' for every new customer.

            Falls back to {'status': 'unmanaged'} on network error so the UI
            degrades gracefully (green self-hosted dot) rather than blocking.
            """
            import datetime as _dt
            try:
                import sys as _sys, os as _os
                _app_dir = _os.path.dirname(_os.path.abspath(__file__))
                if _app_dir not in _sys.path:
                    _sys.path.insert(0, _app_dir)
                import subscription_client as _sc
            except ImportError:
                return {'status': 'unmanaged', 'name': None, 'days_left': None,
                        'message': 'subscription_client.py not found — running unmanaged',
                        'plan': 'individual', 'seats': 1,
                        'license_group': None, 'features': {}}

            try:
                resp = _sc.validate_license(lk)
            except Exception as _e:
                # Worker unreachable (offline, DNS failure, etc.) — fail open
                return {'status': 'unmanaged', 'name': None, 'days_left': None,
                        'message': f'Worker unreachable — running offline ({_e})',
                        'plan': 'individual', 'seats': 1,
                        'license_group': None, 'features': {}}

            valid      = resp.get('valid', False)
            reason     = resp.get('reason', '')
            expires_at = resp.get('expires_at', '')
            edition    = resp.get('edition', 'mobile')
            plan       = 'business' if edition == 'business' else 'individual'

            # Parse days_left from the ISO expires_at the Worker returns
            days_left = None
            if expires_at:
                try:
                    expiry    = _dt.datetime.fromisoformat(
                                    expires_at.replace('Z', '+00:00'))
                    now_utc   = _dt.datetime.now(_dt.timezone.utc)
                    days_left = (expiry.date() - now_utc.date()).days
                except Exception:
                    pass

            _WARN_DAYS  = 30
            _GRACE_DAYS = 30

            if valid:
                if days_left is not None and days_left <= _WARN_DAYS:
                    status  = 'warning'
                    message = (f'Subscription expires in {days_left} day(s) '
                               f'— renewal recommended')
                else:
                    status  = 'ok'
                    d_str   = f'{days_left}d remaining' if days_left is not None else 'active'
                    message = f'Active — {d_str}'

            elif reason == 'not_found':
                status  = 'unmanaged'
                message = 'License key not found in registry — running unmanaged'

            elif reason == 'revoked':
                status  = 'blocked'
                message = 'License revoked — contact support'

            else:
                # suspended / subscription_canceled — soft fail, grace ladder applies
                if days_left is not None and days_left < 0:
                    days_over = -days_left
                    remaining = _GRACE_DAYS - days_over
                    if remaining > 0:
                        status  = 'warning'
                        message = (f'Subscription cancelled — '
                                   f'{remaining}d grace period remaining')
                    else:
                        status  = 'blocked'
                        message = 'Subscription cancelled — grace period elapsed'
                else:
                    status  = 'warning'
                    message = (f'Subscription inactive '
                               f'({reason or "suspended"}) — check billing')

            return {
                'status':        status,
                'name':          None,   # /validate doesn't expose customer name
                'days_left':     days_left,
                'message':       message,
                'plan':          plan,
                'seats':         1,
                'license_group': None,
                'features':      {},
            }

        def _run_status_check():
            """Background thread: check internet + subscription, update lights."""
            def _worker():
                online = _check_internet()
                self.root.after(0, lambda: _update_internet_light(online))
                lk = _license_key_var.get().strip()
                if lk:
                    # v8.0.0: validate against the Subscription Worker instead of
                    # the retired GitHub subs.json registry. New AP-PERS-/AP-BIZ-
                    # keys are only in the Worker's KV store, never in subs.json.
                    sub_result = _validate_license_worker(lk)
                    _current_sub_result[0] = sub_result
                    self.root.after(0, lambda: _update_sub_light(sub_result))
                else:
                    # No license key set — no subscription configured
                    self.root.after(0, lambda: (
                        _sub_canvas.itemconfig(_sub_dot, fill='#cc0000'),
                        _sub_lbl.config(text='No License Key', foreground='#cc0000')
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

        # ── Server uptime display ──────────────────────────────────────────────
        # Shows how long the HTTP server has been running, e.g. "· up 2h 15m".
        # Blank when stopped. Updates every 30 s via a self-rescheduling after().
        _http_uptime_var = tk.StringVar(value="")
        ttk.Label(http_ctrl_row, textvariable=_http_uptime_var,
                  foreground='#666666', font=('Arial', 9)).pack(side='left', padx=(0, 12))

        _http_start_time  = [None]   # [datetime | None] — set when server goes Running
        _uptime_after_id  = [None]   # [str | None]      — cancellable after() token

        def _fmt_uptime():
            """Return a compact 'up Xh Ym' string from _http_start_time[0]."""
            if _http_start_time[0] is None:
                return ""
            from datetime import datetime as _dt
            elapsed = int((_dt.now() - _http_start_time[0]).total_seconds())
            h, rem  = divmod(elapsed, 3600)
            m       = rem // 60
            if h > 0:
                return f"· up {h}h {m}m"
            elif m > 0:
                return f"· up {m}m"
            else:
                return "· up <1m"

        def _start_uptime_ticker():
            """Refresh the uptime label and reschedule itself every 30 s."""
            _http_uptime_var.set(_fmt_uptime())
            _uptime_after_id[0] = self.root.after(30_000, _start_uptime_ticker)

        def _stop_uptime_ticker():
            """Cancel the ticker and blank the uptime label."""
            if _uptime_after_id[0] is not None:
                self.root.after_cancel(_uptime_after_id[0])
                _uptime_after_id[0] = None
            _http_start_time[0] = None
            _http_uptime_var.set("")

        def _mark_server_running():
            """Record the start time and kick off the uptime ticker (once only)."""
            if _http_start_time[0] is None:   # guard: don't double-start
                _http_start_time[0] = __import__('datetime').datetime.now()
                _start_uptime_ticker()

        # ── Expose uptime internals as instance attributes for unit testing ───
        # Tests in tests/gui/test_http_uptime.py call these directly rather
        # than driving the full subprocess lifecycle.
        self._http_uptime_var      = _http_uptime_var
        self._http_start_time      = _http_start_time    # mutable [datetime|None]
        self._fmt_uptime           = _fmt_uptime
        self._mark_server_running  = _mark_server_running
        self._stop_uptime_ticker   = _stop_uptime_ticker

        def _start_http_server():
            tok = _remote_token_var.get().strip()
            # In Business server mode there is no single bearer token —
            # authentication is per-user via users.json. Skip the token
            # guard entirely; the MCP server handles auth itself.
            if not tok and not _settings_is_server_mode:
                messagebox.showwarning("No Token", "Save a Bearer token first.")
                return
            if self._http_server_proc is not None and self._http_server_proc.poll() is None:
                messagebox.showinfo("Already Running", "HTTP server is already running.")
                return

            # ── Subscription check before starting ────────────────────────────
            # Run in background to avoid freezing the UI during network check.
            # Subscription gate uses the LICENSE KEY (not bearer token).
            #   ok        → green,  start server
            #   warning   → yellow, show popup, start server (grace countdown)
            #   blocked   → red,    show popup, block server start
            #   unmanaged → green,  allow (self-hosted / no registry)
            lk = _license_key_var.get().strip()
            def _pre_start_check():
                online     = _check_internet()
                subs_data  = _fetch_subs_gui() if online else None
                sub_result = _check_subscription_gui(lk, subs_data) if lk else {
                    'status': 'unmanaged', 'name': None, 'days_left': None,
                    'message': 'No license key — self-hosted mode'}
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
                    # Force UTF-8 decoding of the subprocess's stdout. Without
                    # this, Python uses the platform default (cp1252 on
                    # Windows), which crashes _watch_http with a
                    # UnicodeDecodeError as soon as the MCP server emits any
                    # non-ASCII byte (emoji status markers, em-dashes in log
                    # text, accented characters in paths, etc.). The MCP
                    # server already configures its own stdout via
                    # _make_safe_text_stream to write UTF-8, so this matches
                    # what's actually on the pipe. errors="replace" is
                    # belt-and-suspenders: if a third-party library somewhere
                    # in the dependency chain writes raw non-UTF-8 bytes, we
                    # get a "?" in the captured log line instead of a dead
                    # watcher thread (which would leave the GUI stuck on
                    # "Starting…" forever).
                    encoding="utf-8", errors="replace",
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
                        _mark_server_running()          # start uptime ticker
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
                                _http_status_lbl.configure(foreground='#27ae60'),
                                _mark_server_running(),         # start uptime ticker
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
                            _http_status_lbl.configure(foreground='#cc0000'),
                            _stop_uptime_ticker(),          # clear uptime on stop
                        ))
                threading.Thread(target=_watch_http, daemon=True).start()
            except Exception as _e:
                messagebox.showerror("Launch Error", str(_e))

        # Store reference for auto-start on launch (see __init__)
        self._start_http_server_fn = _start_http_server

        def _stop_http_server():
            if self._http_server_proc is None or self._http_server_proc.poll() is not None:
                _http_status_var.set("⬤ Stopped")
                _http_status_lbl.configure(foreground='#cc0000')
                _stop_uptime_ticker()               # ensure ticker is cancelled
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
            _stop_uptime_ticker()                   # clear uptime on manual stop
            # Restore normal Windows sleep/power management
            self._set_sleep_prevention(False)

        http_btn_row = ttk.Frame(remote_frame)
        http_btn_row.pack(fill='x', pady=(4, 8))
        ttk.Button(http_btn_row, text="▶ Start HTTP Server",
                   command=_start_http_server).pack(side='left', padx=(0, 6))
        ttk.Button(http_btn_row, text="■ Stop",
                   command=_stop_http_server).pack(side='left', padx=(0, 6))

        def _force_kill_port():
            """Kill any process holding the configured HTTP port — useful when
            a crashed or interrupted server run leaves a zombie process on port
            8000 that prevents a clean restart.

            Priority 1: if this GUI session has a tracked subprocess for the
            HTTP server (self._http_server_proc), kill that PID directly —
            no netstat needed at all. This is the common case and is instant.

            Priority 2 (fallback): if no tracked subprocess (e.g. a previous
            GUI session was closed without stopping the server, or it was
            started outside the GUI), fall back to netstat to find the PID.
            netstat -ano can be slow while a server with a Cloudflare Tunnel
            or many open connections is running, so this path has a longer
            timeout and a clear message if it still doesn't return in time.
            """
            port_str = _http_port_var.get().strip()
            try:
                port = int(port_str)
            except ValueError:
                messagebox.showerror("Bad Port", f"Port must be a number, got: {port_str}")
                return

            pid = None
            via_tracked_proc = False

            # ── Priority 1: use the PID we already know about ────────────────────
            if (self._http_server_proc is not None
                    and self._http_server_proc.poll() is None):
                pid = self._http_server_proc.pid
                via_tracked_proc = True

            # ── Priority 2: netstat fallback (only if PID isn't already known) ───
            if pid is None:
                try:
                    result = subprocess.run(
                        f'netstat -ano | findstr ":{port} "',
                        shell=True, capture_output=True, text=True, timeout=20
                    )
                    for line in result.stdout.splitlines():
                        if 'LISTENING' in line:
                            parts = line.split()
                            if parts:
                                try:
                                    pid = int(parts[-1])
                                    break
                                except ValueError:
                                    pass
                except subprocess.TimeoutExpired:
                    messagebox.showerror(
                        "netstat Timed Out",
                        f"netstat did not respond within 20 seconds.\n\n"
                        f"This can happen while a server with a Cloudflare Tunnel\n"
                        f"or many open connections is running.\n\n"
                        f"Try manually in an Administrator command prompt:\n\n"
                        f"  netstat -ano | findstr :{port}\n"
                        f"  taskkill /PID <pid> /F")
                    return
                except Exception as _ne:
                    messagebox.showerror("netstat Error", str(_ne))
                    return

            if pid is None:
                # Double-check with a socket probe
                import socket as _sock
                with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as _s:
                    _s.settimeout(1)
                    in_use = _s.connect_ex(('127.0.0.1', port)) == 0
                if in_use:
                    messagebox.showwarning(
                        "Port In Use",
                        f"Port {port} is in use but the PID could not be identified.\n\n"
                        f"Run this in an Administrator command prompt:\n"
                        f"  netstat -ano | findstr :{port}\n"
                        f"  taskkill /PID <pid> /F")
                else:
                    messagebox.showinfo("Port Free", f"Port {port} is not in use — nothing to kill.")
                return

            source_note = ("tracked HTTP server process" if via_tracked_proc
                            else "found via netstat")
            if not messagebox.askyesno(
                    "Force Kill Port",
                    f"Kill process PID {pid} holding port {port}?\n"
                    f"({source_note})\n\n"
                    f"Use this when a crashed server is blocking a restart.\n"
                    + ("" if via_tracked_proc else
                       "This requires Administrator privileges.")):
                return

            try:
                result = subprocess.run(
                    ['taskkill', '/PID', str(pid), '/F'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    _http_status_var.set(f"⬤ Killed PID {pid} — port {port} free")
                    _http_status_lbl.configure(foreground='#1a7a1a')
                    messagebox.showinfo(
                        "Process Killed",
                        f"✅ PID {pid} terminated — port {port} is now free.\n\n"
                        f"You can now click ▶ Start HTTP Server.")
                else:
                    err = result.stderr.strip() or result.stdout.strip()
                    messagebox.showerror(
                        "Kill Failed",
                        f"Could not kill PID {pid}.\n\n"
                        f"Error: {err}\n\n"
                        f"Try running AI-Prowler as Administrator.")
            except Exception as _ke:
                messagebox.showerror("Kill Error", str(_ke))

        ttk.Button(http_btn_row, text="🔨 Force Kill Port",
                   command=_force_kill_port).pack(side='left')

        ttk.Separator(remote_frame, orient='horizontal').pack(fill='x', pady=(0, 8))

        # ── cloudflared executable path helper ────────────────────────────────
        def _cf_exe():
            return str(Path(__file__).parent / 'cloudflared.exe')

        # ── Tunnel domain var — defined here so both personal and server
        #    mode branches below can reference it safely ──────────────────
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

        # ── Named Tunnel section ──────────────────────────────────────────────
        # Setup Cloudflare Tunnel guide hidden in v8.0.0 — tunnel is now
        # provisioned automatically via the subscription flow above.

        if not _settings_is_server_mode:
            # ── Personal mode: Connect Claude.ai button ───────────────────────
            # Opens Claude.ai with the Add Custom Connector modal pre-filled
            # with the MCP URL.  Turns red after activation to prompt the user.
            guide_row = ttk.Frame(remote_frame)
            guide_row.pack(fill='x', pady=(0, 6))

            def _open_claude_connector():
                import webbrowser
                domain = _tun_domain_var.get().strip().replace(
                    'https://', '').replace('http://', '').rstrip('/')
                if not domain:
                    messagebox.showwarning(
                        "No Domain",
                        "Activate your subscription first so the tunnel domain is set,\n"
                        "then click this button to connect Claude.ai.")
                    return
                mcp_url = f"https://{domain}/mcp"
                try:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(mcp_url)
                    self.root.update()
                except Exception:
                    pass
                messagebox.showinfo(
                    "MCP URL Copied — Paste into Claude.ai",
                    f"Your MCP URL has been copied to the clipboard:\n\n"
                    f"  {mcp_url}\n\n"
                    f"Click OK and the Claude.ai connector form will open.\n\n"
                    f"1. Paste the URL into the 'Remote MCP server URL' field\n"
                    f"2. Name it 'AI-Prowler'\n"
                    f"3. Leave OAuth fields blank\n"
                    f"4. Click Add → enter your Bearer Token when prompted\n"
                    f"5. Set 'Always allow' for all tools")
                claude_url = "https://claude.ai/customize/connectors?modal=add-custom-connector"
                webbrowser.open(claude_url)
                try:
                    _connect_claude_btn.configure(
                        background='SystemButtonFace',
                        foreground='SystemButtonText',
                        text="📖 Connect Claude.ai  (open connector setup)")
                except Exception:
                    pass

            _connect_claude_btn = tk.Button(guide_row,
                       text="📖 Connect Claude.ai  (auto)",
                       command=_open_claude_connector,
                       relief='raised', bd=1,
                       font=('Arial', 9))
            _connect_claude_btn.pack(side='left', padx=(0, 4))
            ttk.Button(guide_row,
                       text="📋 Manual Instructions",
                       command=self.show_claude_connector_guide
                       ).pack(side='left', padx=(0, 8))
            ttk.Label(guide_row,
                      text="← auto opens Claude.ai with URL copied to clipboard",
                      font=('Arial', 8), foreground='gray').pack(side='left')

        else:
            # ── Server mode: Connection Test panel (v8.1.0) ───────────────────
            # Shows the public MCP URL employees need, tests reachability from
            # the internet, and turns green when confirmed accessible.
            # No "Connect Claude.ai" here — employees do that from their own
            # devices using the URL displayed below.

            srv_test_frame = ttk.LabelFrame(remote_frame,
                                            text="Server Connection Test",
                                            padding=(10, 6))
            srv_test_frame.pack(fill='x', pady=(0, 8))

            # ── Connector URL display + copy ──────────────────────────────────
            ttk.Label(srv_test_frame,
                      text="Connector URL — employees paste this into Claude.ai:",
                      font=('Arial', 9, 'bold')).pack(anchor='w')
            ttk.Label(srv_test_frame, font=('Arial', 8), foreground='gray',
                      text="Claude Team: Owner adds once in Organization Settings → Connectors.\n"
                           "Claude Pro:  Each employee adds individually in Settings → Connectors → +."
                      ).pack(anchor='w', pady=(0, 6))

            url_row = ttk.Frame(srv_test_frame)
            url_row.pack(fill='x', pady=(0, 8))

            _srv_mcp_url_var = tk.StringVar()

            def _refresh_srv_mcp_url(*_):
                d = _tun_domain_var.get().strip().replace(
                    'https://', '').replace('http://', '').rstrip('/')
                _srv_mcp_url_var.set(f"https://{d}/mcp" if d else "")

            _tun_domain_var.trace_add('write', _refresh_srv_mcp_url)
            _refresh_srv_mcp_url()

            _srv_url_entry = ttk.Entry(url_row, textvariable=_srv_mcp_url_var,
                                       width=44, state='readonly',
                                       font=('Courier New', 9))
            _srv_url_entry.pack(side='left', padx=(0, 6))

            def _copy_srv_url():
                url = _srv_mcp_url_var.get()
                if not url or url == "https:///mcp":
                    messagebox.showwarning("No URL",
                        "Activate the server first so the domain is set.")
                    return
                try:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(url)
                    self.root.update()
                    self.status_var.set(f"📋 Copied: {url}")
                    self.root.after(3000, lambda: self.status_var.set("Ready"))
                except Exception as _ce:
                    messagebox.showerror("Copy Failed", str(_ce))

            ttk.Button(url_row, text="📋 Copy",
                       command=_copy_srv_url).pack(side='left')

            ttk.Separator(srv_test_frame, orient='horizontal').pack(
                fill='x', pady=(2, 8))

            # ── Test button + LED + status label ─────────────────────────────
            test_row = ttk.Frame(srv_test_frame)
            test_row.pack(fill='x')

            # LED canvas — gray=untested, orange=testing, green=ok, red=fail
            _srv_test_canvas = tk.Canvas(test_row, width=14, height=14,
                                         bg=self.root.cget('bg'),
                                         highlightthickness=0)
            _srv_test_canvas.pack(side='left', padx=(0, 6))
            _srv_test_dot = _srv_test_canvas.create_oval(
                2, 2, 12, 12, fill='gray', outline='')

            _srv_test_btn = ttk.Button(test_row, text="🌐 Test Server Connection")
            _srv_test_btn.pack(side='left', padx=(0, 10))

            _srv_test_status_var = tk.StringVar(value="Not tested yet")
            _srv_test_status_lbl = ttk.Label(test_row,
                                             textvariable=_srv_test_status_var,
                                             font=('Arial', 8))
            _srv_test_status_lbl.pack(side='left')

            def _test_server_connection():
                """
                Hit the public /mcp URL from this machine — confirms tunnel is
                routing traffic end-to-end from the internet to the local HTTP
                server.  A 200 or 405 response both mean the server is reachable
                (405 = MCP endpoint exists but GET not allowed, which is normal).
                """
                url = _srv_mcp_url_var.get().strip()
                if not url or url == "https:///mcp":
                    messagebox.showwarning(
                        "No URL",
                        "Activate the server first (paste your activation code\n"
                        "and click Auto-Configure Server) so the domain is set.")
                    return

                _srv_test_btn.configure(state='disabled')
                _srv_test_canvas.itemconfig(_srv_test_dot, fill='#E67E00')
                _srv_test_status_var.set(f"Testing {url} …")
                _srv_test_status_lbl.configure(foreground='#888')

                def _worker():
                    ok      = False
                    status  = ""
                    detail  = ""
                    try:
                        import urllib.request as _ur
                        import urllib.error   as _ue
                        req = _ur.Request(url,
                                          headers={"User-Agent": "AI-Prowler-ServerTest/8.1"},
                                          method="GET")
                        try:
                            with _ur.urlopen(req, timeout=12) as resp:
                                code = resp.getcode()
                                ok   = True
                                status  = f"✅ Reachable  (HTTP {code})"
                                detail  = "green"
                        except _ue.HTTPError as he:
                            # 4xx from the MCP endpoint = server is up and answering
                            if he.code in (400, 401, 403, 405):
                                ok      = True
                                status  = f"✅ Reachable  (HTTP {he.code} — server is live)"
                                detail  = "green"
                            else:
                                status  = f"⚠️ HTTP {he.code} — check server config"
                                detail  = "orange"
                    except OSError as oe:
                        status = f"❌ Not reachable — {oe}"
                        detail = "red"
                    except Exception as ex:
                        status = f"❌ Error — {ex}"
                        detail = "red"

                    colour_map = {
                        "green":  "#22C55E",
                        "orange": "#E67E00",
                        "red":    "#CC0000",
                    }
                    colour = colour_map.get(detail, 'gray')

                    def _apply():
                        _srv_test_canvas.itemconfig(_srv_test_dot, fill=colour)
                        _srv_test_status_var.set(status)
                        _srv_test_status_lbl.configure(
                            foreground='#1a7a1a' if ok else '#cc0000')
                        _srv_test_btn.configure(state='normal')
                        if ok:
                            # Show the URL prominently so admin can share it
                            messagebox.showinfo(
                                "Server is Live ✅",
                                f"AI-Prowler Server is publicly reachable.\n\n"
                                f"Connector URL for employees:\n"
                                f"  {url}\n\n"
                                f"Claude Team plan:\n"
                                f"  Organization Settings → Connectors → Add custom connector\n"
                                f"  Paste the URL above → click Add\n\n"
                                f"Claude Pro (each employee individually):\n"
                                f"  Settings → Connectors → + → Add custom connector\n"
                                f"  Paste the URL above → click Add\n\n"
                                f"The URL is also included in each employee's\n"
                                f"personal activation email — already sent.")
                    self.root.after(0, _apply)

                import threading as _th3
                _th3.Thread(target=_worker, daemon=True).start()

            _srv_test_btn.configure(command=_test_server_connection)

            # Expose _connect_claude_btn as a no-op stub so any code that
            # references it after activation (e.g. _activate_server) doesn't
            # crash — server mode uses the test panel instead.
            class _NoOpBtn:
                def configure(self, **_): pass
            _connect_claude_btn = _NoOpBtn()

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

        # MCP URL copy row — assembled from domain + /mcp, ready to paste into Claude.ai
        mcp_url_row = ttk.Frame(act_frame)
        mcp_url_row.pack(fill='x', pady=(0, 6))
        ttk.Label(mcp_url_row, text="Claude.ai MCP URL:", width=18, anchor='w').pack(side='left')
        _mcp_url_var = tk.StringVar()

        def _update_mcp_url(*_):
            d = _tun_domain_var.get().strip().replace('https://', '').replace('http://', '').rstrip('/')
            _mcp_url_var.set(f"https://{d}/mcp" if d else "")

        _tun_domain_var.trace_add('write', _update_mcp_url)
        _update_mcp_url()

        _mcp_url_entry = ttk.Entry(mcp_url_row, textvariable=_mcp_url_var,
                                   width=40, state='readonly')
        _mcp_url_entry.pack(side='left', padx=(4, 4))

        def _copy_mcp_url():
            url = _mcp_url_var.get()
            if not url or url == "https:///mcp":
                messagebox.showwarning("No hostname",
                    "Enter your Public hostname above first.")
                return
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(url)
                self.root.update()
                self.status_var.set(f"Copied: {url}")
                self.root.after(3000, lambda: self.status_var.set("Ready"))
            except Exception as e:
                messagebox.showerror("Copy failed", str(e))

        ttk.Button(mcp_url_row, text="📋 Copy",
                   command=_copy_mcp_url).pack(side='left', padx=(0, 8))
        ttk.Label(mcp_url_row,
                  text="← paste this into Claude.ai → Settings → Connectors → Add custom connector",
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

        # ── Keep It Running — power/sleep help panel ───────────────────────────
        kir_frame = ttk.LabelFrame(remote_frame,
                                   text=" 💡 Keep It Running ",
                                   padding=(8, 4))
        kir_frame.pack(fill='x', pady=(10, 6))

        ttk.Label(kir_frame, foreground='gray',
                  text=("Sleep mode disconnects the MCP server \u2014 mobile Claude will\n"
                        "stop responding until you wake the laptop AND restart the server\n"
                        "via Claude Desktop \u2192 Settings \u2192 Developer \u2192 MCP Servers.")
                  ).pack(anchor='w')

        ttk.Label(kir_frame, foreground='gray',
                  text=("\nRecommended: set Windows Power Plan to \u2018Never sleep\u2019 while\n"
                        "plugged in. Then you can close the lid and walk away \u2014\n"
                        "AI-Prowler stays online for mobile use.")
                  ).pack(anchor='w')

        # ── Helper functions defined first so buttons can reference them ───────
        def _show_keep_running_help():
            dlg = tk.Toplevel(self.root)
            dlg.title("Keep AI-Prowler Running \u2014 Power Settings Guide")
            dlg.resizable(False, False)
            dlg.grab_set()

            outer = ttk.Frame(dlg, padding=16)
            outer.pack(fill='both', expand=True)

            txt = tk.Text(outer, wrap='word', width=62, height=34,
                          font=('Arial', 9), relief='flat',
                          background=dlg.cget('background'), cursor='arrow')
            sb  = ttk.Scrollbar(outer, orient='vertical', command=txt.yview)
            txt.configure(yscrollcommand=sb.set)
            sb.pack(side='right', fill='y')
            txt.pack(side='left', fill='both', expand=True)

            txt.tag_configure('h1',   font=('Arial', 11, 'bold'), spacing1=10)
            txt.tag_configure('h2',   font=('Arial', 10, 'bold'), spacing1=8)
            txt.tag_configure('body', font=('Arial', 9),          lmargin1=8, lmargin2=8)
            txt.tag_configure('code', font=('Courier', 9),
                              background='#e8e8e8', lmargin1=20, lmargin2=20)
            txt.tag_configure('note', font=('Arial', 9, 'italic'), foreground='gray',
                              lmargin1=8, lmargin2=8)

            def h1(t):  txt.insert('end', t + '\n', 'h1')
            def h2(t):  txt.insert('end', t + '\n', 'h2')
            def ln(t):  txt.insert('end', t + '\n', 'body')
            def cd(t):  txt.insert('end', '  ' + t + '\n', 'code')
            def nt(t):  txt.insert('end', t + '\n', 'note')
            def sp():   txt.insert('end', '\n')

            h1("Power Settings \u2014 Keep AI-Prowler Online")
            nt("Follow these three steps once. AI-Prowler will then stay\n"
               "online whenever the laptop is plugged in.")

            sp()
            h2("Step 1 \u2014 Set Sleep to Never (Plugged In)")
            ln("1.  Start \u2192 Settings \u2192 System \u2192 Power & battery")
            ln("2.  Click \u2018Screen, sleep, & hibernate timeouts\u2019 to expand it")
            ln("3.  Under Plugged in, set:")
            ln("      \u2022  Make my device sleep after  \u2192  Never")
            ln("      \u2022  Turn my screen off after    \u2192  Never  (or 2 hours)")
            ln("4.  Scroll down to \u2018Lid, power & sleep button controls\u2019 and expand it")
            ln("5.  Under Plugged in, set all three dropdowns to Do Nothing:")
            ln("      \u2022  Pressing the power button will make my PC  \u2192  Do Nothing")
            ln("      \u2022  Pressing the sleep button will make my PC  \u2192  Do Nothing")
            ln("      \u2022  Closing the lid will make my PC           \u2192  Do Nothing")

            sp()
            h2("Step 2 \u2014 Disable Hibernate")
            ln("Hibernate saves RAM to disk and powers off \u2014 it also kills")
            ln("the MCP server.  Disable it permanently with one command.")
            sp()
            ln("1.  Click Start and type:  cmd")
            ln("2.  Right-click Command Prompt \u2192 Run as administrator \u2192 Yes")
            ln("3.  Type this command exactly and press Enter:")
            cd("powercfg /h off")
            ln("4.  Close Command Prompt")

            sp()
            h2("Step 3 \u2014 Prevent Unattended Windows Update Restarts")
            ln("Windows Update can restart the server mid-day and take it")
            ln("offline.  Set Active Hours so restarts only happen overnight.")
            sp()
            ln("1.  Start \u2192 Settings \u2192 Windows Update \u2192 Advanced options")
            ln("2.  Click \u2018Adjust active hours\u2019 and set:")
            ln("      \u2022  Start:  6:00 AM")
            ln("      \u2022  End:    11:00 PM")
            ln("3.  Turn ON   \u2018Notify me when a restart is required\u2019")
            ln("4.  Turn OFF  \u2018Restart as soon as possible when a restart is required\u2019")
            sp()
            nt("Windows will now only restart outside your active hours\n"
               "and will notify you first.")

            sp()
            h2("Good News \u2014 Windows Update Auto-Reboots Are Safe")
            ln("If AI-Prowler was running before a reboot, Windows re-launches")
            ln("it automatically and the tunnel reconnects on its own \u2014 no")
            ln("operator action needed.")

            txt.configure(state='disabled')

            btn_row = ttk.Frame(outer)
            btn_row.pack(fill='x', pady=(10, 0))

            def _copy_cmd():
                dlg.clipboard_clear()
                dlg.clipboard_append("powercfg /h off")
                copy_btn.configure(text="Copied!")
                dlg.after(2000, lambda: copy_btn.configure(text="Copy  powercfg /h off"))

            copy_btn = ttk.Button(btn_row, text="Copy  powercfg /h off",
                                  command=_copy_cmd)
            copy_btn.pack(side='left', padx=(0, 8))
            ttk.Button(btn_row, text="Close",
                       command=dlg.destroy).pack(side='right')

            dlg.update_idletasks()
            w, h = dlg.winfo_reqwidth(), dlg.winfo_reqheight()
            x = self.root.winfo_x() + (self.root.winfo_width()  - w) // 2
            y = self.root.winfo_y() + (self.root.winfo_height() - h) // 2
            dlg.geometry(f"+{x}+{y}")

        def _apply_power_settings():
            """Run all power settings commands elevated via UAC."""
            import tempfile, os
            script = (
                "@echo off\n"
                "net session >nul 2>&1\n"
                "if %errorlevel% neq 0 (\n"
                "    echo Must be run as Administrator & pause & exit /b 1\n"
                ")\n"
                "echo Applying AI-Prowler power settings...\n"
                "echo.\n"
                "echo [1/4] Sleep (plugged in) -- Never...\n"
                "powercfg /change standby-timeout-ac 0\n"
                "echo [2/4] Hibernate -- Disabled...\n"
                "powercfg /h off\n"
                "echo [3/4] Windows Update active hours -- 6:00 AM to 11:00 PM...\n"
                "reg add \"HKLM\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings\" "
                    "/v ActiveHoursStart /t REG_DWORD /d 6 /f >nul 2>&1\n"
                "reg add \"HKLM\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings\" "
                    "/v ActiveHoursEnd /t REG_DWORD /d 23 /f >nul 2>&1\n"
                "echo [4/4] Auto-restart for updates -- Off...\n"
                "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" "
                    "/v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f >nul 2>&1\n"
                "echo.\n"
                "echo All done! Settings applied:\n"
                "echo   Sleep (plugged in)       -- Never\n"
                "echo   Hibernate                -- Disabled\n"
                "echo   Windows Update hours     -- 6:00 AM to 11:00 PM\n"
                "echo   Auto-restart for updates -- Off\n"
                "echo.\n"
                "echo Click Check Power Settings in AI-Prowler to verify.\n"
                "echo.\n"
                "pause\n"
                "del \"%~f0\"\n"
            )
            tmp = tempfile.NamedTemporaryFile(suffix='.bat', mode='w',
                                              delete=False, encoding='utf-8',
                                              prefix='aip_power_')
            tmp.write(script)
            tmp.close()
            try:
                import ctypes
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", tmp.name, None, None, 1)
                if ret <= 32:
                    messagebox.showerror("Power Setup",
                                         "UAC prompt was cancelled or elevation failed.\n"
                                         "Run AI-Prowler-Power-Setup.bat as administrator manually.")
                    os.unlink(tmp.name)
                else:
                    self.status_var.set("\u26a1 Power settings script launched \u2014 approve UAC prompt")
                    self.root.after(4000, lambda: self.status_var.set("Ready"))
            except Exception as e:
                messagebox.showerror("Power Setup Error", str(e))
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass

        # ── LED status grid ────────────────────────────────────────────────────
        ttk.Separator(kir_frame, orient='horizontal').pack(fill='x', pady=(8, 6))

        led_grid = ttk.Frame(kir_frame)
        led_grid.pack(fill='x', anchor='w')

        LED_OK  = ('\u2b24', '#27ae60')
        LED_BAD = ('\u2b24', '#cc0000')
        LED_UNK = ('\u2b24', '#aaaaaa')

        _kir_checks = [
            "Sleep (plugged in)       \u2192 Never",
            "Hibernate                \u2192 Disabled",
            "Update active hours      \u2192 before 6 AM & after 11 PM",
            "Auto-restart for updates \u2192 Off",
        ]
        _led_vars    = []
        _detail_vars = []
        for i, label in enumerate(_kir_checks):
            lv = tk.StringVar(value=LED_UNK[0])
            dv = tk.StringVar(value="")
            row = ttk.Frame(led_grid)
            row.pack(fill='x', pady=1)
            led_lbl = tk.Label(row, textvariable=lv, font=('Arial', 9),
                               fg=LED_UNK[1], width=2)
            led_lbl.pack(side='left')
            ttk.Label(row, text=label, font=('Arial', 9), width=42,
                      anchor='w').pack(side='left')
            ttk.Label(row, textvariable=dv, font=('Arial', 8),
                      foreground='gray').pack(side='left')
            _led_vars.append((lv, led_lbl))
            _detail_vars.append(dv)

        def _set_led(idx, ok, detail=""):
            char, color = (LED_OK if ok else LED_BAD)
            lv, lbl = _led_vars[idx]
            lv.set(char)
            lbl.configure(fg=color)
            _detail_vars[idx].set(detail)

        def _check_power_settings():
            import subprocess, winreg
            CREATE_NO_WIN = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0

            def _powercfg_query(sub, setting):
                try:
                    r = subprocess.run(
                        ['powercfg', '/query', 'SCHEME_CURRENT', sub, setting],
                        capture_output=True, text=True, creationflags=CREATE_NO_WIN)
                    for line in r.stdout.splitlines():
                        if 'AC Power Setting Index' in line:
                            return int(line.split(':')[-1].strip(), 16)
                except Exception:
                    pass
                return None

            def _reg_dword(hive, path, name, default=None):
                try:
                    with winreg.OpenKey(hive, path) as k:
                        val, _ = winreg.QueryValueEx(k, name)
                        return int(val)
                except Exception:
                    return default

            # LED 0: Sleep (plugged in) — must be Never (0)
            v = _powercfg_query('SUB_SLEEP', 'STANDBYIDLE')
            _set_led(0, v == 0, f"({v//60} min)" if v and v > 0 else "")

            # LED 1: Hibernate — disabled when hiberfil.sys absent
            import os as _os
            hib_off = not _os.path.exists(r'C:\hiberfil.sys')
            _set_led(1, hib_off, "(hiberfil.sys present)" if not hib_off else "")

            # LED 2: Active hours — green if start <= 6 AND end >= 23
            WU_PATH = r'SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
            ah_start = _reg_dword(winreg.HKEY_LOCAL_MACHINE, WU_PATH, 'ActiveHoursStart')
            ah_end   = _reg_dword(winreg.HKEY_LOCAL_MACHINE, WU_PATH, 'ActiveHoursEnd')
            if ah_start is not None and ah_end is not None:
                ah_ok = (ah_start <= 6 and ah_end >= 23)
                _set_led(2, ah_ok, f"({ah_start}:00\u2013{ah_end}:00)")
            else:
                _set_led(2, False, "(not set)")

            # LED 3: Auto-restart off
            AU_PATH = r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            no_reboot = _reg_dword(winreg.HKEY_LOCAL_MACHINE, AU_PATH,
                                   'NoAutoRebootWithLoggedOnUsers')
            _set_led(3, no_reboot == 1, "(not set)" if no_reboot is None else "")

        def _check_power_bg():
            threading.Thread(target=_check_power_settings, daemon=True).start()

        # ── Button row ─────────────────────────────────────────────────────────
        ttk.Separator(kir_frame, orient='horizontal').pack(fill='x', pady=(8, 6))
        kir_btn_row = ttk.Frame(kir_frame)
        kir_btn_row.pack(fill='x', anchor='w')

        ttk.Button(kir_btn_row, text="\U0001f50d Check Power Settings",
                   command=_check_power_bg).pack(side='left', padx=(0, 8))
        ttk.Button(kir_btn_row, text="\U0001f4cb Power Settings Guide",
                   command=_show_keep_running_help).pack(side='left', padx=(0, 8))
        ttk.Button(kir_btn_row, text="\u26a1 Apply Power Settings Now",
                   command=_apply_power_settings).pack(side='left')

        # Auto-check on startup (after 2s so GUI is fully drawn)
        self.root.after(2000, _check_power_bg)




        # Hidden when DEBUG_EN is False (most users don't paste config snippets
        # by hand). Widgets are still constructed so _refresh_snippet and
        # _copy_snippet bindings stay live, but they're parented to an unpacked
        # frame so the user never sees them.
        if DEBUG_EN:
            _snippet_parent = remote_frame
            ttk.Separator(remote_frame, orient='horizontal').pack(fill='x', pady=(0, 8))
        else:
            _snippet_parent = tk.Frame(remote_frame)   # never packed

        ttk.Label(_snippet_parent, text="Claude.ai Web / Mobile Config Snippet:",
                  font=('Arial', 9, 'bold')).pack(anchor='w')
        ttk.Label(_snippet_parent, font=('Arial', 8), foreground='gray',
                  text=("For Claude.ai web or mobile ONLY — NOT for Claude Desktop.\n"
                        "In Claude.ai: Settings → MCP Servers → Add Server → paste URL and token.")
                  ).pack(anchor='w', pady=(0, 4))

        _snippet_text = tk.Text(_snippet_parent, height=8, font=('Courier', 8),
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

        snippet_btn_row = ttk.Frame(_snippet_parent)
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
        privacy_frame = ttk.LabelFrame(_debug_settings_parent,
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

        # About section removed in v7.0.0 — use Help → About AI Prowler instead.

    # ══════════════════════════════════════════════════════════════════════════
    # TAB 6 — SMALL BUSINESS SERVICE TOOLS
    # ══════════════════════════════════════════════════════════════════════════
    def create_small_business_tab(self):
        """
        Dedicated tab for the Small Business / Field Service MCP action tools.

        Sections (in order):
          1. Overview banner — what these tools do and how to invoke them
          2. Free Tools panel — weather, geocode, route, maps URL (no setup)
          3. Job Spreadsheet Updater panel — usage guide + open-file shortcut
          4. Route & Navigation panel — OSRM/Nominatim notes + open Google Maps

        Configuration is read from / written to:
            ~/.ai-prowler/config.json
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
                      "12 MCP tools that let Claude act as your field-service assistant (plus check_tools_status for a quick status report).\n"
                      "Ask Claude in a conversation — no forms to fill out, no menus to navigate.\n\n"
                      "Free tools (weather, routing, maps) work immediately — no setup.\n"
                      "Spreadsheet tools use the default path from Settings if filepath is omitted.\n"
                        "Contractor tools (invoicing, SMS, time logging, AR aging) require Twilio/SMTP — see Settings."
                  )).pack(anchor='w')

        # Claude prompt examples
        ex_frame = ttk.LabelFrame(banner, text="Example prompts to use with Claude",
                                  padding=(8, 4))
        ex_frame.pack(fill='x', pady=(8, 0))

        examples = [
            ("🌤  Weather",      '"What is the weather forecast for New Smyrna Beach for the next 3 days?"'),
            ("🗺  Route",        '"Optimize my route for these 6 jobs today and give me a Google Maps link."'),
            ("📊  Spreadsheet",  '"Mark the Miller Windows job complete in my jobs.xlsx and record invoice #1048."'),
            ("🧾  Invoice",      '"Email invoice #1048 to the Miller account."'),
            ("⏱  Time log",     '"Clock me in on job J-205."'),
            ("📱  SMS",          '"Text the Johnson job that I am on my way."'),
            ("💰  AR aging",     '"Show me my accounts receivable aging report."'),
            ("🔍  Status check", '"Call check_tools_status() and tell me what is ready to use."'),
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

                ("optimize_route(stops, origin, …)",
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

        # ── 3. JOB SPREADSHEET UPDATER ────────────────────────────────────────
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

        # Auto-detect default path with fallbacks. Some installs may not have
        # written default_spreadsheet_path to config.json (e.g. the bundled
        # template went missing at compile time, or installer-side config init
        # failed silently). In that case we look for the template in the
        # standard install location and use it if present.
        def _detect_default_xl_path():
            cfg_val = _load_cfg().get('default_spreadsheet_path', '')
            if cfg_val:
                return cfg_val
            # Standard install location written by the Inno [Files] section:
            #     %USERPROFILE%\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx
            import os as _os
            for candidate in (
                Path.home() / 'Documents' / 'AI-Prowler' / 'AI-Prowler_Job_Tracker.xlsx',
                # Older installs may have used OneDrive's redirected Documents
                Path.home() / 'OneDrive' / 'Documents' / 'AI-Prowler' / 'AI-Prowler_Job_Tracker.xlsx',
                # Fall back to the file shipped next to rag_gui.py (dev runs)
                Path(__file__).parent / 'AI-Prowler_Job_Tracker.xlsx',
            ):
                try:
                    if candidate.exists():
                        return str(candidate).replace('/', _os.sep)
                except Exception:
                    pass
            return ''

        _xl_path_var.set(_detect_default_xl_path())
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

        # ── 4. ROUTE & NAVIGATION NOTES ──────────────────────────────────────
        route_outer = ttk.LabelFrame(f,
                                     text="🗺  Route Optimization & Navigation  —  Free, No Key",
                                     padding=(12, 8))
        route_outer.pack(fill='x', padx=16, pady=(0, 10))

        route_info = (
            "optimize_route(stops, origin, optimize_for, departure_hour, return_to_origin)\n"
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
            "  2. Claude calls optimize_route() → get optimised order\n"
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

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 5. CONTRACTOR WORKFLOW TOOLS ──────────────────────────────────────
        cw_outer = ttk.LabelFrame(f,
                                  text="🧰 Contractor Workflow Tools — Require Setup (SMTP / Twilio)",
                                  padding=(12, 8))
        cw_outer.pack(fill='x', padx=16, pady=(0, 6))

        ttk.Label(cw_outer, justify='left', font=('Arial', 8), foreground='gray',
                  text=(
                      "Five tools that automate the admin side of running a service business.\n"
                      "email_invoice and schedule_next_recurring_job require SMTP email (configure in Settings → Email).\n"
                      "send_sms requires a Twilio account (configure in Settings → Small Business → SMS)."
                  )).pack(anchor='w', pady=(0, 8))

        contractor_tools = [
            (
                "email_invoice(invoice_id, to, filepath)",
                "Reads the Invoices sheet in your job tracker, builds a branded HTML invoice,\n"
                "and emails it directly to the customer — no copy-paste, no manual attachment.\n"
                'Example: "Email invoice #1048 to the Miller account."',
                "Requires SMTP email configured in Settings",
            ),
            (
                "send_sms(to, message)",
                "Sends an SMS text message to a customer or crew member via Twilio.\n"
                "Perfect for on-my-way notifications, reminders, and appointment confirmations.\n"
                'Example: "Text the Johnson job that I am 20 minutes out."',
                "Requires Twilio account SID, auth token, and From number in Settings",
            ),
            (
                "schedule_next_recurring_job(job_id, filepath)",
                "After completing a recurring job, auto-creates the next scheduled instance\n"
                "based on the customer's service frequency (Weekly / Bi-weekly / Monthly / Quarterly).\n"
                'Example: "Schedule the next recurring visit for the Smith account."',
                "Uses the default spreadsheet path — set in Settings → Small Business",
            ),
            (
                "log_time_entry(job_id, action, filepath)",
                "Clocks you in or out on a specific job. Records timestamps to the TimeLog sheet\n"
                "and writes the Actual Duration back to the Jobs_Schedule row when you clock out.\n"
                'Example: "Clock me in on job J-205." / "Clock me out of J-205."',
                "Uses the default spreadsheet path — set in Settings → Small Business",
            ),
            (
                "get_ar_aging_report(filepath, as_of_date)",
                "Generates an Accounts Receivable aging report from your Invoices sheet,\n"
                "bucketed into Current / 1-30 / 31-60 / 61-90 / 90+ days outstanding.\n"
                'Example: "Show me my AR aging report." / "Who owes me money past 30 days?"',
                "Uses the default spreadsheet path — set in Settings → Small Business",
            ),
        ]

        for tool_name, description, requirement in contractor_tools:
            tool_row = ttk.Frame(cw_outer)
            tool_row.pack(fill='x', pady=(0, 10))
            ttk.Label(tool_row, text=f"🔧 {tool_name}", font=('Courier New', 9, 'bold'),
                      foreground='#7c3400').pack(anchor='w')
            ttk.Label(tool_row, text=description, font=('Arial', 8), justify='left',
                      foreground='#333333').pack(anchor='w', padx=(20, 0))
            ttk.Label(tool_row, text=f"  ⚙ {requirement}", font=('Arial', 8),
                      foreground='#888888').pack(anchor='w', padx=(20, 0))

        # Quick-link to Settings for setup
        cw_btn_row = ttk.Frame(cw_outer)
        cw_btn_row.pack(fill='x', pady=(4, 0))
        ttk.Button(cw_btn_row, text="⚙  Open Settings (to configure Email / SMS)",
                   command=lambda: self.notebook.select(self._TAB_INDEX_SETTINGS)
                   ).pack(side='left')

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 6. READ SPREADSHEET TOOL ──────────────────────────────────────────
        rs_outer = ttk.LabelFrame(f,
                                  text="📖 Read Spreadsheet — read_job_spreadsheet()",
                                  padding=(12, 8))
        rs_outer.pack(fill='x', padx=16, pady=(0, 10))
        ttk.Label(rs_outer, justify='left', font=('Arial', 8), foreground='#333333',
                  text=(
                      "read_job_spreadsheet(filepath, sheet, date, max_rows)\n"
                      "  • Reads any sheet in your job tracker — Jobs_Schedule, Customers, Invoices, etc.\n"
                      "  • Supports date filtering: specify a date to see only that day's jobs.\n"
                      "  • Returns structured data Claude can reason over and summarise.\n\n"
                      'Example: "What jobs do I have scheduled for tomorrow?"\n'
                      'Example: "Show me all open invoices from the Invoices sheet."'
                  )).pack(anchor='w')

    # ══════════════════════════════════════════════════════════════════════════
    # 🧠  SELF-LEARNING TAB
    # ══════════════════════════════════════════════════════════════════════════

    def create_learnings_tab(self):
        """
        Dedicated tab for viewing and managing the Self-Learning knowledge base.

        Sections:
          1. Overview banner — what self-learning is and how Claude uses it
          2. Stats panel — live counts by category, status, outcome
          3. Learnings table — Treeview with all learnings, click to expand
          4. Detail panel — shows full content of selected learning
          5. Action buttons — refresh, archive, delete, export, reindex

        Data source:  ~/.ai-prowler/learnings/self_learning_data.json
        """
        import json as _json
        from pathlib import Path as _Path

        outer = ttk.Frame(self.notebook)
        self.notebook.add(outer, text="🧠 Learnings")
        f = self._make_scrollable_tab(outer)

        _learnings_file = _Path.home() / '.ai-prowler' / 'learnings' / 'self_learning_data.json'

        # ── Helper: load learnings from JSON ─────────────────────────────────
        def _load_learnings() -> list:
            try:
                if _learnings_file.exists():
                    data = _json.loads(_learnings_file.read_text(encoding='utf-8'))
                    if isinstance(data, dict) and 'learnings' in data:
                        return data['learnings']
            except Exception as exc:
                print(f"Warning: Could not read learnings file: {exc}")
            return []

        # ── 1. OVERVIEW BANNER ───────────────────────────────────────────────
        banner = ttk.LabelFrame(f, text="🧠 Self-Learning Knowledge Base — Overview",
                                padding=(12, 8))
        banner.pack(fill='x', padx=16, pady=(10, 6))

        ttk.Label(banner, justify='left', font=('Arial', 9),
                  text=(
                      "Claude automatically records learnings from your conversations — "
                      "business lessons,\nfact corrections, project insights, client preferences, "
                      "and process improvements.\n\n"
                      "Learnings are stored in a JSON file and indexed in ChromaDB for "
                      "instant semantic retrieval.\n"
                      "Claude checks this knowledge base BEFORE answering questions, "
                      "and records new learnings\nautomatically when it detects corrections, "
                      "outcomes, or improvements — always with confirmation."
                  )).pack(anchor='w')

        ex_frame = ttk.LabelFrame(banner, text="Example prompts that trigger self-learning",
                                  padding=(8, 4))
        ex_frame.pack(fill='x', pady=(8, 0))

        examples = [
            ("🔍  Check",      '"What do we know about Client X?"  →  Claude calls search_learnings()'),
            ("📝  Record",     '"Remember: always submit permits 2 weeks before job start"'),
            ("📊  Post-Op",    '"Analyze the Johnson project — what went right and wrong?"'),
            ("🔄  Correct",    '"Actually, the correct phone number is 555-0200"'),
            ("📋  Browse",     '"Show me all business lessons we have learned"'),
            ("📈  Stats",      '"How many learnings do we have and which are most applied?"'),
        ]
        for icon_label, prompt in examples:
            row = ttk.Frame(ex_frame)
            row.pack(fill='x', pady=1)
            ttk.Label(row, text=icon_label, font=('Arial', 8, 'bold'),
                      width=14, anchor='w').pack(side='left')
            ttk.Label(row, text=prompt, font=('Arial', 8),
                      foreground='#555555', anchor='w').pack(side='left')

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 2. STATS PANEL ───────────────────────────────────────────────────
        stats_frame = ttk.LabelFrame(f, text="📊 Knowledge Base Statistics",
                                     padding=(12, 8))
        stats_frame.pack(fill='x', padx=16, pady=(0, 6))

        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x')

        self._sl_stat_total      = tk.StringVar(value="—")
        self._sl_stat_active     = tk.StringVar(value="—")
        self._sl_stat_deprecated = tk.StringVar(value="—")
        self._sl_stat_archived   = tk.StringVar(value="—")
        self._sl_stat_applied    = tk.StringVar(value="—")

        stat_items = [
            ("Total",      self._sl_stat_total),
            ("Active",     self._sl_stat_active),
            ("Deprecated", self._sl_stat_deprecated),
            ("Archived",   self._sl_stat_archived),
            ("Total Applied", self._sl_stat_applied),
        ]
        for col, (label, var) in enumerate(stat_items):
            sf = ttk.Frame(stats_grid)
            sf.grid(row=0, column=col, padx=12, pady=4)
            ttk.Label(sf, textvariable=var, font=('Arial', 16, 'bold'),
                      foreground='#2563EB').pack()
            ttk.Label(sf, text=label, font=('Arial', 8),
                      foreground='#666666').pack()

        self._sl_stat_categories = tk.StringVar(value="")
        ttk.Label(stats_frame, textvariable=self._sl_stat_categories,
                  font=('Arial', 8), foreground='#444444',
                  justify='left').pack(anchor='w', pady=(6, 0))

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 3. LEARNINGS TABLE ───────────────────────────────────────────────
        table_frame = ttk.LabelFrame(f, text="📚 All Learnings",
                                     padding=(12, 8))
        table_frame.pack(fill='x', padx=16, pady=(0, 6))

        # Filter rows — split into two rows to avoid overcrowding
        filter_row1 = ttk.Frame(table_frame)
        filter_row1.pack(fill='x', pady=(0, 3))
        filter_row2 = ttk.Frame(table_frame)
        filter_row2.pack(fill='x', pady=(0, 6))

        # ── Row 1: Category, Status, Outcome, Source ─────────────────────
        ttk.Label(filter_row1, text="Category:", font=('Arial', 8)).pack(side='left')
        self._sl_filter_cat = tk.StringVar(value="All")
        cat_combo = ttk.Combobox(filter_row1, textvariable=self._sl_filter_cat,
                                 width=18, state='readonly',
                                 values=["All", "fact_correction", "business_lesson",
                                         "project_insight", "process_improvement",
                                         "mistake_learned", "best_practice",
                                         "client_preference", "technical_note", "general"])
        cat_combo.pack(side='left', padx=(4, 12))

        ttk.Label(filter_row1, text="Status:", font=('Arial', 8)).pack(side='left')
        self._sl_filter_status = tk.StringVar(value="active")
        status_combo = ttk.Combobox(filter_row1, textvariable=self._sl_filter_status,
                                    width=12, state='readonly',
                                    values=["All", "active", "deprecated", "archived"])
        status_combo.pack(side='left', padx=(4, 12))

        ttk.Label(filter_row1, text="Outcome:", font=('Arial', 8)).pack(side='left')
        self._sl_filter_outcome = tk.StringVar(value="All")
        outcome_combo = ttk.Combobox(filter_row1, textvariable=self._sl_filter_outcome,
                                     width=10, state='readonly',
                                     values=["All", "positive", "negative",
                                             "neutral", "unknown"])
        outcome_combo.pack(side='left', padx=(4, 12))

        ttk.Label(filter_row1, text="Source:", font=('Arial', 8)).pack(side='left')
        self._sl_filter_source = tk.StringVar(value="All")
        self._sl_source_combo = ttk.Combobox(filter_row1,
                                             textvariable=self._sl_filter_source,
                                             width=16, state='readonly',
                                             values=["All"])
        self._sl_source_combo.pack(side='left', padx=(4, 0))

        # ── Row 2: Search text, Semantic, Filter, Reset ───────────────────
        ttk.Label(filter_row2, text="Search:", font=('Arial', 8)).pack(side='left')
        self._sl_filter_search = tk.StringVar(value="")
        search_entry = ttk.Entry(filter_row2, textvariable=self._sl_filter_search, width=30)
        search_entry.pack(side='left', padx=(4, 8))
        ttk.Label(filter_row2,
                  text="(searches title, content, context, tags, source)",
                  font=('Arial', 7), foreground='gray').pack(side='left', padx=(0, 12))

        # Semantic search toggle — when on, the search box runs through
        # ChromaDB so "client emails" matches a learning titled "phone vs
        # email contact preferences" even though the words don't overlap.
        # When off, falls back to the substring matcher in _refresh_table.
        self._sl_semantic_search = tk.BooleanVar(value=False)
        ttk.Checkbutton(filter_row2, text="🧠 Semantic",
                        variable=self._sl_semantic_search,
                        command=lambda: _refresh_table()).pack(side='left',
                                                               padx=(0, 8))

        ttk.Button(filter_row2, text="🔍 Filter",
                   command=lambda: _refresh_table()).pack(side='left', padx=(0, 4))
        ttk.Button(filter_row2, text="↻ Reset",
                   command=lambda: _reset_filters()).pack(side='left')

        # Treeview
        columns = ('title', 'category', 'status', 'confidence', 'outcome',
                   'applied', 'created', 'source')
        tree_scroll = ttk.Scrollbar(table_frame, orient='vertical')
        self._sl_tree = ttk.Treeview(table_frame, columns=columns,
                                     show='headings', height=12,
                                     yscrollcommand=tree_scroll.set,
                                     selectmode='browse')
        tree_scroll.config(command=self._sl_tree.yview)

        col_cfg = [
            ('title',      'Title',      220, 'w'),
            ('category',   'Category',   120, 'w'),
            ('status',     'Status',     75,  'center'),
            ('confidence', 'Conf.',      55,  'center'),
            ('outcome',    'Outcome',    70,  'center'),
            ('applied',    'Applied',    55,  'center'),
            ('created',    'Created',    85,  'center'),
            ('source',     'Source',     90,  'w'),
        ]
        for col_id, heading, width, anchor in col_cfg:
            self._sl_tree.heading(col_id, text=heading,
                                  command=lambda c=col_id: _sort_column(c))
            self._sl_tree.column(col_id, width=width, anchor=anchor,
                                 minwidth=40)

        self._sl_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.pack(side='right', fill='y')

        self._sl_sort_col = 'created'
        self._sl_sort_rev = True
        self._sl_data_map = {}

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 4. DETAIL PANEL ──────────────────────────────────────────────────
        detail_frame = ttk.LabelFrame(f, text="📄 Learning Detail — select a row above",
                                      padding=(12, 8))
        detail_frame.pack(fill='x', padx=16, pady=(0, 6))

        self._sl_detail_title = tk.StringVar(value="")
        ttk.Label(detail_frame, textvariable=self._sl_detail_title,
                  font=('Arial', 10, 'bold'), foreground='#1E40AF',
                  wraplength=700).pack(anchor='w')

        self._sl_detail_meta = tk.StringVar(
            value="Select a learning from the table above to see its full details.")
        ttk.Label(detail_frame, textvariable=self._sl_detail_meta,
                  font=('Arial', 8), foreground='#666666',
                  wraplength=700, justify='left').pack(anchor='w', pady=(4, 6))

        ttk.Label(detail_frame, text="Content:", font=('Arial', 8, 'bold'),
                  foreground='#333333').pack(anchor='w')
        self._sl_detail_content = scrolledtext.ScrolledText(
            detail_frame, height=5, wrap='word', font=('Arial', 9),
            state='disabled', bg='#F9FAFB', relief='flat',
            borderwidth=1)
        self._sl_detail_content.pack(fill='x', pady=(2, 6))

        ttk.Label(detail_frame, text="Context (why this was learned):",
                  font=('Arial', 8, 'bold'), foreground='#333333').pack(anchor='w')
        self._sl_detail_context = scrolledtext.ScrolledText(
            detail_frame, height=3, wrap='word', font=('Arial', 9),
            state='disabled', bg='#FFFBEB', relief='flat',
            borderwidth=1)
        self._sl_detail_context.pack(fill='x', pady=(2, 6))

        self._sl_detail_supersession = tk.StringVar(value="")
        ttk.Label(detail_frame, textvariable=self._sl_detail_supersession,
                  font=('Arial', 8), foreground='#D97706',
                  wraplength=700).pack(anchor='w')

        id_row = ttk.Frame(detail_frame)
        id_row.pack(fill='x', pady=(4, 0))
        ttk.Label(id_row, text="ID:", font=('Arial', 8, 'bold'),
                  foreground='#999999').pack(side='left')
        self._sl_detail_id = tk.StringVar(value="")
        id_entry = ttk.Entry(id_row, textvariable=self._sl_detail_id,
                             state='readonly', font=('Arial', 8), width=40)
        id_entry.pack(side='left', padx=(4, 8))
        ttk.Button(id_row, text="📋 Copy ID",
                   command=lambda: _copy_id()).pack(side='left')

        ttk.Separator(f, orient='horizontal').pack(fill='x', padx=16, pady=6)

        # ── 5. ACTION BUTTONS ────────────────────────────────────────────────
        actions_frame = ttk.LabelFrame(f, text="⚡ Actions",
                                       padding=(12, 8))
        actions_frame.pack(fill='x', padx=16, pady=(0, 6))

        btn_row1 = ttk.Frame(actions_frame)
        btn_row1.pack(fill='x', pady=(0, 6))

        ttk.Button(btn_row1, text="↻  Refresh",
                   command=lambda: _refresh_all()).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row1, text="📦  Archive Selected",
                   command=lambda: _archive_selected()).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row1, text="🗑  Delete Selected",
                   command=lambda: _delete_selected()).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row1, text="🔄  Rebuild ChromaDB Index",
                   command=lambda: _reindex()).pack(side='left', padx=(0, 8))

        btn_row2 = ttk.Frame(actions_frame)
        btn_row2.pack(fill='x')

        ttk.Button(btn_row2, text="💾  Export to CSV",
                   command=lambda: _export_csv()).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row2, text="📂  Open JSON File",
                   command=lambda: _open_json_file()).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row2, text="📂  Open Learnings Folder",
                   command=lambda: _open_folder()).pack(side='left')

        # ── Row 3: editing, conflict detection, learning packs ──────────────
        btn_row3 = ttk.Frame(actions_frame)
        btn_row3.pack(fill='x', pady=(6, 0))

        ttk.Button(btn_row3, text="➕  New Learning",
                   command=lambda: _open_editor(None)).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row3, text="✏️  Edit Selected",
                   command=lambda: _edit_selected()).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row3, text="🚦  Detect Conflicts",
                   command=lambda: _open_conflict_dialog()).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row3, text="📤  Export Pack",
                   command=lambda: _export_pack()).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row3, text="📥  Import Pack",
                   command=lambda: _import_pack()).pack(side='left')

        ttk.Label(actions_frame, text=f"Storage: {_learnings_file}",
                  font=('Arial', 7), foreground='#999999').pack(anchor='w', pady=(6, 0))

        # ── Internal functions ───────────────────────────────────────────────

        def _reset_filters():
            self._sl_filter_cat.set("All")
            self._sl_filter_status.set("active")
            self._sl_filter_outcome.set("All")
            self._sl_filter_source.set("All")
            self._sl_filter_search.set("")
            self._sl_semantic_search.set(False)
            _refresh_table()

        def _refresh_all():
            _update_stats()
            _refresh_table()

        def _update_stats():
            learnings = _load_learnings()
            total     = len(learnings)
            active    = sum(1 for l in learnings if l.get('status') == 'active')
            dep       = sum(1 for l in learnings if l.get('status') == 'deprecated')
            arch      = sum(1 for l in learnings if l.get('status') == 'archived')
            applied   = sum(l.get('applied_count', 0) for l in learnings)

            self._sl_stat_total.set(str(total))
            self._sl_stat_active.set(str(active))
            self._sl_stat_deprecated.set(str(dep))
            self._sl_stat_archived.set(str(arch))
            self._sl_stat_applied.set(str(applied))

            cats = {}
            for l in learnings:
                c = l.get('category', 'general')
                cats[c] = cats.get(c, 0) + 1
            if cats:
                parts = [f"{c}: {n}" for c, n in
                         sorted(cats.items(), key=lambda x: -x[1])]
                self._sl_stat_categories.set("By category:  " + "  |  ".join(parts))
            else:
                self._sl_stat_categories.set("")

        def _refresh_table():
            learnings = _load_learnings()

            cat_filter     = self._sl_filter_cat.get()
            status_filter  = self._sl_filter_status.get()
            outcome_filter = self._sl_filter_outcome.get()
            source_filter  = self._sl_filter_source.get()
            search_text    = self._sl_filter_search.get().strip()
            semantic_on    = (self._sl_semantic_search.get()
                              and bool(search_text)
                              and SELF_LEARNING_AVAILABLE)

            # Dynamically populate the Source dropdown with values from the DB
            all_sources = sorted({
                l.get('source', 'operator') or 'operator'
                for l in learnings
                if l.get('source')
            })
            self._sl_source_combo['values'] = ["All"] + all_sources

            # Similarity scores get attached when semantic search ran.
            similarity_by_id: dict = {}

            if semantic_on:
                try:
                    matches = _sl_engine.check_learned(
                        search_text,
                        n_results=50,
                        active_only=(status_filter == "active"),
                        track_application=False,
                    )
                    similarity_by_id = {m["learning_id"]: m["similarity"]
                                        for m in matches}
                except Exception as exc:
                    print(f"Warning: semantic search failed: {exc}")
                    similarity_by_id = {}

            filtered = []
            for l in learnings:
                if cat_filter != "All" and l.get('category', 'general') != cat_filter:
                    continue
                if status_filter != "All" and l.get('status', 'active') != status_filter:
                    continue
                if outcome_filter != "All" and l.get('outcome', 'unknown') != outcome_filter:
                    continue
                if source_filter != "All" and l.get('source', 'operator') != source_filter:
                    continue
                if semantic_on:
                    if l['id'] not in similarity_by_id:
                        continue
                elif search_text:
                    haystack = (
                        f"{l.get('title', '')} {l.get('content', '')} "
                        f"{l.get('context', '')} {' '.join(l.get('tags', []))} "
                        f"{l.get('source', '')} {l.get('recorded_by', '')}"
                    ).lower()
                    if search_text.lower() not in haystack:
                        continue
                filtered.append(l)

            if semantic_on:
                # In semantic mode the natural sort order is similarity desc,
                # overriding the column-based sort.
                filtered.sort(
                    key=lambda l: similarity_by_id.get(l['id'], 0),
                    reverse=True)
            else:
                col = self._sl_sort_col
                rev = self._sl_sort_rev
                def sort_key(l):
                    if col == 'confidence':
                        return l.get('confidence', 0)
                    if col == 'applied':
                        return l.get('applied_count', 0)
                    return str(l.get(col, '')).lower()
                filtered.sort(key=sort_key, reverse=rev)

            self._sl_tree.delete(*self._sl_tree.get_children())
            self._sl_data_map.clear()

            status_icons = {'active': '✅', 'deprecated': '⚠️', 'archived': '📦'}
            outcome_icons = {'positive': '✅', 'negative': '❌',
                             'neutral': '➖', 'unknown': '❓'}

            for l in filtered:
                created = l.get('created_at', '')[:10]
                conf = f"{l.get('confidence', 0):.0%}"
                status_txt = status_icons.get(l.get('status', 'active'), '❓')
                outcome_txt = outcome_icons.get(l.get('outcome', 'unknown'), '❓')

                # In semantic mode, prefix the title with the similarity score
                # so the user sees how strong the match is at a glance.
                title_txt = l.get('title', 'Untitled')
                if semantic_on and l['id'] in similarity_by_id:
                    sim_pct = int(round(similarity_by_id[l['id']] * 100))
                    title_txt = f"[{sim_pct}%]  {title_txt}"

                iid = self._sl_tree.insert('', 'end', values=(
                    title_txt,
                    l.get('category', 'general'),
                    status_txt,
                    conf,
                    outcome_txt,
                    l.get('applied_count', 0),
                    created,
                    l.get('source', 'operator'),
                ))
                self._sl_data_map[iid] = l

        def _sort_column(col):
            if self._sl_sort_col == col:
                self._sl_sort_rev = not self._sl_sort_rev
            else:
                self._sl_sort_col = col
                self._sl_sort_rev = col == 'created'
            _refresh_table()

        def _on_select(event):
            sel = self._sl_tree.selection()
            if not sel:
                return
            iid = sel[0]
            l = self._sl_data_map.get(iid)
            if not l:
                return

            self._sl_detail_title.set(f"📌 {l.get('title', 'Untitled')}")

            tags_str = ', '.join(l.get('tags', []))
            meta_parts = [
                f"Category: {l.get('category', 'general')}",
                f"Status: {l.get('status', 'active')}",
                f"Source: {l.get('source', 'operator')}",
                f"Confidence: {l.get('confidence', 0):.0%}",
                f"Outcome: {l.get('outcome', 'unknown')}",
                f"Applied: {l.get('applied_count', 0)}x",
                f"Created: {l.get('created_at', '?')}",
                f"Updated: {l.get('updated_at', '?')}",
            ]
            if tags_str:
                meta_parts.append(f"Tags: {tags_str}")
            self._sl_detail_meta.set("  |  ".join(meta_parts))

            self._sl_detail_content.config(state='normal')
            self._sl_detail_content.delete('1.0', 'end')
            self._sl_detail_content.insert('1.0', l.get('content', ''))
            self._sl_detail_content.config(state='disabled')

            self._sl_detail_context.config(state='normal')
            self._sl_detail_context.delete('1.0', 'end')
            self._sl_detail_context.insert('1.0',
                                           l.get('context', '(no context recorded)'))
            self._sl_detail_context.config(state='disabled')

            sup_parts = []
            if l.get('supersedes'):
                sup_parts.append(f"↻ Supersedes: {l['supersedes'][:12]}…")
            if l.get('superseded_by'):
                sup_parts.append(
                    f"⚠ SUPERSEDED BY: {l['superseded_by'][:12]}… "
                    f"— prefer the newer version")
            self._sl_detail_supersession.set("  |  ".join(sup_parts))

            self._sl_detail_id.set(l.get('id', ''))

        self._sl_tree.bind('<<TreeviewSelect>>', _on_select)

        def _copy_id():
            lid = self._sl_detail_id.get()
            if lid:
                self.root.clipboard_clear()
                self.root.clipboard_append(lid)
                self.status_var.set(f"Copied learning ID: {lid[:12]}…")

        def _archive_selected():
            sel = self._sl_tree.selection()
            if not sel:
                messagebox.showinfo("No Selection",
                                    "Select a learning from the table first.")
                return
            l = self._sl_data_map.get(sel[0])
            if not l:
                return
            if not messagebox.askyesno(
                    "Archive Learning",
                    f"Archive \"{l.get('title', 'Untitled')}\"?\n\n"
                    "It will be hidden from Claude's search results "
                    "but kept for historical reference."):
                return
            if SELF_LEARNING_AVAILABLE:
                try:
                    _sl_engine.update_learning(l['id'], {'status': 'archived'})
                    self.status_var.set(f"Archived: {l.get('title', '')[:40]}")
                    _refresh_all()
                except Exception as exc:
                    messagebox.showerror("Error", f"Failed to archive: {exc}")
            else:
                messagebox.showinfo(
                    "Unavailable",
                    "self_learning.py not found — cannot modify learnings "
                    "from the GUI.\nUse Claude: "
                    "update_learning(id, {status: 'archived'})")

        def _delete_selected():
            sel = self._sl_tree.selection()
            if not sel:
                messagebox.showinfo("No Selection",
                                    "Select a learning from the table first.")
                return
            l = self._sl_data_map.get(sel[0])
            if not l:
                return
            if not messagebox.askyesno(
                    "Delete Learning",
                    f"PERMANENTLY delete \"{l.get('title', 'Untitled')}\"?\n\n"
                    "This cannot be undone. Consider archiving instead.",
                    icon='warning'):
                return
            if SELF_LEARNING_AVAILABLE:
                # Two-phase delete: JSON cleanup then ChromaDB cleanup.
                # delete_learning() raises ChromaIndexError if the second
                # phase fails — JSON state is already saved at that point,
                # so we warn the user about the orphan and offer reindex.
                try:
                    _sl_engine.delete_learning(l['id'])
                    self.status_var.set(f"Deleted: {l.get('title', '')[:40]}")
                    _refresh_all()
                except _sl_engine.ChromaIndexError as exc:
                    # JSON delete succeeded, ChromaDB delete failed.
                    # The learning is gone from the source of truth, but
                    # an orphan embedding remains in the search index.
                    self.status_var.set(
                        f"Deleted (orphan in index): "
                        f"{l.get('title', '')[:30]}")
                    _refresh_all()
                    self._show_partial_delete_dialog(str(exc))
                except Exception as exc:
                    messagebox.showerror("Error", f"Failed to delete: {exc}")
            else:
                messagebox.showinfo(
                    "Unavailable",
                    "self_learning.py not found — cannot delete learnings "
                    "from the GUI.\nUse Claude: delete_learning(id)")

        def _reindex():
            if not SELF_LEARNING_AVAILABLE:
                messagebox.showinfo("Unavailable",
                                    "self_learning.py not found — cannot reindex.")
                return
            if not messagebox.askyesno(
                    "Rebuild Index",
                    "Rebuild the ChromaDB learnings index from the JSON file?\n\n"
                    "This is safe — it wipes and rebuilds the search index.\n"
                    "No learnings are deleted."):
                return
            try:
                count = _sl_engine.reindex_all_learnings()
                messagebox.showinfo("Reindex Complete",
                                    f"Rebuilt ChromaDB index with {count} "
                                    f"active learnings.")
                self.status_var.set(f"Reindexed {count} learnings")
            except Exception as exc:
                messagebox.showerror("Reindex Failed", str(exc))

        def _export_csv():
            learnings = _load_learnings()
            if not learnings:
                messagebox.showinfo("Empty", "No learnings to export.")
                return
            dest = filedialog.asksaveasfilename(
                defaultextension='.csv',
                filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
                initialfile='ai_prowler_learnings.csv')
            if not dest:
                return
            try:
                import csv
                with open(dest, 'w', newline='', encoding='utf-8') as fh:
                    writer = csv.writer(fh)
                    writer.writerow([
                        'ID', 'Title', 'Content', 'Category', 'Context',
                        'Source', 'Confidence', 'Tags', 'Status',
                        'Outcome', 'Applied Count', 'Created', 'Updated',
                        'Supersedes', 'Superseded By'])
                    for l in learnings:
                        writer.writerow([
                            l.get('id', ''),
                            l.get('title', ''),
                            l.get('content', ''),
                            l.get('category', ''),
                            l.get('context', ''),
                            l.get('source', ''),
                            l.get('confidence', ''),
                            ','.join(l.get('tags', [])),
                            l.get('status', ''),
                            l.get('outcome', ''),
                            l.get('applied_count', 0),
                            l.get('created_at', ''),
                            l.get('updated_at', ''),
                            l.get('supersedes', ''),
                            l.get('superseded_by', ''),
                        ])
                self.status_var.set(
                    f"Exported {len(learnings)} learnings to {dest}")
                messagebox.showinfo(
                    "Export Complete",
                    f"Exported {len(learnings)} learnings to:\n{dest}")
            except Exception as exc:
                messagebox.showerror("Export Failed", str(exc))

        def _open_json_file():
            if _learnings_file.exists():
                import subprocess as _sp
                import platform as _pf
                if _pf.system() == 'Windows':
                    os.startfile(str(_learnings_file))
                elif _pf.system() == 'Darwin':
                    _sp.Popen(['open', str(_learnings_file)])
                else:
                    _sp.Popen(['xdg-open', str(_learnings_file)])
            else:
                messagebox.showinfo(
                    "Not Found",
                    f"Learnings file does not exist yet:\n{_learnings_file}\n\n"
                    "It will be created the first time Claude records a learning.")

        def _open_folder():
            folder = _learnings_file.parent
            folder.mkdir(parents=True, exist_ok=True)
            import subprocess as _sp
            import platform as _pf
            if _pf.system() == 'Windows':
                os.startfile(str(folder))
            elif _pf.system() == 'Darwin':
                _sp.Popen(['open', str(folder)])
            else:
                _sp.Popen(['xdg-open', str(folder)])

        # ════════════════════════════════════════════════════════════════════
        # NEW FEATURES — inline editing, conflict detection, packs
        # ════════════════════════════════════════════════════════════════════

        # Constants for the editor — kept in one place so the form schema
        # stays in lockstep with what self_learning.update_learning accepts.
        _CATEGORIES = ["fact_correction", "business_lesson", "project_insight",
                       "process_improvement", "mistake_learned", "best_practice",
                       "client_preference", "technical_note", "general"]
        _STATUSES   = ["active", "deprecated", "archived"]
        _OUTCOMES   = ["positive", "negative", "neutral", "unknown"]
        _SOURCES    = ["operator", "claude_detected", "project_review",
                       "post_mortem", "research", "observation"]

        def _edit_selected():
            """Edit the learning currently selected in the table."""
            sel = self._sl_tree.selection()
            if not sel:
                messagebox.showinfo("No Selection",
                                    "Select a learning from the table first.")
                return
            l = self._sl_data_map.get(sel[0])
            if not l:
                return
            _open_editor(l)

        def _open_editor(existing_learning):
            """
            Open the modal editor. Pass an existing learning dict to edit it,
            or None to create a new one.
            """
            if not SELF_LEARNING_AVAILABLE:
                messagebox.showinfo(
                    "Unavailable",
                    "self_learning.py not found — cannot create or edit "
                    "learnings from the GUI.")
                return

            is_new = existing_learning is None
            dlg = tk.Toplevel(self.root)
            dlg.title("New Learning" if is_new else "Edit Learning")
            dlg.transient(self.root)
            dlg.grab_set()
            dlg.geometry("680x600")

            outer = ttk.Frame(dlg, padding=12)
            outer.pack(fill='both', expand=True)

            ttk.Label(outer,
                      text=("Create a new learning" if is_new
                            else "Edit this learning"),
                      font=('Arial', 12, 'bold')).pack(anchor='w', pady=(0, 8))

            # ── Form fields ──────────────────────────────────────────────────
            form = ttk.Frame(outer)
            form.pack(fill='both', expand=True)

            # Title
            ttk.Label(form, text="Title:",
                      font=('Arial', 9, 'bold')).grid(row=0, column=0,
                                                       sticky='w', pady=4)
            title_var = tk.StringVar(value=(existing_learning or {}).get('title', ''))
            ttk.Entry(form, textvariable=title_var, width=70).grid(
                row=0, column=1, sticky='ew', padx=(8, 0), pady=4)

            # Content
            ttk.Label(form, text="Content:",
                      font=('Arial', 9, 'bold')).grid(row=1, column=0,
                                                       sticky='nw', pady=4)
            content_text = scrolledtext.ScrolledText(form, height=6, wrap='word',
                                                     font=('Arial', 9))
            content_text.grid(row=1, column=1, sticky='ew', padx=(8, 0), pady=4)
            content_text.insert('1.0', (existing_learning or {}).get('content', ''))

            # Context
            ttk.Label(form, text="Context:",
                      font=('Arial', 9, 'bold')).grid(row=2, column=0,
                                                       sticky='nw', pady=4)
            context_text = scrolledtext.ScrolledText(form, height=3, wrap='word',
                                                     font=('Arial', 9))
            context_text.grid(row=2, column=1, sticky='ew', padx=(8, 0), pady=4)
            context_text.insert('1.0', (existing_learning or {}).get('context', ''))

            # Category / Status row
            cat_row = ttk.Frame(form)
            cat_row.grid(row=3, column=1, sticky='ew', padx=(8, 0), pady=4)

            ttk.Label(cat_row, text="Category:", font=('Arial', 9)).pack(side='left')
            cat_var = tk.StringVar(
                value=(existing_learning or {}).get('category', 'general'))
            ttk.Combobox(cat_row, textvariable=cat_var, values=_CATEGORIES,
                         width=20, state='readonly').pack(side='left', padx=(4, 12))

            ttk.Label(cat_row, text="Status:", font=('Arial', 9)).pack(side='left')
            status_var = tk.StringVar(
                value=(existing_learning or {}).get('status', 'active'))
            ttk.Combobox(cat_row, textvariable=status_var, values=_STATUSES,
                         width=12, state='readonly').pack(side='left', padx=(4, 0))

            # Outcome / Confidence row
            out_row = ttk.Frame(form)
            out_row.grid(row=4, column=1, sticky='ew', padx=(8, 0), pady=4)

            ttk.Label(out_row, text="Outcome:", font=('Arial', 9)).pack(side='left')
            outcome_var = tk.StringVar(
                value=(existing_learning or {}).get('outcome', 'unknown'))
            ttk.Combobox(out_row, textvariable=outcome_var, values=_OUTCOMES,
                         width=12, state='readonly').pack(side='left', padx=(4, 12))

            ttk.Label(out_row, text="Confidence:",
                      font=('Arial', 9)).pack(side='left')
            conf_var = tk.DoubleVar(
                value=float((existing_learning or {}).get('confidence', 0.8)))
            conf_scale = ttk.Scale(out_row, from_=0.0, to=1.0, orient='horizontal',
                                   variable=conf_var, length=160)
            conf_scale.pack(side='left', padx=(4, 4))
            conf_label = ttk.Label(out_row, text=f"{conf_var.get():.0%}",
                                   width=6, font=('Arial', 9, 'bold'))
            conf_label.pack(side='left')
            def _update_conf(*_):
                conf_label.config(text=f"{conf_var.get():.0%}")
            conf_var.trace_add('write', _update_conf)

            # Source (only editable when creating new — source is metadata
            # about how the learning entered the system, not the user's
            # business preference)
            if is_new:
                src_row = ttk.Frame(form)
                src_row.grid(row=5, column=1, sticky='ew', padx=(8, 0), pady=4)
                ttk.Label(src_row, text="Source:",
                          font=('Arial', 9)).pack(side='left')
                source_var = tk.StringVar(value='operator')
                ttk.Combobox(src_row, textvariable=source_var, values=_SOURCES,
                             width=18, state='readonly').pack(side='left',
                                                              padx=(4, 0))
            else:
                source_var = tk.StringVar(
                    value=(existing_learning or {}).get('source', 'operator'))

            # Tags
            ttk.Label(form, text="Tags:",
                      font=('Arial', 9, 'bold')).grid(row=6, column=0,
                                                       sticky='w', pady=4)
            tags_var = tk.StringVar(
                value=', '.join((existing_learning or {}).get('tags', [])))
            ttk.Entry(form, textvariable=tags_var, width=70).grid(
                row=6, column=1, sticky='ew', padx=(8, 0), pady=4)
            ttk.Label(form, text="(comma-separated)",
                      font=('Arial', 8), foreground='#888888').grid(
                row=7, column=1, sticky='w', padx=(8, 0))

            form.columnconfigure(1, weight=1)

            # Read-only metadata for existing learnings
            if not is_new:
                meta_frame = ttk.LabelFrame(outer, text="Metadata (read-only)",
                                            padding=(8, 4))
                meta_frame.pack(fill='x', pady=(8, 0))
                meta_lines = [
                    f"ID: {existing_learning.get('id', '')}",
                    f"Created: {existing_learning.get('created_at', '?')}",
                    f"Updated: {existing_learning.get('updated_at', '?')}",
                    f"Applied: {existing_learning.get('applied_count', 0)}x",
                    f"Source:  {existing_learning.get('source', 'operator')}",
                ]
                ttk.Label(meta_frame, text=' | '.join(meta_lines),
                          font=('Arial', 8), foreground='#666666').pack(anchor='w')

            # ── Buttons ──────────────────────────────────────────────────────
            btn_row = ttk.Frame(outer)
            btn_row.pack(fill='x', pady=(12, 0))

            def _do_save():
                title_v   = title_var.get().strip()
                content_v = content_text.get('1.0', 'end-1c').strip()
                if not title_v or not content_v:
                    messagebox.showwarning(
                        "Incomplete",
                        "Title and Content are required.",
                        parent=dlg)
                    return
                tags_list = [t.strip().lower() for t in tags_var.get().split(',')
                             if t.strip()]

                try:
                    if is_new:
                        _sl_engine.record_learning(
                            title=title_v,
                            content=content_v,
                            category=cat_var.get(),
                            context=context_text.get('1.0', 'end-1c').strip(),
                            source=source_var.get(),
                            confidence=float(conf_var.get()),
                            tags=tags_list,
                            outcome=outcome_var.get(),
                        )
                        self.status_var.set(f"Created: {title_v[:40]}")
                    else:
                        _sl_engine.update_learning(
                            existing_learning['id'],
                            {
                                'title':      title_v,
                                'content':    content_v,
                                'category':   cat_var.get(),
                                'context':    context_text.get('1.0', 'end-1c').strip(),
                                'confidence': float(conf_var.get()),
                                'tags':       tags_list,
                                'status':     status_var.get(),
                                'outcome':    outcome_var.get(),
                            })
                        self.status_var.set(f"Updated: {title_v[:40]}")
                    dlg.destroy()
                    _refresh_all()
                except Exception as exc:
                    messagebox.showerror("Save Failed", str(exc), parent=dlg)

            ttk.Button(btn_row,
                       text=("Create" if is_new else "Save Changes"),
                       command=_do_save,
                       style='Accent.TButton').pack(side='right', padx=(8, 0))
            ttk.Button(btn_row, text="Cancel",
                       command=dlg.destroy).pack(side='right')

        # ────────────────────────────────────────────────────────────────────
        # CONFLICT DETECTION DIALOG
        # ────────────────────────────────────────────────────────────────────

        def _open_conflict_dialog():
            """Open the conflict detection modal with adjustable threshold."""
            if not SELF_LEARNING_AVAILABLE:
                messagebox.showinfo(
                    "Unavailable",
                    "self_learning.py not found — cannot detect conflicts.")
                return

            dlg = tk.Toplevel(self.root)
            dlg.title("Detect Conflicts")
            dlg.transient(self.root)
            dlg.grab_set()
            dlg.geometry("860x680")

            outer = ttk.Frame(dlg, padding=12)
            outer.pack(fill='both', expand=True)

            ttk.Label(outer, text="🚦  Conflict Detection",
                      font=('Arial', 14, 'bold')).pack(anchor='w')
            ttk.Label(outer, font=('Arial', 9), foreground='#444444',
                      justify='left',
                      text=("Finds pairs of active learnings that look like they "
                            "might contradict each other,\nbased on how similar "
                            "their meaning is. Adjust the slider to tune sensitivity.")
                      ).pack(anchor='w', pady=(2, 10))

            # ── Sensitivity slider ───────────────────────────────────────────
            slider_frame = ttk.LabelFrame(outer, text="Sensitivity threshold",
                                          padding=(10, 8))
            slider_frame.pack(fill='x', pady=(0, 10))

            current_threshold = _sl_engine.get_conflict_threshold()
            thresh_var = tk.DoubleVar(value=current_threshold)

            slider_row = ttk.Frame(slider_frame)
            slider_row.pack(fill='x')

            ttk.Label(slider_row, text="Loose\n(more flags)",
                      font=('Arial', 8), foreground='#666666',
                      justify='center').pack(side='left', padx=(0, 8))

            sens_scale = ttk.Scale(
                slider_row,
                from_=_sl_engine.MIN_CONFLICT_THRESHOLD,
                to=_sl_engine.MAX_CONFLICT_THRESHOLD,
                orient='horizontal', variable=thresh_var, length=380)
            sens_scale.pack(side='left', fill='x', expand=True)

            ttk.Label(slider_row, text="Strict\n(near-duplicates)",
                      font=('Arial', 8), foreground='#666666',
                      justify='center').pack(side='left', padx=(8, 0))

            value_lbl = ttk.Label(slider_frame,
                                  text=f"Threshold: {thresh_var.get():.2f}",
                                  font=('Arial', 10, 'bold'),
                                  foreground='#1E40AF')
            value_lbl.pack(anchor='center', pady=(4, 0))

            ttk.Label(slider_frame, font=('Arial', 8),
                      foreground='#555555', justify='left',
                      wraplength=780,
                      text=(
                          "Recommended: 0.75 — flags learnings that talk about "
                          "the same subject and likely contradict each other.   "
                          "Lower (~0.60): catches subtler overlaps but produces "
                          "more false positives — pairs that are merely related.   "
                          "Higher (~0.85): only near-duplicates. Use when your "
                          "knowledge base is large and you only want clear conflicts."
                      )).pack(anchor='w', pady=(8, 0))

            # ── Pairs list ───────────────────────────────────────────────────
            pairs_frame = ttk.LabelFrame(outer, text="Flagged pairs", padding=(8, 6))
            pairs_frame.pack(fill='both', expand=True, pady=(4, 0))

            pairs_status = tk.StringVar(value="Click 'Re-scan' to detect conflicts.")
            ttk.Label(pairs_frame, textvariable=pairs_status,
                      font=('Arial', 9), foreground='#444444').pack(anchor='w',
                                                                    pady=(0, 6))

            # Scrollable canvas for pair rows
            list_canvas = tk.Canvas(pairs_frame, highlightthickness=0)
            list_scroll = ttk.Scrollbar(pairs_frame, orient='vertical',
                                        command=list_canvas.yview)
            list_canvas.configure(yscrollcommand=list_scroll.set)
            list_canvas.pack(side='left', fill='both', expand=True)
            list_scroll.pack(side='right', fill='y')

            pairs_inner = ttk.Frame(list_canvas)
            list_canvas.create_window((0, 0), window=pairs_inner, anchor='nw')

            def _resize_inner(_):
                list_canvas.configure(scrollregion=list_canvas.bbox("all"))
            pairs_inner.bind('<Configure>', _resize_inner)

            current_pairs = []  # holds the most recent scan result

            def _render_pairs():
                # Clear and re-render based on the current threshold filter
                for child in pairs_inner.winfo_children():
                    child.destroy()
                threshold = thresh_var.get()
                visible = [p for p in current_pairs
                           if p['similarity'] >= threshold]
                if not visible:
                    if current_pairs:
                        pairs_status.set(
                            f"No pairs at or above {threshold:.2f}. "
                            f"({len(current_pairs)} pair(s) below threshold — "
                            "lower the slider to see them.)")
                    else:
                        pairs_status.set("No conflicts found. ✅")
                    return
                pairs_status.set(
                    f"Showing {len(visible)} pair(s) at or above {threshold:.2f}.")

                for pair in visible:
                    _render_one_pair(pair)

            def _render_one_pair(pair):
                a = pair['a']; b = pair['b']; sim = pair['similarity']
                row = ttk.LabelFrame(pairs_inner,
                                     text=f"Similarity: {sim:.0%}",
                                     padding=(8, 6))
                row.pack(fill='x', padx=4, pady=4)

                cols = ttk.Frame(row)
                cols.pack(fill='x')

                def _side(parent, learning, label):
                    box = ttk.Frame(parent, padding=(6, 4),
                                    relief='solid', borderwidth=1)
                    box.pack(side='left', fill='both', expand=True, padx=4)
                    ttk.Label(box, text=label, font=('Arial', 8, 'bold'),
                              foreground='#1E40AF').pack(anchor='w')
                    ttk.Label(box, text=learning.get('title', 'Untitled'),
                              font=('Arial', 9, 'bold'),
                              wraplength=320, justify='left').pack(anchor='w')
                    ttk.Label(box, text=learning.get('content', '')[:280] +
                              ('…' if len(learning.get('content', '')) > 280 else ''),
                              font=('Arial', 8), foreground='#444444',
                              wraplength=320, justify='left').pack(anchor='w',
                                                                   pady=(2, 0))
                    ttk.Label(box,
                              text=f"category: {learning.get('category', 'general')}  •  "
                                   f"created: {learning.get('created_at', '')[:10]}",
                              font=('Arial', 7),
                              foreground='#888888').pack(anchor='w',
                                                         pady=(4, 0))

                _side(cols, a, "A")
                _side(cols, b, "B")

                # Per-pair actions
                act_row = ttk.Frame(row)
                act_row.pack(fill='x', pady=(6, 0))

                def _supersede(winner, loser):
                    """Mark loser as deprecated, link superseded_by → winner.id."""
                    if not messagebox.askyesno(
                            "Confirm Supersede",
                            f"Keep \"{winner.get('title', '?')}\" as the active "
                            f"learning, and mark \"{loser.get('title', '?')}\" "
                            "as deprecated?",
                            parent=dlg):
                        return
                    try:
                        _sl_engine.update_learning(
                            loser['id'],
                            {'status': 'deprecated'})
                        # Manually patch the supersedes/superseded_by linkage
                        # by reading + writing the JSON file directly. The
                        # update_learning API doesn't accept those fields.
                        import json as _j
                        f = _learnings_file
                        data = _j.loads(f.read_text(encoding='utf-8'))
                        for ll in data['learnings']:
                            if ll['id'] == loser['id']:
                                ll['superseded_by'] = winner['id']
                            elif ll['id'] == winner['id']:
                                if not ll.get('supersedes'):
                                    ll['supersedes'] = loser['id']
                        f.write_text(_j.dumps(data, indent=2,
                                              ensure_ascii=False),
                                     encoding='utf-8')
                        # Reindex both so ChromaDB metadata stays in sync
                        _sl_engine._index_learning(
                            next(ll for ll in data['learnings']
                                 if ll['id'] == loser['id']))
                        _sl_engine._index_learning(
                            next(ll for ll in data['learnings']
                                 if ll['id'] == winner['id']))
                        _do_rescan()
                        _refresh_all()
                    except Exception as exc:
                        messagebox.showerror("Supersede Failed", str(exc),
                                             parent=dlg)

                def _dismiss_pair():
                    try:
                        _sl_engine.dismiss_conflict(a['id'], b['id'])
                        _do_rescan()
                    except Exception as exc:
                        messagebox.showerror("Dismiss Failed", str(exc),
                                             parent=dlg)

                def _edit_a():
                    _open_editor(a); _do_rescan(); _refresh_all()
                def _edit_b():
                    _open_editor(b); _do_rescan(); _refresh_all()

                ttk.Button(act_row, text="A supersedes B",
                           command=lambda: _supersede(a, b)).pack(
                               side='left', padx=(0, 4))
                ttk.Button(act_row, text="B supersedes A",
                           command=lambda: _supersede(b, a)).pack(
                               side='left', padx=(0, 4))
                ttk.Button(act_row, text="✏️  Edit A",
                           command=_edit_a).pack(side='left', padx=(0, 4))
                ttk.Button(act_row, text="✏️  Edit B",
                           command=_edit_b).pack(side='left', padx=(0, 4))
                ttk.Button(act_row, text="Not a conflict",
                           command=_dismiss_pair).pack(side='left', padx=(8, 0))

            def _do_rescan():
                pairs_status.set("Scanning…")
                dlg.update_idletasks()
                try:
                    pairs = _sl_engine.find_conflicts(
                        threshold=_sl_engine.MIN_CONFLICT_THRESHOLD)
                    # Always pull at the floor so the slider can filter live
                    # without re-querying.
                    current_pairs.clear()
                    current_pairs.extend(pairs)
                    _render_pairs()
                except Exception as exc:
                    pairs_status.set(f"Scan failed: {exc}")

            # Live re-render when slider moves (no re-scan needed)
            def _on_slider(*_):
                value_lbl.config(text=f"Threshold: {thresh_var.get():.2f}")
                _render_pairs()
            thresh_var.trace_add('write', _on_slider)

            def _save_default():
                saved = _sl_engine.set_conflict_threshold(thresh_var.get())
                self.status_var.set(
                    f"Default conflict threshold saved: {saved:.2f}")

            # ── Bottom button row ────────────────────────────────────────────
            btm = ttk.Frame(outer)
            btm.pack(fill='x', pady=(10, 0))
            ttk.Button(btm, text="🔍  Re-scan",
                       command=_do_rescan).pack(side='left')
            ttk.Button(btm, text="💾  Save as default",
                       command=_save_default).pack(side='left', padx=(8, 0))
            ttk.Button(btm, text="Close",
                       command=dlg.destroy).pack(side='right')

            # Initial scan
            dlg.after(50, _do_rescan)

        # ────────────────────────────────────────────────────────────────────
        # EXPORT / IMPORT LEARNING PACKS
        # ────────────────────────────────────────────────────────────────────

        def _export_pack():
            if not SELF_LEARNING_AVAILABLE:
                messagebox.showinfo(
                    "Unavailable",
                    "self_learning.py not found — cannot export pack.")
                return

            # Quick options dialog
            opt = tk.Toplevel(self.root)
            opt.title("Export Learning Pack")
            opt.transient(self.root)
            opt.grab_set()
            opt.geometry("460x230")

            box = ttk.Frame(opt, padding=14)
            box.pack(fill='both', expand=True)

            ttk.Label(box, text="📤  Export Learning Pack",
                      font=('Arial', 12, 'bold')).pack(anchor='w', pady=(0, 6))
            ttk.Label(box, font=('Arial', 9), foreground='#444444',
                      wraplength=420, justify='left',
                      text=("Saves your learnings as a single .aiplearn file "
                            "you can share with another AI-Prowler instance "
                            "or keep as a backup.")
                      ).pack(anchor='w', pady=(0, 10))

            include_inactive_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(box,
                            text="Include deprecated and archived learnings (full history backup)",
                            variable=include_inactive_var).pack(anchor='w')

            def _do_export():
                opt.destroy()
                from datetime import datetime as _dt
                stamp = _dt.now().strftime("%Y%m%d_%H%M%S")
                dest = filedialog.asksaveasfilename(
                    defaultextension=".aiplearn",
                    initialfile=f"ai_prowler_learnings_{stamp}.aiplearn",
                    filetypes=[("AI-Prowler learning pack", "*.aiplearn"),
                               ("JSON files", "*.json"),
                               ("All files", "*.*")])
                if not dest:
                    return
                try:
                    result = _sl_engine.export_learnings(
                        dest,
                        include_inactive=include_inactive_var.get())
                    self.status_var.set(
                        f"Exported {result['exported']} learnings to {dest}")
                    messagebox.showinfo(
                        "Export Complete",
                        f"Exported {result['exported']} learning(s) to:\n{dest}")
                except Exception as exc:
                    messagebox.showerror("Export Failed", str(exc))

            btn_row = ttk.Frame(box)
            btn_row.pack(fill='x', pady=(14, 0))
            ttk.Button(btn_row, text="Choose location…",
                       command=_do_export,
                       style='Accent.TButton').pack(side='right', padx=(8, 0))
            ttk.Button(btn_row, text="Cancel",
                       command=opt.destroy).pack(side='right')

        def _import_pack():
            if not SELF_LEARNING_AVAILABLE:
                messagebox.showinfo(
                    "Unavailable",
                    "self_learning.py not found — cannot import pack.")
                return

            src = filedialog.askopenfilename(
                title="Select learning pack to import",
                filetypes=[("AI-Prowler learning pack", "*.aiplearn"),
                           ("JSON files", "*.json"),
                           ("All files", "*.*")])
            if not src:
                return

            # Options dialog
            opt = tk.Toplevel(self.root)
            opt.title("Import Learning Pack")
            opt.transient(self.root)
            opt.grab_set()
            opt.geometry("560x340")

            box = ttk.Frame(opt, padding=14)
            box.pack(fill='both', expand=True)

            ttk.Label(box, text="📥  Import Learning Pack",
                      font=('Arial', 12, 'bold')).pack(anchor='w', pady=(0, 6))
            ttk.Label(box, text=f"Source:  {src}",
                      font=('Arial', 8), foreground='#666666',
                      wraplength=520, justify='left').pack(anchor='w', pady=(0, 10))

            mode_var = tk.StringVar(value='merge')

            ttk.Label(box, text="How should existing learnings be handled?",
                      font=('Arial', 9, 'bold')).pack(anchor='w')

            ttk.Radiobutton(box, variable=mode_var, value='merge',
                            text="Merge (recommended): add new learnings, "
                                 "ask before overwriting existing ones"
                            ).pack(anchor='w', pady=(4, 0))
            ttk.Radiobutton(box, variable=mode_var, value='append',
                            text="Append: copy in with fresh IDs, never "
                                 "overwrite existing data"
                            ).pack(anchor='w', pady=(2, 0))
            ttk.Radiobutton(box, variable=mode_var, value='replace',
                            text="⚠ Replace: WIPE existing learnings, "
                                 "use only the imported pack"
                            ).pack(anchor='w', pady=(2, 0))

            ttk.Label(box, font=('Arial', 8), foreground='#888888',
                      wraplength=520, justify='left',
                      text=("Merge: per-ID conflicts open a dialog so you can "
                            "pick keep-mine, take-theirs, or keep-both.   "
                            "Append: safe but you can't merge updates by ID later.   "
                            "Replace: last resort — there's no undo.")
                      ).pack(anchor='w', pady=(8, 0))

            def _resolver(local, incoming):
                """Per-collision dialog — runs in the import thread."""
                pick = {'val': 'keep_local'}
                d = tk.Toplevel(opt)
                d.title("ID Collision")
                d.transient(opt); d.grab_set()
                d.geometry("700x420")
                p = ttk.Frame(d, padding=12); p.pack(fill='both', expand=True)
                ttk.Label(p, text="ID collision — same learning ID exists locally",
                          font=('Arial', 11, 'bold')).pack(anchor='w')
                ttk.Label(p, text=f"ID: {local.get('id', '')}",
                          font=('Arial', 8), foreground='#888888').pack(anchor='w',
                                                                        pady=(0, 8))

                def _show_one(parent, lr, label):
                    fr = ttk.LabelFrame(parent, text=label, padding=(8, 4))
                    fr.pack(fill='x', pady=4)
                    ttk.Label(fr, text=lr.get('title', 'Untitled'),
                              font=('Arial', 10, 'bold')).pack(anchor='w')
                    ttk.Label(fr, text=lr.get('content', '')[:240] +
                              ('…' if len(lr.get('content', '')) > 240 else ''),
                              font=('Arial', 9), foreground='#444444',
                              wraplength=620, justify='left').pack(anchor='w')
                    ttk.Label(fr,
                              text=f"category: {lr.get('category', 'general')}  •  "
                                   f"updated: {lr.get('updated_at', '?')}",
                              font=('Arial', 7),
                              foreground='#888888').pack(anchor='w', pady=(4, 0))

                _show_one(p, local, "Local (current)")
                _show_one(p, incoming, "Incoming (from pack)")

                br = ttk.Frame(p); br.pack(fill='x', pady=(10, 0))

                def _set(v):
                    pick['val'] = v
                    d.destroy()

                ttk.Button(br, text="Keep local",
                           command=lambda: _set('keep_local')).pack(side='left')
                ttk.Button(br, text="Take incoming",
                           command=lambda: _set('take_incoming')).pack(side='left',
                                                                        padx=(8, 0))
                ttk.Button(br, text="Keep both (supersede)",
                           command=lambda: _set('supersede')).pack(side='left',
                                                                    padx=(8, 0))
                d.wait_window()
                return pick['val']

            def _do_import():
                mode = mode_var.get()
                if mode == 'replace':
                    if not messagebox.askyesno(
                            "Confirm Replace",
                            "REPLACE will permanently delete every learning "
                            "currently in your knowledge base and use only the "
                            "imported pack.\n\nThis cannot be undone. Continue?",
                            icon='warning', parent=opt):
                        return
                opt.destroy()
                try:
                    result = _sl_engine.import_learnings(
                        src, mode=mode,
                        on_conflict='ask',
                        conflict_resolver=_resolver)
                    parts = []
                    if result.get('added'):       parts.append(f"{result['added']} added")
                    if result.get('updated'):     parts.append(f"{result['updated']} updated")
                    if result.get('superseded'):  parts.append(f"{result['superseded']} superseded")
                    if result.get('skipped'):     parts.append(f"{result['skipped']} skipped")
                    if result.get('replaced_total') is not None:
                        parts.append(f"{result['replaced_total']} total after replace")
                    summary_txt = ", ".join(parts) if parts else "no changes"
                    self.status_var.set(f"Import: {summary_txt}")
                    msg = f"Import complete: {summary_txt}."
                    if result.get('errors'):
                        msg += "\n\nWarnings:\n" + "\n".join(result['errors'][:8])
                    messagebox.showinfo("Import Complete", msg)
                    _refresh_all()
                except Exception as exc:
                    messagebox.showerror("Import Failed", str(exc))

            btn_row = ttk.Frame(box)
            btn_row.pack(fill='x', side='bottom', pady=(14, 0))
            ttk.Button(btn_row, text="Import",
                       command=_do_import,
                       style='Accent.TButton').pack(side='right', padx=(8, 0))
            ttk.Button(btn_row, text="Cancel",
                       command=opt.destroy).pack(side='right')

        # ── Initial load ─────────────────────────────────────────────────────
        _refresh_all()

    def _show_partial_delete_dialog(self, error_text: str):
        """
        Show a partial-delete diagnostic dialog with a scrollable, selectable
        text area for the full traceback. Used when JSON delete succeeded
        but ChromaDB cleanup failed.

        The standard messagebox.showwarning truncates long messages and is
        not selectable, which loses the diagnostic information we need to
        actually fix the underlying issue.
        """
        import tkinter.scrolledtext as _st

        win = tk.Toplevel(self.root)
        win.title("Partial Delete — Index Cleanup Failed")
        win.geometry("760x560")
        win.transient(self.root)
        win.grab_set()

        # ── Header ──────────────────────────────────────────────────────────
        header = ttk.Frame(win, padding=(15, 12, 15, 6))
        header.pack(fill='x')
        ttk.Label(
            header,
            text="⚠️  Deleted from JSON file successfully, "
                 "but ChromaDB index cleanup failed.",
            font=('Segoe UI', 10, 'bold'),
            foreground='#a05a00',
        ).pack(anchor='w')
        ttk.Label(
            header,
            text="The learning is gone from the source of truth, but a stale\n"
                 "embedding remains in the search index. Diagnostic details\n"
                 "below — copy this if you need to investigate further.",
            justify='left',
        ).pack(anchor='w', pady=(4, 0))

        # ── Diagnostic text area (scrollable, selectable) ───────────────────
        body = ttk.Frame(win, padding=(15, 6, 15, 6))
        body.pack(fill='both', expand=True)
        ttk.Label(body, text="Diagnostic details:",
                  font=('Segoe UI', 9, 'bold')).pack(anchor='w')
        text_widget = _st.ScrolledText(
            body, wrap='word', height=18,
            font=('Consolas', 9),
            background='#fafafa',
        )
        text_widget.pack(fill='both', expand=True, pady=(4, 0))
        text_widget.insert('1.0', error_text)
        text_widget.configure(state='normal')   # keep editable so user can copy

        # ── Action buttons ──────────────────────────────────────────────────
        btn_frame = ttk.Frame(win, padding=(15, 6, 15, 12))
        btn_frame.pack(fill='x')

        def _copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(error_text)
            self.status_var.set("Diagnostic details copied to clipboard")

        ttk.Label(
            btn_frame,
            text="To fix the orphan embedding now:\n"
                 "Click '🔄 Rebuild ChromaDB Index' on the Learnings tab.",
            justify='left',
        ).pack(side='left')

        ttk.Button(btn_frame, text="📋 Copy Details",
                   command=_copy_to_clipboard).pack(side='right', padx=(0, 6))
        ttk.Button(btn_frame, text="Close",
                   command=win.destroy).pack(side='right')

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

    # ══════════════════════════════════════════════════════════════════════
    #  ADMIN TAB — Business server-mode user/seat management (Slice 1)
    #  Only created when config edition=business AND mode=server (see the
    #  conditional call in the tab-setup block). Reads/writes the SAME
    #  ~/.ai-prowler/users.json the server backend authenticates against.
    #  Slice 1 = Active Users table + Add/Edit/Remove/Regenerate-token.
    #  (Slice 2 adds the License/Seats panel + child-key dropdown;
    #   Slice 3 the Active Installs panel; Slice 4 the audit log.)
    # ══════════════════════════════════════════════════════════════════════
    def _admin_users_path(self):
        """Path to the server's users.json (the file the backend reads)."""
        from pathlib import Path as _Path
        return _Path.home() / ".ai-prowler" / "users.json"

    def _admin_load_users(self):
        """Load users.json → full dict (with 'users' map). Returns a safe
        default skeleton if the file is missing/unreadable so the UI still works."""
        import json as _json
        p = self._admin_users_path()
        try:
            if p.exists():
                data = _json.loads(p.read_text(encoding="utf-8-sig")) or {}
                if not isinstance(data.get("users"), dict):
                    data["users"] = {}
                return data
        except Exception as e:
            try:
                from tkinter import messagebox
                messagebox.showwarning(
                    "users.json",
                    f"Could not read users.json:\n{e}\n\n"
                    "Starting from an empty user list. Saving will OVERWRITE the "
                    "existing file — back it up first if it contains data.")
            except Exception:
                pass
        return {"users": {}}

    def _admin_save_users(self, data):
        """Write users.json atomically (temp + replace) so a crash mid-write
        can't corrupt the live auth file. Returns True on success.

        v7.0.1: auto-syncs collection_map private rules before writing so
        the admin never has to edit collection_map by hand."""
        import json as _json, os as _os
        from pathlib import Path as _Path
        p = self._admin_users_path()
        try:
            # Auto-generate private collection_map rules from user list.
            self._admin_sync_collection_map(data)
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".json.tmp")
            tmp.write_text(_json.dumps(data, indent=2), encoding="utf-8")
            _os.replace(str(tmp), str(p))
            return True
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Save failed", f"Could not write users.json:\n{e}")
            return False

    def _admin_gen_token(self):
        """Generate a 16-hex bearer token (secrets.token_hex(8)) — spec §5.2."""
        import secrets
        return secrets.token_hex(8)

    # ── Slice 2: seat pool (child license keys) ────────────────────────────
    #  Provisioning Model A: David mints parent + N child keys, delivers them as
    #  ~/.ai-prowler/seats.json {parent_license_key, seats_total, child_keys:[...]}.
    #  The customer tab NEVER mints or calls Worker admin endpoints. It reads the
    #  delivered pool, assigns a child key to each user (stored as child_license_key
    #  on the users.json record), and validates a key on Save against the PUBLIC
    #  /license/validate (same public endpoint the mobile sub uses — no token).
    #  A seat is 'used' iff some active user record carries that child key, so
    #  users.json is the single source of truth for allocation (no dual-write).
    def _admin_seats_path(self):
        from pathlib import Path as _Path
        # v8.0.0: prefer license_seats.json (subscription worker format)
        # Fall back to legacy seats.json if not present
        new_path = _Path.home() / ".ai-prowler" / "license_seats.json"
        if new_path.exists():
            return new_path
        return _Path.home() / ".ai-prowler" / "seats.json"

    def _admin_load_seats(self):
        """Load the seat pool. Supports both formats:
        v8.0.0 license_seats.json: {license_key, seats_total, seats:[{seat_id,status,assigned_to}]}
        legacy seats.json:         {parent_license_key, seats_total, child_keys:[...]}
        Always returns a normalised dict with both child_keys and seats arrays."""
        import json as _json
        from pathlib import Path as _Path
        p = self._admin_seats_path()
        try:
            if p.exists():
                data = _json.loads(p.read_text(encoding="utf-8-sig")) or {}
                # Detect v8 format: has 'seats' list of dicts
                if isinstance(data.get("seats"), list) and data["seats"] and isinstance(data["seats"][0], dict):
                    # Normalise to legacy format for backward compat with existing callers
                    data.setdefault("parent_license_key", data.get("license_key", ""))
                    data.setdefault("seats_total", data.get("seats_total", len(data["seats"])))
                    # Build child_keys list from unassigned seat_ids for dropdown compat
                    data["child_keys"] = [
                        s["seat_id"] for s in data["seats"]
                        if s.get("status") == "unassigned"
                    ]
                    data["_v8_seats"] = data["seats"]  # keep full records
                    return data
                # Legacy format
                if not isinstance(data.get("child_keys"), list):
                    data["child_keys"] = []
                return data
        except Exception as e:
            try:
                from tkinter import messagebox
                messagebox.showwarning(
                    "Seats file",
                    f"Could not read seat pool:\n{e}\n\nNo seat pool available; "
                    "license-key assignment will be disabled until it's fixed.")
            except Exception:
                pass
        return {"parent_license_key": "", "seats_total": 0, "child_keys": [], "_v8_seats": []}

    def _admin_warnings_path(self):
        from pathlib import Path as _Path
        return _Path.home() / ".ai-prowler" / "license_warnings.json"

    def _admin_load_warnings(self):
        """Load child-license warnings written by the engine's startup sweep.
        Returns {'last_check_at': str|None, 'warnings': [...]}. Tolerant of
        missing/corrupt — silent empty default (the warnings are advisory; a
        broken file should NOT pop a modal at the owner)."""
        import json as _json
        p = self._admin_warnings_path()
        try:
            if p.exists():
                data = _json.loads(p.read_text(encoding="utf-8-sig")) or {}
                if not isinstance(data.get("warnings"), list):
                    data["warnings"] = []
                if "last_check_at" not in data:
                    data["last_check_at"] = None
                return data
        except Exception as _e:
            # Advisory data; don't pop a modal. The seat strip will simply not
            # show warnings until the next sweep writes a clean file.
            try:
                print(f"[admin tab] could not read license_warnings.json: {_e}")
            except Exception:
                pass
        return {"last_check_at": None, "warnings": []}

    def _admin_assigned_keys(self, users_data=None):
        """Set of child keys currently assigned to ANY user record (used seats)."""
        if users_data is None:
            users_data = self._admin_load_users()
        assigned = set()
        for u in (users_data.get("users") or {}).values():
            if isinstance(u, dict):
                k = u.get("child_license_key")
                if k:
                    assigned.add(k)
        return assigned

    def _admin_unassigned_keys(self, seats=None, users_data=None):
        """Child keys from the delivered pool not yet assigned to any user."""
        if seats is None:
            seats = self._admin_load_seats()
        assigned = self._admin_assigned_keys(users_data)
        return [k for k in (seats.get("child_keys") or []) if k not in assigned]

    def _admin_mask_key(self, key):
        """Mask a license key for display: keep first 4 + last 4."""
        if not key:
            return ""
        if len(key) <= 9:
            return key
        return f"{key[:4]}…{key[-4:]}"

    def _admin_validate_child_key(self, child_key):
        """Validate a child key against the subscription Worker's
        /license/validate endpoint. Returns (ok: bool|None, message: str).
        Network failure returns (None, ...) — non-fatal, caller decides.

        Placeholder seat IDs (format: {license_key}-S###, generated locally
        before the Admin tab's 'Sync Seats' runs) are not real Worker keys
        and are skipped — treated as unvalidatable but allowed to proceed.
        Real child keys start with AP-CHLD- or AP-PERS-."""
        import json as _json, urllib.request, urllib.error

        # Detect placeholder IDs written by activate_from_payload() before
        # Sync Seats fetches real AP-CHLD- keys from the Worker.
        # Format: {parent_license_key}-S### e.g. AP-BIZ-XXXXXXXX-XXXXXXXX-S001
        import re as _re
        if _re.match(r'^AP-BIZ-[0-9A-F]+-[0-9A-F]+-S\d+$', child_key, _re.IGNORECASE):
            return (None,
                    "This is a placeholder seat ID (not yet synced from the server).\n"
                    "Click 'Sync Seats' to fetch real child keys from the license server.\n"
                    "You can assign this placeholder seat now — the key will be "
                    "updated automatically after syncing.")

        endpoint = "https://api.ai-prowler.com"
        # Honor a config override if present (mirrors _activation_endpoint).
        try:
            cfg = load_config() if RAG_AVAILABLE else {}
            ov = str(cfg.get("license_endpoint", "")).strip()
            if ov:
                endpoint = ov.rstrip("/")
        except Exception:
            pass
        try:
            install_id = ""
            try:
                from pathlib import Path as _Path
                iid = _Path.home() / ".ai-prowler" / "install_id"
                if iid.exists():
                    install_id = iid.read_text(encoding="utf-8").strip()
            except Exception:
                pass
            body = _json.dumps({"license_key": child_key,
                                "install_id": install_id}).encode()
            req = urllib.request.Request(
                f"{endpoint}/license/validate", data=body,
                headers={"Content-Type": "application/json",
                         "User-Agent": "AI-Prowler-AdminTab/1.0"}, method="POST")
            with urllib.request.urlopen(req, timeout=8) as r:
                resp = _json.loads(r.read().decode("utf-8", "replace"))
            if resp.get("valid") is True:
                exp = resp.get("expires_at", "")
                return (True, f"Valid child seat{(' — expires ' + exp) if exp else ''}.")
            reason = resp.get("reason", "invalid")
            return (False, f"License key rejected: {reason}. {resp.get('message','')}".strip())
        except urllib.error.HTTPError as e:
            return (False, f"Validation HTTP error {e.code} (key not accepted).")
        except Exception as e:
            # Network/offline — non-fatal; let the caller offer to proceed.
            return (None, f"Could not reach the license server ({e}). "
                          "You can assign the seat now and it will be "
                          "re-validated automatically later.")

    # ── Admin tab session state ───────────────────────────────────────────────
    # Tracks whether the current GUI session has authenticated for Admin tab
    # mutations. Set to True after a successful bearer-token unlock; cleared
    # when AI-Prowler is closed (instance lifetime only — never persisted).
    # _admin_session_unlocked is initialised in __init__ via _admin_unlock_init()
    # which is called right before create_admin_tab().

    def _admin_requires_lock(self):
        """Return True iff the Admin tab should require a bearer-token unlock.

        Locked mode is active when at least one user in users.json has
        can_manage_users=True (owner always counts as True). If NO such user
        exists — either because users.json is absent/empty or all managers/
        owners have been removed — buttons are always enabled (bootstrapping
        mode / lockout-prevention).
        """
        data = self._admin_load_users()
        users = data.get("users") or {}
        for u in users.values():
            if not isinstance(u, dict):
                continue
            role = (u.get("role") or "").lower()
            if role == "owner" or u.get("can_manage_users"):
                return True
        return False

    def _admin_unlock_init(self):
        """Initialise the per-session unlock flag. Called once before the
        Admin tab is built so the attribute always exists."""
        if not hasattr(self, "_admin_session_unlocked"):
            self._admin_session_unlocked = False

    def _admin_do_unlock(self):
        """Show a bearer-token prompt and validate it against users.json.
        Returns True and sets _admin_session_unlocked=True on success.
        Returns False (no messagebox — caller decides) on cancel/wrong token.
        Unlimited attempts; the dialog re-prompts on a wrong token.
        """
        import tkinter as tk
        from tkinter import ttk, messagebox

        # Build a modal dialog with a password entry
        dlg = tk.Toplevel(self.root)
        dlg.title("Admin Unlock")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)

        frm = ttk.Frame(dlg, padding=20)
        frm.pack(fill='both', expand=True)

        ttk.Label(frm, text="🔒 Admin area is locked",
                  font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=(0, 4))
        ttk.Label(frm, wraplength=320, justify='left',
                  text="Enter your bearer token (your AI-Prowler password) to "
                       "unlock user-management actions for this session.",
                  font=('Segoe UI', 9), foreground='gray'
                  ).pack(anchor='w', pady=(0, 12))

        err_var = tk.StringVar(value="")
        err_lbl = ttk.Label(frm, textvariable=err_var,
                            foreground='#cc0000', font=('Segoe UI', 9))
        err_lbl.pack(anchor='w', pady=(0, 4))

        tok_var = tk.StringVar()
        tok_entry = ttk.Entry(frm, textvariable=tok_var, show='●', width=34,
                              font=('Consolas', 10))
        tok_entry.pack(fill='x', pady=(0, 12))
        tok_entry.focus_set()

        result = [False]   # mutable so inner functions can write it

        def _try_unlock():
            entered = tok_var.get().strip()
            data = self._admin_load_users()
            users = data.get("users") or {}
            # v7.0.0 temp token support removed in v8.0.0 — tokens are permanent
            user = users.get(entered)
            if isinstance(user, dict):
                role = (user.get('role') or '').lower()
                if role == 'owner' or user.get('can_manage_users'):
                    self._admin_session_unlocked = True
                    result[0] = True
                    dlg.destroy()
                    return
                err_var.set('That token does not have admin rights.')
            else:
                err_var.set('Token not recognised -- try again.')
            tok_var.set("")
            tok_entry.focus_set()

        def _cancel():
            dlg.destroy()

        btn_row = ttk.Frame(frm)
        btn_row.pack(fill='x')
        ttk.Button(btn_row, text="Unlock", command=_try_unlock
                   ).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row, text="Cancel", command=_cancel
                   ).pack(side='left')

        # Allow Enter key to submit
        dlg.bind("<Return>", lambda _e: _try_unlock())
        dlg.bind("<Escape>", lambda _e: _cancel())

        ttk.Separator(frm, orient='horizontal').pack(fill='x', pady=(12, 4))
        ttk.Button(frm,
                   text='Forgot your token?  Send recovery email',
                   command=lambda: [dlg.destroy(),
                                    self._admin_recovery_dialog()]
                   ).pack(anchor='w', pady=(0, 8))

        dlg.wait_window()
        return result[0]

    def _admin_gate(self):
        """Call this at the top of every mutating Admin action.
        Returns True if the action should proceed (session already unlocked,
        or lock not required, or user just unlocked successfully).
        Returns False if the user cancelled — caller should return immediately.
        """
        if not self._admin_requires_lock():
            return True          # bootstrapping / no admins defined
        if self._admin_session_unlocked:
            return True          # already authenticated this session
        # Need to unlock
        ok = self._admin_do_unlock()
        if ok:
            self._admin_update_lock_ui()
        return ok


    # ── Token Recovery System ─────────────────────────────────────────────────
    # Email-only self-service recovery for locked-out admins and employees
    # who forget their bearer token.

    def _admin_email_configured(self):
        """Return True if email_config.json exists and has smtp_host + username."""
        import json as _j
        p = Path.home() / ".ai-prowler" / "email_config.json"
        if not p.exists():
            return False
        try:
            d = _j.loads(p.read_text(encoding="utf-8")) or {}
            return bool(d.get("smtp_host", "").strip()) and                    bool(d.get("username", "").strip())
        except Exception:
            return False

    def _admin_send_email_direct(self, to, subject, body):
        """Send an email directly from the GUI using email_config.json.
        Returns (success: bool, message: str)."""
        import json as _j, smtplib, ssl as _ssl, base64 as _b
        from email.mime.multipart import MIMEMultipart as _MM
        from email.mime.text import MIMEText as _MT

        p = Path.home() / ".ai-prowler" / "email_config.json"
        if not p.exists():
            return (False, "Email not configured. "
                           "Configure SMTP in Settings -> Email Configuration.")
        try:
            cfg = _j.loads(p.read_text(encoding="utf-8")) or {}
        except Exception as e:
            return (False, f"Could not read email config: {e}")

        if "_password_b64" in cfg:
            try:
                cfg["password"] = _b.b64decode(cfg["_password_b64"]).decode()
            except Exception:
                pass

        smtp_host = cfg.get("smtp_host", "").strip()
        smtp_port = int(cfg.get("smtp_port", 587))
        username  = cfg.get("username", "").strip()
        password  = cfg.get("password", "")
        from_name = cfg.get("from_name", "AI-Prowler")

        if not smtp_host or not username:
            return (False, "Incomplete email config.")

        msg = _MM("mixed")
        msg["From"]    = f"{from_name} <{username}>"
        msg["To"]      = to
        msg["Subject"] = subject
        msg.attach(_MT(body, "plain", "utf-8"))

        try:
            ctx = _ssl.create_default_context()
            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port,
                                      context=ctx, timeout=20) as s:
                    s.login(username, password)
                    s.sendmail(username, [to], msg.as_bytes())
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as s:
                    s.ehlo()
                    if cfg.get("use_tls", True):
                        s.starttls(context=ctx)
                    s.login(username, password)
                    s.sendmail(username, [to], msg.as_bytes())
            return (True, f"Sent to {to}")
        except Exception as e:
            return (False, str(e))

    def _admin_recovery_eligible_users(self):
        """Return list of (display_name, user_key, user_record) tuples for
        users who are eligible for self-service recovery (owner or manager
        with can_manage_users)."""
        data  = self._admin_load_users()
        users = data.get("users") or {}
        out   = []
        for tok, rec in users.items():
            if not isinstance(rec, dict):
                continue
            role = (rec.get("role") or "").lower()
            if role == "owner" or rec.get("can_manage_users"):
                name = rec.get("name") or f"({role})"
                out.append((name, tok, rec))
        return out

    def _admin_recovery_dialog(self):
        """'Forgot your token?' — emails the admin their existing bearer token.
        No temp tokens. No expiry. Just sends the real token to their
        registered email address so they can log back in."""
        import tkinter as tk
        from tkinter import ttk, messagebox
        from pathlib import Path as _Path

        eligible = self._admin_recovery_eligible_users()
        if not eligible:
            messagebox.showinfo(
                "No Recovery Users",
                "No owner or admin-manager accounts with an email address "
                "are configured.\n\n"
                "Recover manually by opening:\n"
                f"  {_Path.home() / '.ai-prowler' / 'users.json'}\n\n"
                "The bearer tokens are the top-level keys in the JSON.\n"
                "Your record will have your name in the 'name' field.")
            return

        dlg = tk.Toplevel(self.root)
        dlg.title("Admin Token Recovery")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        frm = ttk.Frame(dlg, padding=16)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Token Recovery",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(frm, wraplength=400, justify="left", foreground="gray",
                  text="Select your name. Your existing bearer token will be "
                       "emailed to your registered address so you can log back in."
                  ).pack(anchor="w", pady=(4, 10))

        # User selector
        user_row = ttk.Frame(frm)
        user_row.pack(fill="x", pady=4)
        ttk.Label(user_row, text="Your name:").pack(side="left")
        user_names = [e[0] for e in eligible]
        user_var   = tk.StringVar(value=user_names[0] if user_names else "")
        ttk.Combobox(user_row, textvariable=user_var, values=user_names,
                     state="readonly", width=28).pack(side="left", padx=8)

        def _selected_record():
            name = user_var.get()
            for n, k, r in eligible:
                if n == name:
                    return k, r
            return None, None

        # Email label
        _email_lbl = ttk.Label(frm, text="", foreground="gray",
                               font=("Segoe UI", 9))
        _email_lbl.pack(anchor="w", pady=(4, 0))

        def _mask_email(e):
            if not e or "@" not in e:
                return e or "(no email)"
            local, domain = e.split("@", 1)
            return local[:2] + "***@" + domain

        def _update_label(*_):
            _k, rec = _selected_record()
            if not rec:
                return
            em = rec.get("email", "")
            if em and self._admin_email_configured():
                _email_lbl.config(
                    text=f"Will send to:  {_mask_email(em)}",
                    foreground="black")
            elif not em:
                _email_lbl.config(
                    text="No email address on record — use manual recovery below.",
                    foreground="red")
            else:
                _email_lbl.config(
                    text="SMTP not configured — use manual recovery below.",
                    foreground="red")

        user_var.trace_add("write", _update_label)
        _update_label()

        status_var = tk.StringVar(value="")
        ttk.Label(frm, textvariable=status_var,
                  foreground="#1a6e1a", font=("Segoe UI", 9),
                  wraplength=400).pack(anchor="w", pady=(8, 0))

        def _send():
            ukey, rec = _selected_record()
            if not rec:
                status_var.set("Select a user first.")
                return
            em   = rec.get("email", "").strip()
            name = rec.get("name", "Admin")
            if not em:
                messagebox.showwarning(
                    "No Email",
                    f"{name} has no email address on record.\n\n"
                    "Recover manually by opening:\n"
                    f"  {str(_Path.home() / '.ai-prowler' / 'users.json')}")
                return
            if not self._admin_email_configured():
                messagebox.showwarning(
                    "Email Not Configured",
                    "SMTP is not configured.\n\n"
                    "Configure email in Settings → Email Configuration,\n"
                    "or recover manually by opening:\n"
                    f"  {str(_Path.home() / '.ai-prowler' / 'users.json')}")
                return

            subject = "AI-Prowler Admin Access — Your Bearer Token"
            body = (
                f"Hi {name},\n\n"
                f"Your AI-Prowler admin bearer token is:\n\n"
                f"  {ukey}\n\n"
                f"Use this token to log in to the Admin tab on the server.\n\n"
                f"Keep this token private — it is your admin credential.\n\n"
                f"If you did not request this, someone has access to the server "
                f"machine. Change your token immediately via Admin → Reset Token.\n\n"
                f"-- AI-Prowler Server"
            )
            status_var.set(f"Sending to {_mask_email(em)}...")
            dlg.update_idletasks()
            ok, msg = self._admin_send_email_direct(em, subject, body)
            if ok:
                status_var.set("Sent! Check your email.")
                dlg.after(2000, dlg.destroy)
            else:
                status_var.set(f"Send failed: {msg}")

        def _manual():
            dlg.destroy()
            messagebox.showinfo(
                "Manual Recovery",
                f"Open the following file in a text editor:\n\n"
                f"  {str(_Path.home() / '.ai-prowler' / 'users.json')}\n\n"
                "The bearer tokens are the top-level keys in the JSON.\n"
                "Your record will have your name in the 'name' field.")

        btn_row2 = ttk.Frame(frm)
        btn_row2.pack(fill="x", pady=(12, 0))
        ttk.Button(btn_row2, text="Send My Token by Email",
                   command=_send).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row2, text="Manual Recovery",
                   command=_manual).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row2, text="Cancel",
                   command=dlg.destroy).pack(side="left")

        dlg.wait_window()

    def _admin_send_token_to_user(self):
        """Send the selected employee's current bearer token to their
        registered email address. Admin action -- requires unlock.
        Only available when the selected user has an email address."""
        from tkinter import messagebox
        if not self._admin_gate():
            return
        tok = self._admin_selected_token()
        if not tok:
            messagebox.showinfo("No Selection", "Select a user first.")
            return
        data  = self._admin_load_users()
        users = data.get("users") or {}
        rec   = users.get(tok)
        if not isinstance(rec, dict):
            messagebox.showwarning("Not Found", "User record not found.")
            return
        em   = rec.get("email", "").strip()
        name = rec.get("name", "the user")
        if not em:
            messagebox.showwarning(
                "No Email",
                f"{name} does not have an email address on record.\n\n"
                "Edit the user record to add one, then try again.")
            return
        if not self._admin_email_configured():
            messagebox.showwarning(
                "Email Not Configured",
                "SMTP is not configured on this server.\n\n"
                "Configure email in Settings -> Email Configuration, "
                "then try again.")
            return
        em_short = em[:3] + "***@" + em.split("@", 1)[-1] if "@" in em else em
        if not messagebox.askyesno(
                "Send Token Email",
                f"Send {name}'s current bearer token to:\n  {em_short}\n\n"
                "The email will contain their full bearer token "
                "(their Claude.ai connector password). "
                "Send only to a trusted address."):
            return
        subject = "Your AI-Prowler Access Token"
        body = (
            f"Hi {name},\n\n"
            f"Your AI-Prowler bearer token (the password you use to connect "
            f"Claude.ai to the company server) is:\n\n"
            f"  {tok}\n\n"
            f"How to connect:\n"
            f"  1. Open Claude.ai -> Settings -> Connectors\n"
            f"  2. Find your company AI-Prowler connector\n"
            f"  3. If prompted to re-authenticate, enter the token above\n\n"
            f"Keep this token private -- it is your personal access credential.\n\n"
            f"-- AI-Prowler Server Admin"
        )
        ok, msg = self._admin_send_email_direct(em, subject, body)
        if ok:
            messagebox.showinfo(
                "Token Sent",
                f"Bearer token sent to {em_short}.\n\n"
                f"{name} should check their email and reconnect Claude.ai.")
        else:
            messagebox.showerror(
                "Send Failed",
                f"Could not send email to {em_short}:\n\n{msg}\n\n"
                "Check SMTP settings in Settings -> Email Configuration.")

    def _admin_send_token_via_sms(self):
        """Send the selected employee's bearer token to their cell phone via SMS.
        Requires cell_phone to be set on the user record, and an SMS provider
        (Twilio, SignalWire, or Vonage) configured in Settings → SMS / Text
        Messaging. Admin action — requires unlock.

        NOTE: the free email-to-SMS gateway approach was removed — carriers
        are shutting those gateways down industry-wide (AT&T's is already
        gone, Verizon's is mid-shutdown through 2027). A real SMS provider
        is now required. Uses the same provider-agnostic sms_backends module
        as the Settings tab's own Test SMS button, so this works correctly
        regardless of which provider is configured."""
        from tkinter import messagebox
        if not self._admin_gate():
            return
        tok = self._admin_selected_token()
        if not tok:
            messagebox.showinfo("No Selection", "Select a user first.")
            return
        data  = self._admin_load_users()
        users = data.get("users") or {}
        rec   = users.get(tok)
        if not isinstance(rec, dict):
            messagebox.showwarning("Not Found", "User record not found.")
            return
        name    = rec.get("name", "the user")
        phone   = rec.get("cell_phone", "").strip()
        if not phone:
            messagebox.showwarning(
                "No Phone Number",
                f"{name} does not have a cell phone number on record.\n\n"
                "Edit the user record to add one, then try again.")
            return

        import re as _re
        digits = _re.sub(r'\D', '', phone)
        if len(digits) == 11 and digits[0] == '1':
            digits = digits[1:]
        if len(digits) != 10:
            messagebox.showerror(
                "Invalid Phone",
                f"The phone number on record ({phone!r}) does not look like "
                "a valid 10-digit US number.  Edit the user record to correct it.")
            return

        try:
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).parent))
            from sms_backends import get_sms_backend, load_sms_config
            _sms_backend = get_sms_backend(load_sms_config())
        except Exception as _imp_exc:
            messagebox.showerror("SMS Module Error", str(_imp_exc))
            return

        _sms_ok, _sms_hint = _sms_backend.validate_config()
        if not _sms_ok:
            messagebox.showwarning(
                "SMS Provider Not Configured",
                "SMS delivery requires a provider — Twilio, SignalWire, "
                "or Vonage.\n\n"
                "Go to Settings → SMS / Text Messaging, choose a provider, "
                "and enter your credentials, then try again.")
            return

        ph_display = f"{'*' * 6}{digits[-4:]}"
        if not messagebox.askyesno(
                "Send Token SMS",
                f"Send {name}'s bearer token to {ph_display} via SMS "
                f"({_sms_backend.provider_name.title()})?\n\n"
                "The message will contain their full bearer token "
                "(their Claude.ai connector password). "
                "Send only to a trusted number."):
            return

        body = (
            f"AI-Prowler access token for {name}:\n{tok}\n"
            f"Paste into Claude.ai Settings > Connectors. Keep private."
        )
        try:
            ok, msg = _sms_backend.send(f"+1{digits}", body)
        except Exception as _exc:
            ok, msg = False, str(_exc)

        if ok:
            messagebox.showinfo(
                "Token Sent",
                f"Bearer token sent via SMS to {ph_display}.\n\n"
                f"{name} should check their phone and reconnect Claude.ai.")
        else:
            messagebox.showerror(
                "Send Failed",
                f"Could not send SMS to {ph_display}:\n\n{msg}\n\n"
                "Check SMS provider settings in Settings → SMS / Text Messaging.")

    def _admin_update_lock_ui(self):
        """Refresh the lock-status label and button states in the Admin tab."""
        if not hasattr(self, "_admin_lock_lbl"):
            return
        locked = self._admin_requires_lock()
        unlocked = self._admin_session_unlocked
        if not locked:
            self._admin_lock_lbl.config(
                text="🔓 Unlocked  (no admins configured — bootstrapping mode)",
                foreground='#1f7a1f')
        elif unlocked:
            self._admin_lock_lbl.config(
                text="🔓 Unlocked for this session",
                foreground='#1f7a1f')
        else:
            self._admin_lock_lbl.config(
                text="🔒 Locked — click a button to authenticate",
                foreground='#cc0000')

    def create_admin_tab(self):
        """Admin tab — Active Users management for Business server mode.
        Reads/writes ~/.ai-prowler/users.json (the backend's auth source)."""
        import tkinter as tk
        from tkinter import ttk, messagebox, simpledialog

        self._admin_unlock_init()

        outer = ttk.Frame(self.notebook)
        self.notebook.add(outer, text="👥 Admin")
        f = self._make_scrollable_tab(outer)

        ttk.Label(f, text="👥 User & Seat Management",
                  font=('Segoe UI', 14, 'bold')).pack(anchor='w', pady=(4, 2))
        ttk.Label(f, wraplength=720, justify='left',
                  text="Manage the employees who can connect to this company "
                       "server. Changes are written to ~/.ai-prowler/users.json, "
                       "which the server reads to authenticate each bearer token. "
                       "A user's bearer token is their password — generate it here, "
                       "then send it to them securely. "
                       "Each employee also gets a license seat from your delivered pool."
                  ).pack(anchor='w', pady=(0, 8))

        # ── Lock status strip ─────────────────────────────────────────────────
        # Shows whether the session is locked or unlocked. Updated by
        # _admin_update_lock_ui() after every unlock or users.json change.
        self._admin_lock_lbl = ttk.Label(
            f, text="", font=('Segoe UI', 9, 'bold'))
        self._admin_lock_lbl.pack(anchor='w', pady=(0, 6))
        self._admin_update_lock_ui()   # set initial text

        # ── Seat summary strip (read-only; pool from ~/.ai-prowler/seats.json) ─
        seat_bar = ttk.Frame(f)
        seat_bar.pack(fill='x', pady=(0, 6))
        self._admin_seat_label = ttk.Label(
            seat_bar, text="", font=('Segoe UI', 9, 'bold'))
        self._admin_seat_label.pack(side='left')

        # ── Child-license warning strip (v7.0.0 #4 sweep → GUI surface) ───────
        # Populated by the engine's startup sweep into
        # ~/.ai-prowler/license_warnings.json. Empty when nothing is wrong; lists
        # affected users + masked keys when something is. Soft policy: no
        # action gating, this is purely advisory for the owner.
        self._admin_warning_label = ttk.Label(
            f, text="", font=('Segoe UI', 9),
            foreground='#a05a00', wraplength=720, justify='left')
        self._admin_warning_label.pack(fill='x', pady=(0, 6))

        # ── Active Users table ────────────────────────────────────────────
        table_frame = ttk.Frame(f)
        table_frame.pack(fill='both', expand=True, pady=(0, 6))

        columns = ('name', 'email', 'phone', 'role', 'scopes', 'admin', 'private', 'seat', 'status', 'token')
        tree_scroll = ttk.Scrollbar(table_frame, orient='vertical')
        self._admin_tree = ttk.Treeview(table_frame, columns=columns,
                                        show='headings', height=12,
                                        yscrollcommand=tree_scroll.set,
                                        selectmode='browse')
        tree_scroll.config(command=self._admin_tree.yview)

        col_cfg = [
            ('name',    'Name',          130, 'w'),
            ('email',   'Email',         160, 'w'),
            ('phone',   'Cell Phone',     95, 'center'),
            ('role',    'Role',           80, 'center'),
            ('scopes',  'Scopes',        130, 'w'),
            ('admin',   'Manages Users',  90, 'center'),
            ('private', 'Private Coll.',  80, 'center'),
            ('seat',    'Seat (key)',     110, 'w'),
            ('status',  'Status',         70, 'center'),
            ('token',   'Token',         120, 'w'),   # always masked — use name/email to identify
        ]
        for col_id, heading, width, anchor in col_cfg:
            self._admin_tree.heading(col_id, text=heading)
            self._admin_tree.column(col_id, width=width, anchor=anchor, minwidth=40)
        self._admin_tree.pack(side='left', fill='both', expand=True)
        tree_scroll.pack(side='right', fill='y')

        # ── Action buttons ────────────────────────────────────────────────
        btn_row = ttk.Frame(f)
        btn_row.pack(fill='x', pady=(2, 6))
        ttk.Button(btn_row, text="➕ Add User",
                   command=self._admin_add_user).pack(side='left', padx=(0, 4))
        ttk.Button(btn_row, text="✏️ Edit",
                   command=self._admin_edit_user).pack(side='left', padx=4)
        ttk.Button(btn_row, text="🔑 Regenerate Token",
                   command=self._admin_regen_token).pack(side='left', padx=4)
        ttk.Button(btn_row, text="🚫 Suspend/Activate",
                   command=self._admin_toggle_status).pack(side='left', padx=4)
        ttk.Button(btn_row, text="🗑 Remove",
                   command=self._admin_remove_user).pack(side='left', padx=4)
        ttk.Button(btn_row, text="📧 Send Token Email",
                   command=self._admin_send_token_to_user).pack(side='left', padx=4)
        ttk.Button(btn_row, text="📱 Send Token SMS",
                   command=self._admin_send_token_via_sms).pack(side='left', padx=4)
        ttk.Button(btn_row, text="↻ Refresh",
                   command=self._admin_refresh_table).pack(side='right')
        ttk.Button(btn_row, text="☁ Sync Seats",
                   command=self._admin_sync_seats_from_worker).pack(side='right', padx=(0, 4))

        self._admin_refresh_table()

    def _admin_refresh_table(self):
        """Reload users.json and repopulate the table; refresh seat summary."""
        if not hasattr(self, "_admin_tree"):
            return
        for row in self._admin_tree.get_children():
            self._admin_tree.delete(row)
        data = self._admin_load_users()
        seats = self._admin_load_seats()
        for token, u in (data.get("users") or {}).items():
            if not isinstance(u, dict):
                continue
            role = u.get("role", "field_crew")
            scopes = ", ".join(u.get("scopes") or [])
            is_owner = (role == "owner")
            admin_flag = "✓ (owner)" if is_owner else ("✓" if u.get("can_manage_users") else "")
            private = "✓" if u.get("private_collection_enabled") else ""
            seat = self._admin_mask_key(u.get("child_license_key", ""))
            status = u.get("status", "active")
            phone   = u.get("cell_phone", "")
            # v7.0.1 security: never expose any part of the bearer token on screen.
            # The token IS the authentication credential — even a prefix leaks info.
            # Name + email + role already uniquely identify each row.
            tok_display = "●" * 8
            self._admin_tree.insert(
                '', 'end', iid=token,
                values=(u.get("name", "(unnamed)"), u.get("email", ""), phone,
                        role, scopes, admin_flag, private, seat, status, tok_display))
        # Seat summary strip — v8.0.0 aware
        if hasattr(self, "_admin_seat_label"):
            v8_seats = seats.get("_v8_seats") or []
            if v8_seats:
                # v8 license_seats.json format — full seat records
                total    = seats.get("seats_total") or len(v8_seats)
                assigned = sum(1 for s in v8_seats if s.get("status") == "assigned")
                pending  = sum(1 for s in v8_seats if s.get("status") == "pending_removal")
                free     = sum(1 for s in v8_seats if s.get("status") == "unassigned")
                parent   = self._admin_mask_key(seats.get("parent_license_key", "") or seats.get("license_key", ""))
                txt = f"Seats: {assigned}/{total} assigned · {free} available"
                if pending:
                    txt += f" · ⚠ {pending} pending removal"
                if parent:
                    txt += f"   ·   License: {parent}"
            else:
                # Legacy seats.json format
                total = seats.get("seats_total") or len(seats.get("child_keys") or [])
                used  = len(self._admin_assigned_keys(data))
                free  = max(0, total - used)
                parent = self._admin_mask_key(seats.get("parent_license_key", ""))
                if total == 0 and not seats.get("child_keys"):
                    txt = ("⚠ No seat pool found. Run '☁ Sync Seats' to fetch "
                           "from the subscription worker, or check ~/.ai-prowler/license_seats.json.")
                else:
                    txt = (f"Seats: {used}/{total} used · {free} available"
                           + (f"   ·   License: {parent}" if parent else ""))
            self._admin_seat_label.config(text=txt)

        # Child-license warning strip — read engine-written file. Only the most
        # recent sweep wins; the engine writes an empty warnings list when
        # everything checked out, so an empty list != stale data.
        if hasattr(self, "_admin_warning_label"):
            wdata = self._admin_load_warnings()
            warnings = wdata.get("warnings") or []
            if not warnings:
                self._admin_warning_label.config(text="")
            else:
                # Compact summary: up to 5 names with their reason; rest counted.
                parts = []
                for w in warnings[:5]:
                    name = w.get("name", "?")
                    masked = w.get("child_key_masked", "")
                    reason = w.get("reason", "issue")
                    parts.append(f"{name} ({reason}, {masked})")
                more = len(warnings) - 5
                trailer = f" — and {more} more" if more > 0 else ""
                summary = ", ".join(parts) + trailer
                self._admin_warning_label.config(
                    text=f"⚠ License issue(s) on {len(warnings)} child seat(s): "
                         f"{summary}.  Contact your provider.")

    def _admin_sync_seats_from_worker(self):
        """Sync seat list from the subscription worker into license_seats.json.
        Uses subscription_client.sync_seats() with the license key from config.
        Runs on a background thread so the GUI stays responsive."""
        import threading as _th
        from tkinter import messagebox

        if not self._admin_gate():
            return

        # Get license key from config
        try:
            cfg = load_config() if RAG_AVAILABLE else {}
            license_key = cfg.get("license_key", "").strip()
        except Exception:
            license_key = ""

        if not license_key or not license_key.startswith("AP-BIZ-"):
            messagebox.showwarning(
                "Sync Seats",
                "No Business license key found in config.\n\n"
                "Seat sync is only available for Business plan subscribers.\n"
                "Check Settings -> Remote Access -> License Key.")
            return

        if hasattr(self, "_admin_seat_label"):
            self._admin_seat_label.config(text="Syncing seats from worker...")

        def _worker():
            try:
                import sys as _sys, os as _os
                _app = _os.path.dirname(_os.path.abspath(__file__))
                if _app not in _sys.path:
                    _sys.path.insert(0, _app)
                import subscription_client as _sc
                result = _sc.sync_seats(license_key)
                def _on_done():
                    self._admin_refresh_table()
                    total    = result.get("seats_total", 0)
                    assigned = result.get("seats_assigned", 0)
                    free     = result.get("seats_unassigned", 0)
                    pending  = result.get("seats_pending_removal", 0)
                    msg = f"Seats synced: {assigned}/{total} assigned, {free} available"
                    if pending:
                        msg += f", {pending} pending removal"
                    self.status_var.set(f"✅ {msg}")
                    self.root.after(4000, lambda: self.status_var.set("Ready"))
                self.root.after(0, _on_done)
            except Exception as _ex:
                def _on_err():
                    if hasattr(self, "_admin_seat_label"):
                        self._admin_seat_label.config(
                            text="Sync failed — using cached seat data")
                    self.status_var.set(f"Seat sync failed: {_ex}")
                    self.root.after(4000, lambda: self.status_var.set("Ready"))
                self.root.after(0, _on_err)

        _th.Thread(target=_worker, daemon=True).start()

    def _admin_selected_token(self):
        """Return the token (iid) of the selected row, or None."""
        sel = self._admin_tree.selection()
        return sel[0] if sel else None

    def _admin_user_dialog(self, title, existing=None):
        """Modal dialog to add/edit a user. Returns a dict of fields or None.
        `existing` is the current user dict when editing (role/scopes/flags
        prefilled). Does NOT include the token — that's managed separately.

        v7.0.1: Name is now split into separate First name / Last name fields.
        This guarantees the stable slug id (firstname-lastname) is unambiguous
        and consistent — the admin can't accidentally create 'David  Vavro' vs
        'David Vavro'. A read-only slug preview updates live so the admin sees
        exactly what the private collection name will be."""
        import tkinter as tk
        from tkinter import ttk, messagebox
        import re as _re

        def _to_slug(first, last):
            """firstname-lastname slug matching _make_user_id in ai_prowler_mcp.py."""
            full = f"{first.strip()} {last.strip()}".strip()
            s = full.lower()
            s = _re.sub(r'[\s_]+', '-', s)
            s = _re.sub(r'[^a-z0-9-]', '', s)
            s = _re.sub(r'-+', '-', s)
            return s.strip('-') or "unknown-user"

        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(False, False)
        pad = {'padx': 8, 'pady': 4}

        ex = existing or {}

        # Split existing "Full Name" back into first / last for the edit case.
        _existing_name = ex.get("name", "")
        _name_parts = _existing_name.split(" ", 1)
        _ex_first = _name_parts[0] if _name_parts else ""
        _ex_last  = _name_parts[1] if len(_name_parts) > 1 else ""

        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill='both', expand=True)

        # ── Row 0: First name ──────────────────────────────────────────────
        ttk.Label(frm, text="First name:").grid(row=0, column=0, sticky='e', **pad)
        first_var = tk.StringVar(value=_ex_first)
        ttk.Entry(frm, textvariable=first_var, width=16).grid(
            row=0, column=1, sticky='w', **pad)

        # ── Row 1: Last name ───────────────────────────────────────────────
        ttk.Label(frm, text="Last name:").grid(row=1, column=0, sticky='e', **pad)
        last_var = tk.StringVar(value=_ex_last)
        ttk.Entry(frm, textvariable=last_var, width=16).grid(
            row=1, column=1, sticky='w', **pad)

        # ── Row 2: Slug preview (read-only) ────────────────────────────────
        ttk.Label(frm, text="User ID (slug):").grid(row=2, column=0, sticky='e', **pad)
        slug_var = tk.StringVar(value=_to_slug(_ex_first, _ex_last))
        slug_lbl = ttk.Label(frm, textvariable=slug_var,
                             font=('Consolas', 9), foreground='#336699')
        slug_lbl.grid(row=2, column=1, sticky='w', **pad)
        ttk.Label(frm, text="(auto-generated — used for private collection name)",
                  font=('Segoe UI', 8)).grid(row=2, column=2, sticky='w')

        def _update_slug(*_):
            slug_var.set(_to_slug(first_var.get(), last_var.get()))
        first_var.trace_add('write', _update_slug)
        last_var.trace_add('write',  _update_slug)

        # ── Row 3: Email ───────────────────────────────────────────────────
        ttk.Label(frm, text="Email:").grid(row=3, column=0, sticky='e', **pad)
        email_var = tk.StringVar(value=ex.get("email", ""))
        ttk.Entry(frm, textvariable=email_var, width=34).grid(row=3, column=1,
                                                               columnspan=2, **pad)

        # ── Row 4: Cell phone ──────────────────────────────────────────────
        ttk.Label(frm, text='Cell phone:').grid(row=4, column=0, sticky='e', **pad)
        phone_var = tk.StringVar(value=ex.get('cell_phone', ''))
        ttk.Entry(frm, textvariable=phone_var, width=18).grid(
            row=4, column=1, sticky='w', **pad)
        ttk.Label(frm, text='10 digits, no dashes  e.g. 3215550199',
                  font=('Segoe UI', 8)).grid(row=4, column=2, sticky='w')

        # ── Row 5: Role ────────────────────────────────────────────────────
        # (Carrier field removed — SMS no longer routes through carrier-specific
        # email gateways. Twilio/SignalWire/Vonage deliver directly to the
        # phone number, so no carrier lookup is needed.)
        ttk.Label(frm, text="Role:").grid(row=5, column=0, sticky='e', **pad)
        role_var = tk.StringVar(value=ex.get("role", "field_crew"))
        role_cb = ttk.Combobox(frm, textvariable=role_var, state='readonly',
                               width=31, values=("owner", "manager",
                                                 "staff", "field_crew"))
        role_cb.grid(row=5, column=1, columnspan=2, **pad)

        # ── Row 6: Scopes ──────────────────────────────────────────────────
        ttk.Label(frm, text="Scopes:").grid(row=6, column=0, sticky='ne', **pad)
        scopes_var = tk.StringVar(value=", ".join(ex.get("scopes") or []))
        scopes_entry = ttk.Entry(frm, textvariable=scopes_var, width=34)
        scopes_entry.grid(row=6, column=1, columnspan=2, **pad)
        ttk.Label(frm, text="(the data groups this user may access — you define "
                            "these, e.g. scope:sales, scope:office, scope:ops)",
                  font=('Segoe UI', 8)).grid(row=7, column=1, columnspan=2,
                                             sticky='w', padx=8)

        # ── Row 8: Manage users checkbox ───────────────────────────────────
        manage_var = tk.BooleanVar(value=bool(ex.get("can_manage_users")))
        manage_cb = ttk.Checkbutton(
            frm, text="Can manage users (delegated admin)", variable=manage_var)
        manage_cb.grid(row=8, column=1, columnspan=2, sticky='w', **pad)

        # ── Row 9: Private collection ─────────────────────────────────────
        private_var = tk.BooleanVar(
            value=bool(ex.get("private_collection_enabled", True)))
        ttk.Checkbutton(frm, text="Private collection enabled",
                        variable=private_var).grid(row=9, column=1, columnspan=2,
                                                   sticky='w', **pad)

        # ── Row 10: License seat dropdown ──────────────────────────────────
        ttk.Label(frm, text="License seat:").grid(row=10, column=0, sticky='e', **pad)
        cur_key = ex.get("child_license_key", "")
        avail = list(self._admin_unassigned_keys())
        if cur_key and cur_key not in avail:
            avail = [cur_key] + avail
        key_labels = {"(no seat assigned)": ""}
        for k in avail:
            key_labels[self._admin_mask_key(k) + f"   [{k[:8]}…]"] = k
        init_label = "(no seat assigned)"
        for lbl, k in key_labels.items():
            if k == cur_key and cur_key:
                init_label = lbl
                break
        seat_var = tk.StringVar(value=init_label)
        seat_cb = ttk.Combobox(frm, textvariable=seat_var, state='readonly',
                               width=31, values=list(key_labels.keys()))
        seat_cb.grid(row=10, column=1, columnspan=2, **pad)
        if len(key_labels) == 1:
            ttk.Label(frm, text="(no unassigned seats in the pool)",
                      font=('Segoe UI', 8)).grid(row=11, column=1, columnspan=2,
                                                 sticky='w', padx=8)

        # ── Row 12: Bearer token (Add only) ────────────────────────────────
        is_edit = bool(existing)
        token_var = tk.StringVar(value="")
        if not is_edit:
            ttk.Label(frm, text="Bearer token:").grid(row=12, column=0, sticky='e', **pad)
            ttk.Entry(frm, textvariable=token_var, width=34,
                      font=('Consolas', 10), show='●').grid(row=12, column=1,
                                                            columnspan=2, **pad)
            ttk.Label(frm, text="(optional — leave blank to auto-generate a "
                                "strong token; typing a weak one is insecure)",
                      font=('Segoe UI', 8)).grid(row=13, column=1, columnspan=2,
                                                 sticky='w', padx=8)

        # can_manage_users rules (spec §6.3)
        def _sync_manage_state(*_a):
            r = role_var.get()
            if r == "owner":
                manage_var.set(True)
                manage_cb.state(['disabled'])
            elif r == "manager":
                manage_cb.state(['!disabled'])
            else:
                manage_var.set(False)
                manage_cb.state(['disabled'])
        role_var.trace_add('write', _sync_manage_state)
        _sync_manage_state()

        result = {}

        def _ok():
            first = first_var.get().strip()
            last  = last_var.get().strip()
            if not first or not last:
                messagebox.showwarning("Missing",
                                       "Both First name and Last name are required.",
                                       parent=dlg)
                return
            full_name = f"{first} {last}"
            scopes = [s.strip() for s in scopes_var.get().split(",") if s.strip()]
            chosen_key = key_labels.get(seat_var.get(), "")
            _role = role_var.get()
            _can_manage = True if _role == "owner" else bool(manage_var.get())
            result.update({
                "name":  full_name,
                "first_name": first,
                "last_name":  last,
                "slug":  _to_slug(first, last),
                "email": email_var.get().strip(),
                "cell_phone":   phone_var.get().strip(),
                "role": _role,
                "scopes": scopes,
                "can_manage_users": _can_manage,
                "private_collection_enabled": bool(private_var.get()),
                "child_license_key": chosen_key,
                "custom_token": token_var.get().strip(),
            })
            dlg.destroy()

        def _cancel():
            result.clear()
            dlg.destroy()

        btns = ttk.Frame(frm)
        btns.grid(row=15, column=0, columnspan=3, pady=(10, 0))
        ttk.Button(btns, text="Save", command=_ok).pack(side='left', padx=4)
        ttk.Button(btns, text="Cancel", command=_cancel).pack(side='left', padx=4)

        dlg.wait_window()
        return result or None

    def _admin_sync_collection_map(self, data):
        """Auto-generate collection_map private-directory rules from users.json.

        v7.0.1 — called automatically on every Add / Edit user save so the
        admin never has to touch collection_map by hand.

        For each user with private_collection_enabled=True, ensures a rule
        exists that maps:
            <privates_root>/<First>-<Last>-Private  →  user:<slug>

        where <slug> = firstname-lastname (lowercase, hyphens) and
        <privates_root> is derived from the server's home directory:
            <home>/Documents/AI-Prowler-Server-privates

        IMPORTANT: if a rule for user:<slug> already exists with a custom path
        (set via the folder-setup dialog), that path is preserved. The default
        is only applied when no rule exists yet for that user.

        Rules for users who no longer have private_collection_enabled are
        removed. Rules for non-user collections (scope:*, shared) are left
        untouched. The default_collection is preserved.
        """
        import re as _re
        from pathlib import Path as _Path

        def _slug(name):
            s = (name or "").strip().lower()
            s = _re.sub(r'[\s_]+', '-', s)
            s = _re.sub(r'[^a-z0-9-]', '', s)
            s = _re.sub(r'-+', '-', s)
            return s.strip('-') or "unknown-user"

        def _folder_name(slug):
            """Convert slug 'david-vavro' → 'david-vavro-private' (always lowercase).
            Consistent with _admin_setup_private_folder and _make_user_id."""
            return slug + "-private"

        import os as _os
        privates_root = str(_Path.home() / "Documents" / "AI-Prowler-Server-privates")

        # Build the set of slugs we WANT (users with private enabled).
        want = {}   # slug → default prefix path
        for rec in (data.get("users") or {}).values():
            if not isinstance(rec, dict):
                continue
            if not rec.get("private_collection_enabled"):
                continue
            name = rec.get("name", "")
            if not name:
                continue
            slug   = _slug(name)
            folder = _folder_name(slug)
            want[slug] = privates_root + _os.sep + folder

        # Build a lookup of EXISTING user rules so we can preserve custom paths.
        cmap = data.setdefault("collection_map", {})
        old_rules = cmap.get("rules") or []
        existing_user_paths = {}   # slug → existing prefix (if already set)
        kept_non_user = []
        for r in old_rules:
            col = r.get("collection", "")
            if col.startswith("user:"):
                slug = col[len("user:"):]
                existing_user_paths[slug] = r.get("prefix", "")
            else:
                kept_non_user.append(r)

        # Build new user rules: preserve existing paths, use default for new users.
        new_user_rules = []
        for slug, default_prefix in sorted(want.items()):
            prefix = existing_user_paths.get(slug) or default_prefix
            new_user_rules.append({"prefix": prefix, "collection": f"user:{slug}"})

        cmap["rules"] = kept_non_user + new_user_rules
        cmap.setdefault("default_collection", "shared")

    def _admin_confirm_child_key(self, child_key):
        """Validate an assigned child key on Save. Returns True to proceed,
        False to abort. A hard rejection (valid:false) blocks; a network error
        is non-fatal and offers to proceed (re-validated automatically later).
        An empty key (no seat) always proceeds."""
        from tkinter import messagebox
        if not child_key:
            return True
        ok, msg = self._admin_validate_child_key(child_key)
        if ok is True:
            return True
        if ok is None:
            # Network/offline — offer to proceed.
            return messagebox.askyesno(
                "License server unreachable",
                f"{msg}\n\nAssign this seat anyway? It will be validated "
                "automatically the next time the server can reach the license "
                "service.")
        # ok is False — hard rejection.
        messagebox.showerror("License key rejected",
                             f"{msg}\n\nThis seat was not assigned.")
        return False

    def _admin_add_user(self):
        """Add a new user: collect fields, generate a bearer token, write
        users.json, then show the token so the admin can send it securely."""
        from tkinter import messagebox
        if not self._admin_gate():
            return
        fields = self._admin_user_dialog("Add User")
        if not fields:
            return
        data = self._admin_load_users()
        users = data.setdefault("users", {})

        # Guard: only one owner. If adding an owner and one exists, refuse.
        if fields["role"] == "owner":
            for u in users.values():
                if isinstance(u, dict) and u.get("role") == "owner":
                    messagebox.showerror(
                        "Owner exists",
                        "There is already an owner. Only one owner is allowed; "
                        "change the existing owner's role first if you need to "
                        "transfer ownership.")
                    return

        # Guard: the chosen seat must not already be taken (race vs. another edit).
        child_key = fields.get("child_license_key", "")
        if child_key and child_key in self._admin_assigned_keys(data):
            messagebox.showerror(
                "Seat already assigned",
                "That license seat is already assigned to another user. "
                "Refresh and pick a different seat.")
            return
        # Validate the seat on Save (public /license/validate).
        if not self._admin_confirm_child_key(child_key):
            return

        # Bearer token: use the admin's custom value if provided, else generate
        # a strong random one. A custom token must be unique and not trivially
        # short (a token is a password).
        custom = (fields.get("custom_token") or "").strip()
        if custom:
            if len(custom) < 8:
                messagebox.showerror(
                    "Token too short",
                    "A custom bearer token must be at least 8 characters "
                    "(it's the employee's password). Use a longer value or "
                    "leave it blank to auto-generate a strong one.")
                return
            if custom in users:
                messagebox.showerror(
                    "Token already in use",
                    "That bearer token is already assigned to another user. "
                    "Choose a different value or leave it blank to auto-generate.")
                return
            token = custom
        else:
            token = self._admin_gen_token()
            while token in users:  # extremely unlikely collision guard
                token = self._admin_gen_token()

        import datetime as _dt
        users[token] = {
            "name": fields["name"],
            "email": fields["email"],
            "cell_phone": fields.get("cell_phone", ""),
            "role": fields["role"],
            "scopes": fields["scopes"],
            "can_manage_users": fields["can_manage_users"],
            "private_collection_enabled": fields["private_collection_enabled"],
            "child_license_key": child_key,
            "status": "active",
            "added": _dt.date.today().isoformat(),
        }
        if not self._admin_save_users(data):
            return
        self._admin_refresh_table()
        self._admin_show_token(fields["name"], token)
        if fields.get("private_collection_enabled"):
            self._admin_setup_private_folder(fields["name"], fields.get("slug", ""))

        # Phase 7 — notify subscription worker of seat assignment (non-blocking)
        # Fires for v8 business plans where seat_id comes from license_seats.json
        if child_key and child_key.startswith("AP-BIZ-"):
            self._admin_worker_assign_seat(child_key, fields["email"] or fields["name"])

    def _admin_show_token(self, name, token):
        """Show the freshly generated bearer token with a Copy button. This is
        the ONLY time it's displayed in full — it's stored as the users.json key."""
        import tkinter as tk
        from tkinter import ttk
        dlg = tk.Toplevel(self.root)
        dlg.title("Bearer Token")
        dlg.transient(self.root)
        dlg.grab_set()
        frm = ttk.Frame(dlg, padding=14)
        frm.pack(fill='both', expand=True)
        ttk.Label(frm, text=f"Bearer token for {name}:",
                  font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        ttk.Label(frm, wraplength=440, justify='left',
                  text="Send this to the employee securely. They paste it into "
                       "their Claude MCP connector to authenticate to this server. "
                       "Treat it like a password — this is the only time it's "
                       "shown in full.").pack(anchor='w', pady=(2, 8))

        # v7.0.1 security: token is masked by default so a shoulder-surfer or
        # screen-share cannot capture it. Admin must explicitly click Reveal.
        _reveal_var = tk.BooleanVar(value=False)
        ent = ttk.Entry(frm, width=46, font=('Consolas', 11), show='●')
        ent.pack(fill='x')
        ent.insert(0, token)
        ent.selection_range(0, 'end')
        ent.configure(state='readonly')

        def _toggle_reveal():
            ent.configure(state='normal')
            ent.configure(show='' if _reveal_var.get() else '●')
            ent.configure(state='readonly')

        rev_row = ttk.Frame(frm)
        rev_row.pack(anchor='w', pady=(4, 0))
        ttk.Checkbutton(rev_row, text="👁 Reveal token",
                        variable=_reveal_var,
                        command=_toggle_reveal).pack(side='left')

        def _copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(token)
            copy_btn.configure(text="✓ Copied")
        copy_btn = ttk.Button(frm, text="📋 Copy to Clipboard", command=_copy)
        copy_btn.pack(pady=(8, 0))
        ttk.Button(frm, text="Close", command=dlg.destroy).pack(pady=(6, 0))
        ent.focus_set()

    def _admin_setup_private_folder(self, name, slug):
        """After adding a user with private_collection_enabled, show a dialog
        that prompts the admin to create the private directory on disk.

        The expected path is pre-filled and editable — the admin can correct
        the drive letter, root, or folder name if their setup differs from the
        default. A 'Create Folder' button calls os.makedirs() right there.
        Skipping leaves the collection_map rule in place; the folder can be
        created later, but a reminder note is shown.

        v7.0.1 — prevents the silent failure where the rule exists but the
        folder doesn't, causing all private queries to return zero results.
        """
        import tkinter as tk
        from tkinter import ttk, messagebox, filedialog
        import os, re as _re
        from pathlib import Path as _Path

        # Build default folder name: "David Vavro" → "david-vavro-private" (always lowercase)
        # Uses the same slug logic as _make_user_id so folder name and user id are consistent.
        folder_name = (slug or "unknown-user") + "-private"
        default_root = str(_Path.home() / "Documents" / "AI-Prowler-Server-privates")
        default_path = default_root + os.sep + folder_name

        dlg = tk.Toplevel(self.root)
        dlg.title("Set Up Private Folder")
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.resizable(True, False)
        dlg.minsize(520, 0)

        frm = ttk.Frame(dlg, padding=16)
        frm.pack(fill='both', expand=True)

        ttk.Label(frm, text=f"📁  Private folder for {name}",
                  font=('Segoe UI', 11, 'bold')).pack(anchor='w')
        ttk.Label(frm, wraplength=480, justify='left', foreground='gray',
                  text=(f"This user has a private collection enabled. "
                        f"Create the folder below so their private documents "
                        f"can be indexed. The path is editable — change it if "
                        f"your server layout differs from the default.")
                  ).pack(anchor='w', pady=(4, 10))

        # Editable path row
        path_row = ttk.Frame(frm)
        path_row.pack(fill='x', pady=(0, 4))
        path_var = tk.StringVar(value=default_path)
        path_entry = ttk.Entry(path_row, textvariable=path_var,
                               font=('Consolas', 9), width=52)
        path_entry.pack(side='left', fill='x', expand=True)

        def _browse():
            chosen = filedialog.askdirectory(
                title="Select or create parent folder",
                initialdir=default_root if _Path(default_root).exists() else str(_Path.home()))
            if chosen:
                # Append the folder name so the admin picks the parent, not the full path
                path_var.set(chosen.rstrip('/\\') + os.sep + folder_name)

        ttk.Button(path_row, text="Browse…", command=_browse).pack(
            side='left', padx=(6, 0))

        status_var = tk.StringVar(value="")
        status_lbl = ttk.Label(frm, textvariable=status_var,
                               font=('Segoe UI', 9), wraplength=480, justify='left')
        status_lbl.pack(anchor='w', pady=(4, 0))

        def _create():
            p = path_var.get().strip()
            if not p:
                messagebox.showwarning("No path", "Enter a folder path first.", parent=dlg)
                return
            try:
                _Path(p).mkdir(parents=True, exist_ok=True)
                status_var.set(f"✅  Folder created:  {p}")
                status_lbl.configure(foreground='#1a7a1a')
                # Update collection_map in users.json so the rule points to
                # the actual path the admin chose (may differ from default).
                self._admin_update_private_rule(slug, p)
                create_btn.configure(state='disabled')
            except Exception as e:
                status_var.set(f"❌  Could not create folder: {e}")
                status_lbl.configure(foreground='#cc0000')

        def _skip():
            status_var.set(
                "⚠  Skipped — remember to create the folder before indexing "
                "private documents for this user.")
            status_lbl.configure(foreground='#a05a00')
            dlg.after(2200, dlg.destroy)

        btn_row = ttk.Frame(frm)
        btn_row.pack(fill='x', pady=(12, 0))
        create_btn = ttk.Button(btn_row, text="📁 Create Folder",
                                command=_create, style='Accent.TButton')
        create_btn.pack(side='left', padx=(0, 8))
        ttk.Button(btn_row, text="Skip for now", command=_skip).pack(side='left')
        ttk.Button(btn_row, text="Close", command=dlg.destroy).pack(side='right')

        dlg.wait_window()

    def _admin_get_private_rule_path(self, slug):
        """Return the current collection_map prefix for user:<slug>, or None
        if no rule exists. Used to check whether a custom path was already
        set before deciding whether to show the folder setup popup."""
        if not slug:
            return None
        try:
            data = self._admin_load_users()
            rules = (data.get("collection_map") or {}).get("rules") or []
            target = f"user:{slug}"
            for rule in rules:
                if rule.get("collection") == target:
                    return rule.get("prefix") or None
        except Exception:
            pass
        return None

    def _admin_update_private_rule(self, slug, actual_path):
        """Update the collection_map rule for user:<slug> to point to actual_path.
        Called when the admin edits the default path in the private-folder dialog.
        No-op if the path already matches or the user has no rule."""
        if not slug or not actual_path:
            return
        try:
            data = self._admin_load_users()
            cmap = data.get("collection_map") or {}
            rules = cmap.get("rules") or []
            target = f"user:{slug}"
            updated = False
            for rule in rules:
                if rule.get("collection") == target:
                    rule["prefix"] = actual_path
                    updated = True
                    break
            if updated:
                cmap["rules"] = rules
                data["collection_map"] = cmap
                # Write directly without re-syncing (we want to keep the admin's path)
                import json as _json, os as _os
                p = self._admin_users_path()
                tmp = p.with_suffix(".json.tmp")
                tmp.write_text(_json.dumps(data, indent=2), encoding="utf-8")
                _os.replace(str(tmp), str(p))
        except Exception as e:
            print(f"[admin] could not update private rule for {slug}: {e}")

    def _admin_edit_user(self):
        """Edit the selected user's fields (not the token)."""
        from tkinter import messagebox
        if not self._admin_gate():
            return
        token = self._admin_selected_token()
        if not token:
            messagebox.showinfo("Edit", "Select a user first.")
            return
        data = self._admin_load_users()
        u = (data.get("users") or {}).get(token)
        if not isinstance(u, dict):
            messagebox.showerror("Edit", "User not found (refresh the table).")
            return
        was_owner = (u.get("role") == "owner")
        had_private = bool(u.get("private_collection_enabled"))
        fields = self._admin_user_dialog(f"Edit User — {u.get('name','')}", existing=u)
        if not fields:
            return
        # If demoting the only owner, warn (a server with no owner loses custody).
        if was_owner and fields["role"] != "owner":
            owners = sum(1 for x in (data.get("users") or {}).values()
                         if isinstance(x, dict) and x.get("role") == "owner")
            if owners <= 1 and not messagebox.askyesno(
                    "Demote owner?",
                    "This is the only owner. Demoting them leaves the company "
                    "server with no owner (no full data custody). Continue?"):
                return
        # Seat (child key) handling: guard against taking a seat another user
        # already holds (excluding this user's own current key), and validate on
        # Save if the key changed.
        new_key = fields.get("child_license_key", "")
        old_key = u.get("child_license_key", "")
        if new_key and new_key != old_key:
            others = self._admin_assigned_keys(data) - ({old_key} if old_key else set())
            if new_key in others:
                messagebox.showerror(
                    "Seat already assigned",
                    "That license seat is already assigned to another user. "
                    "Refresh and pick a different seat.")
                return
            if not self._admin_confirm_child_key(new_key):
                return
        u.update({
            "name": fields["name"], "email": fields["email"],
            "role": fields["role"], "scopes": fields["scopes"],
            "can_manage_users": fields["can_manage_users"],
            "private_collection_enabled": fields["private_collection_enabled"],
            "child_license_key": new_key,
        })
        # Persist optional recovery contact field if provided.
        if fields.get("cell_phone"):
            u["cell_phone"] = fields["cell_phone"]
        if self._admin_save_users(data):
            self._admin_refresh_table()
            self._admin_update_lock_ui()
            # Show the private folder setup popup if:
            #   (a) private collection is enabled, AND
            #   (b) the folder doesn't exist on disk yet
            # This covers both "newly enabled" and "was already enabled but
            # admin never created the folder" (e.g. migrated from old schema).
            if fields["private_collection_enabled"]:
                slug = fields.get("slug", "")
                from pathlib import Path as _Path
                import os as _os
                folder_name = (slug or "unknown-user") + "-private"
                privates_root = str(_Path.home() / "Documents" / "AI-Prowler-Server-privates")
                expected_path = privates_root + _os.sep + folder_name
                # Also check any custom path already in collection_map
                existing_path = self._admin_get_private_rule_path(slug) or expected_path
                if not _Path(existing_path).exists():
                    self._admin_setup_private_folder(fields["name"], slug)

    def _admin_regen_token(self):
        """Regenerate the selected user's bearer token (revocation in 5s, spec
        §5.3). The old token immediately stops authenticating once saved."""
        from tkinter import messagebox
        if not self._admin_gate():
            return
        token = self._admin_selected_token()
        if not token:
            messagebox.showinfo("Regenerate", "Select a user first.")
            return
        data = self._admin_load_users()
        users = data.get("users") or {}
        u = users.get(token)
        if not isinstance(u, dict):
            messagebox.showerror("Regenerate", "User not found (refresh the table).")
            return
        if not messagebox.askyesno(
                "Regenerate token",
                f"Regenerate the bearer token for {u.get('name','')}?\n\n"
                "Their OLD token will stop working immediately. You'll need to "
                "send them the new one."):
            return
        new_token = self._admin_gen_token()
        while new_token in users:
            new_token = self._admin_gen_token()
        # Move the record to the new key (the token IS the key).
        users[new_token] = u
        del users[token]
        if self._admin_save_users(data):
            self._admin_refresh_table()
            self._admin_update_lock_ui()
            self._admin_show_token(u.get("name", ""), new_token)

    def _admin_toggle_status(self):
        """Toggle a user between active and suspended (soft revoke — keeps the
        record but _resolve_user denies access)."""
        from tkinter import messagebox
        if not self._admin_gate():
            return
        token = self._admin_selected_token()
        if not token:
            messagebox.showinfo("Suspend", "Select a user first.")
            return
        data = self._admin_load_users()
        u = (data.get("users") or {}).get(token)
        if not isinstance(u, dict):
            messagebox.showerror("Suspend", "User not found (refresh the table).")
            return
        cur = u.get("status", "active")
        u["status"] = "suspended" if cur == "active" else "active"
        if self._admin_save_users(data):
            self._admin_refresh_table()
            self._admin_update_lock_ui()

    def _admin_remove_user(self):
        """Permanently remove a user from users.json."""
        from tkinter import messagebox
        if not self._admin_gate():
            return
        token = self._admin_selected_token()
        if not token:
            messagebox.showinfo("Remove", "Select a user first.")
            return
        data = self._admin_load_users()
        u = (data.get("users") or {}).get(token)
        if not isinstance(u, dict):
            messagebox.showerror("Remove", "User not found (refresh the table).")
            return
        if u.get("role") == "owner":
            messagebox.showerror(
                "Cannot remove owner",
                "The owner cannot be removed. Transfer ownership first by editing "
                "another user to the owner role, then change this one's role.")
            return
        if not messagebox.askyesno(
                "Remove user",
                f"Permanently remove {u.get('name','')}?\n\nTheir token will stop "
                "working. This cannot be undone."):
            return
        child_key = u.get("child_license_key", "")
        seat_id   = u.get("seat_id", "") or u.get("license_seat_id", "")
        del data["users"][token]
        if self._admin_save_users(data):
            self._admin_refresh_table()
            self._admin_update_lock_ui()
            # v8.0.0 — owner's explicit choice of which seat to remove. This
            # actually SUSPENDS the seat's own child license key (not just
            # returns it to the unassigned pool) since the owner specifically
            # picked this person to remove — see revoke_seats() / the Worker's
            # POST /seats/{key}/revoke. The departing employee's machine picks
            # this up on its next license check and starts the normal 30-day
            # grace countdown, same soft-cancellation behavior as elsewhere.
            if seat_id:
                self._admin_worker_revoke_seat(seat_id)
            elif child_key and child_key.startswith("AP-CHLD-"):
                # Fallback for older user records that only stored the child
                # key, not the seat_id — fire-and-forget unassign so the seat
                # at least frees up; it won't be suspended until the owner
                # also runs a Worker-side cleanup, but this avoids erroring.
                self._admin_worker_unassign_seat(child_key)

    def _admin_worker_assign_seat(self, seat_id, email):
        """Fire-and-forget: tell the subscription worker a seat was assigned.
        Runs on a daemon thread — never blocks the GUI or fails the local save."""
        import threading as _th

        def _call():
            try:
                import sys as _sys, os as _os
                _app = _os.path.dirname(_os.path.abspath(__file__))
                if _app not in _sys.path:
                    _sys.path.insert(0, _app)
                import subscription_client as _sc
                cfg = load_config() if RAG_AVAILABLE else {}
                license_key = cfg.get("license_key", "")
                if not license_key:
                    return
                _sc.assign_seat(license_key, seat_id, email)
                print(f"[admin] worker: seat {seat_id} assigned to {email}")
            except Exception as _ex:
                # Non-fatal — local save already succeeded. Worker will re-sync
                # on next ☁ Sync Seats press.
                print(f"[admin] worker seat assign failed (non-fatal): {_ex}")

        _th.Thread(target=_call, daemon=True).start()

    def _admin_worker_unassign_seat(self, seat_id):
        """Fire-and-forget: tell the subscription worker a seat was released.
        Runs on a daemon thread — never blocks the GUI or fails the local delete."""
        import threading as _th

        def _call():
            try:
                import sys as _sys, os as _os
                _app = _os.path.dirname(_os.path.abspath(__file__))
                if _app not in _sys.path:
                    _sys.path.insert(0, _app)
                import subscription_client as _sc
                cfg = load_config() if RAG_AVAILABLE else {}
                license_key = cfg.get("license_key", "")
                if not license_key:
                    return
                _sc.unassign_seat(license_key, seat_id)
                print(f"[admin] worker: seat {seat_id} released")
            except Exception as _ex:
                print(f"[admin] worker seat unassign failed (non-fatal): {_ex}")

        _th.Thread(target=_call, daemon=True).start()

    def _admin_worker_revoke_seat(self, seat_id):
        """Fire-and-forget: tell the subscription worker the owner has
        EXPLICITLY chosen to revoke this specific seat — immediately
        suspends that seat's own child license key (v8.0.0). Runs on a
        daemon thread — never blocks the GUI or fails the local removal."""
        import threading as _th

        def _call():
            try:
                import sys as _sys, os as _os
                _app = _os.path.dirname(_os.path.abspath(__file__))
                if _app not in _sys.path:
                    _sys.path.insert(0, _app)
                import subscription_client as _sc
                cfg = load_config() if RAG_AVAILABLE else {}
                license_key = cfg.get("license_key", "")
                if not license_key:
                    return
                result = _sc.revoke_seats(license_key, [seat_id])
                print(f"[admin] worker: seat {seat_id} revoked — {result}")
            except Exception as _ex:
                print(f"[admin] worker seat revoke failed (non-fatal): {_ex}")

        _th.Thread(target=_call, daemon=True).start()

    def _on_tab_changed(self, event=None):
        """Handle tab switches."""
        try:
            selected = self.notebook.index(self.notebook.select())
            if selected == self._TAB_INDEX_QUERY:
                self._trigger_prewarm()
            # Settings tab: no synchronous refresh — background poller keeps list current
        except Exception:
            pass

    def _ensure_ollama_disabled(self):
        """
        Called at startup when SUPPORT_LOCAL_HW_LLM is False (Claude-MCP-only mode).

        Ollama is not needed when Claude MCP is the only AI interface.
        This method silently:
          1. Kills the 'ollama app' tray watchdog (it relaunches ollama.exe if left alive)
          2. Removes 'ollama app' from the Windows startup registry so it never
             auto-launches on boot again
          3. Sets the Ollama Windows Service to manual start
          4. Stops the Ollama service and kills any remaining ollama.exe processes

        Runs entirely in a background thread — never blocks the GUI.
        """
        def _do_disable():
            try:
                if sys.platform != 'win32':
                    return

                import winreg

                # ── Step 1: Kill the tray watchdog first ─────────────────────
                # 'ollama app' is the system-tray process that relaunches
                # ollama.exe every time it is killed. Must die before we stop
                # the service, otherwise it immediately restarts it.
                for tray_exe in ('ollama app.exe', 'ollama_app.exe'):
                    subprocess.run(
                        f'taskkill /F /T /IM "{tray_exe}"',
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
                print("[Ollama] Tray watchdog terminated.")

                # ── Step 2: Remove tray app from Windows startup registry ────
                # Ollama installer adds itself to:
                #   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
                # under the key name 'Ollama'.  Remove it so it never comes
                # back after the next reboot.
                startup_keys = [
                    (winreg.HKEY_CURRENT_USER,
                     r'Software\Microsoft\Windows\CurrentVersion\Run'),
                    (winreg.HKEY_LOCAL_MACHINE,
                     r'Software\Microsoft\Windows\CurrentVersion\Run'),
                    (winreg.HKEY_LOCAL_MACHINE,
                     r'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
                ]
                for hive, subkey in startup_keys:
                    try:
                        with winreg.OpenKey(hive, subkey,
                                            0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
                            # Enumerate all values and remove any whose data
                            # path contains 'ollama' (case-insensitive)
                            to_delete = []
                            try:
                                i = 0
                                while True:
                                    name, data, _ = winreg.EnumValue(k, i)
                                    if 'ollama' in str(data).lower() or \
                                       'ollama' in str(name).lower():
                                        to_delete.append(name)
                                    i += 1
                            except OSError:
                                pass   # end of values
                            for name in to_delete:
                                try:
                                    winreg.DeleteValue(k, name)
                                    print(f"[Ollama] Removed startup entry: '{name}'")
                                except Exception:
                                    pass
                    except Exception:
                        pass   # key doesn't exist or no write access — skip

                # ── Step 3: Disable the Windows Service ──────────────────────
                svc_check = subprocess.run(
                    'sc query ollama',
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True)
                if svc_check.returncode != 0:
                    print("[Ollama] Windows Service not found — skipping service steps.")
                else:
                    # Set to manual so it never auto-starts on reboot
                    subprocess.run(
                        'sc config ollama start= demand',
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)

                    # Stop the service if running
                    if 'RUNNING' in (svc_check.stdout or ''):
                        subprocess.run(
                            'sc stop ollama',
                            shell=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
                        print("[Ollama] Service stopped.")
                    else:
                        print("[Ollama] Service was not running.")

                # ── Step 4: Kill any remaining ollama.exe processes ──────────
                subprocess.run(
                    'taskkill /F /T /IM ollama.exe',
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)

                print("[Ollama] Fully disabled — will not auto-start on next boot.")

            except Exception as e:
                print(f"[Ollama] _ensure_ollama_disabled error (non-fatal): {e}")

        threading.Thread(target=_do_disable, daemon=True).start()

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
        # ── Feature-flag gate ─────────────────────────────────────────────────
        # When SUPPORT_LOCAL_HW_LLM is False (the v6.0+ default) the local
        # Ollama Q&A surface is hidden, so prewarming is wasted work and the
        # footer status message would confuse the user. Skip silently — every
        # caller of _trigger_prewarm sits behind a UI that's also hidden, so
        # the early return is safe.
        if not SUPPORT_LOCAL_HW_LLM:
            return
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
        items   = self.queue_listbox.get(0, tk.END)
        n_files = sum(1 for p in items if Path(p).is_file())
        n_dirs  = len(items) - n_files
        parts   = []
        if n_dirs:  parts.append(f"{n_dirs} folder{'s' if n_dirs  != 1 else ''}")
        if n_files: parts.append(f"{n_files} file{'s'  if n_files != 1 else ''}")
        self.queue_count_var.set(f"Queue: {', '.join(parts) if parts else '0 items'}")

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

    def _prewarm_embedding_model(self):
        """
        Download and cache the sentence-transformers embedding model on startup.

        Runs unconditionally (regardless of SUPPORT_LOCAL_HW_LLM) because the
        embedding model is required by ALL indexing and update operations, not
        just the Ollama Q&A path.

        On a fresh install the model (~90 MB) must be downloaded from HuggingFace
        before get_chroma_client() can succeed.  If the user clicks Update All
        before this download completes, the GUI hangs.  This method prevents that
        by:
          1. Disabling Update All / Update Selected while the download runs.
          2. Showing a clear status-bar message so the user knows what is happening.
          3. Re-enabling those buttons and running _reconcile_tracked_index()
             once the model is cached and ChromaDB is initialised.

        On subsequent launches the model is already in the HuggingFace cache so
        get_chroma_client() returns in <1 s — the brief button-disable is invisible.
        """
        if not RAG_AVAILABLE:
            return

        # Disable update buttons to prevent a hang if the user clicks before ready
        try:
            self.update_selected_btn.configure(state='disabled')
            self.update_all_btn.configure(state='disabled')
        except Exception:
            pass

        self.status_var.set("⬇ Preparing embedding model…")

        def _worker():
            try:
                # get_chroma_client() initialises ChromaDB AND downloads/loads
                # the embedding model.  This is the exact same call that
                # Update All makes, so completing it here guarantees Update All
                # will not hang.
                # NOTE: Do NOT write anything to ChromaDB here. Any write
                # immediately after client init races the HNSW compactor and
                # causes "Failed to apply logs to the hnsw segment writer".
                # The user guide will be indexed on the user's first Update All.
                from rag_preprocessor import get_chroma_client
                get_chroma_client()
                self.output_queue.put(('embedding_ready', None))
            except Exception as e:
                self.output_queue.put(('embedding_ready_error', str(e)))

        threading.Thread(target=_worker, daemon=True).start()

    def _reconcile_tracked_index(self):
        """First-launch reconcile: index tracked files that have no chunks yet.

        Reads the auto-update tracking list and, for any tracked path that is a
        FILE with zero chunks in ChromaDB, indexes it. The canonical case is the
        COMPLETE_USER_GUIDE.md the installer seeds into the tracking list but
        never indexes. Runs once per launch in a background thread.

        Safety: purely additive. We only ever index files we find MISSING from
        the collection, one at a time via index_file_list (whose delete is
        scoped to each file's own filepath). Nothing here purges, clears, or
        resets the collection, so an existing database is never destroyed —
        even if the tracking list is large or partly already-indexed.
        """
        if not RAG_AVAILABLE:
            return

        def _worker():
            try:
                from rag_preprocessor import (
                    get_chroma_client, create_or_get_collection)
                try:
                    tracked = load_auto_update_list() or []
                except Exception as _le:
                    print(f"[Reconcile] Could not read tracking list: {_le}")
                    return

                # Only individual files can be probed by chunk_0; directories
                # are left to the normal Update Index flow.
                file_paths = [normalise_path(p) for p in tracked
                              if os.path.isfile(p)]
                if not file_paths:
                    return

                client, emb_fn = get_chroma_client()
                collection = create_or_get_collection(client, emb_fn)

                missing = []
                for fp in file_paths:
                    try:
                        probe = collection.get(ids=[f"{fp}__chunk_0"])
                        if not (probe and probe.get('ids')):
                            missing.append(fp)
                    except Exception:
                        # If the probe itself fails, treat as missing — worst
                        # case index_file_list refreshes the file's own chunks.
                        missing.append(fp)

                if not missing:
                    return

                print(f"[Reconcile] {len(missing)} tracked file(s) not yet "
                      f"indexed — indexing now (additive):")
                for fp in missing:
                    print(f"[Reconcile]   • {fp}")

                self.output_queue.put(
                    ('status', f"Indexing {len(missing)} tracked "
                               f"file{'s' if len(missing) != 1 else ''}…"))

                # index_file_list is per-file additive; root_directory is the
                # parent so provenance breadcrumbs match a single-file add.
                for fp in missing:
                    try:
                        index_file_list(
                            [fp],
                            label="reconcile",
                            root_directory=str(Path(fp).parent),
                        )
                    except Exception as _ie:
                        print(f"[Reconcile] Failed to index {fp}: {_ie}")

                self.output_queue.put(('status', '✅ Tracked files indexed'))
                print("[Reconcile] Done.")
            except Exception as _e:
                # Never let a reconcile problem affect the running GUI.
                print(f"[Reconcile] Skipped due to error: {_e}")

        threading.Thread(target=_worker, daemon=True).start()

    def _index_stop(self):
        """Signal the worker to stop after the current file."""
        self._index_stop_event.set()
        self._index_pause_event.clear()   # unblock if paused so it can see the stop
        self.index_stop_btn.configure(state='disabled')
        self.index_pause_btn.configure(state='disabled')
        self.status_var.set("⏹ Stopping after current file…")

    def _index_cancel(self):
        """
        Discard any saved resume state and return to idle.

        Works from two situations:
          - While running: signals the worker to stop (same as Stop), then
            clears the resume state so Start goes back to a fresh queue run.
          - After stopped: simply clears the resume state and returns to idle.

        The queue contents are left untouched so the user can remove the
        unwanted directory/file before starting again.
        """
        # If the worker is still running, signal it to abort first.
        if self._index_running:
            self._index_cancelled = True   # tell the done-handler to ignore index_stopped
            self._index_stop_event.set()
            self._index_pause_event.clear()

        # Discard resume state — next Start is a clean run.
        self._index_resume_dirs = []
        self._index_resume_file = 0

        self._stop_index_timer()
        self._index_set_buttons('idle')
        self.status_var.set("✕ Indexing cancelled — queue unchanged")

    def _register_directory_for_tracking(self, directory: str, recursive: bool):
        """
        Register a directory OR individual file in the auto-update tracking
        list and establish the file-change baseline.

        Baseline-write responsibility:
          • Directories — written here via scan_directory_for_changes(), which
            walks the tree and records every supported file's mtime/size.
          • Individual files — written by rag_preprocessor.index_file_list()
            itself as it indexes each file. We deliberately do NOT scan the
            file's parent directory here, because the user only opted to
            track that one file, not its siblings.
        """
        is_file = Path(directory).is_file()

        try:
            added = add_to_auto_update_list(directory)
            if added is True:
                kind = "file" if is_file else "directory"
                print(f"   ✅ Added {kind} to Update Index tracking list")
            elif isinstance(added, str):
                # Case-variant replacement — warn the user in the output log
                # and show a popup so it's not missed.
                print(f"   {added}")
                self.root.after(0, lambda msg=added: messagebox.showwarning(
                    "Duplicate Folder Name (Case Variant)", msg))
            else:
                print(f"   ℹ️  Already in tracking list")

            # Directories: scan-and-baseline the whole tree.
            # Files: skip — index_file_list writes the per-file baseline
            # as a side effect of indexing.
            if is_file:
                return

            result = scan_directory_for_changes(directory, recursive, quiet=True)
            if result:
                results, tracking_db, dir_key = result

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
          'idle'    — Start + Scan active, Pause/Stop/Cancel disabled
          'running' — Pause + Stop + Cancel active, Start/Scan disabled
          'stopped' — Start (Resume) + Cancel + Scan active, Pause/Stop disabled
        """
        if state == 'idle':
            self.index_start_btn.configure(text="▶ Start Indexing Queue",
                                           state='normal',
                                           command=self.start_indexing)
            self.index_pause_btn.configure(state='disabled', text="⏸ Pause")
            self.index_stop_btn.configure(state='disabled')
            self.index_cancel_btn.configure(state='disabled')
            self.index_scan_btn.configure(state='normal')

        elif state == 'running':
            self.index_start_btn.configure(state='disabled')
            self.index_pause_btn.configure(state='normal', text="⏸ Pause")
            self.index_stop_btn.configure(state='normal')
            self.index_cancel_btn.configure(state='normal')
            self.index_scan_btn.configure(state='disabled')

        elif state == 'stopped':
            self.index_start_btn.configure(text="▶ Resume Indexing",
                                           state='normal',
                                           command=lambda: self.start_indexing(resume=True))
            self.index_pause_btn.configure(state='disabled', text="⏸ Pause")
            self.index_stop_btn.configure(state='disabled')
            self.index_cancel_btn.configure(state='normal')
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
            grand_skipped_unchanged = grand_skipped_failed = 0

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

                    # In Business server mode pass a collection_resolver so
                    # each file lands in the correct scoped ChromaDB collection
                    # (shared, scope:office, etc.) as defined by collection_map
                    # in users.json. Personal/Home mode: resolver=None (unchanged).
                    _col_resolver = None
                    if self._is_business_server_mode():
                        try:
                            from rag_preprocessor import build_collection_resolver
                            _col_resolver = build_collection_resolver()
                            if _col_resolver is None:
                                print("   ℹ️  No collection_map rules found in users.json"
                                      " — indexing to default collection")
                        except Exception as _cre:
                            print(f"   ⚠️  collection_resolver unavailable: {_cre}"
                                  f" — indexing to default collection")
                            _col_resolver = None
                    stats = index_file_list(
                        file_paths,
                        label=f"{dir_idx}/{n_dirs}",
                        stop_event=self._index_stop_event,
                        pause_event=self._index_pause_event,
                        start_from=start_from,
                        root_directory=str(Path(directory).parent) if is_file else directory,
                        collection_resolver=_col_resolver,
                    )

                    # Register for tracking — use the file itself when a
                    # single file was queued, not the parent directory.
                    stopped_mid = stats.get('stopped_at', 0) > 0
                    if not stopped_mid:
                        track_path = directory if is_file else directory
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
                grand_skipped_unchanged += stats.get('skipped_unchanged', 0)
                grand_skipped_failed    += stats.get('skipped_failed',    0)
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
                    print(f"   Files indexed:            {grand_processed:,}")
                    if grand_skipped_unchanged:
                        print(f"   Files unchanged:          {grand_skipped_unchanged:,}"
                              f"  ← already up to date (skipped)")
                    if grand_skipped_failed:
                        print(f"   Files failed to load:     {grand_skipped_failed:,}"
                              f"  ← unreadable, empty, or unsupported format")
                    if grand_skipped_failed > 0 and grand_processed == 0:
                        print(f"   💡 Tip: click 'Scan Queue' to see exactly which files")
                        print(f"          and what extensions are in the directory.")
                    print(f"   Total chunks:             {grand_chunks:,}")
                    print(f"   Total words:              {grand_words:,}")
                # Build accurate summary — queue may contain files, folders, or both
                _n_files = sum(1 for d in directories if os.path.isfile(d))
                _n_fdirs = n_dirs - _n_files
                _parts   = []
                if _n_fdirs:  _parts.append(f"{_n_fdirs} folder{'s' if _n_fdirs != 1 else ''}")
                if _n_files:  _parts.append(f"{_n_files} file{'s' if _n_files != 1 else ''}")
                _items_desc = ', '.join(_parts) if _parts else f"{n_dirs} items"
                print(f"   Processed:      {_items_desc}")
                print(f"{'='*60}\n")
                self.output_queue.put(('index_progress', ''))
                self.output_queue.put(('status', f'✅ Indexing complete — {_items_desc} done'))
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

    def _derive_indexed_directories(self) -> set:
        """Return the set of directories that currently have chunks in ChromaDB.

        Derived from chunk metadata (root_directory, falling back to the parent
        of filepath) so the Update Index tab can reflect what is ACTUALLY in the
        database — not just the auto-update tracking list. Files indexed
        individually (which never register a directory in the tracking list)
        are represented by their parent directory.

        Returns an empty set on any error; the caller still shows the tracking
        list, so a DB hiccup never blanks the tab.
        """
        dirs = set()
        try:
            from rag_preprocessor import get_chroma_client, create_or_get_collection
            client, emb_fn = get_chroma_client()
            col = create_or_get_collection(client, emb_fn)
            result = col.get(include=['metadatas'])
            for meta in (result.get('metadatas') or []):
                if not isinstance(meta, dict):
                    continue
                root = (meta.get('root_directory') or '').strip()
                fp   = (meta.get('filepath') or '').strip()
                if root:
                    dirs.add(_rag_engine.normalise_path(root))
                elif fp:
                    dirs.add(_rag_engine.normalise_path(str(Path(fp).parent)))
        except Exception as _e:
            print(f"[TrackedList] Could not derive indexed dirs from DB: {_e}")
        return dirs

    def _derive_indexed_directories(self) -> set:
        """Return the set of directories that currently have chunks in ChromaDB.

        Derived from chunk metadata (root_directory, falling back to the parent
        of filepath) so the Update Index tab can reflect what is ACTUALLY in the
        database — not just the auto-update tracking list. Files indexed
        individually (which never register a directory in the tracking list)
        are represented by their parent directory.

        Returns an empty set on any error; the caller still shows the tracking
        list, so a DB hiccup never blanks the tab.
        """
        dirs = set()
        try:
            from rag_preprocessor import get_chroma_client, create_or_get_collection
            client, emb_fn = get_chroma_client()
            col = create_or_get_collection(client, emb_fn)
            result = col.get(include=['metadatas'])
            for meta in (result.get('metadatas') or []):
                if not isinstance(meta, dict):
                    continue
                root = (meta.get('root_directory') or '').strip()
                fp   = (meta.get('filepath') or '').strip()
                if root:
                    dirs.add(_rag_engine.normalise_path(root))
                elif fp:
                    dirs.add(_rag_engine.normalise_path(str(Path(fp).parent)))
        except Exception as _e:
            print(f"[TrackedList] Could not derive indexed dirs from DB: {_e}")
        return dirs

    def _display_scope(self, scope):
        """Render a logical collection name as a short, friendly scope tag for the
        tracked-dirs listing (v7.0.1). 'role:'/'scope:' buckets show as
        'scope:<name>'; 'shared' shows as 'shared'; a private 'user:<id>' or the
        unclassified 'documents' fallback shows as '(private)'."""
        s = (scope or "").strip()
        if not s or s.lower() == "documents":
            return "(private)"
        low = s.lower()
        if low == "shared":
            return "shared"
        if low.startswith("user:"):
            return "(private)"
        if low.startswith("scope:") or low.startswith("role:"):
            return "scope:" + s.split(":", 1)[1].strip()
        return "scope:" + s

    def refresh_tracked_dirs(self):
        """Refresh tracked directories list from the auto-update tracking file.

        Each row is rendered with a write-permission prefix indicating whether
        Claude can modify files in that path (Mobile Write Zones). The raw
        path is stored in self._tracked_raw_paths at the same index so
        callers can look it up without parsing the display string.
        """
        self.tracked_listbox.delete(0, tk.END)
        self._tracked_raw_paths = []

        if not RAG_AVAILABLE:
            self.tracked_listbox.insert(tk.END, "(AI Prowler engine not available)")
            self._tracked_raw_paths.append(None)
            return

        try:
            dirs = load_auto_update_list()
            writable_paths = self._load_writable_paths()
            # v7.0.1 (Q4): in Business server mode also show each folder's read
            # SCOPE next to its write-permission prefix. Load the collection_map
            # once here (not per-row) so the listing stays cheap. Personal/Home/
            # Mobile installs have no scopes — the column is omitted entirely.
            _server_scope = self._is_business_server_mode()
            _scope_rules, _scope_default = [], None
            if _server_scope:
                try:
                    _cm = (self._admin_load_users() or {}).get("collection_map") or {}
                    _scope_rules = _cm.get("rules") or []
                    _scope_default = _cm.get("default_collection")
                except Exception:
                    _scope_rules, _scope_default = [], None
            if dirs:
                for directory in dirs:
                    state, _exact, _narrower = self._writable_state(
                        directory, writable_paths
                    )
                    # Text-based indicators (instead of emoji) — Courier renders
                    # these crisply on every Windows install; emoji glyphs vary
                    # by font and are easy to misread. Pad to 4 chars so paths
                    # align in a column.
                    if state == "full":
                        prefix = "[W] "
                    elif state == "partial":
                        prefix = "[W*]"
                    else:
                        prefix = "[R] "
                    self.tracked_listbox.insert(  # v7.0.1 Q4: scope column in server mode
                          tk.END,
                          (f"{prefix} {self._display_scope(self._resolve_scope_for_path(directory, _scope_rules, _scope_default)):<13} {directory}"
                           if _server_scope else f"{prefix} {directory}"))
                    self._tracked_raw_paths.append(directory)
            else:
                self.tracked_listbox.insert(
                    tk.END,
                    "(No tracked items yet — index a directory or file first)"
                )
                self._tracked_raw_paths.append(None)
        except Exception as e:
            self.tracked_listbox.insert(tk.END, f"(Error loading list: {e})")
            self._tracked_raw_paths.append(None)

    # ══════════════════════════════════════════════════════════════════════
    # Mobile Write Zones — write-permission management for the tracked-path
    # list. The writable allowlist (~/.rag_writable_dirs.json) is read by
    # ai_prowler_mcp.py's _resolve_writable_path() to decide whether Claude
    # can modify a given file. This GUI lets the user pre-authorize zones
    # from the desktop, so mobile sessions don't stall waiting on dialogs.
    # ══════════════════════════════════════════════════════════════════════

    # File location mirrors ai_prowler_mcp.py:_WRITABLE_DIRS_FILE.
    # Defined as a property so a single source of truth is easy to refactor.
    @property
    def _writable_dirs_file(self):
        return Path.home() / ".rag_writable_dirs.json"

    def _load_writable_paths(self) -> list:
        """Read ~/.rag_writable_dirs.json. Returns [] on any error or missing file."""
        try:
            f = self._writable_dirs_file
            if not f.exists():
                return []
            import json as _json
            with open(f, "r", encoding="utf-8") as fh:
                data = _json.load(fh)
            if isinstance(data, list):
                return [str(p) for p in data if isinstance(p, str)]
            return []
        except Exception:
            return []

    def _save_writable_paths(self, paths: list) -> bool:
        """Write ~/.rag_writable_dirs.json. Returns True on success."""
        try:
            f = self._writable_dirs_file
            f.parent.mkdir(parents=True, exist_ok=True)
            import json as _json
            with open(f, "w", encoding="utf-8") as fh:
                _json.dump(sorted(set(paths)), fh, indent=2)
            return True
        except Exception as e:
            messagebox.showerror(
                "Cannot save Mobile Write Zones",
                f"Failed to write {self._writable_dirs_file}:\n\n{e}"
            )
            return False

    def _is_path_writable(self, path: str, writable_paths: list) -> bool:
        """True if `path` is exactly in or is a descendant of any entry in writable_paths.

        Comparison is case-insensitive on Windows; case-sensitive elsewhere.
        Empty writable_paths => always False.

        Kept for backward compatibility. New code should prefer
        _writable_state(), which distinguishes 'full' / 'partial' / 'none'.
        """
        state, _, _ = self._writable_state(path, writable_paths)
        return state == "full"

    def _writable_state(self, path: str, writable_paths: list):
        """Classify a tracked path's write-permission state.

        Returns a 3-tuple (state, exact_match, narrower_grants) where:
            state           — one of 'full', 'partial', 'none':
                              'full'    — path itself OR an ancestor is granted
                              'partial' — some descendant is granted, but path/ancestors aren't
                              'none'    — no overlap with any grant
            exact_match     — True iff `path` itself is literally in writable_paths
                              (only meaningful when state == 'full').
            narrower_grants — list[str] of grant entries strictly *under* path,
                              non-empty only when state == 'partial'.

        Comparison uses pathlib.Path normalization (case handling matches the
        filesystem). All three return values can be computed in one pass.
        """
        if not writable_paths:
            return ("none", False, [])
        try:
            target = Path(path).resolve()
        except Exception:
            target = Path(path)

        # Normalize the input list once
        normalized: list = []
        for w in writable_paths:
            try:
                normalized.append((w, Path(w).resolve()))
            except Exception:
                normalized.append((w, Path(w)))

        def _is_under(child: Path, parent: Path) -> bool:
            """child == parent OR child is strictly inside parent."""
            if child == parent:
                return True
            try:
                return child.is_relative_to(parent)
            except AttributeError:
                c = str(child).rstrip("/\\")
                p = str(parent).rstrip("/\\")
                return c == p or c.startswith(p + "\\") or c.startswith(p + "/")

        exact_match = False
        ancestor_grant = False
        narrower: list = []

        for raw, granted in normalized:
            if target == granted:
                exact_match = True
                ancestor_grant = True   # exact is a degenerate ancestor
            elif _is_under(target, granted):
                ancestor_grant = True
            elif _is_under(granted, target):
                # `granted` is strictly inside `target`
                narrower.append(raw)

        if ancestor_grant:
            return ("full", exact_match, narrower)
        if narrower:
            return ("partial", False, narrower)
        return ("none", False, [])

    def _toggle_writable_for_selected(self):
        """Toggle write permission for the path under the current selection.

        Three transitions are possible depending on the row's current state:
          [R]  → [W]   grant write access (confirmation dialog)
          [W*] → [W]   widen narrower sub-grants up to this row (confirmation
                       dialog listing the entries that will be absorbed)
          [W]  → [R]   revoke (immediate, no confirmation) — only if this row
                       has an exact-match grant; if write access is inherited
                       from an ancestor, show an info dialog explaining where
                       the grant actually lives.
        """
        sel = self.tracked_listbox.curselection()
        if not sel:
            return  # silent — double-click in empty space is harmless
        row_idx = sel[0]
        if row_idx >= len(self._tracked_raw_paths):
            return
        raw_path = self._tracked_raw_paths[row_idx]
        if raw_path is None:
            return  # placeholder / error row, no path to toggle

        writable_paths = self._load_writable_paths()
        state, exact_match, narrower = self._writable_state(
            raw_path, writable_paths
        )

        # IMPORTANT: the read allowlist stores paths with forward slashes
        # ("C:/Users/...") while the writable allowlist stores them with
        # backslashes ("C:\\Users\\..."). Plain string compares fail across
        # the two conventions, so we normalize via pathlib before any
        # list mutation. _writable_state already does this internally for
        # comparisons; this helper is used for storage and exact-match
        # filtering below.
        def _norm(p: str) -> str:
            try:
                return str(Path(p).resolve())
            except Exception:
                return str(Path(p))

        norm_raw = _norm(raw_path)

        if state == "full":
            # ── REVOKE ── only meaningful when there's an exact-match grant.
            # If access is inherited from an ancestor, tell the user where to
            # go to revoke it (since revoking from here would silently leave
            # a hole if other paths also depend on that ancestor grant).
            if exact_match:
                # Filter using normalized comparison — handles slash-direction
                # mismatch between the read and writable allowlists.
                new_list = [p for p in writable_paths
                            if _norm(p) != norm_raw]
                if self._save_writable_paths(new_list):
                    self.status_var.set(f"Revoked write access: {raw_path}")
                    self.refresh_tracked_dirs()
            else:
                # Find the ancestor grant that's giving us write access
                granting_ancestor = next(
                    (w for w in writable_paths
                     if self._writable_state(raw_path, [w])[0] == "full"),
                    None
                )
                messagebox.showinfo(
                    "Cannot revoke from here",
                    f"This path inherits write access from a parent zone:\n\n"
                    f"   {granting_ancestor}\n\n"
                    f"To revoke, find that parent in the list and "
                    f"double-click it instead. (Or edit "
                    f"{self._writable_dirs_file} by hand.)"
                )
            return

        if state == "partial":
            # ── WIDEN ── show the user which narrower entries will be removed
            # and replaced with a single grant at this row's level.
            entries_block = "\n".join(f"   • {p}" for p in narrower)
            if not messagebox.askyesno(
                    "Widen Mobile Write Zone?",
                    f"This path is partially writable — Claude can already "
                    f"modify files inside the following narrower zone"
                    f"{'s' if len(narrower) > 1 else ''}:\n\n"
                    f"{entries_block}\n\n"
                    f"Widening will REPLACE those entries with a single grant "
                    f"covering this entire path:\n\n"
                    f"   {raw_path}\n\n"
                    f"After widening, every file and subdirectory here "
                    f"becomes writable to Claude from all sessions (including "
                    f"mobile). The hard blocklist (Windows, Program Files, "
                    f".git, .ssh, .aws, the job tracker, and AppData except "
                    f"AI-Prowler's own state) still applies.\n\n"
                    f"Proceed with widening?"):
                return
            # Remove the narrower entries (normalized compare) and add the
            # wider one in normalized form.
            narrower_norm_set = {_norm(p) for p in narrower}
            new_list = [p for p in writable_paths
                        if _norm(p) not in narrower_norm_set]
            new_list.append(norm_raw)
            if self._save_writable_paths(new_list):
                self.status_var.set(
                    f"Widened {len(narrower)} → 1 grant: {raw_path}"
                )
                self.refresh_tracked_dirs()
            return

        # state == "none"  → ── GRANT ── significant action, require confirmation
        if not messagebox.askyesno(
                "Grant write access — Mobile Write Zone?",
                f"Allow Claude to modify files in:\n\n"
                f"   {raw_path}\n\n"
                f"This grants write access from ALL sessions, including "
                f"mobile, with no further prompt. The hard blocklist "
                f"(Windows, Program Files, .git, .ssh, .aws, the job tracker, "
                f"and AppData except AI-Prowler's own state) still applies.\n\n"
                f"Revoke later by double-clicking this row again, or by "
                f"editing ~/.rag_writable_dirs.json.\n\n"
                f"Grant write access to this path?"):
            return

        # Store the normalized form so future revoke / widen comparisons
        # match cleanly regardless of slash direction.
        new_list = writable_paths + [norm_raw]
        if self._save_writable_paths(new_list):
            self.status_var.set(f"Granted write access: {raw_path}")
            self.refresh_tracked_dirs()

    def _remove_tracked_directory(self):
        """Remove selected directory from tracking and delete all its vectors."""
        sel = self.tracked_listbox.curselection()
        if not sel:
            messagebox.showwarning("No Selection",
                                   "Select a directory in the list first.")
            return

        # Look up the raw path from the parallel list (the displayed text now
        # includes a write-permission prefix and isn't a path itself).
        row_idx = sel[0]
        if row_idx >= len(self._tracked_raw_paths):
            return
        directory = self._tracked_raw_paths[row_idx]
        if directory is None:
            # Placeholder / error row — nothing to remove
            return

        if not messagebox.askyesno(
                "Remove from Tracking",
                f"Remove this item from tracking?\n\n"
                f"{directory}\n\n"
                f"This will:\n"
                f"  • Remove it from the tracked list\n"
                f"  • Delete all its indexed chunks and vectors from ChromaDB\n"
                f"  • Remove its file-change history\n\n"
                f"The actual files on disk are NOT touched.\n"
                f"You can re-index this item later if needed."):
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
        """Background thread: untrack directory/file and purge its ChromaDB vectors."""
        old_stdout = sys.stdout
        sys.stdout = TextRedirector(self.output_queue, "update")
        is_file = Path(directory).is_file() or not Path(directory).is_dir()
        kind = "file" if is_file else "directory"
        try:
            print(f"🗑  Removing {kind} from index:")
            print(f"   {directory}\n")

            result = remove_directory_from_index(directory)
            chunks = result.get("chunks_removed", 0)
            errors = result.get("errors", [])

            if chunks > 0:
                print(f"✅ Removed {chunks:,} chunk(s) from ChromaDB")
            else:
                print(f"ℹ️  No chunks found in ChromaDB for this {kind}")
                print(f"   (may have been wiped when you cleared the database)")

            print(f"✅ Removed from tracked list")
            print(f"✅ Removed from file-change history")

            if errors:
                for err in errors:
                    print(f"⚠️  {err}")

            print(f"\n✅ Done — {kind} is no longer tracked.")

            self.output_queue.put(("status", f"{kind.title()} removed from tracking"))
            self.output_queue.put(("done", "remove_tracked"))

        except Exception as e:
            self.output_queue.put(("error", f"Error removing directory: {e}"))
            self.output_queue.put(("done", "remove_tracked"))
        finally:
            sys.stdout = old_stdout

    def update_selected(self):
        if not self._embedding_ready:
            import tkinter.messagebox as _mb
            _mb.showwarning(
                "Embedding Model Not Ready",
                "The embedding model is still loading.\n\n"
                "Please wait for the status bar to show\n"
                "\u2705 Embedding model ready, then try again."
            )
            return
        """Update selected directory or file."""
        selection = self.tracked_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection",
                                   "Please select a directory or file")
            return

        # Look up the raw path from the parallel list (display rows are
        # prefixed with write-permission icons and aren't paths themselves).
        row_idx = selection[0]
        if row_idx >= len(self._tracked_raw_paths):
            return
        directory = self._tracked_raw_paths[row_idx]
        if directory is None:
            return  # placeholder row
        
        self.update_output.delete('1.0', tk.END)
        self.update_progress.start()
        self.status_var.set("Updating index + purging deleted...")
        
        thread = threading.Thread(target=self.update_directory_worker,
                                  args=(directory,))
        thread.daemon = True
        thread.start()
    
    def update_all(self):
        """Update all tracked directories and files."""
        if not self._embedding_ready:
            import tkinter.messagebox as _mb
            _mb.showwarning(
                "Embedding Model Not Ready",
                "The embedding model is still loading.\n\n"
                "Please wait for the status bar to show\n"
                "\u2705 Embedding model ready\n\n"
                "then try Update All again."
            )
            return
        self.update_output.delete('1.0', tk.END)
        self.update_progress.start()
        self.status_var.set("Updating all + purging deleted...")
        
        thread = threading.Thread(target=self.update_all_worker)
        thread.daemon = True
        thread.start()
    
    def _tracked_file_is_unchanged(self, file_path):
        """Compare a tracked file's current mtime/size to the tracking DB record.

        Returns:
            True  — file is present in the tracking DB and mtime+size match
                    the on-disk file (i.e. nothing to re-index).
            False — file differs from the stored record, OR the tracking DB
                    has no record for it, OR anything went wrong reading the
                    DB (in which case we err on the side of re-indexing).
        """
        try:
            if not TRACKING_DB.exists():
                return False
            import json as _json
            tracking = _json.loads(TRACKING_DB.read_text(encoding='utf-8'))

            p          = Path(file_path)
            parent_key = normalise_path(str(p.parent))
            file_key   = normalise_path(str(p))

            # The dir_key in tracking can be stored under various forms
            # (the file's parent dir, or sometimes the file path itself
            # if it was registered as an individual tracked file).
            # Search both shapes.
            candidates = [parent_key, file_key]
            for dir_key, dir_data in tracking.items():
                if normalise_path(dir_key) in candidates:
                    files = dir_data.get('files', {}) or {}
                    rec = files.get(file_key)
                    if not rec:
                        # try a case-insensitive lookup for Windows safety
                        for fk, fv in files.items():
                            if normalise_path(fk).lower() == file_key.lower():
                                rec = fv
                                break
                    if not rec:
                        continue
                    try:
                        stored_mtime = float(rec.get('modified', 0))
                        stored_size  = int(rec.get('size', -1))
                    except (TypeError, ValueError):
                        return False
                    current_mtime = p.stat().st_mtime
                    current_size  = p.stat().st_size
                    # Allow a small float tolerance on mtime (filesystems vary)
                    if (abs(current_mtime - stored_mtime) < 1.0
                            and current_size == stored_size):
                        return True
                    return False
            return False
        except Exception:
            return False

    def update_directory_worker(self, directory):
        """Worker thread: update a single directory or file."""
        old_stdout = sys.stdout
        try:
            sys.stdout = TextRedirector(self.output_queue, 'update')
            is_file = Path(directory).is_file()

            # Build collection_resolver for server mode
            _col_resolver_upd = None
            if self._is_business_server_mode():
                try:
                    from rag_preprocessor import build_collection_resolver
                    _col_resolver_upd = build_collection_resolver()
                except Exception:
                    pass

            if is_file:
                # Individual tracked file — check mtime before re-indexing
                fname = Path(directory).name
                if self._tracked_file_is_unchanged(directory):
                    print(f"⏭  Unchanged, skipping: {fname}")
                else:
                    print(f"📄 Re-indexing file: {fname}")
                    stats = index_file_list(
                        [normalise_path(directory)],
                        label="1/1",
                        root_directory=str(Path(directory).parent),
                        collection_resolver=_col_resolver_upd,
                    )
                    chunks = stats.get('chunks_added', 0) if stats else 0
                    print(f"✅ {fname} — {chunks} chunk(s)")
            else:
                command_update(directory, recursive=True, auto_confirm=True,
                               collection_resolver=_col_resolver_upd)

            self.output_queue.put(('status', 'Update complete — index synced & stale chunks purged'))
            self.output_queue.put(('done', 'update'))
        except Exception as e:
            self.output_queue.put(('error', f"Error: {str(e)}"))
            self.output_queue.put(('done', 'update'))
        finally:
            sys.stdout = old_stdout
    
    def update_all_worker(self):
        """Worker thread: update all tracked directories AND files."""
        old_stdout = sys.stdout
        try:
            sys.stdout = TextRedirector(self.output_queue, 'update')
            dirs = load_auto_update_list()
            if not dirs:
                self.output_queue.put(('update', "No tracked directories or files found.\n"
                                                 "Index a directory or file first to start tracking it.\n"))
            else:
                # Build collection_resolver once for the whole run (server mode only)
                _col_resolver = None
                if self._is_business_server_mode():
                    try:
                        from rag_preprocessor import build_collection_resolver
                        _col_resolver = build_collection_resolver()
                    except Exception as _cre:
                        print(f"   ⚠️  collection_resolver unavailable: {_cre}")

                for i, entry in enumerate(dirs, 1):
                    entry_name = Path(entry).name or entry
                    is_file = Path(entry).is_file()

                    if is_file:
                        # Tracked individual file — check mtime before re-indexing
                        if self._tracked_file_is_unchanged(entry):
                            self.output_queue.put(('update', f"\n[{i}/{len(dirs)}] ⏭  Unchanged, skipping: {entry_name}\n"))
                            continue
                        self.output_queue.put(('update', f"\n[{i}/{len(dirs)}] Re-indexing file: {entry_name}\n"))
                        try:
                            stats = index_file_list(
                                [normalise_path(entry)],
                                label=f"{i}/{len(dirs)}",
                                root_directory=str(Path(entry).parent),
                                collection_resolver=_col_resolver,
                            )
                            chunks = stats.get('chunks_added', 0) if stats else 0
                            self.output_queue.put(('update', f"   ✅ {entry_name} — {chunks} chunk(s)\n"))
                        except Exception as _fe:
                            self.output_queue.put(('update', f"   ⚠️  Error: {_fe}\n"))
                    else:
                        # Tracked directory — use standard directory update
                        self.output_queue.put(('update', f"\n[{i}/{len(dirs)}] Updating: {entry_name}\n"))
                        command_update(entry, recursive=True, auto_confirm=True,
                                       collection_resolver=_col_resolver)

                self.output_queue.put(('update', "\n✅ All tracked items updated.\n"))
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
    
    def clear_database_only_cmd(self):
        """Clear Database only — deletes all ChromaDB collections (documents +
        server-mode scope-* collections) and resets file-tracking timestamps,
        but KEEPS the tracked-directories list so folders don't need re-adding.
        Use this after switching from server → personal mode.
        """
        if messagebox.askyesno(
                "Clear Database only",
                "This will delete ALL indexed data:\n\n"
                "  • All ChromaDB collections\n"
                "    (documents + any server-mode scope-* collections)\n"
                "  • File-tracking timestamps  (so every file re-indexes on next scan)\n"
                "  • Email index\n\n"
                "Your tracked-directories list will be KEPT.\n\n"
                "This cannot be undone.\n\nContinue?"):
            errors = []
            try:
                clear_database_only(confirm=True)
                invalidate_chroma_cache()  # force fresh PersistentClient
            except Exception as e:
                errors.append(f"ChromaDB: {e}")

            # Reset in-GUI tracking timestamps too
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
                    "✅ All ChromaDB collections deleted.\n"
                    "✅ File-tracking timestamps reset.\n"
                    "✅ Tracked-directories list preserved.\n\n"
                    "Click 'Update All' in the Update Index tab to re-index.")
            self.refresh_tracked_dirs()

    def clear_database(self):
        """Clear Database + Database list — full wipe of all ChromaDB collections,
        file-tracking, email index, AND the tracked-directories list.
        """
        if messagebox.askyesno(
                "Clear Database + Database list",
                "This will delete ALL indexed data AND your tracked folders list:\n\n"
                "  • All ChromaDB collections\n"
                "    (documents + any server-mode scope-* collections)\n"
                "  • File-tracking timestamps\n"
                "  • Email index\n"
                "  • Tracked-directories list  ← folders must be re-added manually\n\n"
                "This cannot be undone.\n\nContinue?"):
            errors = []
            # 1. Clear the ChromaDB vector store
            try:
                clear_database(confirm=True)
                # Belt-and-suspenders: force a fresh PersistentClient so the
                # next index operation does not hit the stale Rust segment
                # manager that still references the now-deleted HNSW files.
                # clear_database() already calls invalidate_chroma_cache()
                # internally, but calling it here too is safe (idempotent) and
                # ensures the GUI path is covered even if the backend changes.
                invalidate_chroma_cache()
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
                    
                elif msg_type == 'embedding_ready':
                    # Embedding model downloaded and cached — re-enable update
                    # buttons. Reconcile runs inside the prewarm worker thread.
                    self._embedding_ready = True
                    try:
                        self.update_selected_btn.configure(state='normal')
                        self.update_all_btn.configure(state='normal')
                    except Exception:
                        pass
                    self.status_var.set("\u2705 Embedding model ready")

                elif msg_type == 'embedding_ready_error':
                    # Model download failed — re-enable buttons so user can retry
                    try:
                        self.update_selected_btn.configure(state='normal')
                        self.update_all_btn.configure(state='normal')
                    except Exception:
                        pass
                    self.status_var.set("⚠ Embedding model load failed — check internet connection")

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
                        if self._index_cancelled:
                            # User hit Cancel — discard resume state, go idle
                            self._index_cancelled = False
                            self._stop_index_timer()
                            self._index_set_buttons('idle')
                            self.refresh_tracked_dirs()
                        else:
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
        """Handle window close event - cleanly stop all child processes."""

        def _kill_proc(proc, name="process"):
            """Terminate a subprocess gracefully, then force-kill if needed."""
            if proc is None:
                return
            try:
                if proc.poll() is not None:
                    return          # already dead
                proc.terminate()    # polite SIGTERM / TerminateProcess
                try:
                    proc.wait(timeout=3)
                except Exception:
                    pass
                if proc.poll() is None:
                    # Still alive — force kill the entire process tree so no
                    # grandchild Python workers are left behind.
                    try:
                        if sys.platform == 'win32':
                            subprocess.run(
                                ['taskkill', '/F', '/T', '/PID', str(proc.pid)],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
                        else:
                            import signal as _sig
                            import os as _os2
                            _os2.killpg(_os2.getpgid(proc.pid), _sig.SIGKILL)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
            except Exception as e:
                print(f"Warning: could not stop {name}: {e}")

        # ── Ollama (only if AI-Prowler started it) ───────────────────────────
        if self._ollama_process is not None:
            print("Stopping Ollama server (started by AI Prowler)...")
            _kill_proc(self._ollama_process, "Ollama")
            print("Ollama server stopped")

        # ── HTTP MCP server subprocess (python ai_prowler_mcp.py --http) ────
        _kill_proc(self._http_server_proc, "HTTP MCP server")
        self._set_sleep_prevention(False)   # always restore sleep on exit

        # ── cloudflared tunnel ───────────────────────────────────────────────
        _kill_proc(self._cloudflared_proc, "cloudflared tunnel")

        # ── Close window and exit cleanly ────────────────────────────────────
        # Destroy the Tk root first so all after() callbacks are cancelled.
        try:
            self.root.destroy()
        except Exception:
            pass
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

    # ── Per-monitor DPI awareness (Windows) ──────────────────────────────────
    # Tell Windows that AI-Prowler will render at the native screen DPI rather
    # than letting the OS bitmap-upscale a 96 DPI render. Without this, on a
    # 125% or 150% scaled laptop (very common on Win 11) the entire window
    # gets blown up by the OS, which both blurs text AND makes the window
    # consume more physical screen than the 1200x980 we requested — pushing
    # the status bar (MCP Ready) off the bottom of the screen on smaller
    # laptops.
    #
    # We use a fallback chain because the modern API didn't exist before
    # Windows 10 1703 (April 2017). Order is: best → fallback → fallback.
    # All are wrapped in try/except so non-Windows or older Windows just
    # silently skips this step.
    if sys.platform == 'win32':
        try:
            # Best: per-monitor v2 (Win 10 1703+) — handles multi-monitor
            # setups with different scale factors per display.
            ctypes.windll.user32.SetProcessDpiAwarenessContext(
                ctypes.c_void_p(-4))  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        except Exception:
            try:
                # Fallback: per-monitor v1 (Win 8.1+)
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:
                try:
                    # Last resort: system-wide DPI awareness (Vista+)
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass  # Never crash startup over DPI

    if not RAG_AVAILABLE:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("AI Prowler Engine Not Found",
                           f"Could not import AI Prowler modules.\n\n"
                           f"Error: {_RAG_ERROR}\n\n"
                           f"Script dir: {str(Path(__file__).parent)}")
        return
    
    # ── Windows taskbar / tray icon fix ──────────────────────────────────────
    # Without an explicit AppUserModelID, Windows groups the window under the
    # Python interpreter icon instead of the AI-Prowler icon.  Setting a unique
    # AppUserModelID before the Tk window is created tells the shell to treat
    # this process as its own distinct application.
    if sys.platform == 'win32':
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                u'DV.AIProwler.RAG.1'
            )
        except Exception:
            pass

    root = tk.Tk()

    # Apply the AI-Prowler icon to the window AND the taskbar button
    _icon_path = Path(__file__).parent / 'rag_icon.ico'
    if _icon_path.exists() and sys.platform == 'win32':
        try:
            # iconbitmap covers the title-bar icon
            root.iconbitmap(str(_icon_path))
        except Exception:
            pass
        try:
            # wm_iconbitmap with the default= kwarg sets the taskbar icon too
            root.wm_iconbitmap(default=str(_icon_path))
        except Exception:
            pass

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
