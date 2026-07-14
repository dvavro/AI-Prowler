"""
AI-Prowler File Watchdog Daemon
================================
Monitors all tracked directories (from ~/.rag_auto_update_dirs.json) and
automatically re-indexes files the moment they are created, modified, or
moved into a watched folder.

Design decisions:
  - Direct Python import of rag_preprocessor internals (no REST API dependency).
  - Smart Scan parity: always behaves as if Smart Scan is ON. Uses the live
    SKIP_EXTENSIONS, SUPPORTED_EXTENSIONS, and SKIP_DIRECTORIES from
    rag_preprocessor — which already applies the user's Smart Scan Config
    customisations from ~/.rag_config.json at import time. This means the
    watchdog respects the exact same file-type rules as the Index Docs tab.
  - scan_mode_var (the GUI checkbox) is not consulted — the watchdog is a
    background daemon and cannot read Tkinter state. Smart Scan OFF is a
    manual one-time override for special cases; it is not appropriate as a
    persistent daemon behaviour. Users who need to force-index an unusual
    file type do so manually from the Index Docs tab.
  - SKIP_DIRECTORIES: the watchdog respects the rag_preprocessor
    SKIP_DIRECTORIES set so system folders (.git, __pycache__, node_modules,
    etc.) are never watched or indexed.
  - Debounce: waits DEBOUNCE_SECONDS after the last event on a file before
    indexing, so partially-written or OneDrive-syncing files are never indexed
    mid-write.
  - Directories dropped in: triggers index_file_list on all files inside
    recursively using the same Smart Scan filter.
  - Tracked list is re-read every RELOAD_INTERVAL_S so newly added
    directories are picked up without a restart.

Invocation:
  python file_watchdog.py           # foreground, logs to stdout + log file
  python file_watchdog.py --stop    # signal a running daemon to stop

Log file: ~/AI-Prowler/logs/file_watchdog.log
PID file: ~/AI-Prowler/file_watchdog.pid
"""

import sys
import os
import time
import json
import logging
import threading
import argparse
from pathlib import Path


# ── Configuration ─────────────────────────────────────────────────────────────
DEBOUNCE_SECONDS  = 3       # wait after last event before indexing a file
RELOAD_INTERVAL_S = 30      # re-read tracked dirs list every N seconds

# Watchdog-level skip list — covers OS/editor lock files that are never
# meaningful to index and that may cause errors if read mid-write.
# NOTE: extension-based filtering (SKIP_EXTENSIONS / SUPPORTED_EXTENSIONS)
# is delegated to rag_preprocessor at index time, not duplicated here.
_ALWAYS_SKIP_NAMES = {
    "desktop.ini", "thumbs.db", ".ds_store",
}
_ALWAYS_SKIP_PREFIXES = ("~$", ".~lock.")   # Office + LibreOffice lock files
_ALWAYS_SKIP_EXTENSIONS = {
    ".tmp", ".part", ".crdownload", ".~lock", ".swp", ".swo",
}

LOG_DIR  = Path.home() / "AI-Prowler" / "logs"
PID_FILE = Path.home() / "AI-Prowler" / "file_watchdog.pid"
LOG_FILE = LOG_DIR / "file_watchdog.log"

# Module-level reference to rag_preprocessor — set on first use by
# _get_rag_preprocessor(). Exposed at module level so tests can monkeypatch it
# directly: monkeypatch.setattr(wd, "_rag_preprocessor", mock_rp)
_rag_preprocessor = None
# ──────────────────────────────────────────────────────────────────────────────

LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("file_watchdog")

# ── Shared state ──────────────────────────────────────────────────────────────
_pending: dict      = {}   # path -> earliest-time-to-index
_pending_lock       = threading.Lock()
_stop_event         = threading.Event()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ensure_on_path():
    """Add the AI-Prowler install dir to sys.path so rag_preprocessor is importable."""
    d = str(Path(__file__).parent)
    if d not in sys.path:
        sys.path.insert(0, d)


def _get_rag_sets():
    """
    Return (SKIP_EXTENSIONS, SUPPORTED_EXTENSIONS, SKIP_DIRECTORIES) from
    rag_preprocessor.  These already incorporate the user's Smart Scan Config
    customisations saved in ~/.rag_config.json because rag_preprocessor calls
    _apply_saved_extension_config() at import time.

    Returns (None, None, None) on import failure — caller should fall back to
    allowing the file through so it gets logged by _do_reindex_file later.
    """
    try:
        _ensure_on_path()
        import rag_preprocessor as _rp
        return _rp.SKIP_EXTENSIONS, _rp.SUPPORTED_EXTENSIONS, _rp.SKIP_DIRECTORIES
    except Exception as exc:
        log.warning("Could not import rag_preprocessor for filter sets: %s", exc)
        return None, None, None


def _should_skip_always(path: str) -> bool:
    """
    Return True for OS/editor lock files that must NEVER be queued, regardless
    of Smart Scan settings.  These are files that are meaningless to index and
    may be unreadable mid-write.
    """
    name = Path(path).name.lower()
    ext  = Path(path).suffix.lower()
    return (
        name in _ALWAYS_SKIP_NAMES
        or ext in _ALWAYS_SKIP_EXTENSIONS
        or any(name.startswith(p) for p in _ALWAYS_SKIP_PREFIXES)
        or "\\$recycle.bin\\" in path.lower()
    )


def _is_skip_dir(dirpath: str) -> bool:
    """
    Return True if ANY component of the path is in SKIP_DIRECTORIES,
    so we never watch or index inside .git, __pycache__, node_modules, etc.
    """
    _, __, skip_dirs = _get_rag_sets()
    if not skip_dirs:
        return False
    parts = set(Path(dirpath).parts)
    return bool(parts & skip_dirs)


def _smart_scan_allows(filepath: str) -> bool:
    """
    Mirror the Smart Scan ON filter from index_worker / scan_directory:
      - Extension must be in SUPPORTED_EXTENSIONS
      - Extension must NOT be in SKIP_EXTENSIONS
      - is_backup_filename check
    Returns True if the file should be indexed.
    """
    skip_ext, supported_ext, _ = _get_rag_sets()

    # If rag_preprocessor unavailable, allow through (will fail gracefully later)
    if skip_ext is None:
        return True

    try:
        _ensure_on_path()
        global _rag_preprocessor
        if _rag_preprocessor is None:
            import rag_preprocessor as _rp
            _rag_preprocessor = _rp
        is_backup_filename = _rag_preprocessor.is_backup_filename
    except Exception:
        is_backup_filename = lambda f: False  # noqa: E731

    name = Path(filepath).name
    ext  = Path(filepath).suffix.lower()

    if is_backup_filename(name):
        return False
    if ext in skip_ext:
        return False
    if ext not in supported_ext:
        return False
    return True


# ── Indexing functions ────────────────────────────────────────────────────────

# Sentinel returned by _resolve_unattended_collection when this install is in
# PERSONAL mode (no ~/.ai-prowler/users.json / no collection_map at all) —
# meaning server-mode scoping doesn't apply and the watchdog should behave
# exactly as it always has: single "documents" collection, unconditionally.
_PERSONAL_MODE = object()


def _load_users_data():
    """Load ~/.ai-prowler/users.json, or None if it doesn't exist / can't be
    parsed. A missing file is the normal, expected case for a personal-mode
    install — not an error."""
    try:
        p = Path.home() / ".ai-prowler" / "users.json"
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Could not load users.json: %s — treating as personal mode", exc)
        return None


def _log_scope_skip(path: str, reason: str) -> None:
    """Append one line to the SHARED scope-skip log
    (~/AI-Prowler/logs/index_scope_skips.log) — the same file
    rag_preprocessor.py's command_update()/build_collection_resolver()
    write to, so a skip is reviewable in one place regardless of whether
    the watchdog, the Scheduled Task, or a GUI Update button caught it.
    Duplicated rather than imported (matches this file's existing pattern
    for _load_users_data et al.) — this file already has its own separate,
    more detailed log via the `log` object above; this is in ADDITION to
    that, not a replacement. Never raises."""
    try:
        log_dir = Path.home() / "AI-Prowler" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        shared_log = log_dir / "index_scope_skips.log"
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(shared_log, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [watchdog] {path} — {reason}\n")
    except Exception:
        pass


def _resolve_unattended_collection(filepath: str):
    """Determine which ChromaDB collection `filepath` belongs to, with NO
    acting user/session available (the watchdog is a background daemon).

    Returns:
      _PERSONAL_MODE  — this install has no users.json / collection_map at
                         all; caller should use the unscoped single-
                         collection behavior, unchanged from before this fix.
      a collection name (str) — server mode, and a rule safely matched.
      None                    — server mode, but NO rule safely matched
                         (unmatched path, or a rule pointing at a user who
                         no longer exists). Caller MUST skip this file and
                         log a warning — never guess a destination. Per
                         David's explicit design decision (2026-07-13):
                         no default_collection fallback either — skip +
                         log is the ONLY behavior for an unmatched path,
                         deliberately not defaulting to "shared" (that
                         would risk silently exposing content that was
                         never meant to be company-wide). See
                         scope_resolver.resolve_collection_for_unattended_
                         path's docstring for the full rationale.
    """
    users_data = _load_users_data()
    if not users_data:
        return _PERSONAL_MODE

    collection_map = users_data.get("collection_map")
    if not isinstance(collection_map, dict) or not collection_map.get("rules"):
        return _PERSONAL_MODE

    try:
        _ensure_on_path()
        import scope_resolver as _sr
    except Exception as exc:
        log.error("Could not import scope_resolver — skipping %s: %s", filepath, exc)
        return None

    known_ids = _sr.known_user_ids(users_data)
    return _sr.resolve_collection_for_unattended_path(
        filepath, collection_map, known_ids=known_ids)


def _do_reindex_file(filepath: str):
    """
    Index a single file using rag_preprocessor directly, respecting Smart Scan
    rules. Mirrors the Smart Scan ON path in index_worker.

    Server-mode collection awareness (added after the 2026-07 Christina
    incident — a file in an employee's personal directory was silently
    landing in the single default "documents" collection, invisible to
    everyone including its rightful owner): before indexing, resolve which
    scoped collection this path actually belongs to. On a personal-mode
    install this is a no-op (unchanged behavior). In server mode, if no
    rule safely matches, the file is SKIPPED with a warning rather than
    guessed into any collection — see _resolve_unattended_collection.
    """
    # Apply Smart Scan filter before doing any work
    if not _smart_scan_allows(filepath):
        log.debug("Smart Scan skip: %s", filepath)
        return

    target_collection = _resolve_unattended_collection(filepath)
    if target_collection is None:
        _reason = ("no collection_map rule safely matches this path "
                  "(or its rule points at a user who no longer exists)")
        log.warning(
            "Skipping %s — %s. Add a scope rule for this directory in the "
            "Admin tab, or index it manually via index_path() to route it "
            "correctly.", filepath, _reason)
        _log_scope_skip(filepath, _reason)
        return
    scoped = target_collection is not _PERSONAL_MODE
    coll_name = target_collection if scoped else None

    try:
        _ensure_on_path()
        global _rag_preprocessor
        if _rag_preprocessor is None:
            import rag_preprocessor as _rp
            _rag_preprocessor = _rp
        rp = _rag_preprocessor

        fp = rp.normalise_path(filepath)
        if not Path(fp).is_file():
            log.warning("Skipping — file no longer exists: %s", fp)
            return

        # Purge stale chunks then re-index (mirrors reindex_file MCP tool)
        purge_name = coll_name if scoped else rp.COLLECTION_NAME
        try:
            client, embedding_func = rp.get_chroma_client()
            coll = client.get_or_create_collection(
                name=purge_name,
                embedding_function=embedding_func,
            )
            coll.delete(where={"filepath": fp})
        except Exception as exc:
            log.warning("Purge failed for %s in %s: %s — continuing", fp, purge_name, exc)

        index_kwargs = {}
        if scoped:
            index_kwargs["collection_resolver"] = lambda _fp, _c=coll_name: _c

        stats  = rp.index_file_list(
            [fp], label="watchdog",
            root_directory=str(Path(fp).parent),
            **index_kwargs,
        )
        chunks = stats.get("chunks", 0) if stats else 0
        if scoped:
            log.info("Indexed: %s -> %s  (%d chunk(s))", Path(fp).name, coll_name, chunks)
        else:
            log.info("Indexed: %s  (%d chunk(s))", Path(fp).name, chunks)

    except Exception as exc:
        log.error("Failed to index %s: %s", filepath, exc)


def _do_index_directory(dirpath: str):
    """
    Index all Smart-Scan-allowed files in a newly-dropped directory.
    Mirrors the Smart Scan ON path in index_worker using scan_directory.

    Server-mode collection awareness: resolves the collection ONCE for the
    directory itself (not per-file) — every tracked directory has exactly
    one registered scope by design, so every file found inside gets routed
    to that same collection uniformly. See _do_reindex_file's docstring
    for the full incident/rationale writeup; this mirrors the same fix.
    """
    target_collection = _resolve_unattended_collection(dirpath)
    if target_collection is None:
        _reason = ("no collection_map rule safely matches this path "
                  "(or its rule points at a user who no longer exists)")
        log.warning(
            "Skipping directory %s — %s. Add a scope rule for this "
            "directory in the Admin tab, or index it manually via "
            "index_path() to route it correctly.", dirpath, _reason)
        _log_scope_skip(dirpath, _reason)
        return
    scoped = target_collection is not _PERSONAL_MODE
    coll_name = target_collection if scoped else None

    try:
        _ensure_on_path()
        global _rag_preprocessor
        if _rag_preprocessor is None:
            import rag_preprocessor as _rp
            _rag_preprocessor = _rp
        rp = _rag_preprocessor

        dp = rp.normalise_path(dirpath)
        if not Path(dp).is_dir():
            return

        # Use scan_directory — the exact same function index_worker uses
        # when Smart Scan is ON. It applies SKIP_EXTENSIONS, SUPPORTED_EXTENSIONS,
        # and SKIP_DIRECTORIES automatically.
        scan  = rp.scan_directory(dp, recursive=True)
        files = [fp for fp, _ in scan.get("to_index", [])]

        if not files:
            log.info("No Smart-Scan-allowed files in dir: %s", Path(dp).name)
            return

        index_kwargs = {}
        if scoped:
            index_kwargs["collection_resolver"] = lambda _fp, _c=coll_name: _c

        stats  = rp.index_file_list(files, label="watchdog-dir",
                                 root_directory=dp, **index_kwargs)
        chunks = stats.get("chunks", 0) if stats else 0
        if scoped:
            log.info("Indexed dir: %s -> %s  (%d file(s), %d chunk(s))",
                     Path(dp).name, coll_name, len(files), chunks)
        else:
            log.info("Indexed dir: %s  (%d file(s), %d chunk(s))",
                     Path(dp).name, len(files), chunks)

    except Exception as exc:
        log.error("Failed to index directory %s: %s", dirpath, exc)


# ── Watchdog event handler ────────────────────────────────────────────────────

def _make_handler():
    try:
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        log.error("watchdog package not installed.  Run:  pip install watchdog")
        sys.exit(1)

    class _Handler(FileSystemEventHandler):
        def _schedule_file(self, path: str):
            if _should_skip_always(path):
                return
            # Smart Scan pre-filter: skip-listed extensions are dropped
            # immediately at event time so they never sit in the queue.
            # (SUPPORTED_EXTENSIONS check happens in _do_reindex_file too,
            # but filtering early avoids queue bloat on media-heavy dirs.)
            skip_ext, supported_ext, _ = _get_rag_sets()
            if skip_ext is not None:
                ext = Path(path).suffix.lower()
                if ext in skip_ext or ext not in supported_ext:
                    log.debug("Smart Scan pre-filter drop: %s", path)
                    return

            with _pending_lock:
                _pending[path] = time.time() + DEBOUNCE_SECONDS
            log.debug("Queued: %s", path)

        def on_created(self, event):
            if event.is_directory:
                if not _is_skip_dir(event.src_path):
                    with _pending_lock:
                        _pending["__DIR__" + event.src_path] = (
                            time.time() + DEBOUNCE_SECONDS
                        )
            else:
                self._schedule_file(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self._schedule_file(event.src_path)

        def on_moved(self, event):
            if event.is_directory:
                if not _is_skip_dir(event.dest_path):
                    with _pending_lock:
                        _pending["__DIR__" + event.dest_path] = (
                            time.time() + DEBOUNCE_SECONDS
                        )
            else:
                self._schedule_file(event.dest_path)

    return _Handler()


# ── Observer management ───────────────────────────────────────────────────────

def _load_tracked_dirs() -> list:
    """Read ~/.rag_auto_update_dirs.json and return list of tracked paths."""
    json_path = Path.home() / ".rag_auto_update_dirs.json"
    if not json_path.exists():
        return []
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [str(Path(d)) for d in data.get("directories", [])]
    except Exception as exc:
        log.warning("Could not read tracked dirs: %s", exc)
        return []


def _start_observers(dirs: list, handler) -> dict:
    """Start one Observer per tracked directory. Returns {path: observer}.

    If a tracked path is a FILE (e.g. COMPLETE_USER_GUIDE.md tracked
    individually), watch its parent directory instead — watchdog's Observer
    requires a directory path. The handler already filters events by filename
    so only relevant changes trigger a reindex.
    """
    try:
        from watchdog.observers import Observer
    except ImportError:
        log.error("watchdog package not installed.  Run:  pip install watchdog")
        sys.exit(1)

    _, _, skip_dirs = _get_rag_sets()
    observers = {}
    for d in dirs:
        p = Path(d)
        if not p.exists():
            log.warning("Tracked path missing, skipping: %s", d)
            continue

        # If it's a file, watch the parent directory instead
        if p.is_file():
            watch_path = p.parent
            log.info("Watching (parent dir for file): %s", watch_path)
        else:
            watch_path = p
            # Don't watch directories that are in SKIP_DIRECTORIES
            if skip_dirs and watch_path.name in skip_dirs:
                log.warning("Tracked dir is in SKIP_DIRECTORIES, skipping: %s", d)
                continue

        watch_key = str(watch_path)
        if watch_key in observers:
            # Already watching this directory (another tracked file in same dir)
            log.info("Already watching parent dir, skipping duplicate: %s", watch_path)
            continue

        try:
            obs = Observer()
            obs.schedule(handler, str(watch_path), recursive=True)
            obs.start()
            observers[watch_key] = obs
            if p.is_dir():
                log.info("Watching: %s", d)
        except Exception as exc:
            log.error("Failed to start observer for %s: %s", watch_path, exc)

    return observers


def _stop_observers(observers: dict):
    for path, obs in observers.items():
        try:
            obs.stop()
            obs.join(timeout=5)
        except Exception:
            pass


# ── Main loop ─────────────────────────────────────────────────────────────────

def run():
    log.info("=" * 60)
    log.info("AI-Prowler File Watchdog starting")
    log.info("Smart Scan: ON (always) — respects ~/.rag_config.json settings")
    log.info("Debounce: %ds  |  Reload interval: %ds",
             DEBOUNCE_SECONDS, RELOAD_INTERVAL_S)

    # Log which extension sets are active
    skip_ext, supported_ext, skip_dirs = _get_rag_sets()
    if supported_ext:
        log.info("Supported extensions: %d types  |  Skipped: %d types  |  "
                 "Skipped dirs: %d patterns",
                 len(supported_ext), len(skip_ext or []), len(skip_dirs or []))

    # ── Single-instance guard ─────────────────────────────────────────────────
    # If a watchdog is already running, log and exit cleanly rather than
    # starting a second instance that would overwrite the PID file and cause
    # both instances to fight over it — leading to the PID file being deleted
    # on the first instance's exit and the GUI reporting "Stopped" even though
    # a live watchdog is running.
    if is_running():
        log.info("Watchdog already running (PID %s) — exiting duplicate.",
                 PID_FILE.read_text().strip())
        return

    # Write PID file so the GUI can check if we're running
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    handler      = _make_handler()
    current_dirs = _load_tracked_dirs()
    observers    = _start_observers(current_dirs, handler)
    last_reload  = time.time()

    try:
        while not _stop_event.is_set():
            now = time.time()

            # ── Flush debounce queue ──────────────────────────────────────────
            with _pending_lock:
                ready = [(p, t) for p, t in list(_pending.items()) if now >= t]
                for path, _ in ready:
                    del _pending[path]

            for path, _ in ready:
                if path.startswith("__DIR__"):
                    _do_index_directory(path[len("__DIR__"):])
                else:
                    _do_reindex_file(path)

            # ── Reload tracked dirs periodically ─────────────────────────────
            if now - last_reload >= RELOAD_INTERVAL_S:
                new_dirs = _load_tracked_dirs()

                # Normalize: file paths -> parent dir (same as _start_observers)
                # so comparison against observer keys is apples-to-apples.
                # Without this, file-tracked paths thrash stop/start every 30s.
                def _normalise(paths):
                    seen, result = set(), []
                    for d in paths:
                        p = Path(d)
                        watch = str(p.parent) if p.is_file() else str(p)
                        if watch not in seen:
                            seen.add(watch)
                            result.append(watch)
                    return result

                new_watch_dirs = _normalise(new_dirs)
                added    = set(new_watch_dirs) - set(observers)
                removed  = set(observers) - set(new_watch_dirs)

                for d in removed:
                    try:
                        observers[d].stop()
                        observers[d].join(timeout=3)
                    except Exception:
                        pass
                    del observers[d]
                    log.info("Stopped watching (removed): %s", d)

                if added:
                    new_obs = _start_observers(list(added), handler)
                    observers.update(new_obs)

                last_reload = now

            time.sleep(1)

    except KeyboardInterrupt:
        log.info("Watchdog interrupted — shutting down")
    finally:
        _stop_observers(observers)
        try:
            PID_FILE.unlink()
        except Exception:
            pass
        log.info("AI-Prowler File Watchdog stopped")


# ── PID helpers (used by rag_gui.py) ─────────────────────────────────────────

def is_running() -> bool:
    """Return True if a watchdog process is currently running.

    Uses the PID file for a fast first check, then verifies the process
    is actually alive. On Windows, os.kill(pid, 0) raises PermissionError
    when the GUI and watchdog are in different sessions (e.g. GUI launched
    via pythonw in session 0, watchdog in session 1) — so we fall back to
    tasklist for cross-session detection.
    """
    if not PID_FILE.exists():
        return False
    try:
        pid = int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        return False

    # On Windows, os.kill(pid, 0) is unreliable across sessions — it raises
    # OSError or SystemError with WinError 87. Skip it entirely on Windows
    # and go straight to tasklist which works correctly in all sessions.
    if sys.platform != 'win32':
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            pass  # process exists, different user — treat as running
        except OSError:
            try:
                PID_FILE.unlink()
            except Exception:
                pass
            return False

    # Windows: use tasklist — works across all sessions reliably
    try:
        import subprocess as _sp
        # CREATE_NO_WINDOW prevents a console flash when called from
        # a pythonw.exe (windowless) process like the AI-Prowler GUI
        _NO_WINDOW = 0x08000000 if sys.platform == 'win32' else 0
        result = _sp.run(
            ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=5,
            creationflags=_NO_WINDOW
        )
        alive = str(pid) in result.stdout
        if not alive:
            try:
                PID_FILE.unlink()
            except Exception:
                pass
        return alive
    except Exception:
        return True  # assume running if tasklist itself fails


def stop_daemon():
    """Signal a running daemon to stop.

    On Windows, os.kill with SIGTERM fails cross-session (GUI in session 0,
    watchdog in session 1). Falls back to taskkill /F which works across
    all sessions regardless of who launched the process.
    """
    if not PID_FILE.exists():
        return False, "No running watchdog found (PID file missing)."
    try:
        pid = int(PID_FILE.read_text().strip())
    except (ValueError, OSError):
        return False, "Could not read PID file."

    # Try os.kill (SIGTERM) first — works in same session
    try:
        import signal as _signal
        os.kill(pid, _signal.SIGTERM)
        try:
            PID_FILE.unlink()
        except Exception:
            pass
        return True, f"Sent stop signal to watchdog (PID {pid})"
    except (PermissionError, OSError):
        pass

    # Cross-session fallback: taskkill /F works from any session on Windows
    try:
        import subprocess as _sp
        _NO_WINDOW = 0x08000000 if sys.platform == 'win32' else 0
        result = _sp.run(
            ["taskkill", "/PID", str(pid), "/F"],
            capture_output=True, text=True, timeout=10,
            creationflags=_NO_WINDOW
        )
        if result.returncode == 0:
            try:
                PID_FILE.unlink()
            except Exception:
                pass
            return True, f"Watchdog stopped (PID {pid})"
        else:
            return False, f"taskkill failed: {result.stderr.strip()}"
    except Exception as exc:
        return False, f"Could not stop watchdog: {exc}"


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-Prowler File Watchdog")
    parser.add_argument("--stop", action="store_true",
                        help="Stop a running watchdog daemon")
    args = parser.parse_args()

    if args.stop:
        ok, msg = stop_daemon()
        print(msg)
    else:
        run()
