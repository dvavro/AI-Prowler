"""
startup_log.py — AI-Prowler startup diagnostic logger.

Writes a timestamped startup log to ~/.ai-prowler/startup.log on every
launch. Designed to survive the conditions that make normal logging fail:
  - pythonw.exe (stdout=None)
  - Defender quarantine of the log file itself (handled via fallback path)
  - ChromaDB/sentence_transformers import failure (written before imports)
  - GUI crash before Tk mainloop (written synchronously, not via queue)

The log is append-only with a hard cap of 500 lines — older entries are
trimmed so the file never grows unbounded.

Also checks for common Windows Defender exclusion issues at startup and
logs warnings if the key paths are not in the exclusion list.

Usage:
    import startup_log
    startup_log.step("rag_preprocessor imported OK")
    startup_log.warn("ChromaDB path not found")
    startup_log.fail("RAG import failed", exc)
"""

from __future__ import annotations
import os
import sys
import time
import traceback
from pathlib import Path

# ── Log file location ─────────────────────────────────────────────────────────
# Lives in ~/.ai-prowler/logs — the same folder every other piece of
# AI-Prowler's own persistent state already lives in (config.json,
# custom_analysis_tasks.json, scheduler state, etc.), and now also where the
# installer's own install_log.txt/uninstall_log.txt write to (see
# LOG_FOLDER/INSTALL_LOG/UNINSTALL_LOG in AI-Prowler-Setup.iss) — one place
# for all AI-Prowler diagnostic output instead of scattered across
# ~/.ai-prowler and %TEMP%\AI-Prowler.
_LOG_NAME     = "startup.log"
_LOG_KEEP     = 3   # startup.log, startup.log.1, startup.log.2 — last N startups

import tempfile
_log_dir_primary  = Path.home() / '.ai-prowler' / 'logs'
_log_dir_fallback = Path(os.environ.get('TEMP') or tempfile.gettempdir()) / 'AI-Prowler'

_log_path: Path | None = None   # resolved (and rotated) on first write of the session
_session_start = time.time()
_session_ts    = time.strftime('%Y-%m-%d %H:%M:%S')


def _rotate_logs(log_dir: Path, base_name: str = _LOG_NAME, keep: int = _LOG_KEEP) -> None:
    """Shift startup.log -> .1 -> .2 (dropping anything older than `keep`)
    once per process, immediately before the first write of a session — so
    each of the `keep` files is one complete, uninterrupted startup log
    rather than a line-trimmed mash of several sessions."""
    for i in range(keep - 1, 0, -1):
        src = log_dir / (base_name if i == 1 else f'{base_name}.{i - 1}')
        dst = log_dir / f'{base_name}.{i}'
        if src.exists():
            try:
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
            except Exception:
                pass  # Never let rotation itself block startup logging


def _resolve_log_path() -> Path | None:
    """Find a writable log directory — primary, then fallback — rotate its
    logs exactly once for this process, and return the fresh startup.log
    path. Safe to call repeatedly: rotation only happens the first time
    (note begin() is deliberately called twice per session — once at
    module import with version='?', again in main() once APP_VERSION is
    known — so rotation must not re-trigger on that second call)."""
    global _log_path
    if _log_path is not None:
        return _log_path
    for candidate_dir in (_log_dir_primary, _log_dir_fallback):
        try:
            candidate_dir.mkdir(parents=True, exist_ok=True)
            _rotate_logs(candidate_dir)
            candidate = candidate_dir / _LOG_NAME
            # Test write
            with open(candidate, 'a', encoding='utf-8') as _f:
                pass
            _log_path = candidate
            return _log_path
        except Exception:
            continue
    return None


def _write(level: str, msg: str, exc: BaseException | None = None) -> None:
    """Write one line to the startup log. Never raises."""
    try:
        path = _resolve_log_path()
        if path is None:
            return
        elapsed = time.time() - _session_start
        line = f"[{time.strftime('%H:%M:%S')} +{elapsed:5.1f}s] {level:5s} {msg}"
        if exc is not None:
            tb = traceback.format_exc()
            line += f"\n        Exception: {type(exc).__name__}: {exc}"
            line += f"\n        Traceback:\n"
            for tbline in tb.splitlines():
                line += f"          {tbline}\n"

        # Append — no per-line trim needed anymore; _rotate_logs() caps growth
        # at the session level (3 complete startup logs) instead of trimming
        # lines out of a single ever-growing file.
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass  # Never crash startup over logging


def _separator() -> None:
    _write('-----', '-' * 60)


# ── Public API ────────────────────────────────────────────────────────────────

_excepthook_installed = False


def _install_excepthook() -> None:
    """Log ANY uncaught exception anywhere in the process before it exits —
    a global safety net for crashes that happen somewhere other than the
    handful of call sites that manually call fail(). This is exactly what
    caught the v9.0.0 missing-VERSION-file crash: rag_gui.py's own
    APP_VERSION line had no try/except of its own, so without this hook the
    process would have died with zero trace under pythonw.exe."""
    global _excepthook_installed
    if _excepthook_installed:
        return
    _previous_hook = sys.excepthook

    def _hook(exc_type, exc_value, exc_tb):
        fail("UNCAUGHT EXCEPTION — process is about to exit", exc_value)
        _previous_hook(exc_type, exc_value, exc_tb)

    sys.excepthook = _hook
    _excepthook_installed = True


def begin(version: str = '?') -> None:
    """Call once at the very top of rag_gui.py main() — before anything else."""
    _install_excepthook()
    _separator()
    _write('START', f'AI-Prowler v{version} startup — {_session_ts}')
    _write('INFO ', f'Python {sys.version.split()[0]} at {sys.executable}')
    _write('INFO ', f'Platform: {sys.platform}')
    _write('INFO ', f'Working dir: {os.getcwd()}')
    _write('INFO ', f'Script dir: {Path(__file__).parent}')
    _write('INFO ', f'Log file: {_resolve_log_path()}')


def step(msg: str) -> None:
    """Log a successful checkpoint."""
    _write('OK   ', msg)


def warn(msg: str) -> None:
    """Log a warning (non-fatal)."""
    _write('WARN ', msg)


def fail(msg: str, exc: BaseException | None = None) -> None:
    """Log a fatal failure."""
    _write('FAIL ', msg, exc)


def info(msg: str) -> None:
    """Log an informational message."""
    _write('INFO ', msg)


# ── Windows Defender exclusion check ─────────────────────────────────────────

def check_defender_exclusions(install_dir: Path) -> None:
    """
    Check whether key AI-Prowler paths are in the Windows Defender
    exclusion list. Logs warnings for any missing exclusions.

    This runs at startup so a Defender issue is immediately visible in
    startup.log rather than requiring the user to diagnose a silent crash.
    """
    if sys.platform != 'win32':
        return

    paths_to_check = [
        install_dir,
        Path.home() / '.ai-prowler',
        Path.home() / '.cache' / 'huggingface',
        Path.home() / 'AI-Prowler',           # common DB location
        Path(os.environ.get('LOCALAPPDATA', '')) / 'Programs' / 'Python',
    ]

    try:
        import subprocess
        result = subprocess.run(
            ['powershell', '-NonInteractive', '-Command',
             '(Get-MpPreference).ExclusionPath -join "|||"'],
            capture_output=True, text=True, timeout=10
        )
        exclusions_raw = result.stdout.strip().lower()
        exclusions = [e.strip() for e in exclusions_raw.split('|||') if e.strip()]

        _write('INFO ', f'Defender exclusions found: {len(exclusions)}')

        missing = []
        for p in paths_to_check:
            p_str = str(p).lower().rstrip('\\/')
            covered = any(
                p_str.startswith(ex.rstrip('\\/')) or ex.rstrip('\\/').startswith(p_str)
                for ex in exclusions
            )
            if not covered and p.exists():
                missing.append(str(p))
                warn(f'Defender: NOT excluded — {p}')
            elif p.exists():
                step(f'Defender: excluded OK — {p}')
            else:
                info(f'Defender: path does not exist (skip) — {p}')

        if missing:
            warn(f'Defender: {len(missing)} path(s) missing exclusions — '
                 f'this may cause startup crashes or slow indexing. '
                 f'Add exclusions in Windows Security > Virus & threat protection > '
                 f'Manage settings > Exclusions.')
        else:
            step('Defender: all key paths are excluded')

    except Exception as e:
        warn(f'Defender exclusion check failed (non-fatal): {e}')


# ── ChromaDB path check ───────────────────────────────────────────────────────

def check_chroma_path(db_path: str | Path) -> None:
    """Check the ChromaDB path is accessible and not quarantined."""
    p = Path(db_path)
    if not p.exists():
        warn(f'ChromaDB path does not exist yet (will be created): {p}')
        return
    try:
        test_file = p / '.startup_check'
        test_file.write_text('ok', encoding='utf-8')
        test_file.unlink()
        step(f'ChromaDB path writable: {p}')
    except PermissionError as e:
        fail(f'ChromaDB path NOT writable — likely Defender quarantine: {p}', e)
    except Exception as e:
        warn(f'ChromaDB path check failed: {p} — {e}')


# ── HuggingFace cache check ───────────────────────────────────────────────────

def check_hf_cache() -> None:
    """Check the HuggingFace model cache is accessible."""
    hf_cache = Path(
        os.environ.get('HF_HUB_CACHE',
                       str(Path.home() / '.cache' / 'huggingface' / 'hub'))
    )
    if not hf_cache.exists():
        info(f'HuggingFace cache not yet created: {hf_cache}')
        return
    try:
        test_file = hf_cache / '.startup_check'
        test_file.write_text('ok', encoding='utf-8')
        test_file.unlink()
        step(f'HuggingFace cache writable: {hf_cache}')
    except PermissionError as e:
        fail(f'HuggingFace cache NOT writable — likely Defender quarantine: {hf_cache}', e)
    except Exception as e:
        warn(f'HuggingFace cache check failed: {e}')
