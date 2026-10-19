"""
safe_save.py - crash-safe, reader-safe file saves for AI-Prowler (2026-10-19).

WHY
---
The usual `open(path, 'w')` + write truncates the file to EMPTY first and then
fills it in. Anything that reads the file in that moment (the GUI, the MCP
server, the scheduler, the file watcher - they all share these files) sees an
empty or half-written file, and a crash or power cut mid-save leaves it that
way for good. Most AI-Prowler loaders treat an unreadable file as "empty", so
the next load -> change -> save could write back a nearly empty file: the
tracked-folders list, the write allowlist, settings and API keys, the task
queue, OAuth tokens...

HOW
---
Write the new content to a temp file in the SAME folder, flush + fsync it,
then os.replace() it over the real file. os.replace() is atomic: a reader sees
the old file or the new file, never a partial one. On Windows os.replace() is
refused (PermissionError) while another process has the target open, so it
retries briefly. The temp file is always cleaned up.

read_json_retry() is the matching read side: a few quick retries before
treating a file as unreadable, so a passing glitch (an older AI-Prowler still
writing in place, a swap at the exact moment of the read) never reads as
"empty".

This module has no AI-Prowler imports - every program file can use it.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

__all__ = ["atomic_write_bytes", "atomic_write_text", "atomic_write_json", "read_json_retry"]

_MISSING = object()


def atomic_write_bytes(path, data: bytes, *, retries: int = 40, delay: float = 0.05) -> None:
    """Atomically replace `path` with `data`. Raises OSError on failure (the
    original file is then left exactly as it was)."""
    path = Path(path)
    tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass                      # some network / virtual drives can't fsync - still atomic
        for attempt in range(retries):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == retries - 1:
                    raise
                time.sleep(delay)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def atomic_write_text(path, text: str, encoding: str = "utf-8", errors: str = "strict",
                      newline: str | None = None, **kw) -> None:
    """Text version of atomic_write_bytes. `newline` behaves like open()'s:
    None -> '\\n' is written as os.linesep (Windows: CRLF), same as open(path, 'w');
    '' or '\\n' -> written as-is."""
    if newline is None:
        text = text.replace("\n", os.linesep) if os.linesep != "\n" else text
    elif newline not in ("", "\n"):
        text = text.replace("\n", newline)
    atomic_write_bytes(path, text.encode(encoding, errors), **kw)


def atomic_write_json(path, obj, *, indent=2, encoding: str = "utf-8", newline: str | None = None,
                      ensure_ascii: bool = True, **json_kw) -> None:
    """json.dump(obj) to `path`, atomically. Same defaults as json.dump(f, indent=2)
    on a file opened with open(path, 'w', encoding='utf-8')."""
    retry_kw = {k: json_kw.pop(k) for k in ("retries", "delay") if k in json_kw}
    text = json.dumps(obj, indent=indent, ensure_ascii=ensure_ascii, **json_kw)
    atomic_write_text(path, text, encoding=encoding, newline=newline, **retry_kw)


def read_json_retry(path, default=_MISSING, *, attempts: int = 5, delay: float = 0.05, encoding: str = "utf-8"):
    """json.load the file, retrying briefly on an empty/partial/locked read.

    Returns `default` if the file doesn't exist. If it still can't be read after
    the retries: returns `default` when one was given, otherwise re-raises the
    last error (so callers that already handle errors keep doing so)."""
    path = Path(path)
    last = None
    for i in range(attempts):
        try:
            raw = path.read_bytes()
            try:
                text = raw.decode("utf-8-sig" if encoding.lower().replace("_", "-") in ("utf-8", "utf8") else encoding)
            except UnicodeDecodeError:
                # Older AI-Prowler builds wrote some files with Windows' default
                # code page. Never call a readable file "unreadable" over that -
                # callers treat unreadable as empty and could save it back empty.
                text = raw.decode("cp1252", errors="replace")
            return json.loads(text)
        except FileNotFoundError:
            if default is _MISSING:
                raise
            return default
        except (ValueError, OSError) as e:      # JSONDecodeError is a ValueError
            last = e
            if i < attempts - 1:
                time.sleep(delay)
    if default is _MISSING:
        raise last
    return default
