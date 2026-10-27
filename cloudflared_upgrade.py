"""
cloudflared_upgrade.py  (v9.5.0)
================================
Keeps the bundled cloudflared.exe at or above a minimum safe version.

Background — Cloudflare advisory, Oct 2026: cloudflared before 2026.10.2
still trusts eight compromised eMudhra intermediate certificates, letting
anyone in the network path impersonate Cloudflare to the tunnel.

Why this lives in the app and not only the installer: the in-app updater
(rag_gui.py + update_manifest.json) replaces AI-Prowler's own files, never
cloudflared.exe, and cloudflared.exe sits in Program Files where a
non-elevated process cannot write. So on startup the GUI asks this module
whether the tunnel client is too old and, if the user agrees, runs
upgrade_cloudflared.ps1 elevated (one UAC approval). The installer runs the
same .ps1, so both paths share one implementation.

Minimum version:
  * DEFAULT_MIN_VERSION is built in, so the check works offline.
  * notifications.json may carry "min_cloudflared_version" to RAISE the bar
    for a future advisory without shipping a release. It can never LOWER it
    below the built-in floor — a tampered or stale notifications feed must
    not be able to talk an install back into a vulnerable version.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

DEFAULT_MIN_VERSION = "2026.10.2"
NOTIF_KEY = "min_cloudflared_version"
SCRIPT_NAME = "upgrade_cloudflared.ps1"

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


# ── Version helpers ──────────────────────────────────────────────────────────

def parse_version(text) -> tuple:
    """'cloudflared version 2026.3.0 (built …)' or '2026.10.2' → (2026, 3, 0).
    Returns () when nothing version-like is found."""
    if not text:
        return ()
    m = _VERSION_RE.search(str(text))
    if not m:
        return ()
    return tuple(int(g) for g in m.groups())


def is_outdated(current, minimum) -> bool:
    """True when `current` is known and below `minimum`. An unreadable
    current version is NOT reported as outdated (we don't nag on a guess)."""
    cur = parse_version(current)
    req = parse_version(minimum) or parse_version(DEFAULT_MIN_VERSION)
    return bool(cur) and cur < req


def resolve_min_version(notif_data: Optional[dict] = None) -> str:
    """Effective minimum: the higher of the built-in floor and any valid
    min_cloudflared_version in notifications.json."""
    floor = DEFAULT_MIN_VERSION
    try:
        remote = (notif_data or {}).get(NOTIF_KEY, "")
    except AttributeError:
        remote = ""
    r = parse_version(remote)
    if r and r > parse_version(floor):
        return ".".join(str(x) for x in r)
    return floor


# ── Inspecting the installed client ──────────────────────────────────────────

def default_exe() -> Path:
    """cloudflared.exe ships next to the AI-Prowler code (rag_gui._cf_exe())."""
    return Path(__file__).resolve().parent / "cloudflared.exe"


def get_version(exe) -> Optional[str]:
    """Run `cloudflared --version` and return 'X.Y.Z', or None."""
    exe = Path(exe)
    if not exe.exists():
        return None
    flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
    try:
        r = subprocess.run([str(exe), "--version"], capture_output=True,
                           text=True, timeout=15, creationflags=flags)
    except Exception:
        return None
    v = parse_version((r.stdout or "") + (r.stderr or ""))
    return ".".join(str(x) for x in v) if v else None


def check(exe=None, notif_data: Optional[dict] = None) -> dict:
    """Status of the bundled cloudflared.

    Returns {'status', 'current', 'minimum', 'exe'} where status is:
      'missing'  — no cloudflared.exe (Desktop-only install; nothing to do)
      'unknown'  — exe present but version unreadable (don't nag)
      'ok'       — meets the minimum
      'outdated' — below the minimum → offer the upgrade
    """
    exe = Path(exe) if exe else default_exe()
    minimum = resolve_min_version(notif_data)
    if not exe.exists():
        return {"status": "missing", "current": None, "minimum": minimum, "exe": str(exe)}
    current = get_version(exe)
    if not current:
        status = "unknown"
    elif is_outdated(current, minimum):
        status = "outdated"
    else:
        status = "ok"
    return {"status": status, "current": current, "minimum": minimum, "exe": str(exe)}


# ── Running the upgrade ──────────────────────────────────────────────────────

def _state_dir() -> Path:
    d = Path.home() / ".ai-prowler"
    d.mkdir(parents=True, exist_ok=True)
    return d


def build_ps_args(script, exe, minimum, result_file, log_file) -> str:
    """Argument string for powershell.exe (exposed for tests)."""
    return (f'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden '
            f'-File "{script}" -Dest "{exe}" -MinVersion "{minimum}" '
            f'-ResultFile "{result_file}" -LogFile "{log_file}"')


def run_elevated_upgrade(exe=None, minimum: Optional[str] = None,
                         timeout: int = 240) -> dict:
    """Launch upgrade_cloudflared.ps1 elevated and wait for its result.

    Blocking — call from a background thread. Returns the script's result
    dict ({'status': 'upgraded'|'ok'|'failed', 'message', …}), or
    {'status': 'cancelled'} if UAC was declined, or {'status': 'timeout'}.
    """
    exe = Path(exe) if exe else default_exe()
    minimum = minimum or DEFAULT_MIN_VERSION
    script = Path(__file__).resolve().parent / SCRIPT_NAME
    if not script.exists():
        return {"status": "failed", "message": f"{SCRIPT_NAME} not found next to AI-Prowler"}

    state = _state_dir()
    result_file = state / "cloudflared_upgrade_result.json"
    log_file = state / "cloudflared_upgrade.log"
    try:
        result_file.unlink()
    except FileNotFoundError:
        pass
    except Exception:
        pass

    args = build_ps_args(script, exe, minimum, result_file, log_file)

    # ShellExecuteW "runas" is the reliable way to raise UAC from the
    # non-elevated GUI (same pattern as mobile_activator / _run_elevated).
    import ctypes
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", "powershell.exe", args, None, 0)
    if ret <= 32:
        return {"status": "cancelled",
                "message": "Administrator approval was declined or failed to start."}

    deadline = time.time() + timeout
    while time.time() < deadline:
        if result_file.exists():
            try:
                return json.loads(result_file.read_text(encoding="utf-8-sig"))
            except (json.JSONDecodeError, OSError):
                pass  # still being written — retry
        time.sleep(1)
    return {"status": "timeout",
            "message": f"No result after {timeout}s — see {log_file}"}
