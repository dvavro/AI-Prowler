"""
tool_config_store.py
====================
Hardened persistence layer for the MCP Tool Configuration panel
(Settings tab -> MCP Tool Configuration).

DESIGN GUARANTEE (the whole point of this module):
    * ``save_disabled_tools()`` and ``reset_disabled_tools()`` write to
      exactly ONE file: ``~/.ai-prowler/tool_config.json``.
    * They NEVER create, modify, truncate, or delete ``config.json`` --
      or any other file in the state directory.  This is enforced by
      construction: the write path is a module-level constant, the public
      functions take no path argument, and a test snapshots the whole
      state directory to prove nothing else changes.
    * Writes are read-modify-write: the existing file is loaded first and
      only the current mode's ``disabled_tools`` list (plus the schema
      version) is updated.  The other mode's list, the schema version,
      and any unknown/future keys are preserved byte-for-byte in spirit.
    * Writes are atomic (temp file in the same directory + ``os.replace``)
      so a crash or power loss can never leave a half-written file.
    * A timestamped backup of the previous file is kept next to it before
      every overwrite.

Usage from the GUI panel::

    from tool_config_store import save_disabled_tools, reset_disabled_tools, load_tool_config

    # Save button:
    save_disabled_tools(disabled_now, mode="personal")

    # Reset to Defaults button:
    reset_disabled_tools(mode="personal")

    # Panel render:
    cfg = load_tool_config()
    disabled = set(cfg["personal"]["disabled_tools"])
"""

import copy
import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

SCHEMA_VERSION = 1

# The ONLY file this module is ever allowed to write.  There is no code
# path in this module that constructs any other output path.
_TOOL_CONFIG_FILENAME = "tool_config.json"

# Files that must never be touched by this module (defense in depth --
# _checked_write() refuses any target whose name is in this set).
_NEVER_WRITE = frozenset({
    "config.json",
    "remote_access.json",
    "claude_mcp_config.json",
    "setup_progress.json",
    "scheduler_config.json",
    "welcome_config.json",
    # 2026-10-01: the rest of the user's settings files, so the post-save
    # check in save_disabled_tools() protects them too.
    "email_config.json",
    "task_automation_config.json",
    "builtin_analysis_config.json",
    "custom_analysis_tasks.json",
    "license_cache.json",
})


def _state_dir():
    """State directory.  Tests redirect it via AIPROWLER_TEST_STATE_DIR."""
    override = os.environ.get("AIPROWLER_TEST_STATE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".ai-prowler"


def tool_config_path():
    """Absolute path of the single file this module manages."""
    return _state_dir() / _TOOL_CONFIG_FILENAME


def _blank_config():
    return {
        "schema_version": SCHEMA_VERSION,
        "personal": {"disabled_tools": []},
        "server": {"disabled_tools": []},
    }


def load_tool_config():
    """Load the tool config.  Missing or corrupt file -> blank (never raises)."""
    path = tool_config_path()
    try:
        if not path.exists():
            return _blank_config()
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(raw, dict):
            return _blank_config()
        data = _blank_config()
        # Preserve unknown/future top-level keys instead of dropping them.
        for key, value in raw.items():
            if key not in data:
                data[key] = copy.deepcopy(value)
        for mode in ("personal", "server"):
            section = raw.get(mode)
            if isinstance(section, dict):
                disabled = section.get("disabled_tools")
                if isinstance(disabled, list):
                    data[mode]["disabled_tools"] = [str(n) for n in disabled]
        if isinstance(raw.get("schema_version"), int):
            data["schema_version"] = raw["schema_version"]
        return data
    except Exception:
        # Corrupt file: return blank rather than propagating a wipe.
        return _blank_config()


def _checked_write(path, data):
    """Atomic write with backup.  Refuses any target that isn't tool_config.json."""
    if path.name in _NEVER_WRITE or path.name != _TOOL_CONFIG_FILENAME:
        raise RuntimeError(
            "tool_config_store: refusing to write to protected file %r" % (path.name,)
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = path.with_name("%s.bak_%s" % (_TOOL_CONFIG_FILENAME, stamp))
        shutil.copy2(path, backup)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=_TOOL_CONFIG_FILENAME + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _protected_snapshot():
    """Bytes of every protected settings file as it is right now (missing -> None).

    Taken just before a save so the save can prove afterwards that it left the
    user's real settings exactly as they were (2026-10-01, Vicki: a Save in the
    MCP panel appeared to wipe her settings)."""
    snap = {}
    base = _state_dir()
    for name in _NEVER_WRITE:
        p = base / name
        try:
            snap[name] = p.read_bytes() if p.exists() else None
        except OSError:
            snap[name] = None
    return snap


def _looks_valid(raw):
    try:
        json.loads(raw.decode("utf-8-sig"))
        return bool(raw.strip())
    except Exception:
        return False


def _restore_if_damaged(snapshot):
    """Put back any protected settings file that was valid before the save and is
    now missing, empty or unreadable.  A file another part of AI-Prowler
    legitimately changed (still valid JSON) is left alone.  Returns the names
    restored (normally an empty list)."""
    restored = []
    base = _state_dir()
    for name, before in snapshot.items():
        if before is None or not _looks_valid(before):
            continue                       # nothing good to restore to
        p = base / name
        try:
            now = p.read_bytes() if p.exists() else None
        except OSError:
            now = None
        if now is None or not _looks_valid(now):
            try:
                p.write_bytes(before)
                restored.append(name)
            except OSError:
                pass
    return restored


def save_disabled_tools(disabled_tools, mode):
    """Persist one mode's disabled-tool list.

    Only ``tool_config.json`` is written.  Every other file in the state
    directory -- including ``config.json`` -- is left untouched, and is
    verified (and put back if damaged) after the write.
    """
    if mode not in ("personal", "server"):
        raise ValueError("mode must be 'personal' or 'server', got %r" % (mode,))
    snapshot = _protected_snapshot()
    data = load_tool_config()
    data.setdefault(mode, {})["disabled_tools"] = sorted(set(str(n) for n in disabled_tools))
    data["schema_version"] = SCHEMA_VERSION
    try:
        _checked_write(tool_config_path(), data)
    finally:
        _restore_if_damaged(snapshot)
    return data


def reset_disabled_tools(mode):
    """Reset to Defaults: clear one mode's disabled list.

    Only ``tool_config.json`` is written.  The other mode's list is
    preserved, and ``config.json`` (or any other settings file) is never
    touched.
    """
    return save_disabled_tools([], mode)


# ── Optional groups that start OFF (2026-10-12, David) ──────────────────────
# "Job Tracker & Routing" and "SMS & WhatsApp" default to OFF in personal and
# server mode — for NEW installs only. An install that already uses them keeps
# them on (David's choice): with no saved choice, a group counts as on when
# its data is already there (customers or jobs in the jobs database; an SMS
# provider set up). A choice saved in Settings → MCP Tool Configuration always
# wins. Stored as {"optional_groups": {"personal": {group: bool}, "server": …}}
# in this same tool_config.json, through the same guarded write.
DEFAULT_OFF_GROUPS = ("job_tracker", "sms_whatsapp")
OPTIONAL_GROUPS_KEY = "optional_groups"


_JOB_DATA_TABLES = ("customers", "jobs", "invoices", "quotes", "time_entries",
                    "route_stops", "service_pricing")


def _jobs_in_use():
    """True when the Jobs feature has been used on this install: real rows in
    any Jobs table, or (server) more than one user — a crew. The database FILE
    alone proves nothing (status checks create it), and a test server's job
    tables can be empty after E2E cleanup while the crew still use the Jobs
    app (found on David's server 2026-10-12)."""
    import sqlite3
    for p in (_state_dir() / "jobs_database" / "ai_prowler_jobs.db",
              _state_dir() / "ai_prowler_jobs.db"):
        if not p.exists():
            continue
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=2.0)
            try:
                for table in _JOB_DATA_TABLES:
                    try:
                        if con.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                            return True
                    except sqlite3.Error:
                        pass
                try:
                    if (con.execute("SELECT COUNT(*) FROM users").fetchone() or [0])[0] > 1:
                        return True
                except sqlite3.Error:
                    pass
            finally:
                con.close()
        except Exception:
            continue
    try:                                            # server users.json: a crew
        import json as _j
        u = _j.loads((_state_dir() / "users.json").read_text(encoding="utf-8-sig"))
        if len((u or {}).get("users") or {}) > 1:
            return True
    except Exception:
        pass
    return False


def _sms_in_use():
    """True when an SMS / WhatsApp provider is already set up."""
    try:
        from sms_backends import get_sms_backend, load_sms_config
        ok, _ = get_sms_backend(load_sms_config()).validate_config()
        return bool(ok)
    except Exception:
        return False


_IN_USE = {"job_tracker": _jobs_in_use, "sms_whatsapp": _sms_in_use}


def saved_group_choice(mode, group):
    """The choice saved in Settings for this group (True/False), or None."""
    section = (load_tool_config().get(OPTIONAL_GROUPS_KEY) or {}).get(mode) or {}
    val = section.get(group)
    return val if isinstance(val, bool) else None


def group_enabled(mode, group):
    """Is a default-OFF group on for this mode? Saved choice first; otherwise
    on only if the install already uses it (existing installs keep working)."""
    if mode not in ("personal", "server"):
        raise ValueError(f"mode must be 'personal' or 'server', got {mode!r}")
    if group not in DEFAULT_OFF_GROUPS:
        return True
    saved = saved_group_choice(mode, group)
    if saved is not None:
        return saved
    try:
        on = bool(_IN_USE[group]())
    except Exception:
        on = False
    # Record the first decision so it can't flip later (e.g. a test server's
    # job tables emptied by E2E cleanup). Settings can always change it.
    try:
        set_group_enabled(mode, group, on)
    except Exception:
        pass
    return on


def set_group_enabled(mode, group, enabled):
    """Record the owner's choice for a default-OFF group. Only tool_config.json
    is written; every other settings file is verified afterwards."""
    if mode not in ("personal", "server"):
        raise ValueError(f"mode must be 'personal' or 'server', got {mode!r}")
    if group not in DEFAULT_OFF_GROUPS:
        raise ValueError(f"{group!r} is not a default-off group")
    snapshot = _protected_snapshot()
    data = load_tool_config()
    groups = data.get(OPTIONAL_GROUPS_KEY)
    if not isinstance(groups, dict):
        groups = {}
    section = groups.get(mode) if isinstance(groups.get(mode), dict) else {}
    section[group] = bool(enabled)
    groups[mode] = section
    data[OPTIONAL_GROUPS_KEY] = groups
    data["schema_version"] = SCHEMA_VERSION
    try:
        _checked_write(tool_config_path(), data)
    finally:
        _restore_if_damaged(snapshot)
    return data


# ── HR apps switch (2026-10-11, David) ──────────────────────────────────────
# The HR Admin and HR Portal apps (and Claude/Muse/Grok's hr_* tools) are AI-Prowler
# SERVER only and OFF until the owner turns them on in Settings → MCP Tool
# Configuration ("HR apps (HR Admin + HR Portal)"). A plain disabled-tools
# list can't say "off unless turned on", so the choice is its own top-level
# key in the same tool_config.json — written through the same guarded,
# atomic, backed-up path as save_disabled_tools() (never config.json).
HR_APPS_KEY = "hr_apps_enabled"


def hr_apps_enabled():
    """True only after the owner has switched the HR apps on. Missing or
    corrupt file, missing key, or any non-True value → False (off)."""
    return load_tool_config().get(HR_APPS_KEY) is True


def set_hr_apps_enabled(enabled):
    """Record the HR apps switch. Only tool_config.json is written; every other
    settings file is verified (and put back if damaged) afterwards."""
    snapshot = _protected_snapshot()
    data = load_tool_config()
    data[HR_APPS_KEY] = bool(enabled)
    data["schema_version"] = SCHEMA_VERSION
    try:
        _checked_write(tool_config_path(), data)
    finally:
        _restore_if_damaged(snapshot)
    return data
