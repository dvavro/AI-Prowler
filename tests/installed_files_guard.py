"""Protects the INSTALLED AI-Prowler files from the test suite (2026-10-09).

Why: on 2026-10-08 David's real ~/.ai-prowler/config.json was found reduced
to {"edition": "business", "mode": "server", "default_spreadsheet_path": ...}
-- every other setting (tunnel, bearer token, license, SMS) gone, and his
personal install restarted in SERVER mode. Cause: tests/gui/
test_server_status_tab.py's server_gui fixture wrote those two keys into the
real file (keeping the original only in memory, so an interrupted run lost
it), and the AI-Prowler window it then opened added default_spreadsheet_path.

Two layers, both installed by tests/conftest.py before any test runs:

1. GUARD -- no test process may write the installed files below. Any
   in-process open-for-write / replace / rename / delete aimed at one of them
   raises PermissionError and is recorded; tests/conftest.py fails the test.
   Writes made by a SUBPROCESS (which this patch can't see) are caught after
   each test by comparing bytes: the file is put back to how it was when the
   run started, the changed copy is kept next to it, and the test fails.

2. REDIRECT -- a test can point one installed file at its own sandbox copy
   (redirect(real, sandbox)). Every read, write and existence check of the
   real path inside this process then goes to the sandbox file instead.
   tests/gui/conftest.py uses this so the desktop window under test always
   sees a sandbox config.json (personal by default; server-mode tests write
   their own) -- never David's installed one.

Also, once per run, a timestamped copy of each protected file is kept in
~/.ai-prowler/test_guard_backups/ (last 10) as insurance.
"""
from __future__ import annotations

import builtins
import datetime as _dt
import io
import os
import threading
from pathlib import Path

# Resolved ONCE, at import, before any test can monkeypatch Path.home().
REAL_STATE_DIR = Path(os.path.expanduser("~")) / ".ai-prowler"
PROTECTED_NAMES = ("config.json", "users.json", "email_config.json",
                   "remote_access.json", "license_seats.json")
PROTECTED = tuple(REAL_STATE_DIR / n for n in PROTECTED_NAMES)
# Caches the AI-Prowler window keeps in the same folder. The RUNNING install
# refreshes these on its own, so they aren't byte-checked after each test —
# but GUI tests redirect them to their sandbox too, so a test never reads or
# writes the installed copies.
SANDBOX_ONLY_NAMES = ("notifications_cache.json", "dismissed_notifications.json",
                      "welcome_ad_cache.json", "welcome_config.json")
SANDBOX_ONLY = tuple(REAL_STATE_DIR / n for n in SANDBOX_ONLY_NAMES)
# Whole folders no test may write into (2026-10-21). On 2026-10-21 David's real
# learnings (~/.ai-prowler/learnings/self_learning_data.json) were found wiped:
# tests/gui/test_learnings_auto_refresh.py "backed up" the real file, wrote a
# placeholder over it, and an interrupted run left the placeholder — every
# later run then "restored" the placeholder. Any in-process write, replace,
# rename or delete inside these folders is now refused and fails the test.
# Not byte-checked/restored after each test like PROTECTED: the RUNNING
# install legitimately adds learnings while tests run, and putting an old
# snapshot back would lose those.
PROTECTED_DIRS = (REAL_STATE_DIR / "learnings",)
BACKUP_DIR = REAL_STATE_DIR / "test_guard_backups"
KEEP_BACKUPS = 10

_real = {
    "open": builtins.open, "io_open": io.open, "os_open": os.open,
    "replace": os.replace, "rename": os.rename, "remove": os.remove,
    "unlink": os.unlink, "stat": os.stat,
}
_lock = threading.Lock()
_snapshot: dict[str, bytes | None] = {}
_violations: list[str] = []
_redirects: dict[str, str] = {}
_current_test = {"id": "(collection)"}
_installed = False


def _key(p) -> str | None:
    """normcase'd absolute path, or None for fds / non-path arguments."""
    if isinstance(p, int):
        return None
    try:
        return os.path.normcase(os.path.abspath(os.fspath(p)))
    except TypeError:
        return None


_PROTECTED_KEYS = {_key(p): p for p in PROTECTED}
_PROTECTED_DIR_KEYS = tuple(_key(d) + os.sep for d in PROTECTED_DIRS)


def _in_protected_dir(p) -> str | None:
    k = _key(p)
    if k is None:
        return None
    for d in _PROTECTED_DIR_KEYS:
        if k.startswith(d) or k + os.sep == d:
            return k
    return None


def _map(p):
    """The path to really use: the sandbox copy if this path is redirected."""
    if not _redirects:          # fast path: nothing redirected
        return p
    k = _key(p)
    if k is not None and k in _redirects:
        return _redirects[k]
    return p


def _refuse(p, what: str):
    hit = _in_protected_dir(p)
    if hit is not None:
        msg = (f"{what} {hit} -- tests must never change the real learnings folder "
               f"(test: {_current_test['id']})")
        with _lock:
            _violations.append(msg)
        raise PermissionError("TEST GUARD refused to " + msg)
    # cheap pre-check: every protected file is named like one of these
    try:
        if os.path.basename(os.fspath(p)).lower() not in PROTECTED_NAMES:
            return
    except TypeError:
        return
    k = _key(p)
    if k in _PROTECTED_KEYS:
        msg = (f"{what} {_PROTECTED_KEYS[k]} -- tests must never change the installed "
               f"AI-Prowler files (test: {_current_test['id']})")
        with _lock:
            _violations.append(msg)
        raise PermissionError("TEST GUARD refused to " + msg)


def _is_write_mode(mode) -> bool:
    return any(c in str(mode) for c in "wax+")


def _flags_write(flags) -> bool:
    return bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))


# ── wrappers ─────────────────────────────────────────────────────────────────
def _open(file, mode="r", *a, **kw):
    file = _map(file)
    if _is_write_mode(mode):
        _refuse(file, "write")
    return _real["open"](file, mode, *a, **kw)


def _io_open(file, mode="r", *a, **kw):
    file = _map(file)
    if _is_write_mode(mode):
        _refuse(file, "write")
    return _real["io_open"](file, mode, *a, **kw)


def _os_open(path, flags, *a, **kw):
    path = _map(path)
    if _flags_write(flags):
        _refuse(path, "write")
    return _real["os_open"](path, flags, *a, **kw)


def _replace(src, dst, *a, **kw):
    src, dst = _map(src), _map(dst)
    _refuse(dst, "replace")
    _refuse(src, "move away")
    return _real["replace"](src, dst, *a, **kw)


def _rename(src, dst, *a, **kw):
    src, dst = _map(src), _map(dst)
    _refuse(dst, "rename onto")
    _refuse(src, "rename")
    return _real["rename"](src, dst, *a, **kw)


def _remove(path, *a, **kw):
    path = _map(path)
    _refuse(path, "delete")
    return _real["remove"](path, *a, **kw)


def _unlink(path, *a, **kw):
    path = _map(path)
    _refuse(path, "delete")
    return _real["unlink"](path, *a, **kw)


def _stat(path, *a, **kw):
    # Only redirection matters here (Path.exists / os.path.exists / getmtime
    # all go through os.stat) -- reading metadata is never refused.
    return _real["stat"](_map(path), *a, **kw)


# ── public API ───────────────────────────────────────────────────────────────
def install():
    """Patch the file functions and take the start-of-run snapshot (+backup)."""
    global _installed
    if _installed:
        return
    for p in PROTECTED:
        try:
            with _real["open"](p, "rb") as f:
                _snapshot[str(p)] = f.read()
        except FileNotFoundError:
            _snapshot[str(p)] = None
        except OSError:
            _snapshot[str(p)] = None
    _backup_snapshot()
    builtins.open = _open
    io.open = _io_open
    os.open = _os_open
    os.replace = _replace
    os.rename = _rename
    os.remove = _remove
    os.unlink = _unlink
    os.stat = _stat
    _installed = True


def _backup_snapshot():
    """Timestamped copy of every protected file that exists (last KEEP_BACKUPS)."""
    have = {k: v for k, v in _snapshot.items() if v is not None}
    if not have:
        return
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        for path, data in have.items():
            name = Path(path).name
            with _real["open"](BACKUP_DIR / f"{name}.{stamp}", "wb") as f:
                f.write(data)
            olds = sorted(BACKUP_DIR.glob(f"{name}.2*"))
            for old in olds[:-KEEP_BACKUPS]:
                try:
                    _real["unlink"](old)
                except OSError:
                    pass
    except OSError:
        pass   # insurance only -- never stop a run over it


def set_current_test(test_id: str):
    _current_test["id"] = test_id


def take_violations() -> list[str]:
    with _lock:
        v, _violations[:] = list(_violations), []
    return v


def check_and_restore() -> list[str]:
    """Compare every protected file with the start-of-run snapshot. Any file
    that changed (e.g. written by a subprocess) is put back; the changed
    version is kept as <name>.changed_by_test.<stamp> in BACKUP_DIR."""
    problems = []
    for p in PROTECTED:
        want = _snapshot.get(str(p))
        try:
            with _real["open"](p, "rb") as f:
                now = f.read()
        except FileNotFoundError:
            now = None
        except OSError:
            continue
        if now == want:
            continue
        stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            if now is not None:
                with _real["open"](BACKUP_DIR / f"{p.name}.changed_by_test.{stamp}", "wb") as f:
                    f.write(now)
            if want is None:
                _real["unlink"](p)
            else:
                tmp = p.with_name(p.name + ".test_guard_restore")
                with _real["open"](tmp, "wb") as f:
                    f.write(want)
                _real["replace"](tmp, p)
            problems.append(f"{p} was changed during {_current_test['id']} -- put back "
                            f"(changed copy kept in {BACKUP_DIR})")
        except OSError as e:
            problems.append(f"{p} was changed during {_current_test['id']} and could NOT be "
                            f"put back ({e}) -- start-of-run copy is in {BACKUP_DIR}")
    return problems


def redirect(real_path, sandbox_path):
    """Send every in-process access of real_path to sandbox_path."""
    k = _key(real_path)
    with _lock:
        _redirects[k] = str(sandbox_path)


def clear_redirect(real_path):
    with _lock:
        _redirects.pop(_key(real_path), None)


def clear_all_redirects():
    with _lock:
        _redirects.clear()
