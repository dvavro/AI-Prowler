"""
cli_signin_relay.py — phone sign-in relay for per-user Claude CLI tokens
(server mode AI Routing, 2026-09-19).

A server-mode user who has no Claude Code token connects their Claude account
FROM THEIR PHONE: the server runs `claude setup-token` in a hidden console (the
same method the desktop "Get / Renew Token" button uses, minus the visible
window), hands the sign-in link to the Jobs app, the user signs in in their
phone's browser and copies the code Claude shows, pastes it into the Jobs app,
and this module types it into the hidden console, captures the resulting
`sk-ant-oat…` token and saves it for that user
(task_queue_automation.save_user_oauth_token).

Verified by probe on the target machine (2026-09-19):
  * with output redirected to a file inside a hidden real console, setup-token
    prints its sign-in URL and a "Paste code here if prompted >" prompt;
  * the URL's redirect is https://platform.claude.com/oauth/code/callback (a
    code-paste page a phone can reach), NOT localhost;
  * console_inject.py can type into that hidden console — the CLI reacted to a
    fake code with "OAuth error: Invalid code … Press Enter to retry."
NOT verified: the success path with a real code (needs a real sign-in). It is
handled the way the existing desktop flow handles it — the token is read out of
the output file.

One pending sign-in per user, at most MAX_PENDING at once, each killed and its
temp folder (which would hold the token) deleted after LOGIN_TTL_SEC or on any
outcome. The user's code is never logged and travels to the injector on stdin.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LOGIN_TTL_SEC = 600
MAX_PENDING = 5
START_TIMEOUT_SEC = 45
SUBMIT_TIMEOUT_SEC = 30

_HERE = Path(__file__).resolve().parent
_LOCK = threading.RLock()
_SESSIONS: dict = {}

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
_URL_HEAD = "https://claude.com/cai/oauth/authorize"
_PROMPT = "Paste code here"
_TOKEN_RE = re.compile(r"sk-ant-oat[A-Za-z0-9\-_]{10,}")
_CODE_OK = re.compile(r"[A-Za-z0-9_\-#.~%+/=]{10,400}")
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _tqa():
    import task_queue_automation as tqa
    return tqa


def login_root() -> Path:
    return _tqa().AI_PROWLER_HOME / "ai_routing" / "logins"


# ── pure parsing helpers (unit-tested) ──────────────────────────────────────

def clean_output(raw) -> str:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    return _ANSI.sub("", raw)


def parse_signin_url(text: str):
    """The sign-in URL from the CLI's screen output, or None if it isn't fully
    drawn yet. The CLI wraps the (~330 char) URL across lines and redraws the
    screen repeatedly, so: take the LAST URL head, cut at the first paste
    prompt after it, and strip all whitespace to rejoin the wrapped pieces."""
    i = text.rfind(_URL_HEAD)
    if i < 0:
        return None
    j = text.find(_PROMPT, i)
    if j < 0:
        return None
    url = re.sub(r"\s+", "", text[i:j])
    qs = parse_qs(urlparse(url).query)
    if len((qs.get("state") or [""])[0]) < 40 or not qs.get("code_challenge"):
        return None
    return url


def extract_token(text: str):
    """The sk-ant-oat… token printed by the CLI, or None. If the console
    wrapped it (a real token is ~100+ chars, so a short match followed by a
    newline and more token characters means it was split), rejoin it."""
    m = _TOKEN_RE.search(text)
    if not m:
        return None
    tok = m.group(0)
    if len(tok) < 100:
        rest = re.match(r"\r?\n([A-Za-z0-9\-_]+)[ \t]*(?:\r?\n|$)", text[m.end():])
        if rest:
            tok += rest.group(1)
    return tok


def looks_invalid(text: str) -> bool:
    return "Invalid code" in text or "OAuth error" in text


# ── process plumbing (replaced by tests) ────────────────────────────────────

def _spawn_console(bat_path: Path, env: dict):
    """Runs bat_path in a real but HIDDEN console — setup-token needs a real
    console for its input even though its output is redirected to a file."""
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return subprocess.Popen(["cmd", "/c", str(bat_path)], env=env, startupinfo=si,
                            creationflags=subprocess.CREATE_NEW_CONSOLE)


def _inject(pid: int, text: str):
    """Types `text` + Enter into the console of `pid`. Returns (ok, error)."""
    try:
        r = subprocess.run([sys.executable, str(_HERE / "console_inject.py"), str(pid)],
                           input=text, capture_output=True, text=True,
                           creationflags=NOWIN, timeout=30)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    return (r.returncode == 0), (r.stderr or "").strip()


def _kill_tree(pid: int) -> None:
    try:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True, creationflags=NOWIN, timeout=15)
    except Exception:
        pass


# ── session bookkeeping ─────────────────────────────────────────────────────

def _slug(user_id):
    return _tqa()._user_token_slug(user_id)


def _read_bytes(sess) -> bytes:
    try:
        return sess["out"].read_bytes()
    except Exception:
        return b""


def _alive(sess) -> bool:
    return sess["proc"].poll() is None and time.time() < sess["expires"]


def _end(slug: str) -> None:
    """Kills the console, deletes the temp folder (it can hold the token)."""
    with _LOCK:
        sess = _SESSIONS.pop(slug, None)
    if not sess:
        return
    try:
        sess["timer"].cancel()
    except Exception:
        pass
    _kill_tree(sess["proc"].pid)
    time.sleep(0.3)
    shutil.rmtree(sess["dir"], ignore_errors=True)


def _reap_expired() -> None:
    with _LOCK:
        stale = [s for s, v in _SESSIONS.items() if time.time() >= v["expires"]]
    for s in stale:
        _end(s)


def pending_count() -> int:
    with _LOCK:
        return len(_SESSIONS)


def login_pending(user_id) -> bool:
    slug = _slug(user_id)
    with _LOCK:
        s = _SESSIONS.get(slug)
        return bool(s and _alive(s))


# ── public API ──────────────────────────────────────────────────────────────

def start_login(user_id) -> tuple:
    """Starts (or reuses) this user's sign-in. Returns (True, url) or
    (False, message)."""
    slug = _slug(user_id)
    if not slug:
        return False, "Couldn't identify your account."
    _reap_expired()
    with _LOCK:
        existing = _SESSIONS.get(slug)
        if existing and _alive(existing) and existing.get("url"):
            return True, existing["url"]
    if existing:
        _end(slug)

    with _LOCK:
        if len(_SESSIONS) >= MAX_PENDING:
            return False, "Several people are connecting right now — try again in a minute."
        tqa = _tqa()
        folder = login_root() / f"{slug}-{int(time.time())}"
        folder.mkdir(parents=True, exist_ok=True)
        out = folder / "out.txt"
        noop = folder / "noop_browser.bat"
        noop.write_text("@echo off\r\nexit /b 0\r\n", encoding="utf-8")
        bat = folder / "run.bat"
        bat.write_text(f'@echo off\r\n"{tqa._get_claude_exe()}" setup-token > "{out}" 2>&1\r\n',
                       encoding="utf-8")
        env = dict(os.environ)
        env["BROWSER"] = str(noop)  # never open a browser on the server's desktop
        try:
            proc = _spawn_console(bat, env)
        except Exception as exc:  # noqa: BLE001
            shutil.rmtree(folder, ignore_errors=True)
            return False, f"Couldn't start the Claude sign-in: {exc}"
        timer = threading.Timer(LOGIN_TTL_SEC, _end, args=(slug,))
        timer.daemon = True
        timer.start()
        sess = {"proc": proc, "dir": folder, "out": out, "url": None,
                "expires": time.time() + LOGIN_TTL_SEC, "timer": timer}
        _SESSIONS[slug] = sess

    deadline = time.time() + START_TIMEOUT_SEC
    while time.time() < deadline:
        time.sleep(1)
        url = parse_signin_url(clean_output(_read_bytes(sess)))
        if url:
            sess["url"] = url
            return True, url
        if sess["proc"].poll() is not None:
            break
    _end(slug)
    return False, ("The Claude sign-in didn't start. Make sure Claude Code is "
                   "installed on the server, then try again.")


def submit_code(user_id, code: str) -> dict:
    """Delivers the pasted code. Returns {"status", "message", "token"?} with
    status in: connected | invalid_code | no_session | timeout | error."""
    slug = _slug(user_id)
    code = (code or "").strip()
    with _LOCK:
        sess = _SESSIONS.get(slug)
    if not sess or not _alive(sess):
        if sess:
            _end(slug)
        return {"status": "no_session",
                "message": "That sign-in expired — start again to get a new link."}
    if not _CODE_OK.fullmatch(code):
        return {"status": "invalid_code",
                "message": "That doesn't look like the full code. Copy all of it, then paste it again."}

    before = len(_read_bytes(sess))
    ok, err = _inject(sess["proc"].pid, code)
    if not ok:
        return {"status": "error", "message": "Couldn't deliver the code to the sign-in. Start again."}

    deadline = time.time() + SUBMIT_TIMEOUT_SEC
    while time.time() < deadline:
        time.sleep(1)
        raw = _read_bytes(sess)
        new_text = clean_output(raw[before:])
        token = extract_token(new_text) or extract_token(clean_output(raw))
        if token:
            try:
                _tqa().save_user_oauth_token(user_id, token)
            except ValueError:
                _end(slug)
                return {"status": "error", "message": "Claude returned something unexpected. Start again."}
            _end(slug)
            return {"status": "connected", "message": "Connected.", "token": token}
        if looks_invalid(new_text):
            _inject(sess["proc"].pid, "")  # Enter = retry, back to the paste prompt
            return {"status": "invalid_code",
                    "message": "Claude didn't accept that code. Copy the whole code and paste it again."}
        if sess["proc"].poll() is not None:
            break
    return {"status": "timeout",
            "message": "No answer from Claude yet. Try pasting the code again, or start over."}


def cancel_login(user_id) -> None:
    slug = _slug(user_id)
    if slug:
        _end(slug)
