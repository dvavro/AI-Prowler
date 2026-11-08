"""Who is calling the Estimator web app, and are they allowed in.

Rules (design spec "Hosting and access" and "Deployment modes"):

- Personal mode, same PC: opens with no login. A request counts as "same PC"
  only when ALL of these hold:
    * it comes from the loopback address (127.0.0.1 / ::1),
    * it carries no proxy/tunnel headers (Remote Access runs through
      cloudflared, which connects from localhost too, so a tunnelled request
      looks local by address alone - the headers give it away),
    * its Host header is localhost / 127.0.0.1 / [::1] (blocks DNS-rebinding
      pages from reaching the no-login path).
- Everything else (office network, Remote Access, Server mode): login required.
  A signed-in browser gets an HttpOnly, SameSite=Strict session cookie; the PWA
  and scripts can send the same token as "Authorization: Bearer <token>".
- Writes (anything but GET/HEAD) must carry the header X-Estimator-Request: 1.
  Browsers can't add that header to a cross-site request without a CORS
  preflight, which this server never approves, so another web page can't make
  the user's browser change estimates (CSRF).

Who the user is comes from a *verifier* the host plugs in: AI-Prowler's own
account system in Server mode (set_verifier from ai_prowler_mcp.py). In Personal
mode the default verifier accepts the owner with AI-Prowler's remote-access
token (or ESTIMATOR_OWNER_PASSWORD), matching how the mobile apps sign in.

Sessions live in memory: after AI-Prowler restarts, people sign in again.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from estimator.context import PERSONAL_COMPANY_ID, ROLES, RequestContext, personal_context

SESSION_COOKIE = "est_session"
SESSION_TTL_SECONDS = 12 * 3600          # sliding: each use extends it
WRITE_HEADER = "x-estimator-request"
LOGIN_MAX_FAILS = 5                       # per user name + address ...
LOGIN_LOCK_SECONDS = 5 * 60               # ... inside this window, then locked for it

LOOPBACK = {"127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"}
LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "[::1]", "::1"}
# Headers that mean the request came through a proxy or tunnel, not from this PC's browser.
PROXY_HEADERS = ("x-forwarded-for", "x-forwarded-host", "x-real-ip", "forwarded",
                 "cf-connecting-ip", "cf-ray", "cf-visitor", "true-client-ip")

# verifier(username, password) -> {"user_id", "role", "company_id"?, "name"?} or None
Verifier = Callable[[str, str], "dict | None"]


@dataclass
class _Settings:
    mode: str = "personal"                # "personal" | "server"
    company_id: str = PERSONAL_COMPANY_ID
    verifier: Verifier | None = None


_settings = _Settings()
_lock = threading.Lock()
_sessions: dict[str, dict] = {}
_fails: dict[str, list[float]] = {}


# ------------------------------------------------------------------ configuration

def configure(*, mode: str | None = None, company_id: str | None = None,
              verifier: Verifier | None = None) -> None:
    """Set by the host (AI-Prowler) at start-up. Tests call it too."""
    if mode is not None:
        if mode not in ("personal", "server"):
            raise ValueError("mode must be 'personal' or 'server'")
        _settings.mode = mode
    if company_id is not None:
        _settings.company_id = company_id
    if verifier is not None:
        _settings.verifier = verifier


def set_verifier(verifier: Verifier | None) -> None:
    _settings.verifier = verifier


def mode() -> str:
    env = os.environ.get("ESTIMATOR_MODE", "").strip().lower()
    return env if env in ("personal", "server") else _settings.mode


def reset() -> None:
    """Forget every session and setting (tests, and the GUI's Stop button)."""
    global _settings
    with _lock:
        _sessions.clear()
        _fails.clear()
    _settings = _Settings()


# ------------------------------------------------------------------ request helpers

def _h(headers: dict, name: str) -> str:
    """Case-insensitive header lookup."""
    name = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return str(v)
    return ""


def is_loopback(client_ip: str) -> bool:
    return (client_ip or "").strip() in LOOPBACK


def came_through_proxy(headers: dict) -> bool:
    return any(_h(headers, n) for n in PROXY_HEADERS)


def host_is_local(headers: dict) -> bool:
    host = _h(headers, "host").strip().lower()
    if not host:
        return False
    if host.startswith("["):                       # [::1]:8770
        name = host.split("]")[0] + "]"
    else:
        name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return name in LOCAL_HOSTNAMES


def is_same_pc(headers: dict, client_ip: str) -> bool:
    return is_loopback(client_ip) and not came_through_proxy(headers) and host_is_local(headers)


def token_from(headers: dict) -> str:
    auth = _h(headers, "authorization")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    for part in _h(headers, "cookie").split(";"):
        k, _, v = part.strip().partition("=")
        if k == SESSION_COOKIE:
            return v.strip()
    return ""


def write_allowed(method: str, headers: dict) -> bool:
    """True for reads, and for writes that carry the anti-CSRF header."""
    if method.upper() in ("GET", "HEAD", "OPTIONS"):
        return True
    return _h(headers, WRITE_HEADER).strip() == "1"


# ------------------------------------------------------------------ sessions

def _ctx_to_dict(ctx: RequestContext) -> dict:
    return {"company_id": ctx.company_id, "user_id": ctx.user_id, "role": ctx.role, "mode": ctx.mode}


def create_session(ctx: RequestContext, name: str = "") -> str:
    token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = {"ctx": _ctx_to_dict(ctx), "name": name or ctx.user_id,
                            "expires": time.time() + SESSION_TTL_SECONDS}
    return token


def session(token: str) -> dict | None:
    if not token:
        return None
    now = time.time()
    with _lock:
        s = _sessions.get(token)
        if s is None:
            return None
        if s["expires"] < now:
            _sessions.pop(token, None)
            return None
        s["expires"] = now + SESSION_TTL_SECONDS
        return dict(s)


def end_session(token: str) -> bool:
    with _lock:
        return _sessions.pop(token, None) is not None


def session_count() -> int:
    with _lock:
        return len(_sessions)


# ------------------------------------------------------------------ who is it

@dataclass(frozen=True)
class Caller:
    ctx: RequestContext
    name: str
    how: str          # "same_pc" | "session"
    token: str = ""


def resolve(headers: dict, client_ip: str) -> Caller | None:
    """The caller, or None when they must sign in first."""
    tok = token_from(headers)
    s = session(tok)
    if s is not None:
        c = s["ctx"]
        return Caller(RequestContext(company_id=c["company_id"], user_id=c["user_id"], role=c["role"],
                                     mode=c["mode"]), s["name"], "session", tok)
    if mode() == "personal" and is_same_pc(headers, client_ip):
        return Caller(personal_context(), "Owner", "same_pc")
    return None


# ------------------------------------------------------------------ login

def _fail_key(username: str, client_ip: str) -> str:
    return f"{username.strip().lower()}|{client_ip}"


def locked_out(username: str, client_ip: str) -> bool:
    now = time.time()
    with _lock:
        recent = [t for t in _fails.get(_fail_key(username, client_ip), []) if now - t < LOGIN_LOCK_SECONDS]
        _fails[_fail_key(username, client_ip)] = recent
        return len(recent) >= LOGIN_MAX_FAILS


def _note_fail(username: str, client_ip: str) -> None:
    with _lock:
        _fails.setdefault(_fail_key(username, client_ip), []).append(time.time())


def _config_files() -> list[Path]:
    """Where AI-Prowler keeps its remote-access token (same places run_tests.bat reads)."""
    files = [Path.home() / ".ai-prowler" / "config.json"]
    if os.environ.get("APPDATA"):
        files.append(Path(os.environ["APPDATA"]) / "AI-Prowler" / "config.json")
    return files


def _owner_password() -> str:
    """Personal mode password: ESTIMATOR_OWNER_PASSWORD, else AI-Prowler's remote-access token."""
    env = os.environ.get("ESTIMATOR_OWNER_PASSWORD", "")
    if env:
        return env
    for p in _config_files():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        tok = data.get("remote_token") or data.get("bearer_token") or ""
        if tok:
            return str(tok)
    return ""


def _personal_verifier(username: str, password: str) -> dict | None:
    want = _owner_password()
    if not want or username.strip().lower() not in ("owner", ""):
        return None
    if hmac.compare_digest(password.encode("utf-8"), want.encode("utf-8")):
        return {"user_id": "owner", "role": "owner", "name": "Owner"}
    return None


class LoginError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def login(username: str, password: str, client_ip: str) -> tuple[str, Caller]:
    """Check the user name and password. Returns (token, caller) or raises LoginError."""
    username = (username or "").strip()
    if not password:
        raise LoginError("invalid_input", "enter your user name and password")
    if locked_out(username, client_ip):
        raise LoginError("locked", f"too many wrong passwords; try again in {LOGIN_LOCK_SECONDS // 60} minutes")
    verifier = _settings.verifier
    if verifier is None:
        if mode() == "server":
            raise LoginError("not_configured", "server sign-in isn't connected to AI-Prowler accounts yet")
        verifier = _personal_verifier
    try:
        who = verifier(username, password)
    except Exception:  # noqa: BLE001 - a broken verifier must never let anyone in
        who = None
    if not who:
        _note_fail(username, client_ip)
        raise LoginError("bad_login", "user name or password is wrong")
    role = str(who.get("role") or "")
    if role not in ROLES:
        raise LoginError("permission_denied", f"role '{role}' can't use the Estimator")
    ctx = RequestContext(company_id=str(who.get("company_id") or _settings.company_id),
                         user_id=str(who.get("user_id") or username), role=role, mode=mode())
    name = str(who.get("name") or ctx.user_id)
    with _lock:
        _fails.pop(_fail_key(username, client_ip), None)
    token = create_session(ctx, name)
    return token, Caller(ctx, name, "session", token)


def cookie_header(token: str, secure: bool = False) -> str:
    flags = f"; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECONDS}"
    return f"{SESSION_COOKIE}={token}{flags}{'; Secure' if secure else ''}"


def clear_cookie_header() -> str:
    return f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
