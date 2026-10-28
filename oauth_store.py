"""
oauth_store.py - OAuth sign-ins for the Claude connector that survive a restart
(2026-10-28).

WHY
---
ai_prowler_mcp.py used to keep the access tokens it hands to claude.ai only in
memory, and it never handed out a refresh token. Every AI-Prowler restart
therefore threw every sign-in away: claude.ai's saved token got a 401 and,
having no refresh token to fall back on, it stayed disconnected until David
signed in again (mcp_server.log 2026-10-28: "AUTH FAIL: no valid Bearer token
for POST /mcp" after each restart).

WHAT
----
OAuthStore keeps registered clients, access tokens and refresh tokens in a JSON
file under ~/.ai-prowler and reloads it at start-up.

  * Only a SHA-256 hash of each token is written - never the token itself - so
    the file is useless to anyone who copies it.
  * Every token keeps its expiry; expired ones are refused and pruned.
  * The file is written with safe_save.atomic_write_json (temp file + atomic
    replace), so a crash mid-save never leaves it half written.
  * Refresh tokens rotate: each refresh returns a new access + refresh token.
    The old refresh token stays usable for a short grace period so a refresh
    response lost on the network doesn't cost a sign-in.
  * Revoking any token of a sign-in revokes the whole sign-in (RFC 7009).
  * "binding": in personal mode the store is bound to a hash of the owner's
    Bearer token. Changing that token in Settings signs every client out, just
    as a restart used to - persisted sign-ins never outlive the secret they
    were issued under.

exchange_token() is the whole /token endpoint (authorization_code + PKCE, and
refresh_token), shared by personal and server mode so both behave the same and
the tests run the real code.

No AI-Prowler imports except safe_save.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from pathlib import Path

try:
    from safe_save import atomic_write_json, read_json_retry
except Exception:                                    # pragma: no cover - safe_save ships with the app
    import json as _json

    def atomic_write_json(path, obj, **_kw):
        Path(path).write_text(_json.dumps(obj, indent=2), encoding="utf-8")

    def read_json_retry(path, default=None, **_kw):
        try:
            return _json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default

__all__ = ["OAuthStore", "token_hash", "exchange_token",
           "ACCESS_TTL_SECS", "REFRESH_TTL_SECS", "REFRESH_GRACE_SECS"]

ACCESS_TTL_SECS = 30 * 86400        # access token: 30 days, then claude.ai refreshes
REFRESH_TTL_SECS = 365 * 86400      # refresh token: 1 year (renewed on every refresh)
REFRESH_GRACE_SECS = 120            # a rotated refresh token still works this long
MAX_GRANTS = 500                    # cap on stored sign-ins (oldest dropped first)
MAX_CLIENTS = 500
_FILE_VERSION = 1


def token_hash(tok: str) -> str:
    """SHA-256 hex of a token. Tokens are long random strings, so no salt is
    needed to make the hash useless for recovering them."""
    return hashlib.sha256((tok or "").encode("utf-8")).hexdigest()


class OAuthStore:
    """Persistent, hashed OAuth tokens. Thread-safe; every change is saved."""

    def __init__(self, path, *, binding: str = "", clock=time.time,
                 access_ttl: int = ACCESS_TTL_SECS, refresh_ttl: int = REFRESH_TTL_SECS,
                 logger=None):
        self.path = Path(path)
        self._binding = binding or ""
        self._clock = clock
        self.access_ttl = int(access_ttl)
        self.refresh_ttl = int(refresh_ttl)
        self._log = logger
        self._lock = threading.RLock()
        self._clients: dict = {}
        self._access: dict = {}     # hash -> {exp, client_id, grant, data}
        self._refresh: dict = {}    # hash -> {exp, client_id, grant, data, rotated?}
        self._load()

    # ── persistence ────────────────────────────────────────────────────────
    def _warn(self, msg, *a):
        if self._log is not None:
            try:
                self._log.warning(msg, *a)
            except Exception:
                pass

    def _load(self):
        try:
            raw = read_json_retry(self.path, default=None)
        except Exception as e:                      # unreadable even after retries
            self._warn("OAuth store %s unreadable (%s) - starting empty", self.path, e)
            raw = None
        if not isinstance(raw, dict):
            return
        self._clients = dict(raw.get("clients") or {})
        if (raw.get("binding") or "") != self._binding:
            # Issued under a different owner token (Settings token changed):
            # every old sign-in is void. Registered clients are harmless to keep.
            self._access, self._refresh = {}, {}
            self._save()
            return
        self._access = {k: v for k, v in (raw.get("access") or {}).items() if isinstance(v, dict)}
        self._refresh = {k: v for k, v in (raw.get("refresh") or {}).items() if isinstance(v, dict)}
        if self._prune():
            self._save()

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(self.path, {
                "version": _FILE_VERSION,
                "note": "AI-Prowler OAuth sign-ins. Only SHA-256 hashes of tokens are stored.",
                "binding": self._binding,
                "clients": self._clients,
                "access": self._access,
                "refresh": self._refresh,
            })
        except Exception as e:
            # Never break a sign-in over a failed save - it just won't survive a restart.
            self._warn("OAuth store save failed (%s): %s", self.path, e)

    def _prune(self) -> bool:
        now = self._clock()
        before = (len(self._access), len(self._refresh), len(self._clients))
        self._access = {k: v for k, v in self._access.items() if v.get("exp", 0) > now}
        self._refresh = {k: v for k, v in self._refresh.items() if v.get("exp", 0) > now}
        for name, cap in (("_access", MAX_GRANTS), ("_refresh", MAX_GRANTS)):
            d = getattr(self, name)
            if len(d) > cap:
                keep = sorted(d.items(), key=lambda kv: kv[1].get("exp", 0))[-cap:]
                setattr(self, name, dict(keep))
        if len(self._clients) > MAX_CLIENTS:
            keep = sorted(self._clients.items(),
                          key=lambda kv: kv[1].get("client_id_issued_at", 0))[-MAX_CLIENTS:]
            self._clients = dict(keep)
        return before != (len(self._access), len(self._refresh), len(self._clients))

    # ── clients (RFC 7591) ─────────────────────────────────────────────────
    def register_client(self, meta: dict | None = None) -> dict:
        meta = meta if isinstance(meta, dict) else {}
        client_id = secrets.token_urlsafe(16)
        grant_types = meta.get("grant_types") or ["authorization_code", "refresh_token"]
        rec = {
            "client_id": client_id,
            "client_id_issued_at": int(self._clock()),
            "grant_types": list(grant_types),
            "response_types": list(meta.get("response_types") or ["code"]),
            "redirect_uris": list(meta.get("redirect_uris") or []),
            "token_endpoint_auth_method": "none",
            "client_name": str(meta.get("client_name") or "Claude")[:200],
        }
        with self._lock:
            self._clients[client_id] = {k: v for k, v in rec.items() if k != "client_id"}
            self._prune()
            self._save()
        return rec

    def get_client(self, client_id: str) -> dict | None:
        with self._lock:
            c = self._clients.get(client_id or "")
            return dict(c, client_id=client_id) if c else None

    # ── tokens ─────────────────────────────────────────────────────────────
    def issue(self, client_id: str = "", data: dict | None = None, *, _grant: str = "") -> dict:
        """Hand out a new access + refresh token pair. Returns the /token body."""
        access, refresh = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
        now = self._clock()
        grant = _grant or secrets.token_hex(8)
        base = {"client_id": client_id or "", "grant": grant, "data": dict(data or {})}
        with self._lock:
            self._access[token_hash(access)] = dict(base, exp=now + self.access_ttl)
            self._refresh[token_hash(refresh)] = dict(base, exp=now + self.refresh_ttl)
            self._prune()
            self._save()
        return {"access_token": access, "token_type": "bearer",
                "expires_in": self.access_ttl, "refresh_token": refresh}

    def check_access(self, tok: str) -> dict | None:
        """The data stored with a valid, unexpired access token, else None."""
        if not tok:
            return None
        with self._lock:
            rec = self._access.get(token_hash(tok))
            if rec is None:
                return None
            if rec.get("exp", 0) <= self._clock():
                self._access.pop(token_hash(tok), None)
                self._save()
                return None
            return dict(rec.get("data") or {})

    def __contains__(self, tok) -> bool:
        return isinstance(tok, str) and self.check_access(tok) is not None

    def refresh(self, refresh_tok: str, client_id: str = "", *, validate=None) -> dict | None:
        """Swap a refresh token for a new pair (rotation). None = invalid_grant.
        validate(data) -> bool may veto it (e.g. the user was removed)."""
        if not refresh_tok:
            return None
        h = token_hash(refresh_tok)
        with self._lock:
            rec = self._refresh.get(h)
            now = self._clock()
            if rec is None or rec.get("exp", 0) <= now:
                if rec is not None:
                    self._refresh.pop(h, None)
                    self._save()
                return None
            if client_id and rec.get("client_id") and client_id != rec["client_id"]:
                return None
            data = dict(rec.get("data") or {})
            if validate is not None and not validate(data):
                self._revoke_grant(rec.get("grant"))
                self._save()
                return None
            if not rec.get("rotated"):
                # Old refresh token: short grace period, then gone.
                rec["rotated"] = True
                rec["exp"] = min(rec["exp"], now + REFRESH_GRACE_SECS)
            return self.issue(rec.get("client_id", ""), data, _grant=rec.get("grant", ""))

    def _revoke_grant(self, grant):
        if not grant:
            return
        self._access = {k: v for k, v in self._access.items() if v.get("grant") != grant}
        self._refresh = {k: v for k, v in self._refresh.items() if v.get("grant") != grant}

    def revoke(self, tok: str) -> bool:
        """Revoke the sign-in an access OR refresh token belongs to."""
        if not tok:
            return False
        h = token_hash(tok)
        with self._lock:
            rec = self._access.get(h) or self._refresh.get(h)
            if rec is None:
                return False
            self._access.pop(h, None)
            self._refresh.pop(h, None)
            self._revoke_grant(rec.get("grant"))
            self._save()
            return True

    def revoke_all(self):
        with self._lock:
            self._access, self._refresh = {}, {}
            self._save()

    def counts(self) -> dict:
        with self._lock:
            return {"clients": len(self._clients), "access": len(self._access),
                    "refresh": len(self._refresh)}


def _pkce_ok(stored: dict, code_verifier: str) -> bool:
    challenge = stored.get("code_challenge") or ""
    if not challenge:
        return True
    if (stored.get("code_challenge_method") or "plain") == "S256":
        digest = hashlib.sha256((code_verifier or "").encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    else:
        computed = code_verifier or ""
    return secrets.compare_digest(computed, challenge)


def exchange_token(store: OAuthStore, form: dict, auth_codes: dict, *,
                   grant_data=None, validate_refresh=None, logger=None):
    """The /token endpoint for both modes. Returns (status_code, json_body).

    form:          the POSTed form fields (dict of str).
    auth_codes:    the in-memory one-time codes from /authorize (popped here).
    grant_data:    stored_code_dict -> dict saved with the sign-in (server mode
                   keeps a hash of the user's token there). Default: {}.
    validate_refresh: data -> bool, checked on every refresh.
    """
    def _get(k):
        v = form.get(k, "") if hasattr(form, "get") else ""
        return v if isinstance(v, str) else str(v or "")

    grant_type = _get("grant_type")
    client_id = _get("client_id")
    if grant_type == "authorization_code":
        code = _get("code")
        if not code or code not in auth_codes:
            return 400, {"error": "invalid_grant"}
        stored = auth_codes.pop(code)
        if not _pkce_ok(stored, _get("code_verifier")):
            if logger is not None:
                logger.warning("OAuth /token: PKCE mismatch for code")
            return 400, {"error": "invalid_grant", "error_description": "PKCE mismatch"}
        data = grant_data(stored) if grant_data is not None else {}
        body = store.issue(client_id or stored.get("client_id", ""), data)
        if logger is not None:
            logger.info("OAuth /token: signed in (authorization_code) client=%s…",
                        (client_id or "?")[:8])
        return 200, body
    if grant_type == "refresh_token":
        body = store.refresh(_get("refresh_token"), client_id, validate=validate_refresh)
        if body is None:
            if logger is not None:
                logger.warning("OAuth /token: refresh refused (unknown, expired or revoked)")
            return 400, {"error": "invalid_grant"}
        if logger is not None:
            logger.info("OAuth /token: refreshed sign-in client=%s…", (client_id or "?")[:8])
        return 200, body
    return 400, {"error": "unsupported_grant_type"}
