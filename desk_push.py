"""
desk_push.py — AI-Prowler Service Desk, Phase 5: web push alerts.

Each install makes its own VAPID key pair the first time push is used
(P-256, kept in the tickets DB's desk_state so backups carry it). A phone
that taps 🔔 in the Service Desk app registers its push subscription here;
alerts for that user then arrive even with the app closed.

iPhone: web push only works when the app is installed to the home screen
(Share → Add to Home Screen) — the app says so.

Sending uses pywebpush. If it isn't installed, push is skipped quietly and
email / SMS alerts still go out. Subscriptions the push service has retired
(HTTP 404 / 410) are deleted.
"""
from __future__ import annotations

import base64
import json
import logging

import desk_db
import desk_rules as rules
from db_access import utcnow_iso

log = logging.getLogger("desk_push")
VAPID_SUB = "mailto:service-desk@ai-prowler.com"

SCHEMA = """
CREATE TABLE IF NOT EXISTS push_subscriptions (
    endpoint   TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    p256dh     TEXT NOT NULL,
    auth       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_ok    TEXT
);
CREATE INDEX IF NOT EXISTS ix_push_user ON push_subscriptions(user_id);
"""


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _conn(db_path):
    conn = desk_db.get_connection(db_path)
    conn.executescript(SCHEMA)
    return conn


def keys(db_path: str) -> tuple[str, str]:
    """(public key for the browser, private key PEM). Made once per install."""
    conn = _conn(db_path)
    try:
        r = conn.execute("SELECT value FROM desk_state WHERE key = 'vapid_private_pem'").fetchone()
        if r:
            pem = r[0]
        else:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            k = ec.generate_private_key(ec.SECP256R1())
            pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode("ascii")
            conn.execute("INSERT INTO desk_state (key, value) VALUES ('vapid_private_pem', ?)", (pem,))
    finally:
        conn.close()
    from cryptography.hazmat.primitives import serialization
    priv = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    raw = priv.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)
    return _b64(raw), pem


def subscribe(db_path: str, subscription: dict, *, actor=None) -> dict:
    a = rules.normalize_actor(actor)
    if a["role"] in rules.EXTERNAL_ROLES:
        raise desk_db.DeskError("push alerts are for your team")
    ep = str((subscription or {}).get("endpoint") or "")
    k = (subscription or {}).get("keys") or {}
    if not ep.startswith("https://") or not k.get("p256dh") or not k.get("auth"):
        raise desk_db.DeskError("that is not a valid push subscription")
    conn = _conn(db_path)
    try:
        conn.execute("INSERT INTO push_subscriptions (endpoint, user_id, p256dh, auth, created_at) "
                     "VALUES (?, ?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, "
                     "p256dh = excluded.p256dh, auth = excluded.auth",
                     (ep, a["id"], k["p256dh"], k["auth"], utcnow_iso()))
    finally:
        conn.close()
    return {"ok": True, "user": a["id"]}


def unsubscribe(db_path: str, endpoint: str) -> None:
    conn = _conn(db_path)
    try:
        conn.execute("DELETE FROM push_subscriptions WHERE endpoint = ?", (endpoint,))
    finally:
        conn.close()


def subscriptions(db_path: str, user_id: str) -> list[dict]:
    conn = _conn(db_path)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM push_subscriptions WHERE user_id = ?", (user_id,))]
    finally:
        conn.close()


def _default_sender(sub: dict, payload: str, pem: str) -> int:
    """Send one push; returns the HTTP status (201 = delivered)."""
    from py_vapid import Vapid01
    from pywebpush import WebPushException, webpush
    try:
        resp = webpush({"endpoint": sub["endpoint"], "keys": {"p256dh": sub["p256dh"], "auth": sub["auth"]}},
                       data=payload, vapid_private_key=Vapid01.from_pem(pem.encode("ascii")),
                       vapid_claims={"sub": VAPID_SUB}, ttl=3600)
        return getattr(resp, "status_code", 201)
    except WebPushException as e:
        return getattr(getattr(e, "response", None), "status_code", 500) or 500


sender = None   # tests replace this: fn(sub, payload, pem) -> status


def send(db_path: str, user_id: str, title: str, body: str, url: str = "/desk/",
         ticket_id: str = "") -> int:
    """Push to every phone the user registered. Returns how many accepted it."""
    subs = subscriptions(db_path, user_id)
    if not subs:
        return 0
    fn = sender or _default_sender
    if fn is _default_sender:
        try:
            import pywebpush  # noqa: F401
        except ImportError:
            log.info("pywebpush not installed — Service Desk push skipped")
            return 0
    _pub, pem = keys(db_path)
    payload = json.dumps({"title": title[:120], "body": body[:300], "url": url, "ticket_id": ticket_id})
    ok = 0
    for s in subs:
        try:
            status = fn(s, payload, pem)
        except Exception as e:  # noqa: BLE001
            log.warning("push to %s failed: %s", user_id, e)
            continue
        if status in (404, 410):
            unsubscribe(db_path, s["endpoint"])
        elif 200 <= int(status) < 300:
            ok += 1
            conn = _conn(db_path)
            try:
                conn.execute("UPDATE push_subscriptions SET last_ok = ? WHERE endpoint = ?",
                             (utcnow_iso(), s["endpoint"]))
            finally:
                conn.close()
    return ok
