#!/usr/bin/env python3
"""
sms_inbox.py  —  AI-Prowler V8.0.0
=====================================
Local inbox storage and thread model for two-way SMS / WhatsApp messaging.

Instead of polling the Twilio API on every check_sms_replies call, inbound
messages are delivered via webhook (POST /sms-webhook) and stored locally in:
  ~/.ai-prowler/sms_inbox.json    — all inbound messages
  ~/.ai-prowler/sms_threads.json  — outbound thread log (who sent to whom)

This gives:
  • Instant reply checks (local file read, no API latency)
  • Per-crew-member filtering (Mike sees only Karen's reply, not Jake's)
  • Provider-agnostic storage (Twilio, SignalWire, Vonage, WhatsApp all
    write to the same inbox; tools don't care which provider delivered it)
  • Offline resilience (replies stored even if MCP server is restarted)
"""

from __future__ import annotations
import json
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Paths (honour AIPROWLER_TEST_STATE_DIR for tests)
# ─────────────────────────────────────────────────────────────────────────────

import os as _os

def _state_dir() -> Path:
    td = _os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
    return Path(td) if td else Path.home() / ".ai-prowler"

def _inbox_path() -> Path:
    return _state_dir() / "sms_inbox.json"

def _threads_path() -> Path:
    return _state_dir() / "sms_threads.json"


# ─────────────────────────────────────────────────────────────────────────────
# File-level lock — prevents concurrent write corruption
# ─────────────────────────────────────────────────────────────────────────────

_inbox_lock   = threading.Lock()
_threads_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Inbox — inbound messages from any provider
# ─────────────────────────────────────────────────────────────────────────────

def sms_inbox_read(
    since_hours:  float = 24.0,
    from_number:  str   = "",
    unread_only:  bool  = False,
    user_id:      str   = "",
    provider:     str   = "",
) -> list[dict]:
    """
    Read messages from the local SMS inbox.

    Args:
        since_hours:  Only return messages newer than this many hours (default 24).
                      Pass 0 or negative to return all messages.
        from_number:  Filter by sender phone number (10 digits, any format).
                      Empty string = no filter.
        unread_only:  If True, return only messages not yet read by user_id.
        user_id:      Used with unread_only to check the read_by list.
        provider:     Filter by provider ('twilio', 'signalwire', 'vonage',
                      'whatsapp'). Empty = no filter.

    Returns:
        List of message dicts, newest first.
    """
    with _inbox_lock:
        msgs = _load_inbox()

    # Time filter
    if since_hours and since_hours > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        msgs = [m for m in msgs if _parse_ts(m.get("timestamp","")) >= cutoff]

    # Sender filter
    if from_number.strip():
        import re
        digits = re.sub(r'\D', '', from_number)
        if len(digits) == 11 and digits[0] == '1':
            digits = digits[1:]
        msgs = [m for m in msgs if _norm_digits(m.get("from","")) == digits]

    # Provider filter
    if provider.strip():
        msgs = [m for m in msgs if m.get("provider","") == provider.strip().lower()]

    # Unread filter
    if unread_only and user_id:
        msgs = [m for m in msgs if user_id not in (m.get("read_by") or [])]

    # Newest first
    msgs.sort(key=lambda m: m.get("timestamp",""), reverse=True)
    return msgs


def sms_inbox_read_for_user(user_id: str, since_hours: float = 24.0,
                             unread_only: bool = False) -> list[dict]:
    """
    Return only messages relevant to user_id — i.e. replies from phone numbers
    that user_id has previously sent to (via sms_thread_log).

    This prevents Mike from seeing Karen's reply to Jake's message.
    Falls back to all messages if the user has no thread history.
    """
    threads = _load_threads()
    user_threads = {
        thread_id: t
        for thread_id, t in threads.items()
        if t.get("last_sent_by") == user_id
    }

    if not user_threads:
        # New user with no history — show all (they'll build history as they send)
        return sms_inbox_read(since_hours=since_hours, unread_only=unread_only,
                              user_id=user_id)

    all_msgs = sms_inbox_read(since_hours=since_hours, unread_only=unread_only,
                               user_id=user_id)
    relevant_numbers = set(user_threads.keys())  # thread_id == normalised 10-digit number
    return [m for m in all_msgs if _norm_digits(m.get("from","")) in relevant_numbers]


def sms_inbox_append(
    message_id:    str,
    from_number:   str,
    to_number:     str,
    body:          str,
    provider:      str   = "twilio",
    contact_name:  str   = "",
    timestamp:     str   = "",
    direction:     str   = "inbound",
    extra:         dict  = None,
) -> bool:
    """
    Append an inbound message to the local inbox.

    Idempotent: if message_id already exists, the call is a no-op.

    Args:
        message_id:   Provider message SID / ID (used for deduplication).
        from_number:  Sender phone in any format.
        to_number:    Recipient phone (your Twilio/SignalWire number).
        body:         Message text.
        provider:     'twilio' | 'signalwire' | 'vonage' | 'whatsapp'
        contact_name: Resolved name from contacts_cache.json (optional).
        timestamp:    ISO-8601 UTC string. Defaults to now() if empty.
        direction:    'inbound' (default) or 'outbound'.
        extra:        Any additional provider-specific fields to store.

    Returns:
        True if appended, False if duplicate (already existed).
    """
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    entry = {
        "id":           message_id or str(uuid.uuid4()),
        "provider":     provider.strip().lower(),
        "from":         _norm_e164(from_number),
        "to":           _norm_e164(to_number),
        "body":         (body or "").strip(),
        "timestamp":    ts,
        "direction":    direction,
        "contact_name": contact_name or "",
        "read_by":      [],
        "thread_id":    _norm_digits(from_number),
    }
    if extra:
        entry["extra"] = extra

    with _inbox_lock:
        msgs = _load_inbox()
        existing_ids = {m.get("id") for m in msgs}
        if entry["id"] in existing_ids:
            return False  # duplicate
        msgs.append(entry)
        _save_inbox(msgs)
    return True


def sms_inbox_mark_read(message_id: str, user_id: str) -> bool:
    """
    Mark a message as read by user_id.
    Returns True if the message was found and updated, False otherwise.
    """
    with _inbox_lock:
        msgs = _load_inbox()
        for m in msgs:
            if m.get("id") == message_id:
                if user_id not in (m.get("read_by") or []):
                    m.setdefault("read_by", []).append(user_id)
                    _save_inbox(msgs)
                return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Thread log — outbound message history (who sent to whom)
# ─────────────────────────────────────────────────────────────────────────────

def sms_thread_log(
    sent_by:      str,
    to_number:    str,
    body:         str,
    provider:     str = "twilio",
    contact_name: str = "",
    message_id:   str = "",
) -> None:
    """
    Record an outbound message in the thread log.

    Called by send_sms() and send_whatsapp() after a successful send.
    Creates or updates the thread entry for (sent_by, to_number).

    Thread key is the normalised 10-digit recipient number so that
    sms_inbox_read_for_user() can match inbound replies by sender number.
    """
    thread_id = _norm_digits(to_number)
    ts = datetime.now(timezone.utc).isoformat()
    msg_entry = {
        "id":        message_id or str(uuid.uuid4()),
        "direction": "outbound",
        "body":      body,
        "timestamp": ts,
        "sent_by":   sent_by,
        "provider":  provider,
    }

    with _threads_lock:
        threads = _load_threads()
        if thread_id not in threads:
            threads[thread_id] = {
                "thread_id":      thread_id,
                "contact_name":   contact_name or "",
                "last_sent_by":   sent_by,
                "last_sent_at":   ts,
                "provider":       provider,
                "messages":       [],
            }
        else:
            threads[thread_id]["last_sent_by"] = sent_by
            threads[thread_id]["last_sent_at"] = ts
            if contact_name:
                threads[thread_id]["contact_name"] = contact_name
        threads[thread_id]["messages"].append(msg_entry)
        _save_threads(threads)


def sms_thread_get(contact_phone_or_name: str) -> Optional[dict]:
    """
    Return the full thread dict for a contact, or None if not found.
    Matches by normalised phone number or contact_name (case-insensitive).
    """
    threads = _load_threads()
    # Try phone number match first
    digits = _norm_digits(contact_phone_or_name)
    if digits and digits in threads:
        return threads[digits]
    # Try name match
    name_lower = contact_phone_or_name.strip().lower()
    for t in threads.values():
        if t.get("contact_name", "").lower() == name_lower:
            return t
    return None


def sms_thread_get_with_replies(contact_phone_or_name: str,
                                since_hours: float = 168.0) -> dict:
    """
    Return a thread combined with its inbound replies — a full conversation view.

    Returns:
        {
          'thread_id':    '3865550101',
          'contact_name': 'Karen Torres',
          'messages':     [...outbound..., ...inbound...]  sorted by timestamp
        }
    """
    thread = sms_thread_get(contact_phone_or_name)
    if not thread:
        return {}

    thread_id = thread["thread_id"]
    outbound  = thread.get("messages", [])
    inbound   = sms_inbox_read(since_hours=since_hours, from_number=thread_id)

    # Tag direction on each message for display
    for m in inbound:
        m["direction"] = "inbound"

    all_msgs = outbound + inbound
    all_msgs.sort(key=lambda m: m.get("timestamp", ""))

    return {
        "thread_id":    thread_id,
        "contact_name": thread.get("contact_name", thread_id),
        "last_sent_by": thread.get("last_sent_by", ""),
        "provider":     thread.get("provider", ""),
        "messages":     all_msgs,
    }


def sms_active_threads(since_hours: float = 168.0) -> list[dict]:
    """
    Return threads that have had activity (sent or received) within since_hours.
    Sorted by most recent activity first.
    Used by list_sms_contacts_with_replies().
    """
    threads = _load_threads()
    cutoff  = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    active  = []
    for t in threads.values():
        ts = _parse_ts(t.get("last_sent_at", ""))
        if ts >= cutoff:
            # Count unread inbound replies
            inbound = sms_inbox_read(since_hours=since_hours,
                                     from_number=t["thread_id"])
            t = dict(t)  # don't mutate stored data
            t["unread_replies"] = len([m for m in inbound if not m.get("read_by")])
            t["total_replies"]  = len(inbound)
            active.append(t)
    active.sort(key=lambda t: t.get("last_sent_at",""), reverse=True)
    return active


# ─────────────────────────────────────────────────────────────────────────────
# Webhook signature validation
# ─────────────────────────────────────────────────────────────────────────────

def validate_twilio_signature(
    auth_token:  str,
    signature:   str,
    url:         str,
    params:      dict,
) -> bool:
    """
    Validate a Twilio X-Twilio-Signature header using HMAC-SHA1.

    Twilio signs inbound webhook POST requests so the server can verify
    they actually came from Twilio (not a spoofed request).

    Algorithm:
        1. Sort POST params alphabetically by key
        2. Concatenate url + key + value for each param
        3. HMAC-SHA1 of that string using auth_token as key
        4. Base64-encode and compare to the received signature

    Returns True if valid, False if invalid or on any error.
    """
    import hmac
    import hashlib
    import base64

    try:
        # Build the string to sign: url + sorted params
        s = url
        for key in sorted(params.keys()):
            s += key + str(params[key])

        # HMAC-SHA1
        mac = hmac.new(
            auth_token.encode("utf-8"),
            s.encode("utf-8"),
            hashlib.sha1,
        )
        computed = base64.b64encode(mac.digest()).decode("utf-8")
        return hmac.compare_digest(computed, signature)
    except Exception:
        return False


def validate_signalwire_signature(
    auth_token: str,
    signature:  str,
    url:        str,
    params:     dict,
) -> bool:
    """
    SignalWire uses the same HMAC-SHA1 algorithm as Twilio.
    auth_token here is the SignalWire Auth Token (not Project ID).
    """
    return validate_twilio_signature(auth_token, signature, url, params)


def validate_vonage_signature(
    api_secret: str,
    params:     dict,
) -> bool:
    """
    Vonage webhook signature validation using MD5.

    Algorithm:
        1. Remove the 'sig' param from the dict
        2. Sort remaining params alphabetically
        3. Build string: &key=value&key=value...
        4. Append api_secret
        5. MD5 hash the result
        6. Compare to sig param (case-insensitive hex)

    Returns True if valid.
    """
    import hashlib
    try:
        params = dict(params)  # copy so we can pop sig
        received_sig = params.pop("sig", "")
        s = "&".join(f"{k}={params[k]}" for k in sorted(params.keys()))
        s += api_secret
        computed = hashlib.md5(s.encode("utf-8")).hexdigest()
        return computed.lower() == received_sig.lower()
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_inbox() -> list[dict]:
    """Load inbox from disk. Returns [] on any error."""
    p = _inbox_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8")) or {}
        return data.get("messages", [])
    except Exception:
        return []


def _save_inbox(msgs: list[dict]) -> None:
    """Write inbox to disk atomically."""
    p = _inbox_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    # Write to temp then rename for atomicity
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"messages": msgs}, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(p)


def _load_threads() -> dict:
    """Load thread log from disk. Returns {} on any error."""
    p = _threads_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _save_threads(threads: dict) -> None:
    """Write thread log to disk atomically."""
    p = _threads_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(threads, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(p)


def _norm_digits(phone: str) -> str:
    """Return 10 normalised digits for a US phone number, or '' if invalid."""
    import re
    digits = re.sub(r'\D', '', phone or "")
    # Strip 'whatsapp:' prefix digits if present
    if len(digits) == 11 and digits[0] == '1':
        digits = digits[1:]
    return digits if len(digits) == 10 else ""


def _norm_e164(phone: str) -> str:
    """Normalise phone to +1XXXXXXXXXX or return as-is if not parseable."""
    # Handle 'whatsapp:+1XXXXXXXXXX' format
    if phone.startswith("whatsapp:"):
        phone = phone[9:]
    digits = _norm_digits(phone)
    return f"+1{digits}" if digits else phone


def _parse_ts(ts_str: str) -> datetime:
    """Parse an ISO-8601 timestamp string to timezone-aware datetime.
    Returns epoch on any parse error."""
    try:
        # Handle both with and without timezone info
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
