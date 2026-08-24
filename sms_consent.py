#!/usr/bin/env python3
"""
sms_consent.py  —  AI-Prowler
=====================================
Local storage + lifecycle for web-form SMS consent capture.

Every AI-Prowler install can expose a public POST /consent-signup endpoint
that customers embed on their OWN website (via consent-widget.js hosted at
ai-prowler.com). Submissions are stored locally in:

  ~/.ai-prowler/sms_consent.json

Consent state is kept in sync with inbound SMS keyword replies (STOP /
START / etc.) by sms_webhook() in ai_prowler_mcp.py, which calls
consent_set_state() directly — see Phase 1.5 of the SMS consent feature
plan for the full design rationale.

This module deliberately does NOT decide whether send_sms should refuse to
send to an opted-out number — that's a separate, undecided product
question. This module only captures and reports consent state.
"""

from __future__ import annotations
import json
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import os as _os

from sms_inbox import _norm_digits, _norm_e164, _parse_ts


# ─────────────────────────────────────────────────────────────────────────────
# Paths (honour AIPROWLER_TEST_STATE_DIR for tests — same convention as
# sms_inbox.py)
# ─────────────────────────────────────────────────────────────────────────────

def _state_dir() -> Path:
    td = _os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
    return Path(td) if td else Path.home() / ".ai-prowler"

def _consent_path() -> Path:
    return _state_dir() / "sms_consent.json"


# ─────────────────────────────────────────────────────────────────────────────
# File-level lock — prevents concurrent write corruption. This file now has
# TWO writers (the /consent-signup endpoint AND sms_webhook()'s STOP/START
# handling), so this lock matters more than it did for the single-writer
# sms_inbox.json.
# ─────────────────────────────────────────────────────────────────────────────

_consent_lock = threading.Lock()


def _load_consents() -> list[dict]:
    p = _consent_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8")) or {}
        return data.get("consents", [])
    except Exception:
        return []


def _save_consents(records: list[dict]) -> None:
    """Write consent records to disk atomically."""
    p = _consent_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"consents": records}, indent=2, ensure_ascii=False),
                    encoding="utf-8")
    tmp.replace(p)


# ─────────────────────────────────────────────────────────────────────────────
# Web-form signup — called by POST /consent-signup
# ─────────────────────────────────────────────────────────────────────────────

def consent_signup_upsert(
    name:          str,
    phone:         str,
    consented:     bool,
    source_domain: str = "",
    ip:            str = "",
) -> dict:
    """
    Record a web-form consent submission.

    If a record for this phone number already exists, it is UPDATED in
    place (name, consented, timestamp, source_domain, ip all refreshed) —
    duplicate submissions from the same number are treated as "current
    status," not appended as a history log. The original opt-out/opt-in
    lifecycle fields (opted_out_at, resubscribed_at) are only touched by
    consent_set_state(), never by this function.

    Returns the created/updated record.
    """
    norm_phone = _norm_e164(phone)
    now = datetime.now(timezone.utc).isoformat()

    with _consent_lock:
        records = _load_consents()
        existing = next((r for r in records if r.get("phone") == norm_phone), None)

        if existing:
            existing["name"]          = name
            existing["consented"]     = bool(consented)
            existing["timestamp"]     = now
            existing["source"]        = "web_form"
            existing["source_domain"] = source_domain
            existing["ip"]            = ip
            record = existing
        else:
            record = {
                "id":              str(uuid.uuid4()),
                "name":            name,
                "phone":           norm_phone,
                "consented":       bool(consented),
                "timestamp":       now,
                "opted_out_at":    None,
                "resubscribed_at": None,
                "source":          "web_form",
                "source_domain":   source_domain,
                "ip":              ip,
            }
            records.append(record)

        _save_consents(records)
    return record


# ─────────────────────────────────────────────────────────────────────────────
# SMS-reply lifecycle — called by sms_webhook() on STOP/START keywords
# ─────────────────────────────────────────────────────────────────────────────

_OPT_OUT_KEYWORDS = {"STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT"}
_OPT_IN_KEYWORDS  = {"START", "YES", "UNSTOP"}
_INFO_KEYWORDS    = {"HELP"}


def classify_keyword(body: str) -> Optional[str]:
    """
    Classify an inbound message body as 'opt_out', 'opt_in', 'info', or
    None (not a recognized keyword — ordinary conversational message).

    Uses an EXACT match on the trimmed/uppercased body, not a substring
    match — "please stop by the office" must NOT be classified as opt_out.
    """
    normalized = (body or "").strip().upper()
    if normalized in _OPT_OUT_KEYWORDS:
        return "opt_out"
    if normalized in _OPT_IN_KEYWORDS:
        return "opt_in"
    if normalized in _INFO_KEYWORDS:
        return "info"
    return None


def consent_set_state(phone: str, consented: bool) -> bool:
    """
    Update consent state for a phone number in response to an SMS reply
    (STOP/START/etc.). If no record exists for this number yet (e.g. a
    STOP reply from someone who never went through the web form), a
    minimal record is created rather than silently discarded — this
    matters so a future send_sms enforcement feature (if built) has
    something to check against even for numbers with no web-form history.

    Returns True if an existing record was updated, False if a new
    minimal record was created.
    """
    norm_phone = _norm_e164(phone)
    now = datetime.now(timezone.utc).isoformat()
    updated_existing = False

    with _consent_lock:
        records = _load_consents()
        existing = next((r for r in records if r.get("phone") == norm_phone), None)

        if existing:
            existing["consented"] = consented
            if consented:
                existing["opted_out_at"]    = None
                existing["resubscribed_at"] = now
            else:
                existing["opted_out_at"] = now
            updated_existing = True
        else:
            records.append({
                "id":              str(uuid.uuid4()),
                "name":            None,
                "phone":           norm_phone,
                "consented":       consented,
                "timestamp":       now,
                "opted_out_at":    now if not consented else None,
                "resubscribed_at": now if consented else None,
                "source":          "sms_reply",
                "source_domain":   "",
                "ip":              "",
            })

        _save_consents(records)
    return updated_existing


# ─────────────────────────────────────────────────────────────────────────────
# Reading / reporting
# ─────────────────────────────────────────────────────────────────────────────

def consent_list(
    consented_only: bool = False,
    since_days:     float = 0,
) -> list[dict]:
    """
    Return consent records, newest first.

    Args:
        consented_only: if True, only return records where consented=True
                         (i.e. currently opted in — reflects any STOP/START
                         state changes, not just initial signup state).
        since_days:      only return records with timestamp newer than this
                          many days ago. 0 or negative = no filter.
    """
    with _consent_lock:
        records = _load_consents()

    if since_days and since_days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        records = [r for r in records if _parse_ts(r.get("timestamp", "")) >= cutoff]

    if consented_only:
        records = [r for r in records if r.get("consented")]

    records.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    return records


def consent_delete(phone_or_id: str) -> bool:
    """
    Permanently remove a consent record, matched by phone number (any
    format — normalized before matching) or by record id.

    Returns True if a record was found and removed, False otherwise.
    """
    norm_phone = _norm_e164(phone_or_id)

    with _consent_lock:
        records = _load_consents()
        before = len(records)
        records = [
            r for r in records
            if r.get("phone") != norm_phone and r.get("id") != phone_or_id
        ]
        removed = len(records) < before
        if removed:
            _save_consents(records)
    return removed
