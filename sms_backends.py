#!/usr/bin/env python3
"""
sms_backends.py  —  AI-Prowler V8.0.0
======================================
SMS / WhatsApp backend abstraction layer.

Provides a unified send() interface across multiple providers so that
ai_prowler_mcp.py (send_sms, send_whatsapp) can swap providers by changing
one config.json field — no code changes needed.

Supported providers:
  • twilio      — Twilio SMS (existing, already working)
  • signalwire  — SignalWire (Twilio-compatible API, cheaper)
  • vonage      — Vonage / Nexmo (different auth, same concept)
  • whatsapp    — WhatsApp Business via Twilio (same creds, whatsapp: prefix)

Usage:
    from sms_backends import get_sms_backend, get_whatsapp_backend

    backend = get_sms_backend(config_dict)
    ok, msg = backend.send(to="+13865550101", body="Mike is 10 min away")

    wa_backend = get_whatsapp_backend(config_dict)
    ok, msg = wa_backend.send(to="+13865550101", body="Job complete")

All send() calls return (success: bool, message: str).
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Phone number normalisation
# ─────────────────────────────────────────────────────────────────────────────

def normalise_phone(phone: str) -> tuple[bool, str]:
    """
    Normalise a US phone number to E.164 format (+1XXXXXXXXXX).

    Accepts:
        3865550101          10-digit bare
        13865550101         11-digit with leading 1
        (386) 555-0101      formatted
        +13865550101        already E.164

    Returns:
        (True, '+1XXXXXXXXXX')  on success
        (False, error_message)  if the number is not valid
    """
    digits = re.sub(r'\D', '', phone)
    if len(digits) == 11 and digits[0] == '1':
        digits = digits[1:]
    if len(digits) != 10:
        return False, (
            f"'{phone}' does not look like a valid 10-digit US number. "
            f"Pass digits only, e.g. '3865550101'."
        )
    return True, f'+1{digits}'


# ─────────────────────────────────────────────────────────────────────────────
# Base class
# ─────────────────────────────────────────────────────────────────────────────

class SMSBackend:
    """Abstract base for all SMS/WhatsApp providers."""

    provider_name: str = "base"

    def send(self, to: str, body: str) -> tuple[bool, str]:
        """
        Send an SMS (or WhatsApp message) to `to` with text `body`.

        Args:
            to:   Recipient phone number — any reasonable US format accepted;
                  normalise_phone() is called internally.
            body: Message text. Max 1600 chars for SMS; 4096 for WhatsApp.

        Returns:
            (True, confirmation_string)   on success
            (False, error_string)         on failure
        """
        raise NotImplementedError(f"{self.provider_name}.send() not implemented")

    def validate_config(self) -> tuple[bool, str]:
        """
        Check that all required credentials are present.

        Returns:
            (True, '')           if fully configured
            (False, hint_str)    if missing credentials — hint tells user
                                 which Settings fields to fill in
        """
        raise NotImplementedError(f"{self.provider_name}.validate_config() not implemented")


# ─────────────────────────────────────────────────────────────────────────────
# Twilio
# ─────────────────────────────────────────────────────────────────────────────

class TwilioBackend(SMSBackend):
    """
    Twilio SMS backend.
    Credentials: Account SID, Auth Token, From Number.
    Configure in Settings → SMS / Text Messaging (Twilio — Paid).
    """

    provider_name = "twilio"

    def __init__(self, account_sid: str, auth_token: str, from_number: str):
        self.account_sid  = (account_sid  or "").strip()
        self.auth_token   = (auth_token   or "").strip()
        self.from_number  = (from_number  or "").strip()

    def validate_config(self) -> tuple[bool, str]:
        missing = []
        if not self.account_sid:  missing.append("Account SID")
        if not self.auth_token:   missing.append("Auth Token")
        if not self.from_number:  missing.append("From Number")
        if missing:
            return False, (
                f"\u274c Twilio is not configured.\n\n"
                f"Missing: {', '.join(missing)}\n\n"
                f"Go to Settings \u2192 SMS / Text Messaging (Twilio \u2014 Paid), "
                f"enable it, and fill in your credentials."
            )
        return True, ""

    def send(self, to: str, body: str) -> tuple[bool, str]:
        ok, hint = self.validate_config()
        if not ok:
            return False, hint

        if not body or not body.strip():
            return False, "\u274c Message body is empty — nothing to send."

        ok_n, e164_or_err = normalise_phone(to)
        if not ok_n:
            return False, f"\u274c {e164_or_err}"

        try:
            import requests as _req
            resp = _req.post(
                f"https://api.twilio.com/2010-04-01/Accounts/"
                f"{self.account_sid}/Messages.json",
                auth=(self.account_sid, self.auth_token),
                data={
                    "From": self.from_number,
                    "To":   e164_or_err,
                    "Body": body,
                },
                timeout=15,
            )
        except Exception as exc:
            return False, f"\u274c Twilio request failed: {exc}"

        if resp.status_code in (200, 201):
            try:
                sid = resp.json().get("sid", "")
                return True, f"\u2705 SMS sent to {e164_or_err}  (SID: {sid})"
            except Exception:
                return True, f"\u2705 SMS sent to {e164_or_err}"

        try:
            err = resp.json()
            msg = err.get("message", resp.text[:200])
        except Exception:
            msg = resp.text[:200]
        return False, f"\u274c Twilio error {resp.status_code}: {msg}"


# ─────────────────────────────────────────────────────────────────────────────
# SignalWire  (Twilio-compatible API)
# ─────────────────────────────────────────────────────────────────────────────

class SignalWireBackend(SMSBackend):
    """
    SignalWire SMS backend.
    API is Twilio-compatible — same REST pattern, different base URL and auth.

    Credentials:
        Project ID  (like Twilio Account SID)
        Auth Token  (same concept)
        Space URL   (e.g. example.signalwire.com)
        From Number (+1XXXXXXXXXX)

    Configure in Settings → SMS / Text Messaging → Provider: SignalWire.
    Pricing typically 30-50% cheaper than Twilio for SMS.
    """

    provider_name = "signalwire"

    def __init__(self, project_id: str, auth_token: str,
                 space_url: str, from_number: str):
        self.project_id  = (project_id  or "").strip()
        self.auth_token  = (auth_token  or "").strip()
        self.space_url   = (space_url   or "").strip().rstrip("/")
        self.from_number = (from_number or "").strip()

    def validate_config(self) -> tuple[bool, str]:
        missing = []
        if not self.project_id:  missing.append("Project ID")
        if not self.auth_token:  missing.append("Auth Token")
        if not self.space_url:   missing.append("Space URL")
        if not self.from_number: missing.append("From Number")
        if missing:
            return False, (
                f"\u274c SignalWire is not configured.\n\n"
                f"Missing: {', '.join(missing)}\n\n"
                f"Go to Settings \u2192 SMS / Text Messaging \u2192 Provider: SignalWire."
            )
        return True, ""

    def send(self, to: str, body: str) -> tuple[bool, str]:
        ok, hint = self.validate_config()
        if not ok:
            return False, hint

        if not body or not body.strip():
            return False, "\u274c Message body is empty — nothing to send."

        ok_n, e164_or_err = normalise_phone(to)
        if not ok_n:
            return False, f"\u274c {e164_or_err}"

        # Ensure space_url has no scheme — build the full URL ourselves
        space = self.space_url.replace("https://", "").replace("http://", "")
        url   = f"https://{space}/api/laml/2010-04-01/Accounts/{self.project_id}/Messages.json"

        try:
            import requests as _req
            resp = _req.post(
                url,
                auth=(self.project_id, self.auth_token),
                data={
                    "From": self.from_number,
                    "To":   e164_or_err,
                    "Body": body,
                },
                timeout=15,
            )
        except Exception as exc:
            return False, f"\u274c SignalWire request failed: {exc}"

        if resp.status_code in (200, 201):
            try:
                sid = resp.json().get("sid", "")
                return True, f"\u2705 SMS sent to {e164_or_err}  (SID: {sid})"
            except Exception:
                return True, f"\u2705 SMS sent to {e164_or_err}"

        try:
            err = resp.json()
            msg = err.get("message", resp.text[:200])
        except Exception:
            msg = resp.text[:200]
        return False, f"\u274c SignalWire error {resp.status_code}: {msg}"


# ─────────────────────────────────────────────────────────────────────────────
# Vonage / Nexmo
# ─────────────────────────────────────────────────────────────────────────────

class VonageBackend(SMSBackend):
    """
    Vonage (formerly Nexmo) SMS backend.
    Uses a different auth model (api_key + api_secret in the POST body)
    and a different base URL, but the same REST concept.

    Credentials:
        API Key     (8-digit key from Vonage dashboard)
        API Secret  (16-char secret)
        From Number (phone number or alphanumeric sender ID, e.g. 'AIProwler')

    Configure in Settings → SMS / Text Messaging → Provider: Vonage.
    Good for international SMS.
    """

    provider_name = "vonage"
    _API_URL = "https://rest.nexmo.com/sms/json"

    def __init__(self, api_key: str, api_secret: str, from_number: str):
        self.api_key     = (api_key     or "").strip()
        self.api_secret  = (api_secret  or "").strip()
        self.from_number = (from_number or "").strip()

    def validate_config(self) -> tuple[bool, str]:
        missing = []
        if not self.api_key:     missing.append("API Key")
        if not self.api_secret:  missing.append("API Secret")
        if not self.from_number: missing.append("From Number")
        if missing:
            return False, (
                f"\u274c Vonage is not configured.\n\n"
                f"Missing: {', '.join(missing)}\n\n"
                f"Go to Settings \u2192 SMS / Text Messaging \u2192 Provider: Vonage."
            )
        return True, ""

    def send(self, to: str, body: str) -> tuple[bool, str]:
        ok, hint = self.validate_config()
        if not ok:
            return False, hint

        if not body or not body.strip():
            return False, "\u274c Message body is empty — nothing to send."

        # Vonage accepts international format without +; normalise if US number
        ok_n, e164_or_err = normalise_phone(to)
        # Vonage wants digits only for US numbers (no + prefix)
        to_vonage = e164_or_err.lstrip('+') if ok_n else re.sub(r'\D', '', to)
        if not to_vonage:
            return False, f"\u274c Invalid phone number: {to}"

        try:
            import requests as _req
            resp = _req.post(
                self._API_URL,
                data={
                    "api_key":    self.api_key,
                    "api_secret": self.api_secret,
                    "from":       self.from_number,
                    "to":         to_vonage,
                    "text":       body,
                },
                timeout=15,
            )
        except Exception as exc:
            return False, f"\u274c Vonage request failed: {exc}"

        try:
            data = resp.json()
            msgs = data.get("messages", [{}])
            status = str(msgs[0].get("status", ""))
            if status == "0":
                msg_id = msgs[0].get("message-id", "")
                return True, f"\u2705 SMS sent to +{to_vonage}  (ID: {msg_id})"
            err_text = msgs[0].get("error-text", f"Status {status}")
            return False, f"\u274c Vonage error: {err_text}"
        except Exception as exc:
            return False, f"\u274c Vonage response parse error: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# WhatsApp via Twilio
# ─────────────────────────────────────────────────────────────────────────────

class WhatsAppBackend(SMSBackend):
    """
    WhatsApp Business API via Twilio.
    Uses the exact same Twilio credentials as TwilioBackend — the only
    difference is that phone numbers are prefixed with 'whatsapp:'.

    Requirements:
        • Twilio account with WhatsApp sandbox or approved WhatsApp Business number
        • Same Account SID / Auth Token / From Number as Twilio SMS
        • From Number must be registered in Twilio WhatsApp console

    Configure in Settings → SMS / Text Messaging → Twilio → Enable WhatsApp.
    Works worldwide, no carrier gateway issues, supports media messages.
    """

    provider_name = "whatsapp"
    _WA_PREFIX = "whatsapp:"

    def __init__(self, account_sid: str, auth_token: str, from_number: str):
        self._twilio = TwilioBackend(account_sid, auth_token, from_number)
        # Ensure from_number has the whatsapp: prefix
        fn = (from_number or "").strip()
        if not fn.startswith(self._WA_PREFIX):
            fn = self._WA_PREFIX + fn
        self.from_number = fn

    def validate_config(self) -> tuple[bool, str]:
        ok, msg = self._twilio.validate_config()
        if not ok:
            return False, msg.replace("Twilio", "WhatsApp via Twilio")
        return True, ""

    def send(self, to: str, body: str) -> tuple[bool, str]:
        ok, hint = self.validate_config()
        if not ok:
            return False, hint

        if not body or not body.strip():
            return False, "\u274c Message body is empty — nothing to send."

        ok_n, e164_or_err = normalise_phone(to)
        if not ok_n:
            return False, f"\u274c {e164_or_err}"

        # Prefix both From and To with 'whatsapp:'
        wa_to   = self._WA_PREFIX + e164_or_err
        wa_from = self.from_number  # already prefixed in __init__

        try:
            import requests as _req
            resp = _req.post(
                f"https://api.twilio.com/2010-04-01/Accounts/"
                f"{self._twilio.account_sid}/Messages.json",
                auth=(self._twilio.account_sid, self._twilio.auth_token),
                data={
                    "From": wa_from,
                    "To":   wa_to,
                    "Body": body,
                },
                timeout=15,
            )
        except Exception as exc:
            return False, f"\u274c WhatsApp request failed: {exc}"

        if resp.status_code in (200, 201):
            try:
                sid = resp.json().get("sid", "")
                return True, f"\u2705 WhatsApp message sent to {e164_or_err}  (SID: {sid})"
            except Exception:
                return True, f"\u2705 WhatsApp message sent to {e164_or_err}"

        try:
            err = resp.json()
            msg = err.get("message", resp.text[:200])
        except Exception:
            msg = resp.text[:200]
        return False, f"\u274c WhatsApp error {resp.status_code}: {msg}"


# ─────────────────────────────────────────────────────────────────────────────
# Factory functions
# ─────────────────────────────────────────────────────────────────────────────

def get_sms_backend(config: dict) -> SMSBackend:
    """
    Return the appropriate SMSBackend instance for the given config dict.

    The config dict is typically loaded from ~/.ai-prowler/config.json.
    The 'sms_provider' key selects the backend:
        'twilio'      → TwilioBackend      (default if key absent)
        'signalwire'  → SignalWireBackend
        'vonage'      → VonageBackend

    For WhatsApp, use get_whatsapp_backend() instead.

    Returns an SMSBackend whose validate_config() will return (False, hint)
    if credentials are missing — callers don't need to check config themselves.
    """
    provider = str(config.get("sms_provider", "twilio")).strip().lower()

    if provider in ("twilio", ""):
        return TwilioBackend(
            account_sid  = config.get("twilio_account_sid",  ""),
            auth_token   = config.get("twilio_auth_token",   ""),
            from_number  = config.get("twilio_from_number",  ""),
        )

    if provider == "signalwire":
        return SignalWireBackend(
            project_id  = config.get("signalwire_project_id",  ""),
            auth_token  = config.get("signalwire_auth_token",  ""),
            space_url   = config.get("signalwire_space_url",   ""),
            from_number = config.get("signalwire_from_number", ""),
        )

    if provider == "vonage":
        return VonageBackend(
            api_key     = config.get("vonage_api_key",     ""),
            api_secret  = config.get("vonage_api_secret",  ""),
            from_number = config.get("vonage_from_number", ""),
        )

    # Unknown provider — return a stub that always fails with a clear message
    class _UnknownBackend(SMSBackend):
        provider_name = provider
        def validate_config(self): return False, f"\u274c Unknown SMS provider: '{provider}'"
        def send(self, to, body):  return False, f"\u274c Unknown SMS provider: '{provider}'"
    return _UnknownBackend()


def get_whatsapp_backend(config: dict) -> WhatsAppBackend:
    """
    Return a WhatsAppBackend using Twilio credentials from config.
    WhatsApp always uses Twilio — there is no separate WhatsApp provider key.
    """
    return WhatsAppBackend(
        account_sid  = config.get("twilio_account_sid",  ""),
        auth_token   = config.get("twilio_auth_token",   ""),
        from_number  = config.get("twilio_from_number",  ""),
    )


def load_sms_config() -> dict:
    """
    Load SMS/messaging config from ~/.ai-prowler/config.json.
    Returns {} if the file doesn't exist or can't be parsed.
    """
    import json
    cfg_path = Path.home() / ".ai-prowler" / "config.json"
    if not cfg_path.exists():
        return {}
    try:
        return json.loads(cfg_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
