"""service_link.py — the "request service" link on invoices and receipts (2026-10-29, David).

David 2026-10-29: "add that URL to the customer in the Jobs App (programmable in
the jobs app settings) to include the URL in the receipt/invoice" … "make the
URL configurable sending for text and email and invoice and receipt".

Set in the Jobs app → Database → Settings (the same settings table the invoice
already reads for Business Name, Website, …):

  Service Request Link          blank  = off (nothing changes — the default)
                                auto   = this install's Service Desk request
                                         page, https://<tunnel>/support/new
                                any http(s):// URL = that page (e.g. your own
                                         website's contact form)
  Service Request Link Text     optional wording before the link
                                (default "Need anything else? Request service here:")
  Service Link - Email Invoice  Yes / No   ┐
  Service Link - Email Receipt  Yes / No   │ which messages carry it;
  Service Link - Text Invoice   Yes / No   │ a missing or blank row = Yes
  Service Link - Text Receipt   Yes / No   ┘

email_invoice / email_receipt / text_invoice / text_receipt (ai_prowler_mcp.py)
call link_for() and add html_block() / text_line(). Nothing here sends anything
or raises: a problem reading a setting means "no link", never a failed send.
"""
from __future__ import annotations

import html
import sqlite3

URL_KEY = "Service Request Link"
TEXT_KEY = "Service Request Link Text"
DEFAULT_TEXT = "Need anything else? Request service here:"
SUPPORT_PATH = "/support/new"
AUTO = "auto"

# (document, channel) -> its Yes/No settings row
SWITCH_KEYS = {
    ("invoice", "email"): "Service Link - Email Invoice",
    ("receipt", "email"): "Service Link - Email Receipt",
    ("invoice", "sms"):   "Service Link - Text Invoice",
    ("receipt", "sms"):   "Service Link - Text Receipt",
}

# Shown in the Jobs app's Settings checklist (jobs/index.html REQUIRED_INVOICE_SETTINGS)
SETTING_NOTES = {
    URL_KEY: "Optional — 'auto' = your Service Desk request page (/support/new), or paste any "
             "http(s) link. Blank = off. Added to invoices and receipts.",
    TEXT_KEY: f"Optional — words before the link. Default: \"{DEFAULT_TEXT}\"",
}

_NO = {"no", "n", "false", "0", "off"}


def _settings(db_path: str, keys) -> dict:
    out = {}
    try:
        conn = sqlite3.connect(db_path)
        try:
            for k in keys:
                row = conn.execute("SELECT value FROM settings WHERE key = ?", (k,)).fetchone()
                if row and row[0] is not None:
                    out[k] = str(row[0]).strip()
        finally:
            conn.close()
    except Exception:
        pass
    return out


def resolve_url(value: str, base_url: str = "", desk_on: bool = True) -> str:
    """The link the setting stands for, or "" (off / unusable).
    'auto' needs Remote Access (a tunnel) and Service Desk switched on."""
    v = (value or "").strip()
    if not v:
        return ""
    if v.lower() == AUTO:
        base = (base_url or "").strip().rstrip("/")
        if not base or not desk_on:
            return ""
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        return base + SUPPORT_PATH
    if v.lower().startswith(("http://", "https://")) and " " not in v and len(v) <= 500:
        return v
    return ""                                   # not a web link — never put junk in a bill


def link_for(db_path: str, document: str, channel: str, *, base_url: str = "",
             desk_on: bool = True) -> tuple[str, str]:
    """(url, wording) for this message, or ("", "") when it shouldn't carry one.
    document: 'invoice' | 'receipt'; channel: 'email' | 'sms'."""
    switch = SWITCH_KEYS.get((document, channel))
    if not switch:
        return "", ""
    s = _settings(db_path, (URL_KEY, TEXT_KEY, switch))
    if s.get(switch, "").strip().lower() in _NO:
        return "", ""
    url = resolve_url(s.get(URL_KEY, ""), base_url, desk_on)
    if not url:
        return "", ""
    return url, (s.get(TEXT_KEY) or DEFAULT_TEXT).strip()


def html_block(url: str, wording: str) -> str:
    """A small centred block for the HTML email (inserted before </body>)."""
    if not url:
        return ""
    u, w = html.escape(url, quote=True), html.escape(wording or DEFAULT_TEXT)
    return ('<div style="padding:16px 32px;text-align:center;font-family:Arial,sans-serif;'
            'font-size:14px;color:#333;">'
            f'{w} <a href="{u}" style="color:#1a73e8;font-weight:bold;">{u}</a></div>')


def text_line(url: str, wording: str) -> str:
    """The same for a plain-text email body or an SMS (leading space included)."""
    return f" {(wording or DEFAULT_TEXT).strip()} {url}" if url else ""


def add_to_html(html_body: str, url: str, wording: str) -> str:
    block = html_block(url, wording)
    if not block:
        return html_body
    i = html_body.rfind("</body>")
    return html_body[:i] + block + html_body[i:] if i >= 0 else html_body + block
