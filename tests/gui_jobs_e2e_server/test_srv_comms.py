"""Server mode — email & SMS (spec §4.3 comms tier, §6.11 SRV-COMMS).

David's decision 2026-09-27: real email and SMS may go ONLY to David Vavro
and Vicki Vavro. The write guard enforces it:
  • safe tier (normal regression)  — nothing is sent; every send is recorded
  • comms tier (--tier comms)       — send_email / send_alert / send_sms to David
    or Vicki really go out (max 2 emails + 2 texts per run); any other
    recipient, or any tool that looks its recipient up server-side, stays recorded

Run (safe, sends nothing):    run_tests_gui_jobs_e2e.bat --server --human -k test_srv_comms
Run (REAL email + text):      run_tests_gui_jobs_e2e.bat --server --human --tier comms -k test_srv_comms
"""
import os

import pytest
from playwright.sync_api import expect

COMMS = os.environ.get("E2E_TIER", "safe") == "comms"
comms_only = pytest.mark.skipif(not COMMS, reason="real sends only with --tier comms")
NOT_SENT = "[E2E guard — not sent]"


def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


# ── SRV-COMMS-01: safe tier — nothing leaves ──────────────────────────────────
@pytest.mark.skipif(COMMS, reason="safe-tier check; in the comms tier these would really send")
def test_SRV_COMMS_01_safe_tier_sends_nothing(windows):
    (david,) = windows("U1")
    david.log_in()
    _signed_in(david)
    for tool, args in (("send_email", {"to": "Vicki Vavro", "subject": "ZTEST E2E", "body": "not sent"}),
                       ("send_sms", {"to": "Vicki Vavro", "message": "ZTEST E2E not sent"})):
        res = david.app.mcp(tool, args)
        assert NOT_SENT in str(res), f"{tool} wasn't stopped by the guard in the safe tier: {res!r}"


# ── SRV-COMMS-02: real email, the way the app sends one ──────────────────────
# The Jobs app's server connection doesn't offer send_email ("Unknown tool") —
# the app emails through its features. So: a ZTEST job + invoice (owner), then
# David emails the payment receipt for it to VICKI's address (explicit `to`).
def _comms_address(who: str) -> str:
    from safety import Guard
    raw = os.environ.get("AIPROWLER_E2E_COMMS_TO", "")
    if not raw:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            raw = str(winreg.QueryValueEx(k, "AIPROWLER_E2E_COMMS_TO")[0])
    for x in raw.split(","):
        if "@" in x and who in x.lower():
            return x.strip()
    pytest.skip(f"no {who} email address in AIPROWLER_E2E_COMMS_TO")


@comms_only
def test_SRV_COMMS_02_real_email_receipt_to_vicki(windows, data, owner_api, clean_slate):
    import re
    to = _comms_address("vicki")
    jid = data.job("COMMS receipt", **{"Quote Amount ($)": 1})
    out = owner_api.call("create_invoice", {"job_identifier": jid, "quote_amount": 1, "discount": 0, "tax_rate": 0})
    inv = re.search(r"INV-\d+", out).group(0)
    (david,) = windows("U1")
    david.log_in()
    _signed_in(david)
    res = david.app.mcp("email_receipt", {"invoice_identifier": inv, "payment_method": "Cash", "to": to})
    assert NOT_SENT not in str(res), f"guard stopped an allowed send: {res!r}"
    assert str(res).lstrip().startswith("✅"), f"server didn't send the receipt email: {res!r}"
    assert to.lower() in str(res).lower(), f"reply doesn't name Vicki's address: {res!r}"


# ── SRV-COMMS-03: real text Vicki → David ─────────────────────────────────────
@comms_only
def test_SRV_COMMS_03_real_sms_vicki_to_david(windows):
    (vicki,) = windows("U2")
    vicki.log_in()
    _signed_in(vicki)
    res = vicki.app.mcp("send_sms", {"to": "David Vavro",
                                     "message": "AI-Prowler E2E test text (SRV-COMMS-03): Vicki -> David."})
    assert NOT_SENT not in str(res), f"guard stopped an allowed send: {res!r}"
    assert str(res).lstrip().startswith("✅"), f"server didn't send the text: {res!r}"


# ── SRV-COMMS-04: comms tier still refuses anyone else ────────────────────────
@comms_only
def test_SRV_COMMS_04_comms_tier_blocks_other_recipients(windows):
    (david,) = windows("U1")
    david.log_in()
    _signed_in(david)
    for tool, args in (("send_sms", {"to": "Samual Cronin", "message": "ZTEST E2E must not send"}),
                       ("send_email", {"to": "someone@example.com", "subject": "ZTEST", "body": "must not send"}),
                       ("email_invoice", {"invoice_identifier": "INV-0001"})):
        res = david.app.mcp(tool, args)
        assert NOT_SENT in str(res), f"{tool} to a non-allowed recipient wasn't stopped: {res!r}"
