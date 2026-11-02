"""The "request service" link in real invoice / receipt sends (2026-10-29).

Same set-up as test_invoice_receipt_openpyxl_removal.py: a real job and invoice
in a throwaway SQLite database, only the email / SMS send caught. The link
comes from the Jobs app Settings (service_link.py).

Run: run_tests.bat tests\\mcp_tests\\test_service_link_on_invoices.py
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

DOMAIN = "acme.example.com"
AUTO_URL = f"https://{DOMAIN}/support/new"


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(tmp_path / "never.xlsx"))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: {"configured": True})
    # this install: Remote Access on, Service Desk and its request form on
    import desk_db, desk_gui_links, desk_portal, setup_wizard
    monkeypatch.setattr(setup_wizard, "tunnel_domain", lambda: DOMAIN)
    monkeypatch.setattr(desk_gui_links, "desk_switched_on", lambda cfg=None: True)
    monkeypatch.setattr(desk_db, "get_settings", lambda db: {"portal_enabled": True})
    monkeypatch.setattr(desk_portal, "channels", lambda: {"email": True, "sms": True})
    sent = {}
    monkeypatch.setattr(mcp_mod, "_send_smtp",
                        lambda to, subject, body, body_html=None: (sent.update(body=body, html=body_html) or (True, "ok")))
    monkeypatch.setattr(mcp_mod, "send_sms",
                        lambda to, message, ctx=None: (sent.update(sms=message) or "✅ sent"))
    c = mcp_mod.create_customer({"Company Name": "Blue Wave Cafe", "Email": "jane@example.com"},
                                filepath="", backup=False, ctx=None)
    cust = c.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    j = mcp_mod.create_job({"Customer Name / Company": "Blue Wave Cafe", "CustomerID (Customers!A)": cust,
                            "Quote Amount ($)": 150.0}, filepath="", backup=False, ctx=None)
    job = j.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    inv = mcp_mod.create_invoice(job, filepath="", backup=False, ctx=None)
    inv = inv.split("NEW_INVOICE_ID=")[1].splitlines()[0].strip()
    return {"db": tmp_path / "ai_prowler_jobs.db", "inv": inv, "sent": sent, "mod": mcp_mod}


def settings(env, **rows):
    c = sqlite3.connect(env["db"])
    for k, v in rows.items():
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))
    c.commit(); c.close()


def send(env, tool):
    m, inv = env["mod"], env["inv"]
    env["sent"].clear()
    r = {"email_invoice": lambda: m.email_invoice(inv, filepath="", ctx=None),
         "email_receipt": lambda: m.email_receipt(inv, payment_method="Cash", filepath="", ctx=None),
         "text_invoice":  lambda: m.text_invoice(inv, filepath="", ctx=None),
         "text_receipt":  lambda: m.text_receipt(inv, payment_method="Check", filepath="", ctx=None)}[tool]()
    assert r.startswith("✅"), r
    s = env["sent"]
    return (s.get("html") or "") + "\n" + (s.get("body") or "") + "\n" + (s.get("sms") or "")


TOOLS = ["email_invoice", "email_receipt", "text_invoice", "text_receipt"]


@pytest.mark.parametrize("tool", TOOLS)
def test_no_setting_no_link(env, tool):
    out = send(env, tool)
    assert "/support/new" not in out and "Request service" not in out


@pytest.mark.parametrize("tool", TOOLS)
def test_auto_puts_the_request_form_link_on_it(env, tool):
    settings(env, **{"Service Request Link": "auto"})
    out = send(env, tool)
    assert AUTO_URL in out and "Request service here:" in out
    if tool.startswith("email"):
        assert f'href="{AUTO_URL}"' in env["sent"]["html"] and AUTO_URL in env["sent"]["body"]


def test_own_link_and_wording_and_a_switch(env):
    settings(env, **{"Service Request Link": "https://bluewavewash.com/book",
                     "Service Request Link Text": "Book your next wash:",
                     "Service Link - Text Receipt": "No"})
    assert "Book your next wash: https://bluewavewash.com/book" in send(env, "text_invoice")
    assert "bluewavewash.com" not in send(env, "text_receipt")
    assert "bluewavewash.com/book" in send(env, "email_receipt")


def test_auto_without_remote_access_adds_nothing(env, monkeypatch):
    import setup_wizard
    monkeypatch.setattr(setup_wizard, "tunnel_domain", lambda: "")
    settings(env, **{"Service Request Link": "auto"})
    assert "/support/new" not in send(env, "email_invoice")
