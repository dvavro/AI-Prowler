"""service_link.py — the "request service" link on invoices and receipts (2026-10-29).

Run: run_tests.bat tests\\unit\\test_service_link.py
"""
import re
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import service_link as sl  # noqa: E402

BASE = "https://acme.example.com"


@pytest.fixture
def db(tmp_path):
    p = tmp_path / "jobs.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, notes TEXT, "
              "last_edited_by TEXT, last_edited_at TEXT)")
    c.commit(); c.close()
    return str(p)


def put(db, **rows):
    c = sqlite3.connect(db)
    for k, v in rows.items():
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))
    c.commit(); c.close()


ALL = [("invoice", "email"), ("receipt", "email"), ("invoice", "sms"), ("receipt", "sms")]


# ── what the setting stands for ──────────────────────────────────────────────
@pytest.mark.parametrize("value,base,desk_on,want", [
    ("", BASE, True, ""),                                          # blank = off (the default)
    ("auto", BASE, True, BASE + "/support/new"),
    ("AUTO", "acme.example.com/", True, BASE + "/support/new"),
    ("auto", "", True, ""),                                        # no Remote Access yet
    ("auto", BASE, False, ""),                                     # Service Desk / its form off
    ("https://mysite.com/contact", "", False, "https://mysite.com/contact"),
    ("http://mysite.com/contact", "", True, "http://mysite.com/contact"),
    ("mysite.com/contact", BASE, True, ""),                        # not a web link
    ("javascript:alert(1)", BASE, True, ""),
    ("https://a b.com", BASE, True, ""),
])
def test_resolve_url(value, base, desk_on, want):
    assert sl.resolve_url(value, base, desk_on) == want


def test_nothing_set_means_no_link_anywhere(db):
    for doc, ch in ALL:
        assert sl.link_for(db, doc, ch, base_url=BASE) == ("", "")


def test_set_link_goes_on_all_four_by_default(db):
    put(db, **{"Service Request Link": "auto"})
    for doc, ch in ALL:
        assert sl.link_for(db, doc, ch, base_url=BASE) == (BASE + "/support/new", sl.DEFAULT_TEXT)


@pytest.mark.parametrize("doc,ch", ALL)
def test_each_message_can_be_switched_off_on_its_own(db, doc, ch):
    put(db, **{"Service Request Link": "https://mysite.com/help", sl.SWITCH_KEYS[(doc, ch)]: "No"})
    for d2, c2 in ALL:
        url, _ = sl.link_for(db, d2, c2)
        assert (url == "") == ((d2, c2) == (doc, ch)), (d2, c2)


def test_custom_wording(db):
    put(db, **{"Service Request Link": "https://mysite.com/help",
               "Service Request Link Text": "Book your next cleaning:"})
    assert sl.link_for(db, "receipt", "sms") == ("https://mysite.com/help", "Book your next cleaning:")


def test_unreadable_database_means_no_link(tmp_path):
    assert sl.link_for(str(tmp_path / "missing.db"), "invoice", "email", base_url=BASE) == ("", "")


# ── how it looks ─────────────────────────────────────────────────────────────
def test_html_block_is_escaped_and_goes_before_body_end():
    page = "<html><body><p>Invoice</p></body></html>"
    out = sl.add_to_html(page, 'https://x.com/?a=1&b="2"', "Need <help>?")
    assert out.index("x.com") < out.index("</body>")
    assert "&amp;b=&quot;2&quot;" in out and "Need &lt;help&gt;?" in out and "<help>" not in out


def test_no_url_changes_nothing():
    assert sl.add_to_html("<body></body>", "", "x") == "<body></body>"
    assert sl.text_line("", "x") == ""


def test_text_line():
    assert sl.text_line("https://x.com", "") == " " + sl.DEFAULT_TEXT + " https://x.com"


# ── the Jobs app Settings screen lists the same keys ──────────────────────────
def test_jobs_app_settings_list_matches():
    html = (ROOT / "jobs" / "index.html").read_text(encoding="utf-8")
    block = re.search(r"var SERVICE_LINK_SETTINGS = \[(.*?)\];", html, re.S)
    assert block, "SERVICE_LINK_SETTINGS missing from jobs/index.html"
    keys = re.findall(r"setting: '([^']+)'", block.group(1))
    assert keys == [sl.URL_KEY, sl.TEXT_KEY, *sl.SWITCH_KEYS.values()]
    assert f"dflt: '{sl.DEFAULT_TEXT}'" in block.group(1)


# ── all four send tools use it, for the right message ─────────────────────────
@pytest.mark.parametrize("tool,doc,ch", [("email_invoice", "invoice", "email"),
                                         ("email_receipt", "receipt", "email"),
                                         ("text_invoice", "invoice", "sms"),
                                         ("text_receipt", "receipt", "sms")])
def test_send_tools_call_it(tool, doc, ch):
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    body = src.split(f"\ndef {tool}(", 1)[1].split("\n@mcp.tool()", 1)[0]
    assert f'"{doc}", "{ch}")' in body and "_service_link(" in body, tool
