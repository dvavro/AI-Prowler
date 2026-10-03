"""
R-068 (David 2026-09-29: "In the server mode, we need AR report aging report
to be visible by the owner And manager").

- get_ar_aging_report: owner + manager allowed; staff / field_crew refused
  (it had NO role check before — any signed-in server user could read every
  customer's balance). Personal mode unrestricted.
- the Jobs app's /pwa-api allow-lists (server + personal) include it.
- the Jobs app: Reports tab shown to owner AND manager; an AR Aging card at the
  top; everything else on Reports stays owner-only.

Run:  run_tests.bat tests\\mcp\\test_r068_ar_aging_owner_manager.py -v
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

import ai_prowler_mcp as mcp_mod
from db_access import init_db
from db_write_ops import db_create_customer, db_create_invoice, db_create_job

SRC = Path(mcp_mod.__file__).resolve().parent


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    p = str(tmp_path / "jobs.db")
    init_db(p)
    cid = db_create_customer(p, {"Company Name": "Owes Co"}, actor="t").split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    db_create_job(p, {"CustomerID (Customers!A)": cid, "Customer Name / Company": "Owes Co",
                      "Quote Amount ($)": 95}, actor="t")
    db_create_invoice(p, "JOB-0001", actor="t", due_days=30)
    conn = sqlite3.connect(p)
    conn.execute("UPDATE invoices SET due_date = '2026-01-01'")
    conn.commit()
    conn.close()
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, fp="": p)
    return p


def _as(monkeypatch, role):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: {"name": f"T {role}", "role": role})


@pytest.mark.parametrize("role", ["owner", "manager"])
def test_owner_and_manager_see_the_ar_aging_report(db_path, monkeypatch, role):
    _as(monkeypatch, role)
    out = mcp_mod.get_ar_aging_report(as_of_date="2026-02-15", ctx=None)
    assert not out.startswith("❌"), out[:200]
    assert "AR AGING REPORT" in out and "Owes Co" in out and "31 – 60 days overdue" in out


@pytest.mark.parametrize("role", ["staff", "field_crew", "someone_else"])
def test_everyone_else_is_refused(db_path, monkeypatch, role):
    _as(monkeypatch, role)
    out = mcp_mod.get_ar_aging_report(as_of_date="2026-02-15", ctx=None)
    assert out.startswith("❌") and "owner and managers" in out
    assert "Owes Co" not in out


def test_personal_mode_unrestricted(db_path, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    out = mcp_mod.get_ar_aging_report(as_of_date="2026-02-15", ctx=None)
    assert "Owes Co" in out


def test_both_jobs_api_allow_lists_include_it():
    src = (SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert src.count('"get_ar_aging_report",') >= 2, "get_ar_aging_report missing from a /pwa-api allow-list"
    srv = src[src.index("_srv_pa_allowed = {"):]
    srv = srv[:srv.index("}")]
    assert '"get_ar_aging_report"' in srv, "not in the SERVER /pwa-api allow-list"


def test_jobs_app_reports_tab_for_owner_and_manager_only_ar_for_manager():
    html = (SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    assert 'id="arAgingCard"' in html and 'id="reportsOwnerOnly"' in html
    assert "mcpCall('get_ar_aging_report'" in html
    # the tab: owner or manager in server mode
    m = re.search(r"navReports\.style\.display\s*=\s*\(([^;]+)\)\s*\?", html)
    assert m and "'owner'" in m.group(1) and "'manager'" in m.group(1), m.group(0) if m else "no navReports rule"
    # the AR card sits OUTSIDE the owner-only block; the owner-only block hides for non-owners
    assert html.index('id="arAgingCard"') < html.index('id="reportsOwnerOnly"')
    lr = html[html.index("async function loadReports()"):]
    lr = lr[:lr.index("var el = document.getElementById('reportsContent')")]
    assert "loadArAging()" in lr and "_ownerView" in lr and "if (!_ownerView) return;" in lr
    assert "_show('arAgingCard', _arView)" in lr and "_arView = _ownerView || _role === 'manager'" in lr


def test_r069_jobs_app_customer_reminders_for_owner_manager_staff():
    """R-069 (David 2026-09-29): Customer Reminders visible to owner, managers
    and staff; the send controls only to the owner; charts owner-only."""
    html = (SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"navReports\.style\.display\s*=\s*\(([^;]+)\)\s*\?", html)
    assert m and all(f"'{r}'" in m.group(1) for r in ("owner", "manager", "staff"))
    assert "'field_crew'" not in m.group(1)
    # the reminders card is OUTSIDE the owner-only block
    oo_start = html.index('id="reportsOwnerOnly"')
    oo_end = html.index("</div><!-- /reportsOwnerOnly -->")
    card = html.index('id="customerRemindersCard"')
    assert not (oo_start < card < oo_end), "Customer Reminders is still inside the owner-only block"
    lr = html[html.index("async function loadReports()"):]
    lr = lr[:lr.index("var el = document.getElementById('reportsContent')")]
    assert "_remView = _arView || _role === 'staff'" in lr
    assert "_show('customerRemindersCard', _remView)" in lr and "_show('staleCustomerMessageBox', _ownerView)" in lr
    fs = html[html.index("async function findStaleCustomers()"):]
    fs = fs[:fs.index("async function sendStaleCustomerReminders")]
    i_guard = fs.index("_reportsRole() !== 'owner'")
    assert i_guard < fs.index("stale-cust-check"), "non-owners must return before the send checkboxes/buttons are drawn"
