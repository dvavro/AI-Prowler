"""
tests/mcp_tests/test_lookup_customer_email_openpyxl_removal.py
============================================================
Second, separate bug found while porting email_invoice()/text_invoice()/
email_receipt()/text_receipt() off openpyxl: send_email()/send_alert()'s
own customer-lookup helper, _lookup_customer_email(name_or_id), was
STILL fully openpyxl-based (opened the old .xlsx directly via
_get_default_spreadsheet_path()) — same disease, different tool, and a
distinct function from _lookup_invoice_customer_email (a name collision
was found and fixed along the way: this one and the new invoice-tools
helper briefly shared a name, with the later definition silently
shadowing the earlier one at module load).

This tests the fix: _lookup_customer_email() is now DB-backed AND newly
ctx-aware (previously always read the single shared default spreadsheet
path regardless of who was asking — now resolves the CALLING crew
member's own per-user database in server mode via
_resolve_job_db_path(ctx, ...), same as every other ported tool this
session).

Run with:
    run_tests.bat tests\\mcp\\test_lookup_customer_email_openpyxl_removal.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _owner(uid="dave"):
    return {"id": uid, "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}


@pytest.fixture
def personal_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"  # deliberately never created
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    return tmp_path / "ai_prowler_jobs.db"


def test_never_touches_the_old_xlsx_file(personal_env, mcp_mod):
    """The .xlsx is never created anywhere in this test — proves this no
    longer depends on openpyxl/the old file at all."""
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe", "Email": "jane@example.com"},
                             filepath="", backup=False, ctx=None)
    email = mcp_mod._lookup_customer_email("Blue Wave Cafe", ctx=None)
    assert email == "jane@example.com"


def test_matches_by_exact_customer_id(personal_env, mcp_mod):
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe", "Email": "jane@example.com"},
                             filepath="", backup=False, ctx=None)
    email = mcp_mod._lookup_customer_email("CUST-0001", ctx=None)
    assert email == "jane@example.com"


def test_matches_by_partial_company_name(personal_env, mcp_mod):
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe", "Email": "jane@example.com"},
                             filepath="", backup=False, ctx=None)
    email = mcp_mod._lookup_customer_email("blue wave", ctx=None)
    assert email == "jane@example.com"


def test_matches_by_first_name(personal_env, mcp_mod):
    mcp_mod.create_customer({"First Name": "Karen", "Last Name": "Walsh", "Email": "karen@example.com"},
                             filepath="", backup=False, ctx=None)
    email = mcp_mod._lookup_customer_email("Karen", ctx=None)
    assert email == "karen@example.com"


def test_matches_by_phone(personal_env, mcp_mod):
    mcp_mod.create_customer({"Company Name": "X", "Phone": "386-555-0101", "Email": "x@example.com"},
                             filepath="", backup=False, ctx=None)
    email = mcp_mod._lookup_customer_email("386-555-0101", ctx=None)
    assert email == "x@example.com"


def test_no_match_returns_none(personal_env, mcp_mod):
    mcp_mod.create_customer({"Company Name": "X", "Email": "x@example.com"},
                             filepath="", backup=False, ctx=None)
    email = mcp_mod._lookup_customer_email("Nobody Here", ctx=None)
    assert email is None


def test_customer_with_blank_email_not_returned(personal_env, mcp_mod):
    mcp_mod.create_customer({"Company Name": "No Email LLC"}, filepath="", backup=False, ctx=None)
    email = mcp_mod._lookup_customer_email("No Email LLC", ctx=None)
    assert email is None


def test_blank_query_returns_none(personal_env, mcp_mod):
    mcp_mod.create_customer({"Company Name": "X", "Email": "x@example.com"},
                             filepath="", backup=False, ctx=None)
    assert mcp_mod._lookup_customer_email("   ", ctx=None) is None


def test_default_ctx_none_still_works_for_backward_compatibility(personal_env, mcp_mod):
    """Callers that don't pass ctx at all (old call sites, or any other
    future caller) must keep working exactly as before."""
    mcp_mod.create_customer({"Company Name": "X", "Email": "x@example.com"},
                             filepath="", backup=False, ctx=None)
    email = mcp_mod._lookup_customer_email("X")  # no ctx kwarg at all
    assert email == "x@example.com"


# ══════════════════════════════════════════════════════════════════════════
# End-to-end through send_email/send_alert's own name→email resolution
# ══════════════════════════════════════════════════════════════════════════

def test_send_email_resolves_customer_name_to_real_email(personal_env, mcp_mod, monkeypatch):
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe", "Email": "jane@example.com"},
                             filepath="", backup=False, ctx=None)
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: {"configured": True})
    sent = {}
    def _fake_send_smtp(to, subject, body, **kwargs):
        sent["to"] = to
        return True, "ok"
    monkeypatch.setattr(mcp_mod, "_send_smtp", _fake_send_smtp)

    result = mcp_mod.send_email(to="Blue Wave Cafe", subject="Hi", body="Test", ctx=None)
    assert sent.get("to") == "jane@example.com", result


# ══════════════════════════════════════════════════════════════════════════
# Server mode — correct per-user database resolution
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path / "ai_prowler_jobs.db"


def test_server_mode_finds_customer_via_ctx_resolved_path(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: owner)
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe", "Email": "jane@example.com"},
                             filepath="", backup=False, ctx=_make_ctx(owner))

    email = mcp_mod._lookup_customer_email("Blue Wave Cafe", ctx=_make_ctx(owner))
    assert email == "jane@example.com"


def test_server_mode_ignores_filepath_and_still_resolves_correctly(server_env, monkeypatch, mcp_mod, tmp_path):
    owner = _owner()
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: owner)
    mcp_mod.create_customer({"Company Name": "Real Co", "Email": "real@example.com"},
                             filepath="", backup=False, ctx=_make_ctx(owner))

    # No filepath argument on this function at all anymore — ctx alone
    # must resolve to the correct (server-mode master) database.
    email = mcp_mod._lookup_customer_email("Real Co", ctx=_make_ctx(owner))
    assert email == "real@example.com"
