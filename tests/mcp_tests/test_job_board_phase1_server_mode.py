"""
tests/mcp_tests/test_job_board_phase1_server_mode.py
==================================================
Job Board Architecture Spec — Phase 1 (spec §5, §11).

Server-mode coverage for the six write tools wired to db_write_ops this
phase (create_job, create_customer, create_quote, create_invoice,
log_time_entry, update_job_spreadsheet). Complements
test_job_board_phase1_mcp_wiring.py, which is personal-mode only
(ctx=None) by design, and test_db_write_ops_phase1.py, which already
exhaustively covers the crew-scoping allow/deny matrix at the
db_write_ops layer directly (restrict=True/crew_name passed in as plain
arguments).

What THIS file proves that those two don't: that the real @mcp.tool()
functions, called with a genuine server-mode ctx, correctly derive
restrict/crew_name via _job_crew_scope(ctx, db_path) and pass them
through to db_write_ops — the MCP-layer integration seam itself, not
the crew-scoping logic (already proven correct in isolation).

In-process (not subprocess) like test_job_spreadsheet_scope.py, since a
real ctx/MagicMock can't be serialized across a subprocess boundary the
way a plain dict argument can.

Run with:
    run_tests.bat tests\\mcp\\test_job_board_phase1_server_mode.py -v
"""
from __future__ import annotations

import sqlite3
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


def _field_crew(uid="jake-r", name="Jake R"):
    return {"id": uid, "name": name, "role": "field_crew", "status": "active", "scopes": []}


def _owner(uid="dave"):
    return {"id": uid, "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}


@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    """Sets up a shared default_spreadsheet_path folder (server mode's
    "master" location) so _resolve_job_db_path resolves every call in a
    test to the SAME ai_prowler_jobs.db, mirroring how a real server-mode
    install has one shared master spreadsheet path in Settings."""
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    db_path = tmp_path / "ai_prowler_jobs.db"
    return db_path


def _set_user(monkeypatch, mcp_mod, user):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)


def _col(db_path, table, column, where_col, where_val):
    conn = sqlite3.connect(str(db_path))
    row = conn.execute(f"SELECT {column} FROM {table} WHERE {where_col} = ?", (where_val,)).fetchone()
    conn.close()
    return row[0] if row else None


# ══════════════════════════════════════════════════════════════════════════
# create_job / create_customer / create_quote — server mode just needs to
# work (no crew-scoping on creation, per their own docstrings), resolving
# through the shared master db rather than any filepath argument.
# ══════════════════════════════════════════════════════════════════════════

def test_create_customer_server_mode(server_env, monkeypatch, mcp_mod):
    user = _field_crew()
    _set_user(monkeypatch, mcp_mod, user)
    result = mcp_mod.create_customer(
        {"Company Name": "Blue Wave Cafe"}, filepath="", backup=False, ctx=_make_ctx(user),
    )
    assert result.startswith("✅"), result
    assert _col(server_env, "customers", "company_name", "customer_id", "CUST-0001") == "Blue Wave Cafe"


def test_create_job_server_mode(server_env, monkeypatch, mcp_mod):
    user = _field_crew()
    _set_user(monkeypatch, mcp_mod, user)
    cust_result = mcp_mod.create_customer(
        {"Company Name": "Jane Smith"}, filepath="", backup=False, ctx=_make_ctx(user),
    )
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    result = mcp_mod.create_job(
        {"CustomerID": cust_id, "Customer Name / Company": "Jane Smith"}, filepath="", backup=False, ctx=_make_ctx(user),
    )
    assert result.startswith("✅"), result
    assert _col(server_env, "jobs", "customer_name", "job_id", "JOB-0001") == "Jane Smith"
    # Audit stamp: created_by should reflect the server-mode user, not "operator".
    assert _col(server_env, "jobs", "created_by", "job_id", "JOB-0001") == "Jake R"


def test_create_quote_server_mode(server_env, monkeypatch, mcp_mod):
    """Fixed 2026-09-24: this test predated the 2026-09-23 owner-requested
    policy change that blocks field_crew from the Quotes sheet entirely
    (see _field_crew_sheet_denied / _FIELD_CREW_BLOCKED_SHEETS and the
    comment directly above create_quote's own denial check). It previously
    asserted field_crew could create a quote, matching create_customer's
    and create_job's behavior — but create_quote was deliberately made
    stricter than those two the day before this fix, and the test was
    simply never updated to match. This is the intended, correct
    application behavior; only the test's expectation was stale."""
    user = _field_crew()
    _set_user(monkeypatch, mcp_mod, user)
    result = mcp_mod.create_quote(
        {"Customer Name / Company": "Jane Smith"}, filepath="", backup=False, ctx=_make_ctx(user),
    )
    assert result.startswith("❌"), result
    assert "Quotes" in result, result


def test_create_job_server_mode_ignores_filepath_argument(server_env, monkeypatch, mcp_mod, tmp_path):
    """Same access-control contract as _resolve_job_spreadsheet_path:
    server mode never lets a caller redirect a write via `filepath`."""
    user = _field_crew()
    _set_user(monkeypatch, mcp_mod, user)
    decoy = tmp_path / "decoy.db"
    cust_result = mcp_mod.create_customer(
        {"Company Name": "X"}, filepath="", backup=False, ctx=_make_ctx(user),
    )
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    result = mcp_mod.create_job(
        {"CustomerID": cust_id, "Customer Name / Company": "X"}, filepath=str(decoy), backup=False, ctx=_make_ctx(user),
    )
    assert result.startswith("✅"), result
    assert not decoy.exists()
    assert _col(server_env, "jobs", "customer_name", "job_id", "JOB-0001") == "X"


# ══════════════════════════════════════════════════════════════════════════
# create_invoice — crew-scoping IS enforced; this is the seam that matters.
# ══════════════════════════════════════════════════════════════════════════

def _seed_job_for_crew(mcp_mod, monkeypatch, db_path, owner_user, crew_name, quote_amount=200):
    """Create a customer + job assigned to crew_name, acting as an
    unrestricted owner so the seeding step itself isn't crew-scoped."""
    _set_user(monkeypatch, mcp_mod, owner_user)
    cust = mcp_mod.create_customer({"Company Name": "Torres Residence"}, filepath="", backup=False,
                                    ctx=_make_ctx(owner_user))
    cust_id = cust.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    job = mcp_mod.create_job({
        "CustomerID (Customers!A)": cust_id,
        "Customer Name / Company": "Torres Residence",
        "Crew / Technician": crew_name,
        "Quote Amount ($)": quote_amount,
    }, filepath="", backup=False, ctx=_make_ctx(owner_user))
    return job.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def test_create_invoice_field_crew_denied_for_unassigned_job(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    job_id = _seed_job_for_crew(mcp_mod, monkeypatch, server_env, owner_user, crew_name="Someone Else")

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.create_invoice(job_id, filepath="", backup=False, ctx=_make_ctx(crew))
    assert result.startswith("❌"), result
    assert "assigned to you" in result


def test_create_invoice_field_crew_allowed_for_own_job(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    crew = _field_crew()
    job_id = _seed_job_for_crew(mcp_mod, monkeypatch, server_env, owner_user, crew_name=crew["name"])

    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.create_invoice(job_id, filepath="", backup=False, ctx=_make_ctx(crew))
    assert result.startswith("✅"), result
    assert "NEW_INVOICE_ID=" in result


def test_create_invoice_owner_unrestricted_regardless_of_assignment(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    job_id = _seed_job_for_crew(mcp_mod, monkeypatch, server_env, owner_user, crew_name="Nobody In Particular")

    _set_user(monkeypatch, mcp_mod, owner_user)
    result = mcp_mod.create_invoice(job_id, filepath="", backup=False, ctx=_make_ctx(owner_user))
    assert result.startswith("✅"), result


# ══════════════════════════════════════════════════════════════════════════
# log_time_entry — server mode works; crew scope is advisory-only by
# design (any authenticated user may clock in/out, per the tool's own
# docstring), so no denial case is expected here.
# ══════════════════════════════════════════════════════════════════════════

def test_log_time_entry_server_mode_clock_in(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    crew = _field_crew()
    job_id = _seed_job_for_crew(mcp_mod, monkeypatch, server_env, owner_user, crew_name=crew["name"])

    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.log_time_entry(job_id, "start", ctx=_make_ctx(crew))
    assert result.startswith("⏱️"), result
    assert _col(server_env, "time_entries", "crew_user_id", "job_id", job_id) == "jake-r"


# ══════════════════════════════════════════════════════════════════════════
# update_job_spreadsheet — Jobs_Schedule and Customers crew-scoping through
# the real MCP tool, ctx-driven.
# ══════════════════════════════════════════════════════════════════════════

def test_update_job_spreadsheet_field_crew_denied_for_unassigned_job(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    job_id = _seed_job_for_crew(mcp_mod, monkeypatch, server_env, owner_user, crew_name="Someone Else")

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.update_job_spreadsheet(
        job_id, {"Job Status": "Complete"}, filepath="",
        id_column="JobID (JOB-####)", sheet_name="Jobs_Schedule", backup=False,
        ctx=_make_ctx(crew),
    )
    assert result.startswith("❌"), result
    assert "assigned to you" in result


def test_update_job_spreadsheet_field_crew_allowed_for_own_job(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    crew = _field_crew()
    job_id = _seed_job_for_crew(mcp_mod, monkeypatch, server_env, owner_user, crew_name=crew["name"])

    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.update_job_spreadsheet(
        job_id, {"Job Status": "Complete"}, filepath="",
        id_column="JobID (JOB-####)", sheet_name="Jobs_Schedule", backup=False,
        ctx=_make_ctx(crew),
    )
    assert result.startswith("✅"), result
    assert _col(server_env, "jobs", "job_status", "job_id", job_id) == "Complete"


def test_update_job_spreadsheet_customers_field_crew_denied_for_unlinked_customer(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    _set_user(monkeypatch, mcp_mod, owner_user)
    cust = mcp_mod.create_customer({"Company Name": "Unrelated Co"}, filepath="", backup=False,
                                    ctx=_make_ctx(owner_user))
    cust_id = cust.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    # No job links this customer to any crew member.

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.update_job_spreadsheet(
        cust_id, {"Phone": "386-555-0101"}, filepath="",
        id_column="CustomerID (CUST-####)", sheet_name="Customers", backup=False,
        ctx=_make_ctx(crew),
    )
    assert result.startswith("❌"), result


def test_update_job_spreadsheet_customers_field_crew_allowed_for_linked_customer(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    crew = _field_crew()
    job_id = _seed_job_for_crew(mcp_mod, monkeypatch, server_env, owner_user, crew_name=crew["name"])
    cust_id = _col(server_env, "jobs", "customer_id", "job_id", job_id)

    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.update_job_spreadsheet(
        cust_id, {"Phone": "386-555-0101"}, filepath="",
        id_column="CustomerID (CUST-####)", sheet_name="Customers", backup=False,
        ctx=_make_ctx(crew),
    )
    assert result.startswith("✅"), result
    assert _col(server_env, "customers", "phone", "customer_id", cust_id) == "386-555-0101"


def test_update_job_spreadsheet_customers_field_crew_locked_field_rejected(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    crew = _field_crew()
    job_id = _seed_job_for_crew(mcp_mod, monkeypatch, server_env, owner_user, crew_name=crew["name"])
    cust_id = _col(server_env, "jobs", "customer_id", "job_id", job_id)

    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.update_job_spreadsheet(
        cust_id, {"Standard Quote ($)": 999}, filepath="",
        id_column="CustomerID (CUST-####)", sheet_name="Customers", backup=False,
        ctx=_make_ctx(crew),
    )
    assert result.startswith("❌"), result
    assert "staff/manager/owner" in result


def test_update_job_spreadsheet_owner_unrestricted(server_env, monkeypatch, mcp_mod):
    owner_user = _owner()
    job_id = _seed_job_for_crew(mcp_mod, monkeypatch, server_env, owner_user, crew_name="Nobody")

    _set_user(monkeypatch, mcp_mod, owner_user)
    result = mcp_mod.update_job_spreadsheet(
        job_id, {"Job Status": "Complete"}, filepath="",
        id_column="JobID (JOB-####)", sheet_name="Jobs_Schedule", backup=False,
        ctx=_make_ctx(owner_user),
    )
    assert result.startswith("✅"), result
