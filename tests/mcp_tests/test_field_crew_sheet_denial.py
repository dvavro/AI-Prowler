"""
tests/mcp_tests/test_field_crew_sheet_denial.py
===========================================
Blanket access rule (2026-09-23, at the owner's request): in SERVER MODE,
field_crew has NO ACCESS AT ALL to Settings, Services_Pricing, Quotes, or
Invoices — not filtered, not scoped, denied outright. Customers stays fully
open to field_crew (gate codes / access notes / on-site contact — needed to
actually work a job). Personal mode is never affected (solo business — the
one user is the owner and sees everything).

This is stricter than, and layered BEFORE, the older per-field / per-
customer-ownership scoping update_job_spreadsheet already applied to
Customers/Invoices/Quotes for field_crew.
"""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

from db_access import init_db

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod, db_path):
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": db_path)
    return db_path


def _user(role, name="Jake", uid="u1"):
    return {"id": uid, "name": name, "role": role}


def _as(mcp_mod, monkeypatch, role):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: _user(role))


def _personal_mode(mcp_mod, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)


@pytest.mark.parametrize("sheet", ["Settings", "Services_Pricing", "Quotes", "Invoices"])
def test_field_crew_denied_read_on_blocked_sheets(mcp_mod, env, monkeypatch, sheet):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.read_job_spreadsheet(sheet_name=sheet, ctx=None)
    assert out.startswith("❌") and sheet in out


@pytest.mark.parametrize("sheet", ["Settings", "Services_Pricing", "Quotes", "Invoices"])
@pytest.mark.parametrize("role", ["owner", "manager", "staff"])
def test_other_roles_not_denied_read_on_those_sheets(mcp_mod, env, monkeypatch, sheet, role):
    _as(mcp_mod, monkeypatch, role)
    out = mcp_mod.read_job_spreadsheet(sheet_name=sheet, ctx=None)
    assert not out.startswith("❌") or sheet not in out.split("\n")[0]
    # More precisely: must not be OUR denial message specifically.
    assert "do not have access to the" not in out


def test_field_crew_keeps_read_access_to_customers(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.read_job_spreadsheet(sheet_name="Customers", ctx=None)
    assert "do not have access to the" not in out


def test_field_crew_keeps_read_access_to_jobs_schedule(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.read_job_spreadsheet(sheet_name="Jobs_Schedule", ctx=None)
    assert "do not have access to the" not in out


def test_personal_mode_never_denied_any_sheet(mcp_mod, env, monkeypatch):
    _personal_mode(mcp_mod, monkeypatch)
    for sheet in ["Settings", "Services_Pricing", "Quotes", "Invoices", "Customers"]:
        out = mcp_mod.read_job_spreadsheet(sheet_name=sheet, ctx=None)
        assert "do not have access to the" not in out


@pytest.mark.parametrize("sheet", ["Settings", "Services_Pricing", "Quotes", "Invoices"])
def test_field_crew_denied_update_on_blocked_sheets(mcp_mod, env, monkeypatch, sheet):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.update_job_spreadsheet(
        job_identifier="anything", updates={"Notes": "x"}, sheet_name=sheet, ctx=None,
    )
    assert out.startswith("❌") and "do not have access to the" in out


def test_field_crew_denied_create_quote(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.create_quote(updates={"Customer Name / Company": "Jane"}, ctx=None)
    assert out.startswith("❌") and "do not have access to the" in out


def test_field_crew_can_still_create_a_customer(mcp_mod, env, monkeypatch):
    # Customers uses the SAME shared helper as create_quote — confirms the
    # denial is scoped to the sheet_name argument, not a blanket lockout of
    # everything the helper touches.
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.create_customer(updates={
        "Company Name": "New Co", "Street Address": "1 Main St", "City": "NSB", "State": "FL",
    }, ctx=None)
    assert not out.startswith("❌") or "do not have access to the" not in out


def test_field_crew_denied_create_setting(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.create_setting(updates={"Setting": "Test Key", "Value": "1"}, ctx=None)
    assert out.startswith("❌")   # already-existing staff-only gate, confirmed still working


def test_field_crew_denied_create_service_pricing(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.create_service_pricing(updates={"Service Code": "TEST"}, ctx=None)
    assert out.startswith("❌")   # already-existing staff-only gate, confirmed still working


@pytest.mark.parametrize("sheet", ["Settings", "Services_Pricing", "Quotes", "Invoices"])
def test_board_updates_also_denies_field_crew_on_blocked_sheets(mcp_mod, env, monkeypatch, sheet):
    # get_board_updates is a SEPARATE read path (db_get_jobs_changed_since,
    # not db_read_job_spreadsheet) — this is the gap that would otherwise
    # let a field_crew user reach these sheets' data via Board polling even
    # with read_job_spreadsheet itself locked down.
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.get_board_updates(since="2000-01-01T00:00:00", sheet_name=sheet, ctx=None)
    parsed = json.loads(out)
    assert "error" in parsed and "do not have access to the" in parsed["error"]


def test_board_updates_customers_and_jobs_still_work_for_field_crew(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    for sheet in ["Customers", "Jobs_Schedule"]:
        out = mcp_mod.get_board_updates(since="2000-01-01T00:00:00", sheet_name=sheet, ctx=None)
        parsed = json.loads(out)
        assert not (isinstance(parsed, dict) and "error" in parsed and "do not have access" in parsed.get("error", ""))
