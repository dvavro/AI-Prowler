"""
tests/mcp_tests/test_create_invoice_isolated.py
=============================================
Functional tests for _create_invoice_impl() (the create_invoice tool) that
exercise the REAL production function — not a reimplemented copy — while
staying fully isolated, matching the same subprocess-isolation pattern as
test_log_time_entry_isolated.py:

  1. Every test builds its own scratch SQLite database inside pytest's
     tmp_path. Nothing here ever opens a file under Documents/AI-Prowler
     or the dev-folder install's real database.

  2. Each test runs the real function in a SEPARATE SUBPROCESS with
     USERPROFILE (Windows' $HOME) redirected into tmp_path, so importing
     ai_prowler_mcp.py — which opens ~/.ai-prowler/logs/mcp_server.log in
     truncate mode at import time — can never fight a live server process
     for that file.

2026-09-14 migration note: this file originally built a scratch .xlsx
workbook with openpyxl, using the real decorated multi-line headers to
exercise header canonicalization, and specifically poisoned Jobs_Schedule's
own formula cells (Actual Amount/Tax/Invoice Total) with wrong values to
prove create_invoice never depends on openpyxl's stale cached formula
results. Since Phase 1 (Job Board Architecture Spec), _create_invoice_impl()
reads/writes the SQLite job database via db_write_ops.db_create_invoice
instead — there are no decorated headers or formula cells to canonicalize
or poison at all; the schema has real, plainly-named columns, and every
dollar amount create_invoice writes is computed fresh from quote_amount/
discount_applied alone. Rewritten to build the scratch fixture directly
against the real db_schema.py schema, the same way
test_job_board_phase1_mcp_wiring.py and test_log_time_entry_isolated.py
already do. Read-back helpers now read real column names (job_id,
quote_amount, subtotal, taxable_amt, ...) instead of decorated sheet
headers.

Safe to run at any time, including while AI-Prowler is running live.

Run with:
    pytest tests/mcp_tests/test_create_invoice_isolated.py -v
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"
DB_WRITE_OPS_FILE = SRC_ROOT / "db_write_ops.py"


def _build_scratch_tracker(path: Path, jobs: list[dict], seed_invoice_ids: "list[str] | None" = None):
    """
    Build a minimal but realistic scratch SQLite job database at `path`,
    using the real db_schema.apply_schema. `jobs` is a list of dicts keyed
    by the real `jobs` table column names (job_id, customer_name,
    quote_amount, discount_applied, invoice_id, ...) — missing keys are
    left NULL, matching how a real partially-filled job row looks.

    `seed_invoice_ids`, if given, pre-populates the `invoices` table with
    placeholder rows under those IDs (for ID-sequencing tests).
    """
    sys.path.insert(0, str(SRC_ROOT))
    from db_access import get_connection
    from db_schema import apply_schema

    conn = get_connection(str(path))
    try:
        apply_schema(conn)
        for job in jobs:
            # jobs.customer_id is a real FK to customers(customer_id) with
            # foreign_keys=ON — auto-seed a minimal customers row for any
            # customer_id a fixture references, so tests can set one purely
            # to exercise the job->invoice copy-through without needing to
            # separately build out a full customer record.
            cust_id = job.get("customer_id")
            if cust_id:
                conn.execute(
                    "INSERT OR IGNORE INTO customers (customer_id) VALUES (?)",
                    (cust_id,),
                )
            # jobs.invoice_id is likewise a real FK to invoices(invoice_id) —
            # a fixture that pre-seeds a job as "already invoiced" needs a
            # matching placeholder invoices row too.
            existing_inv_id = job.get("invoice_id")
            if existing_inv_id:
                conn.execute(
                    "INSERT OR IGNORE INTO invoices (invoice_id) VALUES (?)",
                    (existing_inv_id,),
                )
            cols = ", ".join(job.keys())
            qs = ", ".join(["?"] * len(job))
            conn.execute(f"INSERT INTO jobs ({cols}) VALUES ({qs})", tuple(job.values()))
        for inv_id in (seed_invoice_ids or []):
            conn.execute("INSERT INTO invoices (invoice_id) VALUES (?)", (inv_id,))
        conn.commit()
    finally:
        conn.close()


def _run_create_invoice(
    tmp_path: Path, db_path: Path, job_identifier: str,
    quote_amount=None, discount=None, description="", service_type="",
    tax_rate=0.07, due_days=30,
) -> str:
    """Run the REAL _create_invoice_impl() in an isolated subprocess (ctx=None,
    i.e. personal mode — server-mode crew scoping is covered structurally,
    see TestCrewScopingWired below, matching this codebase's existing
    convention of not fully mocking server-mode ctx in isolated tests)."""
    scratch_home = tmp_path / "scratch_home"
    scratch_home.mkdir(exist_ok=True)

    script = textwrap.dedent(f"""
        import sys, json
        sys.path.insert(0, {str(SRC_ROOT)!r})
        import ai_prowler_mcp as m
        result = m._create_invoice_impl(
            {job_identifier!r}, {quote_amount!r}, {discount!r},
            {description!r}, {service_type!r}, {tax_rate!r}, {due_days!r},
            {str(db_path)!r}, False, None,
        )
        print("RESULT_JSON_START" + json.dumps(result) + "RESULT_JSON_END")
    """)

    env = os.environ.copy()
    env["USERPROFILE"] = str(scratch_home)
    env["HOME"] = str(scratch_home)

    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(SRC_ROOT), env=env,
        capture_output=True, text=True, timeout=90,
    )

    if "RESULT_JSON_START" not in proc.stdout:
        raise AssertionError(
            f"Subprocess did not return a result.\n"
            f"--- stdout ---\n{proc.stdout}\n"
            f"--- stderr ---\n{proc.stderr}\n"
            f"--- returncode --- {proc.returncode}"
        )

    payload = proc.stdout.split("RESULT_JSON_START", 1)[1].split("RESULT_JSON_END", 1)[0]
    return json.loads(payload)


def _read_job_row(db_path: Path, job_id: str) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    if row is None:
        raise AssertionError(f"JobID {job_id!r} not found in jobs.")
    return dict(row)


def _read_invoice_rows(db_path: Path) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM invoices").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _read_invoice_by_id(db_path: Path, inv_id: str) -> dict:
    for r in _read_invoice_rows(db_path):
        if r["invoice_id"] == inv_id:
            return r
    raise AssertionError(f"InvoiceID {inv_id!r} not found in invoices.")


# ══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def priced_job_tracker(tmp_path):
    """One job that already has a quote_amount/discount_applied on file
    (the common case: a technician priced the job earlier and is now
    invoicing without needing to change anything)."""
    path = tmp_path / "scratch_job_board.db"
    _build_scratch_tracker(path, [{
        "job_id": "JOB-0001",
        "customer_id": "CUST-0001",
        "customer_name": "Torres Residence",
        "customer_type": "Residential",
        "service_date": "2026-08-24",
        "service_type": "Window",
        "service_details": "Full exterior window cleaning",
        "crew": "Jake R.",
        "quote_amount": 200,
        "discount_applied": 20,
    }])
    return path


@pytest.fixture
def unpriced_job_tracker(tmp_path):
    """A job with no price set anywhere — the on-the-spot case where a
    quote_amount override is required."""
    path = tmp_path / "scratch_job_board.db"
    _build_scratch_tracker(path, [{
        "job_id": "JOB-0002",
        "customer_name": "Blue Wave Cafe",
        "service_date": "2026-08-24",
        "service_type": "Window",
        "crew": "Mike C.",
    }])
    return path


@pytest.fixture
def already_invoiced_job_tracker(tmp_path):
    path = tmp_path / "scratch_job_board.db"
    _build_scratch_tracker(path, [{
        "job_id": "JOB-0003",
        "customer_name": "Sunshine Realty LLC",
        "quote_amount": 150,
        "invoice_id": "INV-0007",
    }])
    return path


# ══════════════════════════════════════════════════════════════════════════
# TESTS — happy path, using the job's own stored price
# ══════════════════════════════════════════════════════════════════════════

class TestUsesJobsOwnStoredPrice:
    def test_success_message(self, tmp_path, priced_job_tracker):
        result = _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001")
        assert "❌" not in result, f"Unexpected error: {result}"
        assert "✅ Invoice created: INV-0001" in result
        assert "NEW_INVOICE_ID=INV-0001" in result

    def test_amounts_computed_correctly(self, tmp_path, priced_job_tracker):
        """200 - 20 = 180 taxable, * 1.07 = 192.60 total. There are no
        formula cells in the SQLite schema at all — every dollar amount is
        computed fresh from quote_amount/discount_applied by db_create_invoice,
        so this is guaranteed by design rather than something that needs a
        poisoned fixture to prove."""
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001")
        inv = _read_invoice_by_id(priced_job_tracker, "INV-0001")
        assert inv["subtotal"] == 200
        assert inv["discount"] == 20
        assert inv["taxable_amt"] == 180
        assert inv["tax"] == pytest.approx(12.6)
        assert inv["total_due"] == pytest.approx(192.6)
        assert inv["balance_due"] == pytest.approx(192.6)
        assert inv["amount_paid"] == 0

    def test_customer_and_job_fields_copied_across(self, tmp_path, priced_job_tracker):
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001")
        inv = _read_invoice_by_id(priced_job_tracker, "INV-0001")
        assert inv["job_id"] == "JOB-0001"
        assert inv["customer_id"] == "CUST-0001"
        assert inv["customer_name"] == "Torres Residence"
        assert inv["customer_type"] == "Residential"
        assert inv["service_type"] == "Window"
        assert inv["description"] == "Full exterior window cleaning"

    def test_payment_status_defaults_unpaid(self, tmp_path, priced_job_tracker):
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001")
        inv = _read_invoice_by_id(priced_job_tracker, "INV-0001")
        assert inv["payment_status"] == "Unpaid"

    def test_due_date_defaults_net_30(self, tmp_path, priced_job_tracker):
        import datetime
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001")
        inv = _read_invoice_by_id(priced_job_tracker, "INV-0001")
        expected = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        assert inv["due_date"] == expected

    def test_invoice_id_written_back_onto_job_row(self, tmp_path, priced_job_tracker):
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001")
        job = _read_job_row(priced_job_tracker, "JOB-0001")
        assert job["invoice_id"] == "INV-0001"

    def test_job_row_price_unchanged_when_no_override_given(self, tmp_path, priced_job_tracker):
        """No override passed → the job's own Quote Amount/Discount must
        still reflect the same values (db_create_invoice always writes the
        effective amount back, but with no override that's the same value
        the job already had)."""
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001")
        job = _read_job_row(priced_job_tracker, "JOB-0001")
        assert job["quote_amount"] == 200
        assert job["discount_applied"] == 20

    def test_matches_by_partial_customer_name(self, tmp_path, priced_job_tracker):
        result = _run_create_invoice(tmp_path, priced_job_tracker, "Torres")
        assert "✅ Invoice created" in result


# ══════════════════════════════════════════════════════════════════════════
# TESTS — the "technician adjusts price on the spot" override path
# ══════════════════════════════════════════════════════════════════════════

class TestOnTheSpotOverrides:
    def test_quote_amount_override_used_over_job_value(self, tmp_path, priced_job_tracker):
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001", quote_amount=300)
        inv = _read_invoice_by_id(priced_job_tracker, "INV-0001")
        assert inv["subtotal"] == 300

    def test_quote_amount_override_written_back_to_job(self, tmp_path, priced_job_tracker):
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001", quote_amount=300)
        job = _read_job_row(priced_job_tracker, "JOB-0001")
        assert job["quote_amount"] == 300

    def test_discount_override(self, tmp_path, priced_job_tracker):
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001",
                             quote_amount=100, discount=10)
        inv = _read_invoice_by_id(priced_job_tracker, "INV-0001")
        assert inv["discount"] == 10
        assert inv["taxable_amt"] == 90

    def test_description_and_service_type_override(self, tmp_path, priced_job_tracker):
        _run_create_invoice(
            tmp_path, priced_job_tracker, "JOB-0001",
            quote_amount=250, description="Pressure wash driveway",
            service_type="Pressure Wash",
        )
        inv = _read_invoice_by_id(priced_job_tracker, "INV-0001")
        assert inv["description"] == "Pressure wash driveway"
        assert inv["service_type"] == "Pressure Wash"
        job = _read_job_row(priced_job_tracker, "JOB-0001")
        assert job["service_details"] == "Pressure wash driveway"
        assert job["service_type"] == "Pressure Wash"

    def test_unpriced_job_requires_override(self, tmp_path, unpriced_job_tracker):
        result = _run_create_invoice(tmp_path, unpriced_job_tracker, "JOB-0002")
        assert "❌" in result
        assert "No price to invoice" in result

    def test_unpriced_job_succeeds_with_override(self, tmp_path, unpriced_job_tracker):
        result = _run_create_invoice(tmp_path, unpriced_job_tracker, "JOB-0002",
                                      quote_amount=220)
        assert "✅ Invoice created" in result
        inv = _read_invoice_by_id(unpriced_job_tracker, "INV-0001")
        assert inv["subtotal"] == 220

    def test_custom_tax_rate(self, tmp_path, priced_job_tracker):
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001",
                             quote_amount=100, discount=0, tax_rate=0.10)
        inv = _read_invoice_by_id(priced_job_tracker, "INV-0001")
        assert inv["tax"] == pytest.approx(10.0)
        assert inv["total_due"] == pytest.approx(110.0)

    def test_custom_due_days(self, tmp_path, priced_job_tracker):
        import datetime
        _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001", due_days=15)
        inv = _read_invoice_by_id(priced_job_tracker, "INV-0001")
        expected = (datetime.date.today() + datetime.timedelta(days=15)).isoformat()
        assert inv["due_date"] == expected


# ══════════════════════════════════════════════════════════════════════════
# TESTS — validation / error paths
# ══════════════════════════════════════════════════════════════════════════

class TestValidation:
    def test_blank_job_identifier_rejected(self, tmp_path, priced_job_tracker):
        result = _run_create_invoice(tmp_path, priced_job_tracker, "")
        assert "❌" in result
        assert "cannot be blank" in result

    def test_nonexistent_job_returns_clear_error(self, tmp_path, priced_job_tracker):
        result = _run_create_invoice(tmp_path, priced_job_tracker, "JOB-DOES-NOT-EXIST")
        assert "❌" in result
        assert "No job found" in result

    def test_ambiguous_match_lists_candidates_and_refuses(self, tmp_path):
        path = tmp_path / "scratch_job_board.db"
        _build_scratch_tracker(path, [
            {"job_id": "JOB-0001", "customer_name": "Window Co A", "quote_amount": 100},
            {"job_id": "JOB-0002", "customer_name": "Window Co B", "quote_amount": 100},
        ])
        result = _run_create_invoice(tmp_path, path, "Window")
        assert "❌" in result
        assert "matches 2 jobs" in result
        assert "JOB-0001" in result and "JOB-0002" in result

    def test_negative_quote_amount_rejected(self, tmp_path, priced_job_tracker):
        result = _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001",
                                      quote_amount=-50)
        assert "❌" in result
        assert "cannot be negative" in result

    def test_discount_exceeding_quote_rejected(self, tmp_path, priced_job_tracker):
        result = _run_create_invoice(tmp_path, priced_job_tracker, "JOB-0001",
                                      quote_amount=100, discount=150)
        assert "❌" in result
        assert "cannot exceed" in result

    def test_already_invoiced_job_refused(self, tmp_path, already_invoiced_job_tracker):
        result = _run_create_invoice(tmp_path, already_invoiced_job_tracker, "JOB-0003")
        assert "❌" in result
        assert "INV-0007" in result
        assert "already has an invoice" in result

    def test_already_invoiced_job_creates_no_new_row(self, tmp_path, already_invoiced_job_tracker):
        """already_invoiced_job_tracker seeds exactly one placeholder
        invoices row (INV-0007, to satisfy the FK the job's own invoice_id
        points at) — a refused create_invoice call must not add a second."""
        before = len(_read_invoice_rows(already_invoiced_job_tracker))
        _run_create_invoice(tmp_path, already_invoiced_job_tracker, "JOB-0003")
        after = len(_read_invoice_rows(already_invoiced_job_tracker))
        assert after == before

    def test_empty_database_returns_no_job_found_not_a_crash(self, tmp_path):
        """2026-09-14 migration note: this used to build a workbook with no
        Jobs_Schedule sheet at all and check for a sheet-specific error —
        that concept doesn't exist anymore, since db_schema.apply_schema
        always creates every table up front. The equivalent honest-gap case
        now is a freshly-schema'd database with no job rows at all, which
        must fail with the normal 'no job found' message, not a crash."""
        path = tmp_path / "empty.db"
        _build_scratch_tracker(path, [])
        result = _run_create_invoice(tmp_path, path, "JOB-0001")
        assert "❌" in result
        assert "No job found" in result


# ══════════════════════════════════════════════════════════════════════════
# TESTS — sequencing, multi-invoice behavior
# ══════════════════════════════════════════════════════════════════════════

class TestSequencing:
    def test_invoice_ids_increment_sequentially(self, tmp_path):
        path = tmp_path / "scratch_job_board.db"
        _build_scratch_tracker(path, [
            {"job_id": "JOB-0001", "customer_name": "A", "quote_amount": 100},
            {"job_id": "JOB-0002", "customer_name": "B", "quote_amount": 100},
        ])
        r1 = _run_create_invoice(tmp_path, path, "JOB-0001")
        r2 = _run_create_invoice(tmp_path, path, "JOB-0002")
        assert "NEW_INVOICE_ID=INV-0001" in r1
        assert "NEW_INVOICE_ID=INV-0002" in r2

    def test_first_invoice_succeeds_on_fresh_database(self, tmp_path):
        """The invoices table always exists (created up front by
        apply_schema) but starts empty — this is the equivalent of the old
        'Invoices sheet auto-created when missing' case."""
        path = tmp_path / "scratch_job_board.db"
        _build_scratch_tracker(
            path,
            [{"job_id": "JOB-0001", "customer_name": "A", "quote_amount": 100}],
        )
        result = _run_create_invoice(tmp_path, path, "JOB-0001")
        assert "✅ Invoice created: INV-0001" in result
        inv = _read_invoice_by_id(path, "INV-0001")
        assert inv["subtotal"] == 100

    def test_next_id_continues_from_existing_invoices(self, tmp_path):
        """A database that already has INV-0001..INV-0004 (e.g. seeded
        data) must continue from INV-0005, not restart at INV-0001."""
        path = tmp_path / "scratch_job_board.db"
        _build_scratch_tracker(
            path,
            [{"job_id": "JOB-0009", "customer_name": "Late Entry", "quote_amount": 100}],
            seed_invoice_ids=["INV-0001", "INV-0002", "INV-0003", "INV-0004"],
        )
        result = _run_create_invoice(tmp_path, path, "JOB-0009")
        assert "NEW_INVOICE_ID=INV-0005" in result


def test_source_exists():
    assert MCP_FILE.exists(), f"ai_prowler_mcp.py not found at {MCP_FILE}"


# ══════════════════════════════════════════════════════════════════════════
# STRUCTURAL TESTS — crew scoping wiring, tool registration
# (matching this codebase's existing convention — see
#  TestSharedCrewScopeHelper in test_server_mode_jobs_pwa.py and
#  TestBackendToolAllowedInBothModes in
#  test_pwa_invoice_button_labels_and_sms_gating.py — of verifying
#  server-mode wiring structurally rather than fully mocking a server-mode
#  ctx/user/crew-assignment in isolated subprocess tests.)
#
# 2026-09-14 migration note: crew-scoping resolution (_job_crew_scope) is
# still called from _create_invoice_impl in ai_prowler_mcp.py, but the
# actual "not assigned to you" refusal message now lives inside
# db_write_ops.db_create_invoice (the restrict/crew_name check moved there
# with the rest of the financial logic) — so that specific assertion now
# reads db_write_ops.py's source instead of ai_prowler_mcp.py's.
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def mcp_source():
    return MCP_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def db_write_ops_source():
    return DB_WRITE_OPS_FILE.read_text(encoding="utf-8")


class TestCrewScopingWired:
    def test_create_invoice_uses_shared_crew_scope_helper(self, mcp_source):
        idx = mcp_source.index("def _create_invoice_impl(")
        end_idx = mcp_source.index("\n@mcp.tool()\ndef create_invoice(", idx)
        body = mcp_source[idx:end_idx]
        assert "_job_crew_scope(ctx, db_path)" in body
        assert "restrict=_ci_restrict" in body
        assert "crew_name=_ci_crew_name" in body

    def test_refuses_when_not_assigned_to_caller(self, db_write_ops_source):
        idx = db_write_ops_source.index("def db_create_invoice(")
        end_idx = db_write_ops_source.index("\ndef ", idx + 1)
        body = db_write_ops_source[idx:end_idx]
        assert "not assigned to you" in body


class TestToolRegisteredInBothPwaModes:
    def test_allowed_in_personal_mode(self, mcp_source):
        idx = mcp_source.index("_allowed_tools = {")
        nearby = mcp_source[idx:idx + 800]
        assert '"create_invoice"' in nearby

    def test_allowed_in_server_mode(self, mcp_source):
        idx = mcp_source.index("_srv_pa_allowed = {")
        nearby = mcp_source[idx:idx + 800]
        assert '"create_invoice"' in nearby

    def test_tool_is_mcp_registered(self, mcp_source):
        assert "@mcp.tool()\ndef create_invoice(" in mcp_source
