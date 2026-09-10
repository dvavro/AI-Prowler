"""
tests/e2e/test_job_tracker_e2e.py
==================================
End-to-end test suite for the Job Tracker spreadsheet MCP tools, driven by
natural-language prompts through the real Anthropic API — exercising the
exact same "Claude decides which tool to call" path a contractor uses by
voice or text, not just direct Python function calls.

WHAT THIS TESTS
----------------
Two layers, both real:
  1. TOOL SELECTION — does Claude pick the right MCP tool and populate the
     right arguments from a natural-language prompt? (an eval, not a unit test)
  2. TOOL CORRECTNESS — does the tool, once called with realistic arguments,
     write the right value into the right column of the real spreadsheet?

This complements (does not replace) the existing unit-test suite. Unit tests
answer "does update_job_spreadsheet() do the right thing given these exact
arguments?" This suite answers "does update_job_spreadsheet() get called
with the right arguments when a person says X?" — the layer where the
create_job _dt NameError and the log_time_entry Actual-Duration-Unit
clobber bug were actually found, because both only manifest when driven by
realistic prompts/values rather than hand-picked unit-test fixtures.

SAFETY MODEL
------------
- Runs against a SEPARATE test job (Customer Name = the value of
  TEST_CUSTOMER_NAME below), never against real customer rows.
- Takes an automatic backup via backup=True (the tool's own default) before
  the very first write — every write tool already does this; no separate
  backup step is required.
- At the end of a full pass, restores the pre-suite backup, removing the
  test job entirely. On any failure, the spreadsheet is LEFT AS-IS with the
  test data still in it for inspection — restoration only happens after a
  clean pass, mirroring how this suite was first run manually.
- Never touches the Customers sheet or any row whose Customer Name doesn't
  match TEST_CUSTOMER_NAME.

REQUIREMENTS
------------
  pip install anthropic pytest
  Set ANTHROPIC_API_KEY in the environment.
  AI_PROWLER_SRC env var pointing at the ai_prowler_mcp.py directory
  (defaults to the real install directory below).

RUN
---
  pytest tests/e2e/test_job_tracker_e2e.py -v -s
  (run with -s to see the live Claude tool-call trace as it happens)

  To skip the network round-trips and cleanup (fast local run against a
  pre-recorded fixture instead), see test_job_tracker_e2e_offline.py.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# INSTALL_DIR is where ai_prowler_mcp.py (the source module) actually runs
# from — needed on sys.path to import the real, live tool implementations.
INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))

# SPREADSHEET_PATH is the DATA file the tools actually read/write — this is
# whatever is configured in AI-Prowler Settings → Small Business → Default
# Spreadsheet Path, which is NOT necessarily anywhere near INSTALL_DIR.
# Getting this wrong means the suite silently tests against the wrong file
# (or a stale leftover copy) while every tool call still reports success,
# since the tools themselves resolve the default path correctly — only an
# external script hardcoding the wrong path would drift from that.
# Confirmed via check_tools_status() / Settings → Small Business.
SPREADSHEET_PATH = Path(os.environ.get(
    "AI_PROWLER_JOB_TRACKER_PATH",
    r"C:\Users\david\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx",
))
TEST_CUSTOMER_NAME = "ZTEST Contractor QA"
MODEL = "claude-sonnet-4-6"

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def anthropic_client():
    anthropic = pytest.importorskip("anthropic")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        pytest.skip("ANTHROPIC_API_KEY not set — skipping live tool-use evals")
    return anthropic.Anthropic()


@pytest.fixture(scope="session")
def mcp_module():
    """Import the real, installed ai_prowler_mcp module — same file the
    live MCP server runs, so a fix verified here is verified for real."""
    import ai_prowler_mcp as m
    return m


@pytest.fixture(scope="session")
def tool_schemas(mcp_module):
    """Extract Anthropic-format tool schemas from the live FastMCP server
    object, for exactly the tools this suite exercises. Using the real
    server's schemas (not hand-written duplicates) means a docstring or
    parameter change is automatically reflected here — no drift possible.
    """
    wanted = {
        "create_job", "update_job_spreadsheet", "read_job_spreadsheet",
        "create_invoice", "log_time_entry",
    }

    async def _list():
        return await mcp_module.mcp.list_tools()

    tools = asyncio.run(_list())
    schemas = [
        {"name": t.name, "description": t.description,
         "input_schema": t.inputSchema}
        for t in tools if t.name in wanted
    ]
    found = {s["name"] for s in schemas}
    missing = wanted - found
    assert not missing, f"Expected tools not found on server: {missing}"
    return schemas


@pytest.fixture(scope="session")
def pre_suite_backup_path(mcp_module):
    """Trigger a backup of the CURRENT spreadsheet state before any test
    writes happen, by calling the tools' own backup mechanism directly
    (same _backup_spreadsheet() every write tool already uses) rather than
    a separate ad-hoc copy step.
    """
    backup_msg = mcp_module._backup_spreadsheet(str(SPREADSHEET_PATH))
    # backup_msg looks like: "💾 Backup saved: _backups/AI-Prowler_Job_Tracker_<ts>.xlsx"
    assert "Backup saved" in backup_msg, f"Pre-suite backup failed: {backup_msg}"
    rel_path = backup_msg.split("Backup saved:")[1].strip()
    return SPREADSHEET_PATH.parent / rel_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def call_claude_tool(client, schemas, prompt: str):
    """Send prompt to Claude with the real tool schemas; return the first
    tool_use block Claude decides to call, or None if it called no tool."""
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        tools=schemas,
        messages=[{"role": "user", "content": prompt}],
    )
    calls = [b for b in response.content if b.type == "tool_use"]
    return calls[0] if calls else None


def find_ztest_job(mcp_module) -> dict | None:
    """Read Jobs_Schedule and return the row dict for our test job, or None.

    BUG FIXED: previously scanned data rows from a HARDCODED min_row=6
    rather than the actual detected header row + 1. Any scenario with
    more data rows landing before row 6 than this suite happened to
    create would have silently skipped real rows — found and fixed via
    test_route_scheduling_e2e.py's near-identical helper, which seeds 3
    same-day jobs and directly exposed the skip (rows 4 and 5 were never
    scanned when min_row was hardcoded to 6).
    """
    import openpyxl
    wb = openpyxl.load_workbook(str(SPREADSHEET_PATH), data_only=True)
    ws = wb["Jobs_Schedule"]
    headers = None
    header_row_num = None
    for row in ws.iter_rows(min_row=1, max_row=5):
        non_empty = [c for c in row if c.value is not None]
        if len(non_empty) >= 3:
            header_row_num = row[0].row
            headers = [str(c.value).strip().replace("\n", " ") if c.value else ""
                       for c in row]
            break
    assert headers, "Could not detect header row in Jobs_Schedule"

    for row in ws.iter_rows(min_row=header_row_num + 1, values_only=True):
        if not any(v is not None for v in row):
            continue
        rdict = dict(zip(headers, row))
        if rdict.get("Customer Name / Company") == TEST_CUSTOMER_NAME:
            return rdict
    return None


# ---------------------------------------------------------------------------
# Test class — full contractor lifecycle, driven by natural language
# ---------------------------------------------------------------------------
@pytest.mark.job_sheet_e2e
class TestJobTrackerE2E:
    """
    One test method per lifecycle stage, in dependency order (pytest runs
    class methods in file order by default; -p no:randomly if you have
    pytest-randomly installed globally, to guarantee ordering here).

    Each test:
      1. Sends a natural-language prompt to Claude with the real tool schemas.
      2. Asserts Claude selected the RIGHT tool with the RIGHT key arguments
         (the eval layer).
      3. Executes that exact tool call against the real spreadsheet.
      4. Reads the spreadsheet back and asserts the RIGHT columns hold the
         RIGHT values (the correctness layer).
    """

    # Stashed across test methods within a session — the created JobID and
    # InvoiceID, since later stages need to reference what earlier stages made.
    job_id: str | None = None
    invoice_id: str | None = None

    def test_01_create_job(self, anthropic_client, tool_schemas, mcp_module,
                            pre_suite_backup_path):
        prompt = (
            f"Add a new job for {TEST_CUSTOMER_NAME}, 99 Test Ave, "
            "Ormond Beach FL 32174, service date 2026-09-11, window washing"
        )
        call = call_claude_tool(anthropic_client, tool_schemas, prompt)
        assert call is not None, "Claude called no tool for a create-job prompt"
        assert call.name == "create_job", f"Expected create_job, got {call.name}"
        updates = call.input.get("updates", {})
        assert TEST_CUSTOMER_NAME in str(updates.get(
            "Customer Name / Company", "")), \
            f"Customer name missing/wrong in Claude's tool call: {updates}"

        # Execute the exact call Claude proposed against the real spreadsheet
        result = mcp_module.create_job(updates=updates, backup=True)
        assert result.startswith("✅"), f"create_job failed: {result}"
        assert "NEW_JOB_ID=" in result, f"No JobID in result: {result}"
        TestJobTrackerE2E.job_id = result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()

        row = find_ztest_job(mcp_module)
        assert row is not None, "Test job not found after create_job"
        assert row["Street Address ★ AI Route"] == "99 Test Ave"
        assert row["State"] == "FL"
        assert row["ZIP ★ AI Route"] in (32174, "32174")

    def test_01b_create_job_lands_adjacent_to_real_data(self, mcp_module):
        """Regression test for the "next empty row" bug: create_job used to
        scan the WHOLE sheet for any row with any non-empty cell (any(c.value
        for c in row)), which a stray formatting artifact far below the real
        data (leftover fill/border, an empty-string ghost cell) could trip,
        landing the new job hundreds of rows below the last real one instead
        of immediately after it. The fix anchors on the last row that
        actually has a JobID value in the id column.

        This asserts the row number directly via openpyxl rather than just
        checking the data reads back correctly — read_job_spreadsheet()
        already skips blank rows, so a correctness-only check would not
        have caught this bug at all; it only manifests as a row-POSITION
        problem, which is exactly what a human opening the sheet in Excel
        actually noticed when this bug was first found.
        """
        import openpyxl
        wb = openpyxl.load_workbook(str(SPREADSHEET_PATH), data_only=True)
        ws = wb["Jobs_Schedule"]

        # Find the header row and the row JOB-0001 (or whatever the FIRST
        # real job is) sits on, then assert our new job is directly below it.
        header_row_idx = None
        for row in ws.iter_rows(min_row=1, max_row=5):
            non_empty = [c for c in row if c.value is not None]
            if len(non_empty) >= 3:
                header_row_idx = row[0].row
                break
        assert header_row_idx is not None

        first_job_row_idx = None
        our_job_row_idx = None
        for row in ws.iter_rows(min_row=header_row_idx + 1):
            val = row[0].value
            if val and str(val).startswith("JOB-"):
                if first_job_row_idx is None:
                    first_job_row_idx = row[0].row
                if val == self.job_id:
                    our_job_row_idx = row[0].row

        assert our_job_row_idx is not None, \
            f"Could not find {self.job_id} by scanning JobID column directly"
        # Allow the new job to be anywhere in the contiguous block of real
        # jobs — the key regression check is that it's NOT hundreds of rows
        # away. A generous but meaningful ceiling: within 5 rows of the
        # first real job, covering any small number of pre-existing rows.
        assert our_job_row_idx <= first_job_row_idx + 5, (
            f"REGRESSION: {self.job_id} landed at row {our_job_row_idx}, "
            f"but the first real job is at row {first_job_row_idx} — "
            f"the new row is not adjacent to real data. This is the "
            f"'any(c.value for c in row)' next-empty-row bug."
        )

    def test_02_schedule_detail_no_sheet_name(self, anthropic_client,
                                               tool_schemas, mcp_module):
        """Regression test for the sheet-default bug: the prompt gives
        Claude no reason to know or say which sheet — if update_job_spreadsheet
        silently falls back to Excel's arbitrary 'active sheet' instead of
        Jobs_Schedule, this call will error or write to the wrong place."""
        assert self.job_id, "test_01 must run first and set job_id"
        prompt = (
            f"Set the crew to Carlos R. on the {TEST_CUSTOMER_NAME} job, "
            "start time 8am, estimated duration 60 minutes"
        )
        call = call_claude_tool(anthropic_client, tool_schemas, prompt)
        assert call is not None
        assert call.name == "update_job_spreadsheet"
        assert not call.input.get("sheet_name"), (
            "Test expects Claude to omit sheet_name for a natural voice "
            "prompt — if this fails, Claude is compensating for a tool gap "
            "that should be fixed at the tool level, not worked around here."
        )

        result = mcp_module.update_job_spreadsheet(
            job_identifier=self.job_id,
            id_column="JobID (JOB-####)",
            updates=call.input["updates"],
        )
        assert result.startswith("✅"), (
            f"update_job_spreadsheet failed without sheet_name — "
            f"regression of the sheet-default bug: {result}"
        )

        row = find_ztest_job(mcp_module)
        assert row["Crew / Technician"] == "Carlos R."
        assert row["Est. Duration"] == 60

    def test_03_notes(self, anthropic_client, tool_schemas, mcp_module):
        prompt = f"Add a note to the {TEST_CUSTOMER_NAME} job: exterior only, gate code 4521"
        call = call_claude_tool(anthropic_client, tool_schemas, prompt)
        assert call is not None
        assert call.name == "update_job_spreadsheet"

        result = mcp_module.update_job_spreadsheet(
            job_identifier=self.job_id,
            id_column="JobID (JOB-####)",
            updates=call.input["updates"],
        )
        assert result.startswith("✅")

        row = find_ztest_job(mcp_module)
        notes = row.get("Service Details / Notes", "") or ""
        assert "4521" in notes, f"Gate code missing from notes: {notes!r}"

    def test_04_clock_in_out_populates_unit_from_blank(self, anthropic_client,
                                                         tool_schemas, mcp_module):
        """Regression test for TWO related bugs in one clock cycle:

        (a) Clock-out used to clobber Actual Duration Unit with the numeric
            elapsed_mins value (a substring-matching bug: "Actual" in col_name
            and "Duration" in col_name also matched "Actual Duration Unit").

        (b) After fixing (a), clock-out also never POPULATED Actual Duration
            Unit when it started out genuinely blank (the fix only stopped
            overwriting an existing value — a job that goes through its very
            first clock-in/out with no one ever having set the unit column
            manually would end up with a number but no unit label).

        This test deliberately does NOT pre-seed Actual Duration Unit before
        clocking — that was the original test's own bug, which is exactly
        what let (b) slip through the first manual test pass undetected.
        """
        row_before = find_ztest_job(mcp_module)
        assert not row_before.get("Actual Duration Unit"), (
            "Test setup assumption violated: Actual Duration Unit should "
            "start blank for this regression check to be meaningful — "
            "if a prior stage set it, this test isn't testing what it thinks."
        )

        in_call = call_claude_tool(
            anthropic_client, tool_schemas,
            f"Clock in for the {TEST_CUSTOMER_NAME} job")
        assert in_call is not None and in_call.name == "log_time_entry"
        assert in_call.input.get("action") == "start"
        mcp_module.log_time_entry(
            job_identifier=self.job_id, action="start")

        out_call = call_claude_tool(
            anthropic_client, tool_schemas,
            "Clock out — job's done")
        assert out_call is not None and out_call.name == "log_time_entry"
        assert out_call.input.get("action") == "stop"
        result = mcp_module.log_time_entry(
            job_identifier=self.job_id, action="stop")
        assert "Clocked OUT" in result

        row = find_ztest_job(mcp_module)
        assert row["Actual Duration Unit"] == "min", (
            f"REGRESSION: Actual Duration Unit not populated from blank — "
            f"got {row['Actual Duration Unit']!r}, expected 'min'"
        )

    def test_04b_second_clock_cycle_preserves_manual_unit(self, mcp_module):
        """Companion regression check: once a unit is set (by any means),
        a SECOND clock-out must not clobber it back to a number — this is
        the original clobber-bug check, kept distinct from test_04's
        populate-from-blank check so a future regression in either
        direction is unambiguous about which behavior broke."""
        mcp_module.update_job_spreadsheet(
            job_identifier=self.job_id,
            id_column="JobID (JOB-####)",
            updates={"Actual Duration Unit": "hour"},  # deliberately non-default
        )
        mcp_module.log_time_entry(job_identifier=self.job_id, action="start")
        mcp_module.log_time_entry(job_identifier=self.job_id, action="stop")

        row = find_ztest_job(mcp_module)
        assert row["Actual Duration Unit"] == "hour", (
            f"REGRESSION: a manually-set unit was clobbered on a later "
            f"clock-out — got {row['Actual Duration Unit']!r}, expected 'hour'"
        )
        # Restore to "min" so the remaining lifecycle stages / final audit
        # see the same value the rest of this suite expects.
        mcp_module.update_job_spreadsheet(
            job_identifier=self.job_id,
            id_column="JobID (JOB-####)",
            updates={"Actual Duration Unit": "min"},
        )

    def test_05_complete_job(self, anthropic_client, tool_schemas, mcp_module):
        prompt = (
            f"Mark the {TEST_CUSTOMER_NAME} job complete, "
            "quote was $125 with a $10 discount"
        )
        call = call_claude_tool(anthropic_client, tool_schemas, prompt)
        assert call is not None and call.name == "update_job_spreadsheet"

        result = mcp_module.update_job_spreadsheet(
            job_identifier=self.job_id,
            id_column="JobID (JOB-####)",
            updates=call.input["updates"],
        )
        assert result.startswith("✅")

        row = find_ztest_job(mcp_module)
        assert str(row["Job Status"]).lower() == "completed"
        assert float(row["Quote Amount ($)"]) == 125
        assert float(row["Discount Applied ($)"]) == 10

    def test_06_invoice(self, anthropic_client, tool_schemas, mcp_module):
        prompt = f"Invoice the {TEST_CUSTOMER_NAME} job"
        call = call_claude_tool(anthropic_client, tool_schemas, prompt)
        assert call is not None and call.name == "create_invoice"

        result = mcp_module.create_invoice(
            job_identifier=self.job_id)
        assert result.startswith("✅"), f"create_invoice failed: {result}"
        assert "NEW_INVOICE_ID=" in result
        TestJobTrackerE2E.invoice_id = (
            result.split("NEW_INVOICE_ID=")[1].splitlines()[0].strip())

        row = find_ztest_job(mcp_module)
        assert row["InvoiceID (INV-####)"] == self.invoice_id

    def test_07_payment_and_recurrence(self, anthropic_client, tool_schemas,
                                        mcp_module):
        for prompt, expect_key, expect_val in [
            (f"Mark the {TEST_CUSTOMER_NAME} invoice as paid",
             "Payment Status", "Paid"),
            (f"Make {TEST_CUSTOMER_NAME} a monthly recurring customer",
             "Recurrence", "Monthly"),
        ]:
            call = call_claude_tool(anthropic_client, tool_schemas, prompt)
            assert call is not None and call.name == "update_job_spreadsheet"
            result = mcp_module.update_job_spreadsheet(
                job_identifier=self.job_id,
                id_column="JobID (JOB-####)",
                updates=call.input["updates"],
            )
            assert result.startswith("✅"), f"{prompt!r} failed: {result}"

        row = find_ztest_job(mcp_module)
        assert row["Payment Status"] == "Paid"
        assert row["Recurrence"] == "Monthly"

    def test_08_final_readback_all_columns(self, mcp_module):
        """No Claude call here — just a direct final audit that every column
        we touched across the whole lifecycle still holds the right value,
        catching any cross-stage interference the individual stage
        assertions might have missed."""
        row = find_ztest_job(mcp_module)
        assert row is not None

        expected = {
            "Customer Name / Company": TEST_CUSTOMER_NAME,
            "Street Address ★ AI Route": "99 Test Ave",
            "City ★ AI Route": "Ormond Beach",
            "State": "FL",
            "Crew / Technician": "Carlos R.",
            "Actual Duration Unit": "min",
            "Job Status": "Completed",
            "Payment Status": "Paid",
            "Recurrence": "Monthly",
        }
        mismatches = {
            k: (v, row.get(k)) for k, v in expected.items() if row.get(k) != v
        }
        assert not mismatches, f"Column mismatches at final audit: {mismatches}"

    def test_09_restore_backup_on_full_pass(self, mcp_module,
                                             pre_suite_backup_path):
        """Only runs if every test above passed (pytest runs in file order
        and a prior failure would have already stopped -x runs; for
        non -x runs this still restores, matching 'restore on a full pass'
        as closely as a single-file pytest run can express — for strict
        all-or-nothing semantics, run this suite with -x).
        """
        import shutil
        assert pre_suite_backup_path.exists(), (
            f"Pre-suite backup missing: {pre_suite_backup_path}"
        )
        shutil.copy2(str(pre_suite_backup_path), str(SPREADSHEET_PATH))

        row = find_ztest_job(mcp_module)
        assert row is None, (
            "Restore did not remove the test job — spreadsheet still "
            "contains test data after restore"
        )
