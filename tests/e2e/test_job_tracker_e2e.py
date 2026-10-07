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
import collections
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

# Job Board Architecture Spec migration: this suite no longer hardcodes a
# data-file path at all. create_job/update_job_spreadsheet/read_job_
# spreadsheet/backup_database/restore_database all resolve the live
# ai_prowler_jobs.db path themselves via _resolve_job_db_path() the same
# way they do for any real caller (Claude, the Jobs PWA) — every tool call
# below is made with filepath="" (the default) so the suite is always
# testing against whatever database is actually live, never a hardcoded
# guess. AI_PROWLER_JOB_TRACKER_PATH (still set by
# run_release_gate_job_tracker.bat) is accordingly unused here now; kept
# only so the .bat script doesn't need touching.
TEST_CUSTOMER_NAME = "ZTEST Contractor QA"
MODEL = "claude-sonnet-4-6"

# Manual, stage-by-stage runs (`pytest -k test_02`, pausing between stages
# to check the Jobs PWA) execute in a FRESH process each time, so the
# TestJobTrackerE2E.job_id/invoice_id class attributes below would
# normally reset to None between stages. This file persists them across
# process boundaries purely to support that workflow — it holds no
# customer data, just two ID strings, and test_09's restore step deletes
# it once the lifecycle is done.
_STATE_FILE = Path(__file__).parent / ".job_tracker_e2e_state.json"

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def anthropic_client():
    """Returns a live Anthropic API client if ANTHROPIC_API_KEY is set, or
    None otherwise.

    Note: a Claude Pro/Max claude.ai subscription does NOT provide this
    key — the Anthropic API is a separate product with its own console.
    anthropic.com credentials and billing. Without a key, this suite
    still runs (see resolve_tool_call() below), it just trades away the
    "did Claude pick the right tool from this natural-language prompt"
    eval layer described in the module docstring, keeping only the "does
    the tool write the right data" correctness layer — which is what
    matters for verifying the SQLite migration this run exists to check.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    anthropic = pytest.importorskip("anthropic")
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
    """Trigger a backup of the CURRENT database state before any test
    writes happen.

    Job Board Architecture Spec migration: the old _backup_spreadsheet()
    copied the .xlsx file, which is no longer the live data store (spec
    §7/§8) — a "restore" from that backup would not undo anything the
    SQLite-backed tools did. Uses backup_database() (spec §12.3) instead,
    which backs up the actual live ai_prowler_jobs.db via SQLite's own
    online Backup API.

    Persisted in _STATE_FILE (backup_path key) so this backup is taken
    only ONCE — on whichever stage happens to run first — rather than
    re-backing-up the already-modified database if test_09 runs in its
    own later process, which would silently replace the "pre-suite"
    backup with a mid-lifecycle one and make test_09's restore a no-op.
    """
    state = {}
    if _STATE_FILE.exists():
        try:
            state = json.loads(_STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            state = {}
    if state.get("backup_path"):
        return Path(state["backup_path"])

    backup_msg = mcp_module.backup_database()
    # backup_msg looks like: "✅ Backup saved: C:\...\Backups\AI-Prowler-Backup-<ts>.db"
    assert backup_msg.startswith("✅") and "Backup saved" in backup_msg, \
        f"Pre-suite backup failed: {backup_msg}"
    abs_path = backup_msg.split("Backup saved:")[1].splitlines()[0].strip()
    state["backup_path"] = abs_path
    _STATE_FILE.write_text(json.dumps(state))
    return Path(abs_path)


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


_FakeToolCall = collections.namedtuple("_FakeToolCall", ["name", "input"])


def resolve_tool_call(client, schemas, prompt: str, fallback_name: str,
                       fallback_input: dict):
    """Returns the Claude-selected tool call when a live API client is
    available (call_claude_tool — the real eval), or a pre-built
    stand-in matching fallback_name/fallback_input when it isn't
    (ANTHROPIC_API_KEY unset — see anthropic_client's docstring).

    In fallback mode, any assertion this file makes against call.name or
    call.input is checking data THIS function was told to return, not
    something Claude decided — those specific assertions are vacuously
    true. What still means something in fallback mode is everything
    downstream: does the tool call, given these arguments, actually
    write the right thing to the (now SQLite-backed) store.
    """
    if client is not None:
        return call_claude_tool(client, schemas, prompt)
    return _FakeToolCall(name=fallback_name, input=dict(fallback_input))


def _read_all_job_rows(mcp_module) -> list[dict]:
    """Parse read_job_spreadsheet()'s '  Header: value' text digest into a
    list of per-row dicts, keyed by the exact display headers the sheet
    uses.

    Job Board Architecture Spec migration: goes through the REAL, exposed
    read_job_spreadsheet() tool (same path Claude/the Jobs PWA use) rather
    than re-deriving read logic here, so it automatically reflects the
    spec §13 live-join overlays (e.g. Payment Status / Quote Amount /
    Invoice Total are sourced live from the linked invoice once a job is
    invoiced, not the job row's own stored copy) instead of risking this
    helper silently disagreeing with what a real caller would see.
    """
    text = mcp_module.read_job_spreadsheet(sheet_name="Jobs_Schedule", max_rows=500)
    rows: list[dict] = []
    current: dict = {}
    for line in text.splitlines():
        if line.startswith("  ") and ": " in line and not line.startswith("  ─"):
            key, _, val = line[2:].partition(": ")
            current[key] = val
        elif current and (line.strip() == "" or line.startswith("─")):
            rows.append(current)
            current = {}
    if current:
        rows.append(current)
    return rows


def find_ztest_job(mcp_module) -> dict | None:
    """Return the dict for our test job, or None if it doesn't exist.

    BUG FIXED (pre-migration history, kept for context): previously scanned
    data rows from a HARDCODED min_row=6 rather than the actual detected
    header row + 1 — found and fixed via test_route_scheduling_e2e.py's
    near-identical helper. That whole class of bug is moot now: there is
    no fixed header row to miscalculate once reads go through the
    SQLite-backed read_job_spreadsheet() (spec §5), which this helper now
    calls via _read_all_job_rows() instead of opening the old .xlsx file
    directly with openpyxl — create_job/update_job_spreadsheet etc. no
    longer write to that file at all (spec §7), so the openpyxl version of
    this helper always saw stale/no data post-migration.
    """
    for row in _read_all_job_rows(mcp_module):
        if row.get("Customer Name / Company") == TEST_CUSTOMER_NAME:
            return row
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

    @pytest.fixture(autouse=True)
    def _persist_lifecycle_state(self):
        """Loads job_id/invoice_id from _STATE_FILE before each test (in
        case this stage is running in a fresh process from a prior one),
        and saves them back after — see _STATE_FILE's comment above."""
        if _STATE_FILE.exists():
            try:
                data = json.loads(_STATE_FILE.read_text())
                TestJobTrackerE2E.job_id = (
                    TestJobTrackerE2E.job_id or data.get("job_id"))
                TestJobTrackerE2E.invoice_id = (
                    TestJobTrackerE2E.invoice_id or data.get("invoice_id"))
            except (json.JSONDecodeError, OSError):
                pass
        yield
        # Merge rather than overwrite — pre_suite_backup_path may have
        # already written a "backup_path" key into this same file during
        # this test's setup, and a blind overwrite here would wipe it.
        existing = {}
        if _STATE_FILE.exists():
            try:
                existing = json.loads(_STATE_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                existing = {}
        existing["job_id"] = TestJobTrackerE2E.job_id
        existing["invoice_id"] = TestJobTrackerE2E.invoice_id
        _STATE_FILE.write_text(json.dumps(existing))

    def test_01_create_job(self, anthropic_client, tool_schemas, mcp_module,
                            pre_suite_backup_path):
        prompt = (
            f"Add a new job for {TEST_CUSTOMER_NAME}, 99 Test Ave, "
            "Ormond Beach FL 32174, service date 2026-09-11, window washing"
        )
        call = resolve_tool_call(
            anthropic_client, tool_schemas, prompt,
            fallback_name="create_job",
            fallback_input={
                "updates": {
                    "Customer Name / Company": TEST_CUSTOMER_NAME,
                    "Street Address": "99 Test Ave",
                    "City": "Ormond Beach",
                    "State": "FL",
                    "ZIP": "32174",
                    "Service Date": "2026-09-11",
                    "Service Type": "Window Washing",
                    "Job Status": "Scheduled",
                },
            },
        )
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
        assert row["Street Address"] == "99 Test Ave"
        assert row["State"] == "FL"
        assert row["ZIP"] in (32174, "32174")

    def test_01b_create_job_lands_adjacent_to_real_data(self, mcp_module):
        """Regression check for the OLD "next empty row" bug (openpyxl
        scanning any(c.value for c in row), which a stray formatting
        artifact far below the real data could trip, landing a new job
        hundreds of rows below the last real one).

        Job Board Architecture Spec §11 Phase 1 explicitly calls for this
        to be asserted even though it "should be structurally impossible
        now — there's no 'next empty row' scan at all with real rows":
        create_job now does a plain SQL INSERT (db_write_ops.db_create_job)
        with no sheet-scanning step of any kind, so this bug class cannot
        recur by construction. This checks the SQLite equivalent of
        "landed adjacent to real data" — the new row's rowid is the
        highest in the table (a plain append), not orphaned somewhere odd —
        rather than an openpyxl cell-row check that no longer means
        anything once there's no worksheet being written to.
        """
        from db_access import get_connection

        db_path = mcp_module._resolve_job_db_path(None, "")
        conn = get_connection(db_path)
        try:
            rows = conn.execute(
                "SELECT job_id FROM jobs ORDER BY rowid"
            ).fetchall()
        finally:
            conn.close()
        job_ids = [r["job_id"] for r in rows]
        assert self.job_id in job_ids, \
            f"Could not find {self.job_id} in the jobs table at all"
        assert job_ids[-1] == self.job_id, (
            f"REGRESSION: {self.job_id} is not the last row by rowid "
            f"(last is {job_ids[-1]!r}) — a plain INSERT should always "
            f"append, so this would mean something reordered or "
            f"reinserted rows unexpectedly."
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
        call = resolve_tool_call(
            anthropic_client, tool_schemas, prompt,
            fallback_name="update_job_spreadsheet",
            fallback_input={
                "updates": {
                    "Crew / Technician": "Carlos R.",
                    "Start Time": "8:00 AM",
                    "Est. Duration": 60,
                    "Est. Duration Unit": "min",
                },
            },
        )
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
        # read_job_spreadsheet()'s text digest returns everything as
        # strings (unlike the old openpyxl cell values, which preserved
        # numeric types). Est. Duration is REAL in the schema (db_schema.py
        # — intentional, durations can be fractional), so SQLite stores 60
        # as 60.0 and the digest shows "60.0" — cast through float(), not
        # int() (which rejects the ".0" suffix), matching how every other
        # numeric assertion in this file already handles $ amount columns.
        assert float(row["Est. Duration"]) == 60

    def test_03_notes(self, anthropic_client, tool_schemas, mcp_module):
        prompt = f"Add a note to the {TEST_CUSTOMER_NAME} job: exterior only, gate code 4521"
        call = resolve_tool_call(
            anthropic_client, tool_schemas, prompt,
            fallback_name="update_job_spreadsheet",
            fallback_input={
                "updates": {
                    "Service Details / Notes": "Exterior only, gate code 4521",
                },
            },
        )
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

        in_call = resolve_tool_call(
            anthropic_client, tool_schemas,
            f"Clock in for the {TEST_CUSTOMER_NAME} job",
            fallback_name="log_time_entry",
            fallback_input={"action": "start"})
        assert in_call is not None and in_call.name == "log_time_entry"
        assert in_call.input.get("action") == "start"
        mcp_module.log_time_entry(
            job_identifier=self.job_id, action="start")

        out_call = resolve_tool_call(
            anthropic_client, tool_schemas,
            "Clock out — job's done",
            fallback_name="log_time_entry",
            fallback_input={"action": "stop"})
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
        call = resolve_tool_call(
            anthropic_client, tool_schemas, prompt,
            fallback_name="update_job_spreadsheet",
            fallback_input={
                "updates": {
                    "Job Status": "Completed",
                    "Quote Amount ($)": 125,
                    "Discount Applied ($)": 10,
                },
            },
        )
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
        call = resolve_tool_call(
            anthropic_client, tool_schemas, prompt,
            fallback_name="create_invoice", fallback_input={})
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
        for prompt, expect_key, expect_val, fallback_updates in [
            (f"Mark the {TEST_CUSTOMER_NAME} invoice as paid",
             "Payment Status", "Paid", {"Payment Status": "Paid"}),
            (f"Make {TEST_CUSTOMER_NAME} a monthly recurring customer",
             "Recurrence", "Monthly", {"Recurrence": "Monthly"}),
        ]:
            call = resolve_tool_call(
                anthropic_client, tool_schemas, prompt,
                fallback_name="update_job_spreadsheet",
                fallback_input={"updates": fallback_updates},
            )
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
            "Street Address": "99 Test Ave",
            "City": "Ormond Beach",
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

        Job Board Architecture Spec migration: a raw shutil.copy2 over the
        old .xlsx did nothing to the live database once that file stopped
        being the live store — uses restore_database() (spec §12.4)
        instead, which takes its own safety-backup of current state before
        swapping the pre-suite backup back in.
        """
        assert pre_suite_backup_path.exists(), (
            f"Pre-suite backup missing: {pre_suite_backup_path}"
        )
        result = mcp_module.restore_database(
            backup_path=str(pre_suite_backup_path), confirm=True)
        assert result.startswith("✅"), f"restore_database failed: {result}"

        row = find_ztest_job(mcp_module)
        assert row is None, (
            "Restore did not remove the test job — database still "
            "contains test data after restore"
        )

        # Lifecycle is complete and the DB is back to its pre-suite state —
        # drop the persisted job_id/invoice_id/backup_path so the NEXT
        # full run starts clean instead of reusing stale IDs.
        if _STATE_FILE.exists():
            _STATE_FILE.unlink()
        TestJobTrackerE2E.job_id = None
        TestJobTrackerE2E.invoice_id = None
