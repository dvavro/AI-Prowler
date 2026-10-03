"""
tests/mcp_tests/test_read_job_spreadsheet_crew_scope.py — RETIRED 2026-09-14
========================================================================
This file was openpyxl-based (built a real .xlsx fixture and patched
_get_default_spreadsheet_path) and tested read_job_spreadsheet's crew-
scoping logic before the Job Board Architecture Spec's SQLite migration.
Since read_job_spreadsheet is now DB-backed, the fixture here never
connected to the tool at all -- every test degenerated into "No rows
found" regardless of what the fixture contained.

Coverage moved to:
  - tests/mcp_tests/test_db_read_ops_phase2.py -- field_crew sees only own
    jobs, blank-crew-row exclusion, crew scope never applies to
    Customers, owner sees all, date filtering (single day, multi-day
    range, today keyword) -- all against the real db_read_job_spreadsheet.
  - tests/unit/test_contractor_tools.py::TestCrewNameInCell -- exact
    match, comma-separated multi-crew lists, whitespace tolerance,
    case-insensitivity, and blank handling, as a direct unit test of
    the shared _crew_name_in_cell() helper that db_read_job_spreadsheet
    itself calls.

Original content preserved at
tests/mcp_tests/test_read_job_spreadsheet_crew_scope.py.bak1 for reference.
"""
