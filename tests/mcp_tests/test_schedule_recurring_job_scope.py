"""
tests/mcp_tests/test_schedule_recurring_job_scope.py — RETIRED 2026-09-14
========================================================================
This file was openpyxl-based (built a real .xlsx fixture and patched
_get_default_spreadsheet_path) and tested schedule_next_recurring_job's
ambiguous-match rejection, crew scoping, and `when` date-scoping before
the Job Board Architecture Spec's SQLite migration. Since
schedule_next_recurring_job is now DB-backed, the fixture here never
connected to the tool at all -- every test degenerated into "No job
found" regardless of what the fixture contained.

Coverage moved to:
  - tests/mcp_tests/test_db_route_ops_phase1.py -- ambiguous-match rejection,
    no-match rejection, date-range/`when`-equivalent restriction, and
    field_crew scoping, against the real db_schedule_next_recurring_job.
    Also gained the frequency-math coverage this file's sibling class
    (TestScheduleNextRecurringJobExpandedFrequencies, in
    tests/unit/test_contractor_tools.py) used to provide: Weekly,
    Biweekly, Monthly, Bi-Monthly, Semi-Annually, Annually, and
    month-end-overflow capping.
  - tests/mcp_tests/test_schedule_recurring_job_phase1_mcp_wiring.py --
    MCP-layer wiring: path resolution, personal vs. server mode, and
    the ctx-derived crew-scoping decision.

Original content preserved at
tests/mcp_tests/test_schedule_recurring_job_scope.py.bak1 for reference.
"""
