"""
tests/mcp_tests/test_log_time_entry_identity.py — RETIRED 2026-09-14
========================================================================
This file was openpyxl-based (built a real .xlsx fixture and passed it
to log_time_entry via filepath=) and tested ambiguous-match rejection
and server-mode crew identity/ownership scoping before the Job Board
Architecture Spec's SQLite migration. Since log_time_entry is now
DB-backed, the fixture here never connected to the tool at all -- every
test degenerated into "No job found" regardless of what the fixture
contained.

Coverage moved to:
  - tests/mcp_tests/test_db_log_time_entry_identity.py -- ambiguous-match
    rejection with candidates, exact-match success, server-mode crew
    stamping (caller's own name, not the job's pre-assigned crew),
    second-user-can-start-own-entry, same-user-double-start-blocked,
    cannot-stop-coworker's-open-entry, personal-mode unaffected, and
    actual-duration writeback -- all against the real
    db_write_ops.db_log_time_entry.
  - tests/mcp_tests/test_log_time_entry_isolated.py -- field-writing/GPS
    mechanics (clock-in fields, elapsed calculation, duplicate-clock-in
    blocking, map-URL hyperlinks).

Original content preserved at
tests/mcp_tests/test_log_time_entry_identity.py.bak1 for reference.
"""
