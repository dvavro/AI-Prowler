r"""
tests/e2e/conftest.py
=======================
Guard fixture specific to the job_sheet_e2e suites in this directory.

These suites (test_job_tracker_e2e.py, test_contractor_workflow_e2e.py,
test_route_scheduling_e2e.py, test_job_tracker_remaining_tools_e2e.py) are
DELIBERATELY different from the rest of AI-Prowler's test suite: they are
designed to exercise the REAL installed ai_prowler_mcp.py against the REAL
configured spreadsheet and REAL email config -- sending a real invoice/
receipt email, writing real (synthetic-customer) rows, etc. That's the
whole point of a release-gate suite: prove the real thing works, not a
mock of it.

They are ALSO unrelated to, and must never be confused with, the
Cloudflare-tunnel-minting "e2e" marker used elsewhere in this test suite
(see run_tests.bat's own header comments) -- that marker mints real
licenses and creates real Cloudflare tunnels that need manual cleanup.
This directory happens to hold BOTH kinds of tests, which is exactly why
these suites are invoked ONLY via run_e2e_mcp_tool.bat (see repo root),
never via run_tests.bat or a bare `-m e2e`.

The rest of AI-Prowler's test suite (tests/mcp_tests/, tests/unit/, etc.)
correctly sandboxes ~/.ai-prowler by default (AIPROWLER_TEST_STATE_DIR,
set by run_tests.bat) so automated tests can never touch real credentials
or production state. That sandboxing is exactly wrong for these suites,
which need the real state to mean anything.

PROBLEM THIS GUARDS AGAINST
-----------------------------
If a job_sheet_e2e suite is accidentally invoked THROUGH run_tests.bat
instead of run_e2e_mcp_tool.bat, AIPROWLER_TEST_STATE_DIR silently
redirects ~/.ai-prowler to an empty temp directory for the whole pytest
session -- which breaks these suites in a confusing way: email_receipt()
fails with "Email not configured" even though real email IS configured,
because it's reading from the sandboxed (empty) directory instead. This
happened once during this project's own development and looked like a
wall of real regressions until the actual cause (env var sandboxing, not
a code bug) was traced down.

This fixture fails fast and clearly the moment that's detected, using a
plain print + os._exit rather than pytest.fail() -- pytest.fail() raised
from inside a session-scoped autouse fixture was found to crash pytest's
own fixture-teardown machinery ("assert not self._finalizers"), burying
the real message under a wall of unrelated internal errors instead of
showing it.

CORRECT WAY TO RUN THESE SUITES
-----------------------------------
  run_e2e_mcp_tool.bat                (repo root -- runs all 4 files)
  run_e2e_mcp_tool.bat -k email       (keyword filter, same as pytest -k)
"""
import os

import pytest


@pytest.fixture(autouse=True, scope="session")
def _job_sheet_e2e_requires_real_state():
    sandbox_dir = os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
    if sandbox_dir:
        # pytest.exit() aborts the WHOLE session cleanly and prints the
        # reason through pytest's own reporting — unlike the os._exit(1)
        # this used before, which bypassed stdout/stderr flushing entirely
        # and made a correctly-firing guard look exactly like a silent
        # hang (confirmed the hard way: a real run showed the first test's
        # name printed, then nothing — no error, no PASSED/FAILED, no
        # explanation — because the process was killed before any of this
        # message ever reached the terminal).
        pytest.exit(
            "\n\n"
            "*** job_sheet_e2e/mcp_tool_e2e suites cannot run with "
            "AIPROWLER_TEST_STATE_DIR set ***\n"
            f"    AIPROWLER_TEST_STATE_DIR = {sandbox_dir!r}\n\n"
            "These suites intentionally use REAL AI-Prowler state (email config,\n"
            "the real job tracker spreadsheet, the real knowledge base) to prove\n"
            "the actual installed tools work -- that env var sandboxes\n"
            "~/.ai-prowler to an empty temp directory, which breaks email/SMS/\n"
            "indexing-dependent tests with a confusing 'not configured' error\n"
            "or an apparent hang, rather than a real regression.\n\n"
            "This almost always means these tests were invoked THROUGH\n"
            "run_tests.bat (which used to set this var unconditionally for\n"
            "every run) instead of the dedicated runner:\n\n"
            "    run_e2e_mcp_tool.bat\n\n"
            "(repo root -- never run job_sheet_e2e/mcp_tool_e2e tests via "
            "run_tests.bat)",
            returncode=1,
        )
