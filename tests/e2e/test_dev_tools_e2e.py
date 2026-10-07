"""
tests/e2e/test_dev_tools_e2e.py
=================================
Phase 3a of the broader MCP tool E2E suite (see run_e2e_mcp_tool.bat and
tests/pytest.ini's mcp_tool_e2e marker docs for the full phased plan).

Covers the Dev tools family:
  syntax_check, compile_check, check_python_import, lint_check,
  run_script, run_script_start, run_script_status, run_script_kill

SAFETY MODEL
------------
Creates one dedicated sandbox directory (_e2e_sandbox_dev_tools) under the
already-writable/tracked work directory. Every script/file used by this
suite lives only inside that sandbox and is deleted at the end — nothing
here ever touches real project files.

run_script/run_script_start execute real code, by design (that is what
these tools are for) — every script used here is a small, deliberately
inert Python one-liner (print a marker string, or sleep briefly for the
run_script_kill test) with no filesystem or network side effects outside
the sandbox itself.

REQUIREMENTS
------------
No ANTHROPIC_API_KEY needed.

RUN
---
  run_e2e_mcp_tool.bat -k dev_tools
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

import pytest

INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))
WRITABLE_TEST_DIR = Path(os.environ.get(
    "AI_PROWLER_WRITABLE_TEST_DIR",
    r"C:\Users\david\AI-Prowler-V900_to_V910_work\AI-Prowler",
))
SANDBOX = WRITABLE_TEST_DIR / "_e2e_sandbox_dev_tools"

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


@pytest.fixture(scope="session", autouse=True)
def _sandbox_lifecycle():
    SANDBOX.mkdir(parents=True, exist_ok=True)
    yield
    shutil.rmtree(SANDBOX, ignore_errors=True)


@pytest.mark.mcp_tool_e2e
class TestDevTools:

    job_id: "str | None" = None

    def test_01_syntax_check_valid_python(self, mcp_module):
        target = SANDBOX / "valid_syntax.py"
        target.write_text("x = 1\nprint(x)\n", encoding="utf-8")
        result = mcp_module.syntax_check(filepath=str(target))
        assert "✅" in result, f"syntax_check failed on valid file: {result}"

    def test_02_syntax_check_invalid_python(self, mcp_module):
        target = SANDBOX / "invalid_syntax.py"
        target.write_text("x = (\n", encoding="utf-8")  # unclosed paren
        result = mcp_module.syntax_check(filepath=str(target))
        assert "❌" in result, (
            f"syntax_check should have flagged invalid syntax: {result}"
        )

    def test_03_compile_check(self, mcp_module):
        target = SANDBOX / "valid_syntax.py"
        result = mcp_module.compile_check(filepath=str(target))
        assert "✅" in result, f"compile_check failed: {result}"

    def test_04_check_python_import(self, mcp_module):
        target = SANDBOX / "importable_module.py"
        target.write_text(
            "TEST_MARKER = 'ztest_e2e_dev_tools'\n", encoding="utf-8")
        result = mcp_module.check_python_import(module_or_path=str(target))
        assert "✅" in result or "import OK" in result, (
            f"check_python_import failed on a trivially importable module: {result}"
        )

    def test_05_lint_check(self, mcp_module):
        # Deliberately includes an unused import — pyflakes should flag it.
        target = SANDBOX / "lint_target.py"
        target.write_text(
            "import os\nx = 1\nprint(x)\n", encoding="utf-8")
        result = mcp_module.lint_check(filepath=str(target))
        assert "❌" not in result or "os" in result.lower(), (
            f"lint_check gave an unexpected result for an unused-import "
            f"file: {result}"
        )

    def test_06_run_script_basic(self, mcp_module):
        target = SANDBOX / "print_marker.py"
        target.write_text(
            "print('ZTEST_E2E_DEV_TOOLS_MARKER')\n", encoding="utf-8")
        result = mcp_module.run_script(script_path=str(target), timeout_sec=15)
        assert "ZTEST_E2E_DEV_TOOLS_MARKER" in result, (
            f"run_script did not capture expected output: {result}"
        )

    def test_07_run_script_start_and_status(self, mcp_module):
        target = SANDBOX / "background_job.py"
        target.write_text(
            "import time\n"
            "print('ZTEST_E2E_BACKGROUND_START')\n"
            "time.sleep(2)\n"
            "print('ZTEST_E2E_BACKGROUND_DONE')\n",
            encoding="utf-8",
        )
        start_result = mcp_module.run_script_start(
            script_path=str(target), timeout_sec=30)
        assert "Job started" in start_result or "job_id" in start_result.lower(), (
            f"run_script_start did not report a started job: {start_result}"
        )
        import re
        m = re.search(r"id:\s*(\S+)", start_result)
        assert m, f"Could not parse job_id from: {start_result}"
        TestDevTools.job_id = m.group(1)

        # Poll briefly for completion rather than a fixed sleep.
        status_result = ""
        for _ in range(10):
            status_result = mcp_module.run_script_status(job_id=self.job_id)
            if "DONE" in status_result or "ZTEST_E2E_BACKGROUND_DONE" in status_result:
                break
            time.sleep(1)
        assert "ZTEST_E2E_BACKGROUND_DONE" in status_result, (
            f"Background job did not complete as expected: {status_result}"
        )

    def test_08_run_script_kill(self, mcp_module):
        target = SANDBOX / "long_running.py"
        target.write_text(
            "import time\n"
            "print('ZTEST_E2E_LONGRUN_START')\n"
            "time.sleep(60)\n"
            "print('ZTEST_E2E_LONGRUN_SHOULD_NOT_PRINT')\n",
            encoding="utf-8",
        )
        start_result = mcp_module.run_script_start(
            script_path=str(target), timeout_sec=90)
        import re
        m = re.search(r"id:\s*(\S+)", start_result)
        assert m, f"Could not parse job_id from: {start_result}"
        job_id = m.group(1)

        time.sleep(1.5)  # let it actually start before killing
        kill_result = mcp_module.run_script_kill(job_id=job_id)
        assert "kill" in kill_result.lower() or "✅" in kill_result, (
            f"run_script_kill did not report success: {kill_result}"
        )

        status_result = mcp_module.run_script_status(job_id=job_id)
        assert "ZTEST_E2E_LONGRUN_SHOULD_NOT_PRINT" not in status_result, (
            "REGRESSION: killed job continued running to completion — "
            "run_script_kill did not actually terminate it"
        )
