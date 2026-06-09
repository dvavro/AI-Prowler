"""
Installer script tests — tests/installer/test_installer_scripts.py

Runs the PowerShell installer test harness (Test-SeedUserGuideTracking.ps1)
as a single pytest test so it integrates with the main suite and release gate.

Why PowerShell via subprocess rather than pure Python:
  The SeedUserGuideTracking procedure in AI-Prowler-Setup.iss is an Inno Setup
  Pascal procedure that emits a PowerShell script at install time. The only
  faithful way to test that embedded PowerShell is to run it AS PowerShell.
  A Python reimplementation would test a translation, not the real thing.

Skipped automatically on non-Windows platforms (powershell.exe not present).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PS_SCRIPT = Path(__file__).parent / "Test-SeedUserGuideTracking.ps1"


def _powershell_available() -> bool:
    """Return True if powershell.exe can be found on this machine."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "exit 0"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Installer scripts are Windows-only (Inno Setup / PowerShell)",
)
class TestInstallerScripts:
    """Wrapper tests that delegate to the PowerShell harness."""

    def test_seed_user_guide_tracking(self):
        """
        Runs Test-SeedUserGuideTracking.ps1 and asserts it exits 0 (all pass).

        Covers five scenarios inside the script:
          A - Fresh install (no tracking file)
          B - Reinstall preserving existing tracked directories
          C - Idempotent re-run (guide already listed)
          D - Corrupt JSON file (must not crash)
          E - Legacy backslash paths (must not duplicate the guide entry)

        If the script exits non-zero, the full PowerShell output is included
        in the pytest failure message so you can see exactly which scenario
        failed without needing to re-run manually.
        """
        if not _powershell_available():
            pytest.skip("powershell.exe not found on PATH")

        assert PS_SCRIPT.exists(), (
            f"PowerShell test script not found: {PS_SCRIPT}\n"
            "Expected it at tests/installer/Test-SeedUserGuideTracking.ps1"
        )

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(PS_SCRIPT),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Always print output so it appears in pytest -v and in CI logs
        # even when the test passes (helps with diagnosing flaky runs).
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)

        assert result.returncode == 0, (
            "Test-SeedUserGuideTracking.ps1 reported failures.\n"
            "See the captured output above for the specific scenarios that failed.\n"
            f"Exit code: {result.returncode}"
        )
