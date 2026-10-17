"""Dev helper (2026-10-16): run the two HR isolation e2e tests the way their
docstrings say (py -m pytest ... -m e2e), NOT through run_tests.bat (the
tests\\e2e conftest refuses to run with AIPROWLER_TEST_STATE_DIR set). Each test
starts its own ai_prowler_mcp.py subprocess on a random free port with its OWN
sandbox AIPROWLER_TEST_STATE_DIR and test_mode -- never the live HR data.
ASCII output only."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
env = {k: v for k, v in os.environ.items() if k != "AIPROWLER_TEST_STATE_DIR"}
cmd = [sys.executable, "-m", "pytest",
       "tests/e2e/test_hr_isolation_e2e.py", "tests/e2e/test_hr_isolation_server_mode_e2e.py",
       "-m", "e2e", "-q", "-p", "no:cacheprovider", "--color=no"]
p = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True,
                   encoding="utf-8", errors="replace", timeout=900)
out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
print(out[-12000:].encode("ascii", "backslashreplace").decode())
print("exit code:", p.returncode)
sys.exit(p.returncode)
