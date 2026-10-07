"""
Small wrapper so run_script_start (whose cwd is the tracked parent dir, not
the AI-Prowler source root tests\\run_tests.bat expects) can still invoke
pytest correctly. Usage:
    py scripts\\_run_pytest_from_root.py <pytest args...>
Runs `py -m pytest <args>` with cwd forced to the AI-Prowler source root
(this script's own parent directory), then prints stdout/stderr and exits
with pytest's real exit code.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

args = sys.argv[1:]
proc = subprocess.run(
    [sys.executable, "-m", "pytest"] + args,
    cwd=ROOT,
    capture_output=True,
    text=True,
)
sys.stdout.write(proc.stdout)
sys.stderr.write(proc.stderr)
sys.exit(proc.returncode)
