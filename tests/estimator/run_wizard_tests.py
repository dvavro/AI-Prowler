"""Run AI-Prowler's own Setup wizard and GUI tests (the files the Estimator's Sprint 16 hooks touch).

    python tests\\estimator\\run_wizard_tests.py [extra pytest args]
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"

if __name__ == "__main__":
    pats = [a for a in sys.argv[1:] if a.endswith(".py")] or [
        "test_setup*.py", "unit/test_setup*.py", "gui/test_setup*.py", "unit/test_*wizard*.py", "unit/test_*switch*.py",
        "unit/test_tool_config*.py"]
    sys.argv = [sys.argv[0]] + [a for a in sys.argv[1:] if not a.endswith(".py")]
    picks = sorted({str(p) for pat in pats
                    for p in TESTS.glob(pat)})
    print("Running:", *[Path(p).relative_to(ROOT) for p in picks], sep="\n  ", flush=True)
    cmd = [sys.executable, "-m", "pytest", *picks, "-q", "-p", "no:cacheprovider", "--color=no", *sys.argv[1:]]
    sys.exit(subprocess.call(cmd, cwd=str(ROOT)))
