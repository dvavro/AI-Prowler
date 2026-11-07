"""Run only the Estimator tests.

    python tests\\estimator\\run_estimator_tests.py [extra pytest args]

Uses the AI-Prowler repo root as the working folder so `import estimator` works.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

if __name__ == "__main__":
    cmd = [sys.executable, "-m", "pytest", str(ROOT / "tests" / "estimator"), "-q", "-p", "no:cacheprovider",
           *sys.argv[1:]]
    sys.exit(subprocess.call(cmd, cwd=str(ROOT)))
