"""Runs pytest with the given args in a sandbox state dir and prints the output
(tail). Helper for remote runs where run_tests.bat output is lost."""
import os, subprocess, sys, tempfile
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env = dict(os.environ)
env.setdefault("AIPROWLER_TEST_STATE_DIR", tempfile.mkdtemp(prefix="ai_prowler_test_"))
args = sys.argv[1:]
p = subprocess.run([sys.executable, "-m", "pytest", *args], cwd=root, env=env,
                   capture_output=True, text=True, encoding="utf-8", errors="replace")
out = (p.stdout or "") + (p.stderr or "")
lines = out.splitlines()
print("\n".join(lines[-150:]))
print("rc =", p.returncode)
