"""
Service Desk multi-user E2E (Playwright + Microsoft Edge) — runner.

  py tests\\run_desk_e2e.py             HUMAN mode (default): visible browsers, slowed
                                        clicks, key-by-key typing — watch it happen
  py tests\\run_desk_e2e.py --fast      headless, full speed (unattended runs)
  py tests\\run_desk_e2e.py -k S1       one scenario

Starts two throwaway AI-Prowler servers (Business and Solo) in temp folders —
your real tickets, email and SMS are never touched (outgoing messages are
caught in a file). Runs outside run_tests.bat on purpose, like the HR e2e
suite, because each server gets its own sandbox state folder. Output streams
line by line so a long human-speed run shows progress.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
args = sys.argv[1:]
env = {k: v for k, v in os.environ.items() if k != "AIPROWLER_TEST_STATE_DIR"}
env["PYTHONIOENCODING"] = "utf-8"
env["PYTHONUNBUFFERED"] = "1"
if "--fast" in args:
    args.remove("--fast")
    env["DESK_E2E_FAST"] = "1"
args = [a.replace("~", " ") for a in args]
cmd = [sys.executable, "-u", "-m", "pytest", "tests/e2e/desk", "-m", "e2e", "-v", "-p", "no:cacheprovider",
       "-p", "no:randomly", "--color=no", "--tb=short", "-x" if "--stop" in args else "-q0", *[a for a in args if a != "--stop"]]
cmd = [c for c in cmd if c != "-q0"]
print("Running:", " ".join(cmd), flush=True)
p = subprocess.Popen(cmd, cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     text=True, encoding="utf-8", errors="replace")
for line in p.stdout:
    print(line.rstrip("\n").encode("ascii", "replace").decode("ascii"), flush=True)
sys.exit(p.wait())
