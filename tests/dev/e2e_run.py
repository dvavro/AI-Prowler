"""Dev helper: launch run_gui_jobs_e2e.py with arguments that contain spaces
or parentheses (which cmd.exe / whitespace-split launchers mangle).

Write '~' where a space belongs inside one argument:
    e2e_run.py --server --human --no-open -k SRV_FR_01~and~U1
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.join(os.path.dirname(HERE), "run_gui_jobs_e2e.py")
env = dict(os.environ)
args = []
for a in sys.argv[1:]:
    if a.startswith("ENV:") and "=" in a:          # ENV:E2E_SANDBOX_DATE=2030-01-07
        k, v = a[4:].split("=", 1)
        env[k] = v
    else:
        args.append(a.replace("~", " "))
sys.exit(subprocess.call([sys.executable, RUNNER, *args], env=env))
