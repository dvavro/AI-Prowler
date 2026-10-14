"""Dev helper: sleep N s, then print the last pytest progress line, any FAILED/ERROR
lines and the final summary of a job log. Usage: wait_progress.py <log> [N=200]"""
import re
import sys
import time

time.sleep(int(sys.argv[2]) if len(sys.argv) > 2 else 200)
text = re.sub(r"\x1b\[[0-9;]*m", "", open(sys.argv[1], encoding="utf-8", errors="replace").read())
lines = text.splitlines()
prog = [l for l in lines if re.search(r"\[\s*\d+%\]$", l)]
bad = [l for l in lines if re.search(r"(FAILED|ERROR) ", l) and "::" in l]
tail = [l for l in lines if re.search(r"Tests: \d+ passed|AI-Prowler Jobs app E2E — |=+ .*(passed|failed)", l)]
for l in (prog[-1:] + bad + tail):
    print(l[:300].encode("ascii", "backslashreplace").decode("ascii"))
