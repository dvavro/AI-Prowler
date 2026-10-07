"""Does nothing but wait (default 15 s) — used with probe_server_health.py to
show whether a waiting run_script call freezes the server."""
import sys
import time

s = float(sys.argv[1]) if len(sys.argv) > 1 else 15
time.sleep(s)
print(f"slept {s} s")
