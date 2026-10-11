"""Dev helper: sleep N seconds (default 90) — a short pause between status checks."""
import sys
import time

time.sleep(int(sys.argv[1]) if len(sys.argv) > 1 else 90)
print("ok")
