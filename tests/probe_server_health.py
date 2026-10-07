"""Measures whether the AI-Prowler server keeps answering while something
else runs: polls http://127.0.0.1:<port>/health every 0.5 s (2.5 s timeout —
the same check the desktop app's Running/Stopped LED makes) and writes one
line per check plus a summary to tests\\probe_server_health.out.txt.

    python probe_server_health.py [seconds=40] [port=8000]

Read-only: only ever GETs /health.
"""
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

secs = float(sys.argv[1]) if len(sys.argv) > 1 else 40
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
out = Path(__file__).with_name("probe_server_health.out.txt")
url = f"http://127.0.0.1:{port}/health"

lines, fails, worst, longest_gap, gap_start = [], 0, 0.0, 0.0, None
end = time.monotonic() + secs
while time.monotonic() < end:
    t0 = time.monotonic()
    stamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    try:
        with urllib.request.urlopen(url, timeout=2.5) as r:
            ms = (time.monotonic() - t0) * 1000
            worst = max(worst, ms)
            lines.append(f"{stamp} OK   {ms:7.0f} ms")
            if gap_start is not None:
                longest_gap = max(longest_gap, time.monotonic() - gap_start)
                gap_start = None
    except Exception as e:
        fails += 1
        lines.append(f"{stamp} FAIL {type(e).__name__}: {e}")
        if gap_start is None:
            gap_start = t0
    time.sleep(max(0.0, 0.5 - (time.monotonic() - t0)))
if gap_start is not None:
    longest_gap = max(longest_gap, time.monotonic() - gap_start)

summary = (f"SUMMARY checks={len(lines)} failed={fails} "
           f"slowest_ok={worst:.0f}ms longest_unanswered={longest_gap:.1f}s")
out.write_text("\n".join(lines + [summary]) + "\n", encoding="utf-8")
print(summary)
