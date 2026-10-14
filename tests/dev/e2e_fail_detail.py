"""Dev helper: the failure sections of an E2E run log (ANSI stripped), one per
failed test, last N lines each. Usage: e2e_fail_detail.py <run.log> [N]"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
log = (ROOT / sys.argv[1]).read_text(encoding="utf-8", errors="replace")
n = int(sys.argv[2]) if len(sys.argv) > 2 else 14
log = re.sub(r"\x1b\[[0-9;]*m", "", log)
for m in re.finditer(r"_{5,} (test_\S+) _{5,}\n(.*?)(?=\n_{5,} test_|\n=+ short test summary|\Z)", log, re.S):
    lines = [l for l in m.group(2).splitlines() if l.strip()]
    keep = [l for l in lines if l.startswith("E ")][:n]
    src = [l for l in lines if re.match(r"^tests[\\/].*\.py:\d+:", l) or re.match(r"^gui_jobs_e2e[\\/].*\.py:\d+", l)]
    keep += src[-2:]
    print(f"\n### {m.group(1)}")
    for l in keep:
        print("   " + l[:220].encode("ascii", "backslashreplace").decode("ascii"))
