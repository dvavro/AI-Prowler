"""Dev helper: print line numbers of a literal text in files (no index needed).
Usage: find_text.py "needle" file1 [file2 ...]   (paths relative to the work copy)
Output is ASCII (emoji etc. printed as \\U escapes) — the job console can't
print them and would drop the output."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
needle = sys.argv[1]
for f in sys.argv[2:]:
    for n, line in enumerate((ROOT / f).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if needle in line:
            s = f"{f}:{n}: {line.strip()[:160]}"
            print(s.encode("ascii", "backslashreplace").decode("ascii"))
