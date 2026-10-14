"""Dev helper (2026-10-11): per conflict block — line range, how many lines each
side has, and the first few lines of each side. ASCII output.
Usage: conflict_summary.py file [head_lines]"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
rel = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 6
lines = (REPO / rel).read_text(encoding="utf-8", errors="replace").splitlines()
i, k = 0, 0
while i < len(lines):
    if lines[i].startswith("<<<<<<< "):
        s = i
        m = next(j for j in range(s, len(lines)) if lines[j].startswith("======="))
        e = next(j for j in range(m, len(lines)) if lines[j].startswith(">>>>>>> "))
        k += 1
        ours, theirs = lines[s + 1:m], lines[m + 1:e]
        print(f"\n### block {k}: lines {s + 1}-{e + 1}  OURS={len(ours)} lines  THEIRS={len(theirs)} lines")
        print("  context before:", lines[s - 1][:150].encode("ascii", "backslashreplace").decode("ascii"))
        print("  -- OURS head:")
        for l in ours[:n]:
            print("     " + l[:170].encode("ascii", "backslashreplace").decode("ascii"))
        print("  -- THEIRS head:")
        for l in theirs[:n]:
            print("     " + l[:170].encode("ascii", "backslashreplace").decode("ascii"))
        print("  context after:", (lines[e + 1][:150] if e + 1 < len(lines) else "").encode("ascii", "backslashreplace").decode("ascii"))
        i = e + 1
    else:
        i += 1
print(f"\n{k} block(s)")
