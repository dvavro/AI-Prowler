"""Dev helper (2026-10-11): print each merge-conflict block (<<<<<<< ... >>>>>>>)
with line numbers and a few lines of context. ASCII output.
Usage: show_conflicts.py file1 [file2 ...]   (paths relative to the repo)"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CTX = 3
for rel in sys.argv[1:]:
    lines = (REPO / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    starts = [i for i, l in enumerate(lines) if l.startswith("<<<<<<< ")]
    print(f"\n######## {rel}: {len(starts)} conflict block(s)")
    for s in starts:
        e = next(i for i in range(s, len(lines)) if lines[i].startswith(">>>>>>> "))
        print(f"---- lines {s + 1}-{e + 1}")
        for i in range(max(0, s - CTX), min(len(lines), e + 1 + CTX)):
            print(f"{i + 1:6}: {lines[i][:200]}".encode("ascii", "backslashreplace").decode("ascii"))
