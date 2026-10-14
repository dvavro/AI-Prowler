"""Dev helper: regex search across *.py files under a folder (relative to the work copy).
Usage: grep_tree.py <folder> <regex>   ('~' = space). ASCII output."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
rx = re.compile(sys.argv[2].replace("~", " "))
for p in sorted((ROOT / sys.argv[1]).rglob("*.py")):
    if "artifacts" in p.parts or "__pycache__" in p.parts:
        continue
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        continue
    for n, line in enumerate(lines, 1):
        if rx.search(line):
            s = f"{p.relative_to(ROOT)}:{n}: {line.strip()[:170]}"
            print(s.encode("ascii", "backslashreplace").decode("ascii"))
