"""Dev helper: lines in a line range of a file matching a regex. ASCII output.
Usage: gui_text_grep.py <file> <start> <end> <regex>"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
f, a, b, rx = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), re.compile(sys.argv[4].replace("~", " "))
for n, line in enumerate((ROOT / f).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
    if a <= n <= b and rx.search(line):
        print(f"{n}: {line.strip()[:170]}".encode("ascii", "backslashreplace").decode("ascii"))
