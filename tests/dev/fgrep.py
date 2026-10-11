"""Dev helper: regex grep over files on disk (not the search index).
Usage: fgrep.py <regex> <dir-or-file> [glob=*.py]   ('~' = space in the regex)
Skips .bak files and artifacts folders. ASCII-safe output."""
import pathlib
import re
import sys

pat = re.compile(sys.argv[1].replace("~", " "), re.I)
root = pathlib.Path(sys.argv[2])
glob = sys.argv[3] if len(sys.argv) > 3 else "*.py"
files = [root] if root.is_file() else sorted(root.rglob(glob))
n = 0
for f in files:
    if not root.is_file() and ("artifacts" in f.parts or ".bak" in f.name):
        continue
    try:
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        continue
    for i, line in enumerate(lines, 1):
        if pat.search(line):
            print(f"{f}:{i}: {line.strip()[:200]}".encode("ascii", "replace").decode())
            n += 1
            if n >= 300:
                sys.exit(0)
