"""grep an absolute-path file for a regex, print matches (ANSI stripped, ASCII, up to 400 chars)."""
import re
import sys

text = re.sub(r"\x1b\[[0-9;]*m", "", open(sys.argv[1], encoding="utf-8", errors="replace").read())
rx = re.compile(sys.argv[2].replace("~", " "))
for i, l in enumerate(text.splitlines(), 1):
    if rx.search(l):
        print(f"{i}: {l[:400]}".encode("ascii", "backslashreplace").decode("ascii"))
