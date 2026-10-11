"""One-off (2026-10-10): toast() in remote\\index.html sets textContent, so HTML
entities in toast messages show literally ("&#9989; ..."). Replace the entities in
toast(...) calls with the real characters. Prints each changed line (ASCII-escaped)."""
import html
import re
from pathlib import Path

f = Path(__file__).resolve().parents[2] / "remote" / "index.html"
src = f.read_text(encoding="utf-8")
out, n = [], 0
for line in src.split("\n"):
    if "toast(" in line and "&#" in line:
        new = re.sub(r"&#\d+;", lambda m: html.unescape(m.group(0)), line)
        if new != line:
            n += 1
            print(new.strip()[:140].encode("ascii", "backslashreplace").decode("ascii"))
            line = new
    out.append(line)
f.write_text("\n".join(out), encoding="utf-8")
print("lines changed:", n)
