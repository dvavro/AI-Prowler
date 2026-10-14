"""2026-10-12: undo ai_names.py where "Claude" was part of CODE inside a long
string — e.g. the Claude Desktop launcher's app id "...!Claude" and the
PowerShell filter "*Claude*". Heuristic: the phrase touching code punctuation
(! * \\ = _ $ { } [ ] < >  or a quote that isn't prose). Prints every fix.
ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
N = "Claude, Muse, or Grok"
RX = re.compile(r"(?<=[!*\\=_${\[<>])" + re.escape(N) + r"|" + re.escape(N) + r"(?=[*_!\\$}\]<>])")
files = list(ROOT.glob("*.py")) + [ROOT / f for f in (
    "jobs/index.html", "remote/index.html", "hr_admin/index.html", "hr_portal/index.html")]
total = 0
for p in files:
    raw = p.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    s = raw.replace("\r\n", "\n")
    hits = [s.count("\n", 0, m.start()) + 1 for m in RX.finditer(s)]
    if not hits:
        continue
    new = RX.sub("Claude", s)
    if p.suffix == ".py":
        compile(new, str(p), "exec")
    p.write_bytes(new.replace("\n", nl).encode("utf-8"))
    total += len(hits)
    for ln in hits:
        line = new.splitlines()[ln - 1].strip()[:130]
        print(f"{p.name}:{ln}: {line}".encode("ascii", "backslashreplace").decode("ascii"))
print(f"fixed {total}")
