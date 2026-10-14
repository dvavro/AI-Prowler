"""2026-10-12 follow-up: ai_names.py looked one line at a time, so a product
name split across a line break or two string pieces — e.g.
    "... to use Claude "
    "Code CLI ..."
became "Claude, Muse, or Grok" + "Code CLI". Put those back to "Claude".
Also: the Claude-token email's "anyone with it can use your ... subscription".
Prints each fix. ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
N = "Claude, Muse, or Grok"
PRODUCT = r"(?:Code|Desktop|Pro\b|Max\b|CLI|token|\.ai|phone app|desktop app|subscription)"
# N, then optional closing quote, newline, optional comment marker / opening quote, then the product word
RX = re.compile(re.escape(N) + r"(\s*[\"']?\s*\n\s*(?:#\s*|//\s*)?(?:[rfbuRFBU]{0,2}[\"'])?\s*)(" + PRODUCT + r")")
files = list(ROOT.glob("*.py")) + [ROOT / f for f in (
    "jobs/index.html", "remote/index.html", "hr_admin/index.html", "hr_portal/index.html",
    "COMPLETE_USER_GUIDE.md", "README.md")]
total = 0
for p in files:
    raw = p.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    s = raw.replace("\r\n", "\n")
    hits = []

    def rep(m):
        hits.append((s.count("\n", 0, m.start()) + 1, m.group(2)))
        return "Claude" + m.group(1) + m.group(2)
    new = RX.sub(rep, s)
    if hits:
        if p.suffix == ".py":
            compile(new, str(p), "exec")
        p.write_bytes(new.replace("\n", nl).encode("utf-8"))
        total += len(hits)
        for ln, w in hits:
            print(f"{p.name}:{ln}: '{N}' + '{w}' -> 'Claude {w}'")
print(f"fixed {total}")
