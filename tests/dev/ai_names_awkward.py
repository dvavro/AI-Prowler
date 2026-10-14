"""Dev helper (2026-10-12): after ai_names.py — find awkward results such as
"Claude, Muse, or Grok AI", "... MCP", doubled names, "an Claude, Muse...". ASCII."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATS = [r"Claude, Muse, or Grok (AI|MCP|token|CLI|connector|Connector|chat|account)\b",
        r"\ban Claude, Muse, or Grok", r"Claude, Muse, or Grok, Muse", r"Grok's\w"]
files = list(ROOT.glob("*.py")) + [ROOT / f for f in ("jobs/index.html", "remote/index.html",
          "hr_admin/index.html", "hr_portal/index.html", "COMPLETE_USER_GUIDE.md", "README.md")]
for p in files:
    for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        for rx in PATS:
            m = re.search(rx, line)
            if m:
                print(f"{p.name}:{n}: [{m.group(0)}] {line.strip()[:120]}".encode("ascii", "backslashreplace").decode("ascii"))
                break
