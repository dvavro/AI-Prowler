"""2026-10-12: more code-like spots where the rename could have landed:
"Claude, Muse, or Grok" directly followed by .ext / ( / a closing quote that ends
a short string, or inside a comparison (==, in, startswith). Read-only. ASCII."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
N = re.escape("Claude, Muse, or Grok")
PATS = [N + r"\.(exe|lnk|json|log|app|dll)\b", N + r"\(", r"(==|!=|\bin\b|startswith\(|endswith\(|find\()\s*[\"']" + N,
        r"[\"']" + N + r"[\"']", N + r"[\"']\s*(in|==|!=|\))"]
for p in list(ROOT.glob("*.py")) + [ROOT / f for f in ("jobs/index.html", "remote/index.html",
                                                       "hr_admin/index.html", "hr_portal/index.html")]:
    for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if any(re.search(rx, line) for rx in PATS):
            print(f"{p.name}:{n}: {line.strip()[:140]}".encode("ascii", "backslashreplace").decode("ascii"))
