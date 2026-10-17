"""Dev check (2026-10-16): every inline <script> block in hr_admin/index.html
and hr_portal/index.html must parse (node --check). ASCII output only."""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
bad = 0
for rel in ("hr_admin/index.html", "hr_portal/index.html"):
    html = (ROOT / rel).read_text(encoding="utf-8")
    blocks = [m.group(1) for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S)]
    for i, js in enumerate(blocks):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
            f.write(js)
            path = f.name
        r = subprocess.run(["node", "--check", path], capture_output=True, text=True, encoding="utf-8", errors="replace")
        Path(path).unlink(missing_ok=True)
        if r.returncode != 0:
            bad += 1
            print(f"FAIL {rel} script #{i}:")
            print("   " + (r.stderr or "")[-900:].encode("ascii", "backslashreplace").decode().replace("\n", "\n   "))
    print(f"{rel}: {len(blocks)} inline scripts checked")
print("ALL OK" if not bad else f"{bad} script(s) failed")
sys.exit(1 if bad else 0)
