"""Dev helper: node --check every inline <script> in jobs\\index.html."""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
APP = sys.argv[1] if len(sys.argv) > 1 else "jobs"          # "jobs" or "remote"
html = open(os.path.join(ROOT, APP, "index.html"), encoding="utf-8").read()
html = re.sub(r"<!--.*?-->", "", html, flags=re.S)          # comments may mention <script>
blocks = [m.group(1) for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S | re.I)]
blocks = [b for b in blocks if b.strip()]
bad = 0
for i, js in enumerate(blocks):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(js)
        p = f.name
    r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
    os.unlink(p)
    if r.returncode:
        bad += 1
        print(f"block {i}: SYNTAX ERROR\n{r.stderr[-1500:]}")
print(f"{len(blocks)} inline script block(s), {bad} with errors")
sys.exit(1 if bad else 0)
