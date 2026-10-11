"""Syntax-check every inline <script> in an HTML page with `node --check`.

Default page: jobs\\index.html (the Jobs app). Usage:
    python tests\\check_jobs_js.py [path\\to\\page.html]
Prints one line per script block and exits 1 on any syntax error.
(node --check does not catch a misplaced </div> — see test_pwa_sheet.py.)
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
page = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "jobs" / "index.html"
html = page.read_text(encoding="utf-8")
blocks = [(m.start(), m.group(2)) for m in
          # a real tag starts its own line; this skips "<script>" mentioned
          # inside an HTML comment's prose
          re.finditer(r"^[ \t]*<script(?![^>]*\bsrc=)([^>]*)>(.*?)</script>", html, re.S | re.I | re.M)
          if "json" not in m.group(1).lower()]
bad = 0
with tempfile.TemporaryDirectory() as td:
    for i, (pos, code) in enumerate(blocks):
        line = html.count("\n", 0, pos) + 1
        f = Path(td) / f"block{i}.js"
        f.write_text(code, encoding="utf-8")
        r = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
        if r.returncode:
            bad += 1
            err = r.stderr.strip()[:1500].encode("ascii", "replace").decode()
            print(f"FAIL script block {i} (starts at {page.name}:{line}):\n{err}")
        else:
            print(f"OK   script block {i} (starts at {page.name}:{line}) - {code.count(chr(10))} lines")
print(f"{len(blocks)} block(s), {bad} with syntax errors")
sys.exit(1 if bad else 0)
