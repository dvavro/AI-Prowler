"""Dev helper (2026-10-11): sanity checks on the merged tree.
  * every tracked .py compiles
  * the inline JavaScript of every web app (jobs, remote, hr, hr_admin, hr_portal)
    parses with node
  * no merge markers anywhere in tracked text files
ASCII output."""
import os
import py_compile
import re
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def p(s):
    print(str(s).encode("ascii", "backslashreplace").decode("ascii"))


tracked = subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True,
                         encoding="utf-8").stdout.splitlines()
bad_py = []
for f in tracked:
    if f.endswith(".py"):
        try:
            # in memory — py_compile's cfile=os.devnull fails on Windows ("nul")
            compile((REPO / f).read_bytes(), f, "exec")
        except Exception as e:
            bad_py.append(f"{f}: {str(e)[:200]}")
p(f"python: {sum(f.endswith('.py') for f in tracked)} files, {len(bad_py)} failed")
for b in bad_py:
    p("  " + b)

markers = []
for f in tracked:
    if f.endswith((".py", ".html", ".js", ".md", ".bat", ".json", ".txt", ".iss", ".ini")):
        try:
            t = (REPO / f).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if re.search(r"^(<<<<<<< |>>>>>>> )", t, re.M):
            markers.append(f)
p(f"merge markers left: {markers or 'none'}")

for app in ("jobs", "remote", "hr", "hr_admin", "hr_portal"):
    for page in sorted((REPO / app).glob("*index*.html")) if (REPO / app).is_dir() else []:
        html = re.sub(r"<!--.*?-->", "", page.read_text(encoding="utf-8", errors="replace"), flags=re.S)
        blocks = [b for b in re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S | re.I) if b.strip()]
        bad = 0
        for js in blocks:
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
                fh.write(js)
                name = fh.name
            r = subprocess.run(["node", "--check", name], capture_output=True, text=True)
            os.unlink(name)
            if r.returncode:
                bad += 1
                p(f"  {page.relative_to(REPO)}: {r.stderr.strip().splitlines()[-1][:200] if r.stderr.strip() else 'error'}")
        p(f"js: {page.relative_to(REPO)} — {len(blocks)} block(s), {bad} with errors")
