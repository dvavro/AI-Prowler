"""2026-10-11 (David): retire the original /hr/ app — `git rm -r hr/` (5 files:
index.html, manifest.json, sw.js, 2 icons). Recoverable from git history.
Refuses if hr/ holds anything unexpected. ASCII output."""
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
expected = {"icon-192.png", "icon-512.png", "index.html", "manifest.json", "sw.js"}
have = {p.name for p in (REPO / "hr").iterdir()} if (REPO / "hr").is_dir() else set()
assert have == expected, f"hr/ holds {sorted(have)} — stopping"
r = subprocess.run(["git", "-C", str(REPO), "rm", "-r", "-q", "hr"], capture_output=True, text=True)
print("git rm -r hr:", "ok" if r.returncode == 0 else r.stderr.strip())
print("hr/ still on disk:", (REPO / "hr").exists())
