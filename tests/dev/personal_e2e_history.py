"""Dev helper: past personal Jobs-app E2E runs — date, sandbox date, pass/fail
counts — from tests/gui_jobs_e2e/artifacts/*/SUMMARY.txt (or run.log)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "tests" / "gui_jobs_e2e" / "artifacts"
rows = []
for d in sorted(p for p in ROOT.iterdir() if p.is_dir()):
    f = d / "SUMMARY.txt"
    if not f.exists():
        f = d / "run.log"
    if not f.exists():
        continue
    t = f.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"Tests: (\d+) passed, (\d+) failed, (\d+) skipped", t)
    s = re.search(r"Sandbox date: (\S+)", t)
    k = re.search(r"-k (\S+)", t)
    if m:
        rows.append((d.name, s.group(1) if s else "?", int(m.group(1)), int(m.group(2)), int(m.group(3))))
for r in rows[-25:]:
    print(f"{r[0]}  sandbox={r[1]:10}  passed={r[2]:4} failed={r[3]:3} skipped={r[4]}")
