"""grep across live source files only (no .bak*, no artifacts). Usage: grep_live.py PATTERN [--tests]"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
pat = re.compile(sys.argv[1])
with_tests = "--tests" in sys.argv
exts = {".py", ".js", ".html", ".bat", ".iss", ".md", ".json"}
for p in sorted(ROOT.rglob("*")):
    if not p.is_file() or p.suffix not in exts or ".bak" in p.name or "artifacts" in p.parts:
        continue
    rel = p.relative_to(ROOT)
    if (rel.parts[0] == "tests") != with_tests and not (with_tests and rel.parts[0] != "tests"):
        continue
    if rel.parts[0] in ("node_modules", ".git", "venv", "build", "dist"):
        continue
    try:
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if pat.search(line):
                print(f"{rel}:{i}: {line.strip()[:160]}")
    except OSError:
        pass
