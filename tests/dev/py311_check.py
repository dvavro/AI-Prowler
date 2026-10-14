"""Dev helper (2026-10-11, David: stay on Python 3.11 for now).
  1. every tracked .py compiles under THIS interpreter (3.11) — syntax
  2. no use of library features added in 3.12+ (scan)
  3. no launcher / installer / script pointing at another Python version
ASCII output."""
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def p(s=""):
    print(str(s).encode("ascii", "backslashreplace").decode("ascii"))


p(f"interpreter: {sys.version.split()[0]}  ({sys.executable})")
files = subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True,
                       encoding="utf-8").stdout.splitlines()

# 1. syntax
bad = []
for f in files:
    if f.endswith(".py"):
        try:
            compile((REPO / f).read_bytes(), f, "exec")
        except SyntaxError as e:
            bad.append(f"{f}:{e.lineno}: {e.msg}")
p(f"\n1. syntax under 3.11: {sum(f.endswith('.py') for f in files)} files, {len(bad)} fail")
for b in bad:
    p("   " + b)

# 2. 3.12+ library features
NEW = {
    r"\bitertools\.batched\b|from itertools import[^\n]*\bbatched\b": "itertools.batched (3.12)",
    r"\btyping\.override\b|from typing import[^\n]*\boverride\b": "typing.override (3.12)",
    r"\bPath\(.*\)\.walk\(|\.walk\(top_down": "Path.walk (3.12)",
    r"^\s*type\s+\w+\s*(\[.*\])?\s*=": "type alias statement (3.12)",
    r"^\s*(def|class)\s+\w+\[[A-Za-z_, ]+\]\s*[(:]": "generic [T] syntax (3.12)",
    r"\bsys\.monitoring\b": "sys.monitoring (3.12)",
    r"\bcalendar\.(JANUARY|Month|Day)\b": "calendar.Month/Day enums (3.12)",
    r"\bdatetime\.UTC\b": None,          # 3.11 has it — fine
}
hits = []
for f in files:
    if not f.endswith(".py"):
        continue
    for n, line in enumerate((REPO / f).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        for rx, what in NEW.items():
            if what and re.search(rx, line):
                hits.append(f"{f}:{n}: {what}: {line.strip()[:100]}")
p(f"\n2. 3.12+ library features: {len(hits)}")
for h in hits:
    p("   " + h)

# 3. other Python versions referenced by launchers / installer / scripts
VER = re.compile(r"(?i)python\s?3\.?(1[2-9])|Python3(1[2-9])\b|py\s+-3\.(1[2-9])|python_requires.*3\.(1[2-9])")
refs = []
for f in files:
    if f.endswith((".bat", ".cmd", ".ps1", ".iss", ".py", ".txt", ".toml", ".cfg", ".ini", ".json", ".md")):
        for n, line in enumerate((REPO / f).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if VER.search(line):
                refs.append(f"{f}:{n}: {line.strip()[:120]}")
p(f"\n3. references to Python 3.12+: {len(refs)}")
for r in refs[:40]:
    p("   " + r)
pins = [l.strip() for l in (REPO / "requirements.txt").read_text(encoding="utf-8", errors="replace").splitlines()
        if l.strip() and not l.startswith("#")] if (REPO / "requirements.txt").exists() else []
p(f"\nrequirements.txt: {len(pins)} entries; python markers: "
  + str([l for l in pins if "python_version" in l][:10] or "none"))
iss = (REPO / "AI-Prowler-Setup.iss").read_text(encoding="utf-8", errors="replace")
p("installer bundles: " + ", ".join(sorted(set(re.findall(r"python-3\.\d+\.\d+-amd64\.exe", iss)))))
