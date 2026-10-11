"""Dev helper (2026-10-11): does tests\\gui_jobs_e2e_server\\users.local.json hold
real secrets? Prints the KEY structure and, per value, only whether it looks like
an env-var NAME or like a token/password (length + character mix) — never the
value itself. Also: is it on GitHub's main, and is it identical to ours?"""
import json
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
F = REPO / "tests" / "gui_jobs_e2e_server" / "users.local.json"


def describe(v):
    if not isinstance(v, str):
        return type(v).__name__
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", v):
        return "looks like an ENV-VAR NAME"
    if v.startswith("http"):
        return "a URL"
    if len(v) >= 20 and re.search(r"[A-Za-z]", v) and re.search(r"\d", v):
        return f"LOOKS LIKE A SECRET ({len(v)} chars)"
    return f"text ({len(v)} chars)"


def walk(x, path=""):
    if isinstance(x, dict):
        for k, v in x.items():
            walk(v, f"{path}.{k}" if path else k)
    elif isinstance(x, list):
        for i, v in enumerate(x):
            walk(v, f"{path}[{i}]")
    else:
        print(f"  {path}: {describe(x)}")


data = json.loads(F.read_text(encoding="utf-8"))
print("structure (values hidden):")
walk(data)


def git(*a):
    return subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True).stdout.strip()


rel = "tests/gui_jobs_e2e_server/users.local.json"
print("\nin origin/main:", "yes" if git("ls-tree", "origin/main", rel) else "no")
print("first committed:", git("log", "--diff-filter=A", "--format=%h %ad %an", "--date=short", "--", rel) or "?")
print("local file differs from last commit:", "yes" if git("diff", "--name-only", "--", rel) else "no")
