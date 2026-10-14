"""2026-10-12 follow-up to ai_names.py:
  * Claude-CLI-specific lines go back to "Claude": per-user Claude CLI tokens,
    AI Routing / analysis runs (Claude Code CLI), /login, billing — including a
    regex that matches the Claude CLI's own output ("No Claude token is saved")
  * "Claude, Muse, or Grok AI" -> "Claude, Muse, or Grok"
  * "Claude, Muse, or Grok MCP" -> "MCP (Claude, Muse, or Grok)"
Prints what changed per file. ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
N = "Claude, Muse, or Grok"
CLI_WORDS = re.compile(r"token|\bCLI\b|/login|Claude Code|AI Routing|billed|claude -p", re.I)
files = [p for p in ROOT.glob("*.py")] + [ROOT / f for f in (
    "jobs/index.html", "remote/index.html", "hr_admin/index.html", "hr_portal/index.html",
    "COMPLETE_USER_GUIDE.md", "README.md")]
for p in files:
    raw = p.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.replace("\r\n", "\n").split("\n")
    reverted = tidied = 0
    for i, l in enumerate(lines):
        if N not in l:
            continue
        if CLI_WORDS.search(l):
            lines[i] = l.replace("Claude/Muse/Grok's", "Claude's").replace(N, "Claude")
            reverted += 1
            continue
        new = l.replace(N + " AI", N).replace(N + " MCP", "MCP (" + N + ")")
        if new != l:
            lines[i] = new
            tidied += 1
    if reverted or tidied:
        out = "\n".join(lines)
        if p.suffix == ".py":
            compile(out, str(p), "exec")
        p.write_bytes(out.replace("\n", nl).encode("utf-8"))
        print(f"{p.name}: {reverted} Claude-specific line(s) reverted, {tidied} tidied")
