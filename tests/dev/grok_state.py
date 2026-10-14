"""Dev helper (2026-10-12): where do Grok / Muse / api_agent_runner / runner
appear now (after David's own edits)? File mtimes + matching lines. ASCII."""
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = ["task_queue_automation.py", "rag_gui.py", "api_agent_runner.py", "ai_prowler_mcp.py",
         "COMPLETE_USER_GUIDE.md", "update_install.bat", "AI-Prowler-Setup.iss"]
RX = re.compile(r"(?i)grok|muse|api_agent_runner|\"runner\"|runner_model|xai|x\.ai")
for f in FILES:
    p = ROOT / f
    if not p.exists():
        print(f"\n== {f}: MISSING")
        continue
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    hits = [(i + 1, l.strip()) for i, l in enumerate(lines) if RX.search(l)]
    print(f"\n== {f}  modified {time.strftime('%m-%d %H:%M', time.localtime(p.stat().st_mtime))}  "
          f"{len(hits)} hit(s)")
    if f in ("rag_gui.py", "ai_prowler_mcp.py", "COMPLETE_USER_GUIDE.md"):
        hits = [h for h in hits if re.search(r"(?i)api.?key|runner|x\.ai|console\.x|api_agent", h[1])]
    for n, l in hits[:40]:
        print(f"  {n:6}: {l[:150]}".encode("ascii", "backslashreplace").decode("ascii"))
    if len(hits) > 40:
        print(f"  ... {len(hits) - 40} more")
