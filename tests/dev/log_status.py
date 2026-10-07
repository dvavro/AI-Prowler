"""Read-only diagnostic (2026-10-02): why didn't mcp_server.log rotate?

Prints the last few server starts recorded in mcp_server.log, its newest
lines, and every running python process whose command line mentions
ai_prowler_mcp / rag_gui (PID, start time, command line).
"""
import json
import subprocess
from collections import deque
from pathlib import Path

LOG = Path.home() / ".ai-prowler" / "logs" / "mcp_server.log"

starts, tail = deque(maxlen=6), deque(maxlen=8)
with open(LOG, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        if "Entry point: transport=" in line:
            starts.append(line.rstrip()[:160])
        tail.append(line.rstrip()[:160])
print("=== last server starts in mcp_server.log ===")
for s in starts:
    print("  " + s)
print("\n=== newest lines in mcp_server.log ===")
for s in tail:
    print("  " + s)

ps = ("Get-CimInstance Win32_Process | "
      "Select-Object ProcessId,ParentProcessId,Name,CreationDate,CommandLine | ConvertTo-Json -Compress")
out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                     capture_output=True, text=True, timeout=90).stdout.strip()
print("\n=== running AI-Prowler python processes (and who started them) ===")
try:
    rows = json.loads(out) if out else []
    rows = rows if isinstance(rows, list) else [rows]
except Exception:
    rows = []
    print("  (could not read the process list)")
by_pid = {r.get("ProcessId"): r for r in rows}


def _when(r):
    import datetime as _dt
    import re as _re
    m = _re.search(r"(\d+)", str(r.get("CreationDate") or ""))
    return _dt.datetime.fromtimestamp(int(m.group(1)) / 1000).strftime("%Y-%m-%d %H:%M") if m else "?"


def _short(cmd):
    import re as _re
    return _re.sub(r"(--token\s+)\S+", r"\1<hidden>", cmd or "")[:200]   # never print the token


for r in rows:
    cmd = r.get("CommandLine") or ""
    if "ai_prowler_mcp" in cmd or "rag_gui" in cmd:
        print(f"\n  PID {r.get('ProcessId')}  started {_when(r)}  {r.get('Name')}")
        print(f"      {_short(cmd)}")
        p, depth = by_pid.get(r.get("ParentProcessId")), 0
        while p is not None and depth < 4:
            print(f"      {'  ' * depth}└ started by PID {p.get('ProcessId')} {p.get('Name')} "
                  f"({_when(p)}): {_short(p.get('CommandLine'))}")
            p, depth = by_pid.get(p.get("ParentProcessId")), depth + 1
        if r.get("ParentProcessId") not in by_pid:
            print(f"      └ started by PID {r.get('ParentProcessId')} — no longer running")
