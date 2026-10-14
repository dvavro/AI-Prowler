"""Dev helper: list the actions recorded in a Playwright trace.zip (method, params, error).
Usage: trace_actions.py <trace.zip relative to work copy> [filter]"""
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
z = zipfile.ZipFile(ROOT / sys.argv[1])
flt = sys.argv[2].replace("~", " ") if len(sys.argv) > 2 else ""
for name in z.namelist():
    if not name.endswith(".trace"):
        continue
    for line in z.read(name).decode("utf-8", "replace").splitlines():
        try:
            ev = json.loads(line)
        except Exception:
            continue
        t = ev.get("type")
        if t == "before":
            s = f"{ev.get('startTime', 0):.0f} BEFORE {ev.get('callId')} {ev.get('class')}.{ev.get('method')} {json.dumps(ev.get('params'))[:200]}"
        elif t == "after":
            s = f"{ev.get('endTime', 0):.0f} AFTER {ev.get('callId')} err={json.dumps(ev.get('error'))[:300] if ev.get('error') else ''}"
        elif t in ("console", "log"):
            s = f"{t.upper()} {json.dumps(ev)[:300]}"
        else:
            continue
        if flt and flt not in s:
            continue
        print(s.encode("ascii", "backslashreplace").decode("ascii"))
