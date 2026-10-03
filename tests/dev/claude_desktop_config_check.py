"""Read-only (2026-10-03): which MCP servers is Claude Desktop told to start?

Looks for claude_desktop_config.json in both places Claude Desktop keeps it —
the normal install (%APPDATA%\\Claude) and the Microsoft Store / MSIX install
(%LOCALAPPDATA%\\Packages\\Claude_*\\LocalCache\\Roaming\\Claude) — and lists
each "mcpServers" entry. Anything after --token / in env is hidden.
"""
import glob
import json
import os
import re

paths = [os.path.expandvars(r"%APPDATA%\Claude\claude_desktop_config.json")]
paths += glob.glob(os.path.expandvars(
    r"%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\claude_desktop_config.json"))


def hide(s):
    return re.sub(r"(--token[ =])\S+", r"\1<hidden>", str(s))


found = False
for p in paths:
    if not os.path.exists(p):
        print(f"(not present) {p}")
        continue
    found = True
    st = os.stat(p)
    import datetime as dt
    print(f"\n=== {p}\n    last changed {dt.datetime.fromtimestamp(st.st_mtime):%Y-%m-%d %H:%M}, {st.st_size} bytes")
    raw = open(p, encoding="utf-8-sig").read()
    try:
        cfg = json.loads(raw)
    except Exception as e:
        print(f"    NOT valid JSON: {e}")
        continue
    servers = cfg.get("mcpServers") or {}
    print(f"    mcpServers entries: {len(servers)}")
    for name, s in servers.items():
        cmd = s.get("command", "")
        args = " ".join(hide(a) for a in s.get("args", []))
        env = ", ".join(f"{k}=<hidden>" for k in (s.get("env") or {}))
        print(f"    - {name!r}: {cmd} {args}" + (f"   env: {env}" if env else ""))
    # the same key twice in the raw text is silently collapsed by json.loads
    keys = re.findall(r'"([^"]+)"\s*:\s*\{\s*"command"', raw)
    dupes = {k for k in keys if keys.count(k) > 1}
    if dupes:
        print(f"    !! listed more than once in the raw file: {sorted(dupes)}")
    others = [k for k in cfg if k != "mcpServers"]
    if others:
        print(f"    other settings: {others}")
if not found:
    print("\nNo Claude Desktop settings file found.")
