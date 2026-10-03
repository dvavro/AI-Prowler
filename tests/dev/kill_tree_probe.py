"""Probe for run_script_kill (2026-10-01): does stopping a job stop the whole
process tree?  Harmless — only writes a heartbeat file in %TEMP%.

  python kill_tree_probe.py            parent: starts a child, waits forever
  python kill_tree_probe.py child      child: starts the grandchild, waits forever
  python kill_tree_probe.py grand      grandchild: writes its PID + time every 0.5 s
  python kill_tree_probe.py check      report: which probe processes are still alive,
                                       and whether the heartbeat is still moving
  python kill_tree_probe.py cleanup    force-stop any probe process still alive
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BEAT = Path(tempfile.gettempdir()) / "aiprowler_kill_tree_probe.json"
NOWIN = 0x08000000 if sys.platform == "win32" else 0


def _write(role):
    data = {}
    try:
        data = json.loads(BEAT.read_text(encoding="utf-8"))
    except Exception:
        pass
    data[role] = os.getpid()
    data[f"{role}_beat"] = time.time()
    BEAT.write_text(json.dumps(data), encoding="utf-8")


def _alive(pid):
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                         capture_output=True, text=True, creationflags=NOWIN).stdout
    return str(pid) in out


mode = sys.argv[1] if len(sys.argv) > 1 else "parent"

if mode in ("parent", "child"):
    if mode == "parent" and BEAT.exists():
        BEAT.unlink()
    _write(mode)
    nxt = "child" if mode == "parent" else "grand"
    subprocess.Popen([sys.executable, __file__, nxt], creationflags=NOWIN)
    while True:
        time.sleep(1)

elif mode == "grand":
    while True:
        _write("grand")
        time.sleep(0.5)

elif mode in ("check", "cleanup"):
    try:
        data = json.loads(BEAT.read_text(encoding="utf-8"))
    except Exception:
        print("no heartbeat file — probe never started")
        sys.exit(0)
    beat1 = data.get("grand_beat", 0)
    time.sleep(2.0)
    try:
        beat2 = json.loads(BEAT.read_text(encoding="utf-8")).get("grand_beat", 0)
    except Exception:
        beat2 = beat1
    any_alive = False
    for role in ("parent", "child", "grand"):
        pid = data.get(role)
        alive = bool(pid) and _alive(pid)
        any_alive |= alive
        print(f"{role:6} PID {pid}: {'STILL RUNNING' if alive else 'stopped'}")
        if mode == "cleanup" and alive:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, creationflags=NOWIN)
            print(f"        -> force-stopped by cleanup")
    moving = beat2 > beat1
    print(f"heartbeat: {'STILL MOVING (grandchild working)' if moving else 'stopped'}")
    print("RESULT: " + ("BUG — processes left running" if (any_alive or moving)
                        else "OK — whole tree stopped"))
