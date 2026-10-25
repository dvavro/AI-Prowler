"""The "server cleanup is due" note and the reminder every test run prints
(2026-10-25, Vicki: "when I run the run_test.bat or you run it can it print a
reminder to clean up the server database and why and the command").

The server-mode E2E suite runs on David's PC but its test data lives on the
AI-Prowler Server. Data the Jobs app can't delete (mileage records, uploaded
photo files) is removed by ztest_server_cleanup.py ON THE SERVER. When a
server run leaves such data, it adds a line to a small note on THIS PC
(~/.ai-prowler/e2e_server_cleanup_pending.json). Every pytest run on this PC
(run_tests.bat, the E2E launchers, the runs Claude starts) ends with the
reminder — flagged "DUE" while the note has entries. server_cleanup_done.bat
clears the note once the script has been run on the server.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path

PENDING_FILE = Path(os.environ.get("AIPROWLER_E2E_PENDING_FILE", "")
                    or Path.home() / ".ai-prowler" / "e2e_server_cleanup_pending.json")
SCRIPT = r"tests\server_cleanup\run_ztest_server_cleanup.bat"
DONE = r"tests\server_cleanup\server_cleanup_done.bat"


def read() -> list:
    try:
        d = json.loads(PENDING_FILE.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def add(what: str, test: str = "") -> None:
    """Record that a server run left data only the server script can remove."""
    items = read()
    items.append({"at": _dt.datetime.now().isoformat(timespec="seconds"), "what": what, "test": test})
    try:
        PENDING_FILE.parent.mkdir(parents=True, exist_ok=True)
        PENDING_FILE.write_text(json.dumps(items[-200:], indent=1), encoding="utf-8")
    except OSError:
        pass


def clear() -> int:
    n = len(read())
    try:
        PENDING_FILE.unlink()
    except OSError:
        pass
    return n


def reminder_lines() -> list:
    """Plain ASCII on purpose: a Windows console (run_tests.bat) isn't UTF-8,
    so emoji and long dashes print as garbage there."""
    items = read()
    if items:
        first = min(i.get("at", "") for i in items)
        lines = [f"!! SERVER CLEANUP IS DUE - {len(items)} item(s) since {first.replace('T', ' ')}:"]
        seen = []
        for i in items:
            w = i.get("what", "")
            if w not in seen:
                seen.append(w)
        lines += [f"     - {w}" for w in seen[:8]]
    else:
        lines = ["Server cleanup reminder - nothing is waiting right now."]
    lines += [
        "   Why: server-mode E2E tests leave data the Jobs app can't delete - mileage records (an IRS",
        "        log: void / retire only) and uploaded test photos. They sit on the AI-Prowler Server.",
        f"   How: on the SERVER, signed in as AI-Prowler-Server, run  {SCRIPT}",
        "        (dry run first, then it asks; backs up the job database before removing anything)",
        "        or:  python tests\\server_cleanup\\ztest_server_cleanup.py --apply",
        f"        Then on this PC run  {DONE}  to clear this reminder.",
    ]
    return lines
