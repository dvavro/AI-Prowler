"""Copying the shared runner settings into the Jobs and HR agent databases writes nothing when nothing
changed (2026-10-31: the HR browser tests' guard saw the REAL HR folder's hr_agent.db modified every
3 minutes by the scheduler's copy, although no value had changed).
Run: run_tests.bat tests\\unit\\test_agent_sync_no_rewrite.py
"""
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent_hr_store as hstore  # noqa: E402
import desk_agent_store as store  # noqa: E402
import desk_db  # noqa: E402


def fingerprint(db: str):
    folder = Path(db).parent
    return sorted((p.name, p.stat().st_size, p.stat().st_mtime_ns) for p in folder.iterdir() if p.is_file())


@pytest.mark.parametrize("mod", [store, hstore], ids=["jobs", "hr"])
def test_sync_writes_only_what_changed(tmp_path, monkeypatch, mod):
    tdb = str(tmp_path / "tickets" / "tickets.db")
    desk_db.init_db(tdb)
    desk_db.set_setting(tdb, "agent_name", "Sam", edition="solo")
    adb = str(tmp_path / "agent" / "x.db")
    monkeypatch.setattr(mod, "PATH_OVERRIDE", Path(adb))
    s = mod.sync_shared(tdb)                                   # first copy writes
    assert s["agent_name"] == "Sam"
    before = fingerprint(adb)
    time.sleep(1.2)                                            # a write would change the times
    for _ in range(3):
        mod.sync_shared(tdb)                                   # the scheduler's ticks: nothing changed
    assert fingerprint(adb) == before
    desk_db.set_setting(tdb, "agent_name", "Alex", edition="solo")
    assert mod.sync_shared(tdb)["agent_name"] == "Alex"         # a real change is still copied
