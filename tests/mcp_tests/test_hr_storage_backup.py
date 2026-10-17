"""
HR storage, backup, restore and cross-process lock (David, 2026-10-16, Phase 1).

  * storage: _hr_save_db / _hr_load_db write and read
        <HR data folder>\\company\\settings.json + <collection>.json
        <HR data folder>\\employees\\EMP-00001_Last_First\\employee.json,
            <collection>.json, task_tracking.json
    and round-trip the one in-memory dict (content and list order).
  * fresh start: an old hr_db.json next to the new folders is never read or changed.
  * deleted employees go to employees\\_deleted\\ (never silently lost); a folder
    another process created after we loaded is never archived by our save.
  * backups: one complete dated HR_<UTC timestamp> copy, retention, validation,
    last result, the admin-only HTTP routes, the scheduler's daily cadence.
  * restore: one employee from a backup; the current folder is set aside.
  * lock: _hr_db_lock makes another PROCESS wait, is re-entrant, and releases.

Everything runs in pytest's tmp_path with ZTEST data. It never touches the real
HR data (C:\\Users\\AI-Prowler-Server\\.ai-prowler\\hr\\) or config.json.

Run: run_tests.bat tests\\mcp_tests\\test_hr_storage_backup.py -v
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

E1 = {"id": "EMP-00001", "first_name": "ZTEST", "last_name": "One", "status": "Active",
      "title": "Original", "personal_email": "one+hrtest@example.com"}
E2 = {"id": "EMP-00002", "first_name": "ZTEST", "last_name": "Two", "status": "Active",
      "personal_email": "two+hrtest@example.com"}
F1, F2 = "EMP-00001_One_ZTEST", "EMP-00002_Two_ZTEST"


def _seed():
    return {
        "config": {"company_name": "ZTEST Co", "setup_complete": True},
        "employees": [dict(E1), dict(E2)],
        "tasks": [
            {"id": "TASK-00001", "employee_id": "EMP-00001", "name": "I-9", "status": "Not Started",
             "last_reminder_sent_at": "2026-10-01T12:00:00Z", "escalated": True},
            {"id": "TASK-00002", "employee_id": "EMP-00002", "name": "W-4", "status": "Not Started"},
            {"id": "TASK-00003", "name": "Company task", "status": "Not Started"},
        ],
        "pto_requests": [{"id": "PTO-1", "employee_id": "EMP-00001", "days": 2}],
        "locations": [{"id": "L1", "name": "ZTEST Shop"}],
        "events": [],
    }


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    live = tmp_path / "hr"
    live.mkdir()
    monkeypatch.setattr(m, "_HR_DB_PATH", str(live / "hr_db.json"))
    m._hr_save_db(_seed())
    m.ztest_live = live
    m.ztest_backups = tmp_path / "backups"
    return m


def _tool(ap, name):
    f = getattr(ap, name)
    return getattr(f, "fn", f)


def _read(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


# ── storage ──────────────────────────────────────────────────────────────────
def test_layout_on_disk(ap):
    live = ap.ztest_live
    assert _read(live / "company" / "settings.json")["company_name"] == "ZTEST Co"
    assert [i["id"] for i in _read(live / "company" / "locations.json")["items"]] == ["L1"]
    assert [i["id"] for i in _read(live / "company" / "tasks.json")["items"]] == ["TASK-00003"]
    e1 = live / "employees" / F1
    assert _read(e1 / "employee.json")["id"] == "EMP-00001"
    assert [i["id"] for i in _read(e1 / "pto_requests.json")["items"]] == ["PTO-1"]
    tasks = _read(e1 / "tasks.json")["items"]
    assert [t["id"] for t in tasks] == ["TASK-00001"]
    assert "last_reminder_sent_at" not in tasks[0] and "escalated" not in tasks[0], \
        "scheduler marks belong in task_tracking.json"
    track = _read(e1 / "task_tracking.json")
    assert track["tasks"]["TASK-00001"]["escalated"] is True
    assert not (live / "employees" / F2 / "pto_requests.json").exists()
    assert not (live / "hr_db.json").exists(), "the old single file is never written"


def test_round_trip_content_and_order(ap):
    db = ap._hr_load_db()
    assert [e["id"] for e in db["employees"]] == ["EMP-00001", "EMP-00002"]
    assert [t["id"] for t in db["tasks"]] == ["TASK-00001", "TASK-00002", "TASK-00003"]
    t1 = db["tasks"][0]
    assert t1["last_reminder_sent_at"] == "2026-10-01T12:00:00Z" and t1["escalated"] is True
    assert db["pto_requests"] == [{"id": "PTO-1", "employee_id": "EMP-00001", "days": 2}]
    assert db["locations"] == [{"id": "L1", "name": "ZTEST Shop"}]
    assert db["employees"][0]["title"] == "Original"
    assert "_hr_order" not in json.dumps(db), "on-disk ordering key leaked into the data"


def test_old_hr_db_json_is_ignored_and_untouched(ap):
    old = ap.ztest_live / "hr_db.json"
    old.write_text(json.dumps({"employees": [{"id": "EMP-09999", "first_name": "OLD"}]}), encoding="utf-8")
    before = old.read_bytes()
    db = ap._hr_load_db()
    assert all(e["id"] != "EMP-09999" for e in db["employees"])
    ap._hr_save_db(db)
    assert old.read_bytes() == before


def test_unchanged_files_are_not_rewritten(ap):
    p = ap.ztest_live / "employees" / F1 / "employee.json"
    before = p.stat().st_mtime_ns
    time.sleep(0.05)
    ap._hr_save_db(ap._hr_load_db())
    assert p.stat().st_mtime_ns == before


def test_deleted_employee_folder_is_archived(ap):
    db = ap._hr_load_db()
    db["employees"] = [e for e in db["employees"] if e["id"] != "EMP-00002"]
    ap._hr_save_db(db)
    emps = ap.ztest_live / "employees"
    assert not (emps / F2).exists()
    archived = list((emps / "_deleted").glob(F2 + "_*"))
    assert len(archived) == 1 and (archived[0] / "employee.json").exists()
    assert [e["id"] for e in ap._hr_load_db()["employees"]] == ["EMP-00001"]


def test_folder_created_by_another_process_is_not_archived(ap):
    stale = ap._hr_load_db()                    # this "process" loaded before EMP-00003 existed
    other = ap._hr_load_db()
    other["employees"].append({"id": "EMP-00003", "first_name": "ZTEST", "last_name": "Three"})
    ap._hr_save_db(other)
    ap._hr_save_db(stale)
    assert (ap.ztest_live / "employees" / "EMP-00003_Three_ZTEST" / "employee.json").exists()
    assert not (ap.ztest_live / "employees" / "_deleted").exists()


def test_renamed_folder_moves_with_its_files(ap):
    doc = ap.ztest_live / "employees" / F1 / "onboarding" / "ztest.txt"
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text("ZTEST", encoding="utf-8")
    db = ap._hr_load_db()
    db["employees"][0]["doc_folder"] = "EMP-00001_Renamed_ZTEST"
    ap._hr_save_db(db)
    new = ap.ztest_live / "employees" / "EMP-00001_Renamed_ZTEST"
    assert (new / "onboarding" / "ztest.txt").read_text(encoding="utf-8") == "ZTEST"
    assert not (ap.ztest_live / "employees" / F1).exists()


def test_privacy_settings_never_overwrite_company_config(ap):
    """db["settings"] (HR Admin's location toggles) and the company config
    both used to map to company\\settings.json — a toggle wiped the setup."""
    st, _ct, _b = ap._hr_api_route("POST", "/settings", {}, {"location_clock": False}, {"role": "admin"})
    assert st == 200
    db = ap._hr_load_db()
    assert db["config"]["company_name"] == "ZTEST Co" and db["config"]["setup_complete"] is True
    assert db["settings"]["location_clock"] is False
    assert _read(ap.ztest_live / "company" / "settings.json")["company_name"] == "ZTEST Co"
    assert _read(ap.ztest_live / "company" / "app_settings.json")["location_clock"] is False
    ap._hr_save_db(db)
    assert ap._hr_load_db()["config"]["company_name"] == "ZTEST Co", "survives another round trip"


def test_reserved_employee_file_names(ap):
    db = ap._hr_load_db()
    db["employee"] = [{"id": "X1", "employee_id": "EMP-00001", "note": "ZTEST"}]   # a key named like employee.json
    ap._hr_save_db(db)
    e1 = ap.ztest_live / "employees" / F1
    assert _read(e1 / "employee.json")["id"] == "EMP-00001", "the record file is untouched"
    assert _read(e1 / "data_employee.json")["items"][0]["id"] == "X1"
    again = ap._hr_load_db()
    assert again["employee"][0]["id"] == "X1" and again["employees"][0]["id"] == "EMP-00001"


def test_scheduler_state_file_is_left_alone(ap):
    st = ap.ztest_live / "company" / "scheduler_state.json"
    st.write_text('{"scheduler": {}}', encoding="utf-8")
    db = ap._hr_load_db()
    assert "scheduler_state" not in db
    ap._hr_save_db(db)
    assert st.read_text(encoding="utf-8") == '{"scheduler": {}}'


# ── backup settings ──────────────────────────────────────────────────────────
def test_backup_settings_validation(ap):
    upd = ap._hr_update_backup_settings
    assert upd({"backup_dir": "relative\\folder"})[0] is False
    assert upd({"backup_dir": str(ap.ztest_live / "inside")})[0] is False, "inside the live HR data"
    assert upd({"backup_dir": str(ap.ztest_live)})[0] is False, "the live HR data folder itself"
    assert upd({"enabled": True})[0] is False, "on without a folder"
    assert upd({"schedule": "hourly"})[0] is False
    ok, _msg, cfg = upd({"backup_dir": str(ap.ztest_backups), "enabled": True, "schedule": "daily",
                         "hour": 99, "minute": 5, "retention_count": 0})
    assert ok and cfg["hour"] == 23 and cfg["minute"] == 5 and cfg["retention_count"] == 1
    assert ap.ztest_backups.is_dir()
    saved = ap._hr_load_db()["config"]["employee_backup"]
    assert saved["backup_dir"] == str(ap.ztest_backups) and saved["schedule"] == "daily"


def test_scheduler_reads_daily_cadence(ap):
    import hr_scheduler as hs
    assert hs._employee_backup_cadence() is None, "off until configured"
    ap._hr_update_backup_settings({"backup_dir": str(ap.ztest_backups), "enabled": True,
                                   "schedule": "daily", "hour": 7, "minute": 5})
    assert hs._employee_backup_cadence() == ("daily", 7, 5)
    ap._hr_update_backup_settings({"schedule": "weekly", "weekday": 0})
    assert hs._employee_backup_cadence() == ("weekly", 0, 7, 5)
    assert Path(hs._HR_TRACKING_PATH).parts[-2:] == ("company", "scheduler_state.json")


# ── backups ──────────────────────────────────────────────────────────────────
def test_backup_is_one_complete_dated_copy(ap):
    ap._hr_update_backup_settings({"backup_dir": str(ap.ztest_backups)})
    (ap.ztest_live / "employees" / F1 / "onboarding").mkdir(parents=True, exist_ok=True)
    (ap.ztest_live / "employees" / F1 / "onboarding" / "ztest.pdf").write_bytes(b"%PDF-ZTEST")
    r = ap._hr_run_employee_backup()
    assert r["ok"] and r["backed_up"] == 2 and not r["errors"], r
    assert ap._HR_BACKUP_SNAPSHOT_RE.match(r["snapshot"])
    snap = ap.ztest_backups / r["snapshot"]
    assert _read(snap / "company" / "settings.json")["company_name"] == "ZTEST Co"
    assert (snap / "employees" / F1 / "employee.json").exists()
    assert (snap / "employees" / F2 / "employee.json").exists()
    assert (snap / "employees" / F1 / "onboarding" / "ztest.pdf").read_bytes() == b"%PDF-ZTEST"
    assert _read(snap / "backup_info.json")["employees"] == 2
    assert not list(snap.rglob("*.lock")) and not list(snap.rglob("*.tmp"))
    lr = ap._hr_load_db()["config"]["employee_backup"]["last_result"]
    assert lr["ok"] is True and lr["snapshot"] == r["snapshot"]


def test_backup_without_folder_fails_cleanly(ap):
    r = ap._hr_run_employee_backup()
    assert r["ok"] is False and r["snapshot"] == "" and r["errors"]


def test_retention_deletes_only_old_hr_snapshots(ap):
    ap.ztest_backups.mkdir()
    for old in ("HR_20200101T000000Z", "HR_20200102T000000Z"):
        (ap.ztest_backups / old).mkdir()
    (ap.ztest_backups / "keep_me").mkdir()
    ap._hr_update_backup_settings({"backup_dir": str(ap.ztest_backups), "retention_count": 2})
    r = ap._hr_run_employee_backup()
    snaps = ap._hr_list_backup_snapshots(str(ap.ztest_backups))
    assert snaps == ["HR_20200102T000000Z", r["snapshot"]]
    assert (ap.ztest_backups / "keep_me").is_dir(), "never touches anything else in the folder"


def test_backup_tools(ap):
    assert "No backup" in _tool(ap, "hr_list_backups")()
    ap._hr_update_backup_settings({"backup_dir": str(ap.ztest_backups)})
    out = _tool(ap, "hr_backup_now")()
    assert "Backed up the company data and 2 employee folder(s)" in out, out
    listing = _tool(ap, "hr_list_backups")("EMP-00002")
    assert "HR_" in listing and "2 employee folder(s)" in listing
    assert "Last backup" in _tool(ap, "hr_get_backup_settings")()


# ── restore ──────────────────────────────────────────────────────────────────
def test_restore_one_employee(ap):
    ap._hr_update_backup_settings({"backup_dir": str(ap.ztest_backups)})
    snap = ap._hr_run_employee_backup()["snapshot"]
    db = ap._hr_load_db()
    db["employees"][0]["title"] = "Changed by mistake"
    ap._hr_save_db(db)
    out = _tool(ap, "hr_restore_employee")("EMP-00001")
    assert "Restored EMP-00001" in out and snap in out, out
    db = ap._hr_load_db()
    assert next(e for e in db["employees"] if e["id"] == "EMP-00001")["title"] == "Original"
    assert next(e for e in db["employees"] if e["id"] == "EMP-00002")["status"] == "Active"
    replaced = list((ap.ztest_live / "employees" / "_replaced").glob(F1 + "_*"))
    assert len(replaced) == 1
    assert _read(replaced[0] / "employee.json")["title"] == "Changed by mistake"
    assert any(a.get("action") == "employee_restored_from_backup" for a in db["audit_log"])


def test_restore_after_folder_rename_leaves_one_folder(ap):
    ap._hr_update_backup_settings({"backup_dir": str(ap.ztest_backups)})
    ap._hr_run_employee_backup()
    db = ap._hr_load_db()
    db["employees"][0]["doc_folder"] = "EMP-00001_Renamed_ZTEST"
    ap._hr_save_db(db)
    _tool(ap, "hr_restore_employee")("EMP-00001")
    live = [p.name for p in (ap.ztest_live / "employees").iterdir() if not p.name.startswith("_")]
    assert sorted(live) == sorted([F1, F2]), live
    assert [e["id"] for e in ap._hr_load_db()["employees"]].count("EMP-00001") == 1


def test_restore_unknown(ap):
    assert _tool(ap, "hr_restore_employee")("EMP-00001").startswith("\u274c"), "no folder configured"
    ap._hr_update_backup_settings({"backup_dir": str(ap.ztest_backups)})
    ap._hr_run_employee_backup()
    assert "No backup contains" in _tool(ap, "hr_restore_employee")("EMP-09999")
    assert "not found" in _tool(ap, "hr_restore_employee")("EMP-00001", "HR_19990101T000000Z")


# ── HTTP routes (HR Admin -> Settings -> Backups) ────────────────────────────
def _call(ap, method, path, body=None, role="admin"):
    auth = {"role": role}
    if role == "employee":
        auth["employee_id"] = "EMP-00001"
    st, _ct, b = ap._hr_api_route(method, path, {}, body or {}, auth)
    return st, json.loads(b)


def test_backup_routes_are_admin_only(ap):
    for method, path in (("GET", "/backup"), ("POST", "/backup/settings"), ("POST", "/backup/now")):
        assert _call(ap, method, path, role=None)[0] == 401
        assert _call(ap, method, path, role="employee")[0] == 403


def test_backup_routes(ap):
    st, r = _call(ap, "GET", "/backup")
    assert st == 200 and r["snapshots"] == [] and r["last_result"] is None
    assert r["settings"]["retention_count"] == 3 and r["data_folder"] == str(ap.ztest_live)
    st, r = _call(ap, "POST", "/backup/settings", {"backup_dir": "not\\absolute"})
    assert st == 400 and r["error"]
    st, r = _call(ap, "POST", "/backup/settings", {"backup_dir": str(ap.ztest_backups), "enabled": True,
                                                   "schedule": "daily", "hour": 6, "minute": 30,
                                                   "retention_count": 5, "ztest_extra": 1})
    assert st == 200 and r["ok"] and r["settings"]["backup_dir"] == str(ap.ztest_backups)
    assert r["settings"]["hour"] == 6 and r["settings"]["retention_count"] == 5
    assert "ztest_extra" not in ap._hr_load_db()["config"]["employee_backup"], "only known keys are saved"
    st, r = _call(ap, "POST", "/backup/now")
    assert st == 200 and r["result"]["ok"] and r["snapshots"] == [r["result"]["snapshot"]]
    assert r["last_result"]["ok"] is True
    assert _call(ap, "GET", "/backup/now")[0] == 405


def test_backup_now_route_reports_failure(ap):
    st, r = _call(ap, "POST", "/backup/now")
    assert st == 400 and "No backup directory" in r["error"]


# ── cross-process lock ───────────────────────────────────────────────────────
_HOLDER = r"""
import os, sys, time
fh = open(sys.argv[1], "a+")
try:
    if os.name == "nt":
        import msvcrt
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    print("BUSY", flush=True)
    sys.exit(0)
print("LOCKED", flush=True)
time.sleep(float(sys.argv[2]))
"""


def _holder(ap, hold):
    lock = str(ap.ztest_live / ".hr_data.lock")
    return subprocess.Popen([sys.executable, "-c", _HOLDER, lock, str(hold)],
                            stdout=subprocess.PIPE, text=True)


def test_lock_waits_for_another_process(ap):
    p = _holder(ap, 1.5)
    try:
        assert p.stdout.readline().strip() == "LOCKED"
        t0 = time.time()
        with ap._hr_db_lock:
            waited = time.time() - t0
        assert waited >= 1.0, f"took the HR lock while another process held it (waited {waited:.2f}s)"
    finally:
        p.wait(timeout=30)


def test_lock_is_reentrant_and_released(ap):
    with ap._hr_db_lock:
        with ap._hr_db_lock:                    # nested in the same thread: no deadlock
            p = _holder(ap, 0)
            assert p.stdout.readline().strip() == "BUSY", "other processes must wait while we hold it"
            p.wait(timeout=30)
        p = _holder(ap, 0)
        assert p.stdout.readline().strip() == "BUSY", "still held until the OUTER block ends"
        p.wait(timeout=30)
    p = _holder(ap, 0)
    assert p.stdout.readline().strip() == "LOCKED", "released after the outer block"
    p.wait(timeout=30)
