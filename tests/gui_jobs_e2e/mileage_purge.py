"""Remove E2E mileage test data for good — PERSONAL suite (2026-10-25, Vicki:
"have it clean up the leftover data").

Mileage records are an IRS log, so the app itself never deletes them: a trip
can only be voided (kept as "removed"), a vehicle only retired, and a paid
reimbursement locks its trips. That's right for real data, but it means the
app's own tools can't take test data back out. The personal suite's Jobs app
server runs on this same PC, so it deletes its test rows straight from the job
database file.

WHAT counts as test data, and HOW it's deleted, is defined once, in
tests/server_cleanup/ztest_server_cleanup.py (find_mileage_rows /
delete_mileage_rows) — the same script that cleans the AI-Prowler Server, run
on that machine. This module adds what only a run on THIS PC can do:

  * Same-database check first: the trips, vehicles and reimbursements the Jobs
    app server reports (get_mileage_log / mileage_reimbursement, read through
    the guarded API) must match the file exactly — otherwise nothing is touched.
  * The run's own registry: trips this run created with no marker (a typed
    quick-add trip) are included; a trip counts as test data just for its ZTEST
    vehicle only inside the sandbox window.
  * A copy of the whole database is saved in the run's folder before any delete.

The database is ~/.ai-prowler/jobs_database/ai_prowler_jobs.db, or the path in
AIPROWLER_E2E_JOBS_DB.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from safety import SANDBOX_DATES

_CORE_DIR = Path(__file__).resolve().parent.parent / "server_cleanup"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
import ztest_server_cleanup as core          # noqa: E402

DEFAULT_DB = Path.home() / ".ai-prowler" / "jobs_database" / "ai_prowler_jobs.db"


def db_path() -> Path:
    return Path(os.environ.get("AIPROWLER_E2E_JOBS_DB", "").strip() or DEFAULT_DB)


# ── same database? ───────────────────────────────────────────────────────────
def _server_view(api) -> dict:
    w0, w1 = min(SANDBOX_DATES), max(SANDBOX_DATES)
    d = json.loads(api.call("get_mileage_log", {"start_date": w0, "end_date": w1}, expect_ok=False))
    rs = json.loads(api.call("mileage_reimbursement", {"action": "list", "as_json": True}, expect_ok=False))
    return {"trips": {t["trip_id"]: (t["trip_date"], t["status"]) for t in d.get("trips", [])},
            "vehicles": {v["vehicle_id"]: v["vin"] for v in d.get("vehicles", []) if v.get("active")},
            "reimbs": {r["reimbursement_id"]: r["status"] for r in rs}}


def _file_view(conn, limit_reimbs: int) -> dict:
    w0, w1 = min(SANDBOX_DATES), max(SANDBOX_DATES)
    trips = {r["trip_id"]: (r["trip_date"], r["status"]) for r in conn.execute(
        "SELECT trip_id, trip_date, status FROM mileage_trips WHERE trip_date BETWEEN ? AND ?", (w0, w1))}
    veh = {r["vehicle_id"]: r["vin"] for r in conn.execute("SELECT vehicle_id, vin FROM vehicles WHERE active = 1")}
    reimbs = {r["reimbursement_id"]: r["status"] for r in conn.execute(
        "SELECT reimbursement_id, status FROM mileage_reimbursements ORDER BY period_start DESC, "
        "reimbursement_id DESC LIMIT ?", (limit_reimbs,))}
    return {"trips": trips, "vehicles": veh, "reimbs": reimbs}


def same_database(api, conn, log) -> str:
    """'' when the file holds exactly what the Jobs app server reports;
    otherwise why not. Retried: a clock-out builds trips in the background."""
    why = "not checked"
    for attempt in range(4):
        s = _server_view(api)
        f = _file_view(conn, max(len(s["reimbs"]), 1))
        diff = [k for k in ("trips", "vehicles", "reimbs") if s[k] != f[k]]
        if not diff:
            return ""
        why = "; ".join(f"{k}: server {len(s[k])} vs file {len(f[k])}" for k in diff)
        log(f"mileage purge: database check attempt {attempt + 1} differs ({why})")
        time.sleep(1.5)
    return why


# ── what is test data / what is left ─────────────────────────────────────────
def find_test_rows(conn, created_ids=()) -> dict:
    return core.find_mileage_rows(conn, created_ids, vehicle_dates=sorted(SANDBOX_DATES))


def leftovers(conn=None) -> list[str]:
    """Test mileage rows still in the database (should be none after a purge)."""
    own = conn is None
    if own:
        p = db_path()
        if not p.exists():
            return []
        conn = core.connect(p, ro=True)
    try:
        if not core.has_mileage_tables(conn):
            return []
        f = find_test_rows(conn)
        return ([f"mileage trip {t}" for t in f["trips"]] + [f"vehicle {v}" for v in f["vehicles"]]
                + [f"reimbursement {r}" for r in f["reimbs"]])
    finally:
        if own:
            conn.close()


# ── the purge ────────────────────────────────────────────────────────────────
def purge(api, created_ids, run_dir, log, why: str) -> dict:
    """Delete every E2E mileage row. Returns a summary; {"skipped": reason}
    when it can't safely run."""
    p = db_path()
    if not p.exists():
        return {"skipped": f"no job database at {p}"}
    conn = core.connect(p)
    try:
        if not core.has_mileage_tables(conn):
            return {"skipped": "the database has no mileage tables"}
        f = find_test_rows(conn, created_ids)
        if not (f["trips"] or f["vehicles"] or f["reimbs"]):
            log(f"mileage purge ({why}): nothing to remove")
            return {"trips": 0, "vehicles": 0, "reimbursements": 0}
        diff = same_database(api, conn, log)
        if diff:
            log(f"mileage purge ({why}): SKIPPED — {p} isn't the database the Jobs app is serving ({diff})")
            return {"skipped": f"{p} doesn't match what the Jobs app server reports ({diff})"}
        f = find_test_rows(conn, created_ids)          # again, after the check's wait
        backup = core.backup_db(conn, run_dir, f"mileage_purge_{why}")
        n = core.delete_mileage_rows(conn, f)
        n["backup"] = str(backup)
        n["left"] = leftovers(conn)
        log(f"mileage purge ({why}): removed {n['trips']} trips, {n['reimbursements']} reimbursements, "
            f"{n['vehicles']} vehicles; kept {n['vehicles_kept'] or 'none'}; left {n['left'] or 'nothing'}; "
            f"backup {backup.name}")
        return n
    finally:
        conn.close()
