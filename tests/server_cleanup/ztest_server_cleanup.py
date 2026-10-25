"""Remove E2E test data from an AI-Prowler install — run ON THE SERVER MACHINE
(2026-10-25, Vicki: "the cleanup script on the server machine").

WHY THIS EXISTS
  The server-mode E2E suite runs on David's PC and talks to the AI-Prowler
  Server over the internet. Most test data it removes itself through the Jobs
  app (customers, jobs, routes, prices, learnings). Some it can't, because the
  app deliberately has no way to delete it and the files live on the server:
    • mileage records — an IRS log: trips can only be voided, vehicles only
      retired, paid trips are locked;
    • uploaded photos / files — the Jobs app has no photo delete; they sit in
      the server account's Documents\\AI-Prowler\\JobPhotos\\<job> folders.
  Those tests were skipped or never written until now. This script deletes
  that data on the machine that owns it.

WHAT IT REMOVES (only provably-test data)
  Mileage (job database ~/.ai-prowler/jobs_database/ai_prowler_jobs.db):
    trips whose notes / driver / customer say "ZTEST E2E" (or in a ZTEST
    vehicle during the last 60 days), with their edit history and AI-review
    dismissals; reimbursements of a "ZTEST E2E" driver or made only of test
    trips, with their events; vehicles nicknamed "ZTEST E2E …" with their
    odometer readings, day picks and default-vehicle entries.
  Uploads (~/Documents/AI-Prowler/JobPhotos/<job>/): files with "ztest" in the
    name — the suite always uploads "ztest_…" files. MOVED into the backup
    folder (not destroyed); an emptied job folder is removed.
  Reported, not removed: ZTEST customers / jobs still in the database (the
  suite removes those through the app — if any are listed, the last run was
  interrupted; run the suite again) and "ZTEST E2E" learnings (the suite
  removes those itself as the owner; deleting them here, behind the running
  server's search index, could damage the index).

SAFETY
  Dry run by default — it lists everything and changes nothing. --apply makes
  a full copy of the job database first, then deletes in one transaction (all
  or nothing). Real rows are never selected; a vehicle a real trip uses is kept.

USAGE (on the server, signed in as the account AI-Prowler runs under)
  python ztest_server_cleanup.py            # dry run: what would be removed
  python ztest_server_cleanup.py --apply    # remove it (backup first)
  python ztest_server_cleanup.py --home C:\\Users\\AI-Prowler-Server --apply
  or double-click run_ztest_server_cleanup.bat (dry run, then asks).
Exit code 0 = nothing left afterwards; 1 = something is still there / failed.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import shutil
import sqlite3
import sys
from pathlib import Path

ZTEST_PREFIX = "ZTEST E2E"
_LIKE = ZTEST_PREFIX + "%"                         # SQLite LIKE is case-insensitive for ASCII
SETTING_DEFAULT_VEHICLES = "Mileage Default Vehicles"
VEHICLE_ONLY_DAYS = 60                             # a trip marked only by its ZTEST vehicle: this recent


# ── locations (the same per-account folders the app itself uses) ─────────────
def paths(home: Path) -> dict:
    return {"db": home / ".ai-prowler" / "jobs_database" / "ai_prowler_jobs.db",
            "photos": home / "Documents" / "AI-Prowler" / "JobPhotos",
            "learnings": home / ".ai-prowler" / "learnings" / "self_learning_data.json",
            "backups": home / ".ai-prowler" / "ztest_cleanup_backups"}


def connect(db, ro: bool = False):
    conn = (sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30) if ro
            else sqlite3.connect(str(db), timeout=30))
    conn.row_factory = sqlite3.Row
    return conn


def has_mileage_tables(conn) -> bool:
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    return {"mileage_trips", "vehicles", "mileage_reimbursements"} <= names


# ── mileage: what is test data (shared with tests/gui_jobs_e2e/mileage_purge.py) ──
def find_mileage_rows(conn, created_ids=(), vehicle_dates=None) -> dict:
    """{'trips', 'vehicles', 'reimbs'} of provably-test rows.
    created_ids: TRIP ids a test run registered (e.g. a typed quick-add trip
    with no marker). vehicle_dates: the dates on which a trip counts as test
    data just because it's in a ZTEST vehicle (default: the last 60 days)."""
    if vehicle_dates is None:
        today = _dt.date.today()
        vehicle_dates = [(today + _dt.timedelta(days=d)).isoformat() for d in range(-VEHICLE_ONLY_DAYS, 8)]
    vdates = sorted(set(vehicle_dates))
    veh = [r[0] for r in conn.execute("SELECT vehicle_id FROM vehicles WHERE COALESCE(nickname,'') LIKE ?",
                                      (_LIKE,))]
    created = sorted({str(i) for i in created_ids if str(i).startswith("TRIP-")})
    q = ("SELECT trip_id FROM mileage_trips WHERE COALESCE(notes,'') LIKE ? OR COALESCE(crew,'') LIKE ? "
         "OR COALESCE(customer_name,'') LIKE ?")
    args: list = ["%" + ZTEST_PREFIX + "%", _LIKE, _LIKE]
    if veh and vdates:
        q += (f" OR (vehicle_id IN ({','.join('?' * len(veh))}) AND trip_date IN "
              f"({','.join('?' * len(vdates))}))")
        args += veh + vdates
    if created:
        q += f" OR trip_id IN ({','.join('?' * len(created))})"
        args += created
    trips = sorted({r[0] for r in conn.execute(q, args)})
    tset = set(trips)
    reimbs = {r[0] for r in conn.execute(
        "SELECT reimbursement_id FROM mileage_reimbursements WHERE COALESCE(crew,'') LIKE ? OR user_key LIKE ?",
        (_LIKE, _LIKE))}
    # A real user's reimbursement made ONLY of test trips (the server tests
    # submit as Samual / Vicki) is test data too. One real trip in it = keep it.
    for r in conn.execute("SELECT reimbursement_id FROM mileage_reimbursements").fetchall():
        rid = r[0]
        if rid in reimbs:
            continue
        ids = [x[0] for x in conn.execute("SELECT trip_id FROM mileage_trips WHERE reimbursement_id = ?", (rid,))]
        if ids and all(i in tset for i in ids):
            reimbs.add(rid)
    return {"trips": trips, "vehicles": veh, "reimbs": sorted(reimbs)}


def delete_mileage_rows(conn, found: dict) -> dict:
    """Delete `found` in ONE transaction. Returns counts; a vehicle that a
    remaining (real) trip still uses is kept and listed."""
    trips, reimbs = found["trips"], found["reimbs"]
    n = {"trips": len(trips), "reimbursements": len(reimbs), "vehicles": 0, "vehicles_kept": []}
    conn.execute("BEGIN IMMEDIATE")
    try:
        for i in range(0, len(trips), 400):
            part = trips[i:i + 400]
            marks = ",".join("?" * len(part))
            conn.execute(f"DELETE FROM mileage_trip_edits WHERE trip_id IN ({marks})", part)
            conn.execute(f"DELETE FROM mileage_trips WHERE trip_id IN ({marks})", part)
            for t in part:                              # AI-review finding ids end in ':<trip id>'
                conn.execute("DELETE FROM mileage_review_actions WHERE finding_id LIKE ?", ("%:" + t,))
        if reimbs:
            marks = ",".join("?" * len(reimbs))
            conn.execute(f"UPDATE mileage_trips SET reimbursement_id = NULL WHERE reimbursement_id IN ({marks})",
                         reimbs)
            conn.execute(f"DELETE FROM mileage_reimbursement_events WHERE reimbursement_id IN ({marks})", reimbs)
            conn.execute(f"DELETE FROM mileage_reimbursements WHERE reimbursement_id IN ({marks})", reimbs)
        conn.execute("DELETE FROM mileage_day_builds WHERE user_key LIKE ?", (_LIKE,))
        conn.execute("DELETE FROM mileage_day_vehicles WHERE user_key LIKE ?", (_LIKE,))
        gone = []
        for v in found["vehicles"]:
            if conn.execute("SELECT 1 FROM mileage_trips WHERE vehicle_id = ? LIMIT 1", (v,)).fetchone():
                n["vehicles_kept"].append(v)
                continue
            conn.execute("DELETE FROM odometer_readings WHERE vehicle_id = ?", (v,))
            conn.execute("DELETE FROM mileage_day_vehicles WHERE vehicle_id = ?", (v,))
            conn.execute("DELETE FROM vehicles WHERE vehicle_id = ?", (v,))
            gone.append(v)
        n["vehicles"] = len(gone)
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (SETTING_DEFAULT_VEHICLES,)).fetchone()
        if row and gone:
            try:
                m = json.loads(row[0] or "{}")
            except ValueError:
                m = None
            if isinstance(m, dict) and any(val in gone for val in m.values()):
                m = {k: val for k, val in m.items() if val not in gone}
                conn.execute("UPDATE settings SET value = ? WHERE key = ?", (json.dumps(m), SETTING_DEFAULT_VEHICLES))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return n


def backup_db(conn, folder, tag: str) -> Path:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    dst_path = folder / f"jobs_db_before_{tag.replace(' ', '_')}_{_dt.datetime.now():%Y%m%d_%H%M%S}.db"
    dst = sqlite3.connect(str(dst_path))
    try:
        conn.backup(dst)
    finally:
        dst.close()
    return dst_path


# ── other test data ─────────────────────────────────────────────────────────
def find_upload_files(photos: Path) -> list:
    if not photos.is_dir():
        return []
    return sorted(p for p in photos.glob("*/*") if p.is_file() and "ztest" in p.name.lower())


def move_uploads(files: list, photos: Path, dest: Path) -> int:
    n = 0
    for f in files:
        target = dest / f.relative_to(photos)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(f), str(target))
        n += 1
        folder = f.parent
        if folder.is_dir() and not any(folder.iterdir()):
            folder.rmdir()
    return n


def find_ztest_learnings(path: Path) -> list:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = data.get("learnings", []) if isinstance(data, dict) else []
    return [f"{l.get('id', '?')} {l.get('title', '')!r} ({l.get('status', '?')})" for l in rows
            if str(l.get("title", "")).upper().startswith(ZTEST_PREFIX)]


def find_ztest_jobs(conn) -> list:
    out = []
    try:
        for r in conn.execute("SELECT customer_id, company_name FROM customers WHERE company_name LIKE ?", (_LIKE,)):
            out.append(f"customer {r[0]} {r[1]}")
        for r in conn.execute("SELECT job_id, customer_name FROM jobs WHERE customer_name LIKE ?", (_LIKE,)):
            out.append(f"job {r[0]} {r[1]}")
    except sqlite3.Error:
        pass
    return out


# ── the run ─────────────────────────────────────────────────────────────────
def scan(home: Path) -> dict:
    p = paths(home)
    out = {"paths": p, "mileage": None, "uploads": find_upload_files(p["photos"]),
           "learnings": find_ztest_learnings(p["learnings"]), "jobs": [], "problems": []}
    if p["db"].exists():
        conn = connect(p["db"], ro=True)
        try:
            if has_mileage_tables(conn):
                out["mileage"] = find_mileage_rows(conn)
            out["jobs"] = find_ztest_jobs(conn)
        finally:
            conn.close()
    else:
        out["problems"].append(f"no job database at {p['db']} — is --home the account AI-Prowler runs under?")
    return out


def describe(s: dict) -> list:
    m = s["mileage"] or {"trips": [], "vehicles": [], "reimbs": []}
    lines = [f"Job database : {s['paths']['db']}",
             f"Photo folder : {s['paths']['photos']}",
             f"Mileage test data   : {len(m['trips'])} trips, {len(m['reimbs'])} reimbursements, "
             f"{len(m['vehicles'])} vehicles",
             f"Uploaded test files : {len(s['uploads'])}"]
    for f in s["uploads"][:20]:
        lines.append(f"    {f.parent.name}\\{f.name}")
    if s["jobs"]:
        lines.append(f"ZTEST customers/jobs still in the database (not removed here — run the E2E suite "
                     f"again, its sweep deletes them): {len(s['jobs'])}")
        lines += [f"    {x}" for x in s["jobs"][:20]]
    if s["learnings"]:
        lines.append(f"ZTEST learnings (not removed here — the suite deletes them as the owner; or delete "
                     f"them in AI-Prowler's Learnings tab): {len(s['learnings'])}")
        lines += [f"    {x}" for x in s["learnings"][:20]]
    lines += [f"!! {x}" for x in s["problems"]]
    return lines


def apply(home: Path, log=print) -> dict:
    p = paths(home)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    res = {"mileage": None, "uploads": 0, "backup": None}
    if p["db"].exists():
        conn = connect(p["db"])
        try:
            if has_mileage_tables(conn):
                found = find_mileage_rows(conn)
                if found["trips"] or found["vehicles"] or found["reimbs"]:
                    res["backup"] = str(backup_db(conn, p["backups"], "ztest_cleanup"))
                    log(f"Backup of the job database: {res['backup']}")
                    res["mileage"] = delete_mileage_rows(conn, found)
                    log(f"Removed mileage test data: {res['mileage']}")
        finally:
            conn.close()
    files = find_upload_files(p["photos"])
    if files:
        dest = p["backups"] / f"removed_uploads_{stamp}"
        res["uploads"] = move_uploads(files, p["photos"], dest)
        log(f"Moved {res['uploads']} uploaded test file(s) to {dest}")
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Remove AI-Prowler E2E test data on this machine "
                                             "(see the top of the file).")
    ap.add_argument("--apply", action="store_true", help="remove it (default: dry run, change nothing)")
    ap.add_argument("--home", default="", help="profile folder of the account AI-Prowler runs under "
                                              "(default: this account's)")
    a = ap.parse_args(argv)
    home = Path(a.home) if a.home else Path.home()
    print("AI-Prowler E2E test-data cleanup —", "APPLY" if a.apply else "DRY RUN (nothing is changed)")
    s = scan(home)
    for line in describe(s):
        print(line)
    if not s["paths"]["db"].exists():
        return 1
    if not a.apply:
        print("\nDry run only. Run again with --apply to remove the mileage test data and uploaded test files.")
        return 0
    try:
        apply(home)
    except Exception as e:                           # the transaction rolled back
        print(f"!! FAILED — nothing was removed from the database: {type(e).__name__}: {e}")
        return 1
    after = scan(home)
    m = after["mileage"] or {"trips": [], "vehicles": [], "reimbs": []}
    print(f"\nAfter cleanup: {len(m['trips'])} test trips, {len(m['reimbs'])} reimbursements, "
          f"{len(m['vehicles'])} vehicles, {len(after['uploads'])} uploaded files left.")
    if m["trips"] or m["reimbs"] or m["vehicles"] or after["uploads"]:
        print("!! Some test data is still there (a vehicle a real trip uses is kept on purpose).")
        return 1
    print("Done. On David's PC, run tests\\server_cleanup\\server_cleanup_done.bat so test runs stop "
          "showing the reminder.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
