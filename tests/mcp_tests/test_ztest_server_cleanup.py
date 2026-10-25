"""tests/server_cleanup — the script that removes E2E test data ON THE SERVER,
the "server cleanup is due" reminder every test run prints, and the guard
rules the server tests that depend on them use (2026-10-25). Runs in the
normal suite against a throwaway home folder — never the real server."""
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SC = ROOT / "tests" / "server_cleanup"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


core = _load("_ztest_server_cleanup_ut", SC / "ztest_server_cleanup.py")


def _vin(prefix8, tail):
    v = prefix8 + "0" + tail
    cd = sum(core_tr(c) * w for c, w in zip(v, [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2])) % 11
    return v[:8] + ("X" if cd == 10 else str(cd)) + v[9:]


def core_tr(c):
    tr = {**{str(i): i for i in range(10)}, **dict(zip("ABCDEFGH", range(1, 9))),
          **dict(zip("JKLMN", range(1, 6))), "P": 7, "R": 9, **dict(zip("STUVWXYZ", range(2, 10)))}
    return tr[c]


@pytest.fixture
def server_home(tmp_path):
    """A fake server account home: job database with real + test mileage data
    (incl. a real user's reimbursement made only of test trips, and one with a
    real trip), JobPhotos with test + real files, a learnings file."""
    import db_schema
    import db_mileage_ops as mo
    home = tmp_path / "AI-Prowler-Server"
    p = core.paths(home)
    p["db"].parent.mkdir(parents=True)
    c = sqlite3.connect(str(p["db"]))
    db_schema.apply_schema(c)
    c.execute("INSERT INTO customers (customer_id, company_name) VALUES ('CUST-2026-9', 'ZTEST E2E Customer')")
    c.commit()
    c.close()
    db = str(p["db"])
    Z = core.ZTEST_PREFIX
    day = mo._today()
    vid = lambda out: out.split("Added ")[1].split()[0]                       # noqa: E731
    ids = lambda out: [w.strip(",.") for w in out.split() if w.startswith("TRIP-")]   # noqa: E731
    real_van = vid(mo.add_vehicle(db, _vin("1GCWGAFP", "CB200001"), "David", nickname="White Van"))
    sam_car = vid(mo.add_vehicle(db, _vin("2T1BURHE", "JC200002"), "Samual", nickname=f"{Z} Samual's Corolla",
                                 ownership="crew", owner_name="Samual Cronin"))
    vicki_car = vid(mo.add_vehicle(db, _vin("1HGCV1F3", "LA200003"), "Vicki", nickname="Vicki's Accord",
                                   ownership="crew", owner_name="Vicki Vavro"))
    real = ids(mo.add_trip(db, "David", trip_date=day, to_label="Chase", purpose="Bank – deposit", miles=2.6,
                           vehicle_id=real_van))[0]
    sam_test = ids(mo.add_trip(db, "Samual", trip_date=day, to_label="Sunbelt", purpose="Supplies – rental",
                               miles=8.2, crew="Samual Cronin", vehicle_id=sam_car, notes=f"{Z} SRV-MI-01"))[0]
    v_test = ids(mo.add_trip(db, "Vicki", trip_date=day, to_label="Permits", purpose="Permit pickup – x",
                             miles=27.4, crew="Vicki Vavro", vehicle_id=vicki_car, notes=f"{Z} SRV-MI-03"))[0]
    v_real = ids(mo.add_trip(db, "Vicki", trip_date=day, to_label="Lowe's", purpose="Supplies – caulk",
                             miles=3.1, crew="Vicki Vavro", vehicle_id=vicki_car))[0]
    sam_rid = mo.submit_reimbursement(db, "Samual", "samual cronin", "", "Samual Cronin").split()[1]
    mo.return_reimbursement(db, sam_rid, "fix it", "Vicki", "vicki vavro")
    v_rid = mo.submit_reimbursement(db, "Vicki", "vicki vavro", "", "Vicki Vavro").split()[1]   # test + real trip
    jp = p["photos"]
    (jp / "JOB-0001").mkdir(parents=True)
    (jp / "JOB-0001" / "20261025_101500_ztest_photo.txt").write_text("ZTEST E2E photo")
    (jp / "JOB-0001" / "20261020_090000_front_window.jpg").write_bytes(b"\xff\xd8 real")
    (jp / "JOB-0042").mkdir()
    (jp / "JOB-0042" / "20261025_101501_ztest_photo.txt").write_text("ZTEST E2E photo")
    p["learnings"].parent.mkdir(parents=True)
    p["learnings"].write_text(json.dumps({"learnings": [
        {"id": "a1", "title": "ZTEST E2E R-042 crew original", "status": "archived"},
        {"id": "b2", "title": "Crabby's invoices go out Mondays", "status": "active"}]}), encoding="utf-8")
    return {"home": home, "p": p, "db": db, "real": real, "real_van": real_van, "sam_test": sam_test,
            "sam_car": sam_car, "v_test": v_test, "v_real": v_real, "vicki_car": vicki_car,
            "sam_rid": sam_rid, "v_rid": v_rid}


def _n(db, sql, args=()):
    c = sqlite3.connect(db)
    try:
        return c.execute(sql, args).fetchone()[0]
    finally:
        c.close()


def test_dry_run_lists_everything_and_changes_nothing(server_home, capsys):
    h = server_home
    before = _n(h["db"], "SELECT COUNT(*) FROM mileage_trips")
    assert core.main(["--home", str(h["home"])]) == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out and "Mileage test data   : 2 trips, 1 reimbursements, 1 vehicles" in out, out
    assert "Uploaded test files : 2" in out and "ztest_photo.txt" in out
    assert "ZTEST customers/jobs still in the database" in out and "ZTEST E2E Customer" in out
    assert "ZTEST E2E R-042 crew original" in out and "(archived)" in out and "Crabby" not in out
    assert _n(h["db"], "SELECT COUNT(*) FROM mileage_trips") == before
    assert (h["p"]["photos"] / "JOB-0042" / "20261025_101501_ztest_photo.txt").exists()
    assert not h["p"]["backups"].exists()


def test_apply_removes_only_test_data_backs_up_and_moves_uploads(server_home, capsys):
    h = server_home
    assert core.main(["--home", str(h["home"]), "--apply"]) == 0, capsys.readouterr().out
    db = h["db"]
    for t in (h["sam_test"], h["v_test"]):
        assert _n(db, "SELECT COUNT(*) FROM mileage_trips WHERE trip_id = ?", (t,)) == 0
        assert _n(db, "SELECT COUNT(*) FROM mileage_trip_edits WHERE trip_id = ?", (t,)) == 0
    for t in (h["real"], h["v_real"]):
        assert _n(db, "SELECT COUNT(*) FROM mileage_trips WHERE trip_id = ?", (t,)) == 1, t
    # Samual's returned reimbursement was only test trips -> gone, events too
    assert _n(db, "SELECT COUNT(*) FROM mileage_reimbursements WHERE reimbursement_id = ?", (h["sam_rid"],)) == 0
    assert _n(db, "SELECT COUNT(*) FROM mileage_reimbursement_events WHERE reimbursement_id = ?",
              (h["sam_rid"],)) == 0
    # Vicki's has a real trip -> kept, still holds the real trip
    assert _n(db, "SELECT COUNT(*) FROM mileage_reimbursements WHERE reimbursement_id = ?", (h["v_rid"],)) == 1
    assert _n(db, "SELECT reimbursement_id FROM mileage_trips WHERE trip_id = ?", (h["v_real"],)) == h["v_rid"]
    # vehicles: the ZTEST one is gone; real ones (incl. Vicki's car, used by a real trip) stay
    assert _n(db, "SELECT COUNT(*) FROM vehicles WHERE vehicle_id = ?", (h["sam_car"],)) == 0
    assert _n(db, "SELECT COUNT(*) FROM odometer_readings WHERE vehicle_id = ?", (h["sam_car"],)) == 0
    for v in (h["real_van"], h["vicki_car"]):
        assert _n(db, "SELECT COUNT(*) FROM vehicles WHERE vehicle_id = ?", (v,)) == 1
    # uploads: test files moved into the backups folder, real photo untouched, empty folder removed
    jp = h["p"]["photos"]
    assert (jp / "JOB-0001" / "20261020_090000_front_window.jpg").exists()
    assert not (jp / "JOB-0001" / "20261025_101500_ztest_photo.txt").exists()
    assert not (jp / "JOB-0042").exists()
    moved = list(h["p"]["backups"].glob("removed_uploads_*/JOB-0042/20261025_101501_ztest_photo.txt"))
    assert moved, "the uploaded test file wasn't kept in the backups folder"
    backups = list(h["p"]["backups"].glob("jobs_db_before_ztest_cleanup_*.db"))
    assert backups and _n(str(backups[0]), "SELECT COUNT(*) FROM mileage_trips") == 4
    # the customer row is only reported (the suite deletes customers through the app)
    assert _n(db, "SELECT COUNT(*) FROM customers WHERE customer_id = 'CUST-2026-9'") == 1
    out = capsys.readouterr().out
    assert "0 test trips, 0 reimbursements, 0 vehicles, 0 uploaded files left" in out, out
    # a second run finds nothing
    assert core.main(["--home", str(h["home"]), "--apply"]) == 0


def test_wrong_home_is_refused(tmp_path, capsys):
    assert core.main(["--home", str(tmp_path / "nobody"), "--apply"]) == 1
    assert "no job database" in capsys.readouterr().out


# ── the reminder every test run prints ──────────────────────────────────────
@pytest.fixture
def pending(tmp_path, monkeypatch):
    mod = _load("_pending_ut", SC / "pending.py")
    monkeypatch.setattr(mod, "PENDING_FILE", tmp_path / "pending.json")
    return mod


def test_reminder_is_short_when_nothing_is_waiting_and_due_after_a_server_run(pending):
    lines = pending.reminder_lines()
    text = "\n".join(lines)
    assert "nothing is waiting" in text and "DUE" not in text
    assert "run_ztest_server_cleanup.bat" in text and "Why:" in text and "mileage" in text
    pending.add("uploaded test photo(s) ztest_photo.txt in JobPhotos\\JOB-0042", "SRV_SCOPE_12")
    pending.add("uploaded test photo(s) ztest_photo.txt in JobPhotos\\JOB-0042", "SRV_SCOPE_12")
    pending.add("server mileage test records", "test_srv_mileage")
    text = "\n".join(pending.reminder_lines())
    assert "SERVER CLEANUP IS DUE - 3 item(s)" in text
    assert text.isascii(), "the reminder must be plain ASCII (Windows consoles aren't UTF-8)"
    assert text.count("JobPhotos\\JOB-0042") == 1 and "server mileage test records" in text
    assert "server_cleanup_done.bat" in text
    assert pending.clear() == 3 and pending.read() == []
    assert "nothing is waiting" in "\n".join(pending.reminder_lines())


def test_every_pytest_run_prints_the_reminder():
    src = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert "def pytest_terminal_summary" in src and "server_cleanup" in src and "pending.py" in src


# ── guard rules the server tests rely on ────────────────────────────────────
@pytest.fixture
def g():
    s = _load("_e2e_safety_srv_ut", ROOT / "tests" / "gui_jobs_e2e" / "safety.py")
    guard = s.Guard()
    guard.learning_resolver = {"L-1": "ZTEST E2E R-042 crew original", "L-2": "Crabby's invoices"}.get
    guard.reimb_resolver = {"REIM-0001": {"crew": "Samual Cronin", "all_test": True},
                            "REIM-0002": "Samual Cronin"}.get
    return s, guard


def test_server_guard_rules(g):
    s, guard = g
    d = lambda tool, **a: guard.check(tool, a)[0]                               # noqa: E731
    assert d("delete_learning", learning_id="L-1") == "allow"
    assert d("delete_learning", learning_id="L-2") == "block"
    assert d("delete_learning", learning_id="L-9") == "block"
    assert d("list_learnings", status="", tag="ztest") == "allow"
    # a trip for a real crew member only when marked as test data
    assert d("add_mileage_trip", for_crew="Vicki Vavro", to_place="x", notes="ZTEST E2E SRV-MI-02") == "allow"
    assert d("add_mileage_trip", for_crew="Vicki Vavro", to_place="x") == "block"
    # submit: a ZTEST driver, or a real user's own period after the owner's check
    assert d("mileage_reimbursement", action="submit") == "block"
    guard.mileage_submit_ok = {"Samual Cronin"}
    assert d("mileage_reimbursement", action="submit") == "allow"
    assert d("mileage_reimbursement", action="submit", crew="Vicki Vavro") == "block"
    guard.mileage_submit_ok = set()
    # approve / return: submitted by this run, or a reimbursement of only test trips
    assert d("mileage_reimbursement", action="approve", reimbursement_id="REIM-0001") == "allow"
    assert d("mileage_reimbursement", action="approve", reimbursement_id="REIM-0002") == "block"
    guard.created.add("REIM-0003")
    assert d("mileage_reimbursement", action="return", reimbursement_id="REIM-0003", note="x") == "allow"
