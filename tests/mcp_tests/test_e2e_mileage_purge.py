"""The E2E suite's mileage cleanup (tests/gui_jobs_e2e/mileage_purge.py) deletes
ONLY test rows — including paid, locked test trips — keeps real ones, saves a
backup first, and refuses to touch a file that isn't the server's database
(2026-10-25). Runs in the normal suite against a throwaway database."""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
E2E = ROOT / "tests" / "gui_jobs_e2e"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(E2E))
    for m in ("mileage_purge", "safety"):
        sys.modules.pop(m, None)
    import db_schema
    import db_mileage_ops as mo
    import mileage_purge as mp
    from safety import SANDBOX_DATE, ZTEST_PREFIX
    db = tmp_path / "jobs.db"
    c = sqlite3.connect(str(db))
    db_schema.apply_schema(c)
    c.commit()
    c.close()
    monkeypatch.setenv("AIPROWLER_E2E_JOBS_DB", str(db))
    yield {"db": str(db), "mo": mo, "mp": mp, "day": SANDBOX_DATE, "Z": ZTEST_PREFIX, "tmp": tmp_path}
    for m in ("mileage_purge", "safety"):
        sys.modules.pop(m, None)


class FakeApi:
    """Answers the two reads the purge's same-database check makes, from the
    database the 'server' really uses (or a different one)."""

    def __init__(self, mo, db, extra_vehicle=False):
        self.mo, self.db, self.extra = mo, db, extra_vehicle

    def call(self, tool, args, expect_ok=True):
        mo = self.mo
        if tool == "get_mileage_log":
            trips = mo.list_trips(self.db, args["start_date"], args["end_date"], include_void=True)
            veh = mo.list_vehicles(self.db)
            v = [{"vehicle_id": x["vehicle_id"], "vin": x["vin"], "active": x["active"]} for x in veh]
            if self.extra:
                v.append({"vehicle_id": "VEH-9999", "vin": "X" * 17, "active": 1})
            return json.dumps({"trips": [{"trip_id": t["trip_id"], "trip_date": t["trip_date"],
                                          "status": t["status"]} for t in trips], "vehicles": v})
        if tool == "mileage_reimbursement":
            return json.dumps(mo.list_reimbursements(self.db), default=str)
        raise AssertionError(f"purge made an unexpected call: {tool}")


def _vin(mo, prefix8, tail):
    v = prefix8 + "0" + tail
    tr = {**{str(i): i for i in range(10)}, **dict(zip("ABCDEFGH", range(1, 9))),
          **dict(zip("JKLMN", range(1, 6))), "P": 7, "R": 9, **dict(zip("STUVWXYZ", range(2, 10)))}
    w = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
    cd = sum(tr[c] * k for c, k in zip(v, w)) % 11
    v = v[:8] + ("X" if cd == 10 else str(cd)) + v[9:]
    assert not mo.validate_vin(v), v
    return v


def _seed(e):
    mo, db, day, Z = e["mo"], e["db"], e["day"], e["Z"]
    vid = lambda out: out.split("Added ")[1].split()[0]                       # noqa: E731
    real_van = vid(mo.add_vehicle(db, _vin(mo, "1GCWGAFP", "CB100001"), "Dave", nickname="White Van"))
    z_van = vid(mo.add_vehicle(db, _vin(mo, "1FTFW1ET", "DF100002"), "e2e", nickname=f"{Z} Work Van",
                               odometer=131200))
    z_car = vid(mo.add_vehicle(db, _vin(mo, "2T1BURHE", "JC100003"), "e2e", nickname=f"{Z} Sam's Corolla",
                               ownership="crew", owner_name=f"{Z} Driver Sam"))
    ids = lambda out: [w.strip(",.") for w in out.split() if w.startswith("TRIP-")]   # noqa: E731
    real = ids(mo.add_trip(db, "Dave", trip_date=day, to_label="Chase Bank", purpose="Bank – deposit checks",
                           miles=2.6, vehicle_id=real_van))[0]
    mo.update_trip(db, real, {"miles": 2.9}, "detour", "Dave")
    marked = ids(mo.add_trip(db, "e2e", trip_date=day, to_label="Home Depot", purpose="Supplies – ladder",
                             miles=3.8, vehicle_id=real_van, notes=f"{Z} receipt #4471"))[0]
    in_test_van = ids(mo.add_trip(db, "e2e", trip_date=day, to_label="Ace Hardware", purpose="Supplies – caulk",
                                  miles=1.4, vehicle_id=z_van))[0]
    registered = ids(mo.add_trip(db, "e2e", trip_date=day, to_label="Chase", purpose="Bank deposit at Chase",
                                 miles=6))[0]
    crew = [ids(mo.add_trip(db, "e2e", trip_date=day, to_label=t, purpose=f"Supplies – {t}", miles=m,
                            crew=f"{Z} Driver Sam", vehicle_id=z_car))[0] for t, m in (("Sunbelt", 8.2),
                                                                                       ("Flagler", 4.1))]
    ukey = mo.user_key("", f"{Z} Driver Sam")
    rid = mo.submit_reimbursement(db, "e2e", ukey, "", f"{Z} Driver Sam").split()[1]
    assert mo.approve_reimbursement(db, rid, "owner", "owner").startswith("✅")
    assert mo.mark_reimbursement_paid(db, rid, "owner", "owner", method="check").startswith("✅")
    mo.set_default_vehicle(db, "owner", z_van, "e2e")
    c = sqlite3.connect(db)
    c.execute("INSERT INTO mileage_review_actions (finding_id, action, acted_at) VALUES (?, 'dismissed', 'x')",
              (f"long_leg:{day}:{marked}",))
    c.execute("INSERT INTO mileage_review_actions (finding_id, action, acted_at) VALUES (?, 'dismissed', 'x')",
              (f"long_leg:{day}:{real}",))
    c.commit()
    c.close()
    return {"real_van": real_van, "z_van": z_van, "z_car": z_car, "real": real, "marked": marked,
            "in_test_van": in_test_van, "registered": registered, "crew": crew, "rid": rid}


def _count(db, sql, args=()):
    c = sqlite3.connect(db)
    try:
        return c.execute(sql, args).fetchone()[0]
    finally:
        c.close()


def test_purge_deletes_only_test_rows_including_paid_ones_and_keeps_real_data(env):
    s, db, mp, mo = _seed(env), env["db"], env["mp"], env["mo"]
    assert env["mp"].leftovers(), "seeded test rows should be seen as leftovers before the purge"
    log = []
    n = mp.purge(FakeApi(mo, db), {s["registered"]}, env["tmp"], log.append, "unit")
    assert "skipped" not in n, n
    assert n["trips"] == 5 and n["reimbursements"] == 1 and n["vehicles"] == 2, n
    assert Path(n["backup"]).exists(), "no backup copy was saved before deleting"
    assert _count(n["backup"], "SELECT COUNT(*) FROM mileage_trips") == 6, "the backup isn't the pre-purge db"
    # test data gone, audit rows included
    for t in [s["marked"], s["in_test_van"], s["registered"], *s["crew"]]:
        assert _count(db, "SELECT COUNT(*) FROM mileage_trips WHERE trip_id = ?", (t,)) == 0, t
        assert _count(db, "SELECT COUNT(*) FROM mileage_trip_edits WHERE trip_id = ?", (t,)) == 0, t
    assert _count(db, "SELECT COUNT(*) FROM mileage_reimbursements") == 0
    assert _count(db, "SELECT COUNT(*) FROM mileage_reimbursement_events") == 0
    for v in (s["z_van"], s["z_car"]):
        assert _count(db, "SELECT COUNT(*) FROM vehicles WHERE vehicle_id = ?", (v,)) == 0
        assert _count(db, "SELECT COUNT(*) FROM odometer_readings WHERE vehicle_id = ?", (v,)) == 0
    assert _count(db, "SELECT COUNT(*) FROM mileage_review_actions WHERE finding_id LIKE ?",
                  (f"%:{s['marked']}",)) == 0
    c = sqlite3.connect(db)
    dv = json.loads(c.execute("SELECT value FROM settings WHERE key = 'Mileage Default Vehicles'").fetchone()[0])
    c.close()
    assert s["z_van"] not in dv.values(), dv
    # real data untouched
    assert _count(db, "SELECT COUNT(*) FROM mileage_trips WHERE trip_id = ?", (s["real"],)) == 1
    assert _count(db, "SELECT COUNT(*) FROM mileage_trip_edits WHERE trip_id = ?", (s["real"],)) == 1
    assert _count(db, "SELECT COUNT(*) FROM vehicles WHERE vehicle_id = ?", (s["real_van"],)) == 1
    assert _count(db, "SELECT COUNT(*) FROM mileage_review_actions WHERE finding_id LIKE ?",
                  (f"%:{s['real']}",)) == 1
    assert mp.leftovers() == []
    # a second run has nothing to do
    assert mp.purge(FakeApi(mo, db), set(), env["tmp"], log.append, "again")["trips"] == 0


def test_purge_refuses_a_file_that_is_not_the_servers_database(env):
    s, db, mp, mo = _seed(env), env["db"], env["mp"], env["mo"]
    before = _count(db, "SELECT COUNT(*) FROM mileage_trips")
    n = mp.purge(FakeApi(mo, db, extra_vehicle=True), set(), env["tmp"], lambda *a: None, "unit")
    assert "skipped" in n and "vehicles" in n["skipped"], n
    assert _count(db, "SELECT COUNT(*) FROM mileage_trips") == before, "it deleted from the wrong database"
    assert not list(env["tmp"].glob("jobs_db_before_mileage_purge_*")), "no backup should be made when skipped"
    assert s["rid"] and mp.leftovers()


def test_purge_without_a_database_file_is_skipped(env, tmp_path, monkeypatch):
    monkeypatch.setenv("AIPROWLER_E2E_JOBS_DB", str(tmp_path / "missing.db"))
    n = env["mp"].purge(None, set(), tmp_path, lambda *a: None, "unit")
    assert "skipped" in n
    assert env["mp"].leftovers() == []
