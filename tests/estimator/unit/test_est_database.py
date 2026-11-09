"""estimator.db: migrations, constraints, backup and restore. Design spec: Data model; Test plan 'Integration'."""
import sqlite3

import pytest

from estimator import config
from estimator.database import (
    MIGRATIONS, backup_database, connect, current_version, integrity_ok, list_backups, migrate, open_database,
    prune_backups, restore_database,
)

NOW = "2026-11-05T00:00:00+00:00"


def _estimate(conn, title="Test"):
    cur = conn.execute(
        "INSERT INTO estimates (company_id, title, created_by, created_at, updated_at) VALUES (?,?,?,?,?)",
        ("co1", title, "jamie", NOW, NOW))
    return cur.lastrowid


def test_data_folder_and_db_created_in_sandbox(estimator_sandbox, db):
    assert config.data_dir() == estimator_sandbox
    assert config.db_path().exists()
    for sub in config.DATA_SUBDIRS:
        assert (estimator_sandbox / sub).is_dir()


def test_migrations_apply_once(db):
    assert current_version(db) == MIGRATIONS[-1][0]
    assert migrate(db) == []                     # second run does nothing
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"estimates", "trade_sections", "line_items", "price_book", "markups", "estimate_events",
            "company_profile", "setup_progress", "schema_migrations"} <= tables


def test_versions_are_unique_and_increasing():
    versions = [v for v, _, _ in MIGRATIONS]
    assert versions == sorted(set(versions))


def test_newer_database_is_refused(db):
    db.execute("INSERT INTO schema_migrations VALUES (9999, 'future', ?)", (NOW,))
    with pytest.raises(RuntimeError, match="newer"):
        migrate(db)


def test_failed_migration_rolls_back(tmp_path, monkeypatch):
    from estimator.database import migrations as mig
    conn = connect(tmp_path / "x.db")
    monkeypatch.setattr(mig, "MIGRATIONS", [(1, "broken", "CREATE TABLE ok_table (a INT); CREATE TABLE ( broken")])
    with pytest.raises(sqlite3.OperationalError):
        mig.migrate(conn)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "ok_table" not in names and mig.current_version(conn) == 0


def test_every_business_table_has_company_or_parent(db):
    for table in ("estimates", "price_book", "markups", "estimate_events", "company_profile", "setup_progress"):
        cols = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        assert "company_id" in cols, table


def test_constraints(db):
    est = _estimate(db)
    sec = db.execute("INSERT INTO trade_sections (estimate_id, module_id, created_at) VALUES (?,?,?)",
                     (est, "concrete", NOW)).lastrowid
    with pytest.raises(sqlite3.IntegrityError):          # negative money
        db.execute("INSERT INTO line_items (trade_section_id, kind, quantity, unit, unit_cost_cents, created_at,"
                   " updated_at) VALUES (?,?,?,?,?,?,?)", (sec, "material", "1", "ea", -1, NOW, NOW))
    with pytest.raises(sqlite3.IntegrityError):          # unknown kind
        db.execute("INSERT INTO line_items (trade_section_id, kind, quantity, unit, unit_cost_cents, created_at,"
                   " updated_at) VALUES (?,?,?,?,?,?,?)", (sec, "gold", "1", "ea", 1, NOW, NOW))
    with pytest.raises(sqlite3.IntegrityError):          # bad status
        db.execute("UPDATE estimates SET status='maybe' WHERE id=?", (est,))
    with pytest.raises(sqlite3.IntegrityError):          # foreign key
        db.execute("INSERT INTO trade_sections (estimate_id, module_id, created_at) VALUES (999, 'x', ?)", (NOW,))


def test_deleting_estimate_cascades(db):
    est = _estimate(db)
    sec = db.execute("INSERT INTO trade_sections (estimate_id, module_id, created_at) VALUES (?,?,?)",
                     (est, "roofing", NOW)).lastrowid
    db.execute("INSERT INTO line_items (trade_section_id, kind, quantity, unit, unit_cost_cents, created_at,"
               " updated_at) VALUES (?,?,?,?,?,?,?)", (sec, "material", "10", "sq", 12000, NOW, NOW))
    db.execute("DELETE FROM estimates WHERE id=?", (est,))
    assert db.execute("SELECT COUNT(*) FROM line_items").fetchone()[0] == 0


def test_backup_and_restore(db):
    _estimate(db, "Before backup")
    b = backup_database()
    assert integrity_ok(b) and b in list_backups()
    _estimate(db, "After backup")
    db.close()
    restore_database(b)
    conn = open_database()
    titles = [r[0] for r in conn.execute("SELECT title FROM estimates")]
    conn.close()
    assert titles == ["Before backup"]
    assert config.db_path().with_suffix(".db.before_restore").exists()


def test_prune_keeps_newest(db):
    made = [backup_database() for _ in range(5)]
    removed = prune_backups(keep=2)
    assert removed == made[:3] and list_backups() == made[3:]


def test_v2_director_tables(db):  # S3-B01
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"director_jobs", "director_steps", "playbook_overrides", "director_settings"} <= names
    for table in ("director_jobs", "director_settings", "playbook_overrides"):
        cols = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        assert "company_id" in cols, table
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO director_settings (company_id, quick_send_limit_cents, updated_at) VALUES ('c', -5, 'now')")


def test_v1_database_upgrades_to_v2(tmp_path):  # S3-B02
    from estimator.database import migrations as mig
    conn = connect(tmp_path / "old.db")
    mig.migrate(conn, target=1)
    conn.execute("INSERT INTO estimates (company_id, title, created_at, updated_at) VALUES ('default', 'old', 'now', 'now')")
    assert mig.migrate(conn) == [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]   # 14: symbols (Coder 2 Sprint 10)
    assert conn.execute("SELECT title FROM estimates").fetchone()[0] == "old"
    conn.close()


def test_restore_refuses_damaged_backup(tmp_path):
    bad = tmp_path / "estimator_bad.db"
    bad.write_bytes(b"not a database")
    with pytest.raises(RuntimeError, match="damaged"):
        restore_database(bad)

