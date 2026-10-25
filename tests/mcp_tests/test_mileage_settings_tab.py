"""Mileage switches on Database → Settings (2026-10-25, Vicki).

The Profile card is gone; tracking on/off, the crew reimbursement period and
each reminder are ordinary Settings rows (Enabled/Disabled). Older databases
said true/false and kept the reminders in one JSON row — the migration that
runs before default seeding converts them, so a seeded default never hides a
choice already made. Off = quiet: no gaps asking for miles, no rebuilding.

Scratch databases only (tmp_path).
"""
import json
import sys
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SRC_ROOT))

import db_mileage_ops as mo  # noqa: E402
from db_access import get_connection  # noqa: E402
from db_schema import apply_schema  # noqa: E402
import db_write_ops  # noqa: E402

MILEAGE_ROWS = ["Mileage Tracking Enabled", "Mileage Reimbursement Period", "Mileage Pay Period Start",
                *mo.REMINDER_SETTING_KEYS.values()]


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "jobs.db")
    conn = get_connection(path)
    apply_schema(conn)
    conn.close()
    return path


def _get(path, key):
    conn = get_connection(path)
    try:
        r = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return r[0] if r else None
    finally:
        conn.close()


def _put(path, key, value):
    conn = get_connection(path)
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.close()


def test_defaults_are_seeded_and_match_the_readers(db):
    db_write_ops.db_seed_default_settings(db)
    for key in MILEAGE_ROWS:
        assert _get(db, key) is not None, key
    assert _get(db, "Mileage Tracking Enabled") == "Enabled"
    assert mo.tracking_enabled(db) is True
    assert mo.get_reimb_settings(db) == {"kind": "monthly", "anchor": "2026-01-05"}
    assert all(mo.get_reminder_settings(db).values())
    keys = [r[0] for r in db_write_ops.DEFAULT_SETTINGS]
    assert len(keys) == len(set(keys))


def test_settings_tab_values_drive_the_switches(db):
    db_write_ops.db_seed_default_settings(db)
    _put(db, "Mileage Tracking Enabled", "Disabled")
    _put(db, "Mileage Reminder - Weekly Review", "Disabled")
    _put(db, "Mileage Reimbursement Period", "Biweekly")
    assert mo.tracking_enabled(db) is False
    r = mo.get_reminder_settings(db)
    assert r["weekly"] is False and r["gaps"] is True
    assert mo.get_reimb_settings(db)["kind"] == "biweekly"


def test_writers_write_enabled_disabled(db):
    mo.set_tracking_enabled(db, False, "owner")
    assert _get(db, "Mileage Tracking Enabled") == "Disabled"
    msg = mo.set_tracking_enabled(db, True, "owner")
    assert _get(db, "Mileage Tracking Enabled") == "Enabled" and "ON" in msg
    mo.set_reminder(db, "odometer", False, "owner")
    assert _get(db, "Mileage Reminder - Odometer") == "Disabled"
    assert mo.get_reminder_settings(db)["odometer"] is False
    assert _get(db, mo.SETTING_REMINDERS) is None, "no JSON row any more"


def test_off_message_says_route_miles_stay(db):
    msg = mo.set_tracking_enabled(db, False, "owner")
    assert "routes still show miles driven" in msg and "Database → Settings" in msg


def test_legacy_true_false_and_json_are_migrated_not_overridden(db):
    _put(db, "Mileage Tracking Enabled", "false")
    _put(db, mo.SETTING_REMINDERS, json.dumps({"gaps": False, "weekly": True, "pay_period": False}))
    assert mo.tracking_enabled(db) is False              # legacy values still read right
    assert mo.get_reminder_settings(db)["gaps"] is False
    db_write_ops.db_seed_default_settings(db)            # migrate, then seed
    assert _get(db, "Mileage Tracking Enabled") == "Disabled"
    assert _get(db, "Mileage Reminder - Daily Gaps") == "Disabled"
    assert _get(db, "Mileage Reminder - Weekly Review") == "Enabled"
    assert _get(db, "Mileage Reminder - Pay Period") == "Disabled"
    assert _get(db, "Mileage Reminder - Odometer") == "Enabled"   # not in the JSON → default
    assert _get(db, mo.SETTING_REMINDERS) is None
    r = mo.get_reminder_settings(db)
    assert r == {"gaps": False, "weekly": True, "pay_period": False, "odometer": True}
    assert db_write_ops.db_seed_default_settings(db) == 0          # idempotent


def test_legacy_true_becomes_enabled(db):
    _put(db, "Mileage Tracking Enabled", "true")
    db_write_ops.db_seed_default_settings(db)
    assert _get(db, "Mileage Tracking Enabled") == "Enabled" and mo.tracking_enabled(db) is True


def test_off_means_no_reminders(db):
    db_write_ops.db_seed_default_settings(db)
    _put(db, "Mileage Tracking Enabled", "Disabled")
    assert mo.due_reminders(db, "u_owner", True) == []
