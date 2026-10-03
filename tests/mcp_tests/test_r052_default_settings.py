"""
R-052 (2026-09-28): the Jobs app Settings card on a fresh (server) database
showed only the 7 invoicing rows — no Route Origin Mode, Start/End Address,
Email Route On Build, workday/lunch hours, reminder switches, etc. Every one
of those has a built-in default in its reader, but the card can only show and
edit rows that exist, and nothing ever created them.

Fix: db_seed_default_settings() adds any missing row with the value its reader
already falls back to (so behaviour is unchanged), never touching an existing
row; read_job_spreadsheet(Settings) and update_job_spreadsheet(Settings) call
it. The card also hides the internal_* bookkeeping rows.

Run: run_tests.bat tests\\mcp\\test_r052_default_settings.py -v
"""
import sqlite3
import sys
from pathlib import Path

import pytest

from db_access import init_db
import db_write_ops as dwo

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

KEYS = [k for k, _, _ in dwo.DEFAULT_SETTINGS]


def _settings(path):
    conn = sqlite3.connect(path)
    try:
        return dict(conn.execute("SELECT key, value FROM settings").fetchall())
    finally:
        conn.close()


def _readers(path):
    return (
        dwo.db_read_route_origin_mode(path), dwo.db_read_route_address(path),
        dwo.db_read_email_route_on_build(path),
        dwo.db_read_settings_workday_start(path), dwo.db_read_settings_workday_end(path),
        dwo.db_read_settings_lunch_break_start(path),
        dwo.db_read_settings_lunch_break_duration_min(path),
        dwo.db_read_settings_hard_time_tolerance_min(path),
        dwo.db_read_settings_recurring_job_lead_days(path),
        dwo.db_read_settings_stale_customer_days(path),
        dwo.db_read_settings_customer_digest_enabled(path),
        dwo.db_read_settings_customer_reminder_email_enabled(path),
        dwo.db_read_settings_customer_reminder_sms_enabled(path),
        dwo.working_days(path),                    # Working Days (2026-10-02)
    )


@pytest.fixture
def db(tmp_path):
    p = str(tmp_path / "jobs.db")
    init_db(p)
    return p


def test_the_16_editable_settings_are_listed():
    # 17 since 2026-10-02: "Working Days" (Vicki) joined the 16 R-052 rows.
    assert len(KEYS) == 17 and len(set(KEYS)) == 17
    for k in ("Route Origin Mode", "Start/End Street Address", "Start/End ZIP",
              "Email Route On Build", "Workday Start Time", "Lunch Break Duration (min)",
              "Hard Time Tolerance (min)", "Recurring Job Lead Time (days)",
              "Customer Reminder SMS Enabled", "Working Days"):
        assert k in KEYS


def test_seeding_a_fresh_db_adds_every_row(db):
    assert dwo.db_seed_default_settings(db) == 17
    s = _settings(db)
    for k in KEYS:
        assert k in s
    assert s["Route Origin Mode"] == "Jobs Only"
    assert s["Email Route On Build"] == "Disabled"
    assert s["Working Days"] == "Mon,Tue,Wed,Thu,Fri"


def test_seeding_changes_no_behaviour(db):
    before = _readers(db)
    dwo.db_seed_default_settings(db)
    assert _readers(db) == before


def test_seeding_is_idempotent(db):
    dwo.db_seed_default_settings(db)
    assert dwo.db_seed_default_settings(db) == 0


def test_existing_values_are_never_overwritten(db):
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO settings (key, value) VALUES ('Route Origin Mode', 'Company Location')")
    conn.execute("INSERT INTO settings (key, value) VALUES ('Workday Start Time', '06:30')")
    conn.commit()
    conn.close()
    assert dwo.db_seed_default_settings(db) == 15
    s = _settings(db)
    assert s["Route Origin Mode"] == "Company Location"
    assert s["Workday Start Time"] == "06:30"


def test_seed_notes_are_stored(db):
    dwo.db_seed_default_settings(db)
    conn = sqlite3.connect(db)
    note = conn.execute("SELECT notes FROM settings WHERE key='Route Origin Mode'").fetchone()[0]
    conn.close()
    assert "Company Location" in note and "Admin" in note


# ── tool level ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def tool_db(db, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": db)
    return db


def _as(mcp_mod, monkeypatch, role):
    monkeypatch.setattr(mcp_mod, "_current_user",
                        lambda ctx: None if role is None else {"id": "u", "name": "T", "role": role})


@pytest.mark.parametrize("role", ["owner", "manager", "staff", None])
def test_reading_settings_shows_the_defaults(role, tool_db, monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, role)
    out = mcp_mod.read_job_spreadsheet(sheet_name="Settings", max_rows=100, ctx=None)
    for k in ("Route Origin Mode", "Start/End City", "Email Route On Build",
              "Customer Reminder Daily Digest"):
        assert f"Setting: {k}" in out, k


def test_field_crew_still_denied_and_nothing_seeded(tool_db, monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.read_job_spreadsheet(sheet_name="Settings", ctx=None)
    assert "Route Origin Mode" not in out
    assert "Route Origin Mode" not in _settings(tool_db)


def test_updating_a_default_row_on_a_fresh_db_works(tool_db, monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, "owner")
    out = mcp_mod.update_job_spreadsheet(
        job_identifier="Start/End City", updates={"Value": "New Smyrna Beach"},
        sheet_name="Settings", id_column="Setting", ctx=None)
    assert out.startswith("✅"), out
    assert _settings(tool_db)["Start/End City"] == "New Smyrna Beach"


def test_card_hides_internal_rows():
    src = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    i = src.index("async function _renderSettingsCard")
    assert "/^_?internal_/i.test(obj['Setting'])" in src[i:i + 3000]
