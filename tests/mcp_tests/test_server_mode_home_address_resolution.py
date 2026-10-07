"""
tests/mcp_tests/test_server_mode_home_address_resolution.py
=======================================================
Mileage-tracking follow-up (2026-09-19), server-mode correction.

_resolve_jobs_only_origin originally only ever checked
db_read_owner_home_address (personal mode's single ~/.ai-prowler/
config.json address). In server mode that's the WRONG address entirely
— it would use the host machine owner's own home for some OTHER crew
member's route. This file covers the fix: db_read_user_home_address_by_
crew_name (the new per-user lookup, reading users.json's home_address
field — the same one the Admin tab's Add/Edit User dialog and
ai_prowler_mcp.py's _resolve_route_home already use) and
_resolve_jobs_only_origin's is_server_mode/crew_name-aware branching.

Each test sets AIPROWLER_TEST_STATE_DIR to its own tmp_path via
monkeypatch.setenv for full per-test isolation, independent of whatever
run_tests.bat set for the whole session.

Run with:
    run_tests.bat tests\\mcp\\test_server_mode_home_address_resolution.py -v
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest
import requests

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from db_access import init_db
from db_write_ops import (
    db_create_job,
    db_reorder_route_stop,
    db_read_user_home_address_by_crew_name,
    _resolve_jobs_only_origin,
)


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    """Isolated ~/.ai-prowler equivalent for this test only."""
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    return tmp_path


def _write_users(state_dir, users: dict):
    (state_dir / "users.json").write_text(json.dumps({"users": users}), encoding="utf-8")


def _write_owner_config(state_dir, **fields):
    (state_dir / "config.json").write_text(json.dumps(fields), encoding="utf-8")


# ── db_read_user_home_address_by_crew_name — direct unit tests ─────────

def test_matches_active_user_case_insensitively(state_dir):
    _write_users(state_dir, {
        "u1": {"name": "Jake Ramirez", "status": "active", "home_address": "1 Jake St, NSB, FL"},
    })
    assert db_read_user_home_address_by_crew_name("jake ramirez") == "1 Jake St, NSB, FL"
    assert db_read_user_home_address_by_crew_name("JAKE RAMIREZ") == "1 Jake St, NSB, FL"


def test_inactive_user_not_matched(state_dir):
    _write_users(state_dir, {
        "u1": {"name": "Jake Ramirez", "status": "inactive", "home_address": "1 Jake St"},
    })
    assert db_read_user_home_address_by_crew_name("Jake Ramirez") == ""


def test_no_matching_user_returns_empty(state_dir):
    _write_users(state_dir, {
        "u1": {"name": "Maria Santos", "status": "active", "home_address": "2 Maria Ave"},
    })
    assert db_read_user_home_address_by_crew_name("Jake Ramirez") == ""


def test_user_with_no_home_address_set_returns_empty(state_dir):
    _write_users(state_dir, {
        "u1": {"name": "Jake Ramirez", "status": "active"},  # no home_address key at all
    })
    assert db_read_user_home_address_by_crew_name("Jake Ramirez") == ""


def test_blank_crew_name_returns_empty_without_reading_file(state_dir):
    _write_users(state_dir, {
        "u1": {"name": "Jake Ramirez", "status": "active", "home_address": "1 Jake St"},
    })
    assert db_read_user_home_address_by_crew_name("") == ""
    assert db_read_user_home_address_by_crew_name("   ") == ""


def test_missing_users_json_returns_empty_not_raises(state_dir):
    # state_dir exists but no users.json written into it.
    assert db_read_user_home_address_by_crew_name("Jake Ramirez") == ""


def test_malformed_users_json_returns_empty_not_raises(state_dir):
    (state_dir / "users.json").write_text("{not valid json", encoding="utf-8")
    assert db_read_user_home_address_by_crew_name("Jake Ramirez") == ""


# ── _resolve_jobs_only_origin — mode-aware branching ────────────────────

class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def _install_geocode_mock(monkeypatch, lat, lon):
    def fake_get(url, *args, **kwargs):
        if "nominatim.openstreetmap.org/search" in url:
            return _FakeResponse([{"lat": str(lat), "lon": str(lon)}])
        raise AssertionError(f"unexpected URL: {url}")
    monkeypatch.setattr(requests, "get", fake_get)


def test_server_mode_uses_matching_crew_home_address(state_dir, monkeypatch):
    _install_geocode_mock(monkeypatch, 29.5, -81.5)
    # A DIFFERENT address in owner config — proves server mode doesn't
    # accidentally fall back to it (the actual bug this whole file guards).
    _write_owner_config(state_dir, owner_street="99 Wrong House Rd", owner_city="Elsewhere",
                         owner_state="FL", owner_zip="00000")
    _write_users(state_dir, {
        "u1": {"name": "Jake Ramirez", "status": "active", "home_address": "1 Jake St, NSB, FL"},
    })
    result = _resolve_jobs_only_origin(None, None, crew_name="Jake Ramirez", is_server_mode=True)
    assert result == (29.5, -81.5)


def test_server_mode_no_crew_match_returns_none_never_falls_back_to_owner_config(state_dir, monkeypatch):
    """The actual bug: server mode must NEVER use the personal owner
    config as a stand-in for an unmatched crew member — that would be
    some other person's home address."""
    _install_geocode_mock(monkeypatch, 29.5, -81.5)
    _write_owner_config(state_dir, owner_street="99 Wrong House Rd", owner_city="Elsewhere",
                         owner_state="FL", owner_zip="00000")
    _write_users(state_dir, {
        "u1": {"name": "Maria Santos", "status": "active", "home_address": "2 Maria Ave"},
    })
    result = _resolve_jobs_only_origin(None, None, crew_name="Jake Ramirez", is_server_mode=True)
    assert result is None


def test_server_mode_blank_crew_returns_none(state_dir, monkeypatch):
    _install_geocode_mock(monkeypatch, 29.5, -81.5)
    _write_owner_config(state_dir, owner_street="99 Wrong House Rd", owner_city="Elsewhere",
                         owner_state="FL", owner_zip="00000")
    result = _resolve_jobs_only_origin(None, None, crew_name="", is_server_mode=True)
    assert result is None


def test_personal_mode_still_uses_owner_config_unaffected(state_dir, monkeypatch):
    """Regression guard: personal mode's own resolution path (added
    earlier the same day) is untouched by the server-mode branch added
    alongside it."""
    _install_geocode_mock(monkeypatch, 29.0, -80.9)
    _write_owner_config(state_dir, owner_street="1 Home St", owner_city="NSB",
                         owner_state="FL", owner_zip="32168")
    result = _resolve_jobs_only_origin(None, None, crew_name="", is_server_mode=False)
    assert result == (29.0, -80.9)


def test_explicit_gps_always_wins_regardless_of_mode(state_dir):
    # No geocode mock installed at all — if this tried to geocode
    # anything, it would raise on the unmocked requests.get call.
    result = _resolve_jobs_only_origin(40.0, -75.0, crew_name="Jake Ramirez", is_server_mode=True)
    assert result == (40.0, -75.0)


# ── Integration: db_reorder_route_stop actually uses the right address ──

def _seed_stop(db_path, stop_number, job_id=None, lat=29.0, lon=-80.9,
                eta=None, address="", route_date="2026-09-22", crew_id="Jake Ramirez"):
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, address, "
        "latitude, longitude, eta, created_by, last_edited_by, last_edited_at, version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'seed', 'seed', '2026-01-01T00:00:00Z', 1)",
        (route_date, crew_id, stop_number, job_id, address, lat, lon, eta),
    )
    conn.commit()
    stop_id = cur.lastrowid
    conn.close()
    return stop_id


def _get_stop(db_path, stop_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM route_stops WHERE id = ?", (stop_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def test_reorder_route_stop_uses_moving_stops_own_crew_home_address(tmp_path, state_dir, monkeypatch):
    """End-to-end: a manual reorder that touches position 1, in server
    mode, resolves the MOVING STOP's own crew member's home address —
    not the host machine's personal owner config, not some other crew
    member's address."""
    def fake_get(url, *args, **kwargs):
        if "router.project-osrm.org/route" in url:
            return _FakeResponse({"code": "Ok", "routes": [{"legs": [{"duration": 900, "distance": 8000}]}]})
        if "nominatim.openstreetmap.org/search" in url:
            return _FakeResponse([{"lat": "29.5", "lon": "-81.5"}])
        raise AssertionError(f"unexpected URL: {url}")
    monkeypatch.setattr(requests, "get", fake_get)

    _write_owner_config(state_dir, owner_street="99 Wrong House Rd", owner_city="Elsewhere",
                         owner_state="FL", owner_zip="00000")
    _write_users(state_dir, {
        "u1": {"name": "Jake Ramirez", "status": "active", "home_address": "1 Jake St, NSB, FL"},
        "u2": {"name": "Maria Santos", "status": "active", "home_address": "2 Maria Ave, NSB, FL"},
    })

    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Stop 1", crew_id="Jake Ramirez")
    s2 = _seed_stop(db_path, 2, eta="08:20", address="Stop 2", crew_id="Jake Ramirez")

    result = db_reorder_route_stop(db_path, s2, 1, actor="dave", is_server_mode=True)
    assert result.startswith("✅"), result

    moved = _get_stop(db_path, s2)
    assert moved["leg_drive_min"] == 15  # 900 sec, Jake's own leg
    assert moved["leg_drive_miles"] is not None
