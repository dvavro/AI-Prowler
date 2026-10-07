"""
tests/mcp_tests/test_email_route_now.py
===================================
"📧 Email Approved Route Now" (2026-09-21): the manual counterpart to Settings
-> "Email Route On Build". Sends the CURRENTLY SAVED route (results + link)
right now, on request — REGARDLESS of the setting's value (the button that
calls it is only shown/enabled client-side when the setting is Disabled; the
tool itself doesn't re-check it, since a manual send is the person's own
explicit choice, not the automatic one the setting governs).
"""
import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

DATE = "2026-09-22"
HOME = {"street": "1500 Shadow Pines Dr", "city": "New Smyrna Beach", "state": "FL", "zip": "32168"}
JOB1_ADDR = "300 Riverside Dr, New Smyrna Beach, FL 32168"
JOB2_ADDR = "421 Faulkner St, New Smyrna Beach, FL 32168"


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(tmp_path / "x.xlsx"))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address", lambda: dict(HOME))
    return tmp_path / "ai_prowler_jobs.db"


@pytest.fixture
def sent(mcp_mod, monkeypatch):
    box = []
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: {"default_to": "boss@example.com"})

    def fake_send(to, subject, body, *a, **k):
        box.append({"to": to, "subject": subject, "body": body})
        return True, "ok"
    monkeypatch.setattr(mcp_mod, "_send_smtp", fake_send)
    return box


def _make_job(mcp_mod, customer, street, lat, lon):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_result = mcp_mod.create_customer({"Company Name": customer}, filepath="", backup=False, ctx=None)
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    out = mcp_mod.create_job({
        "CustomerID": cust_id, "Customer Name / Company": customer, "Service Date": DATE,
        "Street Address": street, "City": "New Smyrna Beach", "State": "FL",
        "Latitude (AI Geocode)": lat, "Longitude (AI Geocode)": lon,
    }, filepath="", backup=False, ctx=None)
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _stop(job_id, address, arrival="07:15"):
    return {"crew": "", "job_id": job_id, "cust_id": None, "address": address,
            "lat": 29.0, "lon": -80.9, "arrival": arrival,
            "leg_drive_min": 5, "leg_drive_miles": 1.0, "map_url": None}


def _route(mcp_mod, env):
    j1 = _make_job(mcp_mod, "Riverside Grill", "300 Riverside Dr", 29.02, -80.92)
    j2 = _make_job(mcp_mod, "Coastal Dental", "421 Faulkner St", 29.03, -80.93)
    from db_route_ops import db_write_route_stops
    db_write_route_stops(str(env), DATE, [_stop(j1, JOB1_ADDR, "07:15"), _stop(j2, JOB2_ADDR, "08:00")],
                         "test", single_crew=True)
    assert mcp_mod._publish_route_links(str(env), DATE, "", None, "test").startswith("📍")
    return j1, j2


def _set_email_setting(env, value):
    conn = sqlite3.connect(env)
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('Email Route On Build', ?)", (value,))
    conn.commit()
    conn.close()


def test_sends_when_setting_is_disabled(mcp_mod, env, sent):
    _route(mcp_mod, env)
    _set_email_setting(env, "Disabled")
    out = mcp_mod.email_route_now(DATE, ctx=None)
    assert out == "📧 Route link and results emailed to boss@example.com"
    assert len(sent) == 1
    assert "https://www.google.com/maps/dir/" in sent[0]["body"]


def test_sends_when_setting_was_never_touched_at_all(mcp_mod, env, sent):
    # No 'Email Route On Build' row written at all — the new default (Disabled)
    # applies, and email_route_now still sends (force=True bypasses the gate).
    _route(mcp_mod, env)
    out = mcp_mod.email_route_now(DATE, ctx=None)
    assert out.startswith("📧")
    assert len(sent) == 1


def test_also_sends_when_setting_is_enabled_force_bypasses_the_gate(mcp_mod, env, sent):
    """Auto-email and manual send are independent — a manual send works the
    same whether the setting is Enabled, Disabled, or never touched."""
    _route(mcp_mod, env)
    _set_email_setting(env, "Enabled")
    out = mcp_mod.email_route_now(DATE, ctx=None)
    assert out.startswith("📧")
    assert len(sent) == 1


def test_no_saved_route_gives_a_clear_warning_not_an_error(mcp_mod, env, sent):
    _make_job(mcp_mod, "Riverside Grill", "300 Riverside Dr", 29.02, -80.92)   # DB exists, no route
    out = mcp_mod.email_route_now(DATE, ctx=None)
    assert out.startswith("⚠️ Nothing to email") and DATE in out
    assert sent == []


def test_includes_the_stop_list_with_times(mcp_mod, env, sent):
    _route(mcp_mod, env)
    mcp_mod.email_route_now(DATE, ctx=None)
    body = sent[0]["body"]
    assert "Riverside Grill" in body and "Coastal Dental" in body
    assert "7:15 AM" in body and "8:00 AM" in body


def test_email_config_missing_gives_a_note_not_a_crash(mcp_mod, env, monkeypatch):
    _route(mcp_mod, env)
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: None)
    out = mcp_mod.email_route_now(DATE, ctx=None)
    assert out.startswith("ℹ️") and "isn't configured" in out


def test_failed_send_is_reported_not_raised(mcp_mod, env, monkeypatch):
    _route(mcp_mod, env)
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: {"default_to": "boss@example.com"})
    monkeypatch.setattr(mcp_mod, "_send_smtp", lambda *a, **k: (False, "SMTP down"))
    out = mcp_mod.email_route_now(DATE, ctx=None)
    assert out.startswith("⚠️") and "SMTP down" in out


def test_registered_and_on_both_phone_allow_lists(mcp_mod):
    assert hasattr(mcp_mod, "email_route_now")
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert src.count('"email_route_now"') >= 2


_HTML = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")


def test_client_has_the_button_on_both_pages():
    assert 'id="jobsEmailRouteBtn"' in _HTML and 'onclick="emailRouteNow(true)"' in _HTML
    assert 'id="routeEmailRouteBtn"' in _HTML and 'onclick="emailRouteNow(false)"' in _HTML
    assert _HTML.count('class="btn btn-ghost email-route-btn"') == 2


def test_client_button_is_always_active_no_setting_based_gating():
    # 2026-09-21 revision: the client no longer reads the setting to
    # enable/disable this button, or shows an "Auto Email..." alternate label —
    # it's always the same active button in both auto-email states, in both
    # personal and server mode, so a server-mode user can self-serve a route an
    # admin approved but they never received.
    assert "async function _emailRouteOnBuildEnabled()" not in _HTML
    assert "async function _refreshEmailRouteButtons()" not in _HTML
    assert "Auto Email Approved Route Enabled" not in _HTML
    assert "mcpCall('email_route_now'" in _HTML
    assert "if (!btns.length || btns[0].disabled) return;" in _HTML   # only guards a send-in-flight
