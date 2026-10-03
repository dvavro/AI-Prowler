"""Route email — Settings -> "Email Route On Build" now covers BOTH routing methods.

  * Route Today (free engine, suggest_route_schedule): after building, emails the
    results + the saved phone link when the setting is Enabled.
  * Run AI Route: apply_route_order itself never emails (the AI may call it twice in
    one run); the run's worker emails ONCE at the end via _email_route_results.
  * Setting Disabled -> nothing is sent by either.
"""
import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

DATE = "2026-09-21"
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
    """Email 'configured'; records every message instead of sending."""
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
    """Two jobs, route stored, phone link published — like a finished routing run."""
    j1 = _make_job(mcp_mod, "Riverside Grill", "300 Riverside Dr", 29.02, -80.92)
    j2 = _make_job(mcp_mod, "Coastal Dental", "421 Faulkner St", 29.03, -80.93)
    from db_route_ops import db_write_route_stops
    db_write_route_stops(str(env), DATE, [_stop(j1, JOB1_ADDR, "07:15"), _stop(j2, JOB2_ADDR, "14:03")],
                         "test", single_crew=True)
    assert mcp_mod._publish_route_links(str(env), DATE, "", None, "test").startswith("📍")
    return j1, j2


def _set_email_setting(env, value):
    conn = sqlite3.connect(env)
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('Email Route On Build', ?)", (value,))
    conn.commit()
    conn.close()


# ── the helper ────────────────────────────────────────────────────────────

def test_enabled_emails_results_and_link(mcp_mod, env, sent):
    _route(mcp_mod, env)
    _set_email_setting(env, "Enabled")
    note = mcp_mod._email_route_results(str(env), DATE, "", "", "✅ 2 stops planned", include_stops=False)
    assert note == "📧 Route link and results emailed to boss@example.com"
    assert len(sent) == 1 and sent[0]["to"] == "boss@example.com"
    assert "2 stops" in sent[0]["subject"] and DATE in sent[0]["subject"]
    assert "✅ 2 stops planned" in sent[0]["body"]                      # the results
    assert "https://www.google.com/maps/dir/" in sent[0]["body"]        # the link


def test_disabled_sends_nothing(mcp_mod, env, sent):
    _route(mcp_mod, env)
    _set_email_setting(env, "Disabled")
    assert mcp_mod._email_route_results(str(env), DATE, "", "", "x") == ""
    assert sent == []


def test_unset_setting_defaults_to_disabled(mcp_mod, env, sent):
    # Flipped 2026-09-21: an install that's never touched this key now stays
    # quiet by default, since "📧 Email Approved Route Now" (email_route_now)
    # covers on-demand sending regardless of this setting.
    _route(mcp_mod, env)          # no 'Email Route On Build' row written at all
    assert mcp_mod._email_route_results(str(env), DATE, "", "", "x") == ""
    assert sent == []


def test_stop_list_with_12_hour_times_for_the_ai_email(mcp_mod, env, sent):
    _route(mcp_mod, env)
    _set_email_setting(env, "Enabled")   # testing the helper's own formatting, not the gate itself
    mcp_mod._email_route_results(str(env), DATE, "", "", "Order: Riverside then Coastal.", include_stops=True)
    body = sent[0]["body"]
    assert "Order: Riverside then Coastal." in body
    assert "1. 7:15 AM — Riverside Grill" in body and "2. 2:03 PM — Coastal Dental" in body


def test_server_mode_goes_to_the_callers_own_address(mcp_mod, env, sent):
    _route(mcp_mod, env)
    _set_email_setting(env, "Enabled")
    mcp_mod._email_route_results(str(env), DATE, "", "jake@example.com", "x")
    assert sent[0]["to"] == "jake@example.com"


def test_no_email_setup_gives_a_note_and_sends_nothing(mcp_mod, env, monkeypatch):
    _route(mcp_mod, env)
    _set_email_setting(env, "Enabled")
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: None)
    note = mcp_mod._email_route_results(str(env), DATE, "", "", "x")
    assert note.startswith("ℹ️") and "isn't configured" in note


def test_failed_send_is_reported_not_raised(mcp_mod, env, monkeypatch):
    _route(mcp_mod, env)
    _set_email_setting(env, "Enabled")
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: {"default_to": "boss@example.com"})
    monkeypatch.setattr(mcp_mod, "_send_smtp", lambda *a, **k: (False, "SMTP down"))
    note = mcp_mod._email_route_results(str(env), DATE, "", "", "x")
    assert note.startswith("⚠️") and "SMTP down" in note



def test_nothing_saved_means_nothing_to_email(mcp_mod, env, sent):
    _make_job(mcp_mod, "Riverside Grill", "300 Riverside Dr", 29.02, -80.92)   # DB exists, no route
    assert mcp_mod._email_route_results(str(env), DATE, "", "", "x") == ""
    assert sent == []


# ── the two engines ───────────────────────────────────────────────────────

def test_free_engine_path_emails_once(mcp_mod, env, sent):
    _route(mcp_mod, env)
    _set_email_setting(env, "Enabled")   # default flipped to Disabled 2026-09-21 — must opt in for this test
    out = mcp_mod._with_route_link("✅ planned", str(env), DATE, "", None, "test", email=True)
    assert "📍 Phone route link saved" in out and "📧 Route link and results emailed" in out
    assert len(sent) == 1


def test_free_engine_path_emails_nothing_by_default(mcp_mod, env, sent):
    # The new default: an install that's never touched the setting stays quiet.
    _route(mcp_mod, env)
    out = mcp_mod._with_route_link("✅ planned", str(env), DATE, "", None, "test", email=True)
    assert "📍 Phone route link saved" in out and "📧" not in out
    assert sent == []


def test_ai_engine_apply_path_never_emails(mcp_mod, env, sent):
    _route(mcp_mod, env)
    out = mcp_mod._with_route_link("✅ applied", str(env), DATE, "", None, "test")   # email defaults to False
    assert "📍 Phone route link saved" in out and "📧" not in out
    assert sent == []


def test_publishing_a_link_records_when(mcp_mod, env):
    import time
    before = time.time()
    _route(mcp_mod, env)
    assert mcp_mod._ROUTE_LINK_PUBLISHED_AT[DATE] >= before
