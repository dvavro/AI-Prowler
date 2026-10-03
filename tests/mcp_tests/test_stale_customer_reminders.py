"""
tests/mcp_tests/test_stale_customer_reminders.py
=============================================
Reports -> Customer Reminders (2026-09-23, at the owner's request): search
for active customers overdue for a check-in, an explicit reviewed send
(email or SMS), and a once-a-day HOOK (not the scheduler_engine.py/
scheduler_jobs.py background-thread system, per the owner's explicit
instruction — that system is personal-mode only and requires the desktop GUI
to be open) that emails the OWNER a summary — never a customer directly.
"""
import datetime
import sqlite3
import sys
from pathlib import Path

import pytest

from db_access import init_db
from db_write_ops import (
    db_create_job,
    db_find_stale_customers,
    db_read_settings_stale_customer_days,
    db_read_settings_customer_digest_enabled,
    db_read_settings_customer_reminder_email_enabled,
    db_read_settings_customer_reminder_sms_enabled,
    _maybe_send_stale_customer_digest,
)
import db_write_ops as write_ops

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

TODAY = datetime.date.today()


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _sql(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def _create_customer(db_path, cust_id, name, email="", phone="", status="Active", first_name="", onsite_contact=""):
    _sql(db_path,
         "INSERT INTO customers (customer_id, company_name, first_name, onsite_contact, customer_type, status, email, phone, "
         "street_address, city, state, zip) VALUES (?, ?, ?, ?, 'Residential', ?, ?, ?, '1 Main St', 'NSB', 'FL', '32168')",
         (cust_id, name, first_name, onsite_contact, status, email, phone))


def _create_job(db_path, cust_id, name, service_date, status="Complete"):
    db_create_job(db_path, {
        "CustomerID (Customers!A)": cust_id, "Customer Name / Company": name,
        "Service Date": service_date, "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Job Status": status,
    }, actor="test")


def _set_setting(db_path, key, value):
    _sql(db_path, "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))


# ── Settings readers ────────────────────────────────────────────────────────

def test_default_stale_days_is_60(db_path):
    assert db_read_settings_stale_customer_days(db_path) == 60


def test_reads_the_configured_stale_days(db_path):
    _set_setting(db_path, "Stale Customer Reminder Days", 90)
    assert db_read_settings_stale_customer_days(db_path) == 90


def test_default_digest_is_disabled(db_path):
    assert db_read_settings_customer_digest_enabled(db_path) is False


def test_digest_reads_enabled(db_path):
    _set_setting(db_path, "Customer Reminder Daily Digest", "Enabled")
    assert db_read_settings_customer_digest_enabled(db_path) is True


# ── Per-channel Enable toggles (2026-09-23, at the owner's request) ────────

def test_email_channel_defaults_to_enabled(db_path):
    assert db_read_settings_customer_reminder_email_enabled(db_path) is True


def test_sms_channel_defaults_to_enabled(db_path):
    assert db_read_settings_customer_reminder_sms_enabled(db_path) is True


def test_email_channel_can_be_disabled(db_path):
    _set_setting(db_path, "Customer Reminder Email Enabled", "Disabled")
    assert db_read_settings_customer_reminder_email_enabled(db_path) is False
    assert db_read_settings_customer_reminder_sms_enabled(db_path) is True   # independent


def test_sms_channel_can_be_disabled(db_path):
    _set_setting(db_path, "Customer Reminder SMS Enabled", "Disabled")
    assert db_read_settings_customer_reminder_sms_enabled(db_path) is False
    assert db_read_settings_customer_reminder_email_enabled(db_path) is True   # independent


# ── db_find_stale_customers ─────────────────────────────────────────────────

def test_finds_a_customer_overdue_past_the_threshold(db_path):
    _create_customer(db_path, "CUST-0001", "Riverside Grill", email="a@x.com")
    _create_job(db_path, "CUST-0001", "Riverside Grill", (TODAY - datetime.timedelta(days=90)).isoformat())
    out = db_find_stale_customers(db_path, days_threshold=60)
    assert len(out) == 1 and out[0]["customer_id"] == "CUST-0001" and out[0]["days_since"] == 90


def test_recently_serviced_customer_is_not_stale(db_path):
    _create_customer(db_path, "CUST-0002", "Coastal Dental")
    _create_job(db_path, "CUST-0002", "Coastal Dental", (TODAY - datetime.timedelta(days=10)).isoformat())
    out = db_find_stale_customers(db_path, days_threshold=60)
    assert out == []


def test_never_serviced_active_customer_is_always_due(db_path):
    _create_customer(db_path, "CUST-0003", "New Prospect")
    out = db_find_stale_customers(db_path, days_threshold=60)
    assert len(out) == 1 and out[0]["days_since"] is None


def test_inactive_customer_never_shows_up(db_path):
    _create_customer(db_path, "CUST-0004", "Closed Account", status="Inactive")
    out = db_find_stale_customers(db_path, days_threshold=0)
    assert out == []


def test_scheduled_but_not_completed_job_does_not_count_as_serviced(db_path):
    # A job that's merely SCHEDULED hasn't happened yet — it must not reset
    # the "last serviced" clock the same way a Completed one does.
    _create_customer(db_path, "CUST-0005", "Blue Wave Cafe")
    _create_job(db_path, "CUST-0005", "Blue Wave Cafe", (TODAY + datetime.timedelta(days=5)).isoformat(), status="Scheduled")
    out = db_find_stale_customers(db_path, days_threshold=0)
    assert len(out) == 1 and out[0]["days_since"] is None   # still counts as never (completed-)serviced


def test_uses_the_most_recent_completed_job_not_the_first(db_path):
    _create_customer(db_path, "CUST-0006", "Sunset Villas")
    _create_job(db_path, "CUST-0006", "Sunset Villas", (TODAY - datetime.timedelta(days=200)).isoformat())
    _create_job(db_path, "CUST-0006", "Sunset Villas", (TODAY - datetime.timedelta(days=20)).isoformat())
    out = db_find_stale_customers(db_path, days_threshold=0)
    assert out[0]["days_since"] == 20


def test_defaults_to_the_configured_setting_when_threshold_omitted(db_path):
    _set_setting(db_path, "Stale Customer Reminder Days", 30)
    _create_customer(db_path, "CUST-0007", "Test Co")
    _create_job(db_path, "CUST-0007", "Test Co", (TODAY - datetime.timedelta(days=45)).isoformat())
    out = db_find_stale_customers(db_path)   # no explicit threshold
    assert len(out) == 1


def test_sorted_most_overdue_first_never_serviced_last(db_path):
    _create_customer(db_path, "CUST-A", "A")
    _create_job(db_path, "CUST-A", "A", (TODAY - datetime.timedelta(days=100)).isoformat())
    _create_customer(db_path, "CUST-B", "B")
    _create_job(db_path, "CUST-B", "B", (TODAY - datetime.timedelta(days=300)).isoformat())
    _create_customer(db_path, "CUST-C", "C")   # never serviced
    out = db_find_stale_customers(db_path, days_threshold=0)
    assert [c["customer_id"] for c in out] == ["CUST-B", "CUST-A", "CUST-C"]


def test_name_falls_back_to_first_last_when_no_company(db_path):
    _sql(db_path,
         "INSERT INTO customers (customer_id, first_name, last_name, status, street_address, city, state, zip) "
         "VALUES ('CUST-0008', 'Jane', 'Smith', 'Active', '1 Main St', 'NSB', 'FL', '32168')")
    out = db_find_stale_customers(db_path, days_threshold=0)
    assert out[0]["name"] == "Jane Smith"


# ── contact_name (2026-09-23): the actual person to greet, not the account name ──

def test_contact_name_uses_first_name_when_set(db_path):
    _create_customer(db_path, "CUST-0030", "Riverside Grill LLC", first_name="Jane")
    _create_job(db_path, "CUST-0030", "Riverside Grill LLC", (TODAY - datetime.timedelta(days=100)).isoformat())
    out = db_find_stale_customers(db_path, days_threshold=0)
    assert out[0]["contact_name"] == "Jane"
    assert out[0]["name"] == "Riverside Grill LLC"   # business name stays for display/logging


def test_contact_name_falls_back_to_onsite_contact_for_commercial(db_path):
    _create_customer(db_path, "CUST-0031", "Sunset Villas HOA", onsite_contact="Mike Torres")
    _create_job(db_path, "CUST-0031", "Sunset Villas HOA", (TODAY - datetime.timedelta(days=100)).isoformat())
    out = db_find_stale_customers(db_path, days_threshold=0)
    assert out[0]["contact_name"] == "Mike Torres"


def test_contact_name_falls_back_to_business_name_when_nothing_else_on_file(db_path):
    _create_customer(db_path, "CUST-0032", "No Contact Co")
    _create_job(db_path, "CUST-0032", "No Contact Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    out = db_find_stale_customers(db_path, days_threshold=0)
    assert out[0]["contact_name"] == "No Contact Co"


def test_first_name_wins_over_onsite_contact_when_both_present(db_path):
    _create_customer(db_path, "CUST-0033", "Both Co", first_name="Jane", onsite_contact="Mike Torres")
    _create_job(db_path, "CUST-0033", "Both Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    out = db_find_stale_customers(db_path, days_threshold=0)
    assert out[0]["contact_name"] == "Jane"


# ── The daily digest hook (not the scheduler_engine.py system) ─────────────

def test_digest_sends_nothing_when_disabled(db_path, monkeypatch):
    _create_customer(db_path, "CUST-0009", "Overdue Co")
    sent = []
    monkeypatch.setattr(write_ops, "get_connection", write_ops.get_connection)   # sanity no-op
    import ai_prowler_mcp as ap
    monkeypatch.setattr(ap, "send_email", lambda *a, **k: sent.append(a) or "✅ sent")
    _maybe_send_stale_customer_digest(db_path)
    assert sent == []


def test_digest_emails_owner_when_enabled_and_someone_is_due(db_path, monkeypatch):
    _set_setting(db_path, "Customer Reminder Daily Digest", "Enabled")
    _create_customer(db_path, "CUST-0010", "Overdue Co")
    _create_job(db_path, "CUST-0010", "Overdue Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    import ai_prowler_mcp as ap
    monkeypatch.setattr(ap, "_email_config_load", lambda: {"default_to": "owner@example.com"})
    sent = []
    monkeypatch.setattr(ap, "send_email", lambda to, subj, body, **k: sent.append((to, subj, body)) or "✅ sent")
    _maybe_send_stale_customer_digest(db_path)
    assert len(sent) == 1
    assert sent[0][0] == "owner@example.com"
    assert "Overdue Co" in sent[0][2]


def test_digest_sends_nothing_when_enabled_but_nobody_is_due(db_path, monkeypatch):
    _set_setting(db_path, "Customer Reminder Daily Digest", "Enabled")
    _create_customer(db_path, "CUST-0011", "Fine Co")
    _create_job(db_path, "CUST-0011", "Fine Co", (TODAY - datetime.timedelta(days=5)).isoformat())
    import ai_prowler_mcp as ap
    sent = []
    monkeypatch.setattr(ap, "_email_config_load", lambda: {"default_to": "owner@example.com"})
    monkeypatch.setattr(ap, "send_email", lambda *a, **k: sent.append(a) or "✅ sent")
    _maybe_send_stale_customer_digest(db_path)
    assert sent == []


def test_digest_does_not_run_twice_in_the_same_day(db_path, monkeypatch):
    _set_setting(db_path, "Customer Reminder Daily Digest", "Enabled")
    _create_customer(db_path, "CUST-0012", "Overdue Co")
    _create_job(db_path, "CUST-0012", "Overdue Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    import ai_prowler_mcp as ap
    sent = []
    monkeypatch.setattr(ap, "_email_config_load", lambda: {"default_to": "owner@example.com"})
    monkeypatch.setattr(ap, "send_email", lambda *a, **k: sent.append(a) or "✅ sent")
    _maybe_send_stale_customer_digest(db_path)
    _maybe_send_stale_customer_digest(db_path)
    assert len(sent) == 1   # second call was a no-op — already ran today


def test_digest_never_raises_even_if_email_fails(db_path, monkeypatch):
    _set_setting(db_path, "Customer Reminder Daily Digest", "Enabled")
    _create_customer(db_path, "CUST-0013", "Overdue Co")
    _create_job(db_path, "CUST-0013", "Overdue Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    import ai_prowler_mcp as ap
    monkeypatch.setattr(ap, "_email_config_load", lambda: {"default_to": "owner@example.com"})
    monkeypatch.setattr(ap, "send_email", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("smtp down")))
    _maybe_send_stale_customer_digest(db_path)   # must not raise


def test_digest_is_wired_into_both_read_paths():
    # Confirms this is a HOOK on an ordinary read path, not the
    # scheduler_engine.py background-thread system — exactly as instructed.
    import inspect
    from db_read_ops import db_read_job_spreadsheet, db_get_jobs_changed_since
    assert "_maybe_send_stale_customer_digest" in inspect.getsource(db_read_job_spreadsheet)
    assert "_maybe_send_stale_customer_digest" in inspect.getsource(db_get_jobs_changed_since)


# ── The MCP tools ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod, db_path):
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": db_path)
    return db_path


def _as(mcp_mod, monkeypatch, role):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: {"id": "u1", "name": "Dave", "role": role})


def _personal(mcp_mod, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)


def test_find_stale_customers_tool_owner_allowed(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    _create_customer(env, "CUST-0020", "Overdue Co")
    _create_job(env, "CUST-0020", "Overdue Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    out = mcp_mod.find_stale_customers(days_threshold=60, ctx=None)
    assert out.startswith("✅") and "Overdue Co" in out


@pytest.mark.parametrize("role", ["manager", "staff"])
def test_find_stale_customers_tool_allowed_to_manager_and_staff(mcp_mod, env, monkeypatch, role):
    # R-069 (David 2026-09-29): "Customer reminders should be visible for owner,
    # managers, and staff as it's only informational".
    _as(mcp_mod, monkeypatch, role)
    _create_customer(env, "CUST-0021", "Due Again Co")
    _create_job(env, "CUST-0021", "Due Again Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    out = mcp_mod.find_stale_customers(days_threshold=60, ctx=None)
    assert out.startswith("✅") and "Due Again Co" in out


def test_find_stale_customers_tool_denied_to_field_crew(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.find_stale_customers(ctx=None)
    assert out.startswith("❌") and "field crew" in out.lower()


@pytest.mark.parametrize("role", ["manager", "staff"])
def test_send_customer_reminders_still_owner_only(mcp_mod, env, monkeypatch, role):
    # R-069 opened the LIST only; sending a reminder to a customer stays with the owner.
    _as(mcp_mod, monkeypatch, role)
    out = mcp_mod.send_customer_reminders(customer_ids="CUST-0001", ctx=None)
    assert out.startswith("❌") and "owner" in out.lower()


def test_find_stale_customers_tool_unrestricted_in_personal_mode(mcp_mod, env, monkeypatch):
    _personal(mcp_mod, monkeypatch)
    out = mcp_mod.find_stale_customers(ctx=None)
    assert not out.startswith("❌")


def test_send_customer_reminders_denied_to_non_owner(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.send_customer_reminders(customer_ids="CUST-0001", ctx=None)
    assert out.startswith("❌") and "owner" in out.lower()


def test_send_customer_reminders_sends_email_and_reports_skips(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    _create_customer(env, "CUST-0021", "Has Email", email="cust@example.com")
    _create_job(env, "CUST-0021", "Has Email", (TODAY - datetime.timedelta(days=100)).isoformat())
    _create_customer(env, "CUST-0022", "No Contact")
    _create_job(env, "CUST-0022", "No Contact", (TODAY - datetime.timedelta(days=100)).isoformat())

    sent = []
    monkeypatch.setattr(mcp_mod, "send_email", lambda to, subj, body, **k: sent.append((to, subj, body)) or "✅ sent")
    out = mcp_mod.send_customer_reminders(customer_ids="CUST-0021,CUST-0022", channel="email", ctx=None)
    assert len(sent) == 1 and sent[0][0] == "cust@example.com"
    assert "Has Email" in out and "No Contact" in out and "no email" in out.lower()


def test_default_message_greets_the_contact_name_not_the_business_name(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    _create_customer(env, "CUST-0023", "Riverside Grill LLC", email="grill@example.com", first_name="Jane")
    _create_job(env, "CUST-0023", "Riverside Grill LLC", (TODAY - datetime.timedelta(days=100)).isoformat())
    sent = []
    monkeypatch.setattr(mcp_mod, "send_email", lambda to, subj, body, **k: sent.append(body) or "✅ sent")
    mcp_mod.send_customer_reminders(customer_ids="CUST-0023", channel="email", ctx=None)
    assert sent[0].startswith("Hi Jane,")
    assert "Riverside Grill LLC" not in sent[0]   # the account name doesn't leak into the greeting


def test_custom_message_placeholders_are_substituted_per_recipient(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    _create_customer(env, "CUST-0024", "Alpha Co", email="a@example.com", first_name="Alice")
    _create_job(env, "CUST-0024", "Alpha Co", "2026-06-01", status="Complete")
    _create_customer(env, "CUST-0025", "Beta Co", email="b@example.com", first_name="Bob")
    _create_job(env, "CUST-0025", "Beta Co", "2026-07-01", status="Complete")
    sent = []
    monkeypatch.setattr(mcp_mod, "send_email", lambda to, subj, body, **k: sent.append((to, body)) or "✅ sent")
    mcp_mod.send_customer_reminders(
        customer_ids="CUST-0024,CUST-0025", channel="email",
        message="Hey {name}! Your last visit was {date} — due for another?", ctx=None,
    )
    bodies = {to: b for to, b in sent}
    assert bodies["a@example.com"] == "Hey Alice! Your last visit was 2026-06-01 — due for another?"
    assert bodies["b@example.com"] == "Hey Bob! Your last visit was 2026-07-01 — due for another?"


def test_custom_message_with_no_placeholders_is_sent_verbatim(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    _create_customer(env, "CUST-0026", "Gamma Co", email="g@example.com")
    _create_job(env, "CUST-0026", "Gamma Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    sent = []
    monkeypatch.setattr(mcp_mod, "send_email", lambda to, subj, body, **k: sent.append(body) or "✅ sent")
    mcp_mod.send_customer_reminders(customer_ids="CUST-0026", channel="email", message="We miss you!", ctx=None)
    assert sent[0] == "We miss you!"


def test_disabled_email_channel_blocks_the_send(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    _set_setting(env, "Customer Reminder Email Enabled", "Disabled")
    _create_customer(env, "CUST-0027", "Delta Co", email="d@example.com")
    _create_job(env, "CUST-0027", "Delta Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    sent = []
    monkeypatch.setattr(mcp_mod, "send_email", lambda *a, **k: sent.append(a) or "✅ sent")
    out = mcp_mod.send_customer_reminders(customer_ids="CUST-0027", channel="email", ctx=None)
    assert out.startswith("❌") and "EMAIL" in out and "Customer Reminder Email Enabled" in out
    assert sent == []


def test_disabled_sms_channel_blocks_the_send(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    _set_setting(env, "Customer Reminder SMS Enabled", "Disabled")
    _create_customer(env, "CUST-0028", "Epsilon Co", phone="3865550101")
    _create_job(env, "CUST-0028", "Epsilon Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    sent = []
    monkeypatch.setattr(mcp_mod, "send_sms", lambda *a, **k: sent.append(a) or "✅ sent")
    out = mcp_mod.send_customer_reminders(customer_ids="CUST-0028", channel="sms", ctx=None)
    assert out.startswith("❌") and "SMS" in out and "Customer Reminder SMS Enabled" in out
    assert sent == []


def test_disabling_one_channel_does_not_block_the_other(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    _set_setting(env, "Customer Reminder Email Enabled", "Disabled")
    _create_customer(env, "CUST-0029", "Zeta Co", phone="3865550102")
    _create_job(env, "CUST-0029", "Zeta Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    sent = []
    monkeypatch.setattr(mcp_mod, "send_sms", lambda to, msg, **k: sent.append((to, msg)) or "✅ sent")
    out = mcp_mod.send_customer_reminders(customer_ids="CUST-0029", channel="sms", ctx=None)
    assert out.startswith("✅") and len(sent) == 1


def test_finding_stale_customers_is_never_blocked_by_either_channel_toggle(mcp_mod, env, monkeypatch):
    # Searching is not sending — both toggles off must not affect the search.
    _as(mcp_mod, monkeypatch, "owner")
    _set_setting(env, "Customer Reminder Email Enabled", "Disabled")
    _set_setting(env, "Customer Reminder SMS Enabled", "Disabled")
    _create_customer(env, "CUST-0034", "Eta Co")
    _create_job(env, "CUST-0034", "Eta Co", (TODAY - datetime.timedelta(days=100)).isoformat())
    out = mcp_mod.find_stale_customers(days_threshold=60, ctx=None)
    assert out.startswith("✅") and "Eta Co" in out


def test_send_customer_reminders_requires_customer_ids(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    out = mcp_mod.send_customer_reminders(customer_ids="", ctx=None)
    assert out.startswith("❌")


def test_send_customer_reminders_rejects_bad_channel(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner")
    out = mcp_mod.send_customer_reminders(customer_ids="CUST-0001", channel="carrier-pigeon", ctx=None)
    assert out.startswith("❌")


def test_tools_registered_and_on_both_phone_allow_lists(mcp_mod):
    assert hasattr(mcp_mod, "find_stale_customers") and hasattr(mcp_mod, "send_customer_reminders")
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert src.count('"find_stale_customers"') >= 2
    assert src.count('"send_customer_reminders"') >= 2


_HTML = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")


def test_client_has_the_customer_reminders_section():
    assert 'id="staleCustomerDays"' in _HTML
    assert 'id="staleCustomerMessage"' in _HTML
    assert "async function findStaleCustomers()" in _HTML
    assert "async function sendStaleCustomerReminders(channel)" in _HTML
    assert "mcpCall('find_stale_customers'" in _HTML
    assert "message: customMessage" in _HTML   # the textarea's value is actually sent through
    assert "mcpCall('send_customer_reminders'" in _HTML


def test_client_parser_matches_the_new_customerid_first_line_format():
    # The line format was reordered (CustomerID right after the bullet) so
    # the client's regex can't be fooled by "(contact: X)" also being present
    # in parentheses — locks that the two stay in lock-step.
    assert "var re = /^\\s*•\\s*(\\S+)\\s*—\\s*(.+?)\\s*—\\s*last serviced\\s*(.+?)\\s*—\\s*(.+)$/;" in _HTML


def test_client_grays_out_a_disabled_channel_button():
    assert "_getSettingValue('Customer Reminder Email Enabled')" in _HTML
    assert "_getSettingValue('Customer Reminder SMS Enabled')" in _HTML
    assert "Email Disabled</button>" in _HTML
    assert "Text Disabled</button>" in _HTML
