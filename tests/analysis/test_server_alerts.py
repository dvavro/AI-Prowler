"""
tests/analysis/test_server_alerts.py
====================================
2026-11-02 (David): "add to the server ... New alerts a business owner would pay for (no AI cost) ...
server alerts go only to the owner (Configurable), and managers and crew also get the parts that apply
to them and Crew would only ever see their own jobs, the way the Jobs app already limits them" — plus
AI Analysis Tasks on the server for the owner and managers.

Every test runs against a throwaway job database / users list — never the real ones — and never sends
an email (_send_email is replaced).

Run:  run_tests.bat tests\\analysis\\test_server_alerts.py -v
"""
import datetime
import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import scheduler_engine as se
import scheduler_jobs as sj

TODAY = datetime.date.today()


def _d(offset=0):
    return (TODAY + datetime.timedelta(days=offset)).isoformat()


OWNER = {"id": "david-vavro", "name": "David Vavro", "role": "owner", "email": "owner@x.com"}
MANAGER = {"id": "vicki-vavro", "name": "Vicki Vavro", "role": "manager", "email": "vicki@x.com"}
STAFF = {"id": "sam-lead", "name": "Sam Lead", "role": "staff", "email": "sam@x.com"}
CREW = {"id": "jake-r", "name": "Jake R", "role": "field_crew", "email": "jake@x.com"}
CREW2 = {"id": "mia-k", "name": "Mia K", "role": "field_crew", "email": "mia@x.com"}
TEAM = [OWNER, MANAGER, STAFF, CREW, CREW2]


# ── a throwaway job database ─────────────────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path, monkeypatch):
    import db_schema
    import ai_prowler_mcp
    p = tmp_path / "jobs.db"
    conn = sqlite3.connect(p)
    conn.executescript(db_schema.SCHEMA_SQL)
    conn.commit()
    conn.close()
    monkeypatch.setattr(ai_prowler_mcp, "_resolve_job_db_path", lambda *a, **k: str(p))
    monkeypatch.setattr(sj, "_app_on", lambda g: True)
    monkeypatch.setattr(sj, "_weather", lambda loc, days=3: "Sunny")
    monkeypatch.setattr(sj, "_ar_aging", lambda: "31-60 days: Johnson $450")
    monkeypatch.setattr(sj, "_ticket_lines", lambda **k: ["TKT-9 Leak"] if k.get("overdue") else [])
    monkeypatch.setattr(sj, "_bookings_waiting", lambda: ["BK-1 Ann"])
    monkeypatch.setattr(sj, "_mileage_brief_lines", lambda: ["Fix a mileage gap"])
    monkeypatch.setattr(sj, "_hr_due_count", lambda: 2)
    monkeypatch.setattr(sj, "_owner_location", lambda: "")
    monkeypatch.setattr(sj, "_owner_name", lambda: "David")
    monkeypatch.setattr(sj, "_pending_tasks", lambda: [])
    monkeypatch.setattr(sj, "_server_mode", lambda: True)
    return p


def _exec(p, sql, *rows):
    conn = sqlite3.connect(p)
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.executemany(sql, rows) if rows else conn.execute(sql)
    conn.commit()
    conn.close()


def _job(p, job_id, customer, crew, day=None, status="Unscheduled", city="Port Orange", **kw):
    cols = {"job_id": job_id, "customer_name": customer, "crew": crew, "service_date": day or _d(0),
            "job_status": status, "city": city, "state": "FL", "service_type": kw.pop("service_type", "Windows"),
            **kw}
    _exec(p, f"INSERT INTO jobs ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", tuple(cols.values()))


def _as(person, **extra):
    return {"jobs": {}, "_viewer": person, **extra}


# ── who sees what (the Jobs app's own rules) ─────────────────────────────────────────────────────────

class TestRoleLimits:

    def test_crew_sees_only_their_own_jobs_and_no_money(self, db):
        _job(db, "J1", "Jake's Customer", "Jake R")
        _job(db, "J2", "Mia's Customer", "Mia K")
        _job(db, "J3", "Both Customer", "mia k, JAKE R")              # any case, comma list
        _, body = sj.job_morning_briefing(_as(CREW))
        assert "Jake&#x27;s Customer" in body or "Jake's Customer" in body
        assert "Both Customer" in body
        assert "Mia&#x27;s Customer" not in body and "Mia's Customer" not in body
        for private in ("Overdue Invoices", "Service Desk", "Bookings", "HR", "Mileage"):
            assert private not in body, private

    def test_crew_with_no_jobs_gets_nothing(self, db):
        _job(db, "J2", "Mia's Customer", "Mia K")
        assert sj.job_morning_briefing(_as(CREW)) is None
        assert sj.job_end_of_day_summary(_as(CREW)) is None

    def test_staff_sees_every_job_and_the_desk_but_no_money(self, db):
        _job(db, "J1", "Alpha", "Jake R")
        _job(db, "J2", "Bravo", "Mia K")
        _, body = sj.job_morning_briefing(_as(STAFF))
        assert "Alpha" in body and "Bravo" in body
        assert "Service Desk" in body and "Bookings" in body
        assert "Overdue Invoices" not in body and "HR" not in body
        assert sj.job_overdue_invoice_alert(_as(STAFF)) is None
        assert sj.job_billing_leak(_as(STAFF)) is None
        assert sj.job_weekly_scorecard(_as(STAFF)) is None

    def test_manager_and_owner_see_money_and_hr(self, db):
        _job(db, "J1", "Alpha", "Jake R")
        for person in (OWNER, MANAGER):
            _, body = sj.job_morning_briefing(_as(person))
            assert "Overdue Invoices" in body and "👥 HR" in body and "Mileage" in body
            assert f"Good morning, {person['name']}" in body

    def test_server_briefing_has_no_shared_text_inbox_or_chat_tasks(self, db, monkeypatch):
        monkeypatch.setattr(sj, "_unread_sms_threads", lambda: [{"name": "Somebody", "unread": 3}])
        monkeypatch.setattr(sj, "_pending_tasks", lambda: [{"status": "pending", "label": "Chat task",
                                                            "next_due": _d(-1)}])
        _, body = sj.job_morning_briefing(_as(OWNER))
        assert "Somebody" not in body and "Chat task" not in body

    def test_end_of_day_crew_sees_only_their_jobs(self, db):
        _job(db, "J1", "Alpha", "Jake R", status="Complete")
        _job(db, "J2", "Bravo", "Mia K", status="Complete")
        _job(db, "J3", "Charlie", "Jake R", day=_d(1))
        _, body = sj.job_end_of_day_summary(_as(CREW))
        assert "Alpha" in body and "Charlie" in body and "Bravo" not in body

    def test_service_desk_watch_never_goes_to_crew(self, db):
        assert sj.job_service_desk_watch(_as(CREW)) is None
        assert sj.job_service_desk_watch(_as(STAFF)) is not None


# ── the new no-AI alerts ─────────────────────────────────────────────────────────────────────────────

class TestBillingLeak:

    def test_lists_completed_jobs_with_no_invoice(self, db):
        _job(db, "J1", "Not Billed", "Jake R", day=_d(-3), status="Complete", quote_amount=250)
        _job(db, "J2", "Billed", "Jake R", day=_d(-3), status="Complete", invoice_id="INV-1")
        _job(db, "J3", "Still Open", "Jake R", day=_d(-3), status="In Progress")
        _job(db, "J4", "Billed Other Way", "Jake R", day=_d(-3), status="Complete")
        _exec(db, "INSERT INTO invoices (invoice_id, job_id, total_due) VALUES ('INV-2', 'J4', 100)")
        _exec(db, "INSERT INTO time_entries (entry_id, job_id, entry_date, clock_in, clock_out) VALUES "
                  f"('T1', 'J1', '{_d(-3)}', '{_d(-3)} 08:00:00', '{_d(-3)} 10:30:00')")
        subject, body = sj.job_billing_leak(_as(OWNER))
        assert "Not Billed" in body and "$250.00" in body and "2.5 h logged" in body
        assert "J2 —" not in body and "Still Open" not in body and "Billed Other Way" not in body
        assert "1 job(s) not invoiced" in subject

    def test_silent_when_all_invoiced(self, db):
        _job(db, "J2", "Billed", "Jake R", day=_d(-3), status="Complete", invoice_id="INV-1")
        assert sj.job_billing_leak(_as(OWNER)) is None


class TestScorecard:

    def test_numbers_for_last_week(self, db):
        last = _d(-2)
        _job(db, "J1", "A", "Jake R", day=last, status="Complete", invoice_id="INV-1")
        _job(db, "J2", "B", "Jake R", day=last, status="Unscheduled")
        _exec(db, "INSERT INTO invoices (invoice_id, job_id, invoice_date, total_due, amount_paid, payment_date) "
                  f"VALUES ('INV-1', 'J1', '{last}', 300, 120, '{last}')")
        _exec(db, "INSERT INTO time_entries (entry_id, job_id, entry_date, clock_in, clock_out) VALUES "
                  f"('T1', 'J1', '{last}', '{last} 08:00:00', '{last} 10:00:00'), "
                  f"('T2', 'J2', '{last}', '{last} 11:00:00', '{last} 12:00:00')")
        _exec(db, "INSERT INTO quotes (quote_id, quote_date, status) VALUES "
                  f"('Q1', '{last}', 'Approved'), ('Q2', '{last}', 'Declined'), ('Q3', '{last}', 'Approved')")
        subject, body = sj.job_weekly_scorecard(_as(MANAGER))
        assert "$300.00 invoiced" in subject and "$120.00 collected" in subject
        assert "1 / 2" in body                                  # completed / scheduled
        assert "3.0" in body and "2.0" in body                  # hours logged, hours on invoiced jobs
        assert "66% — 2 won, 1 lost" in body
        assert "1.0 crew hours last week were on jobs with no invoice" in body


class TestQuoteFollowup:

    def _quotes(self, db):
        old = _d(-20)
        _exec(db, "INSERT INTO quotes (quote_id, customer_name, quote_date, quote_total, status, created_by) "
                  "VALUES (?, ?, ?, ?, ?, ?)",
              ("Q1", "Vicki's Lead", old, 500, "Open", "vicki-vavro"),
              ("Q2", "Owner Lead", old, 200, "Open", "David Vavro"),
              ("Q3", "Unknown Writer", old, 100, "Open", "someone-gone"),
              ("Q4", "Fresh", _d(-2), 999, "Open", "vicki-vavro"),
              ("Q5", "Answered", old, 999, "Approved", "vicki-vavro"))

    def test_owner_audience_one_list(self, db):
        self._quotes(db)
        out = sj.job_quote_followup({"jobs": {}, "_audience": "owner", "_owners": ["owner@x.com"], "_team": TEAM})
        assert [o[0] for o in out] == [""]                     # "" = the owner(s); the engine addresses it
        body = out[0][2]
        assert "Vicki" in body and "Owner Lead" in body and "Unknown Writer" in body
        assert "Fresh" not in body and "Answered" not in body

    def test_senders_audience_each_gets_their_own(self, db):
        self._quotes(db)
        out = sj.job_quote_followup({"jobs": {}, "_audience": "senders", "_owners": ["owner@x.com"],
                                     "_team": TEAM})
        by_to = {o[0]: o[2] for o in out}
        assert "Vicki" in by_to["vicki@x.com"] and "Owner Lead" not in by_to["vicki@x.com"]
        owners_part = by_to.get("owner@x.com", "") + by_to.get("", "")
        assert "Owner Lead" in owners_part and "Unknown Writer" in owners_part

    def test_each_quote_only_once_a_week(self, db):
        self._quotes(db)
        cfg = {"jobs": {}, "_audience": "owner", "_owners": ["owner@x.com"], "_team": TEAM}
        assert sj.job_quote_followup(cfg)
        assert sj.job_quote_followup(cfg) is None


class TestAppointmentReminders:

    def test_reminds_tomorrows_customers_once_and_lists_missing_emails(self, db, monkeypatch):
        monkeypatch.setattr(sj, "_business_info", lambda: {"name": "Vavro Field Services", "phone": "555-0100"})
        _exec(db, "INSERT INTO customers (customer_id, first_name, email) VALUES (?, ?, ?)",
              ("C1", "Ann", "ann@cust.com"), ("C2", "Bob", ""))
        _job(db, "J1", "Ann Smith", "Jake R", day=_d(1), customer_id="C1", street_address="1 Main St",
             start_time="9:00 AM", end_time="11:00 AM")
        _job(db, "J2", "Bob Jones", "Jake R", day=_d(1), customer_id="C2")
        _job(db, "J3", "Cancelled Carl", "Jake R", day=_d(1), customer_id="C1", status="Cancelled")
        out = sj.job_appointment_reminders({"jobs": {}, "_owners": ["owner@x.com"]})
        to = [o[0] for o in out]
        assert to.count("ann@cust.com") == 1 and "" in to       # "" = the owner's summary
        ann = next(o for o in out if o[0] == "ann@cust.com")
        assert "Vavro Field Services" in ann[2] and "between 9:00 AM and 11:00 AM" in ann[2] and "555-0100" in ann[2]
        assert ann[3]["phone"] == ""                            # texts off: no phone handed over
        owner = next(o for o in out if o[0] == "")[2]
        assert "Bob Jones" in owner and "No email on file" in owner
        assert sj.job_appointment_reminders({"jobs": {}, "_owners": ["owner@x.com"]}) is None   # once

    def test_texts_customers_but_never_one_who_texted_stop(self, db, monkeypatch):
        monkeypatch.setattr(sj, "_business_info", lambda: {"name": "Vavro Field Services", "phone": "555-0100"})
        monkeypatch.setattr(sj, "_sms_opted_out", lambda ph: ph == "386-555-0002")
        _exec(db, "INSERT INTO customers (customer_id, first_name, email, phone) VALUES (?, ?, ?, ?)",
              ("C1", "Ann", "", "386-555-0001"), ("C2", "Bob", "", "386-555-0002"),
              ("C3", "Cy", "cy@cust.com", "386-555-0003"))
        _job(db, "J1", "Ann Smith", "Jake R", day=_d(1), customer_id="C1", start_time="9:00 AM",
             schedule_type="Hard")
        _job(db, "J2", "Bob Jones", "Jake R", day=_d(1), customer_id="C2")
        _job(db, "J3", "Cy Lee", "Jake R", day=_d(1), customer_id="C3")
        out = sj.job_appointment_reminders({"jobs": {}, "_email_on": False, "_sms_on": True})
        ex = lambda o: o[3] if len(o) > 3 else {}
        cust = [o for o in out if o[0] or ex(o).get("phone")]
        assert sorted(ex(o)["phone"] for o in cust) == ["386-555-0001", "386-555-0003"]
        assert all(o[0] == "" for o in cust)                    # email switched off
        ann = next(o for o in cust if ex(o)["phone"] == "386-555-0001")[3]["sms"]
        assert "Vavro Field Services" in ann and "at 9:00 AM" in ann and "555-0100" in ann and len(ann) <= 320
        summary = next(o for o in out if not o[0] and not ex(o).get("phone"))[2]
        assert "Bob Jones" in summary and "opted out" in summary

    def test_opt_out_reads_the_stop_list(self, monkeypatch):
        import sms_consent as sc
        monkeypatch.setattr(sc, "consent_list", lambda: [{"phone": sc._norm_e164("386-555-0002"),
                                                          "consented": False}])
        assert sj._sms_opted_out("386-555-0002") is True
        assert sj._sms_opted_out("386-555-0001") is False
        assert sj._sms_opted_out("") is False


class TestCrewMyDay:

    def test_only_my_jobs_with_map_links(self, db):
        _job(db, "J1", "Mine", "Jake R", street_address="1 Main St", start_time="8:00 AM",
             service_details="Gate code 1234")
        _job(db, "J2", "Not Mine", "Mia K")
        subject, body = sj.job_crew_my_day(_as(CREW))
        assert "Mine" in body and "Not Mine" not in body
        assert "google.com/maps" in body and "Gate code 1234" in body
        assert sj.job_crew_my_day(_as(STAFF)) is None              # staff with nothing assigned: no email

    def test_staff_gets_only_jobs_assigned_to_them(self, db):
        _job(db, "J1", "Lead Job", "Sam Lead")
        _job(db, "J2", "Crew Job", "Jake R")
        _, body = sj.job_crew_my_day(_as(STAFF))
        assert "Lead Job" in body and "Crew Job" not in body


# ── the engine: who gets what ────────────────────────────────────────────────────────────────────────

class TestRecipients:

    @pytest.fixture(autouse=True)
    def team(self, monkeypatch):
        monkeypatch.setattr(se, "_team", lambda: [dict(p) for p in TEAM])

    def test_audiences(self):
        emails = lambda a: [p["email"] for p in se.recipients(a)]
        assert emails("owner") == ["owner@x.com"]
        assert emails("managers") == ["owner@x.com", "vicki@x.com"]
        assert set(emails("team")) == {p["email"] for p in TEAM}

    def test_no_owner_email_falls_back_to_email_configuration(self, monkeypatch):
        monkeypatch.setattr(se, "_team", lambda: [dict(MANAGER)])
        assert [p["email"] for p in se.recipients("owner", "inbox@x.com")] == ["inbox@x.com"]

    def test_every_alert_defaults_to_owner_only(self):
        for jid, meta in sj.JOB_REGISTRY.items():
            if meta.get("delivery") != "self" and jid != "crew_my_day":
                assert meta["default_audience"] == "owner", jid
        assert se.default_job_config("morning_briefing")["audience"] == "owner"

    def test_audience_must_be_allowed(self):
        meta = sj.JOB_REGISTRY["overdue_invoice_alert"]
        assert se.audience_for("overdue_invoice_alert", meta, {"audience": "team"}) == "owner"   # money: never crew
        assert se.audience_for("overdue_invoice_alert", meta, {"audience": "managers"}) == "managers"

    def test_each_person_gets_their_own_version(self, monkeypatch):
        seen, sent = [], []
        meta = {"fn": lambda c: (seen.append(c["_viewer"]["role"]) or (f"for {c['_viewer']['name']}", "x"))
                if c["_viewer"]["role"] != "field_crew" else None, "audiences": ("owner", "managers", "team")}
        monkeypatch.setattr(se, "_send_email", lambda to, s, b: sent.append((to, s)) or True)
        out = se._deliver("morning_briefing", meta, {}, {"audience": "team"}, "", True)
        assert set(seen) == {"owner", "manager", "staff", "field_crew"} - {"field_crew"} | set()
        assert ("vicki@x.com", "for Vicki Vavro") in sent
        assert not any(to in ("jake@x.com", "mia@x.com") for to, _ in sent)     # crew alert returned None
        assert len(out) == 3

    def test_personal_mode_is_unchanged(self, monkeypatch):
        sent = []
        monkeypatch.setattr(se, "_send_email", lambda to, s, b: sent.append((to, s)) or True)
        meta = {"fn": lambda c: ("Hello", "body") if "_viewer" not in c else None}
        se._deliver("morning_briefing", meta, {}, {}, "me@home.com", False)
        assert sent == [("me@home.com", "Hello")]

    def test_self_addressed_alert_sends_to_each_address(self, monkeypatch):
        sent = []
        monkeypatch.setattr(se, "_send_email", lambda to, s, b: sent.append(to) or True)
        meta = {"fn": lambda c: [("cust@x.com", "Reminder", "b")] + [(o, "Summary", "b") for o in c["_owners"]],
                "delivery": "self", "audiences": ("customers",)}
        se._deliver("appointment_reminders", meta, {}, {}, "", True)
        assert sent == ["cust@x.com", "owner@x.com"]

    def test_server_owner_summary_goes_to_every_owner(self, monkeypatch):
        sent = []
        monkeypatch.setattr(se, "_send_email", lambda to, s, b: sent.append(to) or True)
        meta = {"fn": lambda c: [("", "Summary", "b")], "delivery": "self", "audiences": ("owner",)}
        se._deliver("quote_followup", meta, {}, {}, "", True)
        assert sent == ["owner@x.com"]

    def test_mode_filter(self):
        server, personal = sj.jobs_for_mode(True), sj.jobs_for_mode(False)
        assert "sms_reply_monitor" not in server and "due_analysis_tasks" not in server
        assert "crew_my_day" in server and "quote_followup" in server
        assert "crew_my_day" not in personal and "sms_reply_monitor" in personal
        for both in ("billing_leak", "weekly_scorecard", "appointment_reminders", "morning_briefing"):
            assert both in server and both in personal

    def test_tick_skips_server_only_alerts_in_personal_mode(self, monkeypatch):
        ran = []
        cfg = {"enabled": True, "jobs": {"crew_my_day": {"enabled": True, "time": "every_1h", "days": "daily"}}}
        monkeypatch.setattr(se, "load_config", lambda: cfg)
        monkeypatch.setattr(se, "_read_default_to_email", lambda: "me@home.com")
        monkeypatch.setattr(se, "_is_server", lambda: False)
        monkeypatch.setattr(se, "_deliver", lambda *a, **k: ran.append(a[0]) or [])
        monkeypatch.setattr(se, "_in_interval_hours", lambda now: True)
        se._last_run.pop("crew_my_day", None)
        se._tick()
        assert ran == []


# ── ✉ Email / 📱 Text per alert (2026-11-02, David: "send individual alerts to SMS when enabled ... per
# Alert along with email enable in each proactive alert row") ────────────────────────────────────────

class TestTextAlerts:

    PHONES = {"owner@x.com": "386-555-0100", "vicki@x.com": "386-555-0101", "jake@x.com": "386-555-0102"}

    @pytest.fixture(autouse=True)
    def wiring(self, monkeypatch):
        team = [dict(p, phone=self.PHONES.get(p["email"], "")) for p in TEAM]
        monkeypatch.setattr(se, "_team", lambda: [dict(p) for p in team])
        self.mail, self.texts = [], []
        monkeypatch.setattr(se, "_send_email", lambda to, s, b: self.mail.append(to) or True)
        monkeypatch.setattr(se, "_send_sms", lambda to, text: self.texts.append((to, text)) or True)
        monkeypatch.setattr(se, "texting_ready", lambda: True)

    def test_defaults_email_on_text_off(self):
        cfg = se.default_job_config("morning_briefing")
        assert cfg["email"] is True and cfg["sms"] is False
        assert se.channels({}) == (True, False)
        assert se.channels({"email": False, "sms": True}) == (False, True)

    def test_text_is_short_and_readable(self):
        html = "<h2>x</h2><ul>" + "".join(f"<li><b>Job {i}</b> &amp; more</li>" for i in range(10)) + "</ul>"
        t = se.sms_text("📋 Morning Briefing", html)
        assert t.startswith("📋 Morning Briefing: Job 0 & more; Job 1") and "(+4 more)" in t
        assert len(se.sms_text("S", "<li>" + "x" * 900 + "</li>")) <= se.SMS_LIMIT

    def test_personal_email_and_text(self):
        meta = {"fn": lambda c: ("Hello", "<li>one</li>")}
        se._deliver("morning_briefing", meta, {"sms_to": "386-555-0199"}, {"sms": True}, "me@home.com", False)
        assert self.mail == ["me@home.com"]
        assert self.texts == [("386-555-0199", "Hello: one")]

    def test_personal_text_only(self):
        meta = {"fn": lambda c: ("Hello", "b")}
        se._deliver("morning_briefing", meta, {"sms_to": "386-555-0199"}, {"email": False, "sms": True},
                    "me@home.com", False)
        assert self.mail == [] and [t[0] for t in self.texts] == ["386-555-0199"]

    def test_text_skipped_when_texting_not_set_up(self, monkeypatch):
        monkeypatch.setattr(se, "texting_ready", lambda: False)
        meta = {"fn": lambda c: ("Hello", "b")}
        se._deliver("morning_briefing", meta, {"sms_to": "386-555-0199"}, {"sms": True}, "me@home.com", False)
        assert self.mail == ["me@home.com"] and self.texts == []

    def test_server_each_person_texted_on_their_own_cell(self):
        meta = {"fn": lambda c: (f"for {c['_viewer']['name']}", "b"), "audiences": ("owner", "managers")}
        se._deliver("morning_briefing", meta, {}, {"audience": "managers", "sms": True}, "", True)
        assert sorted(self.mail) == ["owner@x.com", "vicki@x.com"]
        assert sorted(t[0] for t in self.texts) == ["386-555-0100", "386-555-0101"]

    def test_server_text_only_reaches_people_with_no_email(self, monkeypatch):
        monkeypatch.setattr(se, "_team", lambda: [{"id": "o", "name": "O", "role": "owner", "email": "",
                                                    "phone": "386-555-0100"}])
        meta = {"fn": lambda c: ("Hi", "b"), "audiences": ("owner",)}
        se._deliver("morning_briefing", meta, {}, {"email": False, "sms": True}, "", True)
        assert self.mail == [] and [t[0] for t in self.texts] == ["386-555-0100"]

    def test_server_customer_reminder_texts_the_customer_and_the_owner(self):
        meta = {"fn": lambda c: [("", "Reminder", "b", {"phone": "386-555-0500", "sms": "See you tomorrow"}),
                                 ("", "Summary", "<li>Ann</li>")] if c["_sms_on"] else None,
                "delivery": "self", "audiences": ("customers",)}
        se._deliver("appointment_reminders", meta, {}, {"email": False, "sms": True}, "", True)
        assert ("386-555-0500", "See you tomorrow") in self.texts
        assert ("386-555-0100", "Summary: Ann") in self.texts
        assert self.mail == []

    def test_quote_sender_texted_on_their_cell_from_the_admin_tab(self):
        meta = {"fn": lambda c: [("vicki@x.com", "Your quotes", "b")], "delivery": "self",
                "audiences": ("senders",)}
        se._deliver("quote_followup", meta, {}, {"audience": "senders", "sms": True}, "", True)
        assert self.mail == ["vicki@x.com"] and [t[0] for t in self.texts] == ["386-555-0101"]

    def test_tick_runs_with_only_a_text_number(self, monkeypatch):
        ran = []
        cfg = {"enabled": True, "sms_to": "386-555-0199",
               "jobs": {"billing_leak": {"enabled": True, "time": "every_1h", "days": "daily", "sms": True}}}
        monkeypatch.setattr(se, "load_config", lambda: cfg)
        monkeypatch.setattr(se, "_read_default_to_email", lambda: "")
        monkeypatch.setattr(se, "_is_server", lambda: False)
        monkeypatch.setattr(se, "_deliver", lambda *a, **k: ran.append(a[0]) or [])
        monkeypatch.setattr(se, "_in_interval_hours", lambda now: True)
        se._last_run.pop("billing_leak", None)
        se._tick()
        assert ran == ["billing_leak"]


# ── AI Analysis Tasks on the server ─────────────────────────────────────────────────────────────────

class TestServerTasks:

    @pytest.fixture
    def server_home(self, tmp_path, monkeypatch):
        import task_queue_automation as tqa
        h = tmp_path / ".ai-prowler"
        h.mkdir()
        (h / "config.json").write_text(json.dumps({"edition": "business", "mode": "server"}), encoding="utf-8")
        (h / "users.json").write_text(json.dumps({"users": {
            "tok-owner": {"name": "David Vavro", "role": "owner", "email": "owner@x.com"},
            "tok-mgr": {"name": "Vicki Vavro", "role": "manager", "email": "vicki@x.com"},
            "tok-staff": {"name": "Sam Lead", "role": "staff"},
            "tok-gone": {"name": "Old Boss", "role": "manager", "status": "inactive"},
        }}), encoding="utf-8")
        monkeypatch.setattr(tqa, "AI_PROWLER_HOME", h)
        monkeypatch.setattr(tqa, "AI_PROWLER_CONFIG_PATH", h / "config.json")
        return tqa

    def test_task_runs_as_its_owner(self, server_home):
        tqa = server_home
        assert tqa._bearer_token({}) == "tok-owner"                              # made in the server window
        assert tqa._bearer_token({"owner_user_id": "vicki-vavro"}) == "tok-mgr"
        assert tqa._bearer_token({"owner_user_id": "sam-lead"}) == ""           # staff can't own tasks
        assert tqa._bearer_token({"owner_user_id": "old-boss"}) == ""           # inactive
        assert tqa._task_owner_email({"owner_user_id": "vicki-vavro"}) == "vicki@x.com"

    def test_emailed_result_goes_to_the_task_owner(self, server_home):
        tqa = server_home
        p = tqa.build_prompt({"provider": "claude"}, {"label": "Ops", "prompt": "x", "task_id": "t1",
                                                      "output_email": True, "owner_user_id": "vicki-vavro"})
        assert "Send the email to vicki@x.com" in p

    def test_why_not_ready_names_the_missing_owner(self, server_home, monkeypatch):
        tqa = server_home
        monkeypatch.setattr(tqa, "has_key", lambda cfg, task=None: True)
        why = tqa.why_not_ready({"provider": "claude"}, {"owner_user_id": "sam-lead"})
        assert "isn't an active owner or manager" in why


class TestTaskToolGate:

    @staticmethod
    def _ctx(user):
        ctx = MagicMock()
        ctx.request_context.request.state.user = user
        return ctx

    def test_owner_and_managers_only(self):
        import ai_prowler_mcp as ap
        assert ap._task_tools_denied(None) == ""
        assert ap._task_tools_denied(self._ctx(OWNER)) == ""
        assert ap._task_tools_denied(self._ctx(MANAGER)) == ""
        assert ap._task_tools_denied(self._ctx(STAFF)).startswith("❌")
        assert ap._task_tools_denied(self._ctx(CREW)).startswith("❌")

    def test_manager_sees_only_their_own_tasks(self):
        import ai_prowler_mcp as ap
        mine, theirs = {"owner_user_id": "vicki-vavro"}, {"owner_user_id": "david-vavro"}
        assert ap._task_is_mine(mine, self._ctx(MANAGER)) and not ap._task_is_mine(theirs, self._ctx(MANAGER))
        assert ap._task_is_mine(theirs, self._ctx(OWNER)) and ap._task_is_mine(mine, None)

    def test_create_stamps_the_owner_and_staff_is_refused(self, tmp_path, monkeypatch):
        import ai_prowler_mcp as ap
        import custom_tasks_manager as ctm
        monkeypatch.setattr(ctm, "CUSTOM_TASKS_PATH", tmp_path / "tasks.json")
        out = ap.create_analysis_task(label="Ops review", prompt="Look at the week.", ctx=self._ctx(MANAGER))
        assert out.startswith("✅")
        t = ctm.load_custom_tasks()[0]
        assert t["owner_user_id"] == "vicki-vavro" and t["owner_name"] == "Vicki Vavro"
        assert ap.create_analysis_task(label="X", prompt="Y", ctx=self._ctx(STAFF)).startswith("❌")
        assert len(ctm.load_custom_tasks()) == 1

    def test_task_tools_offered_on_a_server_chat_runner_tools_not(self):
        import ai_prowler_mcp as ap
        for name in ("create_analysis_task", "list_analysis_tasks", "update_analysis_task",
                     "delete_analysis_task", "save_analysis_report"):
            assert name not in ap._TIER_A_SUPPRESSED, name
        for name in ("get_pending_analysis_tasks", "complete_analysis_task", "queue_single_task",
                     "get_all_queued_tasks"):
            assert name in ap._TIER_A_SUPPRESSED, name

    def test_server_program_starts_alerts_and_tasks_but_never_on_a_test_server(self):
        src = (Path(__file__).resolve().parents[2] / "ai_prowler_mcp.py").read_text(encoding="utf-8")
        i = src.index('if _rt.get("mode") == "server":')
        block = src[i:i + 2200]
        assert "AIPROWLER_TEST_STATE_DIR" in block
        assert "_srv_alerts.start()" in block and "_tqa_srv.start_scheduler()" in block
