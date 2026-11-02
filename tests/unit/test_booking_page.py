"""Service booking Phase 1 — the one customer page (booking-spec.md §3, §3.1, §9.1).

Book a service / Request a new service / Report a problem; a phone number on every path;
"new" → a Requested job (no date) in the Jobs app + a linked ticket; "problem" → linked to
the customer's recent job.
Run: run_tests.bat tests\\unit\\test_booking_page.py
"""
import datetime as dt
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import booking_db  # noqa: E402
import desk_db  # noqa: E402
import desk_portal as p  # noqa: E402
import desk_rules as r  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

PHONE, E164, EMAIL = "(386) 555-0142", "+13865550142", "lopez@example.com"
ADDR = {"street": "12 Ocean Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"}


@pytest.fixture
def env(tmp_path):
    tickets = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    desk_db.set_setting(tickets, "portal_enabled", True, edition=r.SOLO)
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    conn = get_connection(jobs)
    conn.executemany("INSERT INTO service_pricing (service_code, category, name, base_price, min_charge) "
                     "VALUES (?, ?, ?, ?, ?)", [("WIN-EXT", "Windows", "Exterior windows", 150.0, 95.0),
                                                ("GUT", "Gutters", "Gutter clean", 120.0, None)])
    conn.close()
    booking_db.sync_services(jobs)
    booking_db.update_service(jobs, "WIN-EXT", online=True)
    sent = []
    p.send_fn = lambda ch, to, subj, text: sent.append((ch, to, text)) or True
    p.channels_fn = lambda: {"email": True, "sms": True}
    p.jobs_db_fn = lambda: jobs
    yield tickets, jobs, sent
    p.send_fn = p.channels_fn = p.jobs_db_fn = None


def api(db, method, path, body=None):
    st, ct, out = p.route(method, "/support-api" + path, query={}, body=json.dumps(body or {}).encode(),
                          content_type="application/json", ip="1.2.3.4", db_path=db, edition=r.SOLO,
                          base_url="https://x.example", business="Blue Wave")
    return st, json.loads(out)


def code_for(sent, to):
    return re.search(r"\b(\d{6})\b", [t for _c, d, t in sent if d == to and "code is" in t][-1]).group(1)


def file_request(env, path, **extra):
    tickets, _jobs, sent = env
    st, d = api(tickets, "POST", "/start", {"name": "Maria Lopez", "phone": PHONE, "email": EMAIL})
    assert st == 200, d
    body = {"contact_id": d["contact_id"], "code": code_for(sent, E164), "path": path, **extra}
    return api(tickets, "POST", "/verify", body)


# ── phone and code ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,out", [("386-555-0142", E164), ("(386) 555 0142", E164), ("1 386 555 0142", E164),
                                     ("+44 20 7946 0958", "+442079460958")])
def test_phone_numbers_are_cleaned(raw, out):
    assert p.clean_phone(raw) == out


@pytest.mark.parametrize("raw,msg", [("", "enter a phone number"), ("555-0142", "doesn't look right"),
                                     ("12345678901234", "doesn't look right")])
def test_bad_phone_numbers_are_refused(raw, msg):
    with pytest.raises(desk_db.DeskError, match=msg):
        p.clean_phone(raw)


def test_every_request_needs_a_phone_and_the_customer_picks_text_or_email(env):
    tickets, _jobs, sent = env
    st, d = api(tickets, "POST", "/start", {"name": "Pat", "email": EMAIL, "send_by": "email"})
    assert st == 400 and "phone number" in d["message"]
    st, d = api(tickets, "POST", "/start", {"name": "Pat", "phone": PHONE, "email": EMAIL, "send_by": "email"})
    assert st == 200 and d["sent_via"] == "email" and sent[-1][1] == EMAIL
    st, d = api(tickets, "POST", "/start", {"name": "Pat", "phone": PHONE})
    assert st == 200 and d["sent_via"] == "sms" and sent[-1][1] == E164           # text is the default
    st, d = api(tickets, "POST", "/start", {"name": "Pat", "phone": PHONE, "send_by": "email"})
    assert st == 400 and "enter your email address" in d["message"]
    assert desk_db.get_contact(tickets, d.get("contact_id") or "CT-0001")["phone"] == E164


# ── which paths the page offers ──────────────────────────────────────────────

def test_default_page_is_report_a_problem_only_as_before(env):
    tickets, _jobs, _sent = env
    st, d = api(tickets, "GET", "/info")
    assert d["paths"] == ["problem"] and d["phone_required"] is True and d["services"] == []
    st, d = file_request(env, "new", service="Exterior windows", address=ADDR)
    assert st == 400 and "isn't available" in d["message"]


def test_paths_setting_is_checked_and_book_is_offered(env):
    tickets, _jobs, _sent = env
    for bad in ([], ["new", "new"], ["fly"]):
        with pytest.raises(desk_db.DeskError, match="booking_paths must list"):
            desk_db.set_setting(tickets, "booking_paths", bad, edition=r.SOLO)
    s = desk_db.set_setting(tickets, "booking_paths", ["problem", "book", "new"], edition=r.SOLO)
    assert s["booking_paths"] == ["book", "new", "problem"]                       # page order
    assert p.page_paths(s) == ["book", "new", "problem"]                          # Phase 2: book is live
    desk_db.set_setting(tickets, "booking_welcome", "  Thanks for choosing Blue Wave!  ", edition=r.SOLO)
    st, d = api(tickets, "GET", "/info")
    assert d["paths"] == ["book", "new", "problem"] and d["welcome"] == "Thanks for choosing Blue Wave!"
    assert d["services"] == [{"code": "WIN-EXT", "name": "Exterior windows", "description": "",
                              "price": "from $95", "bookable": True, "kind": "service"}]  # online ones only
    assert d["backups"] == 2 and d["approval"] == "approve_all"
    with pytest.raises(desk_db.DeskError, match="300 characters"):
        desk_db.set_setting(tickets, "booking_welcome", "x" * 301, edition=r.SOLO)


# ── Request a new service → a Requested job + a linked ticket ───────────────

def test_new_service_request_creates_customer_job_and_ticket(env):
    tickets, jobs, _sent = env
    desk_db.set_setting(tickets, "booking_paths", ["new", "problem"], edition=r.SOLO)
    st, d = file_request(env, "new", service="Exterior windows", service_code="WIN-EXT", address=ADDR,
                         preferred="Tuesday or Thursday mornings", description="Two-storey house")
    assert st == 201 and d["job_id"] == "JOB-0001"
    t = desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None, edition=r.SOLO)
    assert t["title"] == "New service request — Exterior windows" and t["job_id"] == "JOB-0001"
    assert "12 Ocean Ave, New Smyrna Beach FL 32169" in t["description"] and E164 in t["description"]
    conn = get_connection(jobs)
    job = dict(conn.execute("SELECT * FROM jobs WHERE job_id = 'JOB-0001'").fetchone())
    cust = dict(conn.execute("SELECT * FROM customers WHERE customer_id = ?", (job["customer_id"],)).fetchone())
    req = dict(conn.execute("SELECT * FROM booking_requests WHERE job_id = 'JOB-0001'").fetchone())
    conn.close()
    assert job["job_status"] == "Requested" and not job["service_date"]         # never routed
    assert job["service_type"] == "Exterior windows" and job["preferred_days"] == "Tue,Thu"
    assert job["created_by"] == booking_db.WEB_BOOKING and job["street_address"] == "12 Ocean Ave"
    assert (cust["first_name"], cust["last_name"], cust["phone"]) == ("Maria", "Lopez", E164)
    assert req["ticket_id"] == d["ticket_id"] and req["path"] == "new" and req["status"] == "requested"
    assert desk_db.get_contact(tickets, t["contact_id"])["linked_customer_id"] == cust["customer_id"]


def test_a_returning_customer_is_matched_and_never_overwritten(env):
    tickets, jobs, _sent = env
    desk_db.set_setting(tickets, "booking_paths", ["new", "problem"], edition=r.SOLO)
    conn = get_connection(jobs)
    conn.execute("INSERT INTO customers (customer_id, first_name, last_name, phone, email, street_address, city) "
                 "VALUES ('CUST-2026-7', 'Maria', 'Lopez-Grant', '386.555.0142', '', '9 Old Rd', 'Edgewater')")
    conn.close()
    st, d = file_request(env, "new", service="Something odd", address=ADDR)
    assert st == 201
    conn = get_connection(jobs)
    c = dict(conn.execute("SELECT * FROM customers WHERE customer_id = 'CUST-2026-7'").fetchone())
    job = dict(conn.execute("SELECT * FROM jobs WHERE job_id = ?", (d["job_id"],)).fetchone())
    n = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
    conn.close()
    assert n == 1 and job["customer_id"] == "CUST-2026-7"
    assert (c["last_name"], c["street_address"], c["city"]) == ("Lopez-Grant", "9 Old Rd", "Edgewater")
    assert c["email"] == EMAIL                                                    # blanks are filled in
    assert job["street_address"] == "12 Ocean Ave"                                # the job has this address


@pytest.mark.parametrize("extra,msg", [({"address": ADDR}, "which service"),
                                       ({"service": "Windows", "address": {"street": "12 Ocean Ave"}}, "address"),
                                       ({"service": "Windows"}, "address")])
def test_new_service_needs_a_service_and_an_address(env, extra, msg):
    tickets, _jobs, _sent = env
    desk_db.set_setting(tickets, "booking_paths", ["new"], edition=r.SOLO)
    st, d = file_request(env, "new", **extra)
    assert st == 400 and msg in d["message"]


def test_if_the_jobs_app_cant_take_it_the_ticket_is_still_filed(env):
    tickets, _jobs, _sent = env
    desk_db.set_setting(tickets, "booking_paths", ["new"], edition=r.SOLO)
    p.jobs_db_fn = lambda: str(Path(tickets).parent / "nope" / "missing.db")
    st, d = file_request(env, "new", service="Windows", address=ADDR)
    assert st == 201 and d["job_id"] == ""
    msgs = desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None, edition=r.SOLO)["messages"]
    assert any("Couldn't add this to the Jobs app" in m["body"] and m["visibility"] == "internal" for m in msgs)


# ── Report a problem → linked to the customer's recent job ──────────────────

def test_problem_report_links_the_customers_recent_job(env):
    tickets, jobs, _sent = env
    conn = get_connection(jobs)
    conn.execute("INSERT INTO customers (customer_id, first_name, phone) VALUES ('CUST-2026-3', 'Maria', ?)", (E164,))
    recent = (dt.date.today() - dt.timedelta(days=3)).isoformat()
    old = (dt.date.today() - dt.timedelta(days=200)).isoformat()
    conn.executemany("INSERT INTO jobs (job_id, customer_id, service_date, service_type, job_status) VALUES (?,?,?,?,?)",
                     [("JOB-0040", "CUST-2026-3", old, "Gutters", "Complete"),
                      ("JOB-0041", "CUST-2026-3", recent, "Exterior windows", "Complete")])
    conn.close()
    st, d = file_request(env, "problem", title="Streaks on the front windows")
    assert st == 201
    t = desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None, edition=r.SOLO)
    assert t["job_id"] == "JOB-0041" and t["title"] == "Streaks on the front windows"
    assert any("Probably about JOB-0041" in m["body"] and m["visibility"] == "internal" for m in t["messages"])


def test_problem_report_with_no_matching_customer_is_just_a_ticket(env):
    st, d = file_request(env, "problem", title="Leaky gutter")
    tickets = env[0]
    t = desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None, edition=r.SOLO)
    assert st == 201 and not t["job_id"]


# ── 🌐 Web forms settings in AI-Prowler ──────────────────────────────────────

def test_web_forms_settings_save_paths_and_services(env):
    import desk_gui_settings as dgs
    tickets, jobs, _sent = env
    assert dgs.save_paths(tickets, [], r.SOLO) == (False, "Keep at least one choice on the page.")
    assert dgs.save_paths(tickets, ["new", "problem"], r.SOLO)[0]
    assert desk_db.get_settings(tickets)["booking_paths"] == ["new", "problem"]
    rows, problem = dgs.service_rows(jobs)
    assert not problem and {x["code"] for x in rows} == {"WIN-EXT", "GUT"}
    conn = get_connection(jobs)
    conn.execute("INSERT INTO service_pricing (service_code, name) VALUES ('PRESS', 'Driveway wash')")
    conn.close()
    rows, _ = dgs.service_rows(jobs, load=True)                       # "Load from Services & Pricing"
    assert {x["code"] for x in rows} == {"WIN-EXT", "GUT", "PRESS"}
    assert dgs.set_service(jobs, "GUT", online=True, price_display="none") == (True, "Saved.")
    assert dgs.set_service(jobs, "GUT", minutes=5)[0] is False
    assert dgs.service_rows(str(Path(jobs).parent / "none.db"))[1].startswith("No Jobs database yet")


# ── the page, its address and its settings ──────────────────────────────────

def test_the_page_offers_the_paths_and_always_asks_for_a_phone():
    html = (ROOT / "desk" / "support.html").read_text(encoding="utf-8")
    for s in ("How can we help?", "Get a quote", "Report a problem", 'id="fPhone"',          # 2026-11-02: renamed
              "Phone number (so we can call you)", "Send my code by", "send_by: sendBy()", "path: P.path",
              "Enter your phone number so we can reach you.", "P.paths.length === 1"):
        assert s in html, s
    assert "if (want && P.paths.includes(want))" in html                         # ?path=new links


# ── service area (booking-spec.md §5) ───────────────────────────────────────

def test_service_area_zips_are_checked_when_saved(env):
    tickets, _jobs, _sent = env
    s = desk_db.set_setting(tickets, "booking_area_zips", ["32168", " 32169 ", "32168", "32170-1234"], edition=r.SOLO)
    assert s["booking_area_zips"] == ["32168", "32169", "32170"]                 # trimmed, de-duplicated
    for bad in (["3216"], ["ABCDE"], ["32168", "nope"]):
        with pytest.raises(desk_db.DeskError, match="isn't a 5-digit ZIP"):
            desk_db.set_setting(tickets, "booking_area_zips", bad, edition=r.SOLO)
    import desk_gui_settings as dgs
    assert dgs.parse_zips(" 32168, 32169;32170\n32171 ") == ["32168", "32169", "32170", "32171"]
    assert dgs.parse_zips("") == []
    import desk_tools
    assert "booking_area_zips" in desk_tools.SETTING_HELP


def test_outside_the_service_area_is_still_taken_and_flagged(env):
    tickets, jobs, _sent = env
    desk_db.set_setting(tickets, "booking_paths", ["new", "problem"], edition=r.SOLO)
    desk_db.set_setting(tickets, "booking_area_zips", ["32168"], edition=r.SOLO)
    st, d = file_request(env, "new", service="Exterior windows", address=ADDR)          # ZIP 32169
    assert st == 201 and d["out_of_area"] is True and d["job_id"]                     # still a job to call about
    t = desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None, edition=r.SOLO)
    assert t["title"].endswith("(outside service area)")
    assert any("Outside your service area (ZIP 32169)" in m["body"] and m["visibility"] == "internal"
               for m in t["messages"])
    desk_db.set_setting(tickets, "booking_area_zips", ["32168", "32169"], edition=r.SOLO)
    st, d = file_request(env, "new", service="Exterior windows", address=ADDR)
    assert st == 201 and d["out_of_area"] is False
    desk_db.set_setting(tickets, "booking_area_zips", [], edition=r.SOLO)              # blank = everywhere
    st, d = file_request(env, "new", service="Exterior windows", address=ADDR)
    assert st == 201 and d["out_of_area"] is False


def test_out_of_area_and_a_jobs_app_failure_both_reach_the_team(env):
    tickets, _jobs, _sent = env
    desk_db.set_setting(tickets, "booking_paths", ["new"], edition=r.SOLO)
    desk_db.set_setting(tickets, "booking_area_zips", ["32168"], edition=r.SOLO)
    p.jobs_db_fn = lambda: str(Path(tickets).parent / "nope" / "missing.db")
    st, d = file_request(env, "new", service="Windows", address=ADDR)
    body = " ".join(m["body"] for m in desk_db.get_ticket_detail(tickets, d["ticket_id"], actor=None,
                                                                 edition=r.SOLO)["messages"])
    assert "Outside your service area" in body and "Couldn't add this to the Jobs app" in body


def test_page_tells_an_out_of_area_customer_well_call():
    html = (ROOT / "desk" / "support.html").read_text(encoding="utf-8")
    assert "if (d.out_of_area)" in html and "we'll call you at" in html and 'id="outOfArea"' in html


def test_book_address_serves_the_same_page():
    st, ct, body = p.static_page("/book")
    assert st == 200 and b"How can we help?" in body
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert 'path in ("/support", "/book", "/book/")' in src and "_dpo.jobs_db_fn = lambda" in src
