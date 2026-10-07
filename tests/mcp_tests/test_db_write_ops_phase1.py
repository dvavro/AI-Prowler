"""
Phase 1 tests — Job Board Architecture Spec §11.

Covers db_write_ops.py in isolation (no ai_prowler_mcp.py import, no
openpyxl, no real spreadsheet) — these are the generic create/update
engines and log_time_entry port that Phase 1's actual @mcp.tool()
rewiring will call into. Fully isolated: tmp_path only.

Run: py -m pytest tests\\mcp\\test_db_write_ops_phase1.py -v
"""

import datetime

import pytest

from db_access import get_connection, init_db, transaction
from db_write_ops import (
    CUSTOMERS_HEADER_MAP,
    JOBS_HEADER_MAP,
    db_create_customer,
    db_create_job,
    db_create_quote,
    db_customer_in_crew_scope,
    db_log_time_entry,
    db_update_customer,
    db_update_job,
    generate_next_id,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


# ── ID generation ────────────────────────────────────────────────────────

def test_id_generation_starts_at_one(db_path):
    result = db_create_customer(db_path, {"Company Name": "Blue Wave Cafe"}, actor="david")
    assert "NEW_CUST_ID=CUST-0001" in result


def test_id_generation_increments(db_path):
    db_create_customer(db_path, {"Company Name": "A"}, actor="david")
    result = db_create_customer(db_path, {"Company Name": "B"}, actor="david")
    assert "NEW_CUST_ID=CUST-0002" in result


def test_id_generation_continues_after_a_gap(db_path):
    """Phase 1 spec requirement: highest existing ID is JOB-0007, next
    call produces JOB-0008 — even though 0001-0006 were never inserted
    (a gap, not a dense sequence)."""
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO customers (customer_id) VALUES ('CUST-0001')")
        conn.execute("INSERT INTO jobs (job_id, customer_id) VALUES ('JOB-0007', 'CUST-0001')")
    new_id = generate_next_id(get_connection(db_path), "jobs", "job_id", "JOB", 4)
    assert new_id == "JOB-0008"


# ── Generic create engine / audit trail ─────────────────────────────────

def test_create_customer_maps_headers_and_stamps_audit(db_path):
    result = db_create_customer(
        db_path,
        {
            "Company Name": "Blue Wave Cafe",
            "First Name": "Jane",
            "Last Name": "Smith",
            "Phone": "386-555-0101",
            "Street Address": "42 Beachside Dr",
            "City": "New Smyrna Beach",
            "State": "FL",
            "Status Active/Inactive": "Active",
            # caller-supplied ID must be ignored, per spec
            "CustomerID (CUST-####)": "CUST-9999",
        },
        actor="david",
    )
    assert "NEW_CUST_ID=CUST-0001" in result
    assert "CUST-9999" not in result

    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM customers WHERE customer_id = 'CUST-0001'").fetchone()
    conn.close()
    assert row["company_name"] == "Blue Wave Cafe"
    assert row["first_name"] == "Jane"
    assert row["street_address"] == "42 Beachside Dr"
    assert row["created_by"] == "david"
    assert row["last_edited_by"] == "david"
    assert row["last_edited_at"] is not None
    assert row["version"] == 1


def test_create_customer_reports_unrecognized_columns(db_path):
    result = db_create_customer(db_path, {"Not A Real Column": "x"}, actor="david")
    assert "Columns not found" in result
    assert "Not A Real Column" in result


def test_create_job_newline_header_form_also_resolves(db_path):
    """Callers may pass either the raw newline form or the space-
    normalized form of a header — both must resolve to the same
    column, matching the live spreadsheet's header-detection aliasing."""
    db_create_customer(db_path, {"Company Name": "X"}, actor="david")
    result = db_create_job(
        db_path,
        {"CustomerID (Customers!A)": "CUST-0001", "Job\nStatus": "Scheduled"},
        actor="david",
    )
    assert result.startswith("✅")
    conn = get_connection(db_path)
    row = conn.execute("SELECT job_status FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row["job_status"] == "Scheduled"


# ── Generic update engine ────────────────────────────────────────────────

def test_update_job_partial_match_and_audit_stamp(db_path):
    db_create_customer(db_path, {"Company Name": "Crabby's Daytona"}, actor="david")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Customer Name / Company": "Crabby's Daytona"}, actor="david")

    result = db_update_job(db_path, "crabby", {"Job\nStatus": "Complete"}, actor="mike",
                            id_column="Customer Name / Company")
    assert "✅" in result

    conn = get_connection(db_path)
    row = conn.execute("SELECT job_status, version, last_edited_by FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row["job_status"] == "Complete"
    assert row["version"] == 2
    assert row["last_edited_by"] == "mike"


def test_update_job_no_match_returns_error(db_path):
    result = db_update_job(db_path, "nonexistent", {"Job\nStatus": "Complete"}, actor="mike")
    assert result.startswith("❌")


# ── Crew-scoping parity with update_job_spreadsheet ─────────────────────

def test_field_crew_cannot_update_unassigned_job(db_path):
    db_create_customer(db_path, {"Company Name": "X"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Crew / Technician": "Samantha"}, actor="owner")

    result = db_update_job(db_path, "JOB-0001", {"Job\nStatus": "Complete"},
                            actor="samuel", restrict=True, crew_name="samuel")
    assert result.startswith("❌")
    assert "assigned to you" in result


def test_field_crew_can_update_own_assigned_job(db_path):
    db_create_customer(db_path, {"Company Name": "X"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Crew / Technician": "mike c., samantha"}, actor="owner")

    result = db_update_job(db_path, "JOB-0001", {"Job\nStatus": "Complete"},
                            actor="samantha", restrict=True, crew_name="samantha")
    assert result.startswith("✅")


def test_field_crew_cannot_touch_customer_they_have_no_job_for(db_path):
    db_create_customer(db_path, {"Company Name": "Unrelated Co"}, actor="owner")
    # No jobs row links CUST-0001 to any crew member.
    result = db_update_customer(db_path, "CUST-0001", {"Phone": "555-1111"},
                                 actor="samuel", restrict=True, crew_name="samuel")
    assert result.startswith("❌")
    assert "actually worked a job for" in result


def test_field_crew_can_touch_linked_customer_contact_info(db_path):
    db_create_customer(db_path, {"Company Name": "Linked Co"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Crew / Technician": "samuel"}, actor="owner")
    result = db_update_customer(db_path, "CUST-0001", {"Phone": "555-2222"},
                                 actor="samuel", restrict=True, crew_name="samuel")
    assert result.startswith("✅")


def test_field_crew_locked_customer_fields_rejected(db_path):
    db_create_customer(db_path, {"Company Name": "Linked Co"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Crew / Technician": "samuel"}, actor="owner")
    result = db_update_customer(db_path, "CUST-0001", {"Discount (%)": "50"},
                                 actor="samuel", restrict=True, crew_name="samuel")
    assert result.startswith("❌")
    assert "staff/manager/owner" in result


def test_staff_role_unrestricted_everywhere(db_path):
    """restrict=False (owner/manager/staff) bypasses every crew-scoping
    check, matching _job_crew_scope's return for those roles."""
    db_create_customer(db_path, {"Company Name": "X"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Crew / Technician": "someone-else"}, actor="owner")
    result = db_update_job(db_path, "JOB-0001", {"Job\nStatus": "Complete"},
                            actor="staffmember", restrict=False, crew_name="")
    assert result.startswith("✅")


def test_db_customer_in_crew_scope_direct(db_path):
    db_create_customer(db_path, {"Company Name": "X"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Crew / Technician": "mike c., david vavro"}, actor="owner")
    conn = get_connection(db_path)
    assert db_customer_in_crew_scope(conn, "david vavro", "CUST-0001") is True
    assert db_customer_in_crew_scope(conn, "someone else", "CUST-0001") is False
    assert db_customer_in_crew_scope(conn, "david vavro", "") is False
    conn.close()


# ── log_time_entry: TimeLog row-placement is structurally impossible now ──

def test_clock_in_and_out_no_row_placement_bug(db_path):
    """Spec Phase 1 explicit regression test: the old row-501 bug (a
    stray formula-only cell pushing new entries far below real data)
    cannot recur — there is no 'next empty row' scan at all. Assert
    it anyway rather than assuming."""
    db_create_customer(db_path, {"Company Name": "Harbor Inn"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Customer Name / Company": "Harbor Inn"}, actor="owner")

    result = db_log_time_entry(db_path, "JOB-0001", "start",
                                user_id="", user_display_name="operator")
    assert "Clocked IN" in result
    assert "Entry ID:  TE-0001" in result

    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM time_entries WHERE entry_id = 'TE-0001'").fetchone()
    conn.close()
    assert row is not None
    assert row["clock_out"] is None


def test_clock_out_ownership_keyed_off_real_user_id_fk(db_path):
    """Spec Phase 1 explicit requirement: clock-out ownership match is
    now keyed off a real crew_user_id FK, not name-matching. Two
    different server-mode users clocking in on the same job must each
    only be able to stop their OWN entry."""
    db_create_customer(db_path, {"Company Name": "X"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001"}, actor="owner")
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO users (id, display_name) VALUES ('u_jake', 'Jake')")
        conn.execute("INSERT INTO users (id, display_name) VALUES ('u_karen', 'Karen')")

    db_log_time_entry(db_path, "JOB-0001", "start", user_id="u_jake", user_display_name="Jake")
    db_log_time_entry(db_path, "JOB-0001", "start", user_id="u_karen", user_display_name="Karen")

    conn = get_connection(db_path)
    open_entries = conn.execute(
        "SELECT entry_id, crew_user_id FROM time_entries WHERE job_id = 'JOB-0001' AND clock_out IS NULL"
    ).fetchall()
    conn.close()
    assert len(open_entries) == 2  # both users' shifts coexist — one doesn't block the other

    # Jake cannot be blocked/confused by Karen's open entry when he stops.
    stop_result = db_log_time_entry(db_path, "JOB-0001", "stop", user_id="u_jake", user_display_name="Jake")
    assert "Clocked OUT" in stop_result

    conn = get_connection(db_path)
    jake_entry = conn.execute(
        "SELECT clock_out FROM time_entries WHERE crew_user_id = 'u_jake'"
    ).fetchone()
    karen_entry = conn.execute(
        "SELECT clock_out FROM time_entries WHERE crew_user_id = 'u_karen'"
    ).fetchone()
    conn.close()
    assert jake_entry["clock_out"] is not None
    assert karen_entry["clock_out"] is None  # untouched by Jake's stop


def test_clock_out_writes_actual_duration_back_to_jobs(db_path):
    db_create_customer(db_path, {"Company Name": "X"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001"}, actor="owner")
    db_log_time_entry(db_path, "JOB-0001", "start", user_id="", user_display_name="operator")

    # Backdate clock_in so elapsed comes out > 0 without sleeping in the
    # test. Must use the same local-naive clock db_log_time_entry itself
    # uses (datetime.datetime.now()) — SQLite's own datetime('now') is
    # UTC and would silently introduce a timezone-offset skew here.
    backdated = (datetime.datetime.now() - datetime.timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S")
    with transaction(db_path) as conn:
        conn.execute(
            "UPDATE time_entries SET clock_in = ? WHERE entry_id = 'TE-0001'", (backdated,)
        )

    result = db_log_time_entry(db_path, "JOB-0001", "stop", user_id="", user_display_name="operator")
    assert "Actual Duration written to Jobs_Schedule" in result

    conn = get_connection(db_path)
    row = conn.execute("SELECT actual_duration, actual_duration_unit FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row["actual_duration"] >= 44  # ~45 min, allow for test execution slop
    assert row["actual_duration_unit"] == "min"


def test_starting_twice_on_same_job_blocked_for_same_user(db_path):
    db_create_customer(db_path, {"Company Name": "X"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001"}, actor="owner")
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO users (id, display_name) VALUES ('u_jake', 'Jake')")
    db_log_time_entry(db_path, "JOB-0001", "start", user_id="u_jake", user_display_name="Jake")
    result = db_log_time_entry(db_path, "JOB-0001", "start", user_id="u_jake", user_display_name="Jake")
    assert "already open" in result


def test_ambiguous_job_identifier_rejected(db_path):
    db_create_customer(db_path, {"Company Name": "Alpha Cafe"}, actor="owner")
    db_create_customer(db_path, {"Company Name": "Alpha Bakery"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Customer Name / Company": "Alpha Cafe"}, actor="owner")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0002",
                             "Customer Name / Company": "Alpha Bakery"}, actor="owner")
    result = db_log_time_entry(db_path, "Alpha", "start", user_id="", user_display_name="operator")
    assert "matches 2 jobs" in result
