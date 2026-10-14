"""
"Job Tracker & Routing" and "SMS & WhatsApp" default to OFF (David, 2026-10-12)
— in personal AND server mode — for NEW installs only. An install that already
uses them keeps them on; a choice saved in Settings always wins.

Each test uses its own empty state folder (a "new install").
Run: run_tests.bat tests\\unit\\test_default_off_groups.py -v
"""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def tcs(tmp_path, monkeypatch):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    import tool_config_store as m
    monkeypatch.setattr(m, "_sms_in_use", lambda: False)
    monkeypatch.setitem(m._IN_USE, "sms_whatsapp", lambda: m._sms_in_use())
    return m, tmp_path


def _make_jobs_db(d: Path, with_rows: bool):
    p = d / "jobs_database"
    p.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p / "ai_prowler_jobs.db")
    con.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT)")
    con.execute("CREATE TABLE jobs (id INTEGER PRIMARY KEY, title TEXT)")
    if with_rows:
        con.execute("INSERT INTO customers (name) VALUES ('ZTEST')")
    con.commit()
    con.close()


@pytest.mark.parametrize("mode", ["personal", "server"])
def test_new_install_both_groups_off(tcs, mode):
    m, _ = tcs
    assert m.group_enabled(mode, "job_tracker") is False
    assert m.group_enabled(mode, "sms_whatsapp") is False
    assert m.group_enabled(mode, "core_kb") is True          # other groups unaffected


@pytest.mark.parametrize("mode", ["personal", "server"])
def test_empty_jobs_database_still_counts_as_new(tcs, mode):
    m, d = tcs
    _make_jobs_db(d, with_rows=False)
    assert m.group_enabled(mode, "job_tracker") is False


@pytest.mark.parametrize("mode", ["personal", "server"])
def test_existing_install_with_jobs_data_keeps_job_tracker_on(tcs, mode):
    m, d = tcs
    _make_jobs_db(d, with_rows=True)
    assert m.group_enabled(mode, "job_tracker") is True


def test_server_with_a_crew_counts_as_in_use_even_with_empty_job_tables(tcs):
    """David's server, 2026-10-12: E2E cleanup emptied the job tables, but the
    crew (several users) still use the Jobs app."""
    m, d = tcs
    _make_jobs_db(d, with_rows=False)
    (d / "users.json").write_text('{"users": {"t1": {"name": "A"}, "t2": {"name": "B"}}}', encoding="utf-8")
    assert m.group_enabled("server", "job_tracker") is True


def test_any_job_table_with_rows_counts(tcs):
    m, d = tcs
    _make_jobs_db(d, with_rows=False)
    con = sqlite3.connect(d / "jobs_database" / "ai_prowler_jobs.db")
    con.execute("CREATE TABLE invoices (id INTEGER PRIMARY KEY)")
    con.execute("INSERT INTO invoices DEFAULT VALUES")
    con.commit()
    con.close()
    assert m.group_enabled("personal", "job_tracker") is True


def test_first_decision_is_recorded_and_does_not_flip(tcs):
    m, d = tcs
    _make_jobs_db(d, with_rows=True)
    assert m.group_enabled("server", "job_tracker") is True
    assert m.saved_group_choice("server", "job_tracker") is True, "decision not recorded"
    (d / "jobs_database" / "ai_prowler_jobs.db").unlink()          # data later emptied
    assert m.group_enabled("server", "job_tracker") is True


def test_existing_install_with_sms_set_up_keeps_sms_on(tcs, monkeypatch):
    m, _ = tcs
    monkeypatch.setattr(m, "_sms_in_use", lambda: True)
    assert m.group_enabled("server", "sms_whatsapp") is True


def test_saved_choice_wins_both_ways_and_config_json_untouched(tcs):
    m, d = tcs
    (d / "config.json").write_text('{"mode": "server"}', encoding="utf-8")
    before = (d / "config.json").read_bytes()
    _make_jobs_db(d, with_rows=True)
    m.set_group_enabled("server", "job_tracker", False)        # in use, but switched off
    assert m.group_enabled("server", "job_tracker") is False
    assert m.group_enabled("personal", "job_tracker") is True   # other mode untouched
    m.set_group_enabled("personal", "sms_whatsapp", True)       # new install, switched on
    assert m.group_enabled("personal", "sms_whatsapp") is True
    m.save_disabled_tools(["send_email"], "server")
    assert m.saved_group_choice("server", "job_tracker") is False, "saving the list dropped the choice"
    m.set_hr_apps_enabled(True)
    assert m.saved_group_choice("personal", "sms_whatsapp") is True, "the HR switch dropped the choice"
    assert (d / "config.json").read_bytes() == before


def test_bad_arguments(tcs):
    m, _ = tcs
    with pytest.raises(ValueError):
        m.group_enabled("both", "job_tracker")
    with pytest.raises(ValueError):
        m.set_group_enabled("server", "core_kb", False)


def test_server_and_panel_use_the_rule():
    mcp = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    gui = (ROOT / "rag_gui.py").read_text(encoding="utf-8")
    assert "_tcs_g.group_enabled(_mode_g, _grp)" in mcp
    assert "_USER_DISABLED_TOOLS = _USER_DISABLED_TOOLS | _DEFAULT_OFF_DISABLED" in mcp
    assert "_tcs_g.group_enabled(_tool_cfg_mode_key, _grp)" in gui
    assert "_tcs.set_group_enabled(" in gui
