"""
R-075 (2026-10-08, found by the server E2E review of the 10-05 pause feature):
pause_job had no crew check — in server mode any signed-in user, field crew
included, could pause another crew's (or the owner's) job, which also stashes
and clears its dates and drops it off that person's route. Now field crew may
pause/resume only jobs assigned to them (same rule as update_job_spreadsheet);
owner / manager / staff and personal mode are unchanged. E2E: SRV-PAUSE-02/03.

Run: run_tests.bat tests\\mcp_tests\\test_r075_pause_job_crew_scope.py -v
"""
import sqlite3
import sys
from pathlib import Path

import pytest

from db_access import init_db

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

CREW = "Sam Crew"
OTHER = "Val Other"
DAY = "2026-10-08"
TS = "2026-10-08T12:00:00+00:00"


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    conn = sqlite3.connect(path)
    for jid, crew in (("JOB-0101", CREW), ("JOB-0202", OTHER), ("JOB-0303", f"{OTHER}, {CREW}")):
        conn.execute("INSERT INTO jobs (job_id, customer_name, crew, service_date, job_status, last_edited_at) "
                     "VALUES (?,?,?,?,?,?)", (jid, f"cust {jid}", crew, DAY, "Scheduled", TS))
    conn.commit()
    conn.close()
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": path)
    return path


def _as(mcp_mod, monkeypatch, role, name=CREW):
    monkeypatch.setattr(mcp_mod, "_current_user",
                        lambda ctx: {"id": "u-test", "name": name, "role": role})


def _row(path, jid):
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    return dict(c.execute("SELECT paused, service_date, pause_comment FROM jobs WHERE job_id = ?",
                          (jid,)).fetchone())


def test_field_crew_cannot_pause_another_crews_job(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.pause_job(job_id="JOB-0202", paused=True, reason="x", ctx=None)
    assert out.startswith("❌") and "isn't assigned to you" in out, out
    r = _row(env, "JOB-0202")
    assert not r["paused"] and r["service_date"] == DAY and not r["pause_comment"], r


def test_field_crew_cannot_resume_another_crews_job(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "owner", name="Owner")
    assert mcp_mod.pause_job(job_id="JOB-0202", paused=True, ctx=None).startswith("✅")
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.pause_job(job_id="JOB-0202", paused=False, ctx=None)
    assert out.startswith("❌"), out
    assert _row(env, "JOB-0202")["paused"]


@pytest.mark.parametrize("jid", ["JOB-0101", "JOB-0303"], ids=["own", "shared"])
def test_field_crew_pauses_and_resumes_own_job(mcp_mod, env, monkeypatch, jid):
    _as(mcp_mod, monkeypatch, "field_crew")
    assert mcp_mod.pause_job(job_id=jid, paused=True, reason="parts", ctx=None).startswith("✅")
    assert _row(env, jid)["paused"] and not _row(env, jid)["service_date"]
    assert mcp_mod.pause_job(job_id=jid, paused=False, ctx=None).startswith("✅")
    assert _row(env, jid)["service_date"] == DAY


@pytest.mark.parametrize("role", ["owner", "manager", "staff"])
def test_other_roles_unrestricted(mcp_mod, env, monkeypatch, role):
    _as(mcp_mod, monkeypatch, role, name="Someone Else")
    assert mcp_mod.pause_job(job_id="JOB-0202", paused=True, ctx=None).startswith("✅")


def test_personal_mode_unrestricted(mcp_mod, env, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    assert mcp_mod.pause_job(job_id="JOB-0202", paused=True, ctx=None).startswith("✅")
