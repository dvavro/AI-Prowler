"""2026-10-12: R-090 / R-091 are fixed — update the tests.
  * test_hr_timemachine_flow.py: run the new 5am lifecycle job each simulated
    day; TM-LIFE-01..03 are no longer expected failures
  * test_srv_hr_features.py HF-18: no longer xfail; terminate with a last day
    in the PAST (-> Terminated at once, portal refused) — a future last day
    keeps access until then (covered by the unit tests)
ASCII output."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def edit(rel, pairs):
    p = ROOT / rel
    s = p.read_text(encoding="utf-8")
    for old, new in pairs:
        assert s.count(old) == 1, f"{rel}: {old[:80]!r} found {s.count(old)}x"
        s = s.replace(old, new)
    compile(s, rel, "exec")
    p.write_bytes(s.encode("utf-8"))
    print(f"{rel}: {len(pairs)} change(s)")


edit("tests/mcp_tests/test_hr_timemachine_flow.py", [
    ('''        for job in (hs.job_overdue_checker, hs.job_reminder_48h, hs.job_prestart_welcome,''',
     '''        for job in (hs.job_lifecycle_advance, hs.job_overdue_checker, hs.job_reminder_48h,
                    hs.job_prestart_welcome,'''),
    ('''# ── lifecycle status (R-090: nothing advances it today) ──────────────────────
R090 = pytest.mark.xfail(strict=True, reason="R-090: no HR job advances employee status over time")


@R090
def test_TM_LIFE_01''', '''# ── lifecycle status (R-090, fixed 2026-10-12: job_lifecycle_advance, daily 5am) ─
def test_TM_LIFE_01'''),
    ('''@R090
def test_TM_LIFE_02''', '''def test_TM_LIFE_02'''),
    ('''@R090
def test_TM_LIFE_03''', '''def test_TM_LIFE_03'''),
    ('''  TM-LIFE-01..03  employee status should follow the sequence (Pre-Start ->
             Onboarding on day one, -> Active when onboarding is done,
             Offboarding -> Terminated after the last day). Nothing advances
             the status today — R-090 (xfail strict until fixed).''',
     '''  TM-LIFE-01..03  employee status follows the sequence (Pre-Start ->
             Onboarding on day one, -> Active when onboarding is done,
             Offboarding -> Terminated after the last day) — R-090, fixed by
             hr_scheduler.job_lifecycle_advance (daily 5am).'''),
])

edit("tests/gui_jobs_e2e_server/test_srv_hr_features.py", [
    ('''@pytest.mark.xfail(strict=True, reason="R-091: HR Admin termination (PATCH status 'terminated') creates no "
                                       "offboarding tasks and doesn't end HR Portal access")
def test_HF_18_termination_ends_portal_access_and_starts_offboarding(team):
    d = team["david"]
    # exactly what HR Admin's Terminations screen sends (hr_admin/index.html)
    _ok(d("PATCH", f"/employees/{team['emp2']}", {"status": "terminated", "termination_type": "voluntary",
                                                  "end_date": TODAY.isoformat(), "termination_notes": "ZTEST"}),
        "terminate")''',
     '''def test_HF_18_termination_ends_portal_access_and_starts_offboarding(team):
    """R-091 (fixed 2026-10-12). Last day already passed -> Terminated at once."""
    d = team["david"]
    sess_before = team["vicki"].session
    # exactly what HR Admin's Terminations screen sends (hr_admin/index.html)
    r = _ok(d("PATCH", f"/employees/{team['emp2']}", {"status": "terminated", "termination_type": "voluntary",
                                                      "end_date": D(-1), "termination_notes": "ZTEST"}),
            "terminate")
    assert r.get("offboarding_tasks_created", 0) >= 5, r
    e = _ok(d("GET", f"/employees/{team['emp2']}"), "re-read")
    assert (e.get("employee", e))["status"] == "Terminated"
    st, _, _ = _http("GET", team["o"] + f"/hr-api/employees/{team['emp2']}",
                     headers={"X-Employee-Session": sess_before})
    assert st in (401, 403), f"the terminated employee's open portal session still works (HTTP {st})"'''),
    ('''  HF-18 termination in HR Admin -> portal
         access ends + offboarding tasks
         (R-091, xfail until fixed)''',
     '''  HF-18 termination in HR Admin -> portal
         access ends + offboarding tasks
         (R-091, fixed 2026-10-12)'''),
])
