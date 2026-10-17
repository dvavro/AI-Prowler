"""
HR Portal + HR Admin pages on real data (David, 2026-10-16, Phase 3).

  * both apps compute holidays for any year exactly like an independent
    calculation (nth weekday rules, weekend -> observed day)
  * the Portal's demo / sample content is gone (fake tasks and projects with real
    names, sample feed posts, AI-Prowler founders, sample policies, fake training
    statuses), and the locked manager track sits inside the Trainings page
  * nothing the employee owns is kept only in their browser any more (photo,
    to-dos, reminders, training completions, feed answers) — only the one-time
    upload still reads the old keys
  * HR Admin has the time-off policy, paid holidays, announcements and employee
    resources screens, and gender / usual hours / PTO on the employee record

Safe: reads the two HTML files as text and runs extracted functions in Node.
Never imports ai_prowler_mcp.py or touches HR data. (The full browser run against
the real API is tests/dev/_tmp_phase3_browser_check.py.)

Run: run_tests.bat tests\\gui\\test_hr_portal_phase3_pages.py -v
"""
import calendar
import datetime as dt
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_real_Popen = subprocess.Popen          # the harness stubs subprocess for safety

ROOT = Path(__file__).resolve().parent.parent.parent
PORTAL = (ROOT / "hr_portal" / "index.html").read_text(encoding="utf-8")
ADMIN = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")
YEARS = list(range(2024, 2032))


def expected(year):
    """Independent calculation (Python calendar) of the same 14 holidays."""
    def nth(m, wd, n):
        days = [d for d in range(1, 32) if d <= calendar.monthrange(year, m)[1] and dt.date(year, m, d).weekday() == wd]
        return dt.date(year, m, days[n - 1])

    def last(m, wd):
        days = [d for d in range(1, calendar.monthrange(year, m)[1] + 1) if dt.date(year, m, d).weekday() == wd]
        return dt.date(year, m, days[-1])
    tg = nth(11, 3, 4)
    out = {"new_year": dt.date(year, 1, 1), "mlk": nth(1, 0, 3), "presidents": nth(2, 0, 3), "memorial": last(5, 0),
           "juneteenth": dt.date(year, 6, 19), "independence": dt.date(year, 7, 4), "labor": nth(9, 0, 1),
           "columbus": nth(10, 0, 2), "veterans": dt.date(year, 11, 11), "thanksgiving": tg,
           "day_after_thanksgiving": tg + dt.timedelta(days=1), "christmas_eve": dt.date(year, 12, 24),
           "christmas": dt.date(year, 12, 25), "new_years_eve": dt.date(year, 12, 31)}
    moves = {"new_year", "juneteenth", "independence", "veterans", "christmas"}
    res = {}
    for k, d in out.items():
        o = d
        if k in moves and d.weekday() == 5:
            o = d - dt.timedelta(days=1)
        elif k in moves and d.weekday() == 6:
            o = d + dt.timedelta(days=1)
        res[k] = (d.isoformat(), o.isoformat())
    return res


def _node(js, tmp_path):
    f = tmp_path / "h.js"
    f.write_text(js, encoding="utf-8")
    p = _real_Popen(["node", str(f)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(timeout=60)
    assert p.returncode == 0, err
    return json.loads(out.strip().splitlines()[-1])


@needs_node
def test_admin_holidays_match_for_every_year(tmp_path):
    fn = ADMIN[ADMIN.index("function hrHolidaysForYear(y)"):ADMIN.index("// Fun observances")]
    js = fn + "\nvar r={};[" + ",".join(map(str, YEARS)) + "].forEach(function(y){r[y]={};hrHolidaysForYear(y).forEach(function(h){r[y][h.key]=[h.date,h.observed];});});console.log(JSON.stringify(r));"
    got = _node(js, tmp_path)
    for y in YEARS:
        assert {k: tuple(v) for k, v in got[str(y)].items()} == expected(y), y


@needs_node
def test_portal_holidays_match_for_every_year(tmp_path):
    blk = PORTAL[PORTAL.index("  function pad(n) { return (n < 10 ? '0' : '') + n; }"):PORTAL.index("  // {date: name} of the holidays")]
    js = "var window={};\n" + blk + "\nvar r={};[" + ",".join(map(str, YEARS)) + "].forEach(function(y){r[y]={};window.hrHolidaysForYear(y).forEach(function(h){r[y][h.key]=[h.date,h.observed];});});console.log(JSON.stringify(r));"
    got = _node(js, tmp_path)
    for y in YEARS:
        assert {k: tuple(v) for k, v in got[str(y)].items()} == expected(y), y


@pytest.mark.parametrize("demo", [
    "Process Automation Rollout", "Workplace Safety Audit 2026", "Q4 Onboarding Program",      # fake projects
    "Complete Q3 inventory audit',       due:",                                                # seeded demo tasks
    "Q3 All-Hands Meeting — September 10", "Shoutout to the Operations team",                   # sample feed
    "David Vavro</b> — Co-founder", "What We've Built So Far",                                  # AI-Prowler newsletter
    "AI-Prowler_Employee_Handbook_2026.pdf", "policy_attendance.html",                          # sample handbook
    "Completed</span> Aug 5, 2026", "60% complete",                                             # fake training statuses
    "const HOLIDAYS = {",                                                                        # one-year table
])
def test_portal_demo_content_is_gone(demo):
    assert demo not in PORTAL


def test_manager_track_is_inside_the_trainings_page():
    i = PORTAL.index('<div class="page" id="page-trainings">')
    j = PORTAL.index("</main>", i)
    assert "Manager &amp; Leadership Development" in PORTAL[i:j]


def test_nothing_employee_owned_stays_in_the_browser():
    mig = PORTAL[PORTAL.index("async function moveBrowserData(a)"):PORTAL.index("var started = false;")]
    rest = PORTAL.replace(mig, "")
    for key in ("'ap_hr_photo_'", "'hr_tasks_'", "'hr_reminders_'"):
        assert f"localStorage.setItem({key}" not in rest and f"localStorage.getItem({key}" not in rest, key
    assert "localStorage.setItem('hr_train_v1'" not in PORTAL
    assert "localStorage.setItem('feed_ack_'" not in PORTAL and "localStorage.setItem('feed_rsvp_'" not in PORTAL
    assert "postJSON('/portal/import', body)" in mig and "SEED.indexOf(x.text) < 0" in mig, "sample tasks are not uploaded"
    assert "function _remGet() { return window.pItemsGet ? window.pItemsGet('reminders') : []; }" in PORTAL
    assert "fetch('/hr-api/portal/photo'" in PORTAL


def test_portal_pages_read_the_server():
    for path in ("'/feed'", "'/resources'", "'/documents'", "'/training'", "'/portal/goals'", "'/pto/mine'",
                 "'/portal/items/' + kind", "'/announcements/' + encodeURIComponent(id) + '/respond'"):
        assert path in PORTAL, path
    assert "fetch('/hr-api/pto/balance')" in PORTAL and "fetch('/hr-api/tasks')" in PORTAL
    for el in ('id="feed-body"', 'id="np-body"', 'id="docs-company"', 'id="handbook-list"', 'id="trn-required"',
               'id="sched-week"', 'id="tp-hr-list"', 'id="goals-hr-list"', 'class="pto-left-days"'):
        assert el in PORTAL, el
    assert "if (typeof authState !== 'undefined' && authState) return authState;" in PORTAL, \
        "reads the live sign-in state (window._hrAuthState goes stale)"


def test_admin_phase3_screens():
    for el in ('id="pto-policy-body"', 'id="holiday-policy-body"', 'id="ann-body"', 'id="res-body"',
               'id="info-gender"', 'id="info-work-hours"', 'id="info-pto"', 'id="info-prev-names"',
               "openSetting('company_about')"):
        assert el in ADMIN, el
    assert "loadPhase3Settings();" in ADMIN
    for call in ("apiPost('/pto/policy'", "apiPost('/holidays/policy'", "apiPost('/announcements'",
                 "apiPost('/resources'", "apiPost('/pto/adjust'", "{ work_schedule: out }"):
        assert call in ADMIN, call
    assert not re.search(r"FEDERAL_HOLIDAYS\[|Object\.entries\(FEDERAL_HOLIDAYS|const FEDERAL_HOLIDAYS", ADMIN)
    assert ADMIN.count("hrHolidaysForAdmin(") >= 6
