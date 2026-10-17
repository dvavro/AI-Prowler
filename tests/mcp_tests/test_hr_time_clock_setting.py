"""
Who clocks in (David, 2026-10-16). Some companies don't track time; some track
it only for hourly / non-exempt staff.

  HR Admin -> Settings -> "Who clocks in": everyone (default) / only
  non-exempt employees / nobody. Each record can override it ("Clocks in":
  company rule / required / not required).
  * non-exempt only: FLSA status decides (Non-exempt clocks in, Exempt doesn't);
    with no FLSA status, pay type decides (hourly yes, salary no); neither set
    -> clocks in (the safe side)
  * someone who isn't asked to clock in can't start a clock-in; a shift that
    was already open can still be clocked out; history stays
  * the earlier on/off switch (time_clock_enabled) still reads correctly
  * HR Admin: the choice, editable FLSA status, a "Clocks in" row per record
  * HR Portal: follows the employee's OWN answer (my_clock_required); clock
    pieces hidden, Running Late / Out Today stay

pytest tmp_path + ZTEST data only. Run:
  run_tests.bat tests\\mcp_tests\\test_hr_time_clock_setting.py -v
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
ADMIN = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")
PORTAL = (ROOT / "hr_portal" / "index.html").read_text(encoding="utf-8")

HR = {"role": "admin", "user_id": "ztest-admin"}
EMPS = [  # id, flsa, pay type
    ("EMP-00001", "Non-exempt", "salary"),     # salaried non-exempt -> clocks in
    ("EMP-00002", "Exempt", "salary"),
    ("EMP-00003", None, "salary"),
    ("EMP-00004", None, "hourly"),
    ("EMP-00005", None, ""),
]


def me(n):
    return {"role": "employee", "employee_id": "EMP-0000%d" % n}


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    live = tmp_path / "hr"
    live.mkdir()
    monkeypatch.setattr(m, "_HR_DB_PATH", str(live / "hr_db.json"))
    monkeypatch.setattr(m, "_load_users", lambda: None)
    m._hr_save_db({"config": {"company_name": "ZTEST Co", "setup_complete": True},
                   "employees": [{"id": i, "first_name": "ZTEST", "last_name": "Clock%s" % i[-1], "status": "Active",
                                  "flsa_classification": f, "pay_type": p} for i, f, p in EMPS],
                   "tasks": [], "documents": [], "audit_log": []})
    return m


def call(ap, method, path, body=None, auth=HR):
    st, _ct, b = ap._hr_api_route(method, path, {}, body or {}, auth)
    return st, json.loads(b)


def mode(ap, m):
    st, j = call(ap, "POST", "/settings", {"time_clock_mode": m})
    assert st == 200 and j["settings"]["time_clock_mode"] == m


def mine(ap, n):
    return call(ap, "GET", "/settings", auth=me(n))[1]["settings"]["my_clock_required"]


# ── the company rule ────────────────────────────────────────────────────────
def test_everyone_by_default(ap):
    s = call(ap, "GET", "/settings")[1]["settings"]
    assert s["time_clock_mode"] == "everyone" and "time_clock_enabled" not in s
    assert all(mine(ap, n) for n in range(1, 6))


def test_only_hr_admins_change_it_and_bad_values_refused(ap):
    assert call(ap, "POST", "/settings", {"time_clock_mode": "nobody"}, auth=me(1))[0] == 403
    st, j = call(ap, "POST", "/settings", {"time_clock_mode": "sometimes"})
    assert st == 400 and j["error"] == "bad_time_clock_mode"
    mode(ap, "nobody")
    assert ap._hr_load_db()["settings"]["time_clock_mode"] == "nobody"
    assert ap._hr_load_db()["config"]["company_name"] == "ZTEST Co"          # company setup untouched


def test_earlier_on_off_switch_still_reads(ap):
    db = ap._hr_load_db()
    db["settings"] = {"location_clock": True, "time_clock_enabled": False}  # saved by the earlier version
    ap._hr_save_db(db)
    assert call(ap, "GET", "/settings")[1]["settings"]["time_clock_mode"] == "nobody"
    st, j = call(ap, "POST", "/settings", {"time_clock_enabled": True})
    assert j["settings"]["time_clock_mode"] == "everyone"
    assert "time_clock_enabled" not in ap._hr_load_db()["settings"]


def test_nobody(ap):
    mode(ap, "nobody")
    assert not any(mine(ap, n) for n in range(1, 6))
    st, j = call(ap, "POST", "/timeclock/in", {}, auth=me(4))
    assert st == 409 and j["error"] == "time_clock_off"
    assert not ap._hr_load_db().get("time_entries")


def test_non_exempt_only_uses_flsa_then_pay_type(ap):
    mode(ap, "non_exempt")
    assert [mine(ap, n) for n in range(1, 6)] == [True, False, False, True, True]
    reasons = {e["id"]: (e["clock_required"], e["clock_reason"])
               for e in call(ap, "GET", "/employees")[1]["employees"]}
    assert reasons["EMP-00001"] == (True, "non-exempt")
    assert reasons["EMP-00002"] == (False, "exempt")
    assert reasons["EMP-00003"] == (False, "salaried (FLSA status not set)")
    assert reasons["EMP-00004"] == (True, "hourly (FLSA status not set)")
    assert reasons["EMP-00005"] == (True, "FLSA status and pay type not set")
    one = call(ap, "GET", "/employees/EMP-00002")[1]                         # opening one record
    assert (one["clock_required"], one["clock_reason"]) == (False, "exempt")
    assert call(ap, "POST", "/timeclock/in", {}, auth=me(2))[0] == 409       # exempt
    assert call(ap, "POST", "/timeclock/in", {}, auth=me(1))[0] == 201       # salaried non-exempt


# ── one person's override ───────────────────────────────────────────────────
def test_record_override_wins_in_every_mode(ap):
    st, j = call(ap, "PATCH", "/employees/EMP-00002", {"clock_rule": "required"})
    assert st == 200 and j["employee"]["clock_required"] is True and j["employee"]["clock_reason"] == "set on their record"
    call(ap, "PATCH", "/employees/EMP-00004", {"clock_rule": "not_required"})
    for m in ("everyone", "non_exempt", "nobody"):
        mode(ap, m)
        assert mine(ap, 2) is True and mine(ap, 4) is False, m
    mode(ap, "nobody")
    assert call(ap, "POST", "/timeclock/in", {}, auth=me(2))[0] == 201       # required even with "nobody"
    call(ap, "PATCH", "/employees/EMP-00002", {"clock_rule": ""})             # back to the company rule
    assert mine(ap, 2) is False
    st, j = call(ap, "PATCH", "/employees/EMP-00002", {"clock_rule": "maybe"})
    assert st == 400 and j["error"] == "bad_clock_rule"


def test_flsa_status_is_stored_cleanly(ap):
    for given, stored in (("non exempt", "Non-exempt"), ("NON-EXEMPT", "Non-exempt"), ("Nonexempt", "Non-exempt"),
                          ("exempt", "Exempt"), ("", None)):
        st, j = call(ap, "PATCH", "/employees/EMP-00005", {"flsa_classification": given})
        assert st == 200 and j["employee"]["flsa_classification"] == stored, given
    st, j = call(ap, "PATCH", "/employees/EMP-00005", {"flsa_classification": "banana"})
    assert st == 400 and j["error"] == "bad_flsa"


def test_open_shift_can_still_be_clocked_out_and_history_stays(ap):
    assert call(ap, "POST", "/timeclock/in", {}, auth=me(1))[0] == 201
    mode(ap, "nobody")                                                        # changed mid-shift
    assert call(ap, "POST", "/timeclock/out", {}, auth=me(1))[0] == 200
    ent = ap._hr_load_db()["time_entries"]
    assert len(ent) == 1 and ent[0]["clock_out"]
    st, j = call(ap, "GET", "/timeclock/mine", auth=me(1))
    assert st == 200 and len(j.get("entries", [])) == 1


# ── HR Admin page ───────────────────────────────────────────────────────────
def test_admin_who_clocks_in_choice():
    i = ADMIN.index('id="setting-time_clock_mode"')
    assert ADMIN.index("<h3>Time Clock, Privacy &amp; Location</h3>") < i < ADMIN.index('id="setting-toggle-location_clock"')
    for opt in ('<option value="everyone">Everyone</option>', '<option value="non_exempt">Only non-exempt employees</option>',
                '<option value="nobody">Nobody</option>', 'onchange="saveClockMode(this.value)"',
                "await apiPost('/settings', { time_clock_mode: mode });",
                "if (tcEl) tcEl.value = s.time_clock_mode || 'everyone';"):
        assert opt in ADMIN, opt
    assert "setting-toggle-time_clock_enabled" not in ADMIN
    assert "function _syncTimeClockUi(on)" in ADMIN and 'id="clocklog-off-note"' in ADMIN
    assert "doesn\\'t track" not in ADMIN                                     # no stray backslashes in the page text


def test_admin_record_flsa_and_clocks_in():
    assert 'onclick="editEmpFlsa()"' in ADMIN and 'id="info-flsa"' in ADMIN
    assert "function editEmpFlsa()" in ADMIN and "flsa_classification: document.getElementById(\\'ef-val\\').value" in ADMIN
    assert 'onclick="editEmpClockRule()"' in ADMIN and 'id="info-clock"' in ADMIN
    assert "function editEmpClockRule()" in ADMIN and "clock_rule: document.getElementById(\\'ec-val\\').value" in ADMIN
    assert "set('info-clock'," in ADMIN


# ── HR Portal page ──────────────────────────────────────────────────────────
def test_portal_follows_the_employees_own_answer():
    assert "window.applyTimeClockSetting = function (on)" in PORTAL
    assert "applyTimeClockSetting(((_st && _st.settings) || {}).my_clock_required !== false);" in PORTAL
    assert "body.time-clock-off .tc-only { display: none !important; }" in PORTAL


def test_portal_hides_clock_pieces_but_keeps_running_late():
    for marker in ('class="card tc-only" style="padding:0;overflow:hidden">',          # clock card
                   'class="stat-tile tc-only"',                                       # Days Clocked
                   "<div class=\"tc-only\" onclick=\"goTo('timeclock','Time Clock')\"",  # quick tour
                   "<button class=\"tc-only\" onclick=\"navigate(document.querySelector('[data-page=timeclock]')",
                   '<h1 class="tc-name">Time Clock</h1>',
                   "<p class=\"tc-off-only\">You aren't asked to clock in or out.",
                   "if (pageId === 'timeclock' && window._timeClockOn !== false) { loadTimeClockStatus();"):
        assert marker in PORTAL, marker
    late = PORTAL.index("selfReportAttendance('late')")
    card = PORTAL.rindex('<div class="card', 0, late)
    assert "tc-only" not in PORTAL[card:card + 60]                            # Running Late / Out Today stay
    assert "window._timeClockOn === false && /clock.?(in|out)|punch|time.?card|check.?in/.test(t)" in PORTAL
