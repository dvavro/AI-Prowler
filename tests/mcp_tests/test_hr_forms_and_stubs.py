"""
HR Admin leftover "coming in Week 6/7" stubs replaced (David, 2026-10-17):
  * Settings -> Configure Work States opens the setup wizard at Work States
    (pre-filled); a revisited wizard can Save Changes from any step
  * Settings -> View All Federal & State Forms lists the forms library
    (GET /forms: federal forms + the company's work states), admin only
  * the "?" help button opens a help panel
pytest tmp_path + ZTEST data only. Run:
  run_tests.bat tests\\mcp_tests\\test_hr_forms_and_stubs.py -v
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
ADMIN = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    live = tmp_path / "hr"
    live.mkdir()
    monkeypatch.setattr(m, "_HR_DB_PATH", str(live / "hr_db.json"))
    monkeypatch.setattr(m, "_load_users", lambda: None)
    m._hr_save_db({"config": {"company_name": "ZTEST Co", "setup_complete": True, "work_states": ["FL", "CA"]},
                   "employees": [{"id": "EMP-00001", "first_name": "ZTEST", "last_name": "Forms", "status": "Active"}],
                   "tasks": [], "documents": [], "audit_log": []})
    return m


def call(ap, path, auth):
    st, _ct, b = ap._hr_api_route("GET", path, {}, {}, auth)
    return st, json.loads(b)


def test_forms_route_lists_the_library(ap):
    st, j = call(ap, "/forms", {"role": "admin", "user_id": "ztest-admin"})
    assert st == 200 and j["work_states"] == ["FL", "CA"]
    by = {f["key"]: f for f in j["forms"]}
    assert {"W-4", "I-9", "CA-DE4"} <= set(by) and not any(k.startswith("_") for k in by)
    assert by["W-4"]["applies_to_states"] == "all" and by["W-4"]["pdf_url"].startswith("https://www.irs.gov/")
    assert by["CA-DE4"]["applies_to_states"] == ["CA"]
    assert j["disclaimer"]


def test_forms_route_is_hr_admin_only(ap):
    assert call(ap, "/forms", {"role": "employee", "employee_id": "EMP-00001"})[0] == 403
    assert call(ap, "/forms", {"role": None})[0] in (401, 403)


def test_no_week_stubs_left_on_reachable_buttons():
    for stub in ("State Rules editor coming in Week 6", "Forms Library coming in Week 7",
                 "help chat coming in Week 7"):
        assert stub not in ADMIN, stub
    assert "function openStateRules() { openSetupWizard('work_states'); }" in ADMIN
    assert "async function openFormsLibrary()" in ADMIN and "apiGet('/forms')" in ADMIN
    assert "_NO_STATE_INCOME_TAX" in ADMIN
    i = ADMIN.index("function openClaudeHelp()")
    assert "openModal(" in ADMIN[i:i + 600]


def test_wizard_opens_at_a_step_and_saves_from_any_step():
    assert "function openSetupWizard(startKey) {" in ADMIN
    assert "WIZARD_STEPS.findIndex(s => s.fields.some(f => f.key === startKey))" in ADMIN
    assert 'onclick="wizardSaveNow()" id="wizard-save-btn"' in ADMIN
    assert "async function wizardSaveNow() { _captureWizardStep(); await _wizardFinish(); }" in ADMIN
    assert "(_wizardRevisit && step < WIZARD_STEPS.length - 1)" in ADMIN
    # the last step still saves through the same code
    i = ADMIN.index("async function wizardNext() {")
    assert "await _wizardFinish();" in ADMIN[i:i + 2000]
