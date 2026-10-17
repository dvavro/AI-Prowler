"""
HR Admin -> Company Setup wizard can be revisited (David, 2026-10-16: "I could
not find one to add more states where we hire").

  * reachable from the left menu (first item, before Employees) and from a
    Company Setup card at the top of Settings that shows the current work states
  * opens PRE-FILLED with the saved answers (it used to open blank, and
    finishing it blank would have erased saved details like the EIN)
  * Back keeps what was typed; Cancel leaves without saving; the last button
    says "Save Changes" on a revisit
  * stays self-contained (the wizard capture test runs it on its own)

Checked live in a browser by tests\\dev\\_tmp_clockmode_browser_check.py.
Run: run_tests.bat tests\\gui\\test_hr_wizard_revisit.py -v
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
ADMIN = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")


def test_menu_item_first_before_employees():
    nav = ADMIN[ADMIN.index('<nav id="sidebar-nav">'):]
    first = nav.index('id="sb-company-setup"')
    assert first < nav.index('data-tab="employees"')
    assert 'onclick="closeSidebar();openSetupWizard()"' in nav[first:first + 200]
    assert "Company Setup</button>" in nav[first:first + 400]


def test_settings_card_with_current_states():
    assert 'id="setup-card"' in ADMIN and 'id="setup-card-states"' in ADMIN
    assert ADMIN.index('id="setup-card"') < ADMIN.index("<h3>Company</h3>")
    assert "function _renderSetupCard()" in ADMIN and "  _renderSetupCard();\n" in ADMIN
    assert "Company Setup Wizard</span>" in ADMIN and "Redo Company Setup" not in ADMIN


def test_wizard_opens_prefilled_and_keeps_input():
    i = ADMIN.index("function openSetupWizard(startKey) {")      # 2026-10-17: can open at a given step
    body = ADMIN[i:i + 900]
    assert "const cfg = (state && state.config) || {};" in body
    assert "wizardData[f.key] = cfg[f.key]" in body
    # every field type shows the saved value
    assert "String(wizardData[f.key] ?? '') === o ? ' selected' : ''" in ADMIN
    assert "(wizardData[f.key] || []).includes(o) ? ' checked' : ''" in ADMIN
    assert "value=\"${_wizEsc(wizardData[f.key] ?? '')}\"" in ADMIN
    assert "if (wizardStep > 0) { _captureWizardStep(); renderWizardStep(wizardStep - 1); }" in ADMIN


def test_cancel_and_save_changes_on_a_revisit():
    assert 'onclick="closeSetupWizard()" id="wizard-cancel-btn"' in ADMIN
    assert "function closeSetupWizard()" in ADMIN
    assert "(_wizardRevisit ? 'Save Changes' : 'Complete Setup')" in ADMIN
    assert "_cb.style.display = _wizardRevisit ? '' : 'none';" in ADMIN


def test_wizard_rendering_has_no_outside_dependencies():
    # the wizard capture test runs WIZARD_STEPS..wizardNext on its own (no window, no page helpers)
    s = ADMIN.index("function renderWizardStep(")
    e = ADMIN.index("async function wizardNext()", s)
    render = ADMIN[s:e]
    assert "escapeHtml(" not in render and "window." not in render
