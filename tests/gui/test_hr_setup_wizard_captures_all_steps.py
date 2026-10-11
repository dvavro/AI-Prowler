"""
tests/gui/test_hr_setup_wizard_captures_all_steps.py
=====================================================
Regression guard for a real production data-loss bug found 2026-08-29
while verifying a separate fix (the HR state-dir PermissionError) against
the user's live deployment.

THE BUG (fixed in this same pass, see hr/index.html's wizardNext()):
renderWizardStep(step) replaces #wizard-steps-container's entire innerHTML
on every step transition, tearing down the previous step's form elements.
The original wizardNext() only read field values via document.getElementById()
for ALL WIZARD_STEPS at the very end (on "Complete Setup"), by which point
every earlier step's elements were already gone from the DOM -- each
getElementById() call returned null and was silently skipped
(`if (!el) return;`). Every field from steps 1-9 (company name, EIN, work
states, payroll platform, SUI/state-tax/workers-comp/special-program
registration status, etc. -- 11 of the wizard's 14 fields) was discarded on
every single Complete Setup submission. This was confirmed empirically
against the real, saved production hr_db.json: config fields were blank
even though the user had visibly typed real values into every step.

The fix introduces a persistent `wizardData` accumulator that captures the
CURRENT step's field values inside wizardNext(), before either advancing to
the next step or submitting -- i.e. while that step's elements still exist.

This test drives the real, shipped wizardNext()/renderWizardStep()/
WIZARD_STEPS straight out of hr/index.html through all 10 steps end to end,
with a mock DOM that enforces the real failure mode (getElementById only
resolves ids belonging to whichever step is currently "mounted" -- exactly
like a real browser after innerHTML replacement), and asserts every one of
the 14 fields survives into the final POST /setup/complete payload.

Safe: reads hr/index.html as plain text only, runs the extracted JS in an
isolated Node subprocess with mocked globals. Never imports ai_prowler_mcp.py,
never touches hr_db.json or a live server.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_real_Popen = subprocess.Popen

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
HR_INDEX = SRC_ROOT / "hr" / "index.html"


@pytest.fixture(scope="module")
def node_available():
    if shutil.which("node") is None:
        pytest.skip("Node.js not on PATH — cannot execute wizard JS for behavioral verification")


def _run_node(script_path: Path, timeout: int = 30):
    proc = _real_Popen(
        ["node", str(script_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise
    return proc.returncode, stdout, stderr


def _extract_source_range(source: str, start_marker: str, end_function_marker: str) -> str:
    """Extract a contiguous range of real shipped source, from start_marker
    through the end of the function introduced by end_function_marker (found
    via real brace-depth counting, matching the technique in
    test_hr_pwa_update_banner.py / test_pwa_update_banner.py -- a naive regex
    would truncate at the first inner closing brace instead of the function's
    own). Grabbing one contiguous range (rather than stitching separate
    extracts together) means WIZARD_STEPS, the wizardStep/wizardData state,
    and every function between them run with their real ordering and shared
    scope, exactly as shipped -- nothing about that relationship can drift
    silently out of sync with this test.
    """
    start_idx = source.index(start_marker)
    fn_idx = source.index(end_function_marker, start_idx)
    brace_start = source.index("{", fn_idx)
    depth = 0
    for i in range(brace_start, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start_idx:i + 1]
    raise ValueError(f"Unbalanced braces extracting range starting {start_marker!r}")


@pytest.fixture(scope="module")
def hr_index_text():
    return HR_INDEX.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def wizard_source(hr_index_text):
    return _extract_source_range(
        hr_index_text, "const WIZARD_STEPS", "async function wizardNext()"
    )


class TestWizardDataAccumulatorStructure:
    """Cheap, no-Node structural checks against the real shipped source."""

    def test_wizard_data_accumulator_declared(self, hr_index_text):
        assert "let wizardData = {}" in hr_index_text

    def test_wizard_next_captures_current_step_before_advancing_or_submitting(self, wizard_source):
        capture_idx = wizard_source.index("fields.forEach")
        advance_idx = wizard_source.index("renderWizardStep(wizardStep + 1)")
        submit_idx = wizard_source.index("apiPost('/setup/complete'")
        assert capture_idx < advance_idx, (
            "wizardNext() must capture the current step's field values "
            "BEFORE advancing to the next step (whose render tears down "
            "the current step's DOM elements)"
        )
        assert capture_idx < submit_idx, (
            "wizardNext() must capture the current step's field values "
            "BEFORE the final submit, not only read WIZARD_STEPS at the end"
        )

    def test_config_update_spreads_accumulated_wizard_data(self, wizard_source):
        assert "...wizardData" in wizard_source, (
            "the final configUpdate must be built from the accumulated "
            "wizardData, not re-read from (by then missing) DOM elements"
        )


_HARNESS_TEMPLATE = """
// Mock DOM: enforces the REAL failure mode this bug exploited -- an id
// only resolves via getElementById() if it belongs to whichever wizard
// step is currently "mounted" (mirrors a real browser after
// renderWizardStep() replaces #wizard-steps-container's innerHTML and
// tears down every previous step's elements).
function makeChromeElement() {
  return { classList: { add(){}, remove(){} }, style: {}, textContent: '', innerHTML: '' };
}
const CHROME_IDS = ['wizard-progress-fill','wizard-step-label','wizard-back-btn',
  'wizard-next-btn','wizard-steps-container','setup-wizard','app'];
const chromeElements = {};
CHROME_IDS.forEach(function(id) { chromeElements[id] = makeChromeElement(); });

function makeFieldElement(type) {
  if (type === 'multiselect') {
    return { _checkboxes: [], querySelectorAll: function(sel) {
      return this._checkboxes.filter(function(c) { return c.checked; });
    } };
  }
  return { value: '' };
}
const fieldElements = {};

global.document = {
  getElementById: function(id) {
    if (chromeElements[id]) return chromeElements[id];
    const step = WIZARD_STEPS[wizardStep];
    const fieldDef = step.fields.find(function(f) { return f.id === id; });
    if (!fieldDef) return null; // not mounted for the currently rendered step
    if (!fieldElements[id]) fieldElements[id] = makeFieldElement(fieldDef.type);
    return fieldElements[id];
  },
};

let capturedPost = null;
async function apiPost(path, body) { capturedPost = { path: path, body: body }; return {}; }
let state = { config: {} };
function applyConfig(c) {}
function loadEmployees() {}
function loadTasks() {}
function showToast(msg, type) {}

__EXTRACTED_LOGIC__

function setStepValues(stepIndex, values) {
  WIZARD_STEPS[stepIndex].fields.forEach(function(f) {
    const el = document.getElementById(f.id);
    if (f.type === 'multiselect') {
      el._checkboxes = (values[f.key] || []).map(function(v) { return { value: v, checked: true }; });
    } else {
      el.value = values[f.key];
    }
  });
}

// One value per field, keyed by step index, matching the real WIZARD_STEPS
// shipped in hr/index.html (10 steps, 14 fields total).
const TEST_DATA = [
  { company_name: 'Acme Corp LLC', company_dba: 'Acme Co', entity_type: 'LLC',
    company_address: '123 Main St, City, ST 12345' },
  { ein: '12-3456789' },
  { eftps_enrolled: 'Yes' },
  { work_states: ['CA', 'TX'] },
  { sui_registered: 'Yes, all states' },
  { state_tax_registered: 'Yes' },
  { wc_covered: 'Yes' },
  { special_programs_registered: 'Yes' },
  { payroll_platform: 'Gusto' },
  { doc_root: './hr_documents', hr_admin_email: 'hr@acme.com', owner_email: 'owner@acme.com' },
];

const results = [];
function check(name, cond) { results.push([name, !!cond]); }

(async () => {
  renderWizardStep(0);
  for (let i = 0; i < WIZARD_STEPS.length; i++) {
    setStepValues(i, TEST_DATA[i]);
    await wizardNext();
  }

  check('posted_to_setup_complete', !!capturedPost && capturedPost.path === '/setup/complete');
  const body = (capturedPost && capturedPost.body) || {};
  check('setup_complete_flag_true', body.setup_complete === true);

  const expectedScalars = {
    company_name: 'Acme Corp LLC', company_dba: 'Acme Co', entity_type: 'LLC',
    company_address: '123 Main St, City, ST 12345', ein: '12-3456789',
    eftps_enrolled: 'Yes', sui_registered: 'Yes, all states',
    state_tax_registered: 'Yes', wc_covered: 'Yes',
    special_programs_registered: 'Yes', payroll_platform: 'Gusto',
    doc_root: './hr_documents', hr_admin_email: 'hr@acme.com',
    owner_email: 'owner@acme.com',
  };
  Object.keys(expectedScalars).forEach(function(key) {
    check('captured_' + key, body[key] === expectedScalars[key]);
  });
  check('captured_work_states_array',
    Array.isArray(body.work_states) && body.work_states.length === 2 &&
    body.work_states.indexOf('CA') !== -1 && body.work_states.indexOf('TX') !== -1);

  console.log(JSON.stringify(results));
  process.exit(results.every(function(r) { return r[1]; }) ? 0 : 1);
})();
"""


class TestWizardCapturesEveryStepEndToEnd:
    """Drives the real wizardNext()/renderWizardStep()/WIZARD_STEPS from
    hr/index.html through all 10 steps against a mock DOM that reproduces
    the exact failure mode of the original bug (elements only exist for
    whichever step is currently rendered). Proves all 14 fields across all
    10 steps survive into the final /setup/complete payload -- the thing
    that was silently failing in production before this fix.
    """

    def test_all_wizard_steps_survive_to_final_submit(self, node_available, wizard_source, tmp_path):
        script = _HARNESS_TEMPLATE.replace("__EXTRACTED_LOGIC__", wizard_source)
        script_path = tmp_path / "hr_setup_wizard.js"
        script_path.write_text(script, encoding="utf-8")
        returncode, stdout, stderr = _run_node(script_path, timeout=15)
        if returncode != 0:
            detail = stdout.strip() or "(no stdout)"
            pytest.fail(f"HR setup wizard step-capture test failed.\n{detail}\nstderr: {stderr}")


class TestWizardIsReachableAfterSetupComplete:
    """Regression guard for a THIRD bug found 2026-08-29, alongside the
    step-capture bug above: openSetupWizard() was only ever called from the
    initial /config load, gated on `if (!cfg.setup_complete)`. Once
    setup_complete flips true -- even from a run that saved blank/incomplete
    data, exactly what the step-capture bug above caused -- there was no way
    for the user to get back into the wizard from the UI at all. The
    per-field Settings tab items (openSetting()) are themselves still Week 6
    stubs (`showToast('Edit ... coming in Week 6')`), so they were not a
    working alternative either. This was confirmed against Jamie's real,
    live production hr_db.json: setup_complete was true with blank config
    fields, and there was no path in the shipped app back to a working
    setup screen.

    Fix: a "Redo Company Setup" item in the Settings tab that calls
    openSetupWizard() directly, so the wizard is always reachable regardless
    of setup_complete's value.
    """

    def test_settings_tab_has_a_redo_setup_entry_point(self, hr_index_text):
        assert "Redo Company Setup" in hr_index_text
        assert 'onclick="openSetupWizard()"' in hr_index_text

    def test_open_setup_wizard_is_called_from_more_than_just_the_initial_load_gate(self, hr_index_text):
        # Before the fix there were exactly two hits for the bare substring
        # "openSetupWizard()" -- the function's own definition
        # ("function openSetupWizard() {") and the one real call site inside
        # the `if (!cfg.setup_complete)` branch of the initial config load
        # ("openSetupWizard();"). A naive count(...) >= 2 check would have
        # passed even on the buggy version, so this checks for the two
        # *call* patterns specifically (excluding the definition): the
        # original statement call, and the new onclick call from the
        # Settings entry point.
        assert "openSetupWizard();" in hr_index_text, (
            "the original initial-load call site (`if (!cfg.setup_complete) "
            "{ openSetupWizard(); }`) is missing"
        )
        assert 'onclick="openSetupWizard()"' in hr_index_text, (
            "no UI entry point calls openSetupWizard() outside the initial "
            "load gate -- the wizard is still unreachable once "
            "setup_complete is true"
        )
