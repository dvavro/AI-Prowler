"""Mileage tab (Jobs app) — runs the real Mileage JavaScript from
jobs/index.html in node with a stubbed DOM and a stubbed mcpCall, so the
Phase 4–5 screens are exercised, not just grepped: reminder banner,
crew-reimbursement card + owner approval queue, AI review sheet (Fix / Skip),
file download (export + statement), cancelled-on-arrival, and tracking
off = quiet (the switches are Database → Settings rows since 2026-10-25).

Skips when node isn't installed.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "jobs" / "index.html"

HARNESS = r"""
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
const a = html.indexOf('// ── MILEAGE TRACKER (2026-10-24)');
const b = html.indexOf('// ── REPORTS (2026-09-23');
if (a < 0 || b < a) { console.log(JSON.stringify({error: 'mileage section not found'})); process.exit(0); }
const SRC = html.slice(a, b);
const TODAY = (d => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10))(new Date());
const els = {};
function el(id) { if (!els[id]) els[id] = {id, innerHTML: '', textContent: '', style: {}, value: '', className: ''}; return els[id]; }
global.document = {getElementById: el, createElement: () => ({style: {}, click() { global.clicked = (global.clicked || 0) + 1; }, remove() {}}),
                   body: {appendChild() {}}, querySelectorAll: () => []};
global.state = {serverMode: true, userRole: 'owner',
                jobs: [{id: 'JOB-0007', customer: 'Smiths', date: TODAY, status: 'Scheduled', start: '09:00'},
                       {id: 'JOB-0008', customer: 'Done Co', date: TODAY, status: 'Complete'}]};
global.esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
global.toasts = []; global.showToast = (m, t) => toasts.push([m, t || '']);
global._isFailureResult = r => /^(❌|⛔)/.test(String(r || ''));
global.localStorage = {getItem: () => null, setItem() {}, removeItem() {}};
global.confirm = () => true; global.navigator = {};
global.URL = {createObjectURL: () => 'blob:x', revokeObjectURL() {}};
global.Blob = class { constructor(p, o) { this.o = o; } };
global.atob = s => Buffer.from(s, 'base64').toString('binary');
global.loadJobs = () => {};
global.window = global;
global.calls = [];
const PDF64 = Buffer.from('%PDF-1.4 test').toString('base64');
const LOG = {enabled: true, start: TODAY, end: TODAY, user_key: 'u_owner', is_admin: true, restricted: false,
  trips: [{trip_id: 'TRIP-0001', trip_date: TODAY, from_label: 'Home', to_label: 'Smiths', miles: 4.2, purpose: 'Window – Smiths',
           classification: 'business', status: 'active', vehicle_id: 'VEH-0001', vehicle_label: 'Van …123456'}],
  gaps: [], vehicles: [{vehicle_id: 'VEH-0001', label: 'Van …123456', ownership: 'business', active: 1, last_odometer: 1000, last_odometer_date: TODAY}],
  categories: ['Supplies', 'Other'], rates: [{from: '2026-07-01', cents: 76}], totals: {week_business: 4.2, ytd_business: 4.2},
  reminders: [{type: 'pay_period', text: 'Submit your mileage for 2026-09-01 – 2026-09-30: 10.0 mi, $7.60.', action: 'submit', period: '2026-09-01'},
              {type: 'odometer', text: 'Record the odometer for VEH-0002', action: 'odometer', vehicle_id: 'VEH-0002'}],
  reimbursement: {show: true,
    current: {period_start: '2026-10-01', period_end: '2026-10-31', kind: 'monthly', trip_count: 2, miles: 12.0, amount_usd: 9.12,
              parking_tolls_usd: 2.5, status: '', reimbursement_id: '', gap_days: []},
    mine: [{reimbursement_id: 'REIM-0002', period_start: '2026-08-01', period_end: '2026-08-31', total_usd: 15.2, status: 'paid',
            paid_date: '2026-09-03', paid_method: 'check', paid_reference: '1042', crew: 'Dave'}],
    queue: [{reimbursement_id: 'REIM-0003', period_start: '2026-09-01', period_end: '2026-09-30', total_usd: 7.6, status: 'submitted', crew: 'Sam', user_key: 'u_sam'},
            {reimbursement_id: 'REIM-0004', period_start: '2026-09-01', period_end: '2026-09-30', total_usd: 3.8, status: 'approved', crew: 'Pat', user_key: 'u_pat'}]}};
const FINDINGS = {start: TODAY, end: TODAY, findings: [
  {id: 'duplicate:' + TODAY + ':TRIP-0002', check: 'duplicate', title: 'possible duplicate trip', severity: 'high', trip_id: 'TRIP-0002',
   message: 'TRIP-0002 looks like a copy of TRIP-0001', fix: {action: 'void', trip_id: 'TRIP-0002', summary: 'remove TRIP-0002'}},
  {id: 'two_drivers:' + TODAY + ':VEH-0001', check: 'two_drivers', title: 'vehicle used by two drivers the same day', severity: 'medium',
   trip_id: null, message: 'VEH-0001 has trips by Pat, Sam', fix: null}]};
global.mcpCall = async (tool, args) => {
  calls.push([tool, args || {}]);
  if (tool === 'get_mileage_log') return JSON.stringify(LOG);
  if (tool === 'review_mileage_log') return JSON.stringify(FINDINGS);
  if (tool === 'export_mileage_log') return JSON.stringify({filename: 'Mileage.pdf', mime: 'application/pdf', base64: PDF64});
  if (tool === 'mileage_reimbursement' && args.action === 'statement') return JSON.stringify({filename: 'Mileage_reimbursement_REIM-0002.pdf', mime: 'application/pdf', base64: PDF64});
  if (tool === 'mileage_settings' && args.action === 'get') return JSON.stringify({enabled: LOG.enabled, reimbursement: {kind: 'biweekly'},
      reminders: {gaps: true, weekly: false}, reminder_types: {gaps: 'Daily gaps', weekly: 'Monday review'}});
  return '✅ done';
};
(async () => {
  eval(SRC);
  const out = {};
  await loadMileage();
  out.content = el('miContent').innerHTML;
  await miReview();
  out.review = el('miSheetBody').innerHTML;
  await miReviewAct(0, 'accept');
  out.review_after = el('miSheetBody').innerHTML;
  await miExport('xlsx');
  await miReimbStatement('REIM-0002');
  miCancelledForm();
  out.cancel_sheet = el('miSheetBody').innerHTML;
  await miCancelled('JOB-0007');
  await miReimbSubmit('2026-09-01');
  await miReimbApprove('REIM-0003');
  miReimbPaidForm('REIM-0004');
  el('miPd_method').value = 'payroll'; el('miPd_ref').value = 'PR-7'; el('miPd_date').value = '2026-10-05';
  await miReimbPaid('REIM-0004');
  await mileageInit();
  out.on_ui = {entry: el('miEntryCard').style.display, tools: el('miToolsRow').style.display, nav: el('navMileage').style.display};
  out.miles = await _renderMilesSheet();
  out.miles_data_set = !!(MI.data && MI.data.trips && MI.data.trips.length);
  // Tracking OFF (Database -> Settings -> Mileage Tracking Enabled = Disabled): quiet, not gone.
  LOG.enabled = false;
  LOG.gaps = [{type: 'missing_clock_out', date: TODAY, entry_id: 'TE-1', where: 'Smiths', clock_in: '09:00'}];
  el('clockVehicleRow').style.display = '';
  await mileageInit();
  await loadMileage();
  out.off_content = el('miContent').innerHTML;
  out.off_ui = {entry: el('miEntryCard').style.display, tools: el('miToolsRow').style.display,
                nav: el('navMileage').style.display, picker: el('clockVehicleRow').style.display,
                active: el('miActiveTrip').style.display};
  out.off_miles = await _renderMilesSheet();
  out.calls = calls; out.toasts = toasts; out.clicked = global.clicked || 0;
  console.log(JSON.stringify(out));
})().catch(e => { console.log(JSON.stringify({error: String(e && e.stack || e)})); });
"""


@pytest.fixture(scope="module")
def run():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "harness.js"
        h.write_text(HARNESS, encoding="utf-8")
        p = subprocess.run([node, str(h), str(PAGE)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    line = (p.stdout or "").strip().splitlines()
    assert line, p.stderr
    out = json.loads(line[-1])
    assert "error" not in out, out.get("error")
    return out


def _calls(out, tool):
    return [a for t, a in out["calls"] if t == tool]


def test_reminders_and_reimbursement_card_render(run):
    c = run["content"]
    assert 'data-testid="mi-reminders"' in c and "Submit your mileage for 2026-09-01" in c
    assert "miOdometerForm(&#39;VEH-0002&#39;)" in c or "miOdometerForm('VEH-0002')" in c
    assert 'data-testid="mi-reimb"' in c and "2026-10-01 – 2026-10-31" in c and "$11.62" in c
    assert 'data-testid="mi-reimb-submit"' in c
    assert "WAITING ON YOU" in c and 'data-testid="mi-reimb-approve"' in c and 'data-testid="mi-reimb-paid"' in c
    assert "Paid 2026-09-03 · check #1042" in c
    assert 'data-testid="mi-export"' in c


def test_ai_review_fix_and_skip(run):
    assert run["review"].count('data-testid="mi-finding"') == 2
    assert 'data-testid="mi-finding-fix"' in run["review"] and "Proposed fix: remove TRIP-0002" in run["review"]
    fix = _calls(run, "apply_mileage_review_fix")
    assert fix == [{"finding_id": fix[0]["finding_id"], "action": "accept"}]
    assert fix[0]["finding_id"].startswith("duplicate:")
    assert run["review_after"].count('data-testid="mi-finding"') == 1


def test_downloads_export_and_statement(run):
    ex = _calls(run, "export_mileage_log")
    assert ex and ex[0]["format"] == "xlsx" and ex[0]["deliver"] == "download"
    st = [a for a in _calls(run, "mileage_reimbursement") if a.get("action") == "statement"]
    assert st and st[0]["deliver"] == "download"
    assert run["clicked"] == 2
    assert any(m.startswith("Downloaded Mileage_reimbursement_REIM-0002.pdf") for m, _ in run["toasts"])


def test_cancelled_on_arrival_lists_open_jobs_today(run):
    s = run["cancel_sheet"]
    assert "Smiths" in s and "Done Co" not in s
    c = _calls(run, "job_cancelled_on_arrival")
    assert c and c[0]["job_id"] == "JOB-0007"


def test_reimbursement_actions_send_the_right_calls(run):
    r = _calls(run, "mileage_reimbursement")
    assert {"action": "submit", "period_date": "2026-09-01"} in r
    assert {"action": "approve", "reimbursement_id": "REIM-0003"} in r
    assert {"action": "paid", "reimbursement_id": "REIM-0004", "paid_date": "2026-10-05",
            "method": "payroll", "reference": "PR-7"} in r


def test_tracking_on_shows_entry_tools(run):
    assert run["on_ui"] == {"entry": "", "tools": "contents", "nav": ""}


def test_tracking_off_is_quiet_not_gone(run):
    """2026-10-25 (Vicki): off = a 100% work vehicle tracked by yearly
    odometer. The tab, Reports and Database → Miles stay; nothing asks for
    miles — no vehicle picker, Start/Add trip, gaps, reminders, reimbursements."""
    ui = run["off_ui"]
    assert ui["nav"] == "", "the Mileage tab stays"
    assert ui["entry"] == "none" and ui["tools"] == "none" and ui["picker"] == "none" and ui["active"] == "none"
    c = run["off_content"]
    assert 'data-testid="mi-off"' in c and "Database → Settings → Mileage Tracking Enabled" in c
    assert "route still shows miles driven" in c
    for gone in ('data-testid="mi-reminders"', 'data-testid="mi-gaps"', 'data-testid="mi-reimb"',
                 'data-testid="mi-vehicles"', 'data-testid="mi-admin"'):
        assert gone not in c, gone
    assert 'data-testid="mi-trip"' in c, "trips already logged are still shown"
    m = run["off_miles"]
    assert 'data-testid="miles-sheet"' in m and 'data-testid="miles-off"' in m
    assert 'data-testid="miles-add"' not in m


def test_no_profile_mileage_card():
    """The switches moved to Database → Settings (2026-10-25)."""
    html = PAGE.read_text(encoding="utf-8")
    for gone in ("mileageSettingsCard", "miToggleTracking", "miSetPeriod", "miSetReminder",
                 'id="miPeriodSel"', 'id="miReminderToggles"', "_miRenderSettings"):
        assert gone not in html, gone
    eds = html[html.index("var _ENABLED_DISABLED_SETTINGS = {"):]
    eds = eds[:eds.index("};")]
    for key in ("Mileage Tracking Enabled", "Mileage Reminder - Daily Gaps", "Mileage Reminder - Weekly Review",
                "Mileage Reminder - Pay Period", "Mileage Reminder - Odometer"):
        assert f"'{key}': 'Enabled'" in eds, key
    assert "rowData['Setting'] === 'Mileage Reimbursement Period'" in html
    assert "_show('mileageReportCard', _arView && MI.available)" in html


def test_database_miles_tab_lists_trips_for_editing(run):
    m = run["miles"]
    assert 'data-testid="miles-sheet"' in m and m.count('data-testid="miles-row"') == 1
    assert "TRIP-0001" in m and "miEditTrip('TRIP-0001')" in m and "4.2" in m
    assert 'data-testid="miles-add"' in m and 'data-testid="miles-show-void"' in m
    assert run["miles_data_set"], "the edit sheet looks trips up in MI.data"


def test_database_miles_tab_after_route_and_no_mic():
    html = PAGE.read_text(encoding="utf-8")
    sheets = html[html.index("var _SHEETS = ["):]
    sheets = sheets[:sheets.index("];")]
    assert sheets.index("'Route_Planner'") < sheets.index("'Miles'") < sheets.index("'Services_Pricing'")
    assert "if (sheetName === 'Miles')" in html
    assert "miVoice" not in html and "SpeechRecognition" not in html


def test_page_wiring():
    html = PAGE.read_text(encoding="utf-8")
    for needle in ('data-testid="mi-review"', 'data-testid="mi-cancelled"', 'data-testid="reports-mileage-export"',
                   'id="miEntryCard"', 'id="miToolsRow"', "_miRemindersHtml(d.reminders)",
                   "_miReimbHtml(d.reimbursement)"):
        assert needle in html, needle
