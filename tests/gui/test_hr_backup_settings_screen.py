"""
HR Admin -> Settings -> Backups screen (David, 2026-10-16, Phase 1).

The server stores the backup time (and weekday / day of month) in UTC, with
0 = Monday; the screen shows and edits it in the admin's local time. These
tests run the screen's own conversion functions in Node with a fixed UTC
offset, check the screen's script parses, and that it is wired to the
admin-only /backup routes.

Safe: reads hr_admin/index.html as plain text only and runs extracted JS in a
Node subprocess. Never imports ai_prowler_mcp.py, never touches HR data or a
live server.

Run: run_tests.bat tests\\gui\\test_hr_backup_settings_screen.py -v
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

# The test harness stubs subprocess for safety; keep the real Popen (same as
# tests/gui/test_hr_schedule_reminders.py).
_real_Popen = subprocess.Popen

ROOT = Path(__file__).resolve().parent.parent.parent
ADMIN = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")

needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")


def _run(args):
    proc = _real_Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        raise
    return proc.returncode, out, err


def _conv_src():
    start = ADMIN.index("function _bkOffsetMin()")
    end = ADMIN.index("function _bkSnapLabel(")
    return ADMIN[start:end]


def _node(js, tmp_path):
    f = tmp_path / "bk.js"
    f.write_text(js, encoding="utf-8")
    rc, out, err = _run(["node", str(f)])
    assert rc == 0, err
    return json.loads(out.strip().splitlines()[-1])


@needs_node
@pytest.mark.parametrize("offset", [-240, -300, -480, 0])
def test_local_utc_round_trip(offset, tmp_path):
    js = _conv_src() + f"""
_bkOffsetMin = () => {offset};
let bad = [];
for (let wd = 0; wd < 7; wd++) for (const dom of [1, 14, 27]) for (let h = 0; h < 24; h++) for (const m of [0, 5, 45]) {{
  const u = _bkLocalToUtc(h, m, wd, dom);
  const l = _bkUtcToLocal(u);
  if (u.hour < 0 || u.hour > 23 || u.weekday < 0 || u.weekday > 6 || u.day_of_month < 1 || u.day_of_month > 28) bad.push(['range', h, m, wd, dom, u]);
  if (l.hour !== h || l.minute !== m || l.weekday !== wd || l.day_of_month !== dom) bad.push(['trip', h, m, wd, dom, u, l]);
}}
console.log(JSON.stringify({{bad: bad.slice(0, 5), n: bad.length}}));
"""
    out = _node(js, tmp_path)
    assert out["n"] == 0, out["bad"]


@needs_node
def test_eastern_evening_crosses_into_next_utc_day(tmp_path):
    js = _conv_src() + """
_bkOffsetMin = () => -240;            // EDT
const sunNight = _bkLocalToUtc(21, 30, 6, 27);   // Sunday 9:30 PM, day 27
const morning = _bkLocalToUtc(2, 0, 2, 10);      // Wednesday 2:00 AM, day 10
const back = _bkUtcToLocal({hour: 2, minute: 0, weekday: 6, day_of_month: 1});   // server default
console.log(JSON.stringify({sunNight, morning, back}));
"""
    out = _node(js, tmp_path)
    assert out["sunNight"] == {"hour": 1, "minute": 30, "weekday": 0, "day_of_month": 28}
    assert out["morning"] == {"hour": 6, "minute": 0, "weekday": 2, "day_of_month": 10}
    # server default 02:00 UTC Sunday shows as Saturday 10:00 PM in EDT
    assert out["back"] == {"hour": 22, "minute": 0, "weekday": 5, "day_of_month": 1}


@needs_node
def test_snapshot_label_parses_name(tmp_path):
    src = ADMIN[ADMIN.index("function _bkSnapLabel("):ADMIN.index("async function loadBackupSettings(")]
    js = "function escapeHtml(s){return String(s);}\n" + src + """
const ok = _bkSnapLabel('HR_20261016T020000Z');
const bad = _bkSnapLabel('keep_me');
console.log(JSON.stringify({ok, bad, okIsDate: /2026/.test(ok)}));
"""
    out = _node(js, tmp_path)
    assert out["okIsDate"] and out["bad"] == "keep_me"


@needs_node
def test_screen_script_parses(tmp_path):
    i = ADMIN.index("async function loadBackupSettings(")
    start = ADMIN.rindex("<script", 0, i)
    start = ADMIN.index(">", start) + 1
    end = ADMIN.index("</script>", i)
    f = tmp_path / "script.js"
    f.write_text(ADMIN[start:end], encoding="utf-8")
    rc, _out, err = _run(["node", "--check", str(f)])
    assert rc == 0, err[-2000:]
    # prove the check is real: a broken copy must fail
    bad = tmp_path / "broken.js"
    bad.write_text(ADMIN[start:end] + "\nfunction (", encoding="utf-8")
    assert _run(["node", "--check", str(bad)])[0] != 0


def test_screen_is_wired():
    assert 'id="backup-settings-body"' in ADMIN
    line = next(l for l in ADMIN.splitlines() if "if (tabName === 'settings')" in l and "loadPrivacySettings()" in l)
    assert "loadBackupSettings();" in line, "the Settings tab loads the Backups screen"
    assert "apiGet('/backup')" in ADMIN
    assert "apiPost('/backup/settings', body)" in ADMIN
    assert "apiPost('/backup/now', {})" in ADMIN
    save = ADMIN[ADMIN.index("async function saveBackupSettings("):ADMIN.index("async function runBackupNow(")]
    assert "_bkLocalToUtc(" in save, "time is converted to UTC before it is saved"
    for key in ("enabled", "backup_dir", "schedule", "hour", "minute", "weekday", "day_of_month", "retention_count"):
        assert key + ":" in save, key
    render = ADMIN[ADMIN.index("function renderBackupSettings("):ADMIN.index("function _bkToggleScheduleFields(")]
    assert "_bkUtcToLocal(s)" in render, "time is shown in local time"
    assert "escapeHtml(s.backup_dir" in render and "escapeHtml(n)" in render
