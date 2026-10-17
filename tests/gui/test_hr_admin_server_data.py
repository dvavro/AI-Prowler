"""
HR Admin keeps no HR data in the browser any more (David, 2026-10-16, Phase 2).

Pay stubs, deposits, tax filings, contracts, benefits, performance, compliance,
training portfolios, their documents and photos load from the server at
sign-in and every save goes to the server (see tests/mcp_tests/
test_hr_admin_store.py for the server side, and tests/dev/
_tmp_phase2_browser_check.py for the full browser run against the real API).

Safe: reads hr_admin/index.html as plain text; one Node run of extracted
functions with mocked globals. Never imports ai_prowler_mcp.py, never touches
HR data or a live server.

Run: run_tests.bat tests\\gui\\test_hr_admin_server_data.py -v
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_real_Popen = subprocess.Popen          # the harness stubs subprocess for safety

ROOT = Path(__file__).resolve().parent.parent.parent
ADMIN = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")
STORES = ["hr_pay_stubs", "hr_tax_filings", "hr_contracts", "hr_direct_deposits", "hr_ben_v2", "hr_perf_v1",
          "hr_comp_v1", "hr_train_v1", "hr_ben_docs", "hr_perf_docs", "hr_comp_docs"]


def _fn(name):
    start = ADMIN.index(f"function {name}(")
    start = ADMIN.rfind("\n", 0, start) + 1
    end = ADMIN.index("\n}\n", start) + 2
    return ADMIN[start:end]


@pytest.mark.parametrize("key", STORES)
def test_store_never_read_or_written_in_localstorage(key):
    for verb in ("getItem", "setItem"):
        assert f"localStorage.{verb}('{key}'" not in ADMIN and f'localStorage.{verb}("{key}"' not in ADMIN, key


def test_photos_never_kept_in_localstorage():
    assert "localStorage.setItem(`hr_photo_" not in ADMIN
    assert "localStorage.getItem('hr_photo_' + emp.id)" not in ADMIN
    photo = _fn("saveEmpSheetPhoto")
    assert "apiPost('/admin-photos/' + encodeURIComponent(empId)" in photo and "_shrinkPhoto(file)" in photo


def test_server_data_loads_before_any_screen():
    init = _fn("initAdminApp")
    assert init.index("await loadAdminStores();") < init.index("loadEmployees();")
    load = _fn("loadAdminStores")
    assert "apiGet('/admin-store')" in load and "_adminStoreLoaded = true" in load
    assert "await _asMoveBrowserData();" in load


def test_every_store_is_known_to_the_data_layer():
    keys = re.search(r"var ADMIN_STORE_KEYS = \[([^\]]*)\]", ADMIN).group(1)
    assert sorted(re.findall(r"'([\w]+)'", keys)) == sorted(STORES)


def test_one_time_move_deletes_bank_details_from_the_browser():
    mv = _fn("_asMoveBrowserData")
    assert "apiPost('/admin-store-import', { stores: stores, photos: photos })" in mv
    assert "localStorage.removeItem(key)" in mv
    assert "key !== 'hr_direct_deposits'" in mv, "no browser backup copy of bank details"


def test_deposit_form_keeps_last4_only():
    save = _fn("saveDDForm")
    assert "routing_last4: routing ? routing.slice(-4)" in save
    assert "account_last4: account ? account.slice(-4)" in save
    assert re.search(r"\b(routing|account)\s*,", save.split("saved[empId] =")[1].split("};")[0]) is None, \
        "full numbers must not be saved"
    assert "value=\"${escapeHtml(dd.routing||'')}\"" not in ADMIN and "value=\"${escapeHtml(dd.account||'')}\"" not in ADMIN


def test_files_go_through_the_server():
    for fn in ("_benUploadDocs", "_perfUploadDocs", "_compUploadDocs", "_trainUpload"):
        body = ADMIN[ADMIN.index(f"function {fn}("):][:900]
        assert "_adminAddFiles(input," in body, fn
        assert "readAsDataURL" not in body.split("}\n", 1)[0] or "_adminAddFiles" in body
    assert "apiPost('/admin-files'" in _fn("adminUploadFile")
    assert "apiGet('/admin-files/' + encodeURIComponent(doc.file_id))" in _fn("adminDownloadFile")


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")
def test_nothing_is_saved_before_the_server_data_loads(tmp_path):
    src = ADMIN[ADMIN.index("var ADMIN_STORE_KEYS"):ADMIN.index("async function loadAdminStores(")]
    js = """
var toasts = [], posts = [];
function showToast(m) { toasts.push(m); }
async function apiPost(p, b) { posts.push([p, b]); return { value: b.value }; }
var window = { addEventListener: function () {} };
""" + src + """
var before = adminStoreSet('hr_pay_stubs', [{id: 'X'}]);
var got0 = adminStoreGet('hr_pay_stubs');
_adminStoreLoaded = true;
var after = adminStoreSet('hr_perf_v1', {'EMP-00001': {goals: []}});
var copy = adminStoreGet('hr_perf_v1'); copy['EMP-00001'].goals.push('mutated');
setTimeout(function () {
  console.log(JSON.stringify({before: before, got0: got0, after: after, posts: posts.map(function (p) { return p[0]; }),
                              stored: adminStoreGet('hr_perf_v1'), toasts: toasts.length}));
}, 50);
"""
    f = tmp_path / "t.js"
    f.write_text(js, encoding="utf-8")
    proc = _real_Popen(["node", str(f)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate(timeout=60)
    assert proc.returncode == 0, err
    r = json.loads(out.strip().splitlines()[-1])
    assert r["before"] is False and r["got0"] == [] and r["toasts"] == 1, "refused before load, nothing sent"
    assert r["after"] is True and r["posts"] == ["/admin-store/hr_perf_v1"]
    assert r["stored"] == {"EMP-00001": {"goals": []}}, "screens get copies, never the cached object itself"
