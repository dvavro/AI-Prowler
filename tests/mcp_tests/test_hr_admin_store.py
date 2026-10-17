"""
HR Admin data that used to live only in the browser -> the HR data folders
(David, 2026-10-16, Phase 2).

  * every store round-trips through the server in the browser's own shape, and
    lands in the right place: rows about one employee in THEIR folder, the rest
    in company\\
  * bank details: only the last 4 digits ever reach disk
  * uploaded files and photos are real files in the employee's folder;
    download, replace and delete (deleted files are set aside, not lost)
  * every route is admin only; payroll changes are audited (who + what kind,
    never the values)
  * the one-time browser upload: old employee IDs matched BY NAME through the
    old hr_db.json (read only, unchanged); anything unmatched kept in the company
    folder and attached automatically once that person exists; server data wins;
    running it twice changes nothing

All in pytest's tmp_path with ZTEST / +hrtest@ data. Never touches real HR data
or config.json.

Run: run_tests.bat tests\\mcp_tests\\test_hr_admin_store.py -v
"""
import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

F1, F2 = "EMP-00001_One_ZTEST", "EMP-00002_Two_ZTEST"
PDF = b"%PDF-1.4 ZTEST document"
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")


def durl(raw, mime="application/pdf"):
    return f"data:{mime};base64," + base64.b64encode(raw).decode()


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    live = tmp_path / "hr"
    live.mkdir()
    monkeypatch.setattr(m, "_HR_DB_PATH", str(live / "hr_db.json"))
    m._hr_save_db({"config": {"company_name": "ZTEST Co", "setup_complete": True},
                   "employees": [{"id": "EMP-00001", "first_name": "ZTEST", "last_name": "One", "status": "Active"},
                                 {"id": "EMP-00002", "first_name": "ZTEST", "last_name": "Two", "status": "Active"}],
                   "tasks": [], "documents": [], "audit_log": []})
    m.ztest_live = live
    return m


def call(ap, method, path, body=None, role="admin"):
    auth = {"role": role, "user_id": "ztest-admin"} if role == "admin" else \
           ({"role": "employee", "employee_id": "EMP-00001"} if role == "employee" else {"role": None})
    st, ct, b = ap._hr_api_route(method, path, {}, body or {}, auth)
    return st, json.loads(b)


def put(ap, name, value):
    return call(ap, "POST", f"/admin-store/{name}", {"value": value})


def rd(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def all_text(root):
    return "".join(p.read_text(encoding="utf-8", errors="replace") for p in Path(root).rglob("*") if p.is_file())


# ── stores ──────────────────────────────────────────────────────────────────
def test_list_store_rows_go_to_each_employee(ap):
    stubs = [{"id": "STUB-1", "employee_id": "EMP-00001", "gross": "100.00"},
             {"id": "STUB-2", "employee_id": "EMP-00002", "gross": "200.00"}]
    st, r = put(ap, "hr_pay_stubs", stubs)
    assert st == 200 and r["value"] == stubs
    e1 = rd(ap.ztest_live / "employees" / F1 / "pay_stubs.json")["items"]
    assert [i["id"] for i in e1] == ["STUB-1"]
    assert call(ap, "GET", "/admin-store")[1]["stores"]["hr_pay_stubs"] == stubs
    st, r = put(ap, "hr_tax_filings", [{"id": "w2", "label": "W-2", "filed_at": "2026-01-30T00:00:00Z"}])
    assert st == 200
    assert rd(ap.ztest_live / "company" / "tax_filings.json")["items"][0]["id"] == "w2"


def test_map_store_splits_employee_and_company_keys(ap):
    value = {"EMP-00001": {"i9": {"status": "Complete"}}, "deadlines": [{"title": "EEO-1", "date": "2027-03-31"}]}
    st, r = put(ap, "hr_comp_v1", value)
    assert st == 200 and r["value"] == value
    assert rd(ap.ztest_live / "employees" / F1 / "compliance.json")["items"][0]["data"]["i9"]["status"] == "Complete"
    company = rd(ap.ztest_live / "company" / "compliance.json")["items"]
    assert company[0]["key"] == "deadlines"
    assert not (ap.ztest_live / "employees" / F2 / "compliance.json").exists()


def test_folder_store_docs_follow_their_employee(ap):
    value = {"plan_docs": [{"name": "spd.pdf", "date": "1/1/2026", "size": "1 KB", "file_id": "AF-00009"}],
             "enrollment": [{"name": "form.pdf", "date": "1/2/2026", "emp_id": "EMP-00002", "file_id": "AF-00010"}]}
    st, r = put(ap, "hr_ben_docs", value)
    assert st == 200 and r["value"] == value
    assert rd(ap.ztest_live / "employees" / F2 / "benefit_documents.json")["items"][0]["doc"]["name"] == "form.pdf"
    assert rd(ap.ztest_live / "company" / "benefit_documents.json")["items"][0]["folder"] == "plan_docs"


def test_direct_deposit_keeps_last4_only(ap):
    st, r = put(ap, "hr_direct_deposits", {"EMP-00001": {
        "bank_name": "ZTEST Bank", "account_type": "Checking", "routing": "021000021",
        "account": "123456789012", "account_last4": "9012", "signature": "ZTEST One"}})
    assert st == 200
    dd = r["value"]["EMP-00001"]
    assert dd["account_last4"] == "9012" and dd["routing_last4"] == "0021"
    assert "routing" not in dd and "account" not in dd
    text = all_text(ap.ztest_live)
    assert "123456789012" not in text and "021000021" not in text, "a full bank number reached disk"


def test_store_rejects_inline_files_and_unknown_names(ap):
    st, r = put(ap, "hr_ben_docs", {"plan_docs": [{"name": "x.pdf", "data": durl(PDF * 200)}]})
    assert st == 400 and r["error"] == "files_must_be_uploaded_separately"
    assert put(ap, "hr_nope", [])[0] == 404
    assert put(ap, "hr_pay_stubs", {"not": "a list"})[0] == 400


def test_all_routes_admin_only(ap):
    for method, path in (("GET", "/admin-store"), ("POST", "/admin-store/hr_pay_stubs"),
                         ("POST", "/admin-store-import"), ("POST", "/admin-files"),
                         ("GET", "/admin-files/AF-00001"), ("DELETE", "/admin-files/AF-00001"),
                         ("GET", "/admin-photos"), ("POST", "/admin-photos/EMP-00001"),
                         ("DELETE", "/admin-photos/EMP-00001")):
        assert call(ap, method, path, role=None)[0] == 401, (method, path)
        assert call(ap, method, path, role="employee")[0] == 403, (method, path)


def test_payroll_changes_are_audited_without_values(ap):
    put(ap, "hr_direct_deposits", {"EMP-00001": {"bank_name": "ZTEST Bank", "account": "555566667777"}})
    put(ap, "hr_perf_v1", {"EMP-00001": {"goals": []}})                 # not an audited store
    log = ap._hr_load_db()["audit_log"]
    dd = [a for a in log if a.get("store") == "direct_deposits"]
    assert len(dd) == 1 and dd[0]["employee_id"] == "EMP-00001" and dd[0]["by"] == "ztest-admin"
    assert "ZTEST Bank" not in json.dumps(log) and "7777" not in json.dumps(log)
    assert not [a for a in log if a.get("store") == "performance"]
    put(ap, "hr_direct_deposits", {"EMP-00001": {"bank_name": "ZTEST Bank", "account_last4": "7777"}})
    assert len([a for a in ap._hr_load_db()["audit_log"] if a.get("store") == "direct_deposits"]) == 1, \
        "an unchanged save is not logged"


# ── files ───────────────────────────────────────────────────────────────────
def test_upload_download_delete_file(ap):
    st, r = call(ap, "POST", "/admin-files", {"store": "hr_ben_docs", "folder": "plan_docs", "name": "../evil/spd.pdf",
                                              "data": durl(PDF), "employee_id": "EMP-00001"})
    assert st == 200, r
    f = r["file"]
    on_disk = ap.ztest_live / "employees" / F1 / "benefits" / "plan_docs" / f"{f['id']}_spd.pdf"
    assert on_disk.read_bytes() == PDF, "stored as a real file inside the employee's folder"
    st, r = call(ap, "GET", f"/admin-files/{f['id']}")
    assert st == 200 and base64.b64decode(r["data_b64"]) == PDF and r["filename"] == "spd.pdf"
    assert call(ap, "DELETE", f"/admin-files/{f['id']}")[0] == 200
    assert not on_disk.exists()
    assert list((ap.ztest_live / "employees" / F1 / "_deleted_files").glob("*_spd.pdf")), "set aside, not lost"
    assert call(ap, "GET", f"/admin-files/{f['id']}")[0] == 404


def test_company_file_and_bad_uploads(ap):
    st, r = call(ap, "POST", "/admin-files", {"store": "hr_comp_docs", "folder": "posters", "name": "osha.pdf",
                                              "data": durl(PDF)})
    assert st == 200
    assert (ap.ztest_live / "company" / "files" / "compliance" / "posters" / f"{r['file']['id']}_osha.pdf").exists()
    assert call(ap, "POST", "/admin-files", {"store": "hr_nope", "data": durl(PDF)})[0] == 400
    assert call(ap, "POST", "/admin-files", {"store": "hr_ben_docs", "data": "not a file"})[0] == 400
    assert call(ap, "POST", "/admin-files", {"store": "hr_ben_docs", "data": durl(PDF),
                                             "employee_id": "EMP-09999"})[0] == 404


def test_photos(ap):
    st, r = call(ap, "POST", "/admin-photos/EMP-00001", {"data": durl(PNG, "image/png")})
    assert st == 200
    first = r["photo_file_id"]
    assert list((ap.ztest_live / "employees" / F1 / "photo").glob(f"{first}_photo.png"))
    photos = call(ap, "GET", "/admin-photos")[1]["photos"]
    assert photos["EMP-00001"].startswith("data:image/png;base64,") and "EMP-00002" not in photos
    st, r = call(ap, "POST", "/admin-photos/EMP-00001", {"data": durl(PNG, "image/png")})
    assert r["photo_file_id"] != first
    assert len(list((ap.ztest_live / "employees" / F1 / "photo").glob("*"))) == 1, "old photo set aside"
    assert call(ap, "POST", "/admin-photos/EMP-00001", {"data": durl(PDF)})[0] == 400
    assert call(ap, "DELETE", "/admin-photos/EMP-00001")[0] == 200
    assert call(ap, "GET", "/admin-photos")[1]["photos"] == {}


def test_backup_includes_admin_files(ap):
    call(ap, "POST", "/admin-files", {"store": "hr_ben_docs", "folder": "plan_docs", "name": "spd.pdf",
                                      "data": durl(PDF), "employee_id": "EMP-00001"})
    call(ap, "POST", "/admin-files", {"store": "hr_comp_docs", "folder": "posters", "name": "osha.pdf",
                                      "data": durl(PDF)})
    ap._hr_update_backup_settings({"backup_dir": str(ap.ztest_live.parent / "backups")})
    snap = ap.ztest_live.parent / "backups" / ap._hr_run_employee_backup()["snapshot"]
    assert list((snap / "employees" / F1 / "benefits" / "plan_docs").glob("*_spd.pdf"))
    assert list((snap / "company" / "files" / "compliance" / "posters").glob("*_osha.pdf"))


# ── the one-time browser upload ─────────────────────────────────────────────
OLD_DB = {"employees": [{"id": "EMP-00007", "first_name": "ZTEST", "last_name": "One"},
                        {"id": "EMP-00008", "first_name": "ZTEST", "last_name": "Later"}]}


def _browser():
    return {
        "stores": {
            "hr_pay_stubs": [{"id": "STUB-1", "employee_id": "EMP-00007", "gross": "100.00"},
                             {"id": "STUB-2", "employee_id": "EMP-00099", "gross": "50.00"}],
            "hr_tax_filings": [{"id": "w2", "label": "W-2", "filed_at": "2026-01-30T00:00:00Z"}],
            "hr_direct_deposits": {"EMP-00007": {"bank_name": "ZTEST Bank", "routing": "021000021",
                                                 "account": "123456789012", "account_last4": "9012"}},
            "hr_perf_v1": {"EMP-00008": {"goals": [{"id": "G1", "title": "ZTEST goal"}]}},
            "hr_comp_v1": {"deadlines": [{"title": "ZTEST deadline", "date": "2027-01-01"}]},
            "hr_train_v1": {"EMP-00007": {"safety": {"docs": [{"name": "osha.pdf", "data": durl(PDF), "date": "1/1"}]}}},
            "hr_ben_docs": {"plan_docs": [{"name": "spd.pdf", "data": durl(PDF), "date": "1/1", "size": "1 KB",
                                           "emp_id": None}],
                            "enrollment": [{"name": "enroll.pdf", "data": durl(PDF), "date": "1/2", "size": "1 KB",
                                            "emp_id": "EMP-00008"}]},
        },
        "photos": {"EMP-00007": durl(PNG, "image/png"), "EMP-00008": durl(PNG, "image/png")},
    }


def test_import_matches_by_name_and_keeps_the_rest(ap):
    old = ap.ztest_live / "hr_db.json"
    old.write_text(json.dumps(OLD_DB), encoding="utf-8")
    before = old.read_bytes()
    st, r = call(ap, "POST", "/admin-store-import", _browser())
    assert st == 200, r
    s = r["summary"]
    stores = r["stores"]
    # ZTEST One (old EMP-00007) -> new EMP-00001
    assert [x["id"] for x in stores["hr_pay_stubs"] if x.get("employee_id") == "EMP-00001"] == ["STUB-1"]
    assert stores["hr_direct_deposits"]["EMP-00001"]["account_last4"] == "9012"
    assert "routing" not in stores["hr_direct_deposits"]["EMP-00001"]
    tdoc = stores["hr_train_v1"]["EMP-00001"]["safety"]["docs"][0]
    assert "data" not in tdoc and tdoc["file_id"]
    assert list((ap.ztest_live / "employees" / F1 / "training" / "safety").glob("*_osha.pdf"))
    assert call(ap, "GET", "/admin-photos")[1]["photos"].get("EMP-00001")
    # company-wide items
    assert stores["hr_tax_filings"][0]["id"] == "w2"
    assert stores["hr_comp_v1"]["deadlines"][0]["title"] == "ZTEST deadline"
    assert "emp_id" not in stores["hr_ben_docs"]["plan_docs"][0]
    assert list((ap.ztest_live / "company" / "files" / "benefits" / "plan_docs").glob("*_spd.pdf"))
    # not yet re-created (ZTEST Later) or unknown (EMP-00099): kept, NOT attached to anyone
    assert s["unmatched"] == 4, s                  # STUB-2, perf, enrollment doc, photo
    unmatched = call(ap, "GET", "/admin-store")[1]["unmatched"]
    assert {u["old_employee_id"] for u in unmatched} == {"EMP-00099", "EMP-00008"}
    assert "EMP-00002" not in json.dumps(stores), "nothing guessed onto the other employee"
    assert not any(x.get("employee_id") == "EMP-00002" for x in stores["hr_pay_stubs"])
    assert old.read_bytes() == before, "the old hr_db.json is only read"
    assert "123456789012" not in all_text(ap.ztest_live)


def test_unmatched_attach_once_the_person_exists(ap):
    (ap.ztest_live / "hr_db.json").write_text(json.dumps(OLD_DB), encoding="utf-8")
    call(ap, "POST", "/admin-store-import", _browser())
    db = ap._hr_load_db()
    db["employees"].append({"id": "EMP-00003", "first_name": "ZTEST", "last_name": "Later", "status": "Active"})
    ap._hr_save_db(db)
    (ap.ztest_live / "hr_db.json").unlink()        # attaching later no longer needs the old file
    st, r = call(ap, "GET", "/admin-store")
    stores = r["stores"]
    assert stores["hr_perf_v1"]["EMP-00003"]["goals"][0]["title"] == "ZTEST goal"
    assert stores["hr_ben_docs"]["enrollment"][0]["emp_id"] == "EMP-00003"
    f3 = ap.ztest_live / "employees" / "EMP-00003_Later_ZTEST"
    assert list((f3 / "benefits" / "enrollment").glob("*_enroll.pdf")), "file moved into their folder"
    assert list((f3 / "photo").glob("*")) and call(ap, "GET", "/admin-photos")[1]["photos"].get("EMP-00003")
    assert [u["old_employee_id"] for u in r["unmatched"]] == ["EMP-00099"]
    assert any(a.get("action") == "browser_import_attached" for a in ap._hr_load_db()["audit_log"])


def test_import_server_wins_and_is_idempotent(ap):
    (ap.ztest_live / "hr_db.json").write_text(json.dumps(OLD_DB), encoding="utf-8")
    put(ap, "hr_direct_deposits", {"EMP-00001": {"bank_name": "ZTEST Server Bank", "account_last4": "1111"}})
    call(ap, "POST", "/admin-store-import", _browser())
    st, r = call(ap, "POST", "/admin-store-import", _browser())
    stores = r["stores"]
    assert stores["hr_direct_deposits"]["EMP-00001"]["bank_name"] == "ZTEST Server Bank"
    assert [x["id"] for x in stores["hr_pay_stubs"]] == ["STUB-1"]
    assert len(stores["hr_tax_filings"]) == 1 and len(stores["hr_comp_v1"]["deadlines"]) == 1
    assert len(stores["hr_ben_docs"]["plan_docs"]) == 1


def test_rename_remembers_previous_name_and_import_still_matches(ap):
    """ZTEST One marries and becomes ZTEST Wed; a browser that saved data under
    her old name still finds her."""
    st, r = call(ap, "PATCH", "/employees/EMP-00001", {"last_name": "Wed"})
    assert st == 200 and r["employee"]["previous_names"][0]["last_name"] == "One"
    (ap.ztest_live / "hr_db.json").write_text(json.dumps(OLD_DB), encoding="utf-8")
    st, r = call(ap, "POST", "/admin-store-import", _browser())
    assert [x["id"] for x in r["stores"]["hr_pay_stubs"] if x.get("employee_id") == "EMP-00001"] == ["STUB-1"]
    assert r["stores"]["hr_direct_deposits"]["EMP-00001"]["account_last4"] == "9012"
    # renaming again keeps both earlier names
    call(ap, "PATCH", "/employees/EMP-00001", {"first_name": "Zee"})
    names = [(p["first_name"], p["last_name"]) for p in ap._hr_load_db()["employees"][0]["previous_names"]]
    assert names == [("ZTEST", "One"), ("ZTEST", "Wed")]


def test_portal_sign_in_with_old_name_finds_renamed_employee(ap):
    call(ap, "PATCH", "/employees/EMP-00001", {"last_name": "Wed"})
    db = ap._hr_load_db()
    emp, changed = ap._hr_portal_employee_for_user({"id": "ztest-one", "name": "ZTEST One"}, db)
    assert emp and emp["id"] == "EMP-00001" and changed, "no second record created for the old name"
    assert len(db["employees"]) == 2


def test_assign_unmatched_by_hand_merges_and_remembers_old_name(ap):
    """Re-created under her married name, so the upload can't match her; HR assigns."""
    (ap.ztest_live / "hr_db.json").write_text(json.dumps(OLD_DB), encoding="utf-8")
    db = ap._hr_load_db()
    db["employees"].append({"id": "EMP-00003", "first_name": "ZTEST", "last_name": "Married", "status": "Active"})
    ap._hr_save_db(db)
    put(ap, "hr_perf_v1", {"EMP-00003": {"goals": [{"id": "G0", "title": "server goal"}], "notes": "server"}})
    call(ap, "POST", "/admin-store-import", _browser())
    um = call(ap, "GET", "/admin-store")[1]["unmatched"]
    later = [u for u in um if u["old_employee_id"] == "EMP-00008"]
    assert later and any(u.get("photo", "").startswith("data:image/png") for u in later), "photo preview shown"
    assert call(ap, "POST", "/admin-store-unmatched/assign", {"old_employee_id": "EMP-00008"}, role="employee")[0] == 403
    st, r = call(ap, "POST", "/admin-store-unmatched/assign", {"old_employee_id": "EMP-00008", "employee_id": "EMP-00003"})
    assert st == 200 and r["assigned"] == 3 and r["left"] == 0, r
    stores = call(ap, "GET", "/admin-store")[1]
    goals = stores["stores"]["hr_perf_v1"]["EMP-00003"]["goals"]
    assert [g["id"] for g in goals] == ["G0", "G1"] and stores["stores"]["hr_perf_v1"]["EMP-00003"]["notes"] == "server"
    assert stores["stores"]["hr_ben_docs"]["enrollment"][0]["emp_id"] == "EMP-00003"
    assert "EMP-00008" not in {u["old_employee_id"] for u in stores["unmatched"]}
    f3 = ap.ztest_live / "employees" / "EMP-00003_Married_ZTEST"
    assert list((f3 / "benefits" / "enrollment").glob("*_enroll.pdf")) and list((f3 / "photo").glob("*"))
    prev = ap._hr_load_db()["employees"][2]["previous_names"]
    assert prev[0]["first_name"] == "ZTEST" and prev[0]["last_name"] == "Later"
    assert call(ap, "POST", "/admin-store-unmatched/assign",
                {"old_employee_id": "EMP-00008", "employee_id": "EMP-00003"})[0] == 400, "nothing left"
    assert call(ap, "POST", "/admin-store-unmatched/assign",
                {"old_employee_id": "EMP-00099", "employee_id": "EMP-09999"})[0] == 404


def test_import_without_old_file_attaches_nothing(ap):
    st, r = call(ap, "POST", "/admin-store-import", _browser())
    assert st == 200
    stores = r["stores"]
    assert stores["hr_pay_stubs"] == [] and "EMP-00001" not in stores["hr_direct_deposits"]
    assert stores["hr_tax_filings"][0]["id"] == "w2", "company items still arrive"
    assert r["summary"]["unmatched"] >= 5
