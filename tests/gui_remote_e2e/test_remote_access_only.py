"""Remote PWA — Access-Only Folders on Perms AND Files (REMOTE_PWA_E2E_TEST_SPEC.md §5.5b AO).

Access-only folders are readable by Claude but never indexed; personal mode only
(the Remote app itself is personal-mode only). David 2026-10-09 / 2026-10-10.

Acts ONLY on the access-only test folder C:\\Users\\david\\AI-Prowler-E2E-Remote-AccessOnly
(outside every tracked and every writable folder — a true access-only folder whose
write switch is its own; created and deleted by the run, David's OK 2026-10-10).
The guard blocks grant_access / revoke_access (and the write switch) on any other
path; each test takes it off both lists afterwards, and the run end deletes it.

  AO-01  the section is there; the indexed list above it shows only indexed
         folders (no access-only entries, no [W]/[R] text in the paths)
  AO-02  add a folder: path + Add → token popup "Add Access-Only Folder" →
         right token → it's listed as R, and the server lists it as access-only
         (and NOT as indexed)
  AO-03  wrong token → refused, nothing added
  AO-04  empty path → "Type a folder path first", no popup
  AO-05  a folder that doesn't exist → the server's refusal shows in the popup,
         nothing added
  AO-06  remove (🗑) is instant; the server no longer lists it
  AO-07  adding the same folder again → refused: "already an access-only folder"
  Add rules (2026-10-10, David):
  AO-12  a folder inside an access-only folder → refused "already covered by …"
  AO-13  a file → refused "is a file … folders only"
  AO-14  a folder containing an access-only folder → added, the inner one folded in
  AO-15  a folder inside an INDEXED folder → refused "inside indexed folder"
  Files tab (2026-10-10, David: "a separation between Indexed tracked folders
  and access only folders in the files page"):
  AO-08  two sections — "Indexed Folders" (the sandbox) and "Access-Only
         Folders" (the test folder), each folder in its own section only
  AO-09  read-only access-only folder: "Read only", no Upload; 📥 Download →
         ⬇ Get downloads the exact bytes
  AO-10  writable access-only folder: 📷 Upload saves the file, the status says
         "not indexed", the folder is NOT added to the indexed/tracked list
  AO-11  👁 View a text file inside the access-only folder

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_access_only
"""
import pytest
from playwright.sync_api import expect

from app import type_text
from remote_safety import AO_SANDBOX, SANDBOX, is_ao_sandbox, parse_tracked_sections

AO = str(AO_SANDBOX)
SEED = "ZTEST_E2E_access_only_note.txt"


def _sections(rapi) -> dict:
    return parse_tracked_sections(rapi.text("list_tracked_directories"))


def _listed(rapi) -> bool:
    return any(is_ao_sandbox(p) for p in _sections(rapi)["access_only"])


@pytest.fixture
def ao_folder(rapi):
    """The test folder exists (with one ZTEST file) and is NOT on the list."""
    AO_SANDBOX.mkdir(parents=True, exist_ok=True)
    (AO_SANDBOX / SEED).write_text("ZTEST E2E — access-only folder test, safe to delete.\n", encoding="utf-8")
    if _listed(rapi):
        rapi.call("revoke_access", {"directory": AO})
    assert not _listed(rapi)
    yield AO_SANDBOX
    for p in _sections(rapi)["access_only"]:                 # the folder and anything inside it
        if p.lower() == AO.lower() or p.lower().startswith(AO.lower() + "\\"):
            rapi.call("revoke_access", {"directory": p}, source="cleanup")


@pytest.fixture
def ao_listed(rapi, ao_folder):
    rapi.call("grant_access", {"directory": AO})
    assert _listed(rapi)
    return ao_folder


def _ao_writable(rapi) -> bool:
    for line in rapi.text("list_writable_directories").splitlines():
        if "[W]" in line and is_ao_sandbox(line.split("[W]", 1)[1].strip()):
            return True
    return False


@pytest.fixture
def ao_writable(rapi, ao_listed):
    rapi.call("grant_write_access", {"directory": AO})
    assert _ao_writable(rapi)
    yield ao_listed
    if _ao_writable(rapi):
        rapi.call("revoke_write_access", {"directory": AO}, source="cleanup")


def _files(remote):
    remote.refresh_all()
    remote.goto("files")
    expect(remote.page.locator("#filesAoTitle")).to_be_visible(timeout=20_000)


def _ao_files_row(page):
    return page.locator(".files-ao .row", has=page.locator(".rs", has_text=AO)).first


def _perms(remote):
    remote.refresh_all()
    remote.goto("perms")
    expect(remote.page.locator("#aoTitle")).to_be_visible(timeout=20_000)
    expect(remote.page.locator("#aoList .spinner")).to_have_count(0, timeout=20_000)


def _ao_row(page):
    return page.locator(f'xpath=//div[contains(@class,"ao-row") and @data-path="{AO}"]')


def _type_path(remote, path):
    remote.step(f"type the folder path {path!r} and tap Add")
    inp = remote.page.locator("#aoInput")
    inp.fill("")
    if path:
        type_text(remote.page, inp, path)
    remote.page.locator("#aoAddBtn").click()


def _cancel(remote):
    toast = remote.page.locator("#toast.show")
    if toast.count():
        expect(toast).to_have_count(0, timeout=8_000)
    remote.step("tap Cancel")
    remote.page.locator("#reAuthModal .btn-cancel").click()
    expect(remote.page.locator("#reAuthModal")).to_be_hidden()


# ── AO-01 ────────────────────────────────────────────────────────────────────
def test_AO_01_section_shown_and_indexed_list_clean(remote, rapi, ao_listed):
    _perms(remote)
    page = remote.page
    expect(page.locator("#aoTitle")).to_contain_text("Access-Only Folders")
    expect(_ao_row(page)).to_have_count(1, timeout=20_000)
    # the indexed list holds the sandbox row by its exact path (no "[W] " left
    # on it) and never the access-only folder
    expect(page.locator(f'xpath=//div[@id="permList"]//input[contains(@class,"perm-cb") and @data-path="{SANDBOX}"]')
           ).to_have_count(1)
    expect(page.locator(f'xpath=//div[@id="permList"]//input[@data-path="{AO}"]')).to_have_count(0)
    bad = page.evaluate("""() => [...document.querySelectorAll('#permList .perm-cb, #aoList .perm-cb')]
                           .map(e => e.getAttribute('data-path')).filter(p => /^\\[(W|R|W\\*)\\]/.test(p))""")
    assert not bad, f"paths still carry a [W]/[R] badge: {bad}"


# ── AO-02 ────────────────────────────────────────────────────────────────────
def test_AO_02_add_with_token(remote, rapi, token, ao_folder):
    _perms(remote)
    page = remote.page
    expect(_ao_row(page)).to_have_count(0)
    _type_path(remote, AO)
    modal = page.locator("#reAuthModal")
    expect(modal).to_be_visible()
    expect(page.locator("#raTitle")).to_contain_text("Add Access-Only Folder")
    expect(page.locator("#raPath")).to_have_text(AO)
    expect(page.locator("#raConfirm")).to_have_text("Add Folder")
    remote.step("re-type the Bearer token (not logged) and tap Add Folder")
    type_text(page, page.locator("#raInput"), token)
    page.locator("#raConfirm").click()
    expect(modal).to_be_hidden(timeout=20_000)
    expect(page.locator("#toast")).to_contain_text("Access-only folder added")
    expect(_ao_row(page)).to_have_count(1, timeout=20_000)
    expect(_ao_row(page).locator(".badge")).to_have_text("R")
    expect(page.locator("#aoInput")).to_have_value("")
    secs = _sections(rapi)
    assert any(is_ao_sandbox(p) for p in secs["access_only"]), secs
    assert not any(is_ao_sandbox(p) for p in secs["tracked"]), "an access-only folder was listed as indexed"


# ── AO-03 ────────────────────────────────────────────────────────────────────
def test_AO_03_wrong_token_adds_nothing(remote, rapi, ao_folder):
    _perms(remote)
    _type_path(remote, AO)
    remote.step("type a wrong token and tap Add Folder")
    type_text(remote.page, remote.page.locator("#raInput"), "definitely-not-the-token")
    remote.page.locator("#raConfirm").click()
    expect(remote.page.locator("#raErr")).to_have_text("Incorrect token (1/3)")
    _cancel(remote)
    assert not _listed(rapi), "a folder was added with a wrong token"
    expect(_ao_row(remote.page)).to_have_count(0)


# ── AO-04 ────────────────────────────────────────────────────────────────────
def test_AO_04_empty_path_asks_for_one(remote, rapi, ao_folder):
    _perms(remote)
    _type_path(remote, "")
    expect(remote.page.locator("#toast")).to_contain_text("Type a folder path first")
    expect(remote.page.locator("#reAuthModal")).to_be_hidden()


# ── AO-05 ────────────────────────────────────────────────────────────────────
def test_AO_05_missing_folder_is_refused(remote, rapi, token, ao_folder):
    for f in AO_SANDBOX.iterdir():
        f.unlink()
    AO_SANDBOX.rmdir()                          # the path is right, but the folder is gone
    _perms(remote)
    _type_path(remote, AO)
    type_text(remote.page, remote.page.locator("#raInput"), token)
    remote.page.locator("#raConfirm").click()
    expect(remote.page.locator("#raErr")).to_contain_text("does not exist", timeout=20_000)
    _cancel(remote)
    assert not _listed(rapi), "a missing folder was added"


# ── AO-06 ────────────────────────────────────────────────────────────────────
def test_AO_06_remove_is_instant(remote, rapi, ao_listed):
    _perms(remote)
    row = _ao_row(remote.page)
    expect(row).to_have_count(1, timeout=20_000)
    remote.step("tap 🗑 on the access-only test folder")
    row.locator(".ao-remove").click()
    expect(remote.page.locator("#toast")).to_contain_text("Access removed")
    expect(_ao_row(remote.page)).to_have_count(0, timeout=20_000)
    assert not _listed(rapi), "the server still lists the folder"


# ── AO-07 ────────────────────────────────────────────────────────────────────
def _add_refused(remote, token, path, says):
    """Type `path` → Add → token → the server's refusal shows in the popup."""
    _perms(remote)
    _type_path(remote, path)
    type_text(remote.page, remote.page.locator("#raInput"), token)
    remote.page.locator("#raConfirm").click()
    expect(remote.page.locator("#raErr")).to_contain_text(says, timeout=20_000)
    _cancel(remote)


def test_AO_07_adding_twice_is_refused(remote, rapi, token, ao_listed):
    # 2026-10-10 (David): duplicates are not allowed — refused, not a no-op
    _add_refused(remote, token, AO, "already an access-only folder")
    assert [p for p in _sections(rapi)["access_only"] if is_ao_sandbox(p)].__len__() == 1


# ── Add rules (2026-10-10, David) ────────────────────────────────────────────
CHILD = AO_SANDBOX / "ZTEST_E2E_child"


@pytest.fixture
def child(ao_folder):
    CHILD.mkdir(exist_ok=True)
    yield CHILD


def test_AO_12_folder_covered_by_access_only_folder_is_refused(remote, rapi, token, ao_listed, child):
    _add_refused(remote, token, str(CHILD), "already covered by access-only folder")
    assert not any(str(CHILD).lower() == p.lower() for p in _sections(rapi)["access_only"])


def test_AO_13_a_file_is_refused(remote, rapi, token, ao_folder):
    _add_refused(remote, token, str(AO_SANDBOX / SEED), "is a file")
    assert not _listed(rapi)


def test_AO_14_parent_folds_in_the_inner_folder(remote, rapi, token, child):
    rapi.call("grant_access", {"directory": str(CHILD)})
    assert any(str(CHILD).lower() == p.lower() for p in _sections(rapi)["access_only"])
    _perms(remote)
    _type_path(remote, AO)
    type_text(remote.page, remote.page.locator("#raInput"), token)
    remote.page.locator("#raConfirm").click()
    expect(remote.page.locator("#reAuthModal")).to_be_hidden(timeout=20_000)
    expect(remote.page.locator("#toast")).to_contain_text("folded in")
    ao = _sections(rapi)["access_only"]
    assert any(is_ao_sandbox(p) for p in ao), ao
    assert not any(str(CHILD).lower() == p.lower() for p in ao), f"the inner folder wasn't folded in: {ao}"
    expect(_ao_row(remote.page)).to_have_count(1, timeout=20_000)


def test_AO_15_folder_inside_an_indexed_folder_is_refused(remote, rapi, token):
    inside = SANDBOX / "ZTEST_E2E_ao_inside_indexed"
    inside.mkdir(exist_ok=True)
    try:
        _add_refused(remote, token, str(inside), "inside indexed folder")
        assert not any(str(inside).lower() == p.lower() for p in _sections(rapi)["access_only"])
    finally:
        inside.rmdir()


# ══ Files tab (2026-10-10) ════════════════════════════════════════════════════

# ── AO-08 ────────────────────────────────────────────────────────────────────
def test_AO_08_files_has_indexed_and_access_only_sections(remote, rapi, ao_listed):
    _files(remote)
    page = remote.page
    expect(page.locator("#filesIdxTitle")).to_contain_text("Indexed Folders")
    expect(page.locator("#filesAoTitle")).to_contain_text("Access-Only Folders")
    # the sandbox (indexed) is only in the Indexed card, the test folder only in the Access-Only card
    expect(page.locator(".files-idx .row", has=page.locator(".rs", has_text=str(SANDBOX)))).to_have_count(1)
    expect(page.locator(".files-ao .row", has=page.locator(".rs", has_text=str(SANDBOX)))).to_have_count(0)
    expect(_ao_files_row(page)).to_be_visible()
    expect(page.locator(".files-idx .row", has=page.locator(".rs", has_text=AO))).to_have_count(0)
    # every row's path is a clean path (no [W]/[R] badge)
    bad = page.evaluate("""() => [...document.querySelectorAll('#fileList .rs')]
                           .map(e => e.textContent).filter(t => /^\\[(W|R|W\\*)\\]/.test(t))""")
    assert not bad, f"badges left on paths: {bad}"


# ── AO-09 ────────────────────────────────────────────────────────────────────
def test_AO_09_read_only_access_only_folder_download(remote, rapi, ao_listed, tmp_path):
    assert not _ao_writable(rapi)
    _files(remote)
    page = remote.page
    row = _ao_files_row(page)
    expect(row.get_by_text("Read only")).to_be_visible()
    expect(page.locator(f'xpath=//input[@type="file" and @data-dir="{AO}"]')).to_have_count(0)
    remote.step("tap 📥 Download on the access-only folder")
    row.locator(".dl-picker-btn").click()
    get = page.locator(f'xpath=//button[contains(@class,"dl-btn") and @data-path="{AO}\\{SEED}"]')
    expect(get).to_be_visible(timeout=20_000)
    remote.step(f"tap ⬇ Get on {SEED}")
    with page.expect_download(timeout=30_000) as dl:
        get.click()
    out = tmp_path / "got.txt"
    dl.value.save_as(out)
    assert out.read_bytes() == (AO_SANDBOX / SEED).read_bytes(), "downloaded bytes differ from the file"


# ── AO-10 ────────────────────────────────────────────────────────────────────
def test_AO_10_upload_into_access_only_folder_is_not_indexed(remote, rapi, ao_writable, tmp_path):
    name = "ZTEST_E2E_ao_upload.txt"
    src = tmp_path / name
    src.write_text("ZTEST E2E upload into an access-only folder — safe to delete.\n", encoding="utf-8")
    tracked_before = _sections(rapi)["tracked"]
    _files(remote)
    page = remote.page
    inp = page.locator(f'xpath=//input[@type="file" and @data-dir="{AO}"]')
    expect(inp).to_have_count(1, timeout=20_000)
    remote.step(f"tap 📷 Upload on the access-only folder and choose {name}")
    with page.expect_response(lambda r: "/remote/upload" in r.url, timeout=60_000) as resp:
        inp.set_input_files(str(src))
    assert resp.value.status == 200, f"upload answered {resp.value.status}"
    body = resp.value.json()
    assert body.get("ok") and body.get("indexed") is False, f"should be saved, not indexed: {body}"
    expect(page.locator("#uploadStatus")).to_contain_text("not indexed", timeout=20_000)
    landed = AO_SANDBOX / name
    assert landed.exists() and landed.read_bytes() == src.read_bytes(), "the file on disk differs"
    secs = _sections(rapi)
    assert secs["tracked"] == tracked_before, "the upload added something to the indexed/tracked list"
    assert any(is_ao_sandbox(p) for p in secs["access_only"]), "the folder left the access-only list"


# ── AO-11 ────────────────────────────────────────────────────────────────────
def test_AO_11_view_a_file_in_access_only_folder(remote, rapi, ao_listed):
    _files(remote)
    page = remote.page
    _ao_files_row(page).locator(".dl-picker-btn").click()
    view = page.locator(f'xpath=//button[contains(@class,"dl-prev-btn") and @data-path="{AO}\\{SEED}"]')
    expect(view).to_be_visible(timeout=20_000)
    remote.step(f"tap 👁 View on {SEED}")
    view.click()
    expect(page.locator("#previewWrap")).to_be_visible()
    expect(page.locator("#previewBody")).to_contain_text("access-only folder test", timeout=20_000)
    page.wait_for_timeout(1200)
    page.locator("#previewWrap .preview-close").click()
    expect(page.locator("#previewWrap")).to_be_hidden()
