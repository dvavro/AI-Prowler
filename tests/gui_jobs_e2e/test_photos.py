"""Photos screen — photos AND other files (spec §6.8), personal mode.

The screen has two pickers that feed ONE upload: 📷 Add Photos (camera /
photo library, images only) and 📎 Add Files (any file). Files are "picked"
with Playwright's set_input_files on the real hidden <input type=file> — the
same thing the phone's picker hands the page — then the real Upload button
sends them. Every upload is checked on screen AND on disk (byte for byte) in
<home>/Documents/AI-Prowler/JobPhotos/<JobID>/.

Uploads are not /pwa-api calls, so the write guard doesn't see them: each
test deletes exactly the files it created (and a job folder only if that
leaves it empty — job numbers get reused, a real job's photos are never touched).

PH-08/09 call the upload URL directly (as a script could) to check the server
refuses a job number that would write outside JobPhotos, or a job that
doesn't exist.

Run: run_tests_gui_jobs_e2e.bat --human -k test_photos
"""
import base64
import json
import re
import shutil
import uuid
from pathlib import Path

import pytest
from playwright.sync_api import expect

from api import http, local_api_origin

AI_ROOT = Path.home() / "Documents" / "AI-Prowler"
PHOTOS_ROOT = AI_ROOT / "JobPhotos"
TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


# ── helpers ──────────────────────────────────────────────────────────────────
def _files_in(jid):
    d = PHOTOS_ROOT / jid
    return {p.name for p in d.iterdir()} if d.is_dir() else set()


@pytest.fixture
def disk(request):
    """Remembers what was in each job folder before the test; afterwards
    deletes only files that weren't there, and the folder if it's then empty."""
    before = {}

    def watch(jid):
        before[jid] = _files_in(jid)
        return jid

    yield watch
    for jid, had in before.items():
        d = PHOTOS_ROOT / jid
        for name in _files_in(jid) - had:
            (d / name).unlink(missing_ok=True)
        if d.is_dir() and not any(d.iterdir()):
            d.rmdir()


def _new_files(jid, had):
    return sorted(_files_in(jid) - had)


def _photos_screen(app, page, jid):
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("photos")
    app.log(f"PHOTOS choose {jid}")
    page.locator("#photoJobSelect").select_option(jid)


def _pick(app, page, which, files):
    """which: 'camera' (📷 Add Photos) or 'files' (📎 Add Files).
    files: list of (name, mime, bytes)."""
    app.log(f"PHOTOS pick {[f[0] for f in files]} with {which}")
    inp = page.locator("#fileInputCamera" if which == "camera" else "#fileInputFiles")
    inp.set_input_files([{"name": n, "mimeType": m, "buffer": b} for n, m, b in files])


def _upload(app, page, expect_saved):
    app.log("PHOTOS tap ⬆ Upload")
    with page.expect_response(lambda r: "/photos/upload" in r.url, timeout=60_000):
        page.locator("#uploadBtn").click()
    expect(page.locator("#uploadStatus")).to_have_text(f"✓ {expect_saved} photo(s) saved to AI-Prowler")


# ── PH-01: a photo ───────────────────────────────────────────────────────────
def test_PH_01_upload_a_photo(clean_slate, app, page, data, disk):
    jid = disk(data.job("PH01"))
    had = _files_in(jid)
    _photos_screen(app, page, jid)
    expect(page.locator("#uploadBtn")).to_be_disabled()
    _pick(app, page, "camera", [("gutter.png", "image/png", TINY_PNG)])
    expect(page.locator("#photoGrid .photo-thumb img")).to_have_count(1)
    expect(page.locator("#photoCount")).to_have_text("1 / 10")
    expect(page.locator("#uploadBtn")).to_be_enabled()
    _upload(app, page, 1)
    expect(page.locator("#photoGrid .photo-thumb")).to_have_count(0)      # cleared after upload
    new = _new_files(jid, had)
    assert len(new) == 1 and new[0].endswith("gutter.png"), new
    assert (PHOTOS_ROOT / jid / new[0]).read_bytes() == TINY_PNG


# ── PH-02: other files keep their type and content ───────────────────────────
def test_PH_02_upload_other_files(clean_slate, app, page, data, disk):
    jid = disk(data.job("PH02"))
    had = _files_in(jid)
    files = [("quote-signed.pdf", "application/pdf", PDF),
             ("gate code.txt", "text/plain", b"Gate code 4321\r\n"),
             ("measurements.csv", "text/csv", b"window,width,height\nfront,36,48\n")]
    _photos_screen(app, page, jid)
    _pick(app, page, "files", files)
    thumbs = page.locator("#photoGrid .photo-thumb-file")
    expect(thumbs).to_have_count(3)                    # 📄 + name, not an image preview
    expect(thumbs.nth(0)).to_contain_text("quote-signed.pdf")
    _upload(app, page, 3)
    new = _new_files(jid, had)
    assert len(new) == 3, new
    for name, _mime, content in files:
        stem, ext = name.rsplit(".", 1)
        match = [n for n in new if n.endswith("." + ext)]
        assert match, f"{name}: saved with a different extension — {new}"
        assert (PHOTOS_ROOT / jid / match[0]).read_bytes() == content, f"{name}: content changed"


# ── PH-03: photos and files together, remove one before uploading ────────────
def test_PH_03_mixed_upload_and_remove_one(clean_slate, app, page, data, disk):
    jid = disk(data.job("PH03"))
    had = _files_in(jid)
    _photos_screen(app, page, jid)
    _pick(app, page, "camera", [("before.png", "image/png", TINY_PNG), ("oops.png", "image/png", TINY_PNG)])
    _pick(app, page, "files", [("notes.txt", "text/plain", b"north side first")])
    expect(page.locator("#photoCount")).to_have_text("3 / 10")
    app.log("PHOTOS remove the 2nd photo (✕)")
    page.locator("#photoGrid .photo-thumb").nth(1).locator(".remove-btn").click()
    expect(page.locator("#photoCount")).to_have_text("2 / 10")
    page.locator("#photoNotes").fill("Front windows, before cleaning")
    _upload(app, page, 2)
    new = _new_files(jid, had)
    assert len(new) == 2 and not any("oops" in n for n in new), new
    expect(page.locator("#photoNotes")).to_have_value("")


# ── PH-04: at most 10 per upload ─────────────────────────────────────────────
def test_PH_04_at_most_ten(clean_slate, app, page, data, disk):
    jid = disk(data.job("PH04"))
    _photos_screen(app, page, jid)
    _pick(app, page, "files", [(f"f{i:02}.txt", "text/plain", f"file {i}".encode()) for i in range(12)])
    expect(page.locator("#photoCount")).to_have_text("10 / 10")
    expect(page.locator("#photoGrid .photo-thumb")).to_have_count(10)


# ── PH-05: Upload needs a job AND a file ─────────────────────────────────────
def test_PH_05_upload_needs_job_and_file(clean_slate, app, page, data):
    jid = data.job("PH05")
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("photos")
    btn = page.locator("#uploadBtn")
    expect(btn).to_be_disabled()
    _pick(app, page, "files", [("a.txt", "text/plain", b"a")])
    expect(btn).to_be_disabled()                        # no job chosen yet
    page.locator("#photoJobSelect").select_option(jid)
    expect(btn).to_be_enabled()
    page.locator("#photoGrid .photo-thumb .remove-btn").first.click()
    expect(btn).to_be_disabled()                        # nothing left to send


# ── PH-06: 📎 Add Files from a job opens Photos with that job chosen ─────────
def test_PH_06_add_files_from_job_detail(clean_slate, app, page, data):
    jid = data.job("PH06")
    page.evaluate("async () => { await loadJobs(); }")
    app.goto("jobs")
    page.locator(f"[data-testid='job-card'][data-jobid='{jid}']").click()
    expect(page.locator("#jobModal")).to_have_class(re.compile(r"\bopen\b"))
    app.log("DETAIL tap 📎 Add Files (the file picker it opens is cancelled)")
    page.on("filechooser", lambda fc: None)
    page.locator("#jobModal").get_by_role("button", name=re.compile("Add Files")).click()
    expect(page.locator("#screen-photos")).to_have_class(re.compile(r"\bactive\b"))
    expect(page.locator("#photoJobSelect")).to_have_value(jid)
    expect(page.get_by_test_id("nav-photos")).to_have_class(re.compile(r"\bactive\b"))


# ── PH-07: a file name is shown as text ──────────────────────────────────────
def test_PH_07_file_name_is_shown_as_text(clean_slate, app, page, data):
    jid = data.job("PH07")
    _photos_screen(app, page, jid)
    name = '<img src=x onerror="window.__e2e_ph_xss=1">.txt'
    _pick(app, page, "files", [(name, "text/plain", b"x")])
    expect(page.locator("#photoGrid .photo-thumb-file")).to_contain_text(name)
    page.wait_for_timeout(500)
    assert page.evaluate("() => window.__e2e_ph_xss") is None


# ── PH-08: the server never writes outside JobPhotos ─────────────────────────
@pytest.mark.parametrize("bad_id", ["../ZTEST_E2E_escape_{t}", "..\\ZTEST_E2E_escape_{t}",
                                    "JOB-0001/../../ZTEST_E2E_escape_{t}"])
def test_PH_08_job_number_cannot_escape_the_photos_folder(token, bad_id):
    t = uuid.uuid4().hex[:8]
    bad = bad_id.format(t=t)
    target = AI_ROOT / f"ZTEST_E2E_escape_{t}"
    side = PHOTOS_ROOT / "JOB-0001"                  # the 3rd case may create it on the way
    side_existed = side.exists()
    try:
        status, body = http("POST", local_api_origin() + "/photos/upload", token=token, body={
            "job_id": bad, "notes": "",
            "photos": [{"filename": "x.txt", "data": base64.b64encode(b"escape").decode()}]})
        assert not target.exists(), f"upload with job_id {bad!r} wrote OUTSIDE JobPhotos: {target}"
        try:
            ok = json.loads(body).get("ok")
        except ValueError:
            ok = None
        assert status >= 400 and ok is False, f"upload with job_id {bad!r} was accepted: {status} {body[:200]}"
    finally:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        if not side_existed and side.is_dir() and not any(side.iterdir()):
            side.rmdir()


# ── PH-09: a job that doesn't exist is refused ───────────────────────────────
def test_PH_09_upload_for_a_job_that_does_not_exist_is_refused(token):
    fake = f"JOB-ZT{uuid.uuid4().hex[:6].upper()}"
    try:
        status, body = http("POST", local_api_origin() + "/photos/upload", token=token, body={
            "job_id": fake, "notes": "",
            "photos": [{"filename": "x.txt", "data": base64.b64encode(b"x").decode()}]})
        assert not (PHOTOS_ROOT / fake).exists(), f"a folder was created for non-existent {fake}"
        assert status >= 400 and json.loads(body).get("ok") is False, f"{status} {body[:200]}"
    finally:
        shutil.rmtree(PHOTOS_ROOT / fake, ignore_errors=True)
