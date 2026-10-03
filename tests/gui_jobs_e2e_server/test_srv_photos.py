"""Server mode — photo uploads (spec §6.11.5 SRV-SCOPE-12, plus the server
side of R-028 / R-029).

The Jobs app has no photo DELETE — only upload — so "deletes a photo" in the
spec has nothing to test. Straight HTTP to /photos/upload, the same JSON body
the app sends. Test jobs are owner-made ZTEST jobs (J-A Samual's, J-B Vicki's).

Cleanup: an accepted upload writes a real file into the server's
JobPhotos\\<job> folder. The server's reply says which folder; if that folder is
on this machine the test deletes exactly the files it uploaded (and the folder
if it's then empty). If it isn't reachable from here, it's logged as a leftover.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_photos
"""
import base64
import json
import logging
import os
import uuid
from pathlib import Path

import pytest

from api import http

log = logging.getLogger("e2e_srv")

CREW = "Samual Cronin"
OTHER = "Vicki Vavro"
LEFTOVERS: list[str] = []

# The server runs as its own Windows account, so its JobPhotos folder is under
# THAT profile. An upload the server ACCEPTS writes a real file there, into a
# folder named by job number — and job numbers are reused after a delete
# (G-11), so a leftover would show up on a future real job. Accepted-upload
# tests therefore only run when this machine can reach that folder to clean
# up; refusal tests always run (they write nothing). Found 2026-09-27: the
# first run left 8 small ZTEST files in JOB-0001 / JOB-0002.
SERVER_JOBPHOTOS = Path(os.environ.get("E2E_SERVER_JOBPHOTOS")
                        or r"C:\Users\AI-Prowler-Server\Documents\AI-Prowler\JobPhotos")
CAN_CLEAN = SERVER_JOBPHOTOS.is_dir() and os.access(SERVER_JOBPHOTOS, os.W_OK)
needs_cleanup_access = pytest.mark.skipif(
    not CAN_CLEAN, reason=f"can't reach the server's photo folder ({SERVER_JOBPHOTOS}) to remove an "
                          "accepted upload — set E2E_SERVER_JOBPHOTOS or grant this account access")


def _upload(srv, token, job_id, name="ztest_photo.txt", data=b"ZTEST E2E photo"):
    st, raw = http("POST", srv["origin"] + "/photos/upload", token=token, timeout=60, body={
        "job_id": job_id, "notes": "ZTEST E2E",
        "photos": [{"filename": name, "data": base64.b64encode(data).decode()}]})
    try:
        d = json.loads(raw)
    except ValueError:
        d = {"raw": raw[:200]}
    return st, d


def _remove_uploaded(d):
    """Delete exactly the files the server said it saved; then the folder if empty."""
    folder = Path(d.get("dir", ""))
    if not d.get("dir") or not folder.is_dir():
        if d.get("files"):
            LEFTOVERS.append(f"{d.get('dir')} {d.get('files')}")
            log.info(f"[SRV-PHOTOS] can't reach {d.get('dir')!r} from here — leftover: {d.get('files')}")
        return
    for f in d.get("files", []):
        p = folder / f
        if p.is_file():
            p.unlink()
    if folder.is_dir() and not any(folder.iterdir()):
        folder.rmdir()
    log.info(f"[SRV-PHOTOS] removed uploaded {d.get('files')} from {folder}")


@pytest.fixture
def jobs(clean_slate, data):
    return {"mine": data.job("PHOTO mine", **{"Crew / Technician": CREW}),
            "theirs": data.job("PHOTO theirs", "brannon", **{"Crew / Technician": OTHER})}


@pytest.fixture
def photos_root():
    """The server's JobPhotos folder (never learned by uploading — see CAN_CLEAN).
    Folder checks against it are only meaningful when CAN_CLEAN is true."""
    return SERVER_JOBPHOTOS


def _no_files_in(folder: Path) -> bool:
    return not CAN_CLEAN or not folder.exists() or not any(folder.iterdir())


# ── SRV-SCOPE-12: field crew uploads only to their own jobs ──────────────────
def test_SRV_SCOPE_12_crew_cannot_upload_to_another_crews_job(srv, jobs, photos_root):
    st, d = _upload(srv, srv["users"]["U3"].access_token, jobs["theirs"])
    log.info(f"[SRV-SCOPE-12] Samual -> Vicki's job: HTTP {st} {str(d.get('error', ''))[:120]}")
    assert st >= 400 and d.get("ok") is False, f"Samual uploaded to Vicki's job: {st} {d}"
    assert "not assigned to you" in str(d.get("error", "")), d
    folder = photos_root / jobs["theirs"]
    assert _no_files_in(folder), f"a file was written for Vicki's job: {folder}"


@needs_cleanup_access
def test_SRV_SCOPE_12_crew_can_upload_to_own_job(srv, jobs):
    st, d = _upload(srv, srv["users"]["U3"].access_token, jobs["mine"])
    try:
        assert st == 200 and d.get("ok") and d.get("saved") == 1, f"Samual can't upload to his own job: {st} {d}"
        assert Path(d["dir"]).name == jobs["mine"], f"saved under the wrong job folder: {d['dir']}"
    finally:
        if d.get("ok"):
            _remove_uploaded(d)


@needs_cleanup_access
@pytest.mark.parametrize("key", ["U1", "U2"])
def test_SRV_SCOPE_12_owner_and_manager_can_upload_to_any_crews_job(srv, jobs, key):
    st, d = _upload(srv, srv["users"][key].access_token, jobs["theirs"])
    try:
        assert st == 200 and d.get("ok"), f"{key} can't upload to Vicki's job: {st} {d}"
    finally:
        if d.get("ok"):
            _remove_uploaded(d)


# ── R-028 / R-029 on the server: bad or made-up job numbers ──────────────────
# As the owner (unrestricted), so it's the folder check — not the crew
# check — that has to stop these.
@pytest.mark.parametrize("bad_id", ["../ZTEST_E2E_escape_{t}", "..\\ZTEST_E2E_escape_{t}",
                                    "JOB-0001/../../ZTEST_E2E_escape_{t}"])
def test_SRV_PH_08_job_number_cannot_escape_the_photos_folder(srv, photos_root, bad_id):
    t = uuid.uuid4().hex[:8]
    bad = bad_id.format(t=t)
    outside = photos_root.parent / f"ZTEST_E2E_escape_{t}"
    try:
        st, d = _upload(srv, srv["owner"].access_token, bad)
        assert not (CAN_CLEAN and outside.exists()), f"upload with job number {bad!r} wrote OUTSIDE JobPhotos: {outside}"
        assert st >= 400 and d.get("ok") is False, f"job number {bad!r} was accepted: {st} {d}"
    finally:
        if outside.exists():
            import shutil
            shutil.rmtree(outside, ignore_errors=True)


def test_SRV_PH_09_upload_for_a_job_that_does_not_exist_is_refused(srv, photos_root):
    fake = f"JOB-ZT{uuid.uuid4().hex[:6].upper()}"
    st, d = _upload(srv, srv["owner"].access_token, fake)
    try:
        assert st >= 400 and d.get("ok") is False, f"upload for non-existent {fake} accepted: {st} {d}"
        assert not (CAN_CLEAN and (photos_root / fake).exists()), f"a folder was created for non-existent {fake}"
    finally:
        if d.get("ok"):
            _remove_uploaded(d)


def test_SRV_PHOTOS_zz_no_leftovers():
    """Runs last in this file: anything we couldn't clean up is a failure to report."""
    assert not LEFTOVERS, f"uploaded test files left on the server: {LEFTOVERS}"
