"""R-028 / R-029 (2026-09-26, found by the Jobs-app E2E suite PH-08/PH-09):
/photos/upload built its save folder straight from the job number sent by the
browser, so '..\\Desktop' or 'JOB-1/../../x' wrote files OUTSIDE JobPhotos,
and a made-up job number was accepted. Both upload handlers now use
_job_photo_dir() and _safe_upload_ext(). Pure-function tests — nothing is
written to disk."""
import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def db(tmp_path):
    p = tmp_path / "jobs.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE jobs (job_id TEXT)")
    c.execute("INSERT INTO jobs VALUES ('JOB-0007')")
    c.commit()
    c.close()
    return str(p)


PHOTOS_ROOT = Path.home() / "Documents" / "AI-Prowler" / "JobPhotos"


@pytest.mark.parametrize("bad", ["..", "../x", "..\\x", "JOB-1/../../x", "a/b", "a\\b", "C:x",
                                 "x:stream", "", "   ", ".hidden", "JOB 1", "J" * 65])
def test_R_028_unsafe_job_numbers_are_refused(mcp_mod, db, bad):
    folder, err = mcp_mod._job_photo_dir(bad, db)
    assert folder is None and err, f"{bad!r} was accepted -> {folder}"


def test_R_028_an_existing_job_gets_its_own_folder_inside_JobPhotos(mcp_mod, db):
    folder, err = mcp_mod._job_photo_dir("JOB-0007", db)
    assert err is None
    assert folder == PHOTOS_ROOT / "JOB-0007"
    assert mcp_mod._path_is_inside(folder, PHOTOS_ROOT)


def test_R_029_a_job_that_does_not_exist_is_refused(mcp_mod, db):
    folder, err = mcp_mod._job_photo_dir("JOB-9999", db)
    assert folder is None and "No job JOB-9999" in err


def test_nothing_is_created_on_disk(mcp_mod, db):
    before = PHOTOS_ROOT.exists() and set(PHOTOS_ROOT.iterdir())
    mcp_mod._job_photo_dir("JOB-0007", db)
    mcp_mod._job_photo_dir("../escape", db)
    after = PHOTOS_ROOT.exists() and set(PHOTOS_ROOT.iterdir())
    assert before == after


EXT_MAP = {".jpg": ".jpg", ".jpeg": ".jpg", ".png": ".png", ".gif": ".gif", ".webp": ".webp", ".heic": ".jpg"}


@pytest.mark.parametrize("name, ext", [
    ("a.JPEG", ".jpg"), ("b.heic", ".jpg"), ("c.png", ".png"),
    ("quote.pdf", ".pdf"), ("gate code.txt", ".txt"), ("m.CSV", ".csv"),
    ("camera_capture", ".jpg"),                 # no extension (some phone cameras) -> .jpg, as before
    ("x.txt:hidden", ".txthidden"),             # no NTFS alternate data stream
    ("x.t/x", ".jpg"), ("x.@@", ".bin"),
])
def test_saved_extension_is_safe(mcp_mod, name, ext):
    assert mcp_mod._safe_upload_ext(name, EXT_MAP) == ext
