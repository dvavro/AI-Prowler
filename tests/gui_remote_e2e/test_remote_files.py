"""Remote PWA — Files: browse, 👁 View (RQ-08), ⬇ Get (REMOTE_PWA_E2E_TEST_SPEC.md §5.3, RF).

Browses the way a person does: Files → the tracked folder that contains the
sandbox → 📥 Download (folder picker) → Open → … → sandbox, then View / Get the
ZTEST seed files there. Read-only for the knowledge base; the only files
touched are ZTEST_E2E_* files inside tests\\gui_remote_e2e\\sandbox.

Run: run_tests_gui_jobs_e2e.bat --remote --human -k test_remote_files
"""
import base64
from pathlib import Path

import pytest
from playwright.sync_api import expect

from remote_safety import SANDBOX

SEED_TXT = "ZTEST_E2E_seed.txt"
SEED_PNG = "ZTEST_E2E_seed.png"
def _png_2x2() -> bytes:
    """A valid 2x2 red PNG, built with the standard library (correct CRCs)."""
    import struct, zlib

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * 2 for _ in range(2))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


PNG_BYTES = _png_2x2()


def _tracked_root(rapi) -> str:
    """The tracked folder (as the Files screen lists it) that contains the sandbox."""
    sb = str(SANDBOX).lower()
    roots = []
    for line in rapi.text("list_tracked_directories").splitlines():
        s = "".join(ch for ch in line if 32 <= ord(ch) < 127).strip()
        s = s.split(". ", 1)[-1].strip() if s[:1].isdigit() else s
        s = s.rstrip("\\")
        # the sandbox's own row (it is tracked by itself) or a folder containing it
        if ":\\" in s and (sb == s.lower() or sb.startswith(s.lower() + "\\")):
            roots.append(s)
    if not roots:
        pytest.skip("the sandbox isn't inside a tracked folder")
    return max(roots, key=len)


def _xp(cls: str, path: str) -> str:
    return f'xpath=//button[contains(@class,"{cls}") and @data-path="{path}"]'


def _browse_to_sandbox(remote, rapi):
    root = _tracked_root(rapi)
    remote.goto("files")
    remote.step(f"tap 📥 Download on {root}")
    picker = remote.page.locator(f'xpath=//button[contains(@class,"dl-picker-btn") and @data-dir="{root}"]')
    expect(picker).to_be_visible(timeout=20_000)
    picker.click()
    here = root
    for part in Path(str(SANDBOX)[len(root):].lstrip("\\")).parts:
        here = here + "\\" + part
        remote.step(f"tap Open → {part}")
        btn = remote.page.locator(_xp("dl-subdir-btn", here))
        expect(btn).to_be_visible(timeout=20_000)
        btn.click()
    expect(remote.page.locator(_xp("dl-btn", str(SANDBOX) + "\\" + SEED_TXT))).to_be_visible(timeout=20_000)
    return root


@pytest.fixture
def seeds():
    (SANDBOX / SEED_PNG).write_bytes(PNG_BYTES)
    yield
    (SANDBOX / SEED_PNG).unlink(missing_ok=True)


# ── RF-01: the Files screen lists the tracked folders ────────────────────────
def test_RF_01_files_lists_tracked_folders(remote, rapi):
    root = _tracked_root(rapi)
    screen = remote.goto("files")
    expect(screen.locator(".rs", has_text=root).first).to_be_visible(timeout=20_000)
    # Same rule as the app: writable only if the folder's own line carries [W]
    # (list_writable_directories lists the READ zone too, so "the path is in the
    # text" is true either way).
    writable = rapi.sandbox_writable() if root.lower() == str(SANDBOX).lower() else any(
        "[W]" in l and "".join(c for c in l if 32 <= ord(c) < 127).replace("[W]", "").strip().lower()
        == root.lower() for l in rapi.text("list_writable_directories").splitlines())
    row = screen.locator(".row", has=remote.page.locator(".rs", has_text=root)).first
    if writable:
        expect(row.get_by_text("Upload")).to_be_visible()
    else:
        expect(row.get_by_text("Read only")).to_be_visible()


# ── RF-02: browse into a folder and ← Back ───────────────────────────────────
@pytest.fixture
def subfolder():
    """A ZTEST folder inside the sandbox — since the sandbox moved to its own
    top-level folder (2026-09-29) there was nothing to browse into and back from."""
    import shutil
    sub = SANDBOX / "ZTEST_E2E_sub"
    sub.mkdir(exist_ok=True)
    (sub / "ZTEST_E2E_inside.txt").write_text("ZTEST E2E file inside a subfolder.\n", encoding="utf-8")
    yield sub
    shutil.rmtree(sub, ignore_errors=True)


def test_RF_02_browse_into_a_folder_and_back(remote, rapi, subfolder):
    _browse_to_sandbox(remote, rapi)
    remote.step(f"tap Open → {subfolder.name}")
    remote.page.locator(_xp("dl-subdir-btn", str(subfolder))).click()
    expect(remote.page.locator(_xp("dl-btn", str(subfolder / "ZTEST_E2E_inside.txt")))).to_be_visible(timeout=20_000)
    remote.step("tap ← Back")
    remote.page.locator(".dl-back-btn").first.click()
    expect(remote.page.locator(_xp("dl-btn", str(SANDBOX) + "\\" + SEED_TXT))).to_be_visible(timeout=20_000)


# ── RF-03: 👁 View a text file, then ✕ ────────────────────────────────────────
def test_RF_03_view_a_text_file_and_close(remote, rapi):
    _browse_to_sandbox(remote, rapi)
    remote.step(f"tap 👁 View on {SEED_TXT}")
    remote.page.locator(_xp("dl-prev-btn", str(SANDBOX) + "\\" + SEED_TXT)).click()
    wrap = remote.page.locator("#previewWrap")
    expect(wrap).to_be_visible()
    expect(remote.page.locator("#previewName")).to_have_text(SEED_TXT)
    expect(remote.page.locator("#previewBody")).to_contain_text("zqxremoteseed", timeout=20_000)
    remote.page.wait_for_timeout(1200)
    remote.step("tap ✕")
    remote.page.locator("#previewWrap .preview-close").click()
    expect(wrap).to_be_hidden()


# ── RF-08: 👁 View an image (RM-R-002: loads with the token in a header) ─────
def test_RF_08_view_an_image(remote, rapi, seeds):
    urls = []
    remote.page.on("request", lambda r: urls.append(r.url) if "/remote/download" in r.url else None)
    _browse_to_sandbox(remote, rapi)
    remote.step(f"tap 👁 View on {SEED_PNG}")
    remote.page.locator(_xp("dl-prev-btn", str(SANDBOX) + "\\" + SEED_PNG)).click()
    img = remote.page.locator("#previewBody img")
    expect(img).to_be_visible(timeout=20_000)
    assert img.evaluate("i => i.complete && i.naturalWidth") == 2, "the image didn't load"
    assert urls and all("token=" not in u for u in urls), "the image request put the token in the URL"
    remote.page.wait_for_timeout(1200)
    remote.page.locator("#previewWrap .preview-close").click()
    expect(remote.page.locator("#previewWrap")).to_be_hidden()


def test_RF_09_view_button_only_on_previewable_files(remote, rapi, seeds):
    (SANDBOX / "ZTEST_E2E_blob.bin").write_bytes(b"\x00\x01")
    try:
        _browse_to_sandbox(remote, rapi)
        for name in (SEED_TXT, SEED_PNG):
            expect(remote.page.locator(_xp("dl-prev-btn", str(SANDBOX) + "\\" + name))).to_be_visible()
        expect(remote.page.locator(_xp("dl-prev-btn", str(SANDBOX) + "\\ZTEST_E2E_blob.bin"))).to_have_count(0)
    finally:
        (SANDBOX / "ZTEST_E2E_blob.bin").unlink(missing_ok=True)


# ── RF-04: ⬇ Get downloads the exact bytes ───────────────────────────────────
def test_RF_04_get_downloads_the_exact_file(remote, rapi, tmp_path):
    _browse_to_sandbox(remote, rapi)
    remote.step(f"tap ⬇ Get on {SEED_TXT}")
    with remote.page.expect_download(timeout=30_000) as dl:
        remote.page.locator(_xp("dl-btn", str(SANDBOX) + "\\" + SEED_TXT)).click()
    out = tmp_path / "got.txt"
    dl.value.save_as(out)
    assert out.read_bytes() == (SANDBOX / SEED_TXT).read_bytes(), "downloaded bytes differ from the file"
