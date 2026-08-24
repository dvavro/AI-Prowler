"""
tests/gui/test_pwa_file_upload_and_icon.py
=============================================
Structural tests for two small Jobs PWA fixes made alongside the
server-mode auth work:

  1. Browser-tab favicon (pwa/index.html was missing <link rel="icon">
     entirely — apple-touch-icon existed for the iOS home-screen icon,
     but nothing controlled the actual browser tab icon, so it fell back
     to the generic globe).

  2. File upload widened beyond images-only, plus a real backend bug this
     exposed: unknown file extensions (PDFs, docs, anything not in the
     small image extension map) were being silently renamed to .jpg while
     keeping their original non-JPEG bytes. Fixed in BOTH the server-mode
     and personal-mode /photos/upload handlers.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
PWA_FILE = SRC_ROOT / "jobs" / "index.html"
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"


@pytest.fixture(scope="module")
def pwa_source():
    return PWA_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def mcp_source():
    return MCP_FILE.read_text(encoding="utf-8")


class TestFaviconFixed:
    def test_icon_link_present(self, pwa_source):
        assert 'rel="icon"' in pwa_source

    def test_icon_link_points_at_real_asset(self, pwa_source):
        idx = pwa_source.index('rel="icon"')
        nearby = pwa_source[idx:idx + 100]
        # Icon served under /jobs/ route (disk folder renamed from pwa/ to jobs/)
        assert "/jobs/icon-192.png" in nearby

    def test_apple_touch_icon_still_present(self, pwa_source):
        """Regression guard — this was already correct (matches the
        working /remote/ PWA's pattern) and must not be accidentally
        removed while adding the missing tab-icon tag."""
        assert 'rel="apple-touch-icon"' in pwa_source

    def test_matches_working_remote_pwa_pattern(self, pwa_source):
        """The fix was deliberately copied from remote/index.html's
        already-working icon setup rather than invented from scratch —
        confirm both tags use the same asset naming convention."""
        icon_idx = pwa_source.index('rel="icon"')
        touch_idx = pwa_source.index('rel="apple-touch-icon"')
        icon_line = pwa_source[icon_idx:icon_idx + 100]
        touch_line = pwa_source[touch_idx:touch_idx + 100]
        assert "icon-192.png" in icon_line
        assert "icon-192.png" in touch_line


class TestNonImageThumbnailFallback:
    """renderGrid() previously always rendered <img src="dataUrl">, which
    breaks for non-image files now that the picker accepts them."""

    def test_render_grid_checks_file_type(self, pwa_source):
        idx = pwa_source.index("function renderGrid()")
        nearby = pwa_source[idx:idx + 500]
        assert "startsWith('image/')" in nearby

    def test_render_grid_has_non_image_fallback(self, pwa_source):
        idx = pwa_source.index("function renderGrid()")
        nearby = pwa_source[idx:idx + 500]
        assert "photo-thumb-file" in nearby

    def test_fallback_css_class_defined(self, pwa_source):
        assert ".photo-thumb-file" in pwa_source


class TestExtensionPreservationBugFixed:
    """The real bug: _ext_map4.get(_orig_ext4, ".jpg") forced every
    unrecognized extension to .jpg — a PDF would be saved with a .jpg
    extension while still containing PDF bytes. Fixed in both the
    server-mode and personal-mode handlers by falling back to the file's
    OWN extension instead of a hardcoded one."""

    def test_no_bare_jpg_fallback_remains_anywhere(self, mcp_source):
        """The old buggy pattern must not exist anywhere in the file —
        catches a fix applied to only one of the two handlers."""
        assert '_ext_map4.get(_orig_ext4, ".jpg")' not in mcp_source

    def test_both_handlers_use_original_extension_fallback(self, mcp_source):
        occurrences = mcp_source.count('_ext_map4.get(_orig_ext4, _orig_ext4 or ".jpg")')
        assert occurrences == 2, (
            f"Expected the fixed extension-fallback pattern in exactly 2 "
            f"places (server-mode and personal-mode photo upload handlers), "
            f"found {occurrences}. If a handler was added or removed, this "
            f"count needs updating alongside it."
        )

    def test_known_image_extensions_still_normalized(self, mcp_source):
        """Regression guard — .jpeg still normalizes to .jpg, etc.
        Only UNKNOWN extensions changed behavior."""
        idx = mcp_source.index('_ext_map4 = {')
        nearby = mcp_source[idx:idx + 300]
        assert '".jpeg": ".jpg"' in nearby
        assert '".heic": ".jpg"' in nearby


class TestOriginalFilenamePreserved:
    """Uploaded files were being renamed to a bare timestamp+index (e.g.
    "20260817_143022_1.jpg"), discarding the original filename entirely —
    fine for anonymous camera captures, but confusing for a real document
    like "invoice_march.pdf". Fixed to keep the sanitized original name
    alongside the timestamp+index prefix (which is still needed for
    uniqueness and chronological sorting)."""

    def test_no_bare_timestamp_index_naming_remains(self, mcp_source):
        """The old pattern (timestamp_index+ext, nothing else) must not
        exist anywhere — catches a fix applied to only one handler."""
        assert 'f"{_ts4}_{_idx4}{_ext4}"' not in mcp_source

    def test_both_handlers_preserve_sanitized_original_name(self, mcp_source):
        occurrences = mcp_source.count('f"{_ts4}_{_idx4}_{_safe_stem4}{_ext4}"')
        assert occurrences == 2, (
            f"Expected the filename-preserving pattern in exactly 2 places "
            f"(server-mode and personal-mode handlers), found {occurrences}."
        )

    def test_filename_sanitization_strips_dangerous_characters(self, mcp_source):
        """Must not pass the original filename through unsanitized — path
        separators or other unexpected characters in a user-supplied
        filename could otherwise cause problems."""
        assert "re.sub(r'[^A-Za-z0-9 _.-]'" in mcp_source

    def test_sanitized_name_has_length_cap(self, mcp_source):
        """An absurdly long original filename shouldn't be able to break
        the filesystem's path length limit."""
        idx = mcp_source.index("_safe_stem4 = ")
        nearby = mcp_source[idx:idx + 150]
        assert "[:80]" in nearby


class TestTwoSeparateUploadButtons:
    """Single combined 'take a photo or choose a file' control replaced
    with two distinct buttons — Add Photos (camera-biased) and Add Files
    (general file/document picker) — per explicit user request."""

    def test_two_separate_file_inputs_exist(self, pwa_source):
        assert 'id="fileInputCamera"' in pwa_source
        assert 'id="fileInputFiles"' in pwa_source

    def test_camera_input_keeps_image_and_capture_hints(self, pwa_source):
        idx = pwa_source.index('id="fileInputCamera"')
        nearby = pwa_source[idx - 50:idx + 150]
        assert 'accept="image/*"' in nearby
        assert 'capture="environment"' in nearby

    def test_files_input_has_no_type_restriction(self, pwa_source):
        """The whole point of the second button — must accept any file
        type, not just images, so documents (PDFs etc.) are pickable."""
        idx = pwa_source.index('id="fileInputFiles"')
        nearby = pwa_source[idx - 50:idx + 150]
        assert 'accept="image/*"' not in nearby
        assert 'capture="environment"' not in nearby

    def test_both_buttons_route_to_shared_handler(self, pwa_source):
        """Both pickers must funnel into the same handleFiles() so the
        rest of the flow (thumbnails, notes, upload) is unchanged."""
        cam_input_idx = pwa_source.index('id="fileInputCamera"')
        files_input_idx = pwa_source.index('id="fileInputFiles"')
        assert 'onchange="handleFiles(this.files)"' in pwa_source[cam_input_idx:cam_input_idx + 200]
        assert 'onchange="handleFiles(this.files)"' in pwa_source[files_input_idx:files_input_idx + 200]

    def test_add_photos_and_add_files_labels_present(self, pwa_source):
        assert "Add Photos" in pwa_source
        assert "Add Files" in pwa_source


class TestJobModalAlsoHasTwoButtons:
    """The two-button split (Add Photos / Add Files) was originally only
    applied to the standalone Photos tab — the SEPARATE 'Add Photos'
    button inside the job-detail popup (tapping a job from the list) was
    missed and still had the old single-button behavior."""

    def test_go_photos_accepts_a_picker_argument(self, pwa_source):
        idx = pwa_source.index("function goPhotos(id")
        nearby = pwa_source[idx:idx + 700]
        assert "picker" in nearby
        assert "fileInputCamera" in nearby
        assert "fileInputFiles" in nearby

    def test_job_modal_has_two_photo_buttons_not_one(self, pwa_source):
        idx = pwa_source.index("quickClock")  # unique to the job-detail modal template
        nearby = pwa_source[idx:idx + 700]
        assert "goPhotos('${j.id}','camera')" in nearby
        assert "goPhotos('${j.id}','files')" in nearby

    def test_job_modal_buttons_labeled_photos_and_files(self, pwa_source):
        idx = pwa_source.index("goPhotos('${j.id}','camera')")
        nearby = pwa_source[idx:idx + 300]
        assert "Add Photos" in nearby
        assert "Add Files" in nearby
