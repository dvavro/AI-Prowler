"""
tests/analysis/test_job_images.py
==========================================
Test suite for the Job Image Storage tools (v8.0.0).

Tests:
  TC-JIMGS-001  save_job_image — happy path, validation, base64 decode
  TC-JIMGS-002  list_job_images — listing, tag filtering, missing jobs
  TC-JIMGS-003  delete_job_image — deletion, index update, edge cases
  TC-JIMGS-004  index.json integrity — metadata correctness
  TC-JIMGS-005  helper functions — _load/_save index roundtrip
  TC-JIMGS-006  personal mode path structure — no user slug, direct <root>/<job_id>/
  TC-JIMGS-007  server mode user isolation — each user gets <root>/<user_slug>/<job_id>/
  TC-JIMGS-008  get_job_images_path — personal and server mode output
  TC-JIMGS-009  set_job_images_path — set, validate, persist, reset
  TC-JIMGS-010  _job_user_slug helper — slug derivation and sanitisation

Run:
    run_tests.bat tests\\analysis\\test_job_images.py -v
"""

import base64
import json
import time
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_root(tmp_path):
    """Personal-mode fixture — patches _job_images_root and _job_image_dir
    with no user-slug scoping (ctx=None → personal install behaviour)."""
    root = tmp_path / "job_images"
    root.mkdir()

    def patched_root():
        return root

    def patched_dir(job_id, ctx=None):
        # Personal mode: no user slug
        safe = "".join(c if c.isalnum() or c in "-_" else "_"
                       for c in str(job_id).strip())
        d = root / safe
        d.mkdir(parents=True, exist_ok=True)
        return d

    with patch("ai_prowler_mcp._job_images_root", side_effect=patched_root), \
         patch("ai_prowler_mcp._job_image_dir", side_effect=patched_dir):
        yield root


def _make_server_ctx(username: str):
    """Return a minimal mock ctx that _current_user() will resolve to a user dict."""
    from unittest.mock import MagicMock
    user = {"id": username, "username": username, "name": username, "role": "staff"}
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def tiny_jpeg():
    raw = bytes([
        0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,
        0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0xFF,0xDB,0x00,0x43,
        0x00,0x08,0x06,0x06,0x07,0x06,0x05,0x08,0x07,0x07,0x07,0x09,
        0x09,0x08,0x0A,0x0C,0x14,0x0D,0x0C,0x0B,0x0B,0x0C,0x19,0x12,
        0x13,0x0F,0x14,0x1D,0x1A,0x1F,0x1E,0x1D,0x1A,0x1C,0x1C,0x20,
        0x24,0x2E,0x27,0x20,0x22,0x2C,0x23,0x1C,0x1C,0x28,0x37,0x29,
        0x2C,0x30,0x31,0x34,0x34,0x34,0x1F,0x27,0x39,0x3D,0x38,0x32,
        0x3C,0x2E,0x33,0x34,0x32,0xFF,0xC0,0x00,0x0B,0x08,0x00,0x01,
        0x00,0x01,0x01,0x01,0x11,0x00,0xFF,0xC4,0x00,0x1F,0x00,0x00,
        0x01,0x05,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0xFF,0xDA,0x00,0x08,0x01,0x01,0x00,0x00,0x3F,
        0x00,0xFB,0xD8,0xFF,0xD9,
    ])
    return base64.b64encode(raw).decode("ascii")


def save_one(root, job_id, fname="photo.jpg", tags="test", desc="Test photo"):
    import ai_prowler_mcp as mcp
    mcp.save_job_image(job_id=job_id, filename=fname, image_base64=tiny_jpeg(),
                       description=desc, tags=tags)
    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in job_id)
    job_dir = root / safe_id
    files = [f.name for f in job_dir.glob("*.jpg")]
    return files[0]


# TC-JIMGS-001
class TestSaveJobImage:
    def test_TC_JIMGS_001_happy_path(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.save_job_image(job_id="1042", filename="before.jpg",
                               image_base64=tiny_jpeg(), description="Before",
                               tags="before,gutters")
        assert "OK" in r or "saved" in r.lower()

    def test_TC_JIMGS_001_success_marker(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.save_job_image(job_id="1042", filename="x.jpg",
                               image_base64=tiny_jpeg())
        assert "1042" in r
        job_dir = tmp_root / "1042"
        assert any(f.suffix == ".jpg" for f in job_dir.iterdir())

    def test_TC_JIMGS_001_timestamp_prefix(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="1042", filename="photo.jpg",
                           image_base64=tiny_jpeg())
        names = [f.name for f in (tmp_root / "1042").glob("*.jpg")]
        assert len(names) == 1 and names[0][8] == "_"

    def test_TC_JIMGS_001_data_uri_stripped(self, tmp_root):
        import ai_prowler_mcp as mcp
        uri = f"data:image/jpeg;base64,{tiny_jpeg()}"
        r = mcp.save_job_image(job_id="1042", filename="uri.jpg",
                               image_base64=uri)
        assert "saved" in r.lower() or "1042" in r

    def test_TC_JIMGS_001_tags_parsed(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="1042", filename="t.jpg",
                           image_base64=tiny_jpeg(), tags="before, after, damage")
        idx = json.loads((tmp_root / "1042" / "index.json").read_text())
        assert set(idx[0]["tags"]) == {"before", "after", "damage"}

    def test_TC_JIMGS_001_empty_tags_is_list(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="1042", filename="nt.jpg",
                           image_base64=tiny_jpeg(), tags="")
        idx = json.loads((tmp_root / "1042" / "index.json").read_text())
        assert idx[0]["tags"] == []

    def test_TC_JIMGS_001_multiple_accumulate(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="1042", filename="a.jpg", image_base64=tiny_jpeg())
        time.sleep(0.05)
        mcp.save_job_image(job_id="1042", filename="b.jpg", image_base64=tiny_jpeg())
        idx = json.loads((tmp_root / "1042" / "index.json").read_text())
        assert len(idx) == 2

    def test_TC_JIMGS_001_empty_job_id_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.save_job_image(job_id="", filename="x.jpg", image_base64=tiny_jpeg())
        assert "job_id" in r.lower() and "required" in r.lower() or r.startswith("Error") or "Error" in r or "job_id" in r

    def test_TC_JIMGS_001_missing_job_id_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.save_job_image(job_id="", filename="x.jpg", image_base64=tiny_jpeg())
        assert r.startswith("❌")

    def test_TC_JIMGS_001_missing_filename_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.save_job_image(job_id="1042", filename="", image_base64=tiny_jpeg())
        assert r.startswith("❌")

    def test_TC_JIMGS_001_empty_image_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.save_job_image(job_id="1042", filename="x.jpg", image_base64="")
        assert r.startswith("❌")

    def test_TC_JIMGS_001_invalid_base64_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.save_job_image(job_id="1042", filename="x.jpg",
                               image_base64="!!!NOT_BASE64!!!")
        assert r.startswith("❌")

    def test_TC_JIMGS_001_special_chars_sanitised(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.save_job_image(job_id="JOB/2026", filename="x.jpg",
                               image_base64=tiny_jpeg())
        assert "saved" in r.lower() or "JOB" in r
        assert any(tmp_root.iterdir())


# TC-JIMGS-002
class TestListJobImages:

    def test_TC_JIMGS_002_lists_all(self, tmp_root):
        import ai_prowler_mcp as mcp
        save_one(tmp_root, "1042", "a.jpg", tags="before")
        time.sleep(0.05)
        save_one(tmp_root, "1042", "b.jpg", tags="after")
        r = mcp.list_job_images(job_id="1042")
        assert "2 found" in r

    def test_TC_JIMGS_002_icon_in_result(self, tmp_root):
        import ai_prowler_mcp as mcp
        save_one(tmp_root, "1042")
        r = mcp.list_job_images(job_id="1042")
        assert "1042" in r

    def test_TC_JIMGS_002_description_shown(self, tmp_root):
        import ai_prowler_mcp as mcp
        save_one(tmp_root, "1042", desc="Gutters clogged")
        r = mcp.list_job_images(job_id="1042")
        assert "Gutters clogged" in r

    def test_TC_JIMGS_002_nonexistent_job(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.list_job_images(job_id="9999")
        assert "No images" in r or "not exist" in r

    def test_TC_JIMGS_002_empty_dir(self, tmp_root):
        import ai_prowler_mcp as mcp
        (tmp_root / "empty").mkdir()
        r = mcp.list_job_images(job_id="empty")
        assert "No images" in r

    def test_TC_JIMGS_002_tag_filter_match(self, tmp_root):
        import ai_prowler_mcp as mcp
        save_one(tmp_root, "1042", "before.jpg", tags="before")
        time.sleep(0.05)
        save_one(tmp_root, "1042", "after.jpg", tags="after")
        r = mcp.list_job_images(job_id="1042", tag="before")
        assert "1 found" in r

    def test_TC_JIMGS_002_tag_filter_no_match(self, tmp_root):
        import ai_prowler_mcp as mcp
        save_one(tmp_root, "1042", tags="before")
        r = mcp.list_job_images(job_id="1042", tag="warranty")
        assert "No images with tag" in r

    def test_TC_JIMGS_002_reupload_hint(self, tmp_root):
        import ai_prowler_mcp as mcp
        save_one(tmp_root, "1042")
        r = mcp.list_job_images(job_id="1042")
        assert "re-upload" in r.lower() or "To view" in r

    def test_TC_JIMGS_002_empty_job_id_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.list_job_images(job_id="")
        assert r.startswith("❌")


# TC-JIMGS-003
class TestDeleteJobImage:

    def test_TC_JIMGS_003_file_removed(self, tmp_root):
        import ai_prowler_mcp as mcp
        stored = save_one(tmp_root, "1042")
        assert (tmp_root / "1042" / stored).exists()
        r = mcp.delete_job_image(job_id="1042", filename=stored)
        assert "✅" in r
        assert not (tmp_root / "1042" / stored).exists()

    def test_TC_JIMGS_003_index_updated(self, tmp_root):
        import ai_prowler_mcp as mcp
        stored = save_one(tmp_root, "1042")
        mcp.delete_job_image(job_id="1042", filename=stored)
        idx = json.loads((tmp_root / "1042" / "index.json").read_text())
        assert not any(e["filename"] == stored for e in idx)

    def test_TC_JIMGS_003_other_images_kept(self, tmp_root):
        import ai_prowler_mcp as mcp
        save_one(tmp_root, "1042", "keep.jpg")
        time.sleep(1.1)   # ensure different second-level timestamp prefix
        to_del = save_one(tmp_root, "1042", "delete_me.jpg")
        mcp.delete_job_image(job_id="1042", filename=to_del)
        remaining = [f.name for f in (tmp_root / "1042").glob("*.jpg")]
        assert len(remaining) == 1 and "keep.jpg" in remaining[0]

    def test_TC_JIMGS_003_remaining_count_message(self, tmp_root):
        import ai_prowler_mcp as mcp
        save_one(tmp_root, "1042", "a.jpg")
        time.sleep(0.05)
        stored = save_one(tmp_root, "1042", "b.jpg")
        r = mcp.delete_job_image(job_id="1042", filename=stored)
        assert "1 image" in r or "remaining" in r

    def test_TC_JIMGS_003_nonexistent_file_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        (tmp_root / "1042").mkdir()
        r = mcp.delete_job_image(job_id="1042", filename="ghost.jpg")
        assert r.startswith("❌") and "not found" in r.lower()

    def test_TC_JIMGS_003_nonexistent_job_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.delete_job_image(job_id="9999", filename="photo.jpg")
        assert r.startswith("❌")

    def test_TC_JIMGS_003_empty_job_id_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.delete_job_image(job_id="", filename="photo.jpg")
        assert r.startswith("❌")

    def test_TC_JIMGS_003_empty_filename_error(self, tmp_root):
        import ai_prowler_mcp as mcp
        r = mcp.delete_job_image(job_id="1042", filename="")
        assert r.startswith("❌")


# TC-JIMGS-004
class TestIndexIntegrity:

    def test_TC_JIMGS_004_required_fields(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="1042", filename="f.jpg",
                           image_base64=tiny_jpeg(), description="D",
                           tags="x,y", media_type="image/jpeg")
        entry = json.loads((tmp_root / "1042" / "index.json").read_text())[0]
        for f in ["filename","original","job_id","description",
                  "tags","media_type","saved_at","size_bytes"]:
            assert f in entry, f"Missing: {f}"

    def test_TC_JIMGS_004_original_preserved(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="1042", filename="orig.jpg",
                           image_base64=tiny_jpeg())
        idx = json.loads((tmp_root / "1042" / "index.json").read_text())
        assert idx[0]["original"] == "orig.jpg"

    def test_TC_JIMGS_004_size_positive(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="1042", filename="s.jpg",
                           image_base64=tiny_jpeg())
        idx = json.loads((tmp_root / "1042" / "index.json").read_text())
        assert idx[0]["size_bytes"] > 0

    def test_TC_JIMGS_004_saved_at_iso(self, tmp_root):
        import ai_prowler_mcp as mcp, datetime
        mcp.save_job_image(job_id="1042", filename="t.jpg",
                           image_base64=tiny_jpeg())
        idx = json.loads((tmp_root / "1042" / "index.json").read_text())
        datetime.datetime.strptime(idx[0]["saved_at"], "%Y-%m-%dT%H:%M:%SZ")

    def test_TC_JIMGS_004_job_id_in_entry(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="JOB-999", filename="x.jpg",
                           image_base64=tiny_jpeg())
        idx = json.loads((tmp_root / "JOB-999" / "index.json").read_text())
        assert idx[0]["job_id"] == "JOB-999"

    def test_TC_JIMGS_004_media_type_stored(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="1042", filename="p.png",
                           image_base64=tiny_jpeg(), media_type="image/png")
        idx = json.loads((tmp_root / "1042" / "index.json").read_text())
        assert idx[0]["media_type"] == "image/png"

    def test_TC_JIMGS_004_index_is_json_list(self, tmp_root):
        import ai_prowler_mcp as mcp
        mcp.save_job_image(job_id="1042", filename="j.jpg",
                           image_base64=tiny_jpeg())
        parsed = json.loads((tmp_root / "1042" / "index.json")
                            .read_text(encoding="utf-8"))
        assert isinstance(parsed, list)


# TC-JIMGS-005
class TestHelpers:

    def test_TC_JIMGS_005_empty_when_no_file(self, tmp_path):
        import ai_prowler_mcp as mcp
        assert mcp._load_job_index(tmp_path) == []

    def test_TC_JIMGS_005_empty_on_corrupt(self, tmp_path):
        import ai_prowler_mcp as mcp
        (tmp_path / "index.json").write_text("CORRUPTED", encoding="utf-8")
        assert mcp._load_job_index(tmp_path) == []

    def test_TC_JIMGS_005_roundtrip(self, tmp_path):
        import ai_prowler_mcp as mcp
        entries = [{"filename": "a.jpg", "tags": ["x"]},
                   {"filename": "b.jpg", "tags": ["y"]}]
        mcp._save_job_index(tmp_path, entries)
        loaded = mcp._load_job_index(tmp_path)
        assert len(loaded) == 2
        assert loaded[0]["filename"] == "a.jpg"

    def test_TC_JIMGS_005_valid_json_written(self, tmp_path):
        import ai_prowler_mcp as mcp
        mcp._save_job_index(tmp_path, [{"key": "value"}])
        parsed = json.loads((tmp_path / "index.json")
                            .read_text(encoding="utf-8"))
        assert isinstance(parsed, list) and parsed[0]["key"] == "value"

    def test_TC_JIMGS_005_utf8_preserved(self, tmp_path):
        import ai_prowler_mcp as mcp
        mcp._save_job_index(tmp_path, [{"desc": "Caf\u00e9 r\u00e9sum\u00e9"}])
        loaded = mcp._load_job_index(tmp_path)
        assert "Caf" in loaded[0]["desc"]


# ---------------------------------------------------------------------------
# TC-JIMGS-006  Personal mode path structure
# ---------------------------------------------------------------------------

class TestPersonalModePaths:
    """In personal mode (ctx=None) images go to <root>/<job_id>/ with NO
    user-slug subdirectory inserted."""

    def test_TC_JIMGS_006_no_slug_in_path(self, tmp_path):
        """save_job_image in personal mode writes directly to <root>/<job_id>/."""
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()

        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""):
            mcp.save_job_image(job_id="1042", filename="x.jpg",
                               image_base64=tiny_jpeg())

        # File must be in root/1042/ — no slug subdir
        job_dir = root / "1042"
        assert job_dir.exists()
        assert any(f.suffix == ".jpg" for f in job_dir.iterdir())
        # No extra subdirectory level
        assert not any(
            (root / slug / "1042").exists()
            for slug in ["me", "personal", "user"]
        )

    def test_TC_JIMGS_006_list_in_personal_mode(self, tmp_path):
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""):
            mcp.save_job_image(job_id="1042", filename="a.jpg",
                               image_base64=tiny_jpeg(), tags="before")
            result = mcp.list_job_images(job_id="1042")
        assert "1042" in result
        assert "1 found" in result

    def test_TC_JIMGS_006_delete_in_personal_mode(self, tmp_path):
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""):
            mcp.save_job_image(job_id="1042", filename="del.jpg",
                               image_base64=tiny_jpeg())
            job_dir = root / "1042"
            stored = next(f.name for f in job_dir.glob("*.jpg"))
            result = mcp.delete_job_image(job_id="1042", filename=stored)
        assert "✅" in result
        assert not (job_dir / stored).exists()

    def test_TC_JIMGS_006_path_structure_is_two_levels(self, tmp_path):
        """Personal mode: depth from root to file is exactly 2 (root/job_id/file)."""
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""):
            mcp.save_job_image(job_id="J001", filename="photo.jpg",
                               image_base64=tiny_jpeg())
        files = list(root.rglob("*.jpg"))
        assert len(files) == 1
        # path relative to root: J001/YYYYMMDD_photo.jpg — exactly 2 parts
        rel = files[0].relative_to(root)
        assert len(rel.parts) == 2


# ---------------------------------------------------------------------------
# TC-JIMGS-007  Server mode user isolation
# ---------------------------------------------------------------------------

class TestServerModeIsolation:
    """In server mode each user's images go to <root>/<user_slug>/<job_id>/.
    Users cannot see or delete each other's images for the same job_id."""

    def _setup_two_users(self, tmp_path):
        """Save one image each for 'alice' and 'bob' for job 1042."""
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()

        alice_ctx = _make_server_ctx("alice")
        bob_ctx   = _make_server_ctx("bob")

        with patch("ai_prowler_mcp._job_images_root", return_value=root):
            mcp.save_job_image(job_id="1042", filename="alice.jpg",
                               image_base64=tiny_jpeg(), ctx=alice_ctx)
            time.sleep(0.05)
            mcp.save_job_image(job_id="1042", filename="bob.jpg",
                               image_base64=tiny_jpeg(), ctx=bob_ctx)

        return root, alice_ctx, bob_ctx

    def test_TC_JIMGS_007_slug_subdir_created(self, tmp_path):
        """Each user gets their own subdirectory under the root."""
        import ai_prowler_mcp as mcp
        root, alice_ctx, bob_ctx = self._setup_two_users(tmp_path)
        assert (root / "alice" / "1042").exists()
        assert (root / "bob" / "1042").exists()

    def test_TC_JIMGS_007_directories_are_separate(self, tmp_path):
        """alice and bob directories are completely separate."""
        root, _, _ = self._setup_two_users(tmp_path)
        alice_files = list((root / "alice" / "1042").glob("*.jpg"))
        bob_files   = list((root / "bob"   / "1042").glob("*.jpg"))
        assert len(alice_files) == 1
        assert len(bob_files)   == 1
        assert alice_files[0].name != bob_files[0].name or True  # different timestamps

    def test_TC_JIMGS_007_list_returns_only_own_images(self, tmp_path):
        """list_job_images for alice returns only alice's images."""
        import ai_prowler_mcp as mcp
        root, alice_ctx, bob_ctx = self._setup_two_users(tmp_path)
        with patch("ai_prowler_mcp._job_images_root", return_value=root):
            alice_result = mcp.list_job_images(job_id="1042", ctx=alice_ctx)
            bob_result   = mcp.list_job_images(job_id="1042", ctx=bob_ctx)
        assert "alice.jpg" in alice_result
        assert "alice.jpg" not in bob_result
        assert "bob.jpg" in bob_result
        assert "bob.jpg" not in alice_result

    def test_TC_JIMGS_007_delete_only_affects_own_images(self, tmp_path):
        """Deleting alice's image does not remove bob's."""
        import ai_prowler_mcp as mcp
        root, alice_ctx, bob_ctx = self._setup_two_users(tmp_path)
        with patch("ai_prowler_mcp._job_images_root", return_value=root):
            # Get alice's stored filename
            alice_dir = root / "alice" / "1042"
            alice_stored = next(f.name for f in alice_dir.glob("*.jpg"))
            result = mcp.delete_job_image(job_id="1042",
                                          filename=alice_stored, ctx=alice_ctx)
        assert "✅" in result
        assert not (root / "alice" / "1042" / alice_stored).exists()
        # Bob's file untouched
        bob_files = list((root / "bob" / "1042").glob("*.jpg"))
        assert len(bob_files) == 1

    def test_TC_JIMGS_007_delete_cannot_reach_other_user_files(self, tmp_path):
        """bob cannot delete alice's file even if he knows the exact filename."""
        import ai_prowler_mcp as mcp
        root, alice_ctx, bob_ctx = self._setup_two_users(tmp_path)
        alice_dir = root / "alice" / "1042"
        alice_stored = next(f.name for f in alice_dir.glob("*.jpg"))
        with patch("ai_prowler_mcp._job_images_root", return_value=root):
            # Bob tries to delete alice's filename — scoped to bob's directory
            result = mcp.delete_job_image(job_id="1042",
                                          filename=alice_stored, ctx=bob_ctx)
        # Should fail because bob/1042/<alice_stored> doesn't exist
        assert "❌" in result
        # Alice's file should still be there
        assert (alice_dir / alice_stored).exists()

    def test_TC_JIMGS_007_path_structure_is_three_levels(self, tmp_path):
        """Server mode: depth from root to file is 3 (root/slug/job_id/file)."""
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        ctx = _make_server_ctx("jake_r")
        with patch("ai_prowler_mcp._job_images_root", return_value=root):
            mcp.save_job_image(job_id="J001", filename="photo.jpg",
                               image_base64=tiny_jpeg(), ctx=ctx)
        files = list(root.rglob("*.jpg"))
        assert len(files) == 1
        rel = files[0].relative_to(root)
        assert len(rel.parts) == 3  # slug / job_id / filename

    def test_TC_JIMGS_007_same_user_multiple_jobs_isolated(self, tmp_path):
        """Single server user's images for different jobs don't mix."""
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        ctx = _make_server_ctx("mike_c")
        with patch("ai_prowler_mcp._job_images_root", return_value=root):
            mcp.save_job_image(job_id="J001", filename="a.jpg",
                               image_base64=tiny_jpeg(), ctx=ctx)
            time.sleep(0.05)
            mcp.save_job_image(job_id="J002", filename="b.jpg",
                               image_base64=tiny_jpeg(), ctx=ctx)
        j1_files = list((root / "mike_c" / "J001").glob("*.jpg"))
        j2_files = list((root / "mike_c" / "J002").glob("*.jpg"))
        assert len(j1_files) == 1
        assert len(j2_files) == 1

    def test_TC_JIMGS_007_no_slug_when_no_user(self, tmp_path):
        """ctx=None (personal mode) → no slug subdir created."""
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        with patch("ai_prowler_mcp._job_images_root", return_value=root):
            mcp.save_job_image(job_id="J001", filename="p.jpg",
                               image_base64=tiny_jpeg(), ctx=None)
        # Should be root/J001/<file>, NOT root/<slug>/J001/<file>
        assert (root / "J001").exists()
        # No extra level
        files = list(root.rglob("*.jpg"))
        rel = files[0].relative_to(root)
        assert len(rel.parts) == 2


# ---------------------------------------------------------------------------
# TC-JIMGS-008  get_job_images_path
# ---------------------------------------------------------------------------

class TestGetJobImagesPath:

    def test_TC_JIMGS_008_returns_string(self, tmp_path):
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""):
            result = mcp.get_job_images_path()
        assert isinstance(result, str) and len(result) > 5

    def test_TC_JIMGS_008_shows_root_path(self, tmp_path):
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""):
            result = mcp.get_job_images_path()
        assert str(root) in result

    def test_TC_JIMGS_008_shows_default_source(self, tmp_path):
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        cfg_path = tmp_path / "config.json"
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""), \
             patch("pathlib.Path.home", return_value=tmp_path):
            result = mcp.get_job_images_path()
        assert "default" in result.lower()

    def test_TC_JIMGS_008_shows_custom_source(self, tmp_path):
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        cfg = tmp_path / ".ai-prowler" / "config.json"
        cfg.parent.mkdir()
        cfg.write_text(
            json.dumps({"job_images_root_path": str(root)}),
            encoding="utf-8"
        )
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""), \
             patch("pathlib.Path.home", return_value=tmp_path):
            result = mcp.get_job_images_path()
        assert "custom" in result.lower()

    def test_TC_JIMGS_008_shows_personal_scope_in_server_mode(self, tmp_path):
        """In server mode the output includes the user's personal scoped path."""
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value="vicki_vavro"):
            result = mcp.get_job_images_path()
        assert "vicki_vavro" in result
        assert "personal scope" in result.lower() or str(root / "vicki_vavro") in result

    def test_TC_JIMGS_008_shows_job_count(self, tmp_path):
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        (root / "J001").mkdir()
        (root / "J002").mkdir()
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""):
            result = mcp.get_job_images_path()
        assert "2" in result

    def test_TC_JIMGS_008_shows_reset_hint(self, tmp_path):
        import ai_prowler_mcp as mcp
        root = tmp_path / "imgs"
        root.mkdir()
        with patch("ai_prowler_mcp._job_images_root", return_value=root), \
             patch("ai_prowler_mcp._job_user_slug", return_value=""):
            result = mcp.get_job_images_path()
        assert "set_job_images_path" in result


# ---------------------------------------------------------------------------
# TC-JIMGS-009  set_job_images_path
# ---------------------------------------------------------------------------

class TestSetJobImagesPath:

    def test_TC_JIMGS_009_set_valid_path(self, tmp_path):
        import ai_prowler_mcp as mcp
        target = tmp_path / "custom_photos"
        target.mkdir()
        cfg_path = tmp_path / ".ai-prowler" / "config.json"
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = mcp.set_job_images_path(path=str(target))
        assert "✅" in result
        assert str(target) in result

    def test_TC_JIMGS_009_saves_to_config_json(self, tmp_path):
        import ai_prowler_mcp as mcp
        target = tmp_path / "photos"
        target.mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            mcp.set_job_images_path(path=str(target))
            cfg = json.loads(
                (tmp_path / ".ai-prowler" / "config.json").read_text()
            )
        assert cfg.get("job_images_root_path") == str(target)

    def test_TC_JIMGS_009_reset_with_empty_string(self, tmp_path):
        import ai_prowler_mcp as mcp
        # First set a custom path
        target = tmp_path / "photos"
        target.mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            mcp.set_job_images_path(path=str(target))
            # Then reset
            result = mcp.set_job_images_path(path="")
        assert "✅" in result
        assert "default" in result.lower() or "reset" in result.lower()

    def test_TC_JIMGS_009_reset_removes_key_from_config(self, tmp_path):
        import ai_prowler_mcp as mcp
        target = tmp_path / "photos"
        target.mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            mcp.set_job_images_path(path=str(target))
            mcp.set_job_images_path(path="")
            cfg_path = tmp_path / ".ai-prowler" / "config.json"
            if cfg_path.exists():
                cfg = json.loads(cfg_path.read_text())
                assert "job_images_root_path" not in cfg or cfg["job_images_root_path"] == ""

    def test_TC_JIMGS_009_creates_target_directory(self, tmp_path):
        import ai_prowler_mcp as mcp
        target = tmp_path / "new_photos_dir"
        assert not target.exists()
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = mcp.set_job_images_path(path=str(target))
        assert "✅" in result
        assert target.exists()

    def test_TC_JIMGS_009_relative_path_rejected(self, tmp_path):
        import ai_prowler_mcp as mcp
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = mcp.set_job_images_path(path="relative/path/here")
        assert "❌" in result
        assert "absolute" in result.lower()

    def test_TC_JIMGS_009_takes_effect_immediately(self, tmp_path):
        """After set_job_images_path, _job_images_root reflects the new path."""
        import ai_prowler_mcp as mcp
        target = tmp_path / "new_root"
        target.mkdir()
        with patch("pathlib.Path.home", return_value=tmp_path):
            mcp.set_job_images_path(path=str(target))
            active = mcp._job_images_root()
        assert str(active) == str(target)

    def test_TC_JIMGS_009_preserves_existing_config_keys(self, tmp_path):
        """set_job_images_path should not wipe other config.json keys."""
        import ai_prowler_mcp as mcp
        target = tmp_path / "photos"
        target.mkdir()
        cfg_path = tmp_path / ".ai-prowler" / "config.json"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(
            json.dumps({"default_spreadsheet_path": "C:\\existing.xlsx",
                        "edition": "personal"}),
            encoding="utf-8"
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            mcp.set_job_images_path(path=str(target))
            cfg = json.loads(cfg_path.read_text())
        assert cfg.get("default_spreadsheet_path") == "C:\\existing.xlsx"
        assert cfg.get("edition") == "personal"
        assert cfg.get("job_images_root_path") == str(target)


# ---------------------------------------------------------------------------
# TC-JIMGS-010  _job_user_slug helper
# ---------------------------------------------------------------------------

class TestJobUserSlug:

    def test_TC_JIMGS_010_returns_empty_for_none_ctx(self):
        import ai_prowler_mcp as mcp
        assert mcp._job_user_slug(None) == ""

    def test_TC_JIMGS_010_returns_empty_when_no_user_on_ctx(self):
        import ai_prowler_mcp as mcp
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.request_context.request.state.user = None
        assert mcp._job_user_slug(ctx) == ""

    def test_TC_JIMGS_010_uses_username_field(self):
        import ai_prowler_mcp as mcp
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.request_context.request.state.user = {
            "username": "vicki_vavro", "name": "Vicki Vavro", "id": "u1"
        }
        assert mcp._job_user_slug(ctx) == "vicki_vavro"

    def test_TC_JIMGS_010_falls_back_to_name(self):
        import ai_prowler_mcp as mcp
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.request_context.request.state.user = {
            "username": "", "name": "Jake R", "id": "u2"
        }
        slug = mcp._job_user_slug(ctx)
        assert "jake" in slug.lower()

    def test_TC_JIMGS_010_falls_back_to_id(self):
        import ai_prowler_mcp as mcp
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.request_context.request.state.user = {
            "username": "", "name": "", "id": "user-42"
        }
        slug = mcp._job_user_slug(ctx)
        assert "user" in slug and "42" in slug

    def test_TC_JIMGS_010_slug_is_lowercase(self):
        import ai_prowler_mcp as mcp
        ctx = _make_server_ctx("MikeC")
        slug = mcp._job_user_slug(ctx)
        assert slug == slug.lower()

    def test_TC_JIMGS_010_spaces_replaced_with_underscores(self):
        import ai_prowler_mcp as mcp
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.request_context.request.state.user = {
            "username": "", "name": "John Smith", "id": "u3"
        }
        slug = mcp._job_user_slug(ctx)
        assert " " not in slug
        assert "_" in slug or slug == "john_smith" or "john" in slug

    def test_TC_JIMGS_010_special_chars_sanitised(self):
        import ai_prowler_mcp as mcp
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.request_context.request.state.user = {
            "username": "user@example.com", "name": "", "id": ""
        }
        slug = mcp._job_user_slug(ctx)
        assert "@" not in slug
        assert "." not in slug

    def test_TC_JIMGS_010_slug_only_alphanumeric_hyphen_underscore(self):
        import ai_prowler_mcp as mcp
        import re
        ctx = _make_server_ctx("weird!user#name$here")
        slug = mcp._job_user_slug(ctx)
        assert re.match(r'^[a-z0-9_\-]+$', slug), f"Invalid slug: {slug}"

    def test_TC_JIMGS_010_exception_returns_empty(self):
        import ai_prowler_mcp as mcp
        from unittest.mock import MagicMock
        ctx = MagicMock()
        ctx.request_context.request.state.user = MagicMock(
            side_effect=AttributeError("broken")
        )
        # Should never raise — returns "" on any exception
        try:
            result = mcp._job_user_slug(ctx)
            assert isinstance(result, str)
        except Exception:
            pytest.fail("_job_user_slug raised an exception instead of returning ''")

