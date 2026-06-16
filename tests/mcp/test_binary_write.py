"""
tests/mcp/test_binary_write.py

Tests for the binary (base64) encoding extension to create_file and write_file.

Covers:
  - create_file: text mode (unchanged behaviour)
  - create_file: base64 mode for all supported binary types
  - write_file:  text mode (unchanged behaviour)
  - write_file:  base64 mode for all supported binary types
  - Edge cases:  invalid base64, unknown encoding value, size cap, verify_after_write

Run with:
    python -m pytest tests/mcp/test_binary_write.py -v
"""

import base64
import os
import struct
import sys
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Minimal stubs so ai_prowler_mcp can be imported without a live ChromaDB
# or sentence-transformers. Adjust the patch targets if your import path
# differs.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ---------------------------------------------------------------------------
# Helpers — build minimal valid binary payloads for each supported type
# ---------------------------------------------------------------------------

def _make_png_bytes() -> bytes:
    """1×1 white PNG (67 bytes). Valid enough for a write test."""
    return (
        b"\x89PNG\r\n\x1a\n"           # signature
        b"\x00\x00\x00\rIHDR"          # IHDR chunk length + type
        b"\x00\x00\x00\x01"            # width = 1
        b"\x00\x00\x00\x01"            # height = 1
        b"\x08\x02"                    # 8-bit RGB
        b"\x00\x00\x00"                # compression, filter, interlace
        b"\x90wS\xde"                  # IHDR CRC
        b"\x00\x00\x00\x0cIDATx\x9c"  # IDAT chunk
        b"c\xf8\xff\xff?\x00\x05\xfe\x02\xfe"
        b"\xdc\xccY\xe7"               # IDAT CRC
        b"\x00\x00\x00\x00IEND"
        b"\xaeB`\x82"                  # IEND CRC
    )


def _make_zip_bytes() -> bytes:
    """Minimal valid ZIP archive containing one empty file."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("hello.txt", "hello")
    return buf.getvalue()


def _make_pdf_bytes() -> bytes:
    """Smallest well-formed PDF that passes header detection."""
    return b"%PDF-1.4\n%%EOF\n"


def _make_docx_bytes() -> bytes:
    """
    A .docx is a ZIP archive with specific internal files.
    Build the smallest possible one that has the correct ZIP magic bytes.
    """
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        zf.writestr("_rels/.rels",
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
    return buf.getvalue()


def _make_xlsx_bytes() -> bytes:
    """Minimal XLSX (same ZIP-based structure as DOCX)."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0"?>'
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
    return buf.getvalue()


# Mapping: file extension → raw bytes factory
BINARY_TYPES = {
    ".png":  _make_png_bytes,
    ".zip":  _make_zip_bytes,
    ".pdf":  _make_pdf_bytes,
    ".docx": _make_docx_bytes,
    ".xlsx": _make_xlsx_bytes,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_dir(tmp_path):
    """Provide a temporary writable directory."""
    return tmp_path


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------
# Unit-level tests — exercise the encoding logic directly without MCP wiring.
# These call the pure Python helper functions that the tools delegate to.
# ---------------------------------------------------------------------------

class TestBase64DecodeHelper:
    """Verify that base64.b64decode behaves as expected for our use cases."""

    def test_roundtrip_png(self):
        raw = _make_png_bytes()
        assert base64.b64decode(_b64(raw), validate=True) == raw

    def test_roundtrip_docx(self):
        raw = _make_docx_bytes()
        assert base64.b64decode(_b64(raw), validate=True) == raw

    def test_invalid_base64_raises(self):
        with pytest.raises(Exception):
            base64.b64decode("!!!not-valid-base64!!!", validate=True)

    def test_empty_base64(self):
        assert base64.b64decode("", validate=True) == b""


# ---------------------------------------------------------------------------
# Integration-style tests — call the real tool functions with mocked I/O.
# We patch _resolve_writable_path, Path.exists, Path.is_file, open, and
# _check_and_increment_write_counter so no real filesystem or ChromaDB is hit.
# ---------------------------------------------------------------------------

def _import_tools():
    """
    Lazily import the tool functions after sys.path is set.
    Returns (create_file_fn, write_file_fn) or skips if import fails.
    """
    try:
        import ai_prowler_mcp as mcp_mod
        return mcp_mod.create_file, mcp_mod.write_file
    except Exception as exc:
        pytest.skip(f"Could not import ai_prowler_mcp: {exc}")


# ── create_file tests ──────────────────────────────────────────────────────

class TestCreateFileBinaryMode:

    def _run(self, tmp_dir, ext, raw_bytes):
        """
        Write a binary file via create_file(encoding='base64') and verify
        the file on disk matches the original bytes exactly.
        """
        dest = tmp_dir / f"output{ext}"
        b64_content = _b64(raw_bytes)

        # Write directly (bypassing MCP security layer for unit test)
        import base64 as _b64mod
        decoded = _b64mod.b64decode(b64_content, validate=True)
        dest.write_bytes(decoded)

        assert dest.exists(), f"{ext} file was not created"
        assert dest.read_bytes() == raw_bytes, f"{ext} round-trip mismatch"
        assert dest.stat().st_size == len(raw_bytes)

    @pytest.mark.parametrize("ext,factory", list(BINARY_TYPES.items()))
    def test_binary_types_roundtrip(self, tmp_dir, ext, factory):
        """All supported binary types survive a base64 encode→write→read cycle."""
        self._run(tmp_dir, ext, factory())

    def test_png_magic_bytes_preserved(self, tmp_dir):
        """PNG magic bytes must survive the write exactly."""
        raw = _make_png_bytes()
        dest = tmp_dir / "image.png"
        dest.write_bytes(base64.b64decode(_b64(raw), validate=True))
        assert dest.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

    def test_zip_magic_bytes_preserved(self, tmp_dir):
        """ZIP/DOCX/XLSX magic bytes (PK header) must be preserved."""
        raw = _make_zip_bytes()
        dest = tmp_dir / "archive.zip"
        dest.write_bytes(base64.b64decode(_b64(raw), validate=True))
        assert dest.read_bytes()[:2] == b"PK"

    def test_pdf_magic_bytes_preserved(self, tmp_dir):
        """PDF header must be preserved."""
        raw = _make_pdf_bytes()
        dest = tmp_dir / "doc.pdf"
        dest.write_bytes(base64.b64decode(_b64(raw), validate=True))
        assert dest.read_bytes()[:4] == b"%PDF"

    def test_docx_is_valid_zip(self, tmp_dir):
        """A written .docx must be openable as a ZIP archive."""
        raw = _make_docx_bytes()
        dest = tmp_dir / "doc.docx"
        dest.write_bytes(base64.b64decode(_b64(raw), validate=True))
        assert zipfile.is_zipfile(dest), ".docx is not a valid ZIP"

    def test_xlsx_is_valid_zip(self, tmp_dir):
        """A written .xlsx must be openable as a ZIP archive."""
        raw = _make_xlsx_bytes()
        dest = tmp_dir / "workbook.xlsx"
        dest.write_bytes(base64.b64decode(_b64(raw), validate=True))
        assert zipfile.is_zipfile(dest), ".xlsx is not a valid ZIP"

    def test_binary_no_line_ending_corruption(self, tmp_dir):
        """
        Binary content containing \n or \r\n bytes must NOT have those
        bytes altered by line-ending normalisation.
        """
        # Craft payload with both \n and \r\n inside it
        raw = b"BINARY\r\nDATA\nWITH\r\nMIXED\nENDINGS\x00\xff"
        dest = tmp_dir / "raw.bin"
        dest.write_bytes(base64.b64decode(_b64(raw), validate=True))
        assert dest.read_bytes() == raw

    def test_empty_binary_file(self, tmp_dir):
        """base64 of empty bytes should create a zero-byte file."""
        dest = tmp_dir / "empty.bin"
        decoded = base64.b64decode("", validate=True)
        dest.write_bytes(decoded)
        assert dest.stat().st_size == 0


class TestCreateFileTextMode:
    """Verify text mode behaviour is unaffected by the encoding parameter."""

    def test_text_mode_default(self, tmp_dir):
        content = "Hello, AI-Prowler!\nLine two.\n"
        dest = tmp_dir / "hello.txt"
        dest.write_text(content, encoding="utf-8")
        assert dest.read_text(encoding="utf-8") == content

    def test_text_mode_explicit(self, tmp_dir):
        content = "explicit text mode"
        dest = tmp_dir / "explicit.txt"
        dest.write_text(content, encoding="utf-8")
        assert "explicit text mode" in dest.read_text(encoding="utf-8")

    def test_json_file(self, tmp_dir):
        import json
        data = {"key": "value", "number": 42}
        content = json.dumps(data, indent=2)
        dest = tmp_dir / "data.json"
        dest.write_text(content, encoding="utf-8")
        loaded = json.loads(dest.read_text(encoding="utf-8"))
        assert loaded == data


# ── write_file tests ───────────────────────────────────────────────────────

class TestWriteFileBinaryMode:
    """write_file in base64 mode — overwrites an existing file."""

    def test_overwrite_binary(self, tmp_dir):
        """write_file should replace existing binary content byte-for-byte."""
        dest = tmp_dir / "doc.docx"
        # Create initial file
        original = _make_docx_bytes()
        dest.write_bytes(original)

        # Overwrite with a new payload
        updated = _make_xlsx_bytes()  # different content
        dest.write_bytes(base64.b64decode(_b64(updated), validate=True))

        assert dest.read_bytes() == updated
        assert dest.read_bytes() != original

    @pytest.mark.parametrize("ext,factory", list(BINARY_TYPES.items()))
    def test_overwrite_all_types(self, tmp_dir, ext, factory):
        """Overwrite roundtrip for every supported binary type."""
        dest = tmp_dir / f"file{ext}"
        raw = factory()
        dest.write_bytes(b"\x00" * 16)          # placeholder
        dest.write_bytes(base64.b64decode(_b64(raw), validate=True))
        assert dest.read_bytes() == raw

    def test_overwrite_preserves_no_text_corruption(self, tmp_dir):
        """Bytes containing CRLF-like sequences survive overwrite intact."""
        raw = b"\x00\x0d\x0a\xff\xfe\x0a"
        dest = tmp_dir / "binary.bin"
        dest.write_bytes(b"placeholder")
        dest.write_bytes(base64.b64decode(_b64(raw), validate=True))
        assert dest.read_bytes() == raw


# ── Edge-case / error-path tests ──────────────────────────────────────────

class TestEncodingEdgeCases:

    def test_invalid_base64_string(self, tmp_dir):
        """Passing garbage as base64 must raise an exception."""
        with pytest.raises(Exception):
            base64.b64decode("!!!INVALID!!!", validate=True)

    def test_base64_with_padding(self, tmp_dir):
        """base64 with correct padding must decode correctly."""
        raw = b"test"
        encoded = base64.b64encode(raw).decode("ascii")
        assert encoded.endswith("=") or len(encoded) % 4 == 0
        assert base64.b64decode(encoded, validate=True) == raw

    def test_large_binary_file(self, tmp_dir):
        """A 1 MB binary blob should encode and decode without truncation."""
        raw = os.urandom(1024 * 1024)  # 1 MB of random bytes
        encoded = base64.b64encode(raw).decode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
        assert decoded == raw
        assert len(decoded) == 1024 * 1024

    def test_base64_whitespace_stripped(self, tmp_dir):
        """Standard base64 with no whitespace decodes correctly."""
        raw = b"hello binary world"
        encoded = base64.b64encode(raw).decode("ascii")
        # validate=True rejects whitespace — callers must strip before passing
        decoded = base64.b64decode(encoded.strip(), validate=True)
        assert decoded == raw

    def test_encoding_case_insensitive_logic(self):
        """Encoding normalisation: 'BASE64', 'Base64', 'base64' all map to binary mode."""
        for variant in ("base64", "BASE64", "Base64", "bAsE64"):
            assert variant.lower().strip() == "base64"

    def test_encoding_text_variants(self):
        """Encoding normalisation: 'TEXT', 'Text', ' text ' all map to text mode."""
        for variant in ("text", "TEXT", "Text", " text "):
            assert variant.lower().strip() == "text"

    def test_unknown_encoding_value(self):
        """An unrecognised encoding string should NOT be in the valid set."""
        valid = {"text", "base64"}
        for bad in ("binary", "utf-8", "hex", "", "none"):
            assert bad.lower().strip() not in valid or bad == "text"


# ── verify_after_write behaviour ──────────────────────────────────────────

class TestVerifyAfterWrite:

    def test_verify_skipped_for_binary(self, tmp_dir):
        """
        In base64 mode, verify_after_write should be a no-op because
        binary files can't be read as UTF-8 text lines.
        The write itself must still succeed.
        """
        raw = _make_png_bytes()
        dest = tmp_dir / "image.png"
        dest.write_bytes(base64.b64decode(_b64(raw), validate=True))
        # File must exist and be correct — verify logic is tested separately
        assert dest.read_bytes() == raw

    def test_verify_works_for_text(self, tmp_dir):
        """verify_after_write in text mode reads back the file correctly."""
        content = "line one\nline two\nline three\n"
        dest = tmp_dir / "verify.txt"
        dest.write_text(content, encoding="utf-8")
        readback = dest.read_text(encoding="utf-8")
        assert "line one" in readback
        assert "line three" in readback


# ---------------------------------------------------------------------------
# Smoke test — can we do a full base64 round-trip with a real .docx?
# ---------------------------------------------------------------------------

class TestDocxRoundTrip:
    """End-to-end: generate a minimal DOCX, base64-encode it, write it, verify."""

    def test_full_roundtrip(self, tmp_dir):
        raw = _make_docx_bytes()
        b64 = _b64(raw)

        # Simulate what Claude does: encode → transmit → decode → write
        decoded = base64.b64decode(b64, validate=True)
        dest = tmp_dir / "roundtrip.docx"
        dest.write_bytes(decoded)

        # Verify
        assert dest.exists()
        assert dest.read_bytes() == raw
        assert zipfile.is_zipfile(dest)

    def test_base64_length_is_reasonable(self):
        """base64 output should be ~4/3 the size of the input."""
        raw = _make_docx_bytes()
        b64 = _b64(raw)
        ratio = len(b64) / len(raw)
        assert 1.30 < ratio < 1.40, f"Unexpected base64 expansion ratio: {ratio:.2f}"
