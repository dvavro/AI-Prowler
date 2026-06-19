"""
Unit tests — Phone-image indexing (IMG-EXT-* of the test plan)

Covers the V8.0.0 addition of WebP and HEIC/HEIF support to load_image_ocr()
and the supporting changes in SUPPORTED_EXTENSIONS / SKIP_EXTENSIONS / load_file().

All tests mock PIL.Image.open() and pytesseract so this suite runs without
Tesseract installed and without real image files on disk.

Test IDs
--------
  IMG_01  JPEG file is dispatched to load_image_ocr by load_file
  IMG_02  WebP is now in SUPPORTED_EXTENSIONS (not SKIP_EXTENSIONS)
  IMG_03  WebP is dispatched to load_image_ocr by load_file
  IMG_04  HEIC is in SUPPORTED_EXTENSIONS
  IMG_05  HEIF is in SUPPORTED_EXTENSIONS
  IMG_06  HEIC dispatched to load_image_ocr when pillow-heif is available
  IMG_07  HEIC returns empty string + warning when pillow-heif is missing
  IMG_08  Non-RGB image is converted to RGB before OCR (HEIC mode-conversion)
  IMG_09  load_image_ocr error is non-fatal (returns empty string)
  IMG_10  WebP is no longer in SKIP_EXTENSIONS
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(scope="module")
def rag_module():
    import rag_preprocessor
    return rag_preprocessor


# ===========================================================================
# IMG_01 — JPEG dispatches to load_image_ocr via load_file
# ===========================================================================
def test_IMG_01_jpeg_dispatched_to_load_image_ocr(rag_module, tmp_path):
    """load_file('.jpg') must call load_image_ocr and return its OCR text."""
    fake_img   = MagicMock()
    fake_img.mode = 'RGB'

    with patch("PIL.Image.open", return_value=fake_img), \
         patch("pytesseract.image_to_string", return_value="Receipt total $42.00"):

        jpeg = tmp_path / "receipt.jpg"
        jpeg.write_bytes(b"fake")
        result = rag_module.load_file(str(jpeg))

    assert result is not None, "JPEG must be indexed"
    assert "Receipt total $42.00" in result["content"]
    assert result["extension"] == ".jpg"


# ===========================================================================
# IMG_02 — WebP is in SUPPORTED_EXTENSIONS
# ===========================================================================
def test_IMG_02_webp_in_supported_extensions(rag_module):
    """.webp must appear in SUPPORTED_EXTENSIONS so scan_directory classifies
    it as to_index rather than unsupported."""
    assert ".webp" in rag_module.SUPPORTED_EXTENSIONS, (
        ".webp missing from SUPPORTED_EXTENSIONS — WebP phone photos won't be indexed"
    )


# ===========================================================================
# IMG_03 — WebP dispatches to load_image_ocr via load_file
# ===========================================================================
def test_IMG_03_webp_dispatched_to_load_image_ocr(rag_module, tmp_path):
    """load_file('.webp') must call load_image_ocr and return OCR text."""
    fake_img = MagicMock()
    fake_img.mode = 'RGB'

    with patch("PIL.Image.open", return_value=fake_img), \
         patch("pytesseract.image_to_string", return_value="Whiteboard notes here"):

        webp = tmp_path / "whiteboard.webp"
        webp.write_bytes(b"fake")
        result = rag_module.load_file(str(webp))

    assert result is not None, ".webp must be indexed"
    assert "Whiteboard notes here" in result["content"]
    assert result["extension"] == ".webp"


# ===========================================================================
# IMG_04 — HEIC is in SUPPORTED_EXTENSIONS
# ===========================================================================
def test_IMG_04_heic_in_supported_extensions(rag_module):
    """.heic must appear in SUPPORTED_EXTENSIONS so iPhone photos are indexed."""
    assert ".heic" in rag_module.SUPPORTED_EXTENSIONS, (
        ".heic missing from SUPPORTED_EXTENSIONS — iPhone photos won't be indexed"
    )


# ===========================================================================
# IMG_05 — HEIF is in SUPPORTED_EXTENSIONS
# ===========================================================================
def test_IMG_05_heif_in_supported_extensions(rag_module):
    """.heif must appear in SUPPORTED_EXTENSIONS (alternate HEIC extension)."""
    assert ".heif" in rag_module.SUPPORTED_EXTENSIONS, (
        ".heif missing from SUPPORTED_EXTENSIONS"
    )


# ===========================================================================
# IMG_06 — HEIC indexed when pillow-heif is available
# ===========================================================================
def test_IMG_06_heic_indexed_when_pillow_heif_available(rag_module, tmp_path):
    """When _HEIF_AVAILABLE is True, a .heic file must be OCR-indexed normally."""
    fake_img = MagicMock()
    fake_img.mode = 'RGB'

    with patch.object(rag_module, "_HEIF_AVAILABLE", True), \
         patch("PIL.Image.open", return_value=fake_img), \
         patch("pytesseract.image_to_string", return_value="Photo of invoice page 1"):

        heic = tmp_path / "photo.heic"
        heic.write_bytes(b"fake")
        result = rag_module.load_file(str(heic))

    assert result is not None, ".heic must be indexed when pillow-heif is available"
    assert "Photo of invoice page 1" in result["content"]
    assert result["extension"] == ".heic"


# ===========================================================================
# IMG_07 — HEIC returns empty string + warning when pillow-heif is missing
# ===========================================================================
def test_IMG_07_heic_graceful_fallback_when_pillow_heif_missing(rag_module, tmp_path, capsys):
    """When _HEIF_AVAILABLE is False, load_image_ocr must return '' and print
    a helpful warning — it must NOT crash or raise."""
    with patch.object(rag_module, "_HEIF_AVAILABLE", False):
        heic = tmp_path / "photo.heic"
        heic.write_bytes(b"fake")
        result = rag_module.load_image_ocr(str(heic))

    assert result == "", "Must return empty string when pillow-heif is missing"
    captured = capsys.readouterr()
    assert "pillow-heif" in captured.out, (
        "Must print a 'pillow-heif' warning so the user knows why the file was skipped"
    )


# ===========================================================================
# IMG_08 — Non-RGB image is converted to RGB before Tesseract
# ===========================================================================
def test_IMG_08_non_rgb_image_converted_to_rgb(rag_module, tmp_path):
    """HEIC (and some WebP) images may arrive in RGBA or P mode.  load_image_ocr
    must convert to RGB before calling Tesseract so colour-space errors don't
    abort the OCR run."""
    rgba_img = MagicMock()
    rgba_img.mode = 'RGBA'
    rgb_img  = MagicMock()
    rgb_img.mode = 'RGB'
    rgba_img.convert.return_value = rgb_img

    with patch.object(rag_module, "_HEIF_AVAILABLE", True), \
         patch("PIL.Image.open", return_value=rgba_img), \
         patch("pytesseract.image_to_string", return_value="RGBA photo text") as mock_ocr:

        heic = tmp_path / "rgba.heic"
        heic.write_bytes(b"fake")
        result = rag_module.load_image_ocr(str(heic))

    rgba_img.convert.assert_called_once_with('RGB'), (
        "Non-RGB image must be converted to RGB before OCR"
    )
    assert "RGBA photo text" in result


# ===========================================================================
# IMG_09 — load_image_ocr error is non-fatal
# ===========================================================================
def test_IMG_09_load_image_ocr_error_returns_empty_string(rag_module, tmp_path):
    """If PIL.Image.open() raises (e.g. corrupt file), load_image_ocr must
    return '' rather than propagating the exception."""
    with patch("PIL.Image.open", side_effect=Exception("corrupt image data")):
        jpeg = tmp_path / "corrupt.jpg"
        jpeg.write_bytes(b"not an image")
        result = rag_module.load_image_ocr(str(jpeg))

    assert result == "", "Corrupt image must return empty string, not raise"


# ===========================================================================
# IMG_10 — WebP is NOT in SKIP_EXTENSIONS
# ===========================================================================
def test_IMG_10_webp_not_in_skip_extensions(rag_module):
    """.webp must have been removed from SKIP_EXTENSIONS so scan_directory
    no longer classifies WebP files as binary blobs to skip."""
    assert ".webp" not in rag_module.SKIP_EXTENSIONS, (
        ".webp is still in SKIP_EXTENSIONS — it needs to be removed so "
        "WebP files are routed to OCR indexing, not skipped"
    )


# ===========================================================================
# IMG_11 — HEIC/HEIF not in SKIP_EXTENSIONS
# ===========================================================================
def test_IMG_11_heic_heif_not_in_skip_extensions(rag_module):
    """.heic and .heif must not appear in SKIP_EXTENSIONS."""
    assert ".heic" not in rag_module.SKIP_EXTENSIONS, ".heic must not be skipped"
    assert ".heif" not in rag_module.SKIP_EXTENSIONS, ".heif must not be skipped"


# ===========================================================================
# IMG_12 — Greyscale (L-mode) image passes through without RGB conversion
# ===========================================================================
def test_IMG_12_greyscale_image_skips_rgb_conversion(rag_module, tmp_path):
    """Greyscale ('L' mode) images are already Tesseract-compatible.
    The converter must NOT be called for L-mode images."""
    grey_img = MagicMock()
    grey_img.mode = 'L'

    with patch("PIL.Image.open", return_value=grey_img), \
         patch("pytesseract.image_to_string", return_value="Greyscale scan text"):

        png = tmp_path / "scan.png"
        png.write_bytes(b"fake")
        result = rag_module.load_image_ocr(str(png))

    grey_img.convert.assert_not_called(), (
        "Greyscale ('L') images must NOT be converted — Tesseract handles them natively"
    )
    assert "Greyscale scan text" in result
