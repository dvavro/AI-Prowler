"""
Unit tests — PDF structural table extraction (Section PDF-EXT-* of the test plan)

These tests cover the load_pdf() changes introduced in V8.0.0 that add
structural table extraction alongside prose text.  Three scenarios are
tested end-to-end:

  1. PDF with NO tables    — text is returned; no spurious table blocks appear
  2. PDF WITH tables       — tables are rendered as "Column: Value" blocks that
                             mirror the xlsx/xls format, keyed by page and table
  3. Scanned (image) PDF   — OCR path fires; table extraction is skipped
                             (no text layer means no tables to extract)

All tests mock pdfplumber and the OCR helper so this suite runs without any
PDF files on disk and without Tesseract installed.  That keeps it fast and
deterministic — the mocked surface matches exactly what pdfplumber returns
in production.

Naming convention: PDF_NN matches the plan ID in the V8.0.0 test-plan doc.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Module import helper (mirrors the pattern used in test_indexing.py)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def rag_module():
    import rag_preprocessor
    return rag_preprocessor


# ---------------------------------------------------------------------------
# Shared mock builders
# ---------------------------------------------------------------------------

def _make_page(text: str, tables: list[list[list[str | None]]]) -> MagicMock:
    """Build a mock pdfplumber page that returns *text* and *tables*."""
    page = MagicMock()
    page.extract_text.return_value = text
    page.extract_tables.return_value = tables
    return page


def _open_pdf(pages: list[MagicMock]) -> MagicMock:
    """Build a mock pdfplumber context-manager that yields *pages*."""
    pdf_cm = MagicMock()
    pdf_cm.__enter__ = MagicMock(return_value=pdf_cm)
    pdf_cm.__exit__  = MagicMock(return_value=False)
    pdf_cm.pages = pages
    return pdf_cm


# ===========================================================================
# PDF_01 — plain-text PDF (no tables)
# ===========================================================================
def test_PDF_01_plain_text_no_tables_returns_text_only(rag_module):
    """A PDF that has a text layer but no tables must:
    - Return the prose text unchanged
    - NOT include the '--- Extracted Tables ---' separator
    - NOT raise any exception
    """
    prose = "This is a normal paragraph. " * 30   # well above OCR_MIN_CHARS

    page = _make_page(text=prose, tables=[])
    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm):
        result = rag_module.load_pdf("dummy.pdf")

    assert prose.strip() in result, "Prose text must appear in the result"
    assert "--- Extracted Tables ---" not in result, (
        "No tables were present — table separator must not appear"
    )
    assert "[PDF Table:" not in result, (
        "No tables were present — table block headers must not appear"
    )


# ===========================================================================
# PDF_02 — single table on page 1
# ===========================================================================
def test_PDF_02_single_table_extracted_structurally(rag_module):
    """A PDF with one table must produce 'Column: Value' blocks in the output.

    Expected format for a table on page 1, table 1, first data row:
        [PDF Table: page 1, table 1] [Row 1]
        Invoice #: 1042
        Amount: $426.00
    """
    prose = "Invoice summary follows." * 20

    table = [
        ["Invoice #", "Amount",  "Status"],   # header row
        ["1042",      "$426.00", "Paid"],      # row 1
        ["1043",      "$210.50", "Pending"],   # row 2
    ]

    page = _make_page(text=prose, tables=[table])
    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm):
        result = rag_module.load_pdf("dummy.pdf")

    assert "--- Extracted Tables ---" in result, "Table separator must appear"
    assert "[PDF Table: page 1, table 1] [Row 1]" in result
    assert "[PDF Table: page 1, table 1] [Row 2]" in result
    assert "Invoice #: 1042"   in result
    assert "Amount: $426.00"   in result
    assert "Status: Paid"      in result
    assert "Invoice #: 1043"   in result
    assert "Amount: $210.50"   in result
    assert "Status: Pending"   in result


# ===========================================================================
# PDF_03 — multiple tables across multiple pages
# ===========================================================================
def test_PDF_03_multiple_tables_multiple_pages(rag_module):
    """Tables on different pages must appear with the correct page number.

    Page 1 has a 'Clients' table; page 2 has an 'Orders' table.
    Each block must be tagged with its originating page number.
    """
    clients_table = [
        ["Client",  "Region"],
        ["Acme",    "North"],
        ["Globex",  "South"],
    ]
    orders_table = [
        ["Order ID", "Total"],
        ["ORD-001",  "$500"],
    ]

    page1 = _make_page(text="Client list page. " * 20, tables=[clients_table])
    page2 = _make_page(text="Orders page. "     * 20, tables=[orders_table])
    pdf_cm = _open_pdf([page1, page2])

    with patch("pdfplumber.open", return_value=pdf_cm):
        result = rag_module.load_pdf("dummy.pdf")

    assert "[PDF Table: page 1, table 1] [Row 1]" in result, "Page-1 table missing"
    assert "Client: Acme"    in result
    assert "Region: North"   in result

    assert "[PDF Table: page 2, table 1] [Row 1]" in result, "Page-2 table missing"
    assert "Order ID: ORD-001" in result
    assert "Total: $500"       in result


# ===========================================================================
# PDF_04 — multiple tables on the same page
# ===========================================================================
def test_PDF_04_two_tables_on_same_page_get_distinct_indices(rag_module):
    """Two tables on page 1 must be tagged 'table 1' and 'table 2'."""
    table_a = [["Part",  "Qty"], ["Bolt", "10"], ["Nut", "20"]]
    table_b = [["Colour","Hex"], ["Red",  "#F00"]]

    page = _make_page(text="Parts manifest. " * 20, tables=[table_a, table_b])
    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm):
        result = rag_module.load_pdf("dummy.pdf")

    assert "[PDF Table: page 1, table 1] [Row 1]" in result
    assert "[PDF Table: page 1, table 2] [Row 1]" in result
    assert "Part: Bolt"    in result
    assert "Colour: Red"   in result


# ===========================================================================
# PDF_05 — blank rows inside a table are skipped
# ===========================================================================
def test_PDF_05_blank_rows_inside_table_are_skipped(rag_module):
    """All-None rows that pdfplumber sometimes inserts between table sections
    must be silently dropped — they must not appear as empty blocks."""
    table = [
        ["Name",  "Score"],
        ["Alice", "90"],
        [None,     None],    # blank separator row
        ["Bob",   "82"],
        ["",      ""],       # another blank variant
    ]

    page = _make_page(text="Results table follows. " * 20, tables=[table])
    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm):
        result = rag_module.load_pdf("dummy.pdf")

    # Row numbering preserves the original table position (including blank rows),
    # so Alice is Row 1, the blank at position 2 is skipped (no block emitted),
    # and Bob — at position 3 in the raw table — is labelled Row 3.
    assert "[PDF Table: page 1, table 1] [Row 1]" in result   # Alice
    assert "[PDF Table: page 1, table 1] [Row 3]" in result   # Bob (position 3)
    assert "Name: Alice" in result
    assert "Name: Bob"   in result
    # The blank row at position 2 must produce no block at all
    assert "[PDF Table: page 1, table 1] [Row 2]" not in result, (
        "Blank row at position 2 must be skipped — no [Row 2] block should appear"
    )


# ===========================================================================
# PDF_06 — header-only table (no data rows) is silently skipped
# ===========================================================================
def test_PDF_06_header_only_table_is_skipped(rag_module):
    """A table with only one row (just headers, no data) must not produce any
    output block — len(table) < 2 guard must fire."""
    table = [["Column A", "Column B"]]   # header row only

    page = _make_page(text="Empty table follows. " * 20, tables=[table])
    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm):
        result = rag_module.load_pdf("dummy.pdf")

    assert "[PDF Table:" not in result, (
        "A header-only table must produce no output block"
    )
    assert "--- Extracted Tables ---" not in result


# ===========================================================================
# PDF_07 — extract_tables() error is non-fatal
# ===========================================================================
def test_PDF_07_table_extraction_error_is_non_fatal(rag_module):
    """If pdfplumber's extract_tables() raises an exception (e.g. on a
    malformed stream), load_pdf must still return the prose text without
    crashing — the inner try/except guard must swallow the error."""
    prose = "Normal readable prose. " * 30

    page = MagicMock()
    page.extract_text.return_value = prose
    page.extract_tables.side_effect = Exception("stream decode error")

    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm):
        result = rag_module.load_pdf("dummy.pdf")   # must NOT raise

    assert prose.strip() in result, (
        "Prose text must still be returned when table extraction fails"
    )
    assert "[PDF Table:" not in result


# ===========================================================================
# PDF_08 — scanned PDF: OCR path fires, tables are NOT extracted
# ===========================================================================
def test_PDF_08_scanned_pdf_falls_back_to_ocr_no_tables(rag_module):
    """A scanned (image-only) PDF returns fewer characters than OCR_MIN_CHARS
    from pdfplumber.  The function must:
    - Invoke _ocr_pdf() (the Tesseract path)
    - Return the OCR text
    - NOT include any table blocks (no text layer means no tables)
    """
    ocr_text = "OCR extracted text from scanned document. " * 40

    # pdfplumber finds almost nothing — simulates a scanned page
    page = _make_page(text="", tables=[])
    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm), \
         patch("rag_preprocessor._ocr_pdf", return_value=ocr_text) as mock_ocr:

        result = rag_module.load_pdf("scanned.pdf")

    mock_ocr.assert_called_once_with("scanned.pdf"), (
        "_ocr_pdf must be called exactly once for a scanned PDF"
    )
    assert ocr_text.strip() in result, "OCR text must be returned"
    assert "[PDF Table:" not in result, (
        "Scanned PDF has no text layer — table blocks must not appear"
    )
    assert "--- Extracted Tables ---" not in result


# ===========================================================================
# PDF_09 — scanned PDF: pdfplumber text below threshold even with some chars
# ===========================================================================
def test_PDF_09_sparse_text_triggers_ocr(rag_module):
    """A PDF where pdfplumber extracts only a handful of characters (e.g. an
    image PDF with a visible page number) must still trigger OCR — the sparse
    text must NOT be returned as the final result."""
    sparse_text = "1"   # single character — well below OCR_MIN_CHARS
    ocr_text = "Full scanned body text extracted by Tesseract. " * 40

    page = _make_page(text=sparse_text, tables=[])
    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm), \
         patch("rag_preprocessor._ocr_pdf", return_value=ocr_text):

        result = rag_module.load_pdf("sparse.pdf")

    assert ocr_text.strip() in result
    # The sparse text may or may not appear, but OCR text must dominate
    assert len(result) > len(sparse_text) + 100


# ===========================================================================
# PDF_10 — table output is appended AFTER prose, not before
# ===========================================================================
def test_PDF_10_tables_appended_after_prose(rag_module):
    """The '--- Extracted Tables ---' section must come AFTER the prose text,
    so that a word-based text splitter sees prose chunks before table chunks."""
    prose = "Executive summary paragraph. " * 30
    table = [["Item", "Cost"], ["Widget", "$9.99"]]

    page = _make_page(text=prose, tables=[table])
    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm):
        result = rag_module.load_pdf("dummy.pdf")

    prose_pos = result.find(prose[:30])
    table_pos = result.find("--- Extracted Tables ---")

    assert prose_pos != -1, "Prose text not found in result"
    assert table_pos != -1, "Table section not found in result"
    assert prose_pos < table_pos, (
        "Prose must appear BEFORE the table section in the output string"
    )


# ===========================================================================
# PDF_11 — None cells in table rows are treated as empty strings
# ===========================================================================
def test_PDF_11_none_cells_treated_as_empty_and_omitted(rag_module):
    """pdfplumber sometimes returns None for merged/empty cells.  None cells
    must be coerced to '' and then omitted (same as empty string) so that
    the output contains only populated Column: Value pairs."""
    table = [
        ["Name",  "Middle", "Last"],
        ["Alice", None,     "Smith"],   # no middle name
    ]

    page = _make_page(text="Staff directory. " * 20, tables=[table])
    pdf_cm = _open_pdf([page])

    with patch("pdfplumber.open", return_value=pdf_cm):
        result = rag_module.load_pdf("dummy.pdf")

    assert "Name: Alice"  in result
    assert "Last: Smith"  in result
    assert "Middle:"      not in result, (
        "None/empty cells must be omitted — 'Middle:' should not appear"
    )


# ===========================================================================
# PDF_12 — pdfplumber open() failure returns empty string gracefully
# ===========================================================================
def test_PDF_12_pdfplumber_open_failure_returns_empty_string(rag_module):
    """If pdfplumber.open() itself raises (e.g. corrupted PDF), load_pdf must
    return an empty string rather than propagating the exception."""
    with patch("pdfplumber.open", side_effect=Exception("corrupt PDF stream")):
        result = rag_module.load_pdf("corrupted.pdf")

    assert isinstance(result, str), "load_pdf must always return a string"
    # result may be '' (empty) — that is acceptable; it must not raise
