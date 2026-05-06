# AI-Prowler 6.0.0 — Functional Test Harness

This `tests/` folder contains the pytest suite that automates Sections 4-6 of the test plan (Functional Indexing, Tracking, Update). The GUI tests (Section 7) are not in here — those need pywinauto and live separately.

## How it works

Every test:
1. Gets a fresh, isolated ChromaDB and tracking JSON via the `isolated_env` fixture in `conftest.py`.
2. Builds deterministic sample files via the helpers in `helpers/`.
3. Calls the actual functions in `rag_preprocessor.py` (no mocks, no stubs).
4. Asserts on the function's return value AND on the resulting on-disk state.

Your real install (`~/AI-Prowler/rag_database`, `~/.rag_file_tracking.json`, etc.) is never touched. The harness redirects every module-level path constant to per-test temp directories before any code runs.

## Quick start

From your AI-Prowler source root:

```bash
# Install test deps (one-time, or after updating requirements-test.txt)
pip install -r tests/requirements-test.txt

# Run everything
pytest tests/

# Run only fast tests (skip the ones marked @pytest.mark.slow)
pytest tests/ -m "not slow"

# Run only one test file
pytest tests/unit/test_tracking.py

# Run one specific test by name
pytest tests/unit/test_tracking.py::test_F_TRK_04_same_second_save_with_size_change

# Verbose output for everything (default is already -v but louder)
pytest tests/ -vv

# Stop at the first failure (useful while iterating on a fix)
pytest tests/ -x
```

If your repo layout puts `rag_preprocessor.py` somewhere other than the parent of `tests/`, set:

```bash
export AI_PROWLER_SRC=/path/to/source
```

(on Windows: `set AI_PROWLER_SRC=C:\path\to\source`)

## Reading the output

```
test_tracking.py::test_F_TRK_01_first_scan_creates_record PASSED
test_tracking.py::test_F_TRK_04_same_second_save_with_size_change XFAIL
test_tracking.py::test_F_TRK_05_backup_restore_older_mtime XFAIL
```

- **PASSED** — works as expected.
- **XFAIL** — exercises a known bug. Expected to fail until the bug is fixed. Counts as success for CI purposes.
- **XPASSED** — was marked xfail but is now passing. **The suite will exit non-zero on this** (because of `xfail_strict = true` in `pytest.ini`). When you see it, that means a bug fix landed and you need to remove the `@pytest.mark.xfail(...)` marker from that test.
- **FAILED** — actual regression. Read the traceback.

## The xfail workflow

This is how the harness tracks bug fixes. When you fix one of the 10 bugs from the test plan:

1. The corresponding test (search for the bug ID in comments, e.g. `B-04`) flips from XFAIL to XPASSED.
2. Pytest fails the suite because of `xfail_strict`.
3. You remove the `@pytest.mark.xfail(...)` decorator from that test.
4. Test now reports as PASSED. The fix is locked in — any future regression on this exact issue will fail the suite normally.

This makes the test suite a living artifact of which bugs are fixed and which aren't, with no separate spreadsheet to keep in sync.

## What's NOT in here

- **GUI tests** (G-IDX, G-UPD, G-AUT, G-DB) — need pywinauto on Windows. That's a separate harness because it requires a real desktop session.
- **MCP tool tests** (G-MCP) — need to spawn the MCP server as a subprocess and speak JSON-RPC. Also a separate harness.
- **OCR tests** (F-IDX-08, F-IDX-09) — need Tesseract installed and a way to construct image-only PDFs deterministically. They're scaffolded but skipped by default; remove the skip when you've got Tesseract on the test box.
- **Anything performance-related** — pytest is not a load tester. The big-file test (F-IDX-15) is in the test plan but not here.

## Test → plan ID mapping

Every test function name starts with its test plan ID:

```
test_F_IDX_01_index_empty_directory       → F-IDX-01
test_F_TRK_04_same_second_save_with_size  → F-TRK-04
test_F_UPD_07_clear_database_wipes_all    → F-UPD-07
test_B_03_remove_returns_files_removed    → bug B-03 specifically
```

So you can grep for an ID in the test plan and find the test, or vice versa.

## Adding new tests

1. Pick the right file (`test_indexing.py`, `test_tracking.py`, `test_update.py`, `test_remove.py`).
2. Name the function after its plan ID.
3. Use `isolated_env` as the first fixture so you get a clean DB.
4. Use `sample_files`, `small_text_file`, or `mbox_file` if you need pre-built test data.
5. Don't import `rag_preprocessor` at module top — use the `isolated_env.rag` attribute. The `rag` fixture is session-scoped so it's only imported once.
