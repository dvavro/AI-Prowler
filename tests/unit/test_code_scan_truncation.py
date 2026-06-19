"""
Functional tests — Code/Script Security Scan Truncation

Covers the CODE_SCAN_EXTENSIONS / CODE_SCAN_LINES feature in
rag_preprocessor.py: program and script files are indexed as a SINGLE
chunk containing only the first 500 lines (prefixed with a
"[SECURITY SCAN ONLY]" header), instead of being fully semantically
chunked like documents.

Why this exists
----------------
Code files produce huge amounts of low-value chunk noise if indexed the
normal way (every function/class/boilerplate line becomes embedding
fodder), and grep is the right tool for searching source code anyway.
The 500-line cap also bounds how much of a potentially malicious script
gets read into a single chunk for security-scan purposes, so an enormous
file doesn't balloon a single chunk's size unbounded.

These tests verify:
  1. The cap applies ONLY to program/script extensions (CODE_SCAN_EXTENSIONS) —
     NOT to document/data formats like .txt, .md, .csv, .json, which must be
     fully chunked as normal even when they exceed 500 lines.
  2. A code file under the 500-line cap is stored in full, with a header that
     does NOT claim truncation.
  3. A code file over the cap is truncated to exactly 500 lines, with a header
     that DOES report the true total line count.
  4. Exactly one chunk is produced for a code file regardless of size (no
     semantic chunking) — this is what keeps ChromaDB free of code-boilerplate
     noise.
  5. The scoping holds across a representative sample of CODE_SCAN_EXTENSIONS
     members (not just .py), since a future edit to the set could silently
     narrow or widen what's covered.

Test IDs use the F-CODE-NN convention (a new section, since this feature
postdates the original numbered test plan).
"""
from __future__ import annotations

from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Shared builder — deterministic N-line source file
# ──────────────────────────────────────────────────────────────────────────────
def _make_numbered_lines_file(path: Path, n_lines: int, line_prefix: str = "line") -> Path:
    """Write a file with exactly n_lines lines, each uniquely numbered so
    truncation can be detected precisely (we can assert the LAST surviving
    line number, not just a line count guess based on word splitting)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(f"{line_prefix} {i}" for i in range(1, n_lines + 1))
    path.write_text(content, encoding="utf-8")
    return path


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-01 — code file under the cap is NOT truncated
# ──────────────────────────────────────────────────────────────────────────────
def test_F_CODE_01_short_python_file_not_truncated(isolated_env):
    """A .py file with fewer than CODE_SCAN_LINES lines is stored in full.
    The header must report the actual line count and must NOT say "first N of"
    (that phrasing is reserved for genuinely truncated files)."""
    rag = isolated_env.rag
    f = _make_numbered_lines_file(
        isolated_env.sample_root / "short.py", n_lines=50, line_prefix="x =")

    data = rag.load_file(str(f))
    assert data is not None, "load_file returned None for a valid .py file"

    assert "[SECURITY SCAN ONLY — 50 lines]" in data["content"], (
        f"Expected the non-truncated header form; got: "
        f"{data['content'].splitlines()[0]!r}"
    )
    assert "first" not in data["content"].splitlines()[0].lower(), (
        "Header incorrectly claims truncation for a file under the cap"
    )
    # All 50 numbered lines must survive
    assert "x = 1" in data["content"]
    assert "x = 50" in data["content"]


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-02 — code file over the cap IS truncated to exactly 500 lines
# ──────────────────────────────────────────────────────────────────────────────
def test_F_CODE_02_long_python_file_truncated_to_500_lines(isolated_env):
    """A .py file with MORE than 500 lines is truncated: only the first 500
    survive, the header reports "first 500 of <total>", and line 501+ must
    NOT appear anywhere in the stored content."""
    rag = isolated_env.rag
    f = _make_numbered_lines_file(
        isolated_env.sample_root / "long.py", n_lines=1200, line_prefix="x =")

    data = rag.load_file(str(f))
    assert data is not None

    first_line = data["content"].splitlines()[0]
    assert "[SECURITY SCAN ONLY — first 500 of 1200 lines]" == first_line, (
        f"Truncation header malformed: {first_line!r}"
    )

    # Line 500 (the last surviving line) must be present
    assert "x = 500" in data["content"], "Last surviving line (500) is missing"

    # Line 501 onward must NOT be present — this is the actual cap behaviour
    assert "x = 501" not in data["content"], (
        "Line 501 leaked through — the 500-line cap was not enforced"
    )
    assert "x = 1200" not in data["content"], (
        "Final line of the source file leaked through — file was not truncated"
    )

    # Sanity: exactly 500 content lines + 1 header line = 501 total lines
    body_lines = data["content"].splitlines()[1:]  # drop the header line
    assert len(body_lines) == 500, (
        f"Expected exactly 500 body lines after the header; got {len(body_lines)}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-03 — boundary: a file with EXACTLY 500 lines is not "truncated"
# ──────────────────────────────────────────────────────────────────────────────
def test_F_CODE_03_exactly_500_lines_is_not_truncated(isolated_env):
    """Off-by-one guard: a file with exactly CODE_SCAN_LINES lines should use
    the non-truncated header form (total == cap, nothing was actually cut)."""
    rag = isolated_env.rag
    f = _make_numbered_lines_file(
        isolated_env.sample_root / "exact.py", n_lines=500, line_prefix="x =")

    data = rag.load_file(str(f))
    assert data is not None

    first_line = data["content"].splitlines()[0]
    assert first_line == "[SECURITY SCAN ONLY — 500 lines]", (
        f"A file with exactly the cap's line count should not be marked "
        f"truncated; got: {first_line!r}"
    )
    assert "x = 500" in data["content"]


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-04 — boundary: 501 lines IS truncated (one over the cap)
# ──────────────────────────────────────────────────────────────────────────────
def test_F_CODE_04_501_lines_is_truncated_by_one_line(isolated_env):
    """One line over the cap is the minimal case that must trigger
    truncation — guards against an off-by-one in the comparison operator."""
    rag = isolated_env.rag
    f = _make_numbered_lines_file(
        isolated_env.sample_root / "over_by_one.py", n_lines=501, line_prefix="x =")

    data = rag.load_file(str(f))
    assert data is not None

    first_line = data["content"].splitlines()[0]
    assert first_line == "[SECURITY SCAN ONLY — first 500 of 501 lines]", (
        f"501-line file should report truncation; got: {first_line!r}"
    )
    assert "x = 500" in data["content"]
    assert "x = 501" not in data["content"], "The 501st line should have been cut"


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-05 — exactly one chunk is produced for a code file, any size
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_CODE_05_code_file_always_produces_a_single_chunk(isolated_env):
    """Whether a .py file is tiny or huge, index_file_list must store it as
    exactly ONE chunk in ChromaDB — no semantic chunking for code, since the
    whole point of this feature is to avoid flooding the DB with code-boilerplate
    chunks. This is the regression that matters most: if chunk_text() ever gets
    called on a code file again, this test catches it immediately."""
    rag = isolated_env.rag
    f = _make_numbered_lines_file(
        isolated_env.sample_root / "big.py", n_lines=3000, line_prefix="def f(): pass  #")

    stats = rag.index_file_list(
        [rag.normalise_path(str(f))],
        label="code-scan-chunk-count",
        root_directory=str(f.parent),
    )
    assert stats["processed"] == 1, f"Expected the file to be processed; got {stats}"
    assert stats["chunks"] == 1, (
        f"Code files must produce exactly 1 chunk regardless of size; "
        f"got {stats['chunks']} chunk(s) for a 3000-line .py file — "
        f"semantic chunking may have been incorrectly applied"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-06 — the 500-line cap does NOT apply to plain text documents
# ──────────────────────────────────────────────────────────────────────────────
def test_F_CODE_06_plain_text_file_over_500_lines_is_not_truncated(isolated_env):
    """A .txt file with well over 500 lines must be indexed in FULL — the
    code-scan truncation is scoped to CODE_SCAN_EXTENSIONS only and must
    never leak onto plain document formats."""
    rag = isolated_env.rag
    f = _make_numbered_lines_file(
        isolated_env.sample_root / "long_notes.txt", n_lines=1200, line_prefix="note line")

    data = rag.load_file(str(f))
    assert data is not None

    assert "[SECURITY SCAN ONLY" not in data["content"], (
        "A .txt file should never receive the code-scan header"
    )
    assert "note line 1" in data["content"]
    assert "note line 1200" in data["content"], (
        "The last line of a 1200-line .txt file is missing — "
        "the 500-line code-scan cap incorrectly applied to a document format"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-07 — the 500-line cap does NOT apply to Markdown
# ──────────────────────────────────────────────────────────────────────────────
def test_F_CODE_07_markdown_file_over_500_lines_is_not_truncated(isolated_env):
    """Markdown is a document format (release notes, user guides, etc.) even
    though it commonly lives alongside code in a repo — it must never be
    routed through the code-scan path."""
    rag = isolated_env.rag
    f = _make_numbered_lines_file(
        isolated_env.sample_root / "CHANGELOG.md", n_lines=800, line_prefix="- Fixed issue")

    data = rag.load_file(str(f))
    assert data is not None

    assert "[SECURITY SCAN ONLY" not in data["content"], (
        "A .md file should never receive the code-scan header"
    )
    assert "Fixed issue 800" in data["content"], (
        "Markdown content beyond line 500 is missing — the code-scan cap "
        "incorrectly applied to a Markdown file"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-08 — the 500-line cap does NOT apply to CSV/data files
# ──────────────────────────────────────────────────────────────────────────────
def test_F_CODE_08_csv_file_over_500_rows_is_not_truncated(isolated_env):
    """A large CSV is a data format, not a program file, and must be fully
    indexed even though spreadsheets and code share some superficial
    "lots of short lines" structure that could tempt an incorrect extension
    mapping in the future."""
    rag = isolated_env.rag
    from tests.helpers import sample_files as builders

    rows = [["id", "value"]] + [[str(i), f"row-{i}"] for i in range(1, 901)]
    f = builders.make_csv(isolated_env.sample_root / "big_data.csv", rows)

    data = rag.load_file(str(f))
    assert data is not None
    assert "[SECURITY SCAN ONLY" not in data["content"], (
        "A .csv file should never receive the code-scan header"
    )
    assert "row-900" in data["content"], (
        "CSV content beyond row 500 is missing — the code-scan cap "
        "incorrectly applied to a data file"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-09 — scoping holds across a representative sample of program
# extensions, not just .py
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ext", [
    ".py", ".js", ".ts", ".java", ".cs", ".cpp", ".go", ".rs",
    ".sh", ".ps1", ".css", ".sql", ".rb", ".php",
])
def test_F_CODE_09_truncation_applies_across_program_extensions(isolated_env, ext):
    """Spot-check a broad sample of CODE_SCAN_EXTENSIONS members — not just
    Python — to guard against a future edit to the set accidentally
    excluding a language while leaving others covered."""
    rag = isolated_env.rag
    f = _make_numbered_lines_file(
        isolated_env.sample_root / f"sample{ext}", n_lines=700, line_prefix="x =")

    data = rag.load_file(str(f))
    assert data is not None, f"load_file returned None for {ext}"

    first_line = data["content"].splitlines()[0]
    assert first_line == "[SECURITY SCAN ONLY — first 500 of 700 lines]", (
        f"{ext} file was not truncated as expected; header was: {first_line!r}"
    )
    assert "x = 500" in data["content"]
    assert "x = 700" not in data["content"], (
        f"{ext} file leaked content past the 500-line cap"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-10 — CODE_SCAN_EXTENSIONS contains no document/data formats
# ──────────────────────────────────────────────────────────────────────────────
def test_F_CODE_10_code_scan_extensions_excludes_document_formats(isolated_env):
    """Direct guard on the set itself: confirms common document and data
    extensions are NOT present in CODE_SCAN_EXTENSIONS. This is the fastest,
    most direct way to catch an accidental scope-widening edit to the set —
    no file I/O needed, just a set-membership check."""
    rag = isolated_env.rag
    must_not_be_code_scanned = {
        ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
        ".txt", ".md", ".rst", ".markdown", ".csv", ".tsv",
        ".html", ".htm", ".eml", ".msg", ".mbox",
        ".jpg", ".jpeg", ".png", ".webp",
    }
    overlap = must_not_be_code_scanned & rag.CODE_SCAN_EXTENSIONS
    assert not overlap, (
        f"CODE_SCAN_EXTENSIONS incorrectly includes document/data formats: "
        f"{sorted(overlap)} — these must be fully indexed, not truncated to "
        f"500 lines"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-11 — CODE_SCAN_LINES is exactly 500 (regression guard on the constant)
# ──────────────────────────────────────────────────────────────────────────────
def test_F_CODE_11_code_scan_lines_constant_is_500(isolated_env):
    """Pins the constant itself. If someone changes CODE_SCAN_LINES without
    meaning to (e.g. during an unrelated refactor), this fails immediately
    with a clear message rather than surfacing as a confusing truncation
    mismatch somewhere else."""
    rag = isolated_env.rag
    assert rag.CODE_SCAN_LINES == 500, (
        f"CODE_SCAN_LINES changed from the expected 500 to "
        f"{rag.CODE_SCAN_LINES} — update this test deliberately if that "
        f"was an intentional change"
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-12 — index_directory() (a SEPARATE code path from index_file_list())
# also produces a single chunk for code files
#
# Regression context: index_directory() has its own independent chunking
# logic — it does NOT call index_file_list() internally. The single-chunk
# CODE_SCAN_EXTENSIONS fix was originally applied only to index_file_list(),
# so a real-world Update run through index_directory() still word-chunked
# code files into many pieces (confirmed: ai_prowler_mcp.py produced 7
# chunks instead of 1 on a live GUI Update). This test guards specifically
# against that path regressing again, independent of the index_file_list()
# tests above.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_CODE_12_index_directory_also_single_chunks_code_files(isolated_env):
    """index_directory() — a separate chunking code path from
    index_file_list() — must also store code files as exactly ONE chunk,
    not split via chunk_text()."""
    rag = isolated_env.rag
    folder = isolated_env.sample_root / "dir_path_check"
    _make_numbered_lines_file(folder / "module.py", n_lines=2000, line_prefix="x =")

    rag.index_directory(str(folder), recursive=True, quiet=True)

    client, ef = rag.get_chroma_client()
    coll = client.get_or_create_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    results = coll.get(
        where={"filepath": rag.normalise_path(str(folder / "module.py"))},
        include=["documents"],
    )
    docs = results.get("documents", []) or []
    assert len(docs) == 1, (
        f"index_directory() produced {len(docs)} chunk(s) for a 2000-line "
        f".py file via the standalone-chunking path; expected exactly 1. "
        f"This is the exact bug that motivated this test file: "
        f"index_directory() has its own chunk_text() call that bypasses "
        f"the CODE_SCAN_EXTENSIONS single-chunk rule."
    )
    assert "[SECURITY SCAN ONLY — first 500 of 2000 lines]" in docs[0]
    assert "x = 500" in docs[0]
    assert "x = 501" not in docs[0], "500-line cap not enforced via index_directory()"


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-13 — EVERY extension in CODE_SCAN_EXTENSIONS, via index_directory(),
# for safety
#
# Goes further than F-CODE-12: rather than spot-checking one extension, this
# walks the LIVE rag.CODE_SCAN_EXTENSIONS set itself (not a hardcoded copy),
# so it can never silently drift out of sync if that set gains or loses a
# member in the future. Each extension gets its own isolated subfolder so
# index_directory() indexes them independently and a failure on one
# extension doesn't mask a failure on another.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_CODE_13_index_directory_single_chunk_for_every_code_scan_extension(isolated_env):
    """For safety: every single extension currently in CODE_SCAN_EXTENSIONS
    must produce exactly one chunk when indexed via index_directory(), with
    content correctly capped at 500 lines. Run as one test (not parametrized)
    so the embedding model loads once and all extensions share a single
    index_directory() pass — much faster than one slow test per extension,
    while still asserting on every extension individually so a single bad
    extension is named precisely in the failure output."""
    rag = isolated_env.rag
    root = isolated_env.sample_root / "all_code_scan_exts"

    all_exts = sorted(rag.CODE_SCAN_EXTENSIONS)
    expected_paths = {}
    for ext in all_exts:
        # Each extension in its own subfolder so filenames can't collide
        # (e.g. nothing here, but keeps every file independently addressable
        # by exact path for the ChromaDB lookup below).
        sub = root / ext.lstrip(".")
        fp = _make_numbered_lines_file(sub / f"sample{ext}", n_lines=900, line_prefix="x =")
        expected_paths[ext] = rag.normalise_path(str(fp))

    rag.index_directory(str(root), recursive=True, quiet=True)

    client, ef = rag.get_chroma_client()
    coll = client.get_or_create_collection(name=rag.COLLECTION_NAME, embedding_function=ef)

    failures = []
    for ext, fp in expected_paths.items():
        results = coll.get(where={"filepath": fp}, include=["documents"])
        docs = results.get("documents", []) or []
        if len(docs) != 1:
            failures.append(f"{ext}: expected 1 chunk, got {len(docs)}")
            continue
        body = docs[0]
        if "[SECURITY SCAN ONLY — first 500 of 900 lines]" not in body:
            failures.append(f"{ext}: missing/incorrect truncation header — "
                            f"got first line {body.splitlines()[0]!r}")
        if "x = 500" not in body:
            failures.append(f"{ext}: line 500 missing — content truncated too early")
        if "x = 900" in body:
            failures.append(f"{ext}: line 900 present — 500-line cap not enforced")

    assert not failures, (
        "index_directory() failed the single-chunk / 500-line-cap check for "
        f"{len(failures)} of {len(all_exts)} CODE_SCAN_EXTENSIONS member(s):\n  "
        + "\n  ".join(failures)
    )


# ──────────────────────────────────────────────────────────────────────────────
# F-CODE-14 — command_update() (a THIRD separate code path) also produces a
# single chunk for code files — this is the path real GUI "Update" buttons
# actually use
#
# Regression context: after fixing index_file_list() and index_directory(),
# a real-world GUI Update run still showed ai_prowler_mcp.py as 7 chunks
# instead of 1. The log format ("CHECKING FOR CHANGES" / "FILE SCAN REPORT" /
# "[NEW]"/"[MODIFIED]" tags) traced to a THIRD function, command_update(),
# which has its own independent chunk_text() call in its "PASS 2 — INDEX
# NEW/MODIFIED FILES" section. command_update() is the function actually
# wired to: GUI Update Selected, GUI Update All, the update_tracked_directories
# MCP tool, and the scheduled rag_auto_update.bat task — i.e. every real-world
# entry point a user actually clicks. This test exercises that exact path.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.mark.slow
def test_F_CODE_14_command_update_also_single_chunks_code_files(isolated_env):
    """command_update() — the function behind the GUI's Update Selected/
    Update All buttons — must also store code files as exactly ONE chunk on
    first index, not split via chunk_text(). This is the real-world path a
    user's Update click actually runs; the earlier index_file_list() and
    index_directory() tests do NOT cover it."""
    rag = isolated_env.rag
    folder = isolated_env.sample_root / "command_update_check"
    _make_numbered_lines_file(folder / "service.cs", n_lines=1500, line_prefix="x =")

    # command_update scans for NEW/MODIFIED files relative to the tracking DB,
    # so a fresh folder with no prior tracking entry is treated as all-NEW —
    # auto_confirm=True skips the interactive y/n prompt.
    rag.command_update(str(folder), recursive=True, auto_confirm=True)

    client, ef = rag.get_chroma_client()
    coll = client.get_or_create_collection(name=rag.COLLECTION_NAME, embedding_function=ef)
    results = coll.get(
        where={"filepath": rag.normalise_path(str(folder / "service.cs"))},
        include=["documents"],
    )
    docs = results.get("documents", []) or []
    assert len(docs) == 1, (
        f"command_update() produced {len(docs)} chunk(s) for a 1500-line "
        f".cs file; expected exactly 1. This is the exact real-world bug: "
        f"command_update() has its own chunk_text() call in PASS 2 that "
        f"bypasses the CODE_SCAN_EXTENSIONS single-chunk rule, and this is "
        f"the function GUI Update Selected/Update All actually call."
    )
    assert "[SECURITY SCAN ONLY — first 500 of 1500 lines]" in docs[0]
    assert "x = 500" in docs[0]
    assert "x = 501" not in docs[0], "500-line cap not enforced via command_update()"



