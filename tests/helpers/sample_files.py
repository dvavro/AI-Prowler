"""
Deterministic sample-file builders.

Why these exist
---------------
Several tests need a file of a specific format. Instead of shipping binary
fixtures (which bloat the repo and break diff reviews), we generate them
on demand. Every builder is deterministic — same input, same bytes — so
hash-based assertions work.

Each builder returns the resolved Path of the file it wrote.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, Sequence


def make_txt(path: Path, content: str) -> Path:
    """Write a UTF-8 text file. Used for .txt, .md, .json, .py, .html, etc."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def make_md(path: Path, content: str) -> Path:
    """Markdown file. Just a .txt with a markdown extension — load_md does
    its own syntax stripping at index time so the input doesn't need to be
    pre-cleaned."""
    return make_txt(path, content)


def make_csv(path: Path, rows: Sequence[Sequence[str]]) -> Path:
    """Write rows to a CSV using the stdlib writer (handles quoting)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        for row in rows:
            w.writerow(row)
    return path


def make_binary_blob(path: Path, n_bytes: int = 1024) -> Path:
    """A predictable binary file — used to test SKIP_EXTENSIONS rejection.
    We write null bytes so the output is unambiguously non-text and never
    accidentally decodes as a valid encoding."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x00" * n_bytes)
    return path


def make_unsupported_file(path: Path) -> Path:
    """A file with an extension not in SUPPORTED or SKIP — should be classified
    as 'unsupported' by scan_directory."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("This file has an unknown extension.", encoding="utf-8")
    return path


def touch_with_mtime(path: Path, mtime: float) -> None:
    """Set both atime and mtime of an existing file. Used to construct the
    'older mtime via backup-restore' test case (F-TRK-05)."""
    import os
    os.utime(str(path), (mtime, mtime))


def make_changed_copy(src: Path, dst: Path, suffix_text: str = "extra") -> Path:
    """Copy src to dst with extra text appended. Used to construct a 'modified'
    version where size DEFINITELY differs (so we're testing change detection,
    not flaky equality)."""
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    original = src.read_text(encoding="utf-8")
    dst.write_text(original + "\n" + suffix_text, encoding="utf-8")
    return dst


def write_text_with_size_change(path: Path, base: str, extra_words: int) -> int:
    """Overwrite an existing text file so size is guaranteed to differ from
    the previous content. Returns the new file size in bytes.

    Used for the same-second-save test (F-TRK-04): we need to force a size
    change without relying on mtime resolution.
    """
    new_content = base + (" word" * extra_words)
    path.write_text(new_content, encoding="utf-8")
    import os
    return os.path.getsize(str(path))
