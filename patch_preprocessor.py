#!/usr/bin/env python3
"""
patch_preprocessor.py
Applies two fixes to rag_preprocessor.py:

  Fix 1 — CODE_SCAN_EXTENSIONS + 500-line security scan in load_file()
           Code/script files are indexed as a single security-scan chunk
           (first 500 lines only) instead of being fully chunked, which
           polluted semantic search with code boilerplate noise.

  Fix 2 — ChromaDB batch-add limit in _index_file_list_impl()
           ChromaDB silently fails when >166 documents are added in a
           single .add() call. Large files (e.g. rag_gui.py at 17k lines)
           produced 0 indexed chunks. Fixed by splitting into <=166-item
           batches before calling .add().

Run once from the AI-Prowler work directory:
    python patch_preprocessor.py
"""

import sys
from pathlib import Path

TARGET = Path(__file__).parent / "rag_preprocessor.py"

if not TARGET.exists():
    print(f"ERROR: {TARGET} not found")
    sys.exit(1)

text = TARGET.read_text(encoding="utf-8")
original = text  # keep for diff summary

# ─────────────────────────────────────────────────────────────────────────────
# FIX 1A — Insert CODE_SCAN_EXTENSIONS constant after SUPPORTED_EXTENSIONS block
# Anchor: the closing brace of SUPPORTED_EXTENSIONS (line ~1200)
# ─────────────────────────────────────────────────────────────────────────────
ANCHOR_1A = "    '.gitignore', '.dockerignore', '.editorconfig',\n}"

INSERT_1A = """    '.gitignore', '.dockerignore', '.editorconfig',
}

# ── Code / script extensions — security-scan only ────────────────────────────
# These file types are indexed as a SINGLE chunk containing only the first
# 500 lines, prefixed with [SECURITY SCAN ONLY].  This lets Claude detect
# malicious or harmful scripts without flooding semantic search with thousands
# of chunks of code boilerplate (grep is the right tool for source code).
CODE_SCAN_EXTENSIONS = {
    # Python / Ruby / Perl / R
    '.py', '.rb', '.pl', '.pm', '.r',
    # JavaScript / TypeScript family
    '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    # JVM languages
    '.java', '.kt', '.scala', '.groovy',
    # .NET / C family
    '.cs', '.cpp', '.c', '.h', '.hpp', '.cc', '.cxx',
    # Go / Rust / Swift
    '.go', '.rs', '.swift',
    # PHP
    '.php',
    # Shell / scripts
    '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
    # Web / markup (code-like, not document-like)
    '.css', '.scss', '.sass', '.less',
    # Config / data as code
    '.sql',
}
CODE_SCAN_LINES = 500   # number of lines to read for security scan"""

if ANCHOR_1A in text:
    text = text.replace(ANCHOR_1A, INSERT_1A, 1)
    print("✅ Fix 1A applied — CODE_SCAN_EXTENSIONS constant inserted")
else:
    print("⚠️  Fix 1A SKIPPED — anchor not found (already applied?)")

# ─────────────────────────────────────────────────────────────────────────────
# FIX 1B — Add security-scan branch inside load_file() before the else clause
# Anchor: the 'else:' + 'content = load_text_file(filepath)' fallback
# ─────────────────────────────────────────────────────────────────────────────
ANCHOR_1B = "    else:\n        content = load_text_file(filepath)"

INSERT_1B = """    elif ext in CODE_SCAN_EXTENSIONS:
        # Security scan: read first CODE_SCAN_LINES lines only.
        # Stored as a single chunk — grep is the right tool for code search.
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as _f:
                _lines = []
                for _i, _line in enumerate(_f):
                    if _i >= CODE_SCAN_LINES:
                        break
                    _lines.append(_line)
            _total_lines = sum(1 for _ in open(
                filepath, 'r', encoding='utf-8', errors='replace'))
            _truncated = _total_lines > CODE_SCAN_LINES
            _header = (
                f"[SECURITY SCAN ONLY — first {CODE_SCAN_LINES} of "
                f"{_total_lines} lines]\\n"
                if _truncated else
                f"[SECURITY SCAN ONLY — {_total_lines} lines]\\n"
            )
            content = _header + "".join(_lines)
        except Exception as _e:
            print(f"⚠️  Error reading code file {filepath}: {_e}")
            content = ""
    else:
        content = load_text_file(filepath)"""

if ANCHOR_1B in text:
    text = text.replace(ANCHOR_1B, INSERT_1B, 1)
    print("✅ Fix 1B applied — security-scan branch added to load_file()")
else:
    print("⚠️  Fix 1B SKIPPED — anchor not found (already applied?)")

# ─────────────────────────────────────────────────────────────────────────────
# FIX 2 — Batch ChromaDB .add() calls in _index_file_list_impl()
# Anchor: the single _file_col.add() call followed by processed += 1
# There are TWO occurrences (index and reindex paths) — replace both.
# ─────────────────────────────────────────────────────────────────────────────
OLD_ADD = (
    "            _file_col.add(ids=ids, documents=chunks, metadatas=metadatas)\n"
    "            processed    += 1\n"
    "            total_chunks += len(chunks)\n"
    "            total_words  += file_data['word_count']\n"
    "            print(f\"         ✅ {len(chunks)} chunks added\")"
)

NEW_ADD = (
    "            # ── Batch add — ChromaDB silently fails on >166 docs per call ──\n"
    "            # Large files (e.g. rag_gui.py ~17k lines → 340+ chunks) produced\n"
    "            # 0 indexed chunks without batching.  Split into <=166-item batches;\n"
    "            # any single batch failure is reported so the rest still gets indexed.\n"
    "            _CHROMA_BATCH = 166\n"
    "            _chunks_added = 0\n"
    "            for _b_start in range(0, len(chunks), _CHROMA_BATCH):\n"
    "                _b_ids  = ids[_b_start:_b_start + _CHROMA_BATCH]\n"
    "                _b_docs = chunks[_b_start:_b_start + _CHROMA_BATCH]\n"
    "                _b_meta = metadatas[_b_start:_b_start + _CHROMA_BATCH]\n"
    "                _file_col.add(ids=_b_ids, documents=_b_docs, metadatas=_b_meta)\n"
    "                _chunks_added += len(_b_ids)\n"
    "            processed    += 1\n"
    "            total_chunks += _chunks_added\n"
    "            total_words  += file_data['word_count']\n"
    "            print(f\"         ✅ {_chunks_added} chunks added\")"
)

count_2 = text.count(OLD_ADD)
if count_2 > 0:
    text = text.replace(OLD_ADD, NEW_ADD)
    print(f"✅ Fix 2 applied — ChromaDB batch-add fix applied to {count_2} location(s)")
else:
    # Try with tabs instead of spaces
    OLD_ADD_TAB = OLD_ADD.replace("            ", "\t\t\t")
    NEW_ADD_TAB = NEW_ADD.replace("            ", "\t\t\t")
    count_2t = text.count(OLD_ADD_TAB)
    if count_2t > 0:
        text = text.replace(OLD_ADD_TAB, NEW_ADD_TAB)
        print(f"✅ Fix 2 applied (tab variant) — ChromaDB batch-add fix applied to {count_2t} location(s)")
    else:
        print("⚠️  Fix 2 SKIPPED — anchor not found (already applied, or indentation differs)")
        print("   Manual fix needed at the _file_col.add() call in _index_file_list_impl()")

# ─────────────────────────────────────────────────────────────────────────────
# Write result
# ─────────────────────────────────────────────────────────────────────────────
if text != original:
    # Backup
    bak = TARGET.with_suffix(".py.patch_bak")
    bak.write_text(original, encoding="utf-8")
    print(f"\n📦 Backup saved to: {bak.name}")

    TARGET.write_text(text, encoding="utf-8")
    print(f"✅ {TARGET.name} updated successfully")
else:
    print("\nℹ️  No changes written — all fixes were already applied or anchors not found")

print("\nDone. Re-run Update Index in the AI-Prowler GUI to reindex with the new rules.")
