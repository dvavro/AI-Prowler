#!/usr/bin/env python3
"""
apply_all_fixes.py
Applies ALL three fixes to rag_preprocessor.py in one shot:
  Fix 1: CODE_SCAN_EXTENSIONS constant + 500-line loader branch
  Fix 2: Single-chunk bypass for code files in _index_file_list_impl()
  Fix 3: ChromaDB batch-add (<=166 per call)
Does NOT restore from any backup — works on the current file as-is.
Includes a compile() syntax check before writing.
"""
import sys, shutil
from pathlib import Path

TARGET = Path(__file__).parent / "rag_preprocessor.py"
if not TARGET.exists():
    print(f"ERROR: {TARGET} not found"); sys.exit(1)

text = TARGET.read_text(encoding="utf-8")
original = text
applied = []

# ─── FIX 1A: CODE_SCAN_EXTENSIONS constant ───────────────────────────────────
F1A_OLD = "    '.gitignore', '.dockerignore', '.editorconfig',\n}"
F1A_NEW = """    '.gitignore', '.dockerignore', '.editorconfig',
}

# ── Code / script extensions — security-scan only ────────────────────────────
# Indexed as ONE chunk containing only the first 500 lines, prefixed with
# [SECURITY SCAN ONLY]. Lets Claude detect malicious scripts without flooding
# semantic search with code boilerplate. Use grep for code search.
CODE_SCAN_EXTENSIONS = {
    '.py', '.rb', '.pl', '.pm', '.r',
    '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    '.java', '.kt', '.scala', '.groovy',
    '.cs', '.cpp', '.c', '.h', '.hpp', '.cc', '.cxx',
    '.go', '.rs', '.swift', '.php',
    '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
    '.css', '.scss', '.sass', '.less',
    '.sql',
}
CODE_SCAN_LINES = 500"""

if "CODE_SCAN_EXTENSIONS" not in text:
    if F1A_OLD in text:
        text = text.replace(F1A_OLD, F1A_NEW, 1)
        applied.append("Fix 1A: CODE_SCAN_EXTENSIONS constant inserted")
    else:
        print("WARNING: Fix 1A anchor not found")
else:
    applied.append("Fix 1A: already present — skipped")

# ─── FIX 1B: 500-line security scan branch in load_file() ────────────────────
F1B_OLD = "    else:\n        content = load_text_file(filepath)"
F1B_NEW = """    elif ext in CODE_SCAN_EXTENSIONS:
        # Security scan: read first CODE_SCAN_LINES lines only — stored as one chunk.
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

if "SECURITY SCAN ONLY" not in text:
    if F1B_OLD in text:
        text = text.replace(F1B_OLD, F1B_NEW, 1)
        applied.append("Fix 1B: 500-line loader branch in load_file()")
    else:
        print("WARNING: Fix 1B anchor not found")
else:
    applied.append("Fix 1B: already present — skipped")

# ─── FIX 2: Single-chunk bypass in _index_file_list_impl() ───────────────────
F2_OLD = (
    "        chunks = chunk_text(file_data['content'], CHUNK_SIZE, CHUNK_OVERLAP)\n"
    "        if not chunks:\n"
)
F2_NEW = (
    "        # Code files: store as ONE security-scan chunk — no splitting.\n"
    "        _file_ext = file_data.get('extension', '')\n"
    "        if _file_ext in CODE_SCAN_EXTENSIONS:\n"
    "            chunks = [file_data['content']]\n"
    "        else:\n"
    "            chunks = chunk_text(file_data['content'], CHUNK_SIZE, CHUNK_OVERLAP)\n"
    "        if not chunks:\n"
)

if "CODE_SCAN_EXTENSIONS:\n            chunks = [file_data" not in text:
    count2 = text.count(F2_OLD)
    if count2 == 1:
        text = text.replace(F2_OLD, F2_NEW, 1)
        applied.append("Fix 2: single-chunk bypass for code files")
    elif count2 > 1:
        print(f"WARNING: Fix 2 anchor matched {count2} times — not applied safely")
    else:
        print("WARNING: Fix 2 anchor not found — indentation may differ")
else:
    applied.append("Fix 2: already present — skipped")

# ─── FIX 3: ChromaDB batch-add ───────────────────────────────────────────────
F3_OLD = (
    "            _file_col.add(ids=ids, documents=chunks, metadatas=metadatas)\n"
    "            processed    += 1\n"
    "            total_chunks += len(chunks)\n"
    "            total_words  += file_data['word_count']\n"
    "            print(f\"         \u2705 {len(chunks)} chunks added\")"
)
F3_NEW = (
    "            # Batch add — ChromaDB fails silently on >166 docs per call.\n"
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
    "            print(f\"         \u2705 {_chunks_added} chunks added\")"
)

if "_CHROMA_BATCH" not in text:
    if F3_OLD in text:
        text = text.replace(F3_OLD, F3_NEW)
        applied.append("Fix 3: ChromaDB batch-add")
    else:
        print("WARNING: Fix 3 anchor not found — indentation may differ")
else:
    applied.append("Fix 3: already present — skipped")

# ─── Write & verify ──────────────────────────────────────────────────────────
print("\nResults:")
for a in applied:
    print(f"  {'✅' if 'skipped' not in a else 'ℹ️ '} {a}")

if text == original:
    print("\nℹ️  No changes needed — all fixes already present")
    sys.exit(0)

try:
    compile(text, str(TARGET), 'exec')
    print("\n✅ Syntax check passed")
except SyntaxError as e:
    print(f"\n❌ SYNTAX ERROR — NOT writing file: {e}")
    sys.exit(1)

bak = TARGET.with_suffix(".py.allfixes_bak")
shutil.copy2(str(TARGET), str(bak))
TARGET.write_text(text, encoding="utf-8")
print(f"📦 Backup: {bak.name}")
print(f"✅ {TARGET.name} updated successfully")
print("\nDone. Run Update Index in the GUI.")
