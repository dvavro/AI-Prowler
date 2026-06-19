#!/usr/bin/env python3
"""
test_indexing_fixes.py
Tests for the three fixes applied to rag_preprocessor.py:
  Fix 1: CODE_SCAN_EXTENSIONS constant defined at module level
  Fix 1B: load_file() returns 500-line security scan for code files
  Fix 2: single-chunk bypass for code files in indexing loop
  Fix 3: ChromaDB batch-add present in source
"""
import sys
import os
import tempfile

sys.path.insert(0, r'C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler')
import rag_preprocessor as rp

PASS = 0
FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  PASS: {name}")
        PASS += 1
    else:
        print(f"  FAIL: {name}{(' -- ' + detail) if detail else ''}")
        FAIL += 1

print("\n=== Fix 1: CODE_SCAN_EXTENSIONS at module level ===")
check("CODE_SCAN_EXTENSIONS exists", hasattr(rp, 'CODE_SCAN_EXTENSIONS'))
check("CODE_SCAN_LINES exists", hasattr(rp, 'CODE_SCAN_LINES'))
check("CODE_SCAN_LINES == 500", getattr(rp, 'CODE_SCAN_LINES', None) == 500,
      f"got {getattr(rp, 'CODE_SCAN_LINES', None)}")
for ext in ('.py', '.bat', '.ps1', '.sh', '.js', '.ts', '.sql'):
    check(f"{ext} in CODE_SCAN_EXTENSIONS",
          ext in getattr(rp, 'CODE_SCAN_EXTENSIONS', set()))

print("\n=== Fix 1B: load_file() 500-line security scan ===")
# Create a 1000-line .py file
tmp = tempfile.NamedTemporaryFile(suffix='.py', mode='w',
                                   delete=False, encoding='utf-8')
for i in range(1000):
    tmp.write(f"# line {i+1}\nx_{i} = {i}\n")
tmp.close()
try:
    result = rp.load_file(tmp.name)
    check("load_file returns result for .py", result is not None)
    if result:
        content = result['content']
        lines = content.count('\n')
        check("starts with [SECURITY SCAN ONLY]",
              content.startswith('[SECURITY SCAN ONLY'),
              f"starts with: {repr(content[:60])}")
        check("content ~500 lines (490-520)",
              490 <= lines <= 520,
              f"got {lines} lines")
        check("extension stored as .py", result['extension'] == '.py')
finally:
    os.unlink(tmp.name)

print("\n=== Fix 2: Single-chunk bypass ===")
tmp2 = tempfile.NamedTemporaryFile(suffix='.py', mode='w',
                                    delete=False, encoding='utf-8')
for i in range(1000):
    tmp2.write(f"# line {i+1}\nx_{i} = {i} * 2\n")
tmp2.close()
try:
    r2 = rp.load_file(tmp2.name)
    if r2:
        ext2 = r2.get('extension', '')
        if ext2 in rp.CODE_SCAN_EXTENSIONS:
            chunks2 = [r2['content']]
        else:
            chunks2 = rp.chunk_text(r2['content'], rp.CHUNK_SIZE, rp.CHUNK_OVERLAP)
        check("1000-line .py produces 1 chunk via Fix 2",
              len(chunks2) == 1, f"got {len(chunks2)}")
        check("chunk has SECURITY SCAN header",
              '[SECURITY SCAN ONLY' in chunks2[0])
finally:
    os.unlink(tmp2.name)

# .md should still get multiple chunks
tmp3 = tempfile.NamedTemporaryFile(suffix='.md', mode='w',
                                    delete=False, encoding='utf-8')
tmp3.write("# Title\n" + "word " * 3000)
tmp3.close()
try:
    r3 = rp.load_file(tmp3.name)
    if r3:
        ext3 = r3.get('extension', '')
        if ext3 in rp.CODE_SCAN_EXTENSIONS:
            chunks3 = [r3['content']]
        else:
            chunks3 = rp.chunk_text(r3['content'], rp.CHUNK_SIZE, rp.CHUNK_OVERLAP)
        check(".md file gets multiple chunks (not bypassed)",
              len(chunks3) > 1, f"got {len(chunks3)}")
finally:
    os.unlink(tmp3.name)

print("\n=== Fix 3: ChromaDB batch-add in source ===")
src = open(
    r'C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler\rag_preprocessor.py',
    encoding='utf-8').read()
check("_CHROMA_BATCH in source", '_CHROMA_BATCH' in src)
check("batch loop in source",
      'for _b_start in range(0, len(chunks), _CHROMA_BATCH)' in src)

print(f"\n{'='*50}")
print(f"Results: {PASS} passed, {FAIL} failed")
print('='*50)
sys.exit(0 if FAIL == 0 else 1)
