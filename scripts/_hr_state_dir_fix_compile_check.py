"""One-off compile check for the 2026-08-29 HR state-dir permission fix.
Checks ai_prowler_mcp.py, hr_scheduler.py, and the updated test file.
Safe to delete once no longer needed (matches the pattern of the other
_*_compile_check.py helper scripts already in this folder).
"""
import py_compile
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "ai_prowler_mcp.py"),
    os.path.join(ROOT, "hr_scheduler.py"),
    os.path.join(ROOT, "tests", "mcp", "test_hr_state_dir_isolation.py"),
]

ok = True
for f in FILES:
    try:
        py_compile.compile(f, doraise=True)
        print(f"COMPILE_OK: {f}")
    except py_compile.PyCompileError as e:
        ok = False
        print(f"COMPILE_FAIL: {f}\n{e}")

print("ALL_OK" if ok else "SOME_FAILED")
sys.exit(0 if ok else 1)
