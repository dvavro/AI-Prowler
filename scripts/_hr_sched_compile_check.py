import py_compile, sys

targets = [
    r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_scheduler.py",
    r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\ai_prowler_mcp.py",
]
ok = True
for t in targets:
    try:
        py_compile.compile(t, doraise=True)
        print(f"COMPILE_OK: {t}")
    except Exception as e:
        ok = False
        print(f"COMPILE_FAIL: {t}\n{e}")
print("ALL_OK" if ok else "SOME_FAILED")
