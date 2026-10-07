import py_compile

target = r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\rag_gui.py"
try:
    py_compile.compile(target, doraise=True)
    print(f"COMPILE_OK: {target}")
except Exception as e:
    print(f"COMPILE_FAIL: {target}\n{e}")
