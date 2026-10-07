import py_compile, sys, os

target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ai_prowler_mcp.py")
target = os.path.abspath(target)
try:
    py_compile.compile(target, doraise=True)
    print("COMPILE_OK:", target)
except py_compile.PyCompileError as e:
    print("COMPILE_FAILED")
    print(e)
    sys.exit(1)
