"""Install the Estimator into the AI-Prowler you actually run (default C:\\Program Files\\AI-Prowler).

What it does:
  1. Copies the estimator\\ folder from this development folder into the installed AI-Prowler
     (replacing any older copy, so you can re-run it after each sprint).
  2. Adds the Estimator hook to the installed ai_prowler_mcp.py if it isn't there yet
     (backup saved as ai_prowler_mcp.py.before_estimator), then checks the file still compiles.
     If the check fails, the backup is put back automatically.
Your estimates are stored in your user folder (AI-Prowler\\Estimator), not in Program Files.
"""
import py_compile
import shutil
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent
DST = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"C:\Program Files\AI-Prowler")
ANCHOR = "mcp.tool = _counting_mcp_tool"
HOOK = '''
# Estimator tools (AI-Prowler Estimator). Registered after the mcp.tool
# monkeypatch above so they are counted and audited like every tool.
try:
    from estimator.mcp_tools.est_tools import register as _register_estimator
    _log.info("Estimator tools registered: %s", _register_estimator(mcp))
except Exception as _exc:  # the Estimator must never stop AI-Prowler starting
    _log.warning("Estimator tools not loaded: %s", _exc)
'''


def main() -> int:
    if DST.resolve() == SRC:
        print("The install folder is this development folder; nothing to do.")
        return 1
    mcp_file = DST / "ai_prowler_mcp.py"
    if not mcp_file.exists():
        print(f"Couldn't find {mcp_file}. Nothing was changed.")
        return 1

    try:
        import yaml  # noqa: F401
    except ImportError:
        print("Python is missing PyYAML. Run:  pip install pyyaml   then run this again.")
        return 1

    # 1. copy the estimator package
    target = DST / "estimator"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(SRC / "estimator", target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.bak*"))
    print(f"Copied the Estimator to {target}")

    # 2. add the hook once
    text = mcp_file.read_text(encoding="utf-8")
    if "_register_estimator" in text:
        print("The Estimator hook is already in ai_prowler_mcp.py.")
    else:
        lines = text.splitlines(keepends=True)
        idx = next((i for i, ln in enumerate(lines) if ln.strip() == ANCHOR), None)
        if idx is None:
            print(f"Couldn't find the line '{ANCHOR}' in {mcp_file}. The hook was NOT added; ask Claude for help.")
            return 1
        backup = mcp_file.with_name("ai_prowler_mcp.py.before_estimator")
        shutil.copy2(mcp_file, backup)
        lines.insert(idx + 1, HOOK)
        mcp_file.write_text("".join(lines), encoding="utf-8")
        try:
            py_compile.compile(str(mcp_file), doraise=True)
        except py_compile.PyCompileError as exc:
            shutil.copy2(backup, mcp_file)
            print(f"The edited file didn't compile, so the original was put back. Error: {exc}")
            return 1
        print(f"Added the Estimator hook to {mcp_file} (backup: {backup.name})")

    print("\nDone. Now close AI-Prowler completely and start it again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
