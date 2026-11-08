"""Install the Estimator into the AI-Prowler you actually run (default C:\\Program Files\\AI-Prowler).

What it does:
  1. Copies the estimator\\ folder from this development folder into the installed AI-Prowler
     (replacing any older copy, so you can re-run it after each sprint). This includes the web app
     (estimator\\api and estimator\\ui\\web).
  2. Adds the Estimator hooks to the installed ai_prowler_mcp.py if they aren't there yet
     (backup saved as ai_prowler_mcp.py.before_estimator), then checks the file still compiles.
     If the check fails, the backup is put back automatically. There are two hooks: the MCP tools
     (Coder 1) and the web app at http://localhost:8770/estimator/ (Coder 2, Sprint 1); an install
     that already has the tools hook gets just the web app hook.
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
# Coder 2 Sprint 1: the web app hook goes right after the tools hook (same text as the dev ai_prowler_mcp.py).
WEB_ANCHOR = '_log.warning("Estimator tools not loaded: %s", _exc)'
WEB_MARKER = "_start_estimator_web"
WEB_HOOK = '''
# Estimator web app (Coder 2, Sprint 1): http://localhost:8770/estimator/ in its
# own thread. Only in AI-Prowler's own HTTP server process (_IS_HTTP_SERVER),
# never in a stdio copy or under pytest. Server mode signs people in with
# AI-Prowler's accounts; the lookups run at sign-in time, after this file loads.
try:
    from estimator.api.prowler_link import start_from_ai_prowler as _start_estimator_web
    _est_web_url = _start_estimator_web(
        is_http_server=_IS_HTTP_SERVER, server_mode=_IS_SERVER_MODE,
        load_users=lambda: _load_users(),
        resolve_user=lambda _d, _t: _resolve_user(_d, _t))
    if _est_web_url:
        _log.info("Estimator web app: %s", _est_web_url)
except Exception as _exc:  # the Estimator must never stop AI-Prowler starting
    _log.warning("Estimator web app not started: %s", _exc)
'''


def add_hooks(text: str) -> "tuple[str, list[str], str]":
    """Return (new text, hooks added, error). PURE, so tests can check it without an install."""
    lines = text.splitlines(keepends=True)
    added = []
    if "_register_estimator" not in text:
        idx = next((i for i, ln in enumerate(lines) if ln.strip() == ANCHOR), None)
        if idx is None:
            return text, [], f"Couldn't find the line '{ANCHOR}'"
        lines.insert(idx + 1, HOOK)
        added.append("tools")
    if WEB_MARKER not in text:
        joined = "".join(lines).splitlines(keepends=True)
        idx = next((i for i, ln in enumerate(joined) if ln.strip() == WEB_ANCHOR), None)
        if idx is None:
            return text, [], f"Couldn't find the line '{WEB_ANCHOR}'"
        joined.insert(idx + 1, WEB_HOOK)
        lines = joined
        added.append("web app")
    return "".join(lines), added, ""


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

    # 2. add the hooks once
    text = mcp_file.read_text(encoding="utf-8")
    new_text, added, error = add_hooks(text)
    if error:
        print(f"{error} in {mcp_file}. The hook was NOT added; ask Claude for help.")
        return 1
    if not added:
        print("The Estimator hooks are already in ai_prowler_mcp.py.")
    else:
        backup = mcp_file.with_name("ai_prowler_mcp.py.before_estimator")
        shutil.copy2(mcp_file, backup)
        mcp_file.write_text(new_text, encoding="utf-8")
        try:
            py_compile.compile(str(mcp_file), doraise=True)
        except py_compile.PyCompileError as exc:
            shutil.copy2(backup, mcp_file)
            print(f"The edited file didn't compile, so the original was put back. Error: {exc}")
            return 1
        print(f"Added the Estimator {' and '.join(added)} hook(s) to {mcp_file} (backup: {backup.name})")

    print("\nDone. Now close AI-Prowler completely and start it again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
