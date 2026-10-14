"""2026-10-12: fixes for the 8 Grok-related regression failures.

task_queue_automation.py
  * _normalize_provider: "xai" -> "grok", "claude" -> "anthropic" (David's test)
  * run_queue_now: the new api_key_provider parameter moves to the END (it was
    inserted mid-signature, shifting positional callers' notify settings)
  * _grok_select_tools (broad): after the ranked list, fill spare room up to
    GROK_MAX_TOOLS with the remaining tools (never GROK_NEVER_OFFER)
tests
  * test_task_queue_grok.py: create the fake MCP script's folder; expect
    GROK_MODEL (grok-4.3); prompt says "general knowledge", not web_search;
    the Claude wrapper runs the quoted claude.exe path with -p
  * test_task_queue_automation.py: the fake install_wrapper takes **kwargs
Writes a file only if it compiles. ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def edit(rel, pairs, regex=()):
    p = ROOT / rel
    raw = p.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    s = raw.replace("\r\n", "\n")
    for old, new in pairs:
        n = s.count(old)
        assert n >= 1, f"{rel}: not found: {old[:80]!r}"
        s = s.replace(old, new)
    for rx, new in regex:
        s, n = re.subn(rx, new, s)
        assert n >= 1, f"{rel}: regex not found: {rx}"
    compile(s, rel, "exec")
    p.write_bytes(s.replace("\n", nl).encode("utf-8"))
    print(f"{rel}: ok")


edit("task_queue_automation.py", [
    ('''    p = (provider or "anthropic").strip().lower()
    return p if p in API_KEY_PROVIDERS else "anthropic"''',
     '''    p = (provider or "anthropic").strip().lower()
    p = {"xai": "grok", "claude": "anthropic"}.get(p, p)
    return p if p in API_KEY_PROVIDERS else "anthropic"'''),
    ('''def run_queue_now(mcp_config_path: str, allowed_tools: str,
                     use_api_key: bool = False,
                     api_key_provider: str = "anthropic",
                   notify_on_complete: bool = False,
                   notify_method: str = "sms",
                   timeout: int = 600) -> tuple[bool, str]:''',
     '''def run_queue_now(mcp_config_path: str, allowed_tools: str,
                  use_api_key: bool = False,
                  notify_on_complete: bool = False,
                  notify_method: str = "sms",
                  timeout: int = 600,
                  api_key_provider: str = "anthropic") -> tuple[bool, str]:
    # 2026-10-12: api_key_provider is LAST (keyword) so existing positional
    # callers keep their notify_on_complete / notify_method / timeout meaning.'''),
    ('''        names = order[:GROK_MAX_TOOLS]
    else:''',
     '''        # fill spare room with everything else available (ranked tools first)
        order += sorted(n for n in avail if n not in order)
        names = order[:GROK_MAX_TOOLS]
    else:'''),
])

edit("tests/analysis/test_task_queue_grok.py", [
    ('tqa.LOCAL_MCP_SCRIPT_PATH.write_text("# fake")',
     'tqa.LOCAL_MCP_SCRIPT_PATH.parent.mkdir(parents=True, exist_ok=True)\n'
     '        tqa.LOCAL_MCP_SCRIPT_PATH.write_text("# fake")'),
    ('assert model == "grok-4-1-fast"', 'assert model == tqa.GROK_MODEL   # grok-4.3 since 2026-10-12'),
    ('''        assert "web_search" in p''',
     '''        # 2026-10-12: no web search on /v1/chat/completions (xAI's built-in
        # tools are Responses-API only) — Grok is told to use general knowledge.
        assert "web_search" not in p and "general knowledge" in p'''),
    ('''        assert "ANTHROPIC_API_KEY" in content
        assert "claude -p" in content
        assert "XAI_API_KEY" not in content
        assert "run_grok_queue_headless" not in content''',
     '''        assert "ANTHROPIC_API_KEY" in content
        assert re.search(r'claude(\\.exe)?"? -p', content), "the Claude CLI is invoked"
        assert "XAI_API_KEY" not in content
        assert "run_grok_queue_headless" not in content'''),
])
p = ROOT / "tests/analysis/test_task_queue_grok.py"
s = p.read_text(encoding="utf-8")
if "\nimport re\n" not in s:
    p.write_text(s.replace("import base64\n", "import base64\nimport re\n", 1), encoding="utf-8")

edit("tests/analysis/test_task_queue_automation.py", [], regex=[
    (r"def _fake_install_wrapper\(([^)]*)\)", lambda m: f"def _fake_install_wrapper({m.group(1).rstrip(', ')}, **_kw)"
     if "**" not in m.group(1) else m.group(0)),
])
