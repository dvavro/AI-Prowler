"""
tests/mcp_tests/test_voice_chat_parity.py
=========================================
2026-10-23 (David): "voice control [is] treated the same as text in the chat
window for all MCP tools and for all PWA app tools" — the Jobs and Remote apps
are the visual check, and the AI can be told (typed or spoken, e.g. while
driving) to do anything the apps do. HR stays manual entry (decision, same day).

Guards:
  A. no tool description tells the AI to stay away ("PWA-button-only",
     "not applicable", "used by pasted prompts");
  B. every non-HR tool with a docstring has spoken/typed examples;
  C. everything the Jobs app (/pwa-api, both modes) and the Remote app
     (/remote-api) can call is a real MCP tool the AI can call too;
  D. "plan my week" / "route me for today" work without pasting, and approval
     can be given in the chat (read back first, then a clear yes);
  E. no description points the AI at a removed tool.
Source-level checks — nothing is started, nothing touches real data.
"""
from __future__ import annotations

import ast
import re
import string
from pathlib import Path

import pytest

SRC_PATH = Path(__file__).resolve().parents[2] / "ai_prowler_mcp.py"
SRC = SRC_PATH.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _tools() -> dict:
    out = {}
    for n in ast.walk(TREE):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                any("mcp.tool" in ast.unparse(d) for d in n.decorator_list):
            out[n.name] = ast.get_docstring(n)
    return out


TOOLS = _tools()


def _set_literal(name: str) -> set:
    for n in ast.walk(TREE):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return {e.value for e in ast.walk(n.value) if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    raise AssertionError(f"{name} not found in ai_prowler_mcp.py")


def test_tool_count_sane():
    assert len(TOOLS) > 100


@pytest.mark.parametrize("phrase", ["PWA-button-only", "PWA-only tool", "button-only tool",
                                    "not applicable", "used by pasted"])
def test_A_no_description_keeps_the_ai_away(phrase):
    bad = sorted(name for name, doc in TOOLS.items() if doc and phrase.lower() in doc.lower())
    assert not bad, f"these tool descriptions say '{phrase}': {bad}"


def test_B_every_non_hr_tool_has_spoken_examples():
    missing = sorted(name for name, doc in TOOLS.items()
                     if doc and not name.startswith("hr_")
                     and not re.search(r"Voice examples?:|Examples?:", doc))
    assert not missing, f"no spoken/typed examples: {missing}"


@pytest.mark.parametrize("allow_list", ["_srv_pa_allowed", "_allowed_tools", "_REMOTE_ALLOWED"])
def test_C_everything_the_apps_call_is_an_ai_tool(allow_list):
    names = {x for x in _set_literal(allow_list) if re.fullmatch(r"[a-z_0-9]+", x)}
    assert len(names) > 20, (allow_list, len(names))
    not_tools = sorted(names - set(TOOLS))
    assert not not_tools, f"{allow_list} lists names that are not MCP tools: {not_tools}"


def test_D1_route_and_week_tools_say_how_to_use_them_by_voice():
    for name in ("get_ai_route_prompt", "get_week_plan_prompt"):
        doc = TOOLS[name]
        assert "From chat or voice" in doc and "nobody needs to copy" in doc, name
    assert '"Route me for today"' in TOOLS["get_ai_route_prompt"]
    assert '"Plan my week"' in TOOLS["get_week_plan_prompt"]
    assert "clearly said yes" in TOOLS["apply_week_moves"]


def test_D2_how_to_use_explains_voice():
    i = SRC.index("NOTE - voice and chat (2026-10-23)")
    block = SRC[i:i + 900]
    for s in ("get_ai_route_prompt(route_date)", "get_week_plan_prompt(week_start)",
              "approve_route_schedule", "clearly says yes"):
        assert s in block, s


def test_D3_week_prompt_lets_me_approve_in_the_chat():
    i = SRC.index("def get_week_plan_prompt(")
    body = SRC[i:SRC.index("\n@mcp.tool()", i)]
    # the code really goes into the prompt (an f-string), not a literal "{code}"
    assert 'f"I name), call apply_week_moves(proposal_code=\\"{code}\\"' in body
    assert 'f"those jobs; if I say no, call dismiss_week_proposal(proposal_code=\\"{code}\\")' in body
    assert "until I approve it (in the Jobs app or in this chat)" in body


def test_D4_route_prompt_approval_by_saying_yes():
    i = SRC.index("_RUN_AI_ROUTING_PROMPT_TEMPLATE = (")
    j = SRC.index("\n)\n", i)
    tmpl = ast.literal_eval(SRC[i + len("_RUN_AI_ROUTING_PROMPT_TEMPLATE = "):j + 2])
    fields = {f for _, f, _, _ in string.Formatter().parse(tmpl) if f}
    text = tmpl.format(**{f: "" for f in fields} | {"route_date": "2026-10-23", "crew_arg": ""})
    assert 'approve_route_schedule(route_date="2026-10-23")' in text
    assert "telling you yes in this chat" in text
    assert "listening, not reading" in text


def test_E_no_description_points_at_a_removed_tool():
    for name, doc in TOOLS.items():
        assert not doc or "sync_due_tasks_to_queue" not in doc, name
