"""
R-051 (2026-09-28): AI Route result shown as raw JSON.

Found live: the first real server-mode AI Route run (David's token) worked,
but Claude Code printed "Ignoring 2 permissions.allow entries from
.claude/settings.json: this workspace has not been trusted..." ahead of its
JSON. The wrapper merges stderr into the output file, json.loads failed, and
the Jobs app showed the whole raw payload instead of the one-paragraph result.

Fixes: parse_claude_json_output() finds the JSON even with warning lines
around it, and _ensure_workspace_trusted() (run from generate_mcp_config())
marks ~/.ai-prowler trusted in ~/.claude.json so the warning stops.

Run: run_tests.bat tests\\mcp\\test_r051_ai_route_output_and_trust.py -v
"""
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import task_queue_automation as tqa  # noqa: E402

WARNING = ("Ignoring 2 permissions.allow entries from .claude/settings.json: this workspace "
           "has not been trusted. Run Claude Code interactively here once and accept the trust "
           "dialog, or set projects[\"C:/Users/AI-Prowler-Server/.ai-prowler\"]."
           "hasTrustDialogAccepted: true in C:\\Users\\AI-Prowler-Server\\.claude.json.")
RESULT = {"type": "result", "subtype": "success", "is_error": False,
          "usage": {"input_tokens": 20}, "result": "**Result: nothing to plan.** No jobs."}


# ── parser ──────────────────────────────────────────────────────────────────

def test_plain_json_still_parses():
    assert tqa.parse_claude_json_output(json.dumps(RESULT))["result"] == RESULT["result"]


def test_warning_line_before_json_is_skipped():
    raw = WARNING + "\n" + json.dumps(RESULT)
    parsed = tqa.parse_claude_json_output(raw)
    assert parsed is not None
    assert parsed["result"] == RESULT["result"]


def test_noise_before_and_after():
    raw = "warn {not json}\n" + json.dumps(RESULT) + "\nsome trailing line"
    assert tqa.parse_claude_json_output(raw)["subtype"] == "success"


def test_no_json_returns_none():
    assert tqa.parse_claude_json_output("'claude' is not recognized as a command") is None
    assert tqa.parse_claude_json_output("") is None


def test_unrelated_json_object_is_not_taken_as_result():
    assert tqa.parse_claude_json_output('warn {"a": 1}') is None


def test_worker_uses_tolerant_parser():
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index("AI_ROUTING_LAST_RUN_PATH.read_text")
    window = src[i:i + 800]
    assert "parse_claude_json_output(raw)" in window
    assert "json.loads(raw)" not in window


# ── workspace trust ─────────────────────────────────────────────────────────

@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / ".ai-prowler")
    return tmp_path


def _key(home):
    return str(home / ".ai-prowler").replace("\\", "/")


def test_creates_file_with_trust_key(home):
    tqa._ensure_workspace_trusted()
    data = json.loads((home / ".claude.json").read_text(encoding="utf-8"))
    assert data["projects"][_key(home)]["hasTrustDialogAccepted"] is True


def test_keeps_everything_else_in_the_file(home):
    cfg = home / ".claude.json"
    cfg.write_text(json.dumps({
        "numStartups": 7, "oauthAccount": {"x": 1},
        "projects": {"D:/other": {"hasTrustDialogAccepted": False, "allowedTools": ["a"]},
                     _key(home): {"allowedTools": ["b"]}},
    }), encoding="utf-8")
    tqa._ensure_workspace_trusted()
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["numStartups"] == 7 and data["oauthAccount"] == {"x": 1}
    assert data["projects"]["D:/other"] == {"hasTrustDialogAccepted": False, "allowedTools": ["a"]}
    assert data["projects"][_key(home)] == {"allowedTools": ["b"], "hasTrustDialogAccepted": True}
    assert not (home / ".claude.json.aip_tmp").exists()


def test_already_trusted_is_not_rewritten(home):
    cfg = home / ".claude.json"
    original = json.dumps({"projects": {_key(home): {"hasTrustDialogAccepted": True}}})
    cfg.write_text(original, encoding="utf-8")
    tqa._ensure_workspace_trusted()
    assert cfg.read_text(encoding="utf-8") == original


def test_unreadable_file_is_left_alone(home):
    cfg = home / ".claude.json"
    cfg.write_text("{ this is not json", encoding="utf-8")
    tqa._ensure_workspace_trusted()
    assert cfg.read_text(encoding="utf-8") == "{ this is not json"


def test_generate_mcp_config_marks_trust():
    src = (_SRC / "task_queue_automation.py").read_text(encoding="utf-8")
    i = src.index("def generate_mcp_config(")
    assert "_ensure_workspace_trusted()" in src[i:i + 3000]
