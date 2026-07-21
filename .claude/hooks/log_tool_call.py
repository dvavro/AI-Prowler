#!/usr/bin/env python3
"""
log_tool_call.py — PostToolUse hook for the AI-Prowler autonomous task
runner. Reads the hook event JSON from stdin, appends one line to the
audit log if the tool call was an AI-Prowler MCP tool. Never blocks or
modifies the tool call — this is observation only (exit 0 always).

Referenced from .claude/settings.json's PostToolUse hook.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG_PATH = Path.home() / ".ai-prowler" / "autonomous_run_audit.log"


def main() -> int:
    try:
        event = json.loads(sys.stdin.read() or "{}")
    except Exception:
        # Never let a malformed event crash the hook or block the run.
        return 0

    tool_name = event.get("tool_name", "")
    if not tool_name.startswith("mcp__ai-prowler"):
        return 0  # only log AI-Prowler's own tool calls, not general noise

    tool_input = event.get("tool_input", {})
    success = event.get("tool_response", {}).get("is_error") is not True

    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        # Keep the logged input small — task prompts can be long, and this
        # is an audit trail, not a full transcript.
        input_summary = json.dumps(tool_input)[:200]
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {tool_name} ok={success} input={input_summary}\n")
    except Exception:
        pass  # audit logging must never fail the actual task run

    return 0


if __name__ == "__main__":
    sys.exit(main())
