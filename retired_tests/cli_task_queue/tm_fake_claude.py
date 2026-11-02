"""A fake `claude` for the time-machine scheduled-run test — no Claude, no
credits. The scheduled queue .bat runs it exactly where it would run the real
claude.exe:

    "<claude>" -p "<queue prompt>" --mcp-config "%AIP_MCP_CONFIG%" --strict-mcp-config ...

It checks what the real Claude Code would be handed (the --mcp-config file the
.bat got from scheduled_run_mcp_config(), --strict-mcp-config, the
CLAUDE_CODE_OAUTH_TOKEN the .bat read), then connects to the AI-Prowler named
in that config — the running one — and works the queue with the scripted
stand-in (tm_standin_ai). Prints one JSON line, which the .bat saves as
last_headless_run.json, like the real `--output-format json`.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(APP_ROOT))


def main(argv: list[str]) -> int:
    out = {"argv_ok": False}
    try:
        cfg_path = argv[argv.index("--mcp-config") + 1]
        cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
        servers = cfg.get("mcpServers", {})
        entry = servers.get("ai-prowler", {})
        auth = entry.get("headers", {}).get("Authorization", "")
        out.update(
            argv_ok=True,
            mcp_config=cfg_path,
            servers=sorted(servers),
            url=entry.get("url"),
            has_command="command" in entry,
            strict="--strict-mcp-config" in argv,
            prompt_starts=(argv[argv.index("-p") + 1][:60] if "-p" in argv else ""),
            oauth_env=os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "") == os.environ.get("TQ_EXPECT_OAUTH", "?"),
            cwd=os.getcwd(),
        )
        import task_queue_automation as tqa
        import tm_standin_ai as ai
        client = tqa._HttpMCPClient(auth.replace("Bearer ", "", 1), url=entry.get("url"))
        info = client.initialize(timeout=60)
        try:
            run = ai.work_the_queue(lambda n, a: client.call_tool(n, a), os.environ.get("TQ_WHEN", ""))
        finally:
            client.close()
        out.update(server=(info or {}).get("serverInfo", {}).get("name"), done=run["done"],
                   result=f"stand-in Claude ran {len(run['done'])} task(s)")
        print(json.dumps(out))
        return 0
    except Exception as e:                                   # report, don't hide
        out["error"] = f"{type(e).__name__}: {e}"
        print(json.dumps(out))
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
