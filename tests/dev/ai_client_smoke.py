"""Read-only smoke check of the E2E 'AI' client (MCP over /mcp, as Claude):
the AI-Prowler Server as each of the 3 server users, then the personal
install. Calls only read tools. Prints who answered and the first line."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / "gui_jobs_e2e"
SRV = HERE.parent / "gui_jobs_e2e_server"
sys.path[:0] = [str(SHARED), str(SRV)]

from ai_client import AiClient                     # noqa: E402
from api import get_token, local_api_origin, origin_of   # noqa: E402
from safety import Guard                          # noqa: E402


def user_env(name):
    import os
    v = os.environ.get(name, "")
    if v:
        return v
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return str(winreg.QueryValueEx(k, name)[0])
    except Exception:
        return ""


guard = Guard(tier="safe")
cfg = json.loads((SRV / "users.local.json").read_text(encoding="utf-8"))
srv_origin = origin_of(user_env(cfg["url_env"]))
for u in cfg["users"]:
    ai = AiClient(srv_origin, user_env(u["token_env"]), guard, u["key"])
    try:
        who = ai.call("whoami", expect_ok=False)
        print(f"SERVER {u['key']} {u['name']}: {who.splitlines()[0][:120] if who else '(empty)'}")
    except Exception as e:
        print(f"SERVER {u['key']} {u['name']}: FAILED {e}")
ai = AiClient(local_api_origin(), get_token(), guard, "personal-owner")
try:
    r = ai.call("read_job_spreadsheet", {"sheet_name": "Settings", "max_rows": 1}, expect_ok=False)
    print(f"PERSONAL: {r.splitlines()[0][:120]}")
except Exception as e:
    print(f"PERSONAL: FAILED {e}")
