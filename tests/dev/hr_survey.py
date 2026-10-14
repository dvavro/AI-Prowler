"""Dev helper (2026-10-11): map Jamie's HR apps in the merged work copy — HTTP
routes, auth, mode checks, hr_* tools, catalog entries, GUI section, and the
tests that exercise them. Read-only. ASCII output."""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def p(s=""):
    print(str(s).encode("ascii", "backslashreplace").decode("ascii"))


def grep(rel, pattern, limit=60, ctx=0):
    lines = (REPO / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    rx = re.compile(pattern)
    hits = [i for i, l in enumerate(lines) if rx.search(l)]
    p(f"\n== {rel}  /{pattern}/  {len(hits)} hit(s)")
    for i in hits[:limit]:
        for j in range(max(0, i - ctx), min(len(lines), i + ctx + 1)):
            p(f"  {j + 1:6}: {lines[j].strip()[:170]}")
    if len(hits) > limit:
        p(f"  ... {len(hits) - limit} more")


# HTTP routes + path prefixes for the HR apps
grep("ai_prowler_mcp.py", r'path\.startswith\("/hr|path == "/hr|"/hr-api|/hr_admin|/hr_portal|_HR_PWA|hr_pwa_dir|/hr/', 80)
# mode checks inside HR code
grep("ai_prowler_mcp.py", r"_IS_SERVER_MODE.*hr|hr.*_IS_SERVER_MODE|_hr_require|_hr_auth|_hr_check_token|hr_token|HR_ADMIN_TOKEN|_hr_session", 60)
# the hr_* MCP tools
grep("ai_prowler_mcp.py", r"^def hr_\w+\(", 40)
# where the HR state lives
grep("ai_prowler_mcp.py", r"^_HR_STATE_DIR|^_HR_DB|_hr_load_db\(\) ->|^def _hr_load_db", 10)
# catalog
grep("mcp_tool_catalog.py", r"'hr_|\"hr_|hr_module|'hr'", 40)
# GUI
grep("rag_gui.py", r"(?i)hr admin|hr portal|hr_admin|hr_portal|_hr_|HR Module", 60)
# Jamie's tests
tests = sorted(t.relative_to(REPO).as_posix() for t in (REPO / "tests").rglob("*hr*.py"))
p(f"\n== HR test files ({len(tests)})")
for t in tests:
    txt = (REPO / t).read_text(encoding="utf-8", errors="replace")
    n = len(re.findall(r"^\s*def test_", txt, re.M))
    mode = ("server" if re.search(r"server_mode|_IS_SERVER_MODE\W*=\W*True|mode.*server", txt) else "") + \
           (" personal" if re.search(r"personal", txt) else "")
    p(f"  {t}  ({n} tests){'  mentions: ' + mode if mode else ''}")
