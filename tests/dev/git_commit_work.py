"""Dev helper (2026-10-13): commit the V9.2 work on david-work-2026-10-11.
Stages every modified/deleted TRACKED file plus the listed new source/test
files only — never artifacts, backups, scratch files or tests/dev helpers."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NEW_FILES = [
    "tests/analysis/test_task_queue_auth_selection.py",
    "tests/analysis/test_task_queue_grok.py",
    "tests/gui/test_task_queue_auth_persist.py",
    "tests/gui/test_task_queue_panel_grok.py",
    "tests/gui_jobs_e2e_server/test_srv_hr_apps.py",
    "tests/gui_jobs_e2e_server/test_srv_hr_features.py",
    "tests/mcp_tests/test_hr_api_security.py",
    "tests/mcp_tests/test_hr_lifecycle_r090_r091.py",
    "tests/mcp_tests/test_hr_server_only.py",
    "tests/mcp_tests/test_hr_timemachine_flow.py",
    "tests/mcp_tests/test_pwa_layout_structure.py",
    "tests/unit/test_default_off_groups.py",
    "tests/unit/test_python311_pinned.py",
]
MESSAGE = """V9.2: Task Queue Grok/Claude auth, HR lifecycle (R-090/R-091), Jobs app fixes, sandbox E2E

- Task Queue: Claude CLI (subscription) / Anthropic key / Grok (xAI) key; dry run
  checks only what the selected mode needs; auth choice persisted on change
- Links: Muse.ai and Grok.com buttons, wording updates; HR Admin/Portal QR codes
- HR: daily lifecycle job advances offboarding; termination runs the full
  offboarding flow and ends portal access; REST routes require sign-in;
  employees see only their own incidents/documents
- Default-off groups: an existing install is detected even with empty job tables
- Jobs app: board/route drags survive a lost pointer capture; bottom nav is
  back inside #app (was below the screen on phones)
- run_tests.bat jobs-sandbox: personal Jobs E2E in the time machine sandbox
- Tests updated for the 10-05/06 Jobs redesigns; new HR, Task Queue and
  page-structure tests
- Email route: refusal now says "approve the route first: {date} ({crew})"
- release.py MANIFEST_FILES: add setup_wizard.py, startup_log.py and the HR
  apps (hr_scheduler, HR JSONs, hr_admin/, hr_portal/ incl. docs globs) so
  in-app updates deliver them; write_update_manifest() expands globs
- run_tests.bat default run no longer overrides pytest.ini's -m (live Jobs
  E2E suites were being collected); live_worker moved into pytest.ini;
  live-suite conftests no longer force exit 1 when deselected

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011cWt6Zp5mpbeYCA5ziixcU
"""


def git(*args):
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    print(f"$ git {' '.join(args[:3])}{' ...' if len(args) > 3 else ''}\n{r.stdout}{r.stderr}".rstrip())
    if r.returncode:
        sys.exit(r.returncode)
    return r.stdout


branch = git("rev-parse", "--abbrev-ref", "HEAD").strip()
if branch != "david-work-2026-10-11":
    sys.exit(f"refusing: on branch {branch!r}")
missing = [f for f in NEW_FILES if not (ROOT / f).exists()]
if missing:
    sys.exit(f"missing: {missing}")
git("add", "-u")                       # modified + deleted tracked files
git("add", "--", *NEW_FILES)
git("commit", "-m", MESSAGE)
git("log", "--oneline", "-2")
