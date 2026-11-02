"""2026-11-01: move the old CLI / Windows-Scheduled-Task Task Queue tests out of the suite (the code they
test was removed). Kept in retired_tests/cli_task_queue/ for reference, not collected by pytest."""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "retired_tests" / "cli_task_queue"
FILES = [
    "tests/analysis/test_task_queue_automation.py",
    "tests/analysis/test_task_queue_auth_selection.py",
    "tests/analysis/test_task_queue_grok.py",
    "tests/gui/test_task_queue_panel.py",
    "tests/gui/test_task_queue_panel_grok.py",
    "tests/gui/test_task_queue_auth_persist.py",
    "tests/gui_jobs_timemachine/test_tm_task_queue.py",
    "tests/gui_jobs_timemachine/tm_fake_claude.py",
]
FILES = sys.argv[1:] or FILES + ["tests/mcp_tests/test_r051_ai_route_output_and_trust.py"]
DEST.mkdir(parents=True, exist_ok=True)
for f in FILES:
    src = ROOT / f
    if src.exists():
        shutil.move(str(src), str(DEST / src.name))
        print("moved", f)
    else:
        print("not found", f)
