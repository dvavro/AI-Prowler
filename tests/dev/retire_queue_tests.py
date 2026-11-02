"""One-off (2026-11-01): retire the e2e test of the removed pending_tasks.json queue (second pass)."""
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "retired_tests" / "task_queue_file"
DEST.mkdir(parents=True, exist_ok=True)
src = ROOT / "tests" / "e2e" / "test_agentic_tasks_e2e.py"
if src.exists():
    shutil.move(str(src), str(DEST / src.name))
    print("moved", src.name)
