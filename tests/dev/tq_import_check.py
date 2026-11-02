"""Import + quick smoke of the API-key-only Task Queue modules (no network, temp home)."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
for m in ("task_queue_automation", "task_queue_gui", "desk_agent_providers", "desk_agent_settings",
          "desk_agent_budget", "desk_agent", "desk_gui_agent", "desk_tools", "setup_wizard"):
    __import__(m)
    print("import ok", m)
import py_compile
for f in ("rag_gui.py", "ai_prowler_mcp.py"):
    py_compile.compile(str(ROOT / f), doraise=True)
    print("compile ok", f)

import task_queue_automation as tqa
from datetime import datetime
tmp = Path(tempfile.mkdtemp())
tqa.CONFIG_PATH = tmp / "cfg.json"
cfg = tqa.load_config()
print("default provider", cfg["provider"], "times", tqa.check_times(cfg))
cfg.update(enabled=True, check_times_per_day=3, schedule_time="07:00", schedule_end_time="19:00")
print(tqa.schedule_display(cfg, now=datetime(2026, 11, 2, 8, 0)))
print("due slot", tqa.due_slot(cfg, datetime(2026, 11, 2, 13, 5)))
print("cost", tqa.run_cost("claude-sonnet-5-5", {"input": 1000, "cache_write": 20000, "cache_read": 100000,
                                                  "output": 2000}, 2))
