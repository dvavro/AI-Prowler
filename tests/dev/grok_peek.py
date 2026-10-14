"""Dev helper: the Claude invocation line of the queue wrapper, whether the queue
prompts mention pending_tasks.json, and the GUI's Clear Key provider handling."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import task_queue_automation as tqa  # noqa: E402

c = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*", use_api_key=True)
for l in c.splitlines():
    if "-p" in l and ("claude" in l.lower()):
        print("wrapper line:", l[:160].encode("ascii", "backslashreplace").decode("ascii"))
print("QUEUE_RUNNER_PROMPT has pending_tasks.json:", "pending_tasks.json" in tqa.QUEUE_RUNNER_PROMPT)
print("GROK prompt has pending_tasks.json:", "pending_tasks.json" in tqa.GROK_QUEUE_RUNNER_PROMPT)
g = (ROOT / "rag_gui.py").read_text(encoding="utf-8")
i = g.index("def _tqa_clear_api_key():")
print(g[i:i + 1400].encode("ascii", "backslashreplace").decode("ascii"))
j = g.index("def _tqa_selected_provider")
print(g[j:j + 700].encode("ascii", "backslashreplace").decode("ascii"))
