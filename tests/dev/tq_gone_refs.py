"""Which test files still use Task Queue / CLI names that the 2026-11-01 redesign removed."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import task_queue_automation as tqa  # noqa: E402
import desk_agent_providers as prov  # noqa: E402

gone = re.compile(r"\b(?:tqa|_tqa\w*|t|_t|_tqa_iso)\.([A-Za-z_][A-Za-z0-9_]*)")
pgone = re.compile(r"\bprov\.([A-Za-z_][A-Za-z0-9_]*)")
for p in sorted((ROOT / "tests").rglob("*.py")):
    if ".bak" in p.name or "artifacts" in p.parts:
        continue
    text = p.read_text(encoding="utf-8", errors="replace")
    if "task_queue_automation" not in text and "claude_code" not in text and "desk_agent_providers" not in text:
        continue
    missing = sorted({m for m in gone.findall(text) if not hasattr(tqa, m)} if "task_queue_automation" in text
                     else set())
    pm = sorted({m for m in pgone.findall(text) if not hasattr(prov, m)})
    cc = text.count("claude_code")
    if missing or pm or cc:
        print(f"{p.relative_to(ROOT)}: tqa-missing={missing[:12]}{'...' if len(missing) > 12 else ''} "
              f"({len(missing)}) prov-missing={pm} claude_code={cc}")
