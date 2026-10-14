"""How many offboarding templates apply to a FL employee (and which)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import ai_prowler_mcp as ap  # noqa: E402

t = json.loads((ROOT / "hr_task_templates.json").read_text(encoding="utf-8"))["offboarding"]
ok = [x["template_id"] for x in t if ap._hr_template_applies(x, "FL")]
print(len(ok), ok)
