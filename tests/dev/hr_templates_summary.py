"""Dev helper (2026-10-12): summary of hr_task_templates.json — onboarding (base)
and offboarding templates: anchor, offset, priority, state rules, FL/CA overrides."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
t = json.loads((ROOT / "hr_task_templates.json").read_text(encoding="utf-8"))
print("top-level keys:", list(t.keys()))
for group in ("base", "offboarding"):
    rows = t.get(group, [])
    print(f"\n== {group}: {len(rows)} templates")
    for r in rows:
        ov = r.get("state_overrides") or {}
        print(f"  {r.get('template_id','?'):10} {str(r.get('due_anchor','start_date')):10} "
              f"{int(r.get('due_offset_days', 0)):+4}d {r.get('priority','MEDIUM'):8} "
              f"{(r.get('assigned_to_role') or 'HR'):9} "
              f"{'state' if r.get('state_specific') else '     '} "
              f"{(r.get('name') or '')[:42]:42} "
              f"FL:{ov.get('FL',{}).get('due_offset_days','-')} CA:{ov.get('CA',{}).get('due_offset_days','-')}"
              .encode("ascii", "backslashreplace").decode("ascii"))
