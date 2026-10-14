"""HR server-only conversion, step 1 (2026-10-11, David): mcp_tool_catalog.py —
the 20 hr_* tools become SERVER-only and toggleable (not locked); the 'hr'
category becomes the optional "HR apps (HR Admin + HR Portal)" group. Checks
before writing. ASCII output."""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
f = REPO / "mcp_tool_catalog.py"
src = f.read_text(encoding="utf-8")

old_cat = '''    CategoryMeta(
        "hr", "HR Admin",
        "HR employee management, task tracking, backups, and compliance. "
        "Always on.",
        locked=True,
    ),'''
new_cat = '''    # 2026-10-11 (David): the HR apps are AI-Prowler SERVER only and optional —
    # this group's tick box in Settings → MCP Tool Configuration (server mode)
    # is the one switch for BOTH HR Admin and HR Portal and all hr_* tools.
    # Off until the owner turns it on (tool_config_store.hr_apps_enabled()).
    CategoryMeta(
        "hr", "HR apps (HR Admin + HR Portal)",
        "Employee records, onboarding tasks, documents, time off, time clock "
        "and HR compliance — the HR Admin app (owners and managers) and the "
        "HR Portal app (employees), plus Claude's hr_* tools. AI-Prowler "
        "server only. Off until you turn it on; one switch covers both apps.",
    ),'''
assert old_cat in src, "hr category block not found"
src = src.replace(old_cat, new_cat)

row_rx = re.compile(r"(\('hr_\w+', 'hr', '[^']*',\n\s+'[^']*', )PERSONAL,\n(\s+)True, \"Part of AI-Prowler's always-on HR Admin feature.\", False, None\)")
src, n = row_rx.subn(r"\1SERVER,\n\2False, None, True, 'Used by the HR Admin / HR Portal apps (server).')", src)
assert n == 20, f"expected 20 hr_* rows, changed {n}"
f.write_text(src, encoding="utf-8")
print(f"catalog: hr category optional + {n} hr_* rows -> SERVER, toggleable")
