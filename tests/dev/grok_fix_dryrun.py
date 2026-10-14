"""2026-10-12: task_queue_automation.dry_run_check() — David's Grok auth-check
block (the "# 6. Auth check" section) is indented 2 spaces too far, so the
module doesn't compile at all. Dedent it; also skip the Claude-Code-only
"AI-Prowler Skill file" check when the queue runs on Grok. ASCII output."""
from pathlib import Path

F = Path(__file__).resolve().parents[2] / "task_queue_automation.py"
raw = F.read_bytes().decode("utf-8")
NL = "\r\n" if "\r\n" in raw else "\n"
lines = raw.replace("\r\n", "\n").split("\n")
start = next(i for i, l in enumerate(lines) if l.startswith("      # 6. Auth check"))
end = next(i for i in range(start, len(lines)) if lines[i].startswith("    all_ok = all("))
fixed = 0
for i in range(start, end):
    if lines[i].startswith("      "):
        lines[i] = lines[i][2:]
        fixed += 1
s = "\n".join(lines)
old = '''    skill_path = AI_PROWLER_HOME / ".claude" / "skills" / "ai-prowler-tasks" / "SKILL.md"
    checks.append({
        "name": "AI-Prowler Skill file",
        "ok": skill_path.exists(),
        "detail": str(skill_path),
    })'''
new = '''    skill_path = AI_PROWLER_HOME / ".claude" / "skills" / "ai-prowler-tasks" / "SKILL.md"
    # 2026-10-12: Claude Code only — a Grok run doesn't use the Skill file.
    if effective_api_key_provider(cfg) != "grok":
        checks.append({
            "name": "AI-Prowler Skill file",
            "ok": skill_path.exists(),
            "detail": str(skill_path),
        })'''
assert s.count(old) == 1
s = s.replace(old, new)
assert "cfg = load_config()" in s[:s.index(new)], "cfg must be loaded before the skill check"
compile(s, str(F), "exec")
F.write_bytes(s.replace("\n", NL).encode("utf-8"))
print(f"dedented {fixed} line(s); Skill-file check skipped for Grok; module compiles")
