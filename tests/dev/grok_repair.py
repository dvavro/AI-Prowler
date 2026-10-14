"""2026-10-12: repair task_queue_automation.py after the Grok edits so it compiles
again, then report any remaining syntax error (writes ONLY when the whole file
compiles):
  a. dry_run_check(): "# 6. Auth check" block indented 2 spaces too far
  b. dry_run_check(): Claude-Code-only "AI-Prowler Skill file" check skipped for Grok
  c. run_queue_now(): docstring's closing line ('or a plain-language reason it
     never ran.\"\"\"') and `wrapper_dir = AI_PROWLER_HOME / "manual_run"` lost
ASCII output."""
from pathlib import Path

F = Path(__file__).resolve().parents[2] / "task_queue_automation.py"
raw = F.read_bytes().decode("utf-8")
NL = "\r\n" if "\r\n" in raw else "\n"
s = raw.replace("\r\n", "\n")

# a.
lines = s.split("\n")
start = next(i for i, l in enumerate(lines) if l.startswith("      # 6. Auth check"))
end = next(i for i in range(start, len(lines)) if lines[i].startswith("    all_ok = all("))
for i in range(start, end):
    if lines[i].startswith("      "):
        lines[i] = lines[i][2:]
s = "\n".join(lines)

# b.
old_b = '''    skill_path = AI_PROWLER_HOME / ".claude" / "skills" / "ai-prowler-tasks" / "SKILL.md"
    checks.append({
        "name": "AI-Prowler Skill file",
        "ok": skill_path.exists(),
        "detail": str(skill_path),
    })'''
new_b = '''    skill_path = AI_PROWLER_HOME / ".claude" / "skills" / "ai-prowler-tasks" / "SKILL.md"
    # 2026-10-12: Claude Code only — a Grok run doesn't use the Skill file.
    if effective_api_key_provider(cfg) != "grok":
        checks.append({
            "name": "AI-Prowler Skill file",
            "ok": skill_path.exists(),
            "detail": str(skill_path),
        })'''
assert s.count(old_b) == 1
s = s.replace(old_b, new_b)

# c.
old_c = '''    Returns (success, detail) — detail is either the tail of the
    session's real output (truncated to keep dialog boxes reasonable)
    _provider_now = _normalize_provider(api_key_provider) if use_api_key else "oauth"'''
new_c = '''    Returns (success, detail) — detail is either the tail of the
    session's real output (truncated to keep dialog boxes reasonable)
    or a plain-language reason it never ran."""
    _provider_now = _normalize_provider(api_key_provider) if use_api_key else "oauth"'''
assert s.count(old_c) == 1
s = s.replace(old_c, new_c)
old_c2 = '''    rotate_audit_log()
    wrapper_path = install_wrapper_script(
        wrapper_dir, mcp_config_path, allowed_tools,
        notify_on_complete, notify_method, use_api_key,
        api_key_provider=api_key_provider)'''
new_c2 = '''    rotate_audit_log()

    wrapper_dir = AI_PROWLER_HOME / "manual_run"
    wrapper_path = install_wrapper_script(
        wrapper_dir, mcp_config_path, allowed_tools,
        notify_on_complete, notify_method, use_api_key,
        api_key_provider=api_key_provider)'''
assert s.count(old_c2) == 1
s = s.replace(old_c2, new_c2)

try:
    compile(s, str(F), "exec")
except SyntaxError as e:
    ls = s.split("\n")
    print(f"STILL BROKEN at line {e.lineno}: {e.msg}  (nothing written)")
    for n in range(max(1, e.lineno - 6), min(len(ls), e.lineno + 3) + 1):
        print(f"  {n:6}: {ls[n - 1][:150]}".encode("ascii", "backslashreplace").decode("ascii"))
    raise SystemExit(1)
F.write_bytes(s.replace("\n", NL).encode("utf-8"))
print("repaired: auth-check indent, Skill check (not for Grok), run_queue_now docstring + wrapper_dir — compiles")
