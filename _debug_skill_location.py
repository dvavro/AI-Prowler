from pathlib import Path

candidates = [
    Path.home() / ".claude" / "skills" / "ai-prowler-tasks" / "SKILL.md",
    Path.home() / ".claude" / "commands" / "ai-prowler-run-queue.md",
    Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler\.claude\skills\ai-prowler-tasks\SKILL.md"),
    Path(r"C:\Program Files\AI-Prowler\.claude\skills\ai-prowler-tasks\SKILL.md"),
]
for c in candidates:
    print(f"{'EXISTS' if c.exists() else 'missing'}: {c}")

print()
print("=== Contents of %USERPROFILE%\\.claude (if it exists) ===")
home_claude = Path.home() / ".claude"
if home_claude.exists():
    for item in home_claude.rglob("*"):
        print(" ", item)
else:
    print("  (does not exist at all)")

print()
print("=== Contents of Program Files AI-Prowler .claude (if it exists) ===")
pf_claude = Path(r"C:\Program Files\AI-Prowler\.claude")
if pf_claude.exists():
    for item in pf_claude.rglob("*"):
        print(" ", item)
else:
    print("  (does not exist)")

print()
print("=== Is AI-Prowler even installed to Program Files? ===")
pf = Path(r"C:\Program Files\AI-Prowler")
print("Program Files\\AI-Prowler exists:", pf.exists())
if pf.exists():
    for item in sorted(pf.iterdir()):
        print(" ", item.name)
