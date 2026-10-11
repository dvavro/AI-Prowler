import os, pathlib, json

# Check env var
key = os.environ.get("ANTHROPIC_API_KEY","")
print(f"ANTHROPIC_API_KEY in env: {bool(key)} ({len(key)} chars)")

# Check AI-Prowler config files for stored key
home = pathlib.Path.home()
config_paths = [
    home / ".ai-prowler" / "config.json",
    home / ".ai-prowler" / "settings.json",
    home / "AppData" / "Roaming" / "AI-Prowler" / "config.json",
    home / "AppData" / "Local" / "AI-Prowler" / "config.json",
    pathlib.Path(r"C:\Program Files\AI-Prowler\config.json"),
    pathlib.Path(r"C:\Program Files\AI-Prowler\settings.json"),
    pathlib.Path(r"C:\Program Files\AI-Prowler\.env"),
]
for p in config_paths:
    if p.exists():
        print(f"\nFound: {p}")
        txt = p.read_text(encoding='utf-8', errors='replace')
        if 'anthropic' in txt.lower() or 'api_key' in txt.lower() or 'sk-ant' in txt.lower():
            print("  ✅ Contains Anthropic key reference!")
            # Show snippet without exposing full key
            for line in txt.splitlines():
                if 'anthropic' in line.lower() or 'api_key' in line.lower() or 'sk-ant' in line[:10].lower():
                    print(f"  Line: {line[:60]}...")
        else:
            print(f"  (no anthropic key found, size={len(txt)})")

# Check the main AI-Prowler py for how it loads its own key
main_py = pathlib.Path(r"C:\Program Files\AI-Prowler\ai_prowler_mcp.py")
if main_py.exists():
    txt = main_py.read_text(encoding='utf-8', errors='replace')
    for line in txt.splitlines()[:100]:
        if 'anthropic' in line.lower() or 'api_key' in line.lower():
            print(f"MCP line: {line[:80]}")
