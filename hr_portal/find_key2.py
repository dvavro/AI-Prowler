import pathlib, os

# Check how ai_prowler_mcp.py calls Claude internally
main = pathlib.Path(r"C:\Program Files\AI-Prowler\ai_prowler_mcp.py")
txt = main.read_text(encoding='utf-8', errors='replace')

# Find any anthropic/claude calls
for i, line in enumerate(txt.splitlines(), 1):
    if any(x in line.lower() for x in ['anthropic', 'claude', 'api_key', 'sk-ant', 'bearer']):
        print(f"Line {i}: {line[:100]}")

# Check Windows registry or app data for key
import winreg
try:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\AI-Prowler")
    for i in range(100):
        try:
            name, val, _ = winreg.EnumValue(key, i)
            if 'api' in name.lower() or 'key' in name.lower() or 'anthropic' in name.lower():
                print(f"Registry: {name} = {str(val)[:20]}...")
        except: break
except Exception as e:
    print(f"Registry not found: {e}")

# Check AppData
for p in [
    pathlib.Path.home() / "AppData/Roaming/AI-Prowler",
    pathlib.Path.home() / "AppData/Local/AI-Prowler",
]:
    if p.exists():
        for f in p.rglob("*"):
            if f.is_file() and f.suffix in ('.json','.env','.cfg'):
                try:
                    t = f.read_text(encoding='utf-8', errors='replace')
                    if 'sk-ant' in t or 'api_key' in t.lower():
                        print(f"Found in AppData: {f}")
                except: pass
