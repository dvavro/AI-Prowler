import pathlib, json

# Read the config to see what's in there
config = pathlib.Path.home() / ".ai-prowler" / "config.json"
txt = config.read_text(encoding='utf-8', errors='replace')
print(txt[:2000])

# Also search entire AI-Prowler directory for any key storage
import os
for root, dirs, files in os.walk(r"C:\Program Files\AI-Prowler"):
    for f in files:
        if f.endswith(('.json','.env','.cfg','.ini','.yaml','.yml','.txt')):
            p = pathlib.Path(root) / f
            try:
                t = p.read_text(encoding='utf-8', errors='replace')
                if 'sk-ant' in t or 'anthropic_api_key' in t.lower():
                    print(f"\n✅ Key found in: {p}")
            except: pass
