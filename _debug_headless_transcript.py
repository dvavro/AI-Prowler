import sys, json
from pathlib import Path

p = Path.home() / ".ai-prowler" / "last_headless_run.json"
print("File exists:", p.exists())
if p.exists():
    print("Size:", p.stat().st_size, "bytes")
    print("Modified:", p.stat().st_mtime)
    raw = p.read_text(encoding="utf-8", errors="replace")
    print("=== RAW CONTENT (first 5000 chars) ===")
    print(raw[:5000])
