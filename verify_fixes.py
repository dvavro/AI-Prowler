import os

path = r"C:\Program Files\AI-Prowler\rag_gui.py"
terms = ["77", "83 ", "85 ", "quick", "about", "cloudflare", "user guide",
         "help_menu", "section 13", "tools"]

print(f"File size: {os.path.getsize(path):,} bytes")
with open(path, encoding="utf-8", errors="replace") as f:
    for i, line in enumerate(f, 1):
        low = line.lower()
        if any(t.lower() in low for t in terms):
            print(f"{i:6}: {line.rstrip()[:120]}")
