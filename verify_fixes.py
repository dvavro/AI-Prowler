from pathlib import Path

# Check license for version references
lic = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler\AI-Prowler Setup License.txt")
terms = ["7.0", "8.0", "version", "v7", "v8", "60 tool", "85 tool", "83 tool"]
print("=== LICENSE ===")
for i, line in enumerate(lic.read_text(encoding="utf-8").splitlines(), 1):
    if any(t.lower() in line.lower() for t in terms):
        print(f"{i:4}: {line.rstrip()}")

# Check requirements.txt
req = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler\requirements.txt")
print("\n=== REQUIREMENTS.TXT ===")
print(req.read_text(encoding="utf-8"))

# Check VERSION file
print("\n=== VERSION ===")
ver = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler\VERSION")
print(ver.read_text(encoding="utf-8"))

# Check manifest (look for it)
import os
for f in os.listdir(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler\scripts"):
    print("scripts/", f)
