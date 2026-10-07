import shutil, pathlib

src = pathlib.Path(r"C:\Users\jamie\Documents\AI-Prowler_V910_to_V920\AI-Prowler\hr_portal\index.html")
dst = pathlib.Path(r"C:\Program Files\AI-Prowler\hr_portal\index.html")

shutil.copy2(str(src), str(dst))
print(f"Deployed: {src.stat().st_size} bytes -> {dst}")

# Verify modal exists in deployed file
content = dst.read_text(encoding='utf-8-sig', errors='replace')
if 'openIncidentModal' in content:
    print("✅ openIncidentModal found in deployed file")
else:
    print("❌ openIncidentModal NOT found - something wrong")

if 'incidentModal' in content:
    print("✅ incidentModal div found in deployed file")
else:
    print("❌ incidentModal div NOT found")
