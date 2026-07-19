import json
from pathlib import Path
REPO = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")
for f in ["release-drafts/notifications.json", "release-drafts/welcome_ad.json"]:
    try:
        json.load(open(REPO / f, encoding="utf-8"))
        print(f, "OK")
    except Exception as e:
        print(f, "FAIL", e)
