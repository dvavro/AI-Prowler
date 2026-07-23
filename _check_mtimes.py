import os, datetime

root = r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler"
paths = [
    r"update_manifest.json",
    r"Output\AI-Prowler_INSTALL.exe",
    r"release-drafts\welcome_ad.json",
    r"release-drafts\notifications.json",
    r"VERSION",
    r"task_queue_automation.py",
]
for p in paths:
    full = os.path.join(root, p)
    if os.path.exists(full):
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(full))
        print(f"{p:45s} mtime={mtime}  size={os.path.getsize(full)}")
    else:
        print(f"{p:45s} MISSING")
