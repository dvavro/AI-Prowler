"""Read-only: shows the personal database's email/reminder/route settings rows."""
import os, sqlite3
p = os.path.expanduser(r"~/.ai-prowler/jobs_database/ai_prowler_jobs.db")
conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
for k, v in conn.execute("SELECT key, value FROM settings"):
    if any(w in str(k).lower() for w in ("email", "reminder", "route", "start/end", "home", "workday", "lunch")):
        print(f"{k!r}: {v!r}")
cfg = os.path.expanduser(r"~/.ai-prowler/config.json")
try:
    import json
    c = json.load(open(cfg, encoding="utf-8-sig"))
    print("config home keys:", {k: v for k, v in c.items() if "home" in k.lower() or "owner" in k.lower()})
except Exception as e:
    print("config:", e)
