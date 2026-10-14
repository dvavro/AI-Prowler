"""Dev helper (2026-10-13): find the nearest Monday on/after today whose E2E
sandbox window (date-3 .. date+7, the personal suite's safety window) has NO
non-test jobs in the REAL jobs database. Read-only; prints dates only."""
import datetime as dt
import sqlite3
from pathlib import Path

db = Path.home() / ".ai-prowler" / "jobs_database" / "ai_prowler_jobs.db"
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
cols = [r[1] for r in con.execute("PRAGMA table_info(jobs)")]
date_col = next(c for c in cols if c.lower().replace(" ", "_") in ("service_date", "date", "scheduled_date")) \
    if any(c.lower().replace(" ", "_") in ("service_date", "date", "scheduled_date") for c in cols) else None
name_col = next((c for c in cols if "customer" in c.lower() and "name" in c.lower()), None)
print("date column:", date_col, "| name column:", name_col)
dates = set()
for d, n in con.execute(f'SELECT "{date_col}", "{name_col}" FROM jobs'):
    if not d or (n or "").startswith("ZTEST"):
        continue
    s = str(d)[:10]
    try:
        if "/" in s:
            m, dd, y = str(d).split("/")[:3]
            s = f"{int(y[:4]):04d}-{int(m):02d}-{int(dd):02d}"
        dates.add(dt.date.fromisoformat(s))
    except Exception:
        pass
con.close()
today = dt.date.today()
d = today + dt.timedelta(days=(7 - today.weekday()) % 7)
for _ in range(80):
    window = {d + dt.timedelta(days=i) for i in range(-3, 8)}
    if not (window & dates):
        print("empty sandbox Monday:", d.isoformat(), "| real jobs in the next 90 days:",
              sum(1 for x in dates if today <= x <= today + dt.timedelta(days=90)))
        break
    d += dt.timedelta(days=7)
else:
    print("no empty week found in the next 80 weeks")
