"""Read-only: how many past jobs are still open (would roll over under R-058)."""
import os, sqlite3, datetime, collections
p = os.path.expanduser(r"~/.ai-prowler/jobs_database/ai_prowler_jobs.db")
conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
conn.row_factory = sqlite3.Row
today = datetime.date.today().isoformat()
rows = conn.execute("SELECT job_id, customer_name, service_date, end_date, job_status FROM jobs "
                    "WHERE COALESCE(service_date,'') <> '' AND service_date < ? "
                    "AND LOWER(TRIM(COALESCE(job_status,''))) NOT IN "
                    "('complete','completed','cancelled','canceled','done')", (today,)).fetchall()
print("db:", p)
print("past open jobs:", len(rows))
print("by status:", dict(collections.Counter((r["job_status"] or "(blank)") for r in rows)))
ztest = sum(1 for r in rows if str(r["customer_name"] or "").upper().startswith("ZTEST"))
print("ZTEST among them:", ztest)
for r in sorted(rows, key=lambda r: r["service_date"])[:15]:
    print(" ", r["job_id"], r["service_date"], r["end_date"], r["job_status"], r["customer_name"])
