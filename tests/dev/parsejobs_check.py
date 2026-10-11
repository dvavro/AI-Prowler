"""Dev check: run index.html's parseJobs() in node on a read_job_spreadsheet-
shaped block that has Preferred Day(s); print what it parsed."""
import json
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "mcp_tests"))
from test_yearly_projections import _js_function  # noqa: E402

src = (pathlib.Path(__file__).resolve().parents[2] / "jobs" / "index.html").read_text(encoding="utf-8")
raw = """📋 Jobs_Schedule
   1 row(s)

  JobID (JOB-####): JOB-1
  CustomerID (Customers!A): CUST-2026-2
  Customer Name / Company: X
  Service Date: 10/09/2026
  End Date (blank = single-day job): 10/10/2026
  Preferred Day(s): Monday/Wednesday
  Paused: 0
  Start Time: 8:30 AM
  Job Status: Scheduled
"""
script = "\n".join([_js_function(src, "parseJobs"),
                    f"const r = parseJobs({json.dumps(raw)}, 7);",
                    "process.stdout.write(JSON.stringify({pd: r[0].preferredDays, end: r[0].endDate, keys: Object.keys(r[0]).length}));"])
out = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True)
print(out.returncode, out.stdout, out.stderr[:800])
