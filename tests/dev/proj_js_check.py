"""Dev check: run _calRecurringProjections from a given index.html copy in node
for a Bi-Monthly customer (last 2026-10-01, today 2026-10-08); print dates."""
import json
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "mcp_tests"))
from test_yearly_projections import _js_function  # noqa: E402

src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
cust = {"Company Name": "X", "CustomerID (CUST-####)": "C1", "Status Active/Inactive": "Active",
        "Frequency": "Bi-Monthly", "Last Service Date": "2026-10-01"}
script = "\n".join([
    "const _RD = Date; class FD extends _RD { constructor(...a) { if (a.length) super(...a);"
    " else super(2026, 9, 8); } } globalThis.Date = FD;",
    _js_function(src, "parseJobDate"), _js_function(src, "_dkey"),
    _js_function(src, "_calRecurringProjections"),
    f"process.stdout.write(JSON.stringify(_calRecurringProjections([{json.dumps(cust)}]).map(p => p.date)));"])
print("node:", shutil.which("node"))
out = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True)
print(out.returncode, out.stdout[:300], out.stderr[:300])
