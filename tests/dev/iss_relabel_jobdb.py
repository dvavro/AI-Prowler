"""One-off (2026-10-02): rename the installer's '[Spreadsheet]' install-log
label to '[JobDB]' — that step only creates the job-database folder and writes
config.json; no spreadsheet is installed anymore. Log text only; prints the
count and keeps the file's own encoding and line endings."""
from pathlib import Path

p = Path(__file__).resolve().parent.parent.parent / "AI-Prowler-Setup.iss"
raw = p.read_bytes()
bom = raw.startswith(b"\xef\xbb\xbf")
text = raw.decode("utf-8-sig")
n = text.count("[Spreadsheet]")
text = text.replace("[Spreadsheet]", "[JobDB]")
p.write_bytes((b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8"))
print(f"renamed {n} '[Spreadsheet]' log label(s) to '[JobDB]' in {p.name}")
