"""One-off: rename the Access-Only Remote test FUNCTIONS test_RA_0n -> test_AO_0n
(the sign-in tests in test_remote_auth.py already use RA-01..05). The first pass
(2026-10-10) renamed the comments and spec rows but missed the names: "_RA" has
no word boundary before RA."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
t = ROOT / "tests" / "gui_remote_e2e" / "test_remote_access_only.py"
s = t.read_text(encoding="utf-8")
n = s.count("def test_RA_0")
t.write_text(s.replace("def test_RA_0", "def test_AO_0"), encoding="utf-8")
print("functions renamed:", n)
