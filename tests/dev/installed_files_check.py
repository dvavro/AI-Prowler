"""Dev helper: are the given work-copy files byte-identical to this PC's install
(C:\\Program Files\\AI-Prowler)? Prints sha256 of each side; no secrets."""
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL = Path(r"C:\Program Files\AI-Prowler")
FILES = sys.argv[1:] or ["ai_prowler_mcp.py", "rag_preprocessor.py", "rag_gui.py",
                         "mcp_tool_catalog.py", r"remote\index.html", r"jobs\index.html",
                         "COMPLETE_USER_GUIDE.md"]
bad = 0
for f in FILES:
    w, i = ROOT / f, INSTALL / f
    if not i.exists():
        print(f"{f:28} NOT INSTALLED")
        bad += 1
        continue
    hw, hi = (hashlib.sha256(p.read_bytes()).hexdigest()[:16] for p in (w, i))
    same = hw == hi
    bad += not same
    print(f"{f:28} work {hw}  installed {hi}  {'SAME' if same else 'DIFFERENT'}")
print("all the same" if not bad else f"{bad} file(s) differ")
sys.exit(1 if bad else 0)
