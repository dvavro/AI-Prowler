"""Dev helper: print a file (relative to the work copy) as base64 in one line."""
import base64
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
print(base64.b64encode((ROOT / sys.argv[1]).read_bytes()).decode("ascii"))
