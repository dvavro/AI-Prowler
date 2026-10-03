"""One-off (2026-10-02): restore README.md into the work folder from the
installed copy (it went missing from the work folder; GitHub's front page
needs it). Refuses to overwrite an existing README.md."""
import shutil
from pathlib import Path

src = Path(r"C:\Program Files\AI-Prowler\README.md")
dst = Path(__file__).resolve().parent.parent.parent / "README.md"
if dst.exists():
    print(f"{dst} already exists — not overwritten")
else:
    shutil.copy2(src, dst)
    print(f"restored {dst} ({dst.stat().st_size:,} bytes) from {src}")
