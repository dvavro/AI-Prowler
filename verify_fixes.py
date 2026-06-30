import shutil, sys
from pathlib import Path
src  = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler\rag_gui.py")
dest = Path(r"C:\Program Files\AI-Prowler\rag_gui.py")
try:
    shutil.copy2(str(src), str(dest))
    print(f"✅ Copied rag_gui.py ({src.stat().st_size:,} bytes)")
except PermissionError:
    print(f"❌ Permission denied — copy manually"); sys.exit(1)
