"""Try install_estimator.py on a throwaway copy (never touches Program Files)."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as tmp:
    fake = Path(tmp) / "AI-Prowler"
    fake.mkdir()
    shutil.copy2(ROOT / "ai_prowler_mcp.py.bak1", fake / "ai_prowler_mcp.py")   # original, without the hook
    for run in (1, 2):
        r = subprocess.run([sys.executable, str(ROOT / "install_estimator.py"), str(fake)], capture_output=True, text=True)
        print(f"--- run {run} (rc={r.returncode}) ---\n{r.stdout}{r.stderr}")
    text = (fake / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    print("hook count:", text.count("_register_estimator(mcp)"))
    print("estimator copied:", (fake / "estimator" / "mcp_tools" / "est_tools.py").exists())
    r = subprocess.run([sys.executable, "-c", "import estimator.mcp_tools.est_tools as t; print(len(t.TOOLS), 'tools import OK')"],
                       cwd=str(fake), capture_output=True, text=True)
    print(r.stdout, r.stderr[-500:])
