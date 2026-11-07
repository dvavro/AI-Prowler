"""Check whether the Estimator is installed into the AI-Prowler that runs (Program Files)."""
from pathlib import Path

inst = Path(r"C:\Program Files\AI-Prowler")
mcp = inst / "ai_prowler_mcp.py"
print("installed AI-Prowler:", inst.exists())
print("estimator folder:", (inst / "estimator").is_dir())
print("director folder:", (inst / "estimator" / "director").is_dir())
print("hook in ai_prowler_mcp.py:", mcp.exists() and "_register_estimator" in mcp.read_text(encoding="utf-8", errors="ignore"))
log_dirs = [Path.home() / ".ai-prowler", Path.home() / "AI-Prowler"]
for d in log_dirs:
    for f in sorted(d.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:6]:
        hits = [ln.strip() for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines() if "Estimator tools" in ln]
        if hits:
            print(f"{f.name}: {hits[-1][:300]}")
