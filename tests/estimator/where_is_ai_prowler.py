"""Show which folder the running AI-Prowler is started from, and whether the Estimator is there."""
import subprocess
from pathlib import Path

ps = ("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'ai_prowler|rag_gui|AI-Prowler' } "
      "| ForEach-Object { $_.ProcessId.ToString() + ' | ' + $_.CommandLine }")
out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True).stdout
print("Running AI-Prowler processes:")
print(out.strip() or "(none found)")

print("\nFolders with ai_prowler_mcp.py and whether they have the Estimator:")
home = Path.home()
for base in [home / "Documents", home / "AI-Prowler", home / "OneDrive" / "Documents", Path("C:/AI-Prowler")]:
    if not base.exists():
        continue
    for f in list(base.glob("ai_prowler_mcp.py")) + list(base.glob("*/ai_prowler_mcp.py")) + list(base.glob("*/*/ai_prowler_mcp.py")):
        d = f.parent
        hooked = "_register_estimator" in f.read_text(encoding="utf-8", errors="ignore")
        print(f"  {d}  | estimator folder: {(d / 'estimator').is_dir()} | hook added: {hooked}")
