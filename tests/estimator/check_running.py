"""When did the running AI-Prowler tool server start, and did it load the Estimator?"""
import subprocess
from pathlib import Path

ps = ("Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'ai_prowler_mcp.py|rag_gui.py' } | "
      "ForEach-Object { $_.ProcessId.ToString() + ' | started ' + $_.CreationDate.ToString('yyyy-MM-dd HH:mm:ss') + ' | ' + $_.CommandLine }")
print(subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True).stdout.strip()
      or "AI-Prowler isn't running")

print("\nLog lines mentioning the Estimator:")
found = False
for base in (Path.home() / ".ai-prowler", Path.home() / "AI-Prowler", Path(r"C:\Program Files\AI-Prowler")):
    if not base.exists():
        continue
    for f in base.rglob("*.log"):
        try:
            if f.stat().st_size > 50_000_000:
                continue
            lines = [ln.strip() for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines()
                     if "Estimator" in ln or "estimator" in ln]
        except OSError:
            continue
        for ln in lines[-3:]:
            found = True
            print(f"  {f.name}: {ln[:300]}")
if not found:
    print("  (none)")

print("\nImport test from the installed folder:")
r = subprocess.run([r"C:\Users\jamie\AppData\Local\Programs\Python\Python311\python.exe", "-c",
                    "import estimator.mcp_tools.est_tools as t; print(len(t.TOOLS), 'Estimator tools import OK')"],
                   cwd=r"C:\Program Files\AI-Prowler", capture_output=True, text=True)
print(" ", (r.stdout or r.stderr).strip()[-800:])
