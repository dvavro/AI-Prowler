import subprocess, shutil
from pathlib import Path

REPO = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")

def run(cmd):
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, shell=True)
    return r.stdout.decode("utf-8", errors="replace"), r.stderr.decode("utf-8", errors="replace"), r.returncode

lines = []
gh_path = shutil.which("gh")
lines.append(f"gh CLI on PATH: {gh_path}")
out, err, rc = run("gh --version")
lines.append(f"gh --version rc={rc}\nout={out}\nerr={err}")

out, err, rc = run("gh auth status")
lines.append(f"\ngh auth status rc={rc}\nout={out}\nerr={err}")

out, err, rc = run("git remote -v")
lines.append(f"\ngit remote -v rc={rc}\nout={out}\nerr={err}")

iscc_path = shutil.which("ISCC")
lines.append(f"\nISCC on PATH: {iscc_path}")
for p in [r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe", r"C:\Program Files\Inno Setup 6\ISCC.exe"]:
    lines.append(f"{p} exists: {Path(p).exists()}")

(REPO / "scripts" / "_diff_output.txt").write_text("\n".join(lines), encoding="utf-8")
print("done")
