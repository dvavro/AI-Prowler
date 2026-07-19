import subprocess
from pathlib import Path

REPO = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")

def run(cmd):
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, shell=True)
    out = r.stdout.decode("utf-8", errors="replace")
    err = r.stderr.decode("utf-8", errors="replace")
    return out, err

files = [
    "COMPLETE_USER_GUIDE.md",
]
lines = []
for f in files:
    lines.append("=" * 70)
    lines.append(f"DIFF: {f}")
    lines.append("=" * 70)
    out, err = run(f'git diff HEAD -- "{f}"')
    lines.append(f"[len(out)={len(out)}, len(err)={len(err)}]")
    if err.strip():
        lines.append("STDERR: " + err[:1000])
    lines.append(out[:40000])
    lines.append("")

out_path = REPO / "scripts" / "_diff_output.txt"
out_path.write_text("\n".join(lines), encoding="utf-8")
print("wrote", len(lines), "lines to", out_path)
