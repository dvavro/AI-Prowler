import subprocess
from pathlib import Path

REPO = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")

def run(cmd):
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, shell=True)
    return r.stdout.decode("utf-8", errors="replace"), r.stderr.decode("utf-8", errors="replace")

lines = []
out, err = run("git tag -n99 -l v8.1.*")
lines.append("TAGS v8.1.*:\n" + out + "\nERR:" + err)

out, err = run("git log -5 --oneline")
lines.append("\n\nRECENT LOG:\n" + out)

out, err = run("git show v8.1.3 --stat -s")
lines.append("\n\nv8.1.3 SHOW:\n" + out + "\nERR:" + err)

(REPO / "scripts" / "_diff_output.txt").write_text("\n".join(lines), encoding="utf-8")
print("done")
