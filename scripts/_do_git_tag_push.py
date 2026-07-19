import subprocess
from pathlib import Path

REPO = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")

TAG_MSG = "Release v8.1.4"

def run(cmd, **kw):
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, shell=True, **kw)
    return r.stdout.decode("utf-8", errors="replace"), r.stderr.decode("utf-8", errors="replace"), r.returncode

out, err, rc = run(f'git tag -a v8.1.4 -m "{TAG_MSG}"')
print("TAG rc=", rc, "OUT:", out, "ERR:", err)

out, err, rc = run("git push origin main")
print("\nPUSH main rc=", rc, "OUT:", out, "ERR:", err)

out, err, rc = run("git push origin v8.1.4")
print("\nPUSH tag rc=", rc, "OUT:", out, "ERR:", err)

out, err, rc = run("git log -1 --oneline --decorate")
print("\nLOG:", out)
