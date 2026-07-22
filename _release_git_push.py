import subprocess, sys
from pathlib import Path

REPO = Path(r"C:\Users\david\AI-Prowler_V700_to_V800_work\AI-Prowler")

def run(cmd):
    print(f"$ {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    print(r.stdout)
    if r.stderr:
        print(r.stderr, file=sys.stderr)
    if r.returncode != 0:
        print(f"FAILED (rc={r.returncode})")
        sys.exit(r.returncode)
    return r.stdout

run(["git", "add", "-A"])
run(["git", "status", "--short"])
run(["git", "commit", "-m",
     "Correct v8.1.8 -- Added simplification and Automation with AI to the AI Task Queue"])
run(["git", "tag", "-f", "v8.1.8"])
run(["git", "push", "origin", "main"])
run(["git", "push", "-f", "origin", "v8.1.8"])
print("DONE")
