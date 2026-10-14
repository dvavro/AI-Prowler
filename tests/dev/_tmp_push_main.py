import subprocess, pathlib
REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(__file__).with_suffix(".txt")
lines = []
def run(*a):
    p = subprocess.run(["git", *a], cwd=REPO, capture_output=True, text=True)
    lines.append(f"$ git {' '.join(a)}  (rc={p.returncode})\n{p.stdout}{p.stderr}")
    return p
run("branch", "--show-current")
run("status", "--short", "--untracked-files=no")
run("log", "--oneline", "-3")
run("push", "origin", "main")
run("fetch", "origin")
run("rev-parse", "main", "origin/main")
run("status", "-sb", "--untracked-files=no")
OUT.write_text("\n".join(lines), encoding="utf-8")
print("\n".join(lines))
