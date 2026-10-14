"""Dev helper (2026-10-11): unified diff of wizardNext() (and the multiselect
helpers it uses) between the old hr/index.html (git HEAD) and hr_admin/index.html.
ASCII output."""
import difflib
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
old = subprocess.run(["git", "-C", str(REPO), "show", "HEAD:hr/index.html"], capture_output=True,
                     text=True, encoding="utf-8", errors="replace").stdout
new = (REPO / "hr_admin" / "index.html").read_text(encoding="utf-8", errors="replace")


def fn(text, name):
    m = re.search(r"(async\s+)?function\s+" + name + r"\s*\(", text)
    if not m:
        return []
    i = m.start()
    depth, j, started = 0, text.index("{", i), False
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return text[i:j + 1].splitlines()


for name in ("wizardNext", "renderWizardStep", "toggleMultiselect", "wizardCollect"):
    a, b = fn(old, name), fn(new, name)
    print(f"\n===== {name}: old {len(a)} lines, new {len(b)} lines")
    for line in difflib.unified_diff(a, b, "hr/index.html", "hr_admin/index.html", lineterm="", n=1):
        print(line[:200].encode("ascii", "backslashreplace").decode())
