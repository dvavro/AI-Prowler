"""Dev helper (2026-10-11): after the merge, did any function / line get
duplicated? Compares counts in the merged ai_prowler_mcp.py with origin/main's.
Also: how mcp_tool_catalog marks the hr_* tools on each side. ASCII output."""
import re
import subprocess
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def p(s):
    print(str(s).encode("ascii", "backslashreplace").decode("ascii"))


def show(ref, path):
    return subprocess.run(["git", "-C", str(REPO), "show", f"{ref}:{path}"], capture_output=True,
                          text=True, encoding="utf-8", errors="replace").stdout


merged = (REPO / "ai_prowler_mcp.py").read_text(encoding="utf-8", errors="replace")
theirs = show("origin/main", "ai_prowler_mcp.py")
ours = show("HEAD", "ai_prowler_mcp.py")
needle = "_hros.path.join(_HR_STATE_DIR, doc_root)"
p(f"'{needle}': merged={merged.count(needle)} theirs={theirs.count(needle)} ours={ours.count(needle)}")


def defs(t):
    return Counter(re.findall(r"^def (\w+)\(", t, re.M))


dm, dt_ = defs(merged), defs(theirs)
dups = {k: v for k, v in dm.items() if v > 1}
p(f"functions defined more than once in MERGED: {dups or 'none'}")
p(f"functions defined more than once in THEIRS: { {k: v for k, v in dt_.items() if v > 1} or 'none'}")
p(f"lines: merged={merged.count(chr(10))} theirs={theirs.count(chr(10))} ours={ours.count(chr(10))}")
for k in sorted(dups):
    lines = [i + 1 for i, l in enumerate(merged.splitlines()) if l.startswith(f"def {k}(")]
    p(f"  def {k}: lines {lines}")

cat_t = show("origin/main", "mcp_tool_catalog.py")
cat_m = (REPO / "mcp_tool_catalog.py").read_text(encoding="utf-8")
for name, src in (("theirs", cat_t), ("merged", cat_m)):
    hr = re.findall(r"\('(hr_\w+)',[^)]*?\n?[^)]*?, (PERSONAL|BOTH|SERVER)\b", src)
    p(f"catalog {name}: {len(hr)} hr_* entries, modes {Counter(m for _, m in hr)}")
tier_a_t = re.search(r"_TIER_A_SUPPRESSED\s*=\s*(?:frozenset\()?\{(.*?)\}", theirs, re.S)
p("theirs Tier-A has hr_*: " + str(bool(tier_a_t and "hr_" in tier_a_t.group(1))))
