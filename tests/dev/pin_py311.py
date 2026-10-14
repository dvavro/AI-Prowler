"""One-off (2026-10-11, David: stay on Python 3.11): drop the Python312 /
Python310 fallbacks from the two run_script interpreter finders in
ai_prowler_mcp.py (3.11, else the interpreter AI-Prowler itself runs on), and
make hr_portal/test_live.py 3.11-compatible (no backslash inside an f-string
expression). Checks every change before writing. ASCII output."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# 1. finders
mcp = REPO / "ai_prowler_mcp.py"
src = mcp.read_bytes().decode("utf-8")
nl = "\r\n" if "\r\n" in src else "\n"
n_before = src.count('"Python312"') + src.count('"Python310"')
out, changed = [], 0
lines = src.split(nl)
i = 0
while i < len(lines):
    line = lines[i]
    nxt = lines[i + 1] if i + 1 < len(lines) else ""
    if 'os.path.join(os.environ.get("LocalAppData", ""),' in line and \
            ('"Python312"' in nxt or '"Python310"' in nxt):
        i += 2                                   # drop the 2-line candidate entry
        changed += 1
        continue
    out.append(line)
    i += 1
src2 = nl.join(out)
assert src2.count('"Python312"') == 0 and src2.count('"Python310"') == 0, "fallbacks left"
assert src2.count('"Python311"') >= 2, "the 3.11 entries must stay"
mcp.write_bytes(src2.encode("utf-8"))
print(f"run_script finders: removed {changed} fallback entries ({n_before} references)")

# 2. test_live.py
tl = REPO / "hr_portal" / "test_live.py"
t = tl.read_text(encoding="utf-8")
old1 = """    print(f"Has it-modal div: {'id=\\"it-modal\\"' in html}")"""
old2 = """    print(f"Has fb-type input: {'id=\\"fb-type\\"' in html}")"""
new1 = """    print("Has it-modal div:", 'id="it-modal"' in html)        # 3.11: no backslash in an f-string expression"""
new2 = """    print("Has fb-type input:", 'id="fb-type"' in html)"""
assert old1 in t and old2 in t, "test_live.py lines not found as expected"
t = t.replace(old1, new1).replace(old2, new2)
compile(t, str(tl), "exec")
tl.write_text(t, encoding="utf-8")
print("hr_portal/test_live.py: now compiles on 3.11")
