"""Dev helper (2026-10-11): every entry field in remote\\index.html — static inputs,
textareas, selects, checkboxes, and inputs built in JS strings — and which Remote
E2E test files mention its id. ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
html = (ROOT / "remote" / "index.html").read_text(encoding="utf-8")
tests = {p.name: p.read_text(encoding="utf-8")
         for p in (ROOT / "tests" / "gui_remote_e2e").glob("test_*.py")}
tests.update({p.name: p.read_text(encoding="utf-8")
              for p in (ROOT / "tests" / "gui_remote_e2e").glob("*.py") if not p.name.startswith("test_")})

fields = []
for m in re.finditer(r"<(input|textarea|select)\b([^>]*)>", html, re.I):
    attrs = m.group(2)
    idm = re.search(r"""id=["']([\w-]+)["']""", attrs)
    typ = re.search(r"""type=["']([\w-]+)["']""", attrs)
    cls = re.search(r"""class=["']([^"']+)["']""", attrs)
    line = html.count("\n", 0, m.start()) + 1
    fields.append((line, m.group(1).lower(), (typ.group(1) if typ else ""), idm.group(1) if idm else "",
                   cls.group(1) if cls else ""))
# ids created in JS: getElementById('x') used with .value / .checked
js_ids = set(re.findall(r"getElementById\('([\w-]+)'\)\.(?:value|checked)", html))
static_ids = {f[3] for f in fields if f[3]}
print(f"{len(fields)} input/textarea/select tags; {len(static_ids)} with ids; "
      f"{len(js_ids - static_ids)} more ids read via .value/.checked only in JS")
for line, tag, typ, fid, cls in fields:
    key = fid or cls
    hits = [n for n, t in tests.items() if key and key in t]
    print(f"{line:5} {tag:8} {typ:9} {fid or '(no id)':22} class={cls[:24]:24} tests: {', '.join(hits) or '-- NONE --'}")
print("\nJS-only ids:")
for i in sorted(js_ids - static_ids):
    hits = [n for n, t in tests.items() if i in t]
    print(f"      {i:28} tests: {', '.join(hits) or '-- NONE --'}")
