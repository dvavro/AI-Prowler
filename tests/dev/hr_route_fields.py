"""Dev helper (2026-10-12): for each HR API route, the request fields it reads
(body.get / query.get) and the top-level keys it returns — to write live tests
that send exactly what the apps' forms send. ASCII output."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
body = src[src.index("def _hr_api_route("):]
body = body[:body.index("\ndef ", 10)]
lines = body.splitlines()
starts = [i for i, l in enumerate(lines) if re.search(r'^\s{8}if (?:subpath|.*subpath)', l)]
starts.append(len(lines))
for a, b in zip(starts, starts[1:]):
    head = lines[a].strip()
    m = re.search(r'subpath\s*(?:==|\.startswith\()\s*["\']([^"\']+)["\']', head)
    mm = re.search(r'method\s*==\s*["\'](\w+)["\']', head)
    if not m:
        continue
    blk = "\n".join(lines[a:b])
    reads = sorted(set(re.findall(r'(?:body|b|payload|data)\.get\(["\'](\w+)["\']', blk)))
    qs = sorted(set(re.findall(r'query\.get\(["\'](\w+)["\']', blk)))
    rets = sorted(set(re.findall(r'_hr_json_response\(20\d,\s*\{["\'](\w+)["\']', blk)))
    coll = sorted(set(re.findall(r'db(?:\.setdefault|\.get)?\(?\[?["\'](\w+)["\']', blk)) - {"config"})
    print(f"{(mm.group(1) if mm else '?'):6} {m.group(1):30} body={','.join(reads)[:110]} "
          f"q={','.join(qs)[:40]} ret={','.join(rets)[:50]} db={','.join(coll)[:50]}")
