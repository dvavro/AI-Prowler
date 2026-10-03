"""Compares the Jobs app the server actually serves with the work copy's
jobs\\index.html (deploy check). Run: python check_served_app.py"""
import hashlib
import urllib.request
from pathlib import Path

URL = "https://ap-david-vavro1-00303282.ai-prowler.com/jobs/"
LOCAL = Path(__file__).resolve().parents[2] / "jobs" / "index.html"
MARKERS = ["R-039: just their own name", "R-052: internal bookkeeping rows",
           "R-055 (David 2026-09-28","function _routeOwnDefaultName()", "_isFieldCrewRestricted()) return ''",
           'id="jfCrewPicker"', "function _crewHas(cell, name)", "list_team_members",
           "function _overrunHorizon()", "R-058 overrun"]

req = urllib.request.Request(URL, headers={"Cache-Control": "no-cache", "User-Agent": "deploy-check"})
served = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
local = LOCAL.read_text(encoding="utf-8")
print(f"served: {len(served):,} chars  md5 {hashlib.md5(served.encode()).hexdigest()}")
print(f"local : {len(local):,} chars  md5 {hashlib.md5(local.encode()).hexdigest()}")
for m in MARKERS:
    print(f"  {'OK ' if m in served else 'MISSING'}  {m}")
for ln in served.splitlines():
    if "APP_VERSION" in ln or "CACHE_VERSION" in ln:
        print("  version line:", ln.strip()[:140])
        break
