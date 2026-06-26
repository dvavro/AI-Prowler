"""Debug: probe Worker endpoints using same requests call as the MCP server."""
import json, pathlib
import requests

BASE    = "https://ai-prowler-subscription.david-vavro1.workers.dev"
KEY     = "AP-PERS-808F0151-EE581B55"
INSTALL = "98081eb9d05ac77b"
HDR     = {"User-Agent": "AI-Prowler-MCP/1.0"}

def get(path, label, params=None):
    url = f"{BASE}{path}"
    try:
        r = requests.get(url, params=params, headers=HDR,
                         timeout=10, proxies={"http": None, "https": None})
        print(f"  {label}: HTTP {r.status_code}")
        try:    print(f"  body: {json.dumps(r.json(), indent=2)}")
        except: print(f"  body: {r.text[:400]}")
    except Exception as e:
        print(f"  {label}: ERROR {e}")

print("=== 1. Health ===")
get("/health", "GET /health")

print("\n=== 2. /license/{key}/validate  (what MCP calls) ===")
get(f"/license/{KEY}/validate", "validate", params={"install_id": INSTALL})

print("\n=== 3. /license/{key}/status  (what spec says) ===")
get(f"/license/{KEY}/status", "status", params={"install_id": INSTALL})

print("\n=== 4. config.json ===")
cfg = pathlib.Path.home() / ".ai-prowler" / "config.json"
if cfg.exists():
    c = json.loads(cfg.read_text())
    for k in ("license_key", "plan", "expires_at", "tunnel_domain"):
        print(f"  {k:20s}: {c.get(k)}")
else:
    print("  not found")

print("\n=== 5. license_cache.json ===")
cache = pathlib.Path.home() / ".ai-prowler" / "license_cache.json"
print(cache.read_text()[:800] if cache.exists() else "  not found")

print("\nDone.")
