"""Dev helper (2026-10-12): what does the SERVER actually serve at /hr_admin/ and
/hr_portal/? Compares to the work copy (sha256) and checks the new sign-in
fields are there. Uses the suite's User-Agent (Cloudflare blocks Python's).
ASCII output."""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "gui_jobs_e2e"))
sys.path.insert(0, str(ROOT / "tests" / "gui_jobs_e2e_server"))
from api import USER_AGENT  # noqa: E402
from conftest import _load_users  # noqa: E402

url, _users = _load_users()
origin = "/".join(url.split("/")[:3])
for app, marker in (("hr_admin", 'id="auth-name"'), ("hr_portal", 'id="login-name"')):
    req = urllib.request.Request(f"{origin}/{app}/", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
            st = r.status
    except urllib.error.HTTPError as e:
        print(f"{app}: HTTP {e.code} body={e.read()[:200]!r}")
        continue
    except Exception as e:
        print(f"{app}: ERROR {e}")
        continue
    work = (ROOT / app / "index.html").read_bytes()
    same = hashlib.sha256(body).hexdigest() == hashlib.sha256(work).hexdigest()
    print(f"{app}: HTTP {st}, {len(body):,} B served vs {len(work):,} B work copy, "
          f"identical={same}, new sign-in field present={marker.encode() in body}")
