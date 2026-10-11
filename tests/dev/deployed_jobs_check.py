"""Dev helper: is the work copy's Jobs app what's installed / served?

Compares jobs\\index.html and jobs\\sw.js (sha256) in the work copy with
  1. this PC's install  (C:\\Program Files\\AI-Prowler\\jobs\\)
  2. what the personal app serves  (AIPROWLER_JOBS_URL, if set)
  3. what the AI-Prowler Server serves  (the server E2E suite's URL)
and looks for markers of the latest changes. Prints no tokens."""
import hashlib
import json
import os
import ssl
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
INSTALL = Path(r"C:\Program Files\AI-Prowler")
FILES = ("index.html", "sw.js")
MARKERS = ("_reportsRecurringProjections", "Tax 7% ($) =M*0.07", "_reportsIsUnpricedAutoJob",
           "preferredDays")


def user_env(name):
    v = os.environ.get(name, "")
    if v:
        return v
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return str(winreg.QueryValueEx(k, name)[0])
    except OSError:
        return ""


def sha(b):
    return hashlib.sha256(b).hexdigest()[:16]


def fetch(url):
    req = urllib.request.Request(url, headers={
        "Cache-Control": "no-cache",
        # Cloudflare's front door refuses Python's default user-agent (403)
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/128.0 Safari/537.36"})
    with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as r:
        return r.read()


def origin(u):
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def report(where, get):
    print(f"\n== {where}")
    for f in FILES:
        work = (ROOT / "jobs" / f).read_bytes()
        try:
            got = get(f)
        except Exception as e:                       # noqa: BLE001
            print(f"  {f:11} could not read: {str(e)[:160]}")
            continue
        same = "SAME as work copy" if got == work else "DIFFERENT from work copy"
        print(f"  {f:11} sha256={sha(got)} (work {sha(work)})  {same}")
        if got != work:
            a = work.decode("utf-8", "replace").replace("\r\n", "\n").splitlines()
            b = got.decode("utf-8", "replace").replace("\r\n", "\n").splitlines()
            if a == b:
                print("              (only line endings differ)")
            else:
                import difflib
                d = [l for l in difflib.unified_diff(a, b, "work", where, n=0, lineterm="")
                     if not l.startswith(("---", "+++"))]
                print(f"              {len(d)} diff line(s); first ones:")
                for l in d[:16]:
                    print("              " + l[:150])
        if f == "index.html":
            text = got.decode("utf-8", "replace")
            print("  markers:    " + ", ".join(f"{m} {'✓' if m in text else '✗'}" for m in MARKERS))


report(f"this PC's install ({INSTALL})", lambda f: (INSTALL / "jobs" / f).read_bytes())

personal = user_env("AIPROWLER_JOBS_URL").strip()
if personal:
    report("personal app (served)", lambda f: fetch(origin(personal) + "/jobs/" + f))
else:
    print("\n== personal app (served): AIPROWLER_JOBS_URL not set — skipped")

cfg = json.loads((ROOT / "tests" / "gui_jobs_e2e_server" / "users.local.json").read_text(encoding="utf-8"))
srv = user_env(cfg.get("url_env", "AIPROWLER_SRV_URL")).strip()
if srv:
    report("AI-Prowler Server (served)", lambda f: fetch(origin(srv) + "/jobs/" + f))
else:
    print("\n== AI-Prowler Server: URL variable not set — skipped")
