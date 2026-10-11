"""
run_tests_hr_e2e.py — run the AI-Prowler HR end-to-end browser tests.

Runs ONLY when started by hand. Tests click through the REAL installed
HR Admin + Employee Portal that AI-Prowler hosts on this PC.

Usage (from this folder, or double-click the file):
    run_tests_hr_e2e.py                 all tests, visible browser, slowed down
    run_tests_hr_e2e.py --fast          hidden browser, full speed
    run_tests_hr_e2e.py --test "LAY"    only tests whose name contains "LAY"
    run_tests_hr_e2e.py --slow 800      slower (ms per action), easier to watch
    run_tests_hr_e2e.py --no-pause      don't wait for Enter at the end

Every run writes to logs\\run_<date>_<time>\\ :
    run_tests_hr_e2e.log   full log: every step, result, error, and summary
    results.json           machine-readable results
    report\\index.html     click-through report with screenshots / videos / traces
    test-results\\         screenshots, videos (.webm), traces (.zip) per test
    hr_db.snapshot.json    emergency backup of the HR database (NOT auto-restored)
"""
import argparse, datetime, json, os, random, shutil, ssl, subprocess, sys, time
import urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
AIP_CONFIG = os.path.join(HOME, ".ai-prowler", "config.json")
DEFAULTS = {
    "base_url": "https://ap-jamievavroaiprowler-f68efeed.ai-prowler.com",
    "hr_db_path": os.path.join(HOME, ".ai-prowler", "hr", "hr_db.json"),
    "test_employee": {"first_name": "Test", "last_name": "Tester",
                      "email": "jamievavroaiprowler+hrtest@gmail.com"},
    "watch": True,
    "slow_mo_ms": 400,
}

# ─────────────────────────────────────────────────────────────── logging ──
class Log:
    def __init__(self, path):
        self.f = open(path, "a", encoding="utf-8")
        self.secrets = []
    def hide(self, s):
        if s: self.secrets.append(str(s))
    def __call__(self, msg=""):
        for s in self.secrets:
            msg = msg.replace(s, "********")
        line = f"{datetime.datetime.now():%H:%M:%S}  {msg}"
        try: print(line, flush=True)
        except UnicodeEncodeError: print(line.encode("ascii", "replace").decode(), flush=True)
        self.f.write(line + "\n"); self.f.flush()
    def raw(self, text):
        for s in self.secrets:
            text = text.replace(s, "********")
        try: print(text, end="", flush=True)
        except UnicodeEncodeError: print(text.encode("ascii", "replace").decode(), end="", flush=True)
        self.f.write(text); self.f.flush()

# ─────────────────────────────────────────────────────────────── helpers ──
def load_config():
    cfg = json.loads(json.dumps(DEFAULTS))
    p = os.path.join(HERE, "test_config.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            user = json.load(f)
        for k, v in user.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict): cfg[k].update(v)
            else: cfg[k] = v
    return cfg

def read_admin_token():
    """The AI-Prowler bearer token (remote_token) — read from AI-Prowler's own config, never stored here."""
    with open(AIP_CONFIG, encoding="utf-8") as f:
        tok = (json.load(f).get("remote_token") or "").strip()
    if not tok:
        raise RuntimeError(f"No remote_token found in {AIP_CONFIG}")
    return tok

# The public ai-prowler.com address sits behind a web filter that refuses
# requests that identify as "Python-urllib" (403), so identify as a normal browser.
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/129.0 Safari/537.36 AI-Prowler-HR-E2E")

def api(base, path, token, method="GET", body=None, timeout=20):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base.rstrip("/") + "/hr-api" + path, data=data, method=method)
    req.add_header("User-Agent", BROWSER_UA)
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode() or "{}")
        except Exception: return e.code, {}

def page_ok(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA, "Accept": "text/html"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return str(e)

def run(cmd, log, env=None, cwd=HERE):
    """Run a command, stream its output into the log, return the exit code."""
    log(f"$ {cmd}")
    p = subprocess.Popen(cmd, cwd=cwd, env=env, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    for line in p.stdout:
        log.raw("    " + line)
    return p.wait()

def _decode_body(body):
    """Playwright's JSON report stores text attachments base64-encoded — turn them back into text."""
    if not body:
        return body
    try:
        import base64
        return base64.b64decode(body).decode("utf-8")
    except Exception:
        return body

def walk_results(node, out, path=""):
    """Flatten Playwright's results.json into a list of test results."""
    title = node.get("title", "")
    here = f"{path} › {title}" if path and title else (title or path)
    for spec in node.get("specs", []):
        for t in spec.get("tests", []):
            for r in t.get("results", []) or [{}]:
                out.append({
                    "title": spec.get("title", ""), "file": spec.get("file", ""),
                    "status": r.get("status", t.get("status", "unknown")),
                    "duration_s": round((r.get("duration") or 0) / 1000, 1),
                    "errors": [ (e.get("message") or "").strip() for e in (r.get("errors") or []) ],
                    "attachments": [ (a.get("name"), a.get("path")) for a in (r.get("attachments") or []) if a.get("path") ],
                    "summary": _decode_body(next((a.get("body") for a in (r.get("attachments") or []) if a.get("name") == "summary" and a.get("body")), None)),
                })
    for s in node.get("suites", []):
        walk_results(s, out, here)

# ────────────────────────────────────────────────────────────────── main ──
def main():
    ap = argparse.ArgumentParser(description="Run the AI-Prowler HR end-to-end browser tests.")
    ap.add_argument("--fast", action="store_true", help="hidden browser, full speed")
    ap.add_argument("--test", default="", help="only run tests whose name contains this text")
    ap.add_argument("--slow", type=int, default=None, help="milliseconds per action in watch mode (default 400)")
    ap.add_argument("--no-pause", action="store_true", help="don't wait for Enter before closing")
    args = ap.parse_args()

    cfg = load_config()
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = os.path.join(HERE, "logs", f"run_{stamp}")
    os.makedirs(run_dir, exist_ok=True)
    log = Log(os.path.join(run_dir, "run_tests_hr_e2e.log"))
    exit_code = 1
    started = time.time()

    try:
        log("=" * 72)
        log("AI-Prowler HR — end-to-end tests")
        log(f"Run folder : {run_dir}")
        log(f"Target     : {cfg['base_url']}  (the real installed apps)")
        watch = cfg.get("watch", True) and not args.fast
        slow = args.slow if args.slow is not None else cfg.get("slow_mo_ms", 400)
        log(f"Mode       : {'WATCH (visible browser, ' + str(slow) + ' ms per action)' if watch else 'FAST (hidden browser)'}")
        if args.test: log(f"Filter     : tests containing \"{args.test}\"")
        log("=" * 72)

        # 1. Emergency snapshot of the HR database (NOT restored automatically)
        db = cfg["hr_db_path"]
        if os.path.exists(db):
            shutil.copy2(db, os.path.join(run_dir, "hr_db.snapshot.json"))
            log("✓ Saved emergency snapshot of hr_db.json (not auto-restored — see TEST_SPEC 2.4)")
        else:
            log(f"! hr_db.json not found at {db} — no snapshot taken")

        # 2. Admin token from AI-Prowler's own config
        token = read_admin_token()
        log.hide(token)
        log("✓ Read AI-Prowler bearer token from config.json")

        # 3. Pre-flight: is AI-Prowler up?
        base = cfg["base_url"].rstrip("/")
        for name, url in (("HR Portal", base + "/hr_portal/"), ("HR Admin", base + "/hr_admin/")):
            st = page_ok(url)
            if st != 200:
                raise RuntimeError(f"{name} did not load ({url} → {st}). Is AI-Prowler running and deployed?")
            log(f"✓ {name} is up")
        st, data = api(base, "/employees", token)
        if st != 200:
            raise RuntimeError(f"HR API refused the admin token (status {st}). Check AI-Prowler is running.")
        emps = data.get("employees", data) if isinstance(data, dict) else data
        log(f"✓ HR API is up ({len(emps)} employees)")

        # 4. Test Tester account + fresh PIN for this run
        tt = cfg["test_employee"]
        tt_email = tt["email"].strip().lower()
        me = next((e for e in emps if tt_email in {(e.get("personal_email") or "").lower(), (e.get("work_email") or "").lower()}), None)
        if not me:
            log(f"• Test Tester not found — creating it ({tt['email']})")
            st, created = api(base, "/employees", token, "POST", {
                "personal": {"first_name": tt["first_name"], "last_name": tt["last_name"], "personal_email": tt["email"]},
                "employment": {"title": "QA Test Account", "department": "Testing",
                               "start_date": datetime.date.today().isoformat()},
                "compensation": {},
            })
            if st not in (200, 201):
                raise RuntimeError(f"Could not create Test Tester (status {st}): {created}")
            me = created.get("employee", created)
            log(f"✓ Created Test Tester ({me.get('id')})")
        else:
            log(f"✓ Test Tester exists ({me.get('id')})")
        pin = "".join(random.choice("0123456789") for _ in range(8))
        log.hide(pin)
        st, res = api(base, "/portal/set-pin", token, "POST", {"employee_id": me["id"], "pin": pin})
        if st != 200:
            raise RuntimeError(f"Could not set Test Tester's portal PIN (status {st}): {res}")
        log("✓ Set a fresh one-time portal PIN for Test Tester (not saved anywhere)")

        # 5. Playwright installed?
        if run("node --version", log) != 0:
            raise RuntimeError("Node.js is not installed or not on PATH.")
        if not os.path.exists(os.path.join(HERE, "node_modules", "@playwright", "test")):
            log("• First run: installing Playwright (one time, a few minutes)…")
            if run("npm install", log) != 0:
                raise RuntimeError("npm install failed — see log above.")
            if run("npx playwright install chromium", log) != 0:
                raise RuntimeError("Could not download the test browser — see log above.")
            log("✓ Playwright installed")
        else:
            log("✓ Playwright already installed")

        # 6. Run the tests
        env = dict(os.environ)
        env.update({
            "HR_E2E_RUN_DIR": run_dir,
            "HR_E2E_BASE_URL": base,
            "HR_E2E_WATCH": "1" if watch else "0",
            "HR_E2E_SLOW_MO": str(slow),
            "HR_E2E_TT_EMAIL": tt["email"],
            "HR_E2E_TT_PIN": pin,
            "HR_E2E_TT_NAME": f"{tt['first_name']} {tt['last_name']}",
            "HR_E2E_TT_ID": me["id"],
            "HR_E2E_ADMIN_TOKEN": token,          # for HR Admin sign-in + API checks/cleanup (masked in logs)
            "HR_E2E_RUN_ID": stamp.replace("-", "").replace("_", "")[4:12],   # e.g. 09251415 — tags test data
        })
        cmd = "npx playwright test"
        if args.test:
            cmd += f' --grep "{args.test}"'
        log("-" * 72)
        log("Running tests…" + ("  (watch the Chrome window)" if watch else ""))
        log("-" * 72)
        pw_code = run(cmd, log, env=env)

        # 7. Summarize from results.json
        results_path = os.path.join(run_dir, "results.json")
        rows = []
        if os.path.exists(results_path):
            with open(results_path, encoding="utf-8") as f:
                walk_results(json.load(f), rows)
        passed  = [r for r in rows if r["status"] == "passed"]
        failed  = [r for r in rows if r["status"] in ("failed", "timedOut", "interrupted")]
        skipped = [r for r in rows if r["status"] == "skipped"]

        log("=" * 72)
        log("RESULTS")
        log("=" * 72)
        for r in rows:
            mark = {"passed": "PASS", "skipped": "SKIP"}.get(r["status"], "FAIL")
            log(f"[{mark}] {r['title']}  ({r['duration_s']} s)  — {r['file']}")
            if r["summary"]:
                for line in r["summary"].splitlines():
                    log("        " + line)
            if mark == "FAIL":
                for e in r["errors"]:
                    first = "\n".join(e.splitlines()[:12])
                    for line in first.splitlines():
                        log("        ! " + line)
                for name, path in r["attachments"]:
                    if name in ("video", "trace") or (name == "screenshot"):
                        log(f"        {name}: {path}")
        log("-" * 72)
        log(f"{len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped   ·   {round(time.time() - started)} s total")
        cleanup_lines = [l.strip() for r in rows if r["summary"] for l in r["summary"].splitlines() if "CLEANUP" in l]
        if cleanup_lines:
            failed_cleanup = [l for l in cleanup_lines if "FAILED" in l]
            log(f"Cleanup: {len(cleanup_lines) - len(failed_cleanup)} VERIFIED, {len(failed_cleanup)} FAILED")
            for l in failed_cleanup:
                log("        ! " + l)
            if failed_cleanup:
                log("        → re-run the tests (each test sweeps its own leftovers first) or check the log above")
        else:
            log("Cleanup: no test created data this run.")
        log(f"Report : {os.path.join(run_dir, 'report', 'index.html')}")
        log(f"Log    : {os.path.join(run_dir, 'run_tests_hr_e2e.log')}")
        log("Replay a test step by step:  npx playwright show-trace <trace.zip path from above>")
        log("=" * 72)
        exit_code = 0 if (pw_code == 0 and not failed) else 1

    except Exception as e:
        log("=" * 72)
        log(f"STOPPED: {e}")
        log("=" * 72)
        exit_code = 2

    if not args.no_pause and sys.stdin and sys.stdin.isatty():
        try: input("\nPress Enter to close…")
        except Exception: pass
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
