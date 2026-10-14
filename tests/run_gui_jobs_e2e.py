"""Launcher for the Jobs-app E2E suite (spec §8). Called by
run_tests_gui_jobs_e2e.bat — run that, or:  python tests\\run_gui_jobs_e2e.py --help
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import shutil
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SUITE = TESTS / "gui_jobs_e2e"
ART = SUITE / "artifacts"
KEEP_RUNS = 20

HELP = """
Jobs app end-to-end tests (Playwright + Microsoft Edge, LIVE app, ZTEST data on TODAY's date).
Always watch them with --human (see tests\JOBS_APP_E2E_TEST_SPEC.md section 0 for a command per area).

  run_tests_gui_jobs_e2e.bat                        headless, this window, safe tier
  run_tests_gui_jobs_e2e.bat --human                WATCH it like a person: visible browser, slow clicks,
                                                    key-by-key typing (incl. the login password)
  run_tests_gui_jobs_e2e.bat --human -k AUTH        ...just the login tests, at human speed
  run_tests_gui_jobs_e2e.bat --headed               visible browser at full speed
  run_tests_gui_jobs_e2e.bat --headed --slowmo 500  visible, 0.5 s before every action
  run_tests_gui_jobs_e2e.bat --background           minimized, notification when done
  run_tests_gui_jobs_e2e.bat -k AUTH                only tests whose name matches
  run_tests_gui_jobs_e2e.bat --tier email           also send ONE real route email to the owner
  run_tests_gui_jobs_e2e.bat --tier full            email + one real AI Routing run (credits)
  run_tests_gui_jobs_e2e.bat --server --tier comms  SERVER: real email + SMS, ONLY to David and Vicki
                                                    (max 2 emails + 2 texts per run; AIPROWLER_E2E_COMMS_TO)
  run_tests_gui_jobs_e2e.bat --keep-data            don't clean up (inspect a failure in the app)
  run_tests_gui_jobs_e2e.bat --cleanup-only         only remove leftover ZTEST data, then report
  run_tests_gui_jobs_e2e.bat --browser chrome       use Google Chrome instead of Edge
  run_tests_gui_jobs_e2e.bat --server --human       SERVER MODE: real users (users.local.json + token
                                                    variables) against the AI-Prowler Server's Jobs app
  run_tests_gui_jobs_e2e.bat --remote --human       REMOTE PWA (personal mode): sign-in, files, search,
                                                    permissions, learnings, tasks (REMOTE_PWA_E2E_TEST_SPEC.md)
  run_tests_gui_jobs_e2e.bat --sandbox --human      PERSONAL suite in the time machine's THROWAWAY server:
                                                    empty database, email/SMS caught, real data never touched
                                                    (also: run_tests.bat jobs-sandbox --human)
  ... --sandbox --date 2026-11-02 --human           ...with the server AND browser clocks on that date

Results: tests\\gui_jobs_e2e\\artifacts\\latest\\SUMMARY.txt and report.html
Token:   setx AIPROWLER_JOBS_TOKEN "<Bearer Token from Settings -> Remote Access>"
"""


def _notify(title: str, text: str):
    """Windows toast (best effort; falls back to nothing)."""
    ps = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
        "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
        f"$x=$t.GetElementsByTagName('text');$x.Item(0).AppendChild($t.CreateTextNode('{title}'))>$null;"
        f"$x.Item(1).AppendChild($t.CreateTextNode('{text}'))>$null;"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('AI-Prowler E2E').Show("
        "[Windows.UI.Notifications.ToastNotification]::new($t))"
    )
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _prune():
    runs = sorted(p for p in ART.iterdir() if p.is_dir() and p.name[:8].isdigit())
    for old in runs[:-KEEP_RUNS]:
        shutil.rmtree(old, ignore_errors=True)


def _cleanup_only(run_dir: Path) -> int:
    sys.path.insert(0, str(SUITE))
    from api import ApiClient, get_app_url, get_token, local_api_origin
    from data import TestData
    from safety import Guard
    tok = get_token()
    if not tok:
        print("AIPROWLER_JOBS_TOKEN is not set.")
        return 3
    lines = []
    g = Guard(log=lines.append)
    api = ApiClient(local_api_origin(), tok, g, log=lines.append)
    d = TestData(api, log=lines.append)
    removed = d.sweep("cleanup-only")
    left = d.leftovers()
    msg = (f"Cleanup-only: removed {removed}\n" +
           ("Cleanup: 0 ZTEST rows left ✅" if not left else "LEFT ❌: " + "; ".join(left)))
    (run_dir / "SUMMARY.txt").write_text(msg + "\n", encoding="utf-8")
    (run_dir / "run.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(msg)
    return 0 if not left else 1


def _start_sandbox(a, run_dir: Path, env: dict):
    """--sandbox (David 2026-10-13): run the PERSONAL Jobs suite against the time
    machine's throwaway server instead of the real install. The suite was built
    for "test date = today on a database with no real jobs"; this gives it exactly
    that, any day, with the real database never reachable. The sandbox runs the
    WORK COPY's code (tm_server.py imports ai_prowler_mcp from the repo)."""
    import importlib.util
    os.environ["E2E_RUN_DIR"] = str(run_dir)               # the tm conftest reads it at import
    for p in (TESTS / "gui_jobs_timemachine", TESTS / "gui_jobs_e2e"):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
    spec = importlib.util.spec_from_file_location("tm_sandbox_conftest",
                                                  TESTS / "gui_jobs_timemachine" / "conftest.py")
    tmmod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tmmod)
    day = dt.date.fromisoformat(a.date) if a.date else dt.date.today()
    print(f"[sandbox] starting the time machine's throwaway server — test date {day} …")
    tm = tmmod.TimeMachine(day, "personal").start()
    tm.set_clock(day, dt.datetime.now().strftime("%H:%M"))      # the clock then runs from here
    env.update(AIPROWLER_JOBS_URL=tm.app_url, AIPROWLER_LOCAL_API_ORIGIN=tm.origin,
               AIPROWLER_JOBS_TOKEN=tm.token, E2E_SANDBOX_DATE=day.isoformat(), E2E_SANDBOX_SERVER="1",
               E2E_APP_HOME=str(tm.home),          # the sandbox app's home (photos are saved under it)
               E2E_BROWSER_CLOCK=tm.now().isoformat() if day != dt.date.today() else "")
    print(f"[sandbox] up: {tm.app_url}  (sandbox {tm.home})")
    return tm


def _stop_sandbox(tm, run_dir: Path):
    import json as _json
    try:
        ob = tm.outbox()
        (run_dir / "outbox.json").write_text(_json.dumps(ob, indent=1, ensure_ascii=False), encoding="utf-8")
        print(f"[sandbox] outbox (caught, never sent): {len(ob)} message(s) -> {run_dir / 'outbox.json'}")
    except Exception as e:
        print(f"[sandbox] outbox not saved: {e}")
    tm.stop()
    print("[sandbox] stopped — the throwaway copy is discarded with the run folder")


def main() -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--help", "-h", action="store_true")
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--slowmo", type=int, default=0)
    ap.add_argument("--background", action="store_true")
    ap.add_argument("--tier", choices=["safe", "email", "full", "comms"], default="safe")
    ap.add_argument("--keep-data", action="store_true")
    ap.add_argument("--cleanup-only", action="store_true")
    ap.add_argument("--mobile", action="store_true")
    ap.add_argument("--browser", choices=["msedge", "chrome", "edge"], default="msedge")
    ap.add_argument("--no-open", action="store_true", help="don't open report.html at the end")
    ap.add_argument("--human", action="store_true",
                    help="watch it like a person using it: visible browser, slowed clicks, key-by-key typing")
    ap.add_argument("--type-delay", type=int, default=0, help="ms between typed characters")
    ap.add_argument("--server", action="store_true",
                    help="SERVER-MODE suite (tests\\gui_jobs_e2e_server): real users against the AI-Prowler Server")
    ap.add_argument("--remote", action="store_true",
                    help="REMOTE PWA suite (tests\\gui_remote_e2e): the personal-mode Remote app at /remote/")
    ap.add_argument("--timemachine", action="store_true",
                    help="TIME MACHINE suite (tests\\gui_jobs_timemachine): a throwaway copy of the app "
                         "with a movable clock — walks weeks of work day by day, never touches real data")
    ap.add_argument("--sandbox", action="store_true",
                    help="PERSONAL suite inside the time machine's throwaway server: empty database, "
                         "email/SMS caught, server + browser clocks on the test date — never touches real data")
    ap.add_argument("--date", default="",
                    help="--sandbox: the test date (YYYY-MM-DD, default today)")
    ap.add_argument("-k", dest="k", default="")
    a, extra = ap.parse_known_args()
    if a.help:
        print(HELP)
        return 0
    global SUITE, ART
    if a.tier == "comms" and not a.server:
        print("--tier comms is server-mode only (real email/SMS to David and Vicki) — add --server.")
        return 2
    # --server --timemachine (David 2026-09-29 09:39: "test both the Jobs server
    # and jobs personal modes with the time machine"): the time machine's own
    # throwaway copy runs as a SERVER install (owner, manager, two field crews —
    # all made-up users in the sandbox). It never touches the real server.
    tm_mode = ""
    if a.timemachine:
        tm_mode = "server" if a.server else "personal"
        a.server = False                     # not the live server suite
    if a.server:
        SUITE = TESTS / "gui_jobs_e2e_server"
        ART = SUITE / "artifacts"
    if a.timemachine:
        SUITE = TESTS / "gui_jobs_timemachine"
        ART = SUITE / "artifacts" / tm_mode
    if a.sandbox and (a.server or a.remote or a.timemachine or a.cleanup_only):
        print("--sandbox runs the PERSONAL Jobs suite in a throwaway time-machine server — use it "
              "without --server / --remote / --timemachine / --cleanup-only.")
        return 2
    if a.remote:
        if a.server or a.timemachine or a.tier != "safe":
            print("--remote is its own suite (personal-mode Remote PWA) — use it without "
                  "--server / --timemachine / --tier.")
            return 2
        SUITE = TESTS / "gui_remote_e2e"
        ART = SUITE / "artifacts"
    if a.human:
        # A person watching: visible browser, ~0.6 s before every click/select/
        # keypress, ~0.15 s between typed characters, a short pause around
        # typing. Individual values can still be overridden.
        a.headed = True
        a.slowmo = a.slowmo or 600
        a.type_delay = a.type_delay or 150
    human_env = {"E2E_THINK_MS": "500"} if a.human else {}
    if a.type_delay:
        human_env["E2E_TYPE_DELAY"] = str(a.type_delay)

    ART.mkdir(parents=True, exist_ok=True)
    run_dir = ART / dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True)
    print(f"Run folder: {run_dir}")

    if a.cleanup_only and (a.server or a.remote):
        print("--cleanup-only isn't available with --server / --remote — every run of those suites "
              "sweeps its ZTEST data at the start and end.")
        rc = 2
    elif a.cleanup_only:
        rc = _cleanup_only(run_dir)
    else:
        env = dict(os.environ, E2E_RUN_DIR=str(run_dir), E2E_TIER=a.tier,
                   E2E_KEEP_DATA="1" if a.keep_data else "", PYTHONIOENCODING="utf-8",
                   E2E_TM_MODE=tm_mode, **human_env)
        channel = "msedge" if a.browser in ("msedge", "edge") else "chrome"
        marker = ("jobs_gui_e2e_server" if a.server else
                  "remote_gui_e2e" if a.remote else
                  "jobs_gui_timemachine" if a.timemachine else "jobs_gui_e2e")
        cmd = [sys.executable, "-m", "pytest", str(SUITE), "-m", marker, "-p", "no:cacheprovider",
               "--browser-channel", channel]
        # report.html needs the pytest-html plugin. Found 2026-10-08: after
        # pytest moved to 9.x the plugin was gone and every run died at once
        # with "unrecognized arguments: --html" (exit 4, no tests). The HTML
        # report is a nicety — SUMMARY.txt / run.log are always written — so
        # add it only when the plugin is installed
        # (tests\install_gui_jobs_e2e_deps.bat puts it back).
        import importlib.util as _ilu
        if _ilu.find_spec("pytest_html") is not None:
            cmd += ["--html", str(run_dir / "report.html"), "--self-contained-html"]
        else:
            print("[e2e] pytest-html not installed — skipping report.html (SUMMARY.txt still written)")
        if a.server or a.remote:
            # No traces / videos: they would record the token typed at sign-in
            # (server spec §6.11.3, Remote spec §3.6). The suites take their own
            # masked screenshots.
            cmd += ["--tracing", "off", "--video", "off", "--screenshot", "off"]
        else:
            cmd += ["--tracing", "retain-on-failure", "--video", "retain-on-failure",
                    "--screenshot", "only-on-failure", "--output", str(run_dir / "failures")]
        if a.headed:
            cmd.append("--headed")
        if a.slowmo:
            cmd += ["--slowmo", str(a.slowmo)]
        if a.mobile:
            cmd += ["-k", "mobile" + (f" and ({a.k})" if a.k else "")]
        elif a.k:
            cmd += ["-k", a.k]
        cmd += extra
        tm = _start_sandbox(a, run_dir, env) if a.sandbox else None
        try:
            with open(run_dir / "pytest_output.txt", "w", encoding="utf-8") as out:
                out.write(" ".join(cmd) + "\n\n")
                p = subprocess.Popen(cmd, cwd=str(TESTS.parent), env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
                for line in p.stdout:
                    sys.stdout.write(line)
                    out.write(line)
                rc = p.wait()
        finally:
            if tm is not None:
                _stop_sandbox(tm, run_dir)

    summary = run_dir / "SUMMARY.txt"
    latest = ART / "latest"
    shutil.rmtree(latest, ignore_errors=True)
    latest.mkdir()
    for f in ("SUMMARY.txt", "report.html", "run.log"):
        if (run_dir / f).exists():
            shutil.copy2(run_dir / f, latest / f)
    (latest / "RUN_FOLDER.txt").write_text(str(run_dir) + "\n", encoding="utf-8")
    _prune()

    text = summary.read_text(encoding="utf-8") if summary.exists() else f"(no summary — pytest exit code {rc})"
    print("\n" + "=" * 70 + "\n" + text + "=" * 70)
    first = text.splitlines()[0] if text else ""
    if a.background:
        _notify("AI-Prowler Jobs E2E", first or f"exit {rc}")
    elif (run_dir / "report.html").exists() and not a.no_open:
        try:
            os.startfile(str(run_dir / "report.html"))
        except Exception:
            pass
    return rc


if __name__ == "__main__":
    sys.exit(main())
