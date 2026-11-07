"""
The PAID live agent cost tests (2026-11-03). They spend real API credits on the Agent API Key and work on the
REAL install (with test records that are removed afterwards), so they never run unless asked:

    run_tests.bat live-api-cost                 all five, asks before each one, human mode (visible browser)
    run_tests.bat live-api-cost -k jobs         just one
    run_tests.bat live-api-cost --yes           no questions (someone already agreed to each run)
    run_tests.bat live-api-cost --no-human      no browser

On the AI-Prowler Server the same files run from the owner's private folder: run_live_api_cost_server.bat.
Without AIPROWLER_LIVE_API_COST=1 (set only by those two launchers) every test here is skipped.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ENABLED = os.environ.get("AIPROWLER_LIVE_API_COST", "") == "1"


def _code_root() -> Path:
    env = os.environ.get("AIPROWLER_CODE_DIR", "").strip()
    cands = ([Path(env)] if env else []) + [
        HERE.parent.parent, Path.home() / "Documents" / "AI-Prowler", Path.home() / "AI-Prowler",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "AI-Prowler",
        Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Programs" / "AI-Prowler"]   # the server copy
    for c in cands:
        if (c / "desk_agent.py").exists():
            return c.resolve()
    raise RuntimeError("Can't find AI-Prowler's code — set AIPROWLER_CODE_DIR to the folder with desk_agent.py")


ROOT = _code_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# The real install's paths, captured BEFORE the main test suite's safety fixture (tests/conftest.py) points
# them into a throwaway folder for every test — these tests must use the real Agent API Key, the real run
# records (so the budget counts the spend) and the real task list.
REAL = []
if ENABLED:
    import custom_tasks_manager as _ctm
    import desk_agent_budget as _ab
    import desk_agent_providers as _prov
    import task_queue_automation as _tqa
    for _mod, _names in ((_tqa, ("RUNS_DB_PATH", "SCHED_STATE_PATH", "RUN_LOCK_PATH", "AUDIT_LOG_PATH", "LEGACY_HOME",
                                 "CONFIG_PATH", "STATUS_PATH")),
                         (_ctm, ("CUSTOM_TASKS_PATH", "LEGACY_QUEUE_PATH", "QUEUE_RETIRED_MARKER")),
                         (_prov, ("AGENT_KEY_DIR",)),
                         (_ab, ("STATE_PATH", "send_fn"))):
        for _n in _names:
            if hasattr(_mod, _n):
                REAL.append((_mod, _n, getattr(_mod, _n)))


def pytest_addoption(parser):
    for opt, kw in (("--live-yes", dict(action="store_true", default=False,
                                         help="live cost tests: don't ask before each paid test")),
                    ("--live-human", dict(action="store_true", default=False,
                                          help="live cost tests: show results in a visible browser")),
                    ("--live-dry", dict(action="store_true", default=False,
                                        help="live cost tests: no AI call (free) — try the whole path first"))):
        try:
            parser.addoption(opt, **kw)
        except ValueError:
            pass


def pytest_configure(config):
    config.addinivalue_line("markers", "live_api_cost: PAID live agent tests on the real install (off by default)")


def pytest_collection_modifyitems(config, items):
    skip = pytest.mark.skip(reason="paid live test — run with: run_tests.bat live-api-cost")
    for it in items:
        if HERE in Path(str(it.fspath)).resolve().parents:
            it.add_marker(pytest.mark.live_api_cost)
            if not ENABLED:
                it.add_marker(skip)


@pytest.fixture(autouse=True)
def _the_real_install(monkeypatch):
    for mod, name, val in REAL:
        monkeypatch.setattr(mod, name, val)
    os.environ.pop("AIPROWLER_TEST_STATE_DIR", None)
    yield


@pytest.fixture(autouse=True)
def _ask_first(request):
    """David: 'wait for me to approve the running of each test so I can be present'."""
    if request.config.getoption("--live-yes") or request.config.getoption("--live-dry"):
        yield
        return
    doc = (request.node.function.__doc__ or "").strip().splitlines()
    print("\n" + "#" * 96)
    print(f"  NEXT PAID TEST: {request.node.name}")
    for line in doc[:6]:
        print(f"    {line.strip()}")
    print("#" * 96)
    try:
        ans = input("  Press Enter to run it (spends real API credits), or type s then Enter to skip: ")
    except EOFError:
        pytest.skip("no one at the keyboard to approve it — run with --yes after agreeing to it")
    if ans.strip().lower().startswith("s"):
        pytest.skip("skipped by you")
    yield


@pytest.fixture(scope="session")
def live(request):
    import desk_db
    import desk_agent_budget as ab
    import desk_gui_links
    import desk_rules
    import live_lib
    edition = desk_rules.edition_for_mode(desk_gui_links.mode_of())
    tdb = desk_db.default_db_path()
    desk_db.init_db(tdb)
    ledger = live_lib.Ledger(edition)
    try:                                         # what the Cost Analysis popup predicts right now (free)
        a = ab.analysis(edition)
        ledger.predicted = {"calls_per_day_used": a["calls_per_day_used"], "call_tokens": a["call_tokens"],
                            "complex_share_used": a["complex_share_used"],
                            "estimates": [{k: e[k] for k in ("model", "per_call", "per_day", "per_month")}
                                          for e in a["estimates"]]}
    except Exception as e:  # noqa: BLE001
        ledger.predicted = {"error": str(e)}
    try:
        import desk_alerts
        business = desk_alerts._call("business", default="") or ""
    except Exception:  # noqa: BLE001
        business = ""
    ctx = {"edition": edition, "tdb": tdb, "jobs_db": ab._jobs_db_path(), "business": business, "ledger": ledger,
           "dry": bool(request.config.getoption("--live-dry")),
           "viewer": live_lib.Viewer(request.config.getoption("--live-human"), edition)}
    print(f"\n[live cost] {ledger.host} · edition {edition} · code {ROOT}\n[live cost] results → {ledger.md_path}")
    yield ctx
    print(f"\n[live cost] SESSION TOTAL: ${ledger.total:.5f} in API credits over {len(ledger.rows)} test(s)."
          f"\n[live cost] results: {ledger.md_path}")
