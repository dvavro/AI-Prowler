"""
fd_tracker.py  -  pytest plugin: track Windows kernel handle count per test.

Finds which tests are leaking OS handles (ChromaDB SQLite/HNSW, openpyxl
workbooks, pdfplumber file handles, etc.) that eventually exhaust the limit
and cause OSError [Errno 24] "Too many open files" late in the suite.

Usage — add to any pytest run:
    run_tests.bat tests\\ -q --tb=no -p fd_tracker --fd-track

Output:
  fd_track.log   — delta per test + running total (written as tests run)
  stdout summary — top leakers at session end

Note: uses psutil.num_handles() (Windows kernel handles), NOT CRT stdio fds.
These are different pools. Errno 24 can come from either; this plugin tracks
kernel handles which is the larger/more likely source in a long test run.
"""
from __future__ import annotations
import os, sys
from pathlib import Path
import pytest

FD_LEAK_WARN = 15          # print warning to stdout if single test leaks this many
TOP_N        = 40          # how many top leakers to show in final summary
LOG_PATH     = Path(__file__).parent.parent / "fd_track.log"

try:
    import psutil as _psutil
    _fd_proc = _psutil.Process(os.getpid())
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False


def _hc() -> int:
    """Current OS handle count for this process."""
    if not _PSUTIL_OK:
        return -1
    try:
        # num_handles() = Windows kernel HANDLEs (file, registry, sync, etc.)
        # This is what actually causes Errno 24 on Windows, not CRT stdio count.
        return _fd_proc.num_handles()
    except Exception:
        return -1


def pytest_addoption(parser):
    parser.addoption(
        "--fd-track",
        action="store_true",
        default=False,
        help="Enable per-test OS handle leak tracking (writes fd_track.log).",
    )


class FdTrackerPlugin:
    def __init__(self, config):
        self._enabled = config.getoption("--fd-track", default=False)
        self._before: dict[str, int] = {}
        self._leaks: list[tuple[int, str]] = []

        if not self._enabled:
            return
        if not _PSUTIL_OK:
            print("\n[fd_tracker] psutil not installed - run: pip install psutil", flush=True)
            self._enabled = False
            return

        self._log = LOG_PATH.open("w", encoding="utf-8", buffering=1)
        self._baseline = _hc()
        self._log.write(f"baseline={self._baseline}  pid={os.getpid()}\n")
        self._log.write(f"{'delta':>6}  {'total':>6}  nodeid\n")
        self._log.write("-" * 110 + "\n")
        print(f"\n[fd_tracker] Tracking handles. baseline={self._baseline}. "
              f"Output: {LOG_PATH}", flush=True)

    def pytest_runtest_setup(self, item):
        if self._enabled:
            self._before[item.nodeid] = _hc()

    def pytest_runtest_teardown(self, item, nextitem):
        if not self._enabled:
            return
        before = self._before.pop(item.nodeid, _hc())
        after  = _hc()
        delta  = after - before
        self._log.write(f"{delta:>+6}  {after:>6}  {item.nodeid}\n")
        if delta >= FD_LEAK_WARN:
            print(f"\n[fd_tracker] LEAK +{delta} handles after: "
                  f"{item.nodeid}  (total={after})", flush=True)
        if delta > 0:
            self._leaks.append((delta, item.nodeid))

    def pytest_sessionfinish(self, session, exitstatus):
        if not self._enabled:
            return
        try:
            final = _hc()
            net   = final - self._baseline
            self._log.write("-" * 110 + "\n")
            self._log.write(f"final={final}  baseline={self._baseline}  net={net:+}\n\n")
            top = sorted(self._leaks, reverse=True)[:TOP_N]
            self._log.write(f"Top {TOP_N} handle leakers:\n")
            for d, n in top:
                self._log.write(f"  {d:>+6}  {n}\n")
            self._log.close()
            print(f"\n[fd_tracker] Session done.")
            print(f"[fd_tracker] final={final}  baseline={self._baseline}  net={net:+}")
            print(f"[fd_tracker] Top 10 leakers:")
            for d, n in top[:10]:
                print(f"             {d:>+6}  {n}")
            print(f"[fd_tracker] Full log: {LOG_PATH}", flush=True)
        except Exception:
            # Never let the tracker crash the session teardown.
            try:
                self._log.close()
            except Exception:
                pass


def pytest_configure(config):
    config.pluginmanager.register(FdTrackerPlugin(config), "fd_tracker_plugin")
