"""
tests/unit/test_watchdog_cross_session.py
==========================================
Diagnostic + regression tests for the cross-session watchdog detection bug.

BACKGROUND:
  On Windows, os.kill(pid, 0) behaves differently depending on whether the
  caller and target process are in the same Windows session:
    - Same session: succeeds or raises PermissionError
    - Cross-session: raises OSError(WinError 87) OR wraps it as SystemError
      depending on Python version and Windows build

Test IDs
--------
  WCS-01  Diagnose exact exception from os.kill on this machine
  WCS-02  is_running() returns True for live process in same session
  WCS-03  is_running() returns False and cleans PID file for dead PID
  WCS-04  is_running() handles OSError WinError 87 gracefully
  WCS-05  is_running() handles SystemError wrapping WinError 87 gracefully
  WCS-06  is_running() uses tasklist fallback and returns correct result
  WCS-07  stop_daemon() uses taskkill when os.kill fails
  WCS-08  is_running() never raises for any exception type
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

import file_watchdog


# ─────────────────────────────────────────────────────────────────────────────
# WCS-01  Diagnose exact exception from os.kill on this machine
# ─────────────────────────────────────────────────────────────────────────────

def test_wcs01_oskill_exception_diagnosis(capsys):
    """Diagnostic — prints what os.kill raises on this machine. Always passes."""
    pid = os.getpid()
    try:
        os.kill(pid, 0)
        print(f"\nWCS-01: os.kill({pid}, 0) SUCCEEDED (same session)")
    except Exception as e:
        print(f"\nWCS-01 exception type    : {type(e).__name__}")
        print(f"WCS-01 MRO               : {[c.__name__ for c in type(e).__mro__]}")
        print(f"WCS-01 winerror          : {getattr(e, 'winerror', 'N/A')}")
        print(f"WCS-01 str(e)            : {e}")
        print(f"WCS-01 is OSError        : {isinstance(e, OSError)}")
        print(f"WCS-01 is SystemError    : {isinstance(e, SystemError)}")
        print(f"WCS-01 is PermissionError: {isinstance(e, PermissionError)}")
    assert True


# ─────────────────────────────────────────────────────────────────────────────
# WCS-02  is_running() returns True for live process in same session
# ─────────────────────────────────────────────────────────────────────────────

def test_wcs02_is_running_same_session(tmp_path):
    """is_running() must return True when PID is our own process."""
    pid_file = tmp_path / "file_watchdog.pid"
    pid_file.write_text(str(os.getpid()))
    with patch.object(file_watchdog, 'PID_FILE', pid_file):
        result = file_watchdog.is_running()
    assert result is True, "WCS-02 FAIL: returned False for our own PID"


# ─────────────────────────────────────────────────────────────────────────────
# WCS-03  is_running() returns False and cleans up for dead PID
# ─────────────────────────────────────────────────────────────────────────────

def test_wcs03_is_running_dead_pid(tmp_path):
    """is_running() must return False and delete PID file for a dead PID."""
    pid_file = tmp_path / "file_watchdog.pid"
    pid_file.write_text("99999")
    with patch.object(file_watchdog, 'PID_FILE', pid_file):
        result = file_watchdog.is_running()
    assert result is False, "WCS-03 FAIL: returned True for dead PID 99999"
    assert not pid_file.exists(), "WCS-03 FAIL: stale PID file not cleaned up"


# ─────────────────────────────────────────────────────────────────────────────
# WCS-04  is_running() handles OSError WinError 87
# ─────────────────────────────────────────────────────────────────────────────

def test_wcs04_is_running_handles_oserror_87(tmp_path):
    """is_running() must fall through to tasklist when os.kill raises WinError 87."""
    pid_file = tmp_path / "file_watchdog.pid"
    pid_file.write_text(str(os.getpid()))
    err = OSError("The parameter is incorrect")
    err.winerror = 87
    mock_result = MagicMock()
    mock_result.stdout = f'"python.exe","{os.getpid()}","Console","1","50,000 K"\n'
    with patch.object(file_watchdog, 'PID_FILE', pid_file):
        with patch('os.kill', side_effect=err):
            with patch('subprocess.run', return_value=mock_result):
                result = file_watchdog.is_running()
    assert isinstance(result, bool), "WCS-04 FAIL: raised instead of returning bool"
    assert result is True, "WCS-04 FAIL: returned False when tasklist found PID"


# ─────────────────────────────────────────────────────────────────────────────
# WCS-05  is_running() handles SystemError wrapping WinError 87
# ─────────────────────────────────────────────────────────────────────────────

def test_wcs05_is_running_handles_systemerror(tmp_path):
    """is_running() must NOT crash when os.kill raises SystemError.
    This is the EXACT error seen on the AI-Prowler Server machine."""
    pid_file = tmp_path / "file_watchdog.pid"
    pid_file.write_text(str(os.getpid()))
    err = SystemError(
        "<built-in function kill> returned a result with an exception set"
    )
    mock_result = MagicMock()
    mock_result.stdout = f'"python.exe","{os.getpid()}","Console","1","50,000 K"\n'
    with patch.object(file_watchdog, 'PID_FILE', pid_file):
        with patch('os.kill', side_effect=err):
            with patch('subprocess.run', return_value=mock_result):
                try:
                    result = file_watchdog.is_running()
                except SystemError as e:
                    pytest.fail(
                        f"WCS-05 FAIL: is_running() raised SystemError: {e}\n"
                        f"SystemError from os.kill must be caught and handled."
                    )
    assert isinstance(result, bool), "WCS-05 FAIL: did not return bool"


# ─────────────────────────────────────────────────────────────────────────────
# WCS-06  is_running() uses tasklist fallback correctly
# ─────────────────────────────────────────────────────────────────────────────

def test_wcs06_tasklist_fallback(tmp_path):
    """When os.kill fails, is_running() must use tasklist and return True
    if PID appears in output."""
    pid = os.getpid()
    pid_file = tmp_path / "file_watchdog.pid"
    pid_file.write_text(str(pid))
    mock_result = MagicMock()
    mock_result.stdout = f'"python.exe","{pid}","Console","1","50,000 K"\n'
    with patch.object(file_watchdog, 'PID_FILE', pid_file):
        with patch('os.kill', side_effect=SystemError("cross-session")):
            with patch('subprocess.run', return_value=mock_result):
                result = file_watchdog.is_running()
    assert result is True, "WCS-06 FAIL: tasklist found PID but returned False"


# ─────────────────────────────────────────────────────────────────────────────
# WCS-07  stop_daemon() uses taskkill fallback
# ─────────────────────────────────────────────────────────────────────────────

def test_wcs07_stop_daemon_taskkill_fallback(tmp_path):
    """stop_daemon() must use taskkill /F when os.kill fails cross-session."""
    pid_file = tmp_path / "file_watchdog.pid"
    pid_file.write_text("12345")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "SUCCESS: The process with PID 12345 has been terminated."
    with patch.object(file_watchdog, 'PID_FILE', pid_file):
        with patch('os.kill', side_effect=PermissionError("cross-session")):
            with patch('subprocess.run', return_value=mock_result) as mock_run:
                ok, msg = file_watchdog.stop_daemon()
    assert ok is True, f"WCS-07 FAIL: stop_daemon() returned False: {msg}"
    assert "taskkill" in str(mock_run.call_args), (
        "WCS-07 FAIL: stop_daemon() did not call taskkill"
    )


# ─────────────────────────────────────────────────────────────────────────────
# WCS-08  is_running() never raises for any exception type
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("exc", [
    OSError("generic OS error"),
    PermissionError("permission denied"),
    SystemError("system error"),
    SystemError("<built-in function kill> returned a result with an exception set"),
    Exception("unexpected error"),
])
def test_wcs08_is_running_never_raises(tmp_path, exc):
    """is_running() must NEVER raise — always returns bool for any exception."""
    pid_file = tmp_path / "file_watchdog.pid"
    pid_file.write_text(str(os.getpid()))
    mock_result = MagicMock()
    mock_result.stdout = ""
    with patch.object(file_watchdog, 'PID_FILE', pid_file):
        with patch('os.kill', side_effect=exc):
            with patch('subprocess.run', return_value=mock_result):
                try:
                    result = file_watchdog.is_running()
                    assert isinstance(result, bool), (
                        f"WCS-08 FAIL: returned non-bool {result!r} for "
                        f"{type(exc).__name__}"
                    )
                except Exception as e:
                    pytest.fail(
                        "WCS-08 FAIL: is_running() raised " + type(e).__name__ + ": " + str(e) + "\n"
                        "Triggered by " + type(exc).__name__ + ": " + str(exc)
                    )
