"""
GUI tests — HTTP server uptime display
=======================================

Tests for the "· up Xh Ym" label added next to the ⬤ Running / ⬤ Stopped
indicator in Settings → Remote Access.

Feature contract
----------------
* The uptime label is blank on a fresh GUI.
* Calling _mark_server_running() starts the ticker and shows "· up <1m".
* Calling _mark_server_running() a SECOND time (double-start) does NOT
  reset the start time — the guard protects elapsed-time continuity.
* Calling _stop_uptime_ticker() clears the label and cancels the timer.
* _fmt_uptime() returns the correct human-readable string at various
  elapsed-time thresholds.

Test IDs follow the project convention: G-UPT-NN.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _pump(gui):
    """Pump the Tk event loop enough to let pending after() callbacks fire."""
    gui.root.update()
    gui.root.update_idletasks()


def _set_start_time(gui, dt: datetime):
    """Directly write the mutable start-time container (bypasses the guard)."""
    gui.app._http_start_time[0] = dt


# ─────────────────────────────────────────────────────────────────────────────
# G-UPT-01  Initial state
# ─────────────────────────────────────────────────────────────────────────────

def test_G_UPT_01_uptime_label_blank_on_fresh_gui(gui):
    """On a freshly constructed GUI the uptime StringVar must be empty.
    The label should be invisible to the user until the server starts."""
    _pump(gui)
    assert gui.app._http_uptime_var.get() == "", (
        "Uptime label must start blank; "
        f"got: {gui.app._http_uptime_var.get()!r}"
    )


def test_G_UPT_01b_start_time_none_on_fresh_gui(gui):
    """The internal start-time container must be None before the server
    has ever been started."""
    _pump(gui)
    assert gui.app._http_start_time[0] is None


# ─────────────────────────────────────────────────────────────────────────────
# G-UPT-02  Server starts → uptime label appears
# ─────────────────────────────────────────────────────────────────────────────

def test_G_UPT_02a_mark_running_sets_uptime_label(gui):
    """Calling _mark_server_running() must set the uptime label to a
    non-empty string starting with '· up'."""
    _pump(gui)
    gui.app._mark_server_running()
    _pump(gui)
    val = gui.app._http_uptime_var.get()
    assert val.startswith("· up"), (
        f"Expected uptime label starting with '· up', got: {val!r}"
    )


def test_G_UPT_02b_mark_running_sets_start_time(gui):
    """After _mark_server_running() the start-time container must hold
    a datetime, not None."""
    _pump(gui)
    gui.app._mark_server_running()
    assert gui.app._http_start_time[0] is not None
    assert isinstance(gui.app._http_start_time[0], datetime)


def test_G_UPT_02c_sub_minute_shows_less_than_1m(gui):
    """A server started just now (< 60 s ago) should show '· up <1m'."""
    _pump(gui)
    gui.app._mark_server_running()
    _pump(gui)
    val = gui.app._http_uptime_var.get()
    assert val == "· up <1m", f"Expected '· up <1m', got: {val!r}"


# ─────────────────────────────────────────────────────────────────────────────
# G-UPT-03  Double-start protection
# ─────────────────────────────────────────────────────────────────────────────

def test_G_UPT_03_double_start_does_not_reset_clock(gui):
    """Calling _mark_server_running() a second time must NOT reset the
    start-time — the guard 'if _http_start_time[0] is None' must hold.

    Scenario: server has been running for 5 minutes, then the keyword
    scanner fires a second time. Elapsed time must not jump back to 0.
    """
    _pump(gui)
    # First start — 5 minutes ago
    five_min_ago = datetime.now() - timedelta(minutes=5)
    _set_start_time(gui, five_min_ago)
    # Simulate ticker having already started by calling _mark_server_running
    # a second time (e.g., the fallback keyword scanner fired again).
    gui.app._mark_server_running()
    _pump(gui)
    # Start time must still be the original one, not datetime.now()
    elapsed = (datetime.now() - gui.app._http_start_time[0]).total_seconds()
    assert elapsed >= 290, (
        "Double-start reset the clock — guard failed. "
        f"Elapsed was only {elapsed:.1f}s (expected ≥ 290 s)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# G-UPT-04  Stop clears the label
# ─────────────────────────────────────────────────────────────────────────────

def test_G_UPT_04a_stop_ticker_clears_label(gui):
    """After _stop_uptime_ticker() the uptime label must be blank."""
    _pump(gui)
    gui.app._mark_server_running()
    _pump(gui)
    assert gui.app._http_uptime_var.get() != "", "Pre-condition: label should be set"
    gui.app._stop_uptime_ticker()
    _pump(gui)
    assert gui.app._http_uptime_var.get() == "", (
        "Uptime label must be blank after stop; "
        f"got: {gui.app._http_uptime_var.get()!r}"
    )


def test_G_UPT_04b_stop_ticker_resets_start_time(gui):
    """After _stop_uptime_ticker() the start-time container must be None
    so the next start gets a fresh clock."""
    _pump(gui)
    gui.app._mark_server_running()
    gui.app._stop_uptime_ticker()
    assert gui.app._http_start_time[0] is None


def test_G_UPT_04c_stop_then_restart_works(gui):
    """Stop followed by a new start must produce a fresh uptime label
    (not a residual from the previous run)."""
    _pump(gui)
    gui.app._mark_server_running()
    gui.app._stop_uptime_ticker()
    _pump(gui)
    # Second start
    gui.app._mark_server_running()
    _pump(gui)
    val = gui.app._http_uptime_var.get()
    assert val.startswith("· up"), f"Expected '· up …' after restart, got: {val!r}"


def test_G_UPT_04d_stop_on_already_stopped_is_safe(gui):
    """Calling _stop_uptime_ticker() when no ticker is running must not
    raise an exception (idempotent stop)."""
    _pump(gui)
    # Never started — should be a no-op
    gui.app._stop_uptime_ticker()
    _pump(gui)
    assert gui.app._http_uptime_var.get() == ""
    assert gui.app._http_start_time[0] is None


# ─────────────────────────────────────────────────────────────────────────────
# G-UPT-05  _fmt_uptime format strings
# ─────────────────────────────────────────────────────────────────────────────

def test_G_UPT_05a_fmt_uptime_sub_minute(gui):
    """Elapsed < 60 s → '· up <1m'."""
    _set_start_time(gui, datetime.now() - timedelta(seconds=30))
    assert gui.app._fmt_uptime() == "· up <1m"


def test_G_UPT_05b_fmt_uptime_minutes_only(gui):
    """Elapsed = 5 m exactly → '· up 5m'."""
    _set_start_time(gui, datetime.now() - timedelta(minutes=5))
    assert gui.app._fmt_uptime() == "· up 5m"


def test_G_UPT_05c_fmt_uptime_59_minutes(gui):
    """Elapsed = 59 m → '· up 59m' (no hours shown)."""
    _set_start_time(gui, datetime.now() - timedelta(minutes=59))
    assert gui.app._fmt_uptime() == "· up 59m"


def test_G_UPT_05d_fmt_uptime_one_hour_exact(gui):
    """Elapsed = 60 m → '· up 1h 0m'."""
    _set_start_time(gui, datetime.now() - timedelta(hours=1))
    assert gui.app._fmt_uptime() == "· up 1h 0m"


def test_G_UPT_05e_fmt_uptime_hours_and_minutes(gui):
    """Elapsed = 2 h 15 m → '· up 2h 15m'."""
    _set_start_time(gui, datetime.now() - timedelta(hours=2, minutes=15))
    assert gui.app._fmt_uptime() == "· up 2h 15m"


def test_G_UPT_05f_fmt_uptime_returns_empty_when_not_started(gui):
    """With start_time = None, _fmt_uptime() must return ''."""
    gui.app._http_start_time[0] = None
    assert gui.app._fmt_uptime() == ""
