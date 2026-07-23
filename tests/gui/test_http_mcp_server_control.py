"""
tests/gui/test_http_mcp_server_control.py

Regression coverage for the v8.1.7 HTTP MCP Server fix: the health-check
LED reconciliation, PID discovery, and verified-kill helpers.

WHY THIS FILE EXISTS
---------------------
None of this code (_reconcile_http_led, _http_health_check,
_find_pid_on_port, _kill_pid_verified, _start_http_server,
_stop_http_server, _force_kill_port) was reachable from ANY test in the
suite before v8.1.8. As a result, the entire block was silently deleted
from the working tree at some point before a session on 2026-07-22, and
the full ~1980-test release gate still reported 100% green -- nothing
imported or called any of it, so nothing could fail. The code was
restored from the v8.1.7 git tag. This file exists so that class of
regression -- a whole feature quietly vanishing with zero test failures
-- can't happen invisibly again for this panel.

SAFETY: every test here runs against the isolated `gui` fixture (temp
ChromaDB/config dirs, no real subprocess/network/socket calls reach the
user's actual machine). subprocess.run/Popen are patched by the autouse
_silence_subprocess fixture in conftest.py; individual tests further
override subprocess.run, socket.socket, and urllib.request.urlopen with
fakes as needed. Nothing in this file starts a real HTTP server, spawns
a real process, or touches a real network port -- confirmed safe to run
against a machine with AI-Prowler installed and running.
"""
from __future__ import annotations

import socket
import subprocess
import threading
import urllib.request
from unittest.mock import MagicMock

import pytest


def _pump(gui):
    gui.root.update()
    gui.root.update_idletasks()


def _sync_thread(monkeypatch):
    """Same pattern already established in test_task_queue_panel.py: make
    threading.Thread run its target synchronously instead of spawning a
    real thread, so background-thread code becomes testable without
    races or sleeps."""
    monkeypatch.setattr(
        threading, "Thread",
        lambda target, daemon: type("T", (), {"start": lambda self: target()})()
    )


# ═════════════════════════════════════════════════════════════════════════
# _http_health_check — the actual liveness probe
# ═════════════════════════════════════════════════════════════════════════

def test_health_check_success_returns_true_with_status_detail(gui, monkeypatch):
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.__enter__ = lambda self: fake_resp
    fake_resp.__exit__ = lambda self, *a: False
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: fake_resp)

    alive, detail = gui.app._http_health_check(8000)
    assert alive is True
    assert "200" in detail


def test_health_check_failure_returns_false_with_exception_detail(gui, monkeypatch):
    def _boom(url, timeout):
        raise ConnectionRefusedError("nobody home")
    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    alive, detail = gui.app._http_health_check(8000)
    assert alive is False
    assert "ConnectionRefusedError" in detail


# ═════════════════════════════════════════════════════════════════════════
# _find_pid_on_port — tracked-proc / netstat / socket fallback chain
# ═════════════════════════════════════════════════════════════════════════

def test_find_pid_prefers_tracked_process_when_alive(gui):
    tracked = MagicMock()
    tracked.poll.return_value = None   # still running
    tracked.pid = 4242
    gui.app._http_server_proc = tracked

    pid, source = gui.app._find_pid_on_port(8000)
    assert pid == 4242
    assert source == "tracked HTTP server process"
    gui.app._http_server_proc = None  # cleanup


def test_find_pid_falls_through_to_netstat_when_untracked(gui, monkeypatch):
    gui.app._http_server_proc = None
    netstat_out = MagicMock()
    netstat_out.stdout = (
        "  TCP    0.0.0.0:8000    0.0.0.0:0    LISTENING    9999\n"
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: netstat_out)

    pid, source = gui.app._find_pid_on_port(8000)
    assert pid == 9999
    assert source == "found via netstat"


def test_find_pid_netstat_timeout(gui, monkeypatch):
    gui.app._http_server_proc = None

    def _raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="netstat", timeout=20)
    monkeypatch.setattr(subprocess, "run", _raise_timeout)

    pid, source = gui.app._find_pid_on_port(8000)
    assert pid is None
    assert source == "netstat timed out"


def test_find_pid_netstat_generic_error(gui, monkeypatch):
    gui.app._http_server_proc = None

    def _raise(*a, **kw):
        raise OSError("netstat not found")
    monkeypatch.setattr(subprocess, "run", _raise)

    pid, source = gui.app._find_pid_on_port(8000)
    assert pid is None
    assert source.startswith("netstat error")


def test_find_pid_socket_fallback_port_in_use(gui, monkeypatch):
    gui.app._http_server_proc = None
    empty = MagicMock()
    empty.stdout = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: empty)

    fake_sock = MagicMock()
    fake_sock.__enter__ = lambda self: fake_sock
    fake_sock.__exit__ = lambda self, *a: False
    fake_sock.connect_ex.return_value = 0   # 0 == connection succeeded
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: fake_sock)

    pid, source = gui.app._find_pid_on_port(8000)
    assert pid is None
    assert source == "port in use, PID unknown"


def test_find_pid_socket_fallback_port_free(gui, monkeypatch):
    gui.app._http_server_proc = None
    empty = MagicMock()
    empty.stdout = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: empty)

    fake_sock = MagicMock()
    fake_sock.__enter__ = lambda self: fake_sock
    fake_sock.__exit__ = lambda self, *a: False
    fake_sock.connect_ex.return_value = 111   # nonzero == connection failed
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: fake_sock)

    pid, source = gui.app._find_pid_on_port(8000)
    assert pid is None
    assert source == "port free"


# ═════════════════════════════════════════════════════════════════════════
# _kill_pid_verified — taskkill + port-polling verification
# ═════════════════════════════════════════════════════════════════════════

def test_kill_pid_taskkill_success(gui, monkeypatch):
    ok_result = MagicMock()
    ok_result.returncode = 0
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: ok_result)

    ok, detail = gui.app._kill_pid_verified(1234, 8000)
    assert ok is True
    assert "1234" in detail


def test_kill_pid_taskkill_nonzero_rc_is_failure(gui, monkeypatch):
    bad_result = MagicMock()
    bad_result.returncode = 1
    bad_result.stderr = "Access is denied."
    bad_result.stdout = ""
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: bad_result)

    ok, detail = gui.app._kill_pid_verified(1234, 8000)
    assert ok is False
    assert "denied" in detail.lower()


def test_kill_pid_timeout_but_port_frees_up_counts_as_success(gui, monkeypatch):
    """A slow-to-die process (large model unload etc.) whose taskkill call
    times out is NOT necessarily a failure -- the real signal is whether
    the port actually freed up afterward."""
    def _raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="taskkill", timeout=1)
    monkeypatch.setattr(subprocess, "run", _raise_timeout)

    fake_sock = MagicMock()
    fake_sock.__enter__ = lambda self: fake_sock
    fake_sock.__exit__ = lambda self, *a: False
    fake_sock.connect_ex.return_value = 111   # port already free on first poll
    monkeypatch.setattr(socket, "socket", lambda *a, **kw: fake_sock)

    ok, detail = gui.app._kill_pid_verified(1234, 8000, kill_timeout=1, verify_timeout=5)
    assert ok is True
    assert "slow" in detail.lower()


def test_kill_pid_timeout_and_port_never_frees_is_failure(gui, monkeypatch):
    def _raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="taskkill", timeout=1)
    monkeypatch.setattr(subprocess, "run", _raise_timeout)

    # verify_timeout=0 -> the polling loop's deadline is already in the
    # past by the time it's checked, so this returns immediately with no
    # real sleep -- keeps the test fast while still exercising the
    # "genuinely stuck" failure path.
    ok, detail = gui.app._kill_pid_verified(1234, 8000, kill_timeout=1, verify_timeout=0)
    assert ok is False
    assert "1234" in detail


def test_kill_pid_generic_exception(gui, monkeypatch):
    def _raise(*a, **kw):
        raise OSError("taskkill.exe missing")
    monkeypatch.setattr(subprocess, "run", _raise)

    ok, detail = gui.app._kill_pid_verified(1234, 8000)
    assert ok is False
    assert "taskkill.exe missing" in detail


# ═════════════════════════════════════════════════════════════════════════
# _reconcile_http_led — the debounced LED override loop
#
# NOTE on mocking level: _reconcile_http_led calls the bare closure name
# _http_health_check(port), not self._http_health_check(...) -- same for
# _stop_http_server/_force_kill_port calling _find_pid_on_port /
# _kill_pid_verified below. Python closures resolve free variables by
# name in the enclosing scope, not through `self`, so monkeypatching the
# self.-exposed copy does NOT affect what these higher-level closures
# actually call. Mocking urllib/subprocess/socket instead -- the real
# system-call boundary -- lets the genuine, unmodified production logic
# run end-to-end, which is both more accurate and matches how the rest
# of this codebase's closure-heavy GUI tests are already written.
# ═════════════════════════════════════════════════════════════════════════

def _set_led(gui, text):
    gui.app._http_status_var.set(text)


def _fake_urlopen(alive: bool):
    if alive:
        fake_resp = MagicMock()
        fake_resp.status = 200
        fake_resp.__enter__ = lambda self: fake_resp
        fake_resp.__exit__ = lambda self, *a: False
        return lambda url, timeout: fake_resp

    def _boom(url, timeout):
        raise ConnectionRefusedError("nobody home")
    return _boom


def test_reconcile_marks_running_immediately_on_success(gui, monkeypatch):
    _sync_thread(monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(True))
    _set_led(gui, "⬤ Stopped")
    gui.app._led_fail_streak[0] = 0

    gui.app._reconcile_http_led()
    _pump(gui)

    assert gui.app._http_status_var.get() == "⬤ Running"
    assert str(gui.app._http_status_lbl.cget("foreground")) == "#27ae60"


def test_reconcile_single_failure_does_not_flip_led_yet(gui, monkeypatch):
    """Debounce: one failed check must NOT flip Running -> Stopped."""
    _sync_thread(monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(False))
    _set_led(gui, "⬤ Running")
    gui.app._led_fail_streak[0] = 0

    gui.app._reconcile_http_led()
    _pump(gui)

    assert gui.app._http_status_var.get() == "⬤ Running"   # unchanged
    assert gui.app._led_fail_streak[0] == 1


def test_reconcile_two_consecutive_failures_flips_to_stopped(gui, monkeypatch):
    _sync_thread(monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(False))
    _set_led(gui, "⬤ Running")
    gui.app._led_fail_streak[0] = 1   # one failure already recorded

    gui.app._reconcile_http_led()
    _pump(gui)

    assert gui.app._http_status_var.get() == "⬤ Stopped"
    assert str(gui.app._http_status_lbl.cget("foreground")) == "#cc0000"
    assert gui.app._http_start_time[0] is None   # uptime ticker was stopped


def test_reconcile_recovery_is_not_debounced_and_resets_streak(gui, monkeypatch):
    """Coming back up is immediate -- only going down is debounced."""
    _sync_thread(monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(True))
    _set_led(gui, "⬤ Stopped")
    gui.app._led_fail_streak[0] = 1   # was mid-debounce when it recovered

    gui.app._reconcile_http_led()
    _pump(gui)

    assert gui.app._http_status_var.get() == "⬤ Running"
    assert gui.app._led_fail_streak[0] == 0


def test_reconcile_bad_port_reschedules_without_crashing(gui, monkeypatch):
    gui.app._http_port_var.set("not-a-number")
    # Should not raise.
    gui.app._reconcile_http_led()
    _pump(gui)
    gui.app._http_port_var.set("8000")  # restore for any later test


# ═════════════════════════════════════════════════════════════════════════
# _stop_http_server
# ═════════════════════════════════════════════════════════════════════════

def _fake_run_factory(netstat_stdout="", taskkill_rc=0, taskkill_stderr="",
                       raise_on_netstat=None, raise_on_taskkill=None):
    """Single subprocess.run fake covering both the netstat (shell string
    cmd) and taskkill (list cmd) call shapes _find_pid_on_port /
    _kill_pid_verified actually use."""
    def _fake_run(cmd, *a, **kw):
        is_netstat = isinstance(cmd, str) and "netstat" in cmd
        is_taskkill = isinstance(cmd, list) and cmd and cmd[0] == "taskkill"
        if is_netstat:
            if raise_on_netstat:
                raise raise_on_netstat
            m = MagicMock()
            m.stdout = netstat_stdout
            return m
        if is_taskkill:
            if raise_on_taskkill:
                raise raise_on_taskkill
            m = MagicMock()
            m.returncode = taskkill_rc
            m.stderr = taskkill_stderr
            m.stdout = ""
            return m
        m = MagicMock()
        m.stdout = ""
        m.returncode = 0
        return m
    return _fake_run


def _fake_socket_factory(connect_ex_value=111):
    fake_sock = MagicMock()
    fake_sock.__enter__ = lambda self: fake_sock
    fake_sock.__exit__ = lambda self, *a: False
    fake_sock.connect_ex.return_value = connect_ex_value
    return lambda *a, **kw: fake_sock


def test_stop_server_tracked_process_terminates_it(gui):
    tracked = MagicMock()
    tracked.poll.return_value = None
    gui.app._http_server_proc = tracked

    gui.app._stop_http_server()

    tracked.terminate.assert_called_once()
    assert gui.app._http_server_proc is None
    assert gui.app._http_status_var.get() == "⬤ Stopped"


def test_stop_server_untracked_nothing_on_port_just_sets_stopped(gui, monkeypatch, dialogs):
    gui.app._http_server_proc = None
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(netstat_stdout=""))
    monkeypatch.setattr(socket, "socket", _fake_socket_factory(connect_ex_value=111))  # free
    dialogs.reset()

    gui.app._stop_http_server()

    assert gui.app._http_status_var.get() == "⬤ Stopped"
    assert dialogs.last_call() is None   # no dialog needed for the clean case


def test_stop_server_untracked_pid_found_confirmed_kills_it(gui, monkeypatch, dialogs):
    gui.app._http_server_proc = None
    netstat_line = '  TCP    0.0.0.0:8000    0.0.0.0:0    LISTENING    5555\n'
    monkeypatch.setattr(subprocess, "run",
                         _fake_run_factory(netstat_stdout=netstat_line, taskkill_rc=0))
    dialogs.set_response("askyesno", True)

    gui.app._stop_http_server()

    assert gui.app._http_status_var.get() == "⬤ Stopped"


def test_stop_server_untracked_pid_found_declined_does_nothing(gui, monkeypatch, dialogs):
    gui.app._http_server_proc = None
    netstat_line = '  TCP    0.0.0.0:8000    0.0.0.0:0    LISTENING    5555\n'
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(netstat_stdout=netstat_line))
    dialogs.set_response("askyesno", False)
    _set_led(gui, "⬤ Running")

    gui.app._stop_http_server()

    assert gui.app._http_status_var.get() == "⬤ Running"   # untouched


def test_stop_server_untracked_kill_fails_shows_error_leaves_led(gui, monkeypatch, dialogs):
    gui.app._http_server_proc = None
    netstat_line = '  TCP    0.0.0.0:8000    0.0.0.0:0    LISTENING    5555\n'
    monkeypatch.setattr(subprocess, "run",
                         _fake_run_factory(netstat_stdout=netstat_line,
                                            taskkill_rc=1, taskkill_stderr="Access is denied."))
    dialogs.set_response("askyesno", True)
    dialogs.reset()
    _set_led(gui, "⬤ Running")

    gui.app._stop_http_server()

    assert dialogs.last_call("showerror") is not None
    assert gui.app._http_status_var.get() == "⬤ Running"   # left as-is per the comment


# ═════════════════════════════════════════════════════════════════════════
# _force_kill_port
# ═════════════════════════════════════════════════════════════════════════

def test_force_kill_port_free_shows_info(gui, monkeypatch, dialogs):
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(netstat_stdout=""))
    monkeypatch.setattr(socket, "socket", _fake_socket_factory(connect_ex_value=111))  # free
    dialogs.reset()

    gui.app._force_kill_port()

    assert dialogs.last_call("showinfo") is not None
    assert "not in use" in dialogs.last_call("showinfo")["message"].lower()


def test_force_kill_port_in_use_unknown_pid_warns(gui, monkeypatch, dialogs):
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(netstat_stdout=""))
    monkeypatch.setattr(socket, "socket", _fake_socket_factory(connect_ex_value=0))  # in use
    dialogs.reset()

    gui.app._force_kill_port()

    assert dialogs.last_call("showwarning") is not None


def test_force_kill_port_netstat_timeout_shows_specific_error(gui, monkeypatch, dialogs):
    timeout_exc = subprocess.TimeoutExpired(cmd="netstat", timeout=20)
    monkeypatch.setattr(subprocess, "run", _fake_run_factory(raise_on_netstat=timeout_exc))
    dialogs.reset()

    gui.app._force_kill_port()

    assert dialogs.last_call("showerror") is not None
    assert "netstat" in dialogs.last_call("showerror")["title"].lower()


def test_force_kill_port_confirmed_success(gui, monkeypatch, dialogs):
    netstat_line = '  TCP    0.0.0.0:8000    0.0.0.0:0    LISTENING    7777\n'
    monkeypatch.setattr(subprocess, "run",
                         _fake_run_factory(netstat_stdout=netstat_line, taskkill_rc=0))
    dialogs.set_response("askyesno", True)
    dialogs.reset()

    gui.app._force_kill_port()

    assert dialogs.last_call("showinfo") is not None
    assert "7777" in gui.app._http_status_var.get()


def test_force_kill_port_declined_does_not_kill(gui, monkeypatch, dialogs):
    netstat_line = '  TCP    0.0.0.0:8000    0.0.0.0:0    LISTENING    7777\n'
    run_calls = []
    base_fake = _fake_run_factory(netstat_stdout=netstat_line, taskkill_rc=0)
    def _tracking_fake(cmd, *a, **kw):
        run_calls.append(cmd)
        return base_fake(cmd, *a, **kw)
    monkeypatch.setattr(subprocess, "run", _tracking_fake)
    dialogs.set_response("askyesno", False)

    gui.app._force_kill_port()

    assert not any(isinstance(c, list) and c and c[0] == "taskkill" for c in run_calls)


def test_force_kill_port_kill_fails_shows_error(gui, monkeypatch, dialogs):
    netstat_line = '  TCP    0.0.0.0:8000    0.0.0.0:0    LISTENING    7777\n'
    monkeypatch.setattr(subprocess, "run",
                         _fake_run_factory(netstat_stdout=netstat_line,
                                            taskkill_rc=1, taskkill_stderr="Access denied."))
    dialogs.set_response("askyesno", True)
    dialogs.reset()

    gui.app._force_kill_port()

    assert dialogs.last_call("showerror") is not None
    assert "denied" in dialogs.last_call("showerror")["message"].lower()


def test_force_kill_port_bad_port_value_shows_error(gui, dialogs):
    gui.app._http_port_var.set("not-a-number")
    dialogs.reset()

    gui.app._force_kill_port()

    assert dialogs.last_call("showerror") is not None
    gui.app._http_port_var.set("8000")  # restore
