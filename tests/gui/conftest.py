"""
GUI tests — conftest

Strategy
--------
Drive the GUI in-process. We construct a real Tk root, instantiate RAGGui(root)
exactly the way main() does, and then call methods directly. We never enter
the event loop with mainloop(); instead we pump it manually with root.update()
between actions, which is what every Tkinter test framework does.

What this approach gets us:
  • Every code path the user can trigger by clicking is reachable.
  • Widget state (button enabled? listbox contents? variable value?) is
    introspectable in the same call.
  • No need for pywinauto, X server, or screen recording.
  • Runs on Windows directly. Runs on Linux under xvfb-run.

What it doesn't get us:
  • Visual layout / theme correctness — neither does pywinauto, really.
  • Bugs that only happen during a real mainloop (event-coalescing,
    after() race conditions). For those, the manual smoke test is
    your check.

Hazards we have to handle
-------------------------
1. Modal dialogs (messagebox.showerror, askyesno, …) BLOCK the event loop
   forever in a test context. We patch tkinter.messagebox + filedialog
   so all dialogs become non-blocking and return controllable values.

2. RAGGui.__init__ schedules many root.after(...) callbacks that try to
   start Ollama, an HTTP MCP server, telemetry heartbeats, etc. Those
   callbacks fire as soon as we pump the event loop. We patch
   subprocess.Popen and subprocess.run to no-ops in test mode so that
   even if those callbacks fire, they don't actually launch anything.

3. The GUI imports rag_preprocessor by NAME and aliases globals like
   TRACKING_DB, AUTO_UPDATE_LIST. When isolated_env patches the
   rag_preprocessor module's attributes, the GUI's aliased copies
   become stale. We patch them on the GUI module too.

4. The GUI's tracked-listbox refresh writes "(No tracked items yet …)"
   when the list is empty. Tests that check listbox contents have to
   account for that placeholder string.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Path setup mirroring the unit conftest
_SRC = os.environ.get("AI_PROWLER_SRC")
if _SRC:
    SRC_ROOT = Path(_SRC).resolve()
else:
    SRC_ROOT = Path(__file__).resolve().parent.parent.parent

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# Skip-if-headless guard
#
# The GUI tests need a display. On Windows there always is one. On Linux
# you'd run them inside `xvfb-run -a pytest tests/gui` or set DISPLAY
# explicitly. If neither is the case, we skip the entire suite at collection
# time so they don't crash on import.
# ─────────────────────────────────────────────────────────────────────────────
def _has_display() -> bool:
    if sys.platform == "win32":
        return True   # Windows always has a window station available to the user
    if sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY"))


pytestmark = pytest.mark.skipif(
    not _has_display(),
    reason="GUI tests require a display (use xvfb-run on headless Linux)",
)


# ─────────────────────────────────────────────────────────────────────────────
# Subprocess silencer — stops the GUI's startup callbacks from launching
# anything real. We use a MagicMock so any attribute access (.poll(),
# .terminate(), .stdin, etc.) returns a mock and doesn't AttributeError.
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _silence_subprocess(monkeypatch):
    """Block subprocess calls during GUI tests so Ollama/MCP server startup
    side-effects don't actually launch processes. The Mock objects respond
    to any attribute access with another Mock, which is enough to keep the
    GUI's subprocess-tracking code from crashing."""
    import subprocess

    def _fake_popen(*a, **kw):
        m = MagicMock()
        m.poll.return_value = None     # "still running" — keeps the GUI happy
        m.returncode = None
        m.stdout = MagicMock()
        m.stderr = MagicMock()
        m.stdin  = MagicMock()
        return m

    def _fake_run(*a, **kw):
        cp = MagicMock()
        cp.returncode = 0
        cp.stdout = ""
        cp.stderr = ""
        return cp

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(subprocess, "run", _fake_run)
    # Some code paths use subprocess.check_call / check_output — neutralise too
    monkeypatch.setattr(subprocess, "check_call",   lambda *a, **kw: 0)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: "")


# ─────────────────────────────────────────────────────────────────────────────
# Dialog silencer — modal dialogs would block the test forever otherwise.
#
# Each test can override the default return value via the `dialogs` fixture
# (see below). The defaults are conservative:
#   askyesno   → False (cancel)   ─ avoid destructive ops by default
#   askokcancel → False
#   showinfo / warning / error → None (just acknowledge and continue)
# ─────────────────────────────────────────────────────────────────────────────
class DialogStub:
    """Recorder + controller for tkinter.messagebox calls.

    Tests use it like:
        dialogs.set_response("askyesno", True)
        # ... do something that triggers askyesno ...
        assert dialogs.last_call("askyesno")["title"] == "Confirm Removal"
    """
    def __init__(self):
        self._responses = {
            "askyesno":     False,
            "askokcancel":  False,
            "askquestion":  "no",
            "askretrycancel": False,
            "showinfo":     None,
            "showwarning":  None,
            "showerror":    None,
        }
        self.calls: list[dict] = []

    def set_response(self, dialog_type: str, value):
        self._responses[dialog_type] = value

    def _make(self, dialog_type: str):
        def _stub(title=None, message=None, **kw):
            self.calls.append({"type": dialog_type, "title": title,
                               "message": message, "kwargs": kw})
            return self._responses[dialog_type]
        return _stub

    def last_call(self, dialog_type: str | None = None):
        if dialog_type is None:
            return self.calls[-1] if self.calls else None
        for c in reversed(self.calls):
            if c["type"] == dialog_type:
                return c
        return None

    def reset(self):
        self.calls.clear()


@pytest.fixture
def dialogs(monkeypatch):
    """Silence tkinter.messagebox / filedialog. Test can inspect/control via
    the returned DialogStub object."""
    from tkinter import messagebox, filedialog
    stub = DialogStub()

    for dt in ("askyesno", "askokcancel", "askquestion",
               "askretrycancel", "showinfo", "showwarning", "showerror"):
        monkeypatch.setattr(messagebox, dt, stub._make(dt))

    # File-dialog calls return empty by default (= user cancelled)
    monkeypatch.setattr(filedialog, "askdirectory",   lambda **kw: "")
    monkeypatch.setattr(filedialog, "askopenfilename", lambda **kw: "")
    monkeypatch.setattr(filedialog, "askopenfilenames", lambda **kw: ())

    return stub


# ─────────────────────────────────────────────────────────────────────────────
# Shared Tk root — session-scoped
#
# Why session-scoped: creating a fresh Tk() per test exhausts the Tcl
# interpreter's resources around the 25th call on some Windows Python
# installs (manifests as "Can't find a usable tk.tcl"). Even when it
# works, each Tk() takes 100-300ms — across 25 tests that's most of the
# GUI suite's runtime.
#
# We create ONE root for the whole session, and instead destroy the
# RAGGui's child widgets between tests. Isolation isn't lost — each
# test still gets a freshly-constructed RAGGui with all its variables
# at default values. The Tk interpreter itself is reused.
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def _tk_root():
    """Session-scoped Tk root. Created once, reused across every GUI test."""
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()        # invisible — comment out to watch tests run
    yield root
    try:
        root.destroy()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# The GUI fixture — instantiates a fresh RAGGui in the shared root.
# Tears down all children on exit so the next test gets a clean slate.
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def gui(isolated_env, dialogs, monkeypatch, _tk_root):
    """Build a real RAGGui instance with patched globals so it sees the
    isolated test environment (temp ChromaDB, temp tracking JSON, etc.)
    instead of the user's real install.

    Returns an object exposing:
      .app    — the RAGGui instance
      .root   — the Tk root (shared session-wide)
      .pump() — call root.update() to process pending events
      .wait_until(predicate) — pump events until predicate is truthy
    """
    import tkinter as tk
    import rag_gui as gui_mod
    rag = isolated_env.rag

    # The GUI's `from rag_preprocessor import …` left it with stale aliases.
    # Repoint the names that touch on-disk state at the patched values.
    monkeypatch.setattr(gui_mod, "TRACKING_DB",      rag.TRACKING_DB)
    monkeypatch.setattr(gui_mod, "AUTO_UPDATE_LIST", rag.AUTO_UPDATE_LIST)

    root = _tk_root

    # Wipe any leftover children from the previous test before instantiating
    # the new RAGGui (it builds many widgets as children of root).
    for child in list(root.winfo_children()):
        try:
            child.destroy()
        except Exception:
            pass

    app = gui_mod.RAGGui(root)

    # Cancel any outstanding after() callbacks so they don't fire during
    # the test and confuse our state.
    try:
        for callback_id in root.tk.call("after", "info"):
            try:
                root.after_cancel(callback_id)
            except Exception:
                pass
    except Exception:
        pass

    class GuiHandle:
        pass
    h = GuiHandle()
    h.app = app
    h.root = root
    h.dialogs = dialogs

    def _pump(times: int = 5, interval_ms: int = 10):
        """Process pending Tk events."""
        import time
        for _ in range(times):
            try:
                root.update_idletasks()
                root.update()
            except tk.TclError:
                break
            time.sleep(interval_ms / 1000.0)

    h.pump = _pump

    def _wait_until(predicate, timeout_s: float = 30.0):
        """Pump events until predicate() returns truthy or timeout."""
        import time
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                root.update_idletasks()
                root.update()
            except tk.TclError:
                break
            value = predicate()
            if value:
                return value
            time.sleep(0.05)
        raise AssertionError(
            f"wait_until timed out after {timeout_s}s waiting for {predicate.__name__}"
        )

    h.wait_until = _wait_until

    yield h

    # Per-test teardown: cancel any leftover after() callbacks. The shared
    # root is NOT destroyed here — that happens in the session fixture.
    try:
        for callback_id in root.tk.call("after", "info"):
            try:
                root.after_cancel(callback_id)
            except Exception:
                pass
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Self-learning fixtures — imported from the shared module so GUI learning
# tests can use sl_env / seeded_learnings.
# ─────────────────────────────────────────────────────────────────────────────
from tests.learning_fixtures import (  # noqa: F401, E402
    sl_module,
    sl_env,
    seeded_learnings,
)
