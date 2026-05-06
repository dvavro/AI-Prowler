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
# The GUI fixture — instantiates a real RAGGui in an isolated environment.
# Closes the window on teardown so the next test gets a clean slate.
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def gui(isolated_env, dialogs, monkeypatch):
    """Build a real RAGGui instance with patched globals so it sees the
    isolated test environment (temp ChromaDB, temp tracking JSON, etc.)
    instead of the user's real install.

    Returns an object exposing:
      .app    — the RAGGui instance
      .root   — the Tk root (for direct widget access if needed)
      .pump() — call root.update() to process pending events. Tests that
                trigger threaded background work should call pump() in a
                short loop until the work completes.
    """
    import tkinter as tk
    import rag_gui as gui_mod
    rag = isolated_env.rag

    # The GUI's `from rag_preprocessor import …` left it with stale aliases.
    # Repoint the names that touch on-disk state at the patched values.
    monkeypatch.setattr(gui_mod, "TRACKING_DB",      rag.TRACKING_DB)
    monkeypatch.setattr(gui_mod, "AUTO_UPDATE_LIST", rag.AUTO_UPDATE_LIST)

    # Build the root and instantiate the GUI exactly like main() does
    root = tk.Tk()
    # Don't display the window in CI — withdraw makes it invisible but the
    # widgets still respond to programmatic events. The user can comment
    # this out if they want to *see* what the test is doing.
    root.withdraw()

    app = gui_mod.RAGGui(root)

    # Cancel any outstanding after() callbacks so they don't fire during the
    # test and confuse our state. We can't enumerate them via the public API,
    # so we use Tk's internal info command. This is best-effort cleanup; the
    # subprocess silencer above is the actual safety net.
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
        """Process pending Tk events. `times` controls how many update_idletasks
        + update cycles we run; bump it for tests that involve threaded workers
        (which post results back through self.output_queue)."""
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
        """Pump events until predicate() returns truthy or timeout. Returns
        the predicate's value (so you can `result = wait_until(...)` and use
        it). Raises AssertionError on timeout. Use this for tests that wait
        on a worker thread to finish."""
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

    # Teardown
    try:
        root.destroy()
    except Exception:
        pass
