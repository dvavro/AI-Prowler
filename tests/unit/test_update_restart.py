"""
tests/unit/test_update_restart.py
=================================
"Update downloaded but never installed" (2026-10-21, David).

Download Update only STAGES the new files (%LOCALAPPDATA%\\AI-Prowler\\
pending_update + update_ready.txt); RAG_RUN.bat installs them on the next
start. A server left running (Samuel) stayed on the old version for a day and
nothing said so. Now:

  UR-01..03  what counts as "downloaded, NOT installed yet" (flag + staging +
             a version newer than the one running)
  UR-04..07  Restart Now: clean shutdown (same as File -> Exit), then
             RAG_RUN.bat is started detached so it installs and reopens
  UR-08..09  the "download finished" dialog says NOT installed yet and offers
             Restart Now / Later
  UR-10..12  the reminder (status bar + Server/Home tab banner, each with a
             Restart Now button) stays until the update is really installed
  UR-13..14  source guards: old "ready" wording gone, Server tab has a visible
             banner host, Help -> Notifications popup offers Restart Now

Nothing here downloads, installs or restarts anything: LOCALAPPDATA points at
tmp_path, os._exit / Popen / message boxes are replaced.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

rg = pytest.importorskip("rag_gui")

_METHODS = [
    "_update_paths", "_version_tuple", "_pending_update_version",
    "_refresh_update_pending_ui", "_on_update_downloaded",
    "_restart_to_install_update", "_update_relaunch_command",
    "_launch_detached", "_on_window_close", "_show_update_banner",
    "_clear_update_banner", "create_status_bar",
]


def _stub(**attrs):
    """Object with the real RAGGui update methods but none of its __init__."""
    cls = type("UpdStub", (object,), {n: rg.RAGGui.__dict__[n] for n in _METHODS})
    s = cls()
    s.__dict__.update(attrs)
    return s


@pytest.fixture
def appdata(tmp_path, monkeypatch):
    """Fake %LOCALAPPDATA% and a running version of 9.3.1."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(rg, "APP_VERSION", "9.3.1")
    base = tmp_path / "AI-Prowler"
    base.mkdir()

    def stage(version="9.3.2", staging=True, text=None):
        if staging:
            (base / "pending_update").mkdir(exist_ok=True)
            (base / "pending_update" / "rag_gui.py").write_text("# new", encoding="utf-8")
        (base / "update_ready.txt").write_text(
            text if text is not None else
            f"AI-Prowler update v{version}\nDownloaded: 12 files (all integrity-verified)\n",
            encoding="utf-8")

    def installed():                       # what RAG_RUN.bat does after the copy
        (base / "update_ready.txt").unlink(missing_ok=True)
        import shutil
        shutil.rmtree(base / "pending_update", ignore_errors=True)

    return type("A", (), {"stage": staticmethod(stage), "installed": staticmethod(installed),
                          "base": base})


@pytest.fixture(scope="module")
def _tk_module_root():
    # One Tk interpreter for the module: creating several in a row on Windows
    # occasionally fails, which made a test skip at random.
    tk = rg.tk
    root, err = None, None
    for _ in range(3):
        try:
            root = tk.Tk()
            break
        except tk.TclError as e:
            err = e
    if root is None:
        pytest.skip(f"no display for Tk: {err}")
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:
        pass


@pytest.fixture
def tkroot(_tk_module_root):
    """A fresh Toplevel per test (own status bar / banner host)."""
    top = rg.tk.Toplevel(_tk_module_root)
    top.withdraw()
    yield top
    try:
        top.destroy()
    except Exception:
        pass


# ══ what is "pending" ════════════════════════════════════════════════════════

def test_UR_01_staged_newer_version_is_pending(appdata):
    s = _stub()
    assert s._pending_update_version() is None            # nothing staged
    appdata.stage("9.3.2")
    assert s._pending_update_version() == "9.3.2"
    appdata.stage("9.10.0")                                 # numeric, not string compare
    assert s._pending_update_version() == "9.10.0"


def test_UR_02_same_or_older_version_is_not_pending(appdata):
    s = _stub()
    appdata.stage("9.3.1")
    assert s._pending_update_version() is None
    appdata.stage("9.2.9")
    assert s._pending_update_version() is None


def test_UR_03_flag_without_staging_or_garbage_is_not_pending(appdata):
    s = _stub()
    appdata.stage("9.3.2", staging=False)
    assert s._pending_update_version() is None
    appdata.stage(text="")
    assert s._pending_update_version() is None
    appdata.stage(text="something else entirely\n")
    assert s._pending_update_version() is None


# ══ Restart Now ══════════════════════════════════════════════════════════════

def test_UR_04_relaunch_command_waits_then_runs_the_bat():
    bat = Path(r"C:\Program Files\AI-Prowler\RAG_RUN.bat")
    cmd = rg.RAGGui._update_relaunch_command(bat)
    assert cmd.startswith('cmd.exe /c "ping -n ')
    assert f'& "{bat}""' in cmd                            # path with a space stays quoted


def test_UR_05_restart_now_closes_cleanly_then_relaunches(appdata, monkeypatch):
    appdata.stage("9.3.2")
    calls = []
    s = _stub(status_var=type("V", (), {"set": lambda self, v: calls.append(("status", v))})(),
              root=type("R", (), {"update_idletasks": lambda self: None})())
    s._on_window_close = lambda relaunch=None: calls.append(("close", relaunch))
    asked = []
    monkeypatch.setattr(rg.messagebox, "askyesno", lambda *a, **k: asked.append(a) or True)

    assert s._restart_to_install_update() is True
    assert len(asked) == 1 and "click Yes" in asked[0][1]  # explains the Windows prompt
    close = [c for c in calls if c[0] == "close"]
    assert len(close) == 1 and "RAG_RUN.bat" in close[0][1]


def test_UR_06_restart_declined_or_bat_missing_does_nothing(appdata, monkeypatch, tmp_path):
    appdata.stage("9.3.2")
    closed = []
    s = _stub(status_var=None, root=None)
    s._on_window_close = lambda relaunch=None: closed.append(relaunch)
    monkeypatch.setattr(rg.messagebox, "askyesno", lambda *a, **k: False)
    assert s._restart_to_install_update() is False
    assert closed == []

    warned = []
    monkeypatch.setattr(rg.messagebox, "showwarning", lambda *a, **k: warned.append(a))
    monkeypatch.setattr(rg, "__file__", str(tmp_path / "nowhere" / "rag_gui.py"))
    assert s._restart_to_install_update(ask=False) is False
    assert closed == [] and warned and "start it again" in warned[0][1]


def test_UR_07_window_close_relaunches_after_stopping_everything(monkeypatch):
    events = []

    class P:
        def __init__(self, name): self.name = name
        def poll(self): return None if self.name not in [e[1] for e in events if e[0] == "kill"] else 0
        def terminate(self): events.append(("kill", self.name))
        def wait(self, timeout=None): return 0

    class Exit(Exception):
        pass

    def fake_exit(code):
        events.append(("exit", code))
        raise Exit()

    s = _stub(_ollama_process=None, _http_server_proc=P("http"), _cloudflared_proc=P("tunnel"),
              _set_sleep_prevention=lambda on: events.append(("sleep", on)),
              root=type("R", (), {"destroy": lambda self: events.append(("destroy", None))})())
    s._launch_detached = lambda cmd, cwd=None: events.append(("relaunch", cmd))
    monkeypatch.setattr(os, "_exit", fake_exit)
    with pytest.raises(Exit):
        s._on_window_close(relaunch="CMD")
    order = [e[0] for e in events]
    assert order.index("relaunch") > order.index("kill")          # server stopped first
    assert ("kill", "http") in events and ("kill", "tunnel") in events
    assert order.index("relaunch") < order.index("exit")
    assert ("relaunch", "CMD") in events

    # plain File -> Exit: no relaunch
    events.clear()
    s._http_server_proc = s._cloudflared_proc = None
    with pytest.raises(Exit):
        s._on_window_close()
    assert "relaunch" not in [e[0] for e in events]


def test_UR_07b_launch_detached_uses_its_own_console(monkeypatch):
    got = []
    monkeypatch.setattr(rg.subprocess, "Popen", lambda cmd, **kw: got.append((cmd, kw)) or "proc")
    s = _stub()
    assert s._launch_detached("CMD", cwd="X") == "proc"
    cmd, kw = got[0]
    assert cmd == "CMD" and kw["cwd"] == "X"
    if sys.platform == "win32":
        assert kw["creationflags"] & 0x10                   # CREATE_NEW_CONSOLE


# ══ download finished: NOT installed yet, Restart Now / Later ════════════════

def _dl_stub(calls):
    s = _stub(status_var=type("V", (), {"set": lambda self, v: calls.append(("status", v))})())
    s._refresh_update_pending_ui = lambda: calls.append(("reminder", None))
    s._restart_to_install_update = lambda ask=True: calls.append(("restart", ask))
    return s


def test_UR_08_download_finished_restart_now(monkeypatch):
    calls, boxes = [], []
    monkeypatch.setattr(rg.messagebox, "askyesno", lambda t, m, **k: boxes.append((t, m)) or True)
    _dl_stub(calls)._on_update_downloaded("9.3.2", 12)
    title, msg = boxes[0]
    assert "NOT installed yet" in title and "NOT installed yet" in msg
    assert "still running v9" in msg or "running v" in msg
    assert ("restart", False) in calls                      # no second "are you sure"
    assert ("reminder", None) in calls
    assert any(c[0] == "status" and "NOT installed yet" in c[1] for c in calls)


def test_UR_09_download_finished_later_keeps_reminder(monkeypatch):
    calls = []
    monkeypatch.setattr(rg.messagebox, "askyesno", lambda *a, **k: False)
    _dl_stub(calls)._on_update_downloaded("9.3.2", 12)
    assert not any(c[0] == "restart" for c in calls)
    assert ("reminder", None) in calls


# ══ the reminder (real Tk widgets) ═══════════════════════════════════════════

def _ui_stub(tkroot):
    s = _stub(root=tkroot, _update_banner_widget=None)
    s._restart_to_install_update = lambda ask=True: None
    s._scroll_to_mcp_settings = lambda: None
    s.create_status_bar()
    s._upd_banner_host = rg.ttk.Frame(tkroot)
    s._upd_banner_host.pack(side="top", fill="x")
    return s


def _texts(widget):
    out = []
    for w in widget.winfo_children():
        try:
            out.append(str(w.cget("text")))
        except Exception:
            pass
        out.extend(_texts(w))
    return out


def test_UR_10_reminder_shows_while_pending_and_goes_after_install(appdata, tkroot):
    s = _ui_stub(tkroot)
    assert s._refresh_update_pending_ui() is None
    assert not s._upd_pending_frame.winfo_manager()         # nothing staged: hidden

    appdata.stage("9.3.2")
    assert s._refresh_update_pending_ui() == "9.3.2"
    assert s._upd_pending_frame.winfo_manager() == "pack"   # status bar reminder
    assert "v9.3.2 downloaded — NOT installed yet" in s._upd_pending_var.get()
    assert any("Restart Now" in t for t in _texts(s._upd_pending_frame))
    banner_texts = _texts(s._upd_banner_host)               # Server / Home tab banner
    assert any("NOT installed yet" in t for t in banner_texts)
    assert any("Restart Now to Install" in t for t in banner_texts)

    s._refresh_update_pending_ui()                          # refresh: never stacks banners
    assert len(s._upd_banner_host.winfo_children()) == 1

    appdata.installed()                                     # RAG_RUN.bat installed it
    assert s._refresh_update_pending_ui() is None
    assert not s._upd_pending_frame.winfo_manager()
    assert s._upd_banner_host.winfo_children() == []


def test_UR_11_reminder_survives_status_messages(appdata, tkroot):
    s = _ui_stub(tkroot)
    appdata.stage("9.3.2")
    s._refresh_update_pending_ui()
    s.status_var.set("Indexing 3 files…")                   # normal status traffic
    assert "NOT installed yet" in s._upd_pending_var.get()
    assert s._upd_pending_frame.winfo_manager() == "pack"


def test_UR_12_available_banner_becomes_restart_banner_when_already_downloaded(appdata, tkroot):
    s = _ui_stub(tkroot)
    appdata.stage("9.3.2")
    s._show_update_banner("9.3.2", "https://example.invalid/r", "")
    assert s._update_banner_widget is None                  # no second "Download Update"
    texts = _texts(s._upd_banner_host)
    assert any("Restart Now to Install" in t for t in texts)
    assert not any("Download Update" in t for t in texts)


# ══ source guards ════════════════════════════════════════════════════════════

def _src():
    return (_SRC / "rag_gui.py").read_text(encoding="utf-8")


def test_UR_13_download_wording_says_not_installed():
    src = _src()
    assert '_prog_queue.put(("done", "update_ready", version, downloaded, None))' in src
    assert "Go to File → Exit to restart now." not in src
    assert "ready — restart to apply" not in src
    assert "Downloading does not install it yet." in src


def test_UR_14_server_tab_and_help_popup_offer_restart():
    src = _src()
    i = src.index("def _create_server_status_tab(self):")
    block = src[i:i + 6000]
    assert "self._upd_banner_host = ttk.Frame(server_frame" in block
    assert "self._upd_banner_host.pack(" in block
    j = src.index("def _render_update_buttons():")
    assert "_restart_to_install_update" in src[j:j + 1500]
