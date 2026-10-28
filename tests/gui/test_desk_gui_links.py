"""Business tab → Service Desk links (David 2026-10-28: "provide the URL for the
PWA install on cell phones like the copy and the QR code like the other PWA apps").

Run: run_tests.bat tests\\gui\\test_desk_gui_links.py -v
"""
import json
import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_gui_links as dgl  # noqa: E402


class _App:
    def __init__(self, root):
        self.root = root
        self.status_var = tk.StringVar(value="Ready")


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    return tmp_path


def _cfg(d, **kw):
    (d / "config.json").write_text(json.dumps(kw), encoding="utf-8")


@pytest.fixture(scope="module")
def _root():
    # ONE Tk for the module: a second tk.Tk() on Windows can fail with
    # 'invalid command name "tcl_findLibrary"'.
    try:
        r = tk.Tk()
    except tk.TclError as e:
        pytest.skip(f"no display: {e}")
    r.withdraw()
    yield r
    r.destroy()


@pytest.fixture
def tkroot(_root):
    yield _root
    for c in _root.winfo_children():
        c.destroy()


def _walk(w, kind):
    out = []
    for c in w.winfo_children():
        if isinstance(c, kind):
            out.append(c)
        out += _walk(c, kind)
    return out


@pytest.mark.parametrize("mode", ["personal", "server"])
def test_urls_follow_the_tunnel_in_both_modes(state, mode):
    _cfg(state, mode=mode, tunnel_domain="https://ap-test-1234.ai-prowler.com/")
    assert dgl.desk_urls() == {"app": "https://ap-test-1234.ai-prowler.com/desk/",
                               "support": "https://ap-test-1234.ai-prowler.com/support/new"}
    assert dgl.mode_of() == mode


def test_no_tunnel_no_urls(state):
    _cfg(state, mode="personal")
    assert dgl.desk_urls() == {"app": "", "support": ""}


def test_rows_copy_and_qr_like_the_other_apps(state, tkroot, monkeypatch):
    _cfg(state, mode="server", tunnel_domain="ap-test-1234.ai-prowler.com")
    import tool_config_store as tcs
    tcs.set_group_enabled("server", "service_desk", True)
    shown = []
    import setup_wizard
    monkeypatch.setattr(setup_wizard, "show_qr_window",
                        lambda root, title, url, cap: shown.append((title, url)))
    lf = ttk.LabelFrame(tkroot, text="x")
    lf.pack()
    vars_ = dgl.build_desk_url_rows(_App(tkroot), lf)
    assert vars_["app"].get() == "https://ap-test-1234.ai-prowler.com/desk/"
    btns = _walk(lf, ttk.Button)
    assert [b.cget("text") for b in btns] == ["📋 Copy", "📧 Email", "📱 QR"] * 2
    btns[0].invoke()                                        # Copy the app link
    assert tkroot.clipboard_get() == "https://ap-test-1234.ai-prowler.com/desk/"
    btns[2].invoke()                                        # QR for the app
    btns[5].invoke()                                        # QR for the customer page
    assert [u for _, u in shown] == ["https://ap-test-1234.ai-prowler.com/desk/",
                                     "https://ap-test-1234.ai-prowler.com/support/new"]
    assert not any("turned off" in str(l.cget("text")) for l in _walk(lf, ttk.Label))


def test_says_so_when_service_desk_is_off(state, tkroot):
    _cfg(state, mode="personal", tunnel_domain="ap-test-1234.ai-prowler.com")
    import tool_config_store as tcs
    tcs.set_group_enabled("personal", "service_desk", False)
    lf = ttk.LabelFrame(tkroot, text="x")
    dgl.build_desk_url_rows(_App(tkroot), lf)
    assert any("Service Desk is turned off" in str(l.cget("text")) for l in _walk(lf, ttk.Label))


def test_business_tab_shows_the_rows_and_refreshes_them_on_activation():
    gui = (ROOT / "rag_gui.py").read_text(encoding="utf-8")
    assert "🎫 Service Desk — Mobile URL for Tickets" in gui
    assert "_dgl.build_desk_url_rows(self, desk_lf)" in gui
    assert "self._desk_url_vars['app'].set(f\"https://{d}/desk/\")" in gui


def test_the_app_is_installable_on_a_phone():
    m = json.loads((ROOT / "desk" / "manifest.json").read_text(encoding="utf-8"))
    assert m.get("display") in ("standalone", "fullscreen", "minimal-ui"), m
    assert m.get("start_url", "").startswith("/desk"), m
    assert {i.get("sizes") for i in m.get("icons", [])} >= {"192x192", "512x512"}, m
