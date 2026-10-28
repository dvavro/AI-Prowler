"""
tests/unit/test_onboarding_connect_pwa_version.py
=================================================
David, 2026-10-21 — four changes:

  PV-01..06  PWA version badge: Jobs, Remote, HR Admin and HR Portal show
             "v<VERSION> · <hash>" top-right. The server stamps it in at serve
             time (ai_prowler_mcp._stamp_pwa_build); nothing to bump by hand.
  OB-01..06  New install: "➕ Add a service" blinks red until the picker has
             been opened and closed, then turns green; then "🧭 Set up
             AI-Prowler" blinks red until clicked. Existing users never blink.
  CA-01..07  Connect your AI: two tabs — Claude Desktop (free, no
             subscription, no phone link) and phone/web for Claude, Grok,
             Muse ($10/month subscription -> activation code -> URL).
  AN-01..05  Scheduled AI analyses: say up front they need the Claude Code
             CLI signed in with a Claude Pro account; install / sign in / skip.

Nothing here touches the network, the real config, Claude Desktop's config or
the live server: paths point at tmp_path and the app hooks are fakes.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_SRC = Path(__file__).resolve().parents[2]
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import setup_wizard as sw  # noqa: E402

PWA_APPS = ["jobs", "remote", "hr_admin", "hr_portal", "desk"]   # desk = Service Desk (2026-10-28)
JS_STAMP_RE = re.compile(r"/\*AP_PWA_BUILD\*/'([^']*)'/\*AP_PWA_BUILD_END\*/")   # same as the page's JS


# ══ PWA version badge ════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def mcp():
    return pytest.importorskip("ai_prowler_mcp")


@pytest.mark.parametrize("app", PWA_APPS)
def test_PV_01_every_pwa_page_has_one_badge_and_placeholder(app):
    t = (_SRC / app / "index.html").read_text(encoding="utf-8")
    assert t.count('id="apPwaVer"') == 1
    assert t.count("__AIPROWLER_PWA_BUILD__") == 1, "exactly one placeholder (the server replaces one)"
    assert JS_STAMP_RE.search(t), "the tap-to-check regex must find the stamp in the page"
    assert f"var APP_ROOT = '/{app}/';" in t
    body = t.index("<body")
    assert t.index('id="apPwaVer"') > body, "badge must be inside <body>"


def test_PV_02_stamp_fills_version_and_hash(mcp, tmp_path, monkeypatch):
    monkeypatch.setattr(mcp, "_pwa_app_version", lambda: "9.3.2")
    page = b"<body><script>var BUILD = /*AP_PWA_BUILD*/'__AIPROWLER_PWA_BUILD__'/*AP_PWA_BUILD_END*/;</script>"
    out = mcp._stamp_pwa_build(str(tmp_path), page)
    m = JS_STAMP_RE.search(out.decode("utf-8"))
    assert m and re.fullmatch(r"9\.3\.2 · [0-9a-f]{6}", m.group(1)), m and m.group(1)
    assert mcp._stamp_pwa_build(str(tmp_path), b"no placeholder") == b"no placeholder"


def test_PV_03_hash_follows_the_apps_files(mcp, tmp_path, monkeypatch):
    monkeypatch.setattr(mcp, "_pwa_app_version", lambda: "9.3.2")
    page = b"x __AIPROWLER_PWA_BUILD__ y"
    a = mcp._compute_pwa_build(str(tmp_path), page)
    assert a == mcp._compute_pwa_build(str(tmp_path), page)               # stable
    assert a != mcp._compute_pwa_build(str(tmp_path), page + b" edit")    # page edit
    (tmp_path / "sw.js").write_text("const CACHE = 'auto';", encoding="utf-8")
    assert a != mcp._compute_pwa_build(str(tmp_path), page)               # sw.js counts too


@pytest.mark.parametrize("rel", ["index.html", "some/spa/route"])
def test_PV_04_serving_stamps_pages_and_still_patches_sw(mcp, rel):
    root = str(_SRC / "jobs")
    page = (_SRC / "jobs" / "index.html").read_bytes()
    out = mcp._patch_sw_cache_version(rel, root, page)                    # SPA fallback too
    assert b"__AIPROWLER_PWA_BUILD__" not in out
    assert JS_STAMP_RE.search(out.decode("utf-8")).group(1).startswith(mcp._pwa_app_version())
    sw_js = (_SRC / "jobs" / "sw.js").read_bytes()
    assert b"const CACHE = 'auto';" not in mcp._patch_sw_cache_version("sw.js", root, sw_js)


def test_PV_05_disk_files_never_change(mcp):
    p = _SRC / "remote" / "index.html"
    before = p.read_bytes()
    mcp._patch_sw_cache_version("index.html", str(p.parent), before)
    assert p.read_bytes() == before


def test_PV_06_all_serving_sites_go_through_the_stamp(mcp):
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index("def _patch_sw_cache_version(")
    # 2026-10-28: pages are also icon-versioned on the way out (_version_pwa_icons)
    assert "return _version_pwa_icons(pwa_root, _stamp_pwa_build(pwa_root, body))" in src[i:i + 1500]
    # jobs (server + personal), HR apps, remote
    assert src.count("_patch_sw_cache_version(") >= 5


# ══ new-user nudge: blinking buttons ═════════════════════════════════════════

@pytest.fixture(scope="module")
def tk_root():
    import tkinter as tk
    root = None
    for _ in range(3):
        try:
            root = tk.Tk()
            break
        except tk.TclError:
            pass
    if root is None:
        pytest.skip("no display for Tk")
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:
        pass


@pytest.fixture
def host(tk_root):
    import tkinter as tk
    top = tk.Toplevel(tk_root)
    top.withdraw()
    yield top
    try:
        top.destroy()
    except Exception:
        pass


@pytest.fixture
def fresh(monkeypatch):
    monkeypatch.setattr(sw, "_tracked_paths", lambda: [])


def _panel(host, tmp_path, **progress):
    prog = sw.Progress(path=tmp_path / "setup_progress.json", **progress)
    app = SimpleNamespace(notebook=None)
    p = sw.SetupCenterPanel(host, app, progress=prog)
    return p


def _is_tk_button(w):
    import tkinter as tk
    return isinstance(w, tk.Button)


def _bg(w):
    return str(w.cget("bg")).lower()


def test_OB_01_progress_keeps_the_stage(tmp_path):
    p = sw.Progress(path=tmp_path / "p.json")
    p.set_onboarding(sw.ONB_SETUP)
    assert sw.Progress.load(tmp_path / "p.json").onboarding == sw.ONB_SETUP
    (tmp_path / "p.json").write_text(json.dumps({"onboarding": "weird"}), encoding="utf-8")
    assert sw.Progress.load(tmp_path / "p.json").onboarding is None
    (tmp_path / "p.json").write_text(json.dumps({"picked": True}), encoding="utf-8")   # older file
    assert sw.Progress.load(tmp_path / "p.json").onboarding is None


def test_OB_02_fresh_install_add_a_service_blinks_red(host, tmp_path, fresh):
    p = _panel(host, tmp_path)
    assert p.progress.onboarding == sw.ONB_PICKER
    assert _is_tk_button(p.add_btn) and "Add a service" in p.add_btn.cget("text")
    assert not _is_tk_button(p.toggle_btn)                      # Set up: not yet
    first = _bg(p.add_btn)
    assert first in (sw.BLINK_RED[0].lower(), sw.BLINK_OFF[0].lower())
    assert p._blink_job is not None
    p._blink_job and host.after_cancel(p._blink_job)
    p._start_blink(p.add_btn)                                   # next half of the blink
    p._stop_blink()


def _picker_window(host):
    import tkinter as tk
    wins = [w for w in host.winfo_children() for w in [w] if isinstance(w, tk.Toplevel)]
    for f in host.winfo_children():
        wins += [w for w in f.winfo_children() if isinstance(w, tk.Toplevel)]
    return wins[-1]


def _find_button(widget, text):
    for w in widget.winfo_children():
        try:
            if text in str(w.cget("text")):
                return w
        except Exception:
            pass
        found = _find_button(w, text)
        if found is not None:
            return found
    return None


def test_OB_03_in_and_out_of_the_picker_turns_it_green(host, tmp_path, fresh):
    p = _panel(host, tmp_path)
    p.open_picker()
    win = _picker_window(host)
    _find_button(win, "Cancel").invoke()                        # Cancel counts as in-and-out
    assert p.progress.onboarding == sw.ONB_SETUP
    assert _bg(p.add_btn) == sw.GO_GREEN[0].lower()
    assert _is_tk_button(p.toggle_btn) and "Set up AI-Prowler" in p.toggle_btn.cget("text")
    assert _bg(p.toggle_btn) in (sw.BLINK_RED[0].lower(), sw.BLINK_OFF[0].lower())
    p._stop_blink()


def test_OB_04_save_in_the_picker_also_advances(host, tmp_path, fresh):
    p = _panel(host, tmp_path)
    p.open_picker()
    _find_button(_picker_window(host), "Save").invoke()
    assert p.progress.onboarding == sw.ONB_SETUP and p.progress.picked
    p._stop_blink()


def test_OB_05_set_up_click_opens_panel_and_starts_first_step(host, tmp_path, fresh):
    p = _panel(host, tmp_path, onboarding=sw.ONB_SETUP, collapsed=True)
    started = []
    p.start = lambda m: started.append(m.id)
    p.toggle_btn.invoke()
    assert p.progress.onboarding == sw.ONB_DONE
    assert p.expanded                                          # never folds it shut
    assert started and started[0] == p.progress.plan()[0].id
    assert not _is_tk_button(p.toggle_btn)                     # stops blinking
    assert _bg(p.add_btn) == sw.GO_GREEN[0].lower()            # Add a service stays green
    assert p._blink_job is None


def test_OB_06_existing_user_never_blinks(host, tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "_tracked_paths", lambda: ["C:/docs"])
    p = _panel(host, tmp_path, picked=True)
    assert p.progress.onboarding is None
    assert not _is_tk_button(p.add_btn) and not _is_tk_button(p.toggle_btn)
    assert p._blink_job is None


# ══ Connect your AI ══════════════════════════════════════════════════════════

def test_CA_01_claude_desktop_connected(tmp_path):
    cfg = tmp_path / "claude_desktop_config.json"
    assert not sw.claude_desktop_connected(cfg)                          # no file
    for entry, ok in [({"command": "C:/py/python.exe", "args": ["x"]}, True),
                      ({"command": "C:/py/pythonw.exe"}, False),
                      ({"url": "https://x/mcp"}, False),
                      ({}, False)]:
        cfg.write_text(json.dumps({"mcpServers": {"AI-Prowler": entry}}), encoding="utf-8")
        assert sw.claude_desktop_connected(cfg) is ok, entry
    cfg.write_text("{not json", encoding="utf-8")
    assert not sw.claude_desktop_connected(cfg)


def _connect(host, monkeypatch, domain="", desktop=False, app=None, tab=None):
    monkeypatch.setattr(sw, "tunnel_domain", lambda: domain)
    monkeypatch.setattr(sw, "claude_desktop_connected", lambda path=None: desktop)
    monkeypatch.setattr(sw, "qr_png", lambda *a, **k: None)
    return sw.ConnectAIFlow(host, app or SimpleNamespace(notebook=None), None, tab=tab)


def _texts(w):
    out = []
    for c in w.winfo_children():
        try:
            out.append(str(c.cget("text")))
        except Exception:
            pass
        out += _texts(c)
    return out


def test_CA_02_two_clear_ways(host, monkeypatch):
    f = _connect(host, monkeypatch)
    tabs = [f.tabs.tab(t, "text") for t in f.tabs.tabs()]
    assert "Claude Desktop" in tabs[0] and "free" in tabs[0] and "no subscription" in tabs[0]
    assert "Grok" in tabs[1] and "Muse" in tabs[1] and "$10/month" in tabs[1]
    desk = " ".join(_texts(f.tabs.nametowidget(f.tabs.tabs()[0])))
    assert "FREE Claude account" in desk and "No phone link" in desk
    for b in ("Sign up free", "Download Claude Desktop", "Connect automatically"):
        assert b in desk
    assert f.tabs.index(f.tabs.select()) == f.TAB_DESKTOP          # new user starts on the free way
    f.win.destroy()


def test_CA_03_no_subscription_yet_walks_through_it(host, monkeypatch):
    f = _connect(host, monkeypatch)
    online = " ".join(_texts(f.tabs.nametowidget(f.tabs.tabs()[1])))
    assert "Needs an AI-Prowler subscription ($10/month)" in online
    assert "no desktop app" in online and "activation code" in online
    assert "Subscribe" in online and "Activate" in online
    f.win.destroy()


def test_CA_04_subscribed_shows_url_and_opens_on_that_tab(host, monkeypatch):
    f = _connect(host, monkeypatch, domain="ap-x.ai-prowler.com")
    online = " ".join(_texts(f.tabs.nametowidget(f.tabs.tabs()[1])))
    assert "Subscription active" in online
    assert f.tabs.index(f.tabs.select()) == f.TAB_ONLINE
    f.win.destroy()


def test_CA_05_activate_uses_the_settings_activation(host, monkeypatch):
    got = []
    app = SimpleNamespace(notebook=None, _sw_activate_with_code=got.append)
    f = _connect(host, monkeypatch, app=app)
    warned = []
    monkeypatch.setattr("tkinter.messagebox.showwarning", lambda *a, **k: warned.append(a))
    f._activate()                                            # still "APRO-" -> warn, no call
    assert warned and got == []
    f.code_var.set("APRO-ABC123-DEF456-GHI789")
    monkeypatch.setattr(f, "_wait_for_link", lambda tries: None)
    f._activate()
    assert got == ["APRO-ABC123-DEF456-GHI789"]
    f.win.destroy()


def test_CA_06_link_appears_window_reopens_on_phone_tab(host, monkeypatch):
    f = _connect(host, monkeypatch)
    monkeypatch.setattr(sw, "tunnel_domain", lambda: "ap-x.ai-prowler.com")
    opened = []
    real = sw.ConnectAIFlow

    class Spy(real):
        def __init__(self, *a, **k):
            opened.append(k.get("tab"))
            super().__init__(*a, **k)
    monkeypatch.setattr(sw, "ConnectAIFlow", Spy)
    f._wait_for_link(tries=1)
    assert opened == [real.TAB_ONLINE]
    assert not f.win.winfo_exists()


def test_CA_07_desktop_connect_and_subscribe_use_the_app_hooks(host, monkeypatch):
    calls = []
    app = SimpleNamespace(notebook=None,
                          _sw_auto_configure_claude_desktop=lambda: calls.append("desktop"),
                          _sw_open_subscribe=lambda plan: calls.append(("subscribe", plan)))
    f = _connect(host, monkeypatch, app=app)
    f._connect_desktop()
    f._subscribe()
    assert calls == ["desktop", ("subscribe", "personal")]
    f.win.destroy()
    src = (_SRC / "rag_gui.py").read_text(encoding="utf-8")
    for hook in ("self._sw_auto_configure_claude_desktop = ", "self._sw_open_subscribe = ",
                 "self._sw_activate_with_code = "):
        assert hook in src


# ══ Scheduled AI analyses: Claude Code CLI + Claude Pro ══════════════════════

def test_AN_01_requirement_is_spelled_out():
    t = sw.CLI_NEEDS_TEXT
    assert "Claude Code CLI" in t and "Claude Pro" in t and "free Claude account can't" in t
    assert "Skip for now" in t
    label = dict((s[0], s[1]) for s in sw.SERVICES)["analyses"]
    assert "needs Claude Pro" in label
    assert "Claude Pro" in sw.BY_ID["links"].why


def _links(host, tmp_path, monkeypatch):
    monkeypatch.setattr(sw, "email_configured", lambda: False)
    monkeypatch.setattr(sw, "ai_routing_status", lambda: {"cli": False, "token": "no_credentials"})
    rendered = []
    panel = SimpleNamespace(frame=host, app=SimpleNamespace(),
                            progress=sw.Progress(path=tmp_path / "p.json"),
                            render=lambda: rendered.append(1), open_tab=lambda m: None)
    return sw.LinksFlow(panel), panel


@pytest.mark.parametrize("status, has, hasnt", [
    ({"cli": False, "token": "no_credentials"}, "Install Claude Code CLI", "Sign in with Claude Pro"),
    ({"cli": True, "token": "no_credentials"}, "Sign in with Claude Pro", "Install Claude Code CLI"),
])
def test_AN_02_offers_the_next_missing_step(host, tmp_path, monkeypatch, status, has, hasnt):
    f, _ = _links(host, tmp_path, monkeypatch)
    f._show_cli_status(status)
    texts = " ".join(_texts(f.cli_fix))
    assert has in texts and hasnt not in texts and "Get Claude Pro" in texts
    assert f.cli_ready is False
    f.win.destroy()


def test_AN_03_ready_shows_green_and_no_buttons(host, tmp_path, monkeypatch):
    f, _ = _links(host, tmp_path, monkeypatch)
    f._show_cli_status({"cli": True, "token": "ok"})
    assert f.cli_ready is True and f.cli_fix.winfo_children() == []
    assert "signed in" in f.cli_lbl.cget("text")
    f.win.destroy()


def test_AN_04_skip_for_now(host, tmp_path, monkeypatch):
    f, panel = _links(host, tmp_path, monkeypatch)
    assert _find_button(f.win, "Skip for now") is not None
    f._skip()
    assert panel.progress.states["links"] == sw.SKIPPED
    assert not f.win.winfo_exists()


def test_AN_05_sign_in_opens_the_token_window_only_after_ok(host, tmp_path, monkeypatch):
    f, _ = _links(host, tmp_path, monkeypatch)
    import task_queue_automation as tqa
    opened = []
    monkeypatch.setattr(tqa, "open_setup_token_terminal", lambda: opened.append(1) or (True, "opened"))
    monkeypatch.setattr("tkinter.messagebox.askokcancel", lambda *a, **k: False)
    f._sign_in()
    assert opened == []
    monkeypatch.setattr("tkinter.messagebox.askokcancel", lambda *a, **k: True)
    f._sign_in()
    assert opened == [1]
    f.win.destroy()
