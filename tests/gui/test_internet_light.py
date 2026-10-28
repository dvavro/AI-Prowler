"""Settings → HTTP MCP Server → "Internet:" light.

2026-10-28 (David): "the internet stayed red when the internet was
disconnected then reconnected". The light loaded github.com once (at start
and when the HTTP server started) and then only every 5 minutes, so a server
started while the connection was coming back showed Offline for minutes; one
slow GitHub answer was also enough for red. Now several sites are tried and
the light re-checks every 15 s while Offline, every 60 s while Online.

Run: run_tests.bat tests\\gui\\test_internet_light.py -v
"""
import socket
import sys
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

import rag_gui  # noqa: E402


@pytest.fixture
def home_gui(gui, sandbox_state):
    """The real AI-Prowler window, built as a personal install (sandbox config)."""
    sandbox_state.set_config(edition="home", mode="personal")
    for child in list(gui.root.winfo_children()):
        try:
            child.destroy()
        except Exception:  # noqa: BLE001
            pass
    gui.app = rag_gui.RAGGui(gui.root)
    gui.pump()
    return gui


class _Resp:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(results, calls):
    """results: url -> 'ok' | 'http' | 'timeout' | 'dns'."""
    def op(req, timeout=None):
        url = req.full_url
        calls.append(url)
        r = results.get(url, "timeout")
        if r == "ok":
            return _Resp()
        if r == "http":
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
        if r == "dns":
            raise urllib.error.URLError(socket.gaierror(11001, "getaddrinfo failed"))
        raise TimeoutError("timed out")
    return op


URLS = rag_gui.INTERNET_PROBE_URLS


def test_one_slow_site_no_longer_means_offline():
    calls = []
    first_down = {URLS[0]: "timeout", URLS[1]: "ok"}
    assert rag_gui._internet_reachable(opener=_opener(first_down, calls)) is True
    assert calls == list(URLS[:2])                    # stops at the first answer


def test_github_alone_down_is_still_online():
    calls = []
    results = {u: "ok" for u in URLS}
    results["https://github.com"] = "timeout"
    assert rag_gui._internet_reachable(opener=_opener(results, calls)) is True


def test_an_http_error_page_still_came_over_the_internet():
    assert rag_gui._internet_reachable(opener=_opener({URLS[0]: "http"}, [])) is True


def test_really_offline_is_offline():
    calls = []
    assert rag_gui._internet_reachable(opener=_opener({u: "dns" for u in URLS}, calls)) is False
    assert calls == list(URLS)                        # every site was tried


def test_offline_rechecks_soon_online_less_often():
    assert rag_gui._internet_recheck_ms(False) == 15_000
    assert rag_gui._internet_recheck_ms(True) == 60_000
    assert rag_gui._internet_recheck_ms(False) < 300_000      # not the old 5-minute wait


def test_probe_list_is_not_only_github():
    assert len(URLS) >= 3 and any("github" not in u for u in URLS)


# ── clicking the light (David 2026-10-28: "change the light to yellow then the
#    state of the recheck result so the user can see that a new check was issued")

def test_light_styles():
    assert rag_gui._internet_light_style("checking") == ("#e6a700", "Checking…")
    assert rag_gui._internet_light_style("online")[1] == "Online"
    assert rag_gui._internet_light_style("offline")[1] == "Offline"


def test_yellow_is_held_long_enough_to_see():
    assert rag_gui._internet_checking_hold_ms(100) == rag_gui.INTERNET_CHECKING_MIN_MS - 100
    assert rag_gui._internet_checking_hold_ms(5000) == 0         # a slow check: no extra wait


def _find_internet_light(root):
    """The Online/Offline label right after the "Internet:" label, and the
    dot canvas between them."""
    stack = [root]
    while stack:
        w = stack.pop()
        kids = list(w.winfo_children())
        for i, k in enumerate(kids):
            try:
                if str(k.cget("text")).strip() == "Internet:":
                    return kids[i + 1], kids[i + 2]
            except Exception:  # noqa: BLE001 — widgets without text
                pass
        stack.extend(kids)
    raise AssertionError("Internet light not found in the window")


def _state(canvas, label):
    dot = canvas.find_all()[0]
    return canvas.itemcget(dot, "fill"), str(label.cget("text"))


def test_click_shows_yellow_checking_then_the_result(home_gui, monkeypatch):
    import time as _t
    net = {"up": True}          # the window's own start-up checks call this too

    def _slowish(*a, **kw):
        _t.sleep(0.2)
        return net["up"]
    monkeypatch.setattr(rag_gui, "_internet_reachable", _slowish)
    canvas, label = _find_internet_light(home_gui.root)

    # click the WORD: yellow at once, then green Online
    label.event_generate("<Button-1>")
    home_gui.pump(times=2)
    assert _state(canvas, label) == ("#e6a700", "Checking…")
    home_gui.wait_until(lambda: _state(canvas, label)[1] == "Online", timeout_s=5)
    assert _state(canvas, label) == ("#27ae60", "Online")

    # the connection drops; click the DOT: yellow again, then red Offline
    net["up"] = False
    canvas.event_generate("<Button-1>")
    home_gui.pump(times=2)
    assert _state(canvas, label) == ("#e6a700", "Checking…")
    home_gui.wait_until(lambda: _state(canvas, label)[1] == "Offline", timeout_s=5)
    assert _state(canvas, label) == ("#cc0000", "Offline")


def test_yellow_stays_up_at_least_the_minimum(home_gui, monkeypatch):
    import time as _t
    monkeypatch.setattr(rag_gui, "_internet_reachable", lambda *a, **kw: True)   # instant
    canvas, label = _find_internet_light(home_gui.root)
    t0 = _t.monotonic()
    label.event_generate("<Button-1>")
    home_gui.wait_until(lambda: _state(canvas, label)[1] == "Online", timeout_s=5)
    assert (_t.monotonic() - t0) * 1000 >= rag_gui.INTERNET_CHECKING_MIN_MS - 50
