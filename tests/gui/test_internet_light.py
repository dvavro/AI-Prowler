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

import rag_gui  # noqa: E402


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
