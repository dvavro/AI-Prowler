"""Zip lookup: Zippopotam answers, the cache, failures, and address parsing.

The HTTP call is mocked: no real network in tests. A cache hit never touches
the network; an unreachable API returns None and the review carries on.
"""
import json
import urllib.error
import urllib.request

import pytest

from estimator.estimating import zip_lookup as zl

NOW = "2026-11-18T10:00:00+00:00"
NSB = {"country": "United States", "country abbreviation": "US", "post code": "32168",
       "places": [{"place name": "New Smyrna Beach", "longitude": "-80.9584", "latitude": "29.0247",
                   "state": "Florida", "state abbreviation": "FL"}]}


class _Resp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def http(monkeypatch):
    """urlopen answers with New Smyrna Beach and records every call."""
    calls = []

    def fake(url, timeout=None):
        calls.append(url.full_url if hasattr(url, "full_url") else str(url))
        return _Resp(NSB)

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    return calls


def test_lookup_returns_city_state_and_abbreviation(http):
    out = zl.lookup_zip("32168")
    assert out == {"zip": "32168", "city": "New Smyrna Beach", "state": "Florida", "state_abbr": "FL"}
    assert "32168" in http[0] and len(http) == 1
    assert "county" not in out        # Zippopotam does not return a county


def test_second_lookup_comes_from_the_cache(db, http):
    first = zl.lookup_zip("32168", db)
    second = zl.lookup_zip("32168", db)
    assert first == second
    assert len(http) == 1                                   # the second call never touched the network
    row = db.execute("SELECT city, state_abbr FROM zip_cache WHERE zip_code = '32168'").fetchone()
    assert tuple(row) == ("New Smyrna Beach", "FL")


def test_cached_zip_never_touches_the_network(db, monkeypatch):
    db.execute("INSERT INTO zip_cache (zip_code, city, state, state_abbr, looked_up_at)"
               " VALUES ('32168', 'New Smyrna Beach', 'Florida', 'FL', ?)", (NOW,))

    def boom(url, timeout=None):
        raise AssertionError("a cached zip must not call the API")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert zl.lookup_zip("32168", db) == {"zip": "32168", "city": "New Smyrna Beach",
                                          "state": "Florida", "state_abbr": "FL"}


def test_unknown_zip_returns_none(monkeypatch):
    def missing(url, timeout=None):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", missing)
    assert zl.lookup_zip("99999") is None


def test_unreachable_api_returns_none(monkeypatch):
    def down(url, timeout=None):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(urllib.request, "urlopen", down)
    assert zl.lookup_zip("32168") is None


@pytest.mark.parametrize("bad", ["", "123", "123456", "abcde", "3216a", "  ", None])
def test_bad_zip_rejected_before_any_network_call(bad, http):
    assert zl.lookup_zip(bad) is None
    assert http == []


def test_parse_zip_from_address():
    assert zl.parse_zip_from_address("1500 Shadow Pines Dr, New Smyrna Beach, FL 32168") == "32168"
    assert zl.parse_zip_from_address("12 Oak St") is None
    assert zl.parse_zip_from_address("") is None
    assert zl.parse_zip_from_address(None) is None
    # several 5-digit numbers: the last one wins (the zip is conventionally last)
    assert zl.parse_zip_from_address("Suite 12345, 67890 Main St, Anytown 32168") == "32168"
