"""R-062 (2026-09-29): build_daily_route's start-address lookup failed the
whole build on one dropped Nominatim connection (E2E PSCHED-04/05:
"Could not geocode starting address: ('Connection aborted.' ...)").

Fix: it now uses db_write_ops._geocode (retries, R-023) and that helper
caches successful answers, so routing several days in a row asks for the
same start address only once.
"""
import pathlib

import db_write_ops as dbw

SRC = pathlib.Path(dbw.__file__).parent


class _Resp:
    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


def test_hit_is_cached(monkeypatch):
    n = {"n": 0}

    def get(*a, **k):
        n["n"] += 1
        return _Resp([{"lat": "29.02", "lon": "-80.92"}])

    monkeypatch.setattr(dbw.requests, "get", get)
    assert dbw._geocode("1500 Shadow Pines Dr, NSB, FL") == (29.02, -80.92)
    # same address, different spacing/case -> no second request
    assert dbw._geocode("1500  shadow pines dr, nsb, fl") == (29.02, -80.92)
    assert n["n"] == 1


def test_drop_then_answer_is_retried_and_cached(monkeypatch):
    n = {"n": 0}

    def get(*a, **k):
        n["n"] += 1
        if n["n"] == 1:
            raise ConnectionResetError(10054, "forcibly closed")
        return _Resp([{"lat": "29.1", "lon": "-81.0"}])

    monkeypatch.setattr(dbw.requests, "get", get)
    monkeypatch.setattr("time.sleep", lambda s: None)
    assert dbw._geocode("addr A") == (29.1, -81.0)
    assert dbw._geocode("addr A") == (29.1, -81.0)
    assert n["n"] == 2


def test_misses_and_outages_are_not_cached(monkeypatch):
    n = {"n": 0}

    def get(*a, **k):
        n["n"] += 1
        return _Resp([])

    monkeypatch.setattr(dbw.requests, "get", get)
    assert dbw._geocode("1 NOWHERE Rd") is None
    assert dbw._geocode("1 NOWHERE Rd") is None
    assert n["n"] == 2
    assert "1 nowhere rd" not in dbw._GEOCODE_CACHE


def test_build_daily_route_uses_retrying_lookup():
    src = (SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index("def build_daily_route(")
    body = src[i:i + 60000]
    assert "_geocode_retry(effective_origin)" in body
    # the old one-shot Nominatim call for the origin is gone
    assert 'params={"q": effective_origin' not in body
