"""R-063 (2026-09-29): _osrm_leg — the drive time/miles lookup Route Today,
AI Routing (apply_route_order) and reorder all use — gave up after one try.
A dropped connection left that leg's miles blank, and the Route tab's day
total silently left it out. Now retried (3 tries); a real non-"Ok" OSRM
answer is not retried."""
import db_write_ops as dbw


class _Resp:
    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


OK = {"code": "Ok", "routes": [{"legs": [{"duration": 600, "distance": 8046.72}]}]}


def test_dropped_connection_is_retried(monkeypatch):
    n = {"n": 0}

    def get(*a, **k):
        n["n"] += 1
        if n["n"] < 3:
            raise ConnectionResetError(10054, "forcibly closed")
        return _Resp(OK)

    monkeypatch.setattr(dbw.requests, "get", get)
    monkeypatch.setattr("time.sleep", lambda s: None)
    assert dbw._osrm_leg(29.0, -80.9, 29.1, -80.95) == (10, 5.0)
    assert n["n"] == 3


def test_three_drops_give_up(monkeypatch):
    n = {"n": 0}

    def get(*a, **k):
        n["n"] += 1
        raise ConnectionResetError(10054, "forcibly closed")

    monkeypatch.setattr(dbw.requests, "get", get)
    monkeypatch.setattr("time.sleep", lambda s: None)
    assert dbw._osrm_leg(29.0, -80.9, 29.1, -80.95) == (None, None)
    assert n["n"] == 3


def test_real_no_route_answer_not_retried(monkeypatch):
    n = {"n": 0}

    def get(*a, **k):
        n["n"] += 1
        return _Resp({"code": "NoRoute"})

    monkeypatch.setattr(dbw.requests, "get", get)
    assert dbw._osrm_leg(29.0, -80.9, 29.1, -80.95) == (None, None)
    assert n["n"] == 1


def test_warning_says_miles_are_missing():
    import pathlib
    src = (pathlib.Path(dbw.__file__).parent / "db_route_ops.py").read_text(encoding="utf-8")
    assert src.count("miles are missing from the day's total") == 2
