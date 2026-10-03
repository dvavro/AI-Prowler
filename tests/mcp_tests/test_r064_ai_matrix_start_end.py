"""R-064 (2026-09-29): the drive matrix AI Routing reasons from held
job-to-job legs only, so the AI chose orders without the drive from the day's
start to the first job and back (E2E MILES-04 Jobs Only: 16.16 mi where the
same jobs in the Company-mode order were 15.92 mi). The START/END point —
resolved as apply_route_order resolves it — is now row/column 1."""
import pathlib

import pytest

import db_route_ops as dro

JOBS = [
    {"job_id": "JOB-0001", "address": "210 Sams Ave", "lat": 29.0258, "lon": -80.927},
    {"job_id": "JOB-0002", "address": "105 S Riverside Dr", "lat": 29.028, "lon": -80.925},
]
HOME = (29.0493, -80.9942)


class _Resp:
    def __init__(self, d):
        self._d = d

    def json(self):
        return self._d


@pytest.fixture
def osrm(monkeypatch):
    seen = {}

    def get(url, **k):
        seen["coords"] = url.rsplit("/", 1)[-1].split(";")
        n = len(seen["coords"])
        return _Resp({"code": "Ok", "durations": [[60.0 * (i != j) for j in range(n)] for i in range(n)],
                      "distances": [[1609.344 * (i != j) for j in range(n)] for i in range(n)]})
    monkeypatch.setattr(dro.requests, "get", get)
    monkeypatch.setattr(dro, "db_get_jobs_for_route", lambda *a, **k: [dict(j) for j in JOBS])
    return seen


def test_company_location_start_end_is_row_1(osrm, monkeypatch):
    monkeypatch.setattr(dro, "db_read_route_origin_mode", lambda p: "Company Location")
    monkeypatch.setattr(dro, "db_read_route_address", lambda p: "1500 Shadow Pines Dr")
    monkeypatch.setattr(dro, "_geocode", lambda a: HOME)
    out = dro.db_route_drive_matrix("x.db", "2026-09-29", "", single_crew=True)
    assert len(osrm["coords"]) == 3 and osrm["coords"][0] == f"{HOME[1]},{HOME[0]}"
    assert "1. START/END (business: 1500 Shadow Pines Dr)" in out
    assert "2. JOB-0001" in out and "3. JOB-0002" in out
    assert "compare orders by the whole day" in out


def test_jobs_only_home_is_row_1(osrm, monkeypatch):
    monkeypatch.setattr(dro, "db_read_route_origin_mode", lambda p: "Jobs Only")
    got = {}

    def home(lat, lon, crew_name="", is_server_mode=False, db_path=""):
        got.update(lat=lat, server=is_server_mode)
        return HOME
    monkeypatch.setattr(dro, "_resolve_jobs_only_origin", home)
    out = dro.db_route_drive_matrix("x.db", "2026-09-29", "", single_crew=True)
    assert "1. START/END (Home)" in out and len(osrm["coords"]) == 3
    assert got == {"lat": None, "server": False}      # same resolution apply_route_order uses


def test_no_start_point_keeps_jobs_only_matrix(osrm, monkeypatch):
    monkeypatch.setattr(dro, "db_read_route_origin_mode", lambda p: "Jobs Only")
    monkeypatch.setattr(dro, "_resolve_jobs_only_origin", lambda *a, **k: None)
    out = dro.db_route_drive_matrix("x.db", "2026-09-29", "")
    assert len(osrm["coords"]) == 2 and "START/END" not in out and "1. JOB-0001" in out


def test_ai_prompt_and_tool_use_it():
    src = (pathlib.Path(dro.__file__).parent / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert "compare orders by the whole day" in src          # the AI Routing prompt says so
    assert "_db_route_drive_matrix(db_path, route_date, crew, single_crew=(not _IS_SERVER_MODE))" in src
