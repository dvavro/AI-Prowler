"""Concrete agent auto-run: unit tests for the driver module's pure parts.

The browser driving itself is covered by tests/estimator/browser/
test_e2e_autorun.py; these tests need no browser and no server.
"""

import json
import sqlite3

import pytest

from estimator.agents import concrete_autorun as ca


# ---------------------------------------------------------------- sheet_to_screen

def test_sheet_to_screen_is_the_inverse_of_viewer_tosheet():
    # Viewer.toSheet (review.js:455): [(cx - left - tx)/z, (cy - top - ty)/z].
    # A sheet point round-trips through screen and back.
    rect = {"left": 120, "top": 80, "width": 900, "height": 600}
    z, tx, ty = 2.5, 40, -30
    for x, y in [(0, 0), (1, 1), (6, 5), (36, 24), (0.5, 12.25)]:
        cx, cy = ca.sheet_to_screen(x, y, z, tx, ty, rect)
        assert (cx - rect["left"] - tx) / z == pytest.approx(x)
        assert (cy - rect["top"] - ty) / z == pytest.approx(y)


def test_sheet_to_screen_identity_and_offset():
    rect = {"left": 0, "top": 0, "width": 100, "height": 100}
    assert ca.sheet_to_screen(3, 4, 1, 0, 0, rect) == (3, 4)
    rect = {"left": 10, "top": 20, "width": 100, "height": 100}
    assert ca.sheet_to_screen(3, 4, 2, 5, 6, rect) == (10 + 5 + 6, 20 + 6 + 8)


# ---------------------------------------------------------------- split_base

def test_split_base_accepts_origin_and_page_base():
    page, api = ca.split_base("http://localhost:8770")
    assert page == "http://localhost:8770/estimator/"
    assert api == "http://localhost:8770/estimator-api"
    page, api = ca.split_base("http://localhost:8770/estimator/")
    assert page == "http://localhost:8770/estimator/"
    assert api == "http://localhost:8770/estimator-api"
    page, api = ca.split_base("http://localhost:8770/estimator")
    assert page == "http://localhost:8770/estimator/"
    assert api == "http://localhost:8770/estimator-api"


# ---------------------------------------------------------------- pick_candidate

def _cand(cid, area, area_sqft=None):
    return {"id": cid, "area": area, "area_sqft": area_sqft,
            "corners": [[0, 0], [1, 0], [1, 1], [0, 1]]}


def test_pick_candidate_largest_first():
    cands = [_cand("c1", 24, 384.0), _cand("c2", 80, 1280.0), _cand("c3", 12, 192.0)]
    assert ca.pick_candidate(cands)["id"] == "c2"
    assert ca.pick_candidate([]) is None


def test_pick_candidate_works_uncalibrated_where_sqft_is_none():
    cands = [_cand("c1", 24), _cand("c2", 80)]
    assert ca.pick_candidate(cands)["id"] == "c2"


# ---------------------------------------------------------------- calibration matching

def test_find_calibration_dimension_matches_the_slab_side():
    rect = {"width": 5, "height": 4}
    objects = [
        {"kind": "dimension", "label": "20'-0\"",
         "geometry": {"type": "line", "points": [[1, 7], [6, 7]]}},
        {"kind": "dimension", "label": "not a length",
         "geometry": {"type": "line", "points": [[1, 8], [5, 8]]}},
        {"kind": "wall", "label": None,
         "geometry": {"type": "line", "points": [[1, 1], [6, 1]]}},
    ]
    dim = ca.find_calibration_dimension(objects, rect)
    assert dim is not None
    assert dim["points"] == [[1, 7], [6, 7]]
    assert dim["label"] == "20'-0\""
    assert dim["real_inches"] == pytest.approx(240.0)


def test_find_calibration_dimension_none_when_nothing_matches():
    rect = {"width": 5, "height": 4}
    objects = [{"kind": "dimension", "label": "20'-0\"",
                "geometry": {"type": "line", "points": [[1, 7], [9, 7]]}}]
    assert ca.find_calibration_dimension(objects, rect) is None
    assert ca.find_calibration_dimension([], rect) is None


# ---------------------------------------------------------------- RunStore

_AUTO_RUNS = """
CREATE TABLE auto_runs (
    id                   INTEGER PRIMARY KEY,
    company_id           TEXT NOT NULL,
    estimate_id          INTEGER NOT NULL,
    sheet_id             INTEGER NOT NULL,
    viewport_id          INTEGER NOT NULL,
    module_id            TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'running',
    step                 TEXT NOT NULL DEFAULT 'starting',
    error                TEXT,
    candidate_id         TEXT,
    candidates_json      TEXT NOT NULL DEFAULT '[]',
    measurement_ids_json TEXT NOT NULL DEFAULT '[]',
    created_by           TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
)
"""


@pytest.fixture
def run_db(tmp_path):
    path = tmp_path / "estimator.db"
    conn = sqlite3.connect(str(path))
    conn.execute(_AUTO_RUNS)
    conn.execute(
        "INSERT INTO auto_runs (company_id, estimate_id, sheet_id, viewport_id, module_id,"
        " status, step, created_by, created_at, updated_at)"
        " VALUES ('personal', 3, 5, 4, 'concrete', 'running', 'starting', 'Owner', 't', 't')")
    conn.commit()
    conn.close()
    store = ca.RunStore(str(path))
    yield store, path
    store.close()


def test_run_store_reads_the_run_row(run_db):
    store, _ = run_db
    run = store.read_run(1)
    assert (run["estimate_id"], run["sheet_id"], run["viewport_id"]) == (3, 5, 4)
    assert run["module_id"] == "concrete" and run["status"] == "running"


def test_run_store_read_missing_run_fails(run_db):
    store, _ = run_db
    with pytest.raises(ca.AgentError, match="not found"):
        store.read_run(99)


def test_run_store_missing_db_file_fails_fast(tmp_path):
    with pytest.raises(ca.AgentError, match="database not found"):
        ca.RunStore(str(tmp_path / "nope.db"))


def test_run_store_update_only_touches_given_fields(run_db):
    store, _ = run_db
    cands = [{"id": "c1", "area": 20}]
    store.update(1, step="measuring_area", candidate_id="c1", candidates=cands)
    run = store.read_run(1)
    assert run["step"] == "measuring_area"
    assert run["candidate_id"] == "c1"
    assert json.loads(run["candidates_json"]) == cands
    assert run["status"] == "running"  # untouched
    assert run["error"] is None
    store.update(1, status="done", step="done", measurement_ids=[7, 8, 9])
    run = store.read_run(1)
    assert run["status"] == "done" and run["step"] == "done"
    assert json.loads(run["measurement_ids_json"]) == [7, 8, 9]
    assert run["candidate_id"] == "c1"  # still untouched


def test_run_store_update_failure(run_db):
    store, _ = run_db
    store.update(1, status="failed", step="calibrating", error="no dimension")
    run = store.read_run(1)
    assert (run["status"], run["step"], run["error"]) == ("failed", "calibrating", "no dimension")
