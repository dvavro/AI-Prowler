"""Concrete agent auto-run E2E (Playwright, headless): the agent drives Blueprint Review.

    run_tests_estimator.bat browser -k autorun [--human]

The agent runs as its own process (python -m estimator.agents.concrete_autorun
--headless), exactly as autorun_api.spawn_agent starts it, against this test's
own server and throwaway database. The headed, human-visible run is the same
code path with --headed and still needs David to try it after deploy
(run_tests_estimator.bat browser --human is the headed mode for this track).

The slab is seeded, not read from a fixture plan: four wall lines closing a
5 x 4 paper-inch rectangle on a 36 x 24 foundation sheet at 1/4" = 1'-0"
(scale_ratio 48, so 4 ft per paper inch) - 20 ft x 16 ft, 320 sq ft, 72 lf
round. The Smith residence fixture has rooms, not a slab outline, and reading
it through the plan engine would make the test slow and non-deterministic;
the detector only reads line geometry (slab_find.find_rectangles ignores
polygons), so wall lines are the honest seed.

M1 (calibrated): the run finishes with three proposed measurements stamped
concrete-agent - area_sqft 320, footing_lf 72, perimeter_lf 72.
M2 (uncalibrated): a 20'-0" dimension line spans the slab's width; the agent
calibrates from it in the page first, then measures the same three.
"""

import json
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from e2e_helpers import CTX, _pdf
from estimator.agents import concrete_autorun as ca
from estimator.api import autorun_api
from estimator.config import db_path
from estimator.drawing_model import store
from estimator.estimating import service

ROOT = Path(__file__).resolve().parents[3]

SCALE_RATIO = 48          # 1/4" = 1'-0": 4 ft per paper inch
EXPECT_AREA = 320.0       # 20 ft x 16 ft
EXPECT_PERIMETER = 72.0   # 2 x (20 + 16) ft


def _wall(x1, y1, x2, y2):
    return {"viewport": "plan", "kind": "wall", "source": "cad",
            "geometry": {"type": "line", "points": [[x1, y1], [x2, y2]]}}


def _seed(db, tmp_path, *, calibrated):
    """An estimate with one foundation sheet: wall lines closing the slab
    rectangle (1,1)-(6,5), plus a 20'-0" dimension line when uncalibrated."""
    est = service.create_estimate(db, CTX, "Agent slab job")["id"]
    ps = store.upload(db, CTX, est, _pdf(tmp_path / "slab.pdf", 1, "S"), confirm=True)["plan_set_id"]
    viewport = {"key": "plan", "label": "FOUNDATION PLAN", "scale_note": "1/4\" = 1'-0\""}
    if calibrated:
        viewport["scale_ratio"] = SCALE_RATIO
    objects = [_wall(1, 1, 6, 1), _wall(6, 1, 6, 5), _wall(6, 5, 1, 5), _wall(1, 5, 1, 1)]
    if not calibrated:
        objects.append({"viewport": "plan", "kind": "dimension", "label": "20'-0\"", "source": "cad",
                        "geometry": {"type": "line", "points": [[1, 7], [6, 7]]}})
    store.save_results(db, CTX, ps, {"sheets": [
        {"page_no": 1, "sheet_no": "S-101", "title": "FOUNDATION PLAN",
         "units": "paper_in", "width": 36, "height": 24,
         "viewports": [viewport], "objects": objects}]}, "fake")
    db.commit()
    sheet = store.sheets(db, CTX, ps)["sheets"][0]
    viewports = store.viewports(db, CTX, sheet["id"])["viewports"]
    assert len(viewports) == 1
    return {"est": est, "sheet": sheet["id"], "viewport": viewports[0]["id"]}


def _api_get(base, path):
    _, api_base = ca.split_base(base)
    with urllib.request.urlopen(api_base + path, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _read_run(run_id):
    conn = sqlite3.connect(str(db_path()))
    conn.row_factory = sqlite3.Row
    try:
        return dict(conn.execute("SELECT * FROM auto_runs WHERE id = ?", (run_id,)).fetchone())
    finally:
        conn.close()


def _agent_measurements(estimate_id):
    conn = sqlite3.connect(str(db_path()))
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM measurements WHERE estimate_id = ? AND proposed_by = ?",
            (estimate_id, "concrete-agent"))]
    finally:
        conn.close()


def _run_agent(site, run_id):
    """Invoke the agent exactly as spawn_agent does, but headless for tests."""
    cmd = [sys.executable, "-m", "estimator.agents.concrete_autorun",
           "--base", site, "--db", str(db_path()), "--run-id", str(run_id), "--headless"]
    try:
        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        pytest.fail("the agent did not finish within 300 seconds")
    assert proc.returncode == 0, f"agent exited {proc.returncode}\n--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"


def _check_run_done(site, seed, run_id):
    run = _read_run(run_id)
    assert run["status"] == "done", f"run {run_id} ended {run['status']}: {run['error']}"
    assert run["step"] == "done"
    assert run["candidate_id"] == "c1"
    assert json.loads(run["candidates_json"])
    assert len(json.loads(run["measurement_ids_json"])) == 3
    # The API agrees with the row.
    got = _api_get(site, f"/auto-run/{run_id}")
    assert got["run"]["status"] == "done"
    assert got["run"]["candidate_id"] == "c1"
    assert len(got["run"]["measurement_ids"]) == 3


def _check_measurements(seed):
    rows = _agent_measurements(seed["est"])
    assert len(rows) == 3, f"expected 3 agent measurements, got {len(rows)}: {rows}"
    by_feeds = {r["feeds"]: r for r in rows}
    assert set(by_feeds) == {"area_sqft", "footing_lf", "perimeter_lf"}
    for r in rows:
        assert r["status"] == "proposed", f"{r['feeds']} is {r['status']}, not proposed"
        assert r["module_id"] == "concrete"
        assert json.loads(r["calc_json"])["candidate_id"] == "c1"
    assert by_feeds["area_sqft"]["label"] == "Slab (agent)"
    assert by_feeds["footing_lf"]["label"] == "Footer (agent)"
    assert by_feeds["perimeter_lf"]["label"] == "Forms (agent)"
    assert float(by_feeds["area_sqft"]["qty"]) == pytest.approx(EXPECT_AREA, rel=0.01)
    assert by_feeds["area_sqft"]["unit"] == "sqft"
    assert float(by_feeds["footing_lf"]["qty"]) == pytest.approx(EXPECT_PERIMETER, rel=0.01)
    assert float(by_feeds["perimeter_lf"]["qty"]) == pytest.approx(EXPECT_PERIMETER, rel=0.01)


def _require_agent_ready(site, seed):
    if not autorun_api._playwright_available():
        pytest.skip("Playwright/Chromium is not installed")
    try:
        found = _api_get(site, f"/viewports/{seed['viewport']}/slab-candidates")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            pytest.skip("slab-candidates endpoint not deployed yet")
        raise
    assert found["candidates"], "the seeded slab rectangle was not found"


# ------------------------------------------------------------------ M1: calibrated

def test_E2E_autorun_calibrated_slab(site, db, tmp_path):
    seed = _seed(db, tmp_path, calibrated=True)
    _require_agent_ready(site, seed)
    run_id = autorun_api.create_run(db, CTX, seed["est"], seed["sheet"], seed["viewport"], "concrete")
    _run_agent(site, run_id)
    _check_run_done(site, seed, run_id)
    _check_measurements(seed)


# ------------------------------------------------------------------ M2: calibrates first

def test_E2E_autorun_calibrates_from_dimension(site, db, tmp_path):
    seed = _seed(db, tmp_path, calibrated=False)
    _require_agent_ready(site, seed)
    run_id = autorun_api.create_run(db, CTX, seed["est"], seed["sheet"], seed["viewport"], "concrete")
    _run_agent(site, run_id)
    _check_run_done(site, seed, run_id)
    _check_measurements(seed)
    # The viewport now carries the scale the agent set from the 20'-0" line.
    found = _api_get(site, f"/viewports/{seed['viewport']}/slab-candidates")
    assert found["calibrated"] is True
    assert found["scale_ratio"] == pytest.approx(SCALE_RATIO, rel=0.01)
