"""Walls drawn as two lines, one per face (2026-11-15, Jamie).

The Smith residence plan (the browser tests' A-101) draws every 3" wall as two face lines, with the room outlines
set back from them. Each face of an inside wall then had a room on one side only, so it was taken for an exterior
wall: the 40 x 28 ft house read as 328 lf of exterior wall, 0 lf interior and 2,624 sq ft of siding / exterior paint /
wall insulation (about 136 lf and 1,088 sq ft really). Pieces of a line drawn twice also counted twice.
"""
from pathlib import Path

import pytest

from estimator.building import model as building
from estimator.context import personal_context
from estimator.drawing_model import engine, store
from estimator.estimating import service

CTX = personal_context()
SMITH = Path(__file__).resolve().parents[1] / "browser" / "fixtures" / "smith_residence_A101_revA.pdf"


@pytest.fixture(autouse=True)
def real_engine(monkeypatch):
    engine.clear_engine()
    monkeypatch.setattr(engine, "RUN_INLINE", True)
    yield
    engine.clear_engine()


@pytest.fixture
def smith(db):
    pytest.importorskip("shapely")
    est = service.create_estimate(db, CTX, "Smith residence")
    ps = store.upload(db, CTX, est["id"], str(SMITH), confirm=True)["plan_set_id"]
    engine.start(db, CTX, ps, confirm=True)
    return building.build(db, CTX, estimate_id=est["id"])


def test_inside_walls_drawn_as_two_faces_are_interior(smith):  # DLW-01
    t = smith["totals"]
    assert t["floor_sqft"] == 1048.0                                   # unchanged: five rooms
    assert t["interior_wall_lf"] >= 60                                 # was 0
    assert 110 <= t["exterior_wall_lf"] <= 140                         # was 328; the outline is 136 lf
    assert t["exterior_wall_sqft"] <= 1100                             # was 2,624
    shared = [w for w in smith["walls"] if w["type"] == "interior"]
    assert all(len(w["rooms"]) == 2 for w in shared)
    living_kitchen = [w for w in shared if {r["name"] for r in smith["rooms"] if r["id"] in w["rooms"]}
                      == {"LIVING", "KITCHEN"}]
    assert len(living_kitchen) == 1 and living_kitchen[0]["length_ft"] == 18.0


def test_a_line_drawn_twice_counts_once(smith):  # DLW-02
    # the LIVING face at y=8.47 in is drawn once whole and again in three pieces; it's one wall now
    assert smith["totals"]["wall_lf"] <= 220                           # was 328; framing ~214 lf
    assert len([w for w in smith["walls"] if w["type"] != "other"]) <= 16
